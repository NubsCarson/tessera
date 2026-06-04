//! Freshness binding and the **proof-of-relay** receipt.
//!
//! Two distinct anti-abuse artifacts live here, both from `DESIGN.md` §2:
//!
//!   * [`RelayRequest`] — the relayer-supplied **freshness binding** (`epoch`,
//!     `nonce`) plus the hash of the request the user wants relayed. The user
//!     folds this into what it signs, so a spend message is bound to one request
//!     and **cannot be wire-replayed** against a different request or epoch.
//!   * [`RelayAck`] — the **HOPR-style proof-of-relay receipt**: a signature by
//!     the relayer acknowledging it forwarded the packet for a specific state.
//!     Fair exchange is impossible off-chain without a TTP (EGL / Pagnia–
//!     Gärtner), so we don't try to make serve-and-pay atomic; instead the
//!     relayer can only **claim** a spent unit if it can show this receipt. No
//!     receipt → the unit is not claimable → the refusal-drain (take the payment,
//!     refuse to relay) gains the relayer nothing.

use crate::crypto::{h, Hash, KeyPair, Sig, VerifyingKey};

/// Domain for the bytes the user signs in a spend (state commitment + freshness).
const SPEND_DOMAIN: &[u8] = b"tessera-channel/spend/v1";
/// Domain for the relay-acknowledgement receipt.
const ACK_DOMAIN: &[u8] = b"tessera-channel/relay-ack/v1";

/// A relayer-issued freshness challenge bound to one request to be relayed.
///
/// The relayer hands this to the user *before* the spend; the user signs over
/// it (via [`spend_message`]). Because `epoch`/`nonce` are the relayer's choice
/// and `request_hash` pins the exact request, the resulting signature is good
/// for exactly this (epoch, nonce, request) — replaying the spend bytes against
/// any other request or epoch fails the relayer's freshness check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRequest {
    /// The relayer's current epoch (coarse clock / settlement window).
    pub epoch: u64,
    /// A per-request nonce the relayer issues and will not re-accept within the
    /// epoch (the relayer tracks seen nonces; modeled by the caller / the spend
    /// flow — see [`RelayerChannel`](crate::RelayerChannel)).
    pub nonce: u64,
    /// Hash of the request payload the user wants forwarded (e.g. the onion
    /// packet). Binds the spend to *what* is being relayed.
    pub request_hash: Hash,
}

impl RelayRequest {
    /// Convenience constructor that hashes a raw request payload.
    pub fn new(epoch: u64, nonce: u64, request_payload: &[u8]) -> Self {
        Self {
            epoch,
            nonce,
            request_hash: h(b"tessera-channel/request/v1", request_payload),
        }
    }

    /// The freshness bytes folded into the spend signature.
    fn freshness_bytes(&self) -> [u8; 8 + 8 + 32] {
        let mut out = [0u8; 48];
        out[..8].copy_from_slice(&self.epoch.to_be_bytes());
        out[8..16].copy_from_slice(&self.nonce.to_be_bytes());
        out[16..].copy_from_slice(&self.request_hash);
        out
    }
}

/// The exact message the user signs for a spend: the next state's commitment
/// **bound to** the relayer's freshness challenge.
///
/// `= H(SPEND_DOMAIN || S_{i+1} || epoch || nonce || request_hash)`.
///
/// Both the user (when signing) and the relayer (when verifying) compute this,
/// so they must agree on the freshness challenge — a replayed spend carries the
/// old freshness, which won't match the fresh challenge the relayer expects.
pub fn spend_message(next_commitment: &Hash, fresh: &RelayRequest) -> Hash {
    let mut buf = [0u8; 32 + 48];
    buf[..32].copy_from_slice(next_commitment);
    buf[32..].copy_from_slice(&fresh.freshness_bytes());
    h(SPEND_DOMAIN, &buf)
}

/// A signed proof-of-relay receipt: the relayer attests it forwarded the packet
/// for the state committed by `state_commitment`.
///
/// In the real system this is the HOPR ticket; here it is a plain relayer
/// signature over the state commitment. A unit is only claimable in
/// [`settlement`](crate::settlement) if a matching, valid `RelayAck` exists.
#[derive(Clone, Debug)]
pub struct RelayAck {
    /// The commitment of the state whose relay this receipt acknowledges.
    pub state_commitment: Hash,
    /// The relayer's signature over `H(ACK_DOMAIN || state_commitment)`.
    pub sig: Sig,
}

impl RelayAck {
    /// The relayer issues a receipt acknowledging it relayed `state_commitment`.
    ///
    /// In a fair-exchange-honest flow the relayer issues this only *after*
    /// actually forwarding — but crucially, the receipt is what lets it *claim*,
    /// so an honest relayer that wants to get paid is incentivized to relay and
    /// then issue. A relayer that refuses to relay simply has no receipt to claim
    /// with. This is the asymmetry that defeats the refusal-drain.
    pub fn issue(relayer: &KeyPair, state_commitment: Hash) -> Self {
        let sig = relayer.sign(&Self::message(&state_commitment));
        Self {
            state_commitment,
            sig,
        }
    }

    /// Verify the receipt is a valid relayer signature **and** that it binds the
    /// given state commitment (so a receipt for one state can't be reused to
    /// claim another).
    pub fn is_valid_for(&self, relayer_pk: &VerifyingKey, state_commitment: &Hash) -> bool {
        self.state_commitment == *state_commitment
            && relayer_pk.verify(&Self::message(state_commitment), &self.sig)
    }

    fn message(state_commitment: &Hash) -> Hash {
        h(ACK_DOMAIN, state_commitment)
    }
}
