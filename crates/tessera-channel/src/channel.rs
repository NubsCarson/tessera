//! The Spilman channel **protocol state machine**: open, the user-side spend,
//! the relayer-side verify-and-co-sign (sign-then-serve), and the serve gate.
//!
//! The two sides are modeled as separate types ([`UserChannel`],
//! [`RelayerChannel`]) that exchange [`SignedState`]s and a [`RelayRequest`]
//! freshness challenge, because the *whole point* of the corrected protocol is
//! that the two parties enforce rules on each other's messages. A single
//! "channel object" that did both would hide exactly the equivocation /
//! ordering bugs this crate exists to rule out.

use std::collections::HashSet;

use crate::crypto::{KeyPair, Sig, VerifyingKey};
use crate::relay::{spend_message, RelayRequest};
use crate::state::{ChanId, ChannelState, Salt, SignedState};
use crate::ChannelError;

/// Shared, public channel parameters both sides agree on at open: the channel
/// id, the funding balance `B0`, the salt, and both public keys.
///
/// Conceptually the escrow these describe is spendable by *(relayer countersig
/// on the latest state)* **OR** *(the user alone after a timeout)* — the
/// refund-on-timeout branch modeled in [`settlement`](crate::settlement). There
/// is no chain here, so [`Channel`] is just the agreed parameters; the genesis
/// state `S_0` is its [`Channel::genesis`].
#[derive(Clone, Debug)]
pub struct Channel {
    /// Channel id (opaque; pool-derived in the full design).
    pub chan_id: ChanId,
    /// Funding balance `B0` — the total the user escrowed.
    pub b0: u64,
    /// Per-channel salt.
    pub salt: Salt,
    /// The user's public key (equivocation is attributed to this key).
    pub user_pk: VerifyingKey,
    /// The relayer's public key (co-signatures and relay receipts verify under
    /// this).
    pub relayer_pk: VerifyingKey,
}

impl Channel {
    /// **open(B0)** — agree the channel parameters.
    ///
    /// Models the on-chain `open` that escrows `B0` into the `ChannelRegistry`
    /// at genesis `S_0`. There is no chain yet, so this just binds the
    /// parameters and both public keys. The escrow's *(countersig OR
    /// timeout-refund)* spend condition is not enforced here — it is the
    /// verdict logic in [`settlement`](crate::settlement).
    pub fn open(
        chan_id: ChanId,
        b0: u64,
        salt: Salt,
        user_pk: VerifyingKey,
        relayer_pk: VerifyingKey,
    ) -> Self {
        Self {
            chan_id,
            b0,
            salt,
            user_pk,
            relayer_pk,
        }
    }

    /// The genesis state `S_0 = (chan_id, B0, 0, salt)`.
    pub fn genesis(&self) -> ChannelState {
        ChannelState::genesis(self.chan_id, self.b0, self.salt)
    }
}

/// The **user/client** side of the channel. Holds the user's signing key and
/// the latest doubly-signed state it has (its cursor into the channel).
pub struct UserChannel {
    keys: KeyPair,
    params: Channel,
    /// The latest state the user considers authoritative. Starts unsigned at
    /// genesis (`balance = B0, seq = 0`); after each successful round trip it is
    /// the doubly-signed `S_{i+1}`.
    latest: ChannelState,
}

impl UserChannel {
    /// Create the user side from its keypair and the open channel parameters.
    /// The user's cursor starts at genesis `S_0`.
    pub fn new(keys: KeyPair, params: Channel) -> Self {
        let latest = params.genesis();
        Self {
            keys,
            params,
            latest,
        }
    }

    /// The user's current authoritative state.
    pub fn latest(&self) -> ChannelState {
        self.latest
    }

    /// The user's public key (for settling without re-threading the params).
    pub fn user_pk(&self) -> VerifyingKey {
        self.params.user_pk.clone()
    }

    /// The relayer's public key (this channel's counterparty).
    pub fn relayer_pk(&self) -> VerifyingKey {
        self.params.relayer_pk.clone()
    }

    /// **spend(cost)** — build `S_{i+1}` (decrement balance, bump seq) and sign
    /// it, plus a freshness-binding signature against the relayer's challenge.
    ///
    /// Returns a [`Spend`] with two user signatures:
    ///   * `state.sig_user` over the **bare** state commitment `S_{i+1}` — the
    ///     *durable* unit of truth, re-checkable at settlement without any wire
    ///     context. This is the load-bearing fix: the user signs **every** state,
    ///     so a later fork is attributable to the user's key.
    ///   * `sig_fresh` over `H(S_{i+1} || epoch || nonce || request_hash)` — the
    ///     *ephemeral* binding the relayer checks so a spend can't be wire-
    ///     replayed against a different request/epoch. It is deliberately *not*
    ///     part of the persistent state (it would be the Groth16 proof π in the
    ///     full design — see `DESIGN.md` §2).
    ///
    /// `state.sig_relayer` is `None`; the relayer co-signs next. Errors with
    /// [`ChannelError::Underflow`] if `cost` exceeds the current balance.
    ///
    /// This does **not** advance the user's cursor; the cursor only moves once
    /// the relayer returns the co-signed state to [`accept_cosigned`], so a spend
    /// the relayer never co-signs leaves the user safely on the last
    /// doubly-signed state.
    pub fn spend(&self, cost: u64, fresh: &RelayRequest) -> Result<Spend, ChannelError> {
        let next = self.latest.spend(cost).ok_or(ChannelError::Underflow {
            balance: self.latest.balance,
            cost,
        })?;
        let commitment = next.commitment();
        let sig_user = self.keys.sign(&commitment);
        let sig_fresh = self.keys.sign(&spend_message(&commitment, fresh));
        Ok(Spend {
            signed: SignedState {
                state: next,
                sig_user,
                sig_relayer: None,
            },
            sig_fresh,
        })
    }

    /// Accept the relayer's co-signed reply and advance the cursor to it.
    ///
    /// Verifies the relayer's co-signature over the **same** state the user
    /// signed (and that the user's own signature over the commitment is intact
    /// and the transition is a valid successor of the cursor). Only on success
    /// does the user adopt the new state as authoritative.
    pub fn accept_cosigned(&mut self, cosigned: &SignedState) -> Result<(), ChannelError> {
        cosigned.state.is_successor_of(&self.latest)?;
        // The user re-checks its *own* signature over the commitment is intact
        // (defends against a relayer that swaps the state under us before
        // co-signing).
        if !cosigned.user_sig_valid(&self.params.user_pk) {
            return Err(ChannelError::BadSignature);
        }
        if !cosigned.relayer_sig_valid(&self.params.relayer_pk) {
            return Err(ChannelError::NotCoSigned);
        }
        self.latest = cosigned.state;
        Ok(())
    }

    /// **serve gate (sign-then-serve ordering).** A request may only be
    /// "served"/sent on a state the relayer has **co-signed**. Returns the
    /// served marker on success, or [`ChannelError::NotCoSigned`] if the state
    /// carries no valid relayer co-signature.
    ///
    /// "Serve" here is modeled as producing a [`Served`] marker the test
    /// inspects, standing in for "the relayer actually forwards the packet".
    pub fn serve(&self, cosigned: &SignedState) -> Result<Served, ChannelError> {
        if !cosigned.relayer_sig_valid(&self.params.relayer_pk) {
            return Err(ChannelError::NotCoSigned);
        }
        Ok(Served {
            seq: cosigned.state.seq,
            commitment: cosigned.state.commitment(),
        })
    }
}

/// A user's spend message: the proposed [`SignedState`] (user signature over the
/// bare commitment, relayer co-signature still absent) plus the ephemeral
/// freshness-binding signature the relayer checks for replay defense.
///
/// In the full design `sig_fresh` is subsumed by the Groth16 proof π; here it is
/// a plain signature over the freshness-bound message so the *protocol* property
/// (a spend is bound to one epoch/nonce/request) is testable without a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    /// The proposed next state with the user's commitment signature.
    pub signed: SignedState,
    /// The user's signature over `H(S_{i+1} || epoch || nonce || request_hash)`.
    pub sig_fresh: Sig,
}

/// A marker that a request *was* served — the modeled "callback" for
/// sign-then-serve. Carries which state authorized the serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served {
    /// The seq of the state the serve was authorized by.
    pub seq: u64,
    /// That state's commitment.
    pub commitment: crate::crypto::Hash,
}

/// The **relayer** side: holds the relayer's signing key, the channel params,
/// the latest co-signed state (its in-memory cursor — the design's "single
/// in-memory cursor" that collapses distributed double-spend), and the set of
/// freshness nonces already consumed this epoch.
pub struct RelayerChannel {
    keys: KeyPair,
    params: Channel,
    latest: ChannelState,
    epoch: u64,
    seen_nonces: HashSet<u64>,
}

impl RelayerChannel {
    /// Create the relayer side at genesis, opening freshness `epoch`.
    pub fn new(keys: KeyPair, params: Channel, epoch: u64) -> Self {
        let latest = params.genesis();
        Self {
            keys,
            params,
            latest,
            epoch,
            seen_nonces: HashSet::new(),
        }
    }

    /// The relayer's current co-signed cursor.
    pub fn latest(&self) -> ChannelState {
        self.latest
    }

    /// The relayer's public key (for settling / verifying receipts).
    pub fn relayer_pk(&self) -> VerifyingKey {
        self.params.relayer_pk.clone()
    }

    /// The user (counterparty) public key.
    pub fn user_pk(&self) -> VerifyingKey {
        self.params.user_pk.clone()
    }

    /// Issue a fresh challenge for a request payload: the current epoch and a
    /// caller-chosen `nonce`, bound to `request_payload`.
    ///
    /// The relayer will only accept a spend whose freshness matches a challenge
    /// it issued and whose nonce it has not already consumed this epoch (tracked
    /// in [`verify_and_cosign`]).
    pub fn issue_challenge(&self, nonce: u64, request_payload: &[u8]) -> RelayRequest {
        RelayRequest::new(self.epoch, nonce, request_payload)
    }

    /// **verify + co-sign (sign-then-serve).** Validate the user's proposed
    /// `S_{i+1}` against every protocol rule, and only if all hold, co-sign it
    /// and advance the relayer's cursor — returning the **doubly-signed** state
    /// the relayer hands back *before* it serves.
    ///
    /// Checks, in order:
    ///   1. **predecessor / monotone / no-balance-increase** — `spend.signed.state`
    ///      is a valid successor of the relayer's current cursor (this also
    ///      enforces **balance ok**: a balance increase is rejected, and the
    ///      user's own `spend` already rejected underflow);
    ///   2. **freshness** — `fresh.epoch` is the relayer's epoch and `fresh.nonce`
    ///      has not been consumed this epoch (replay defense);
    ///   3. **user state signature** — `sig_user` is valid over the bare state
    ///      commitment (so a doubly-signed fork is attributable to the user);
    ///   4. **user freshness signature** — `sig_fresh` is valid over the
    ///      freshness-bound message (so the spend is pinned to *this* request and
    ///      can't be wire-replayed even before the nonce is burned).
    ///
    /// On success the nonce is burned, the cursor advances, and the returned
    /// state carries both the user and relayer signatures over the commitment.
    pub fn verify_and_cosign(
        &mut self,
        spend: &Spend,
        fresh: &RelayRequest,
    ) -> Result<SignedState, ChannelError> {
        let proposed = &spend.signed;

        // (1) valid successor of the relayer's current cursor.
        proposed.state.is_successor_of(&self.latest)?;

        // (2) freshness: right epoch, unconsumed nonce.
        if fresh.epoch != self.epoch || self.seen_nonces.contains(&fresh.nonce) {
            return Err(ChannelError::StaleFreshness);
        }

        // (3) the user must have signed this exact state (durable unit of truth).
        if !proposed.user_sig_valid(&self.params.user_pk) {
            return Err(ChannelError::BadSignature);
        }

        // (4) and bound it to this freshness challenge (replay binding).
        let fresh_msg = spend_message(&proposed.state.commitment(), fresh);
        if !self.params.user_pk.verify(&fresh_msg, &spend.sig_fresh) {
            return Err(ChannelError::StaleFreshness);
        }

        // All checks passed → co-sign and advance the cursor. Burn the nonce so
        // the same freshness challenge can't drive a second spend (replay).
        self.seen_nonces.insert(fresh.nonce);
        self.latest = proposed.state;
        let sig_relayer = self.keys.sign(&proposed.state.commitment());
        Ok(SignedState {
            state: proposed.state,
            sig_user: proposed.sig_user.clone(),
            sig_relayer: Some(sig_relayer),
        })
    }

    /// Issue a proof-of-relay receipt for a co-signed state — call this only
    /// after actually forwarding. See [`RelayAck::issue`](crate::RelayAck::issue).
    pub fn issue_relay_ack(&self, state: &ChannelState) -> crate::RelayAck {
        crate::RelayAck::issue(&self.keys, state.commitment())
    }
}
