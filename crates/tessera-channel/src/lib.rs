//! # tessera-channel — the ZK Spilman channel **protocol state machine**
//!
//! This crate implements the **off-chain protocol / state-machine logic** of
//! the *ZK Spilman channel* from [`docs/DESIGN.md`](../../../docs/DESIGN.md) §2:
//! a **unidirectional, monotone-decrementing, single-payee** payment channel
//! (the single payee is the relayer). It is *not* Lightning/eltoo/Poon-Dryja —
//! a network-access rail needs a **payee, not a payment network**, so routing /
//! HTLCs / liquidity / revocation / penalty machinery do not exist here.
//!
//! ## Scope (read this — it is deliberately narrow)
//!
//! This is **Phase 2a**: the protocol correctness, in plain Rust with plain
//! crypto. Specifically present here:
//!
//!   * the channel [`state`] machine ([`ChannelState`] + the SHA-256 commitment
//!     `S_i`), genesis `S_0`, and the monotone-decrement transition;
//!   * [`Channel::open`], [`UserChannel::spend`] (the **user signs each state**),
//!     [`RelayerChannel::verify_and_cosign`] (verify-then-co-sign **before**
//!     serving — *sign-then-serve*), the [`proof-of-relay`](relay) receipt that
//!     gates a claim (the HOPR-style fair-exchange fix), and
//!   * off-chain [`settlement`]: highest doubly-signed `seq` wins; equivocation
//!     (two doubly-signed states off one predecessor) → an attributable
//!     **slash** verdict; relayer-dark → user **refund-on-timeout**.
//!
//! Deliberately **NOT** here (later phases — and the README says so plainly):
//!
//!   * **Phase 2b** — the Groth16 `R_dec` circuit that *hides the balance*. The
//!     ZK layer only adds **balance privacy**; it does not change the protocol
//!     correctness this crate proves. Here `cost`/`balance`/`seq` are in the
//!     clear and checked arithmetically; the ZK layer would later prove the same
//!     transition in zero-knowledge.
//!   * **Phase 2c** — the EVM `ShieldedPool` / `ChannelRegistry` / dispute
//!     verifier (the *on-chain court*). [`settlement`] is an **off-chain model**
//!     of that court's verdict logic so the logic can be tested now; there is no
//!     chain, no funds move, and the timeout/refund branch is modeled as state,
//!     not enforced by a CLTV. The *Solidity* `ChannelRegistry` that **does**
//!     move funds lives in [`contracts/`](../../../contracts) and verifies the
//!     very signatures this crate produces (see Crypto, next).
//!
//! ## Crypto — EVM-native secp256k1 over a recoverable keccak digest (2c revision)
//!
//! **2a signed with P-256 ECDSA**; that was a workspace-convenience choice and is
//! **deliberately revised here**. Because the channel settles on the EVM — which
//! verifies **secp256k1** cheaply and universally via the `ecrecover` precompile,
//! but P-256 only via a non-universal precompile or an expensive library — the
//! **durable, chain-facing** signatures are now **Ethereum-style secp256k1**:
//!
//!   * keys are secp256k1 ([`KeyPair`], via the `k256` RustCrypto crate);
//!   * the signed message is the **keccak256 digest**
//!     [`ChannelState::state_digest`] `= keccak256(domain || S_i)`, signed
//!     **recoverably** ([`Sig`] = `r ‖ s ‖ v`, low-`s`, `v ∈ {27,28}`), so the
//!     Solidity court recovers the signer with `ecrecover(digest, v, r, s)`;
//!   * identity is the **20-byte Ethereum address**
//!     [`VerifyingKey::eth_address`] `= keccak256(pubkey[1..])[12..]`, so Rust and
//!     the contract agree on *who signed*.
//!
//! The SHA-256 state commitment `S_i` is kept (it is internal / stored opaquely
//! on-chain); only the *signed digest* is keccak. Every signature here — the
//! durable state sig, the relayer co-signature, the off-chain freshness binding,
//! and the proof-of-relay receipt — uses this one recoverable path (the latter
//! two never touch chain and could have stayed P-256, but sharing one signature
//! type shrinks the surface). The Rust↔Solidity match is pinned by
//! `tests/eth_vector.rs` (Rust side) + `contracts/test/CrossLanguageVector.t.sol`
//! (the contract recovering the *same* address from the *same* bytes).
//!
//! ## The corrected core (what the red-team had to fix)
//!
//! Four properties are load-bearing and are each exercised by a test:
//!
//!   1. **The user signs every state.** The original "2-of-2" was really 1-of-1
//!      (only the relayer's signature gated the spend), which left user
//!      equivocation *unattributable*. Here [`UserChannel::spend`] produces
//!      `sig_user(S_{i+1})` and the relayer refuses a state without it, so a fork
//!      is provable against the user's key (a [`Verdict::SlashUser`]).
//!   2. **Sign-then-serve.** The relayer co-signs `S_{i+1}` and returns the
//!      doubly-signed state **before** "serving" the request. A
//!      [`SignedState`] that is *served* without the relayer's co-signature is
//!      rejected ([`UserChannel::serve`] requires the co-signed state).
//!   3. **Proof-of-relay.** Fair exchange is impossible off-chain without a TTP
//!      (EGL / Pagnia–Gärtner); the relayer can only **claim** a spent unit
//!      against a signed *relay acknowledgement* that the packet was forwarded.
//!      Without that receipt the unit is **not claimable** — this defeats the
//!      refusal-drain.
//!   4. **Freshness binding.** What the user signs includes a relayer-supplied
//!      epoch + nonce and a request-hash, so a spend message is **not
//!      wire-replayable**.
//!
//! ## Honest limits (no chain yet)
//!
//!   * A **non-forking linear rollback** by the user (just re-presenting an old
//!     doubly-signed state instead of forking) produces no attributable object —
//!     exactly as `DESIGN.md` §2 admits. It is covered by `seq` + countersig +
//!     the watchtower (a *stated* safety component, out of scope here). We do
//!     **not** claim to detect it; [`settlement`] simply takes the
//!     highest-`seq` doubly-signed state as truth.
//!   * Nothing here moves money or talks to a chain. "Escrow", "refund", and
//!     "slash" are **verdicts** a future on-chain court would enforce; this crate
//!     computes the verdict, it does not settle it.
//!
//! ## Example: one honest spend round trip
//!
//! ```
//! use rand_core::OsRng;
//! use tessera_channel::{Channel, KeyPair, RelayerChannel, UserChannel};
//! use tessera_channel::settlement::{settle, Verdict};
//!
//! let mut rng = OsRng;
//! let user_keys = KeyPair::generate(&mut rng);
//! let relayer_keys = KeyPair::generate(&mut rng);
//!
//! // open(B0): agree the channel parameters (B0 = 1000).
//! let chan = Channel::open(
//!     [1u8; 32], 1000, [2u8; 32],
//!     user_keys.verifying_key(), relayer_keys.verifying_key(),
//! );
//! let mut user = UserChannel::new(user_keys, chan.clone());
//! let mut relayer = RelayerChannel::new(relayer_keys, chan.clone(), /* epoch */ 1);
//!
//! // The relayer issues a freshness challenge bound to the request to be relayed.
//! let fresh = relayer.issue_challenge(/* nonce */ 0, b"onion-packet");
//!
//! // spend(cost): the user signs S_1 (and a freshness binding).
//! let spend = user.spend(40, &fresh).unwrap();
//!
//! // The relayer verifies and CO-SIGNS before serving (sign-then-serve).
//! let cosigned = relayer.verify_and_cosign(&spend, &fresh).unwrap();
//! user.accept_cosigned(&cosigned).unwrap();
//! let _served = user.serve(&cosigned).unwrap(); // only allowed once co-signed
//!
//! // After relaying, the relayer issues a proof-of-relay receipt; without it the
//! // spent unit is not claimable at settlement.
//! let ack = relayer.issue_relay_ack(&cosigned.state);
//!
//! // Settlement: highest doubly-signed seq wins → relayer 40, user 960.
//! let verdict = settle(
//!     1000, &user.user_pk(), &relayer.relayer_pk(),
//!     std::slice::from_ref(&cosigned), std::slice::from_ref(&ack),
//! );
//! assert_eq!(verdict, Verdict::Settle { winning_seq: 1, relayer_payout: 40, user_refund: 960 });
//! ```
//!
//! This crate is research-grade and **unaudited**. It is a host (`std`) crate
//! with `#![forbid(unsafe_code)]`, depending only on the workspace's `k256`
//! (secp256k1 ECDSA), `sha3` (keccak256, the EVM hash), `sha2` (SHA-256 state
//! commitment), `rand_core`, and `hex`.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod relay;
pub mod settlement;
pub mod state;

mod channel;

pub use channel::{Channel, RelayerChannel, Served, Spend, UserChannel};
pub use crypto::{EthAddress, EthDigest, EthSig, KeyPair, Sig, VerifyingKey};
pub use relay::{RelayAck, RelayRequest};
pub use settlement::{settle, Verdict};
pub use state::{ChannelState, SignedState, StateError};

/// Crate-wide error type for the protocol state machine.
///
/// Every variant corresponds to a *protocol rule* a participant enforces on a
/// peer's message; none of them indicate an internal bug (those `panic`/`expect`
/// on truly-impossible invariants instead, the way `tessera-arc` does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The proposed next state is not a valid successor of the current one
    /// (wrong predecessor commitment, non-monotone `seq`, or wrong channel id).
    BadTransition(StateError),
    /// `cost > balance` — the monotone-decrement would underflow the escrow.
    Underflow {
        /// Balance available in the predecessor state.
        balance: u64,
        /// Cost the spend tried to subtract.
        cost: u64,
    },
    /// A signature did not verify against the expected key over the expected
    /// state bytes.
    BadSignature,
    /// The freshness binding (epoch / nonce / request-hash) did not match the
    /// challenge the relayer issued, so the spend is stale or replayed.
    StaleFreshness,
    /// A "serve" was attempted on a state that the relayer has not co-signed
    /// (the *sign-then-serve* ordering violation).
    NotCoSigned,
    /// A claim was attempted on a unit with no valid proof-of-relay receipt
    /// (the HOPR-style fair-exchange obligation), or the receipt does not bind
    /// the state being claimed.
    NoProofOfRelay,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelError::BadTransition(e) => write!(f, "invalid state transition: {e}"),
            ChannelError::Underflow { balance, cost } => {
                write!(f, "balance underflow: cost {cost} > balance {balance}")
            }
            ChannelError::BadSignature => f.write_str("signature did not verify"),
            ChannelError::StaleFreshness => {
                f.write_str("freshness binding did not match (stale or replayed spend)")
            }
            ChannelError::NotCoSigned => {
                f.write_str("serve attempted before the relayer co-signed the new state")
            }
            ChannelError::NoProofOfRelay => {
                f.write_str("no valid proof-of-relay receipt for the claimed unit")
            }
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<StateError> for ChannelError {
    fn from(e: StateError) -> Self {
        ChannelError::BadTransition(e)
    }
}
