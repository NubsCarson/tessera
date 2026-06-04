//! The channel **state** and its hash commitment `S_i`.
//!
//! A Spilman state is `(chan_id, balance, seq, salt)`. The on-the-wire unit of
//! truth is its commitment
//!
//! ```text
//! S_i = SHA256("tessera-channel/state/v1" || chan_id || balance || seq || salt)
//! ```
//!
//! (`DESIGN.md` §2 commits this with Poseidon inside the ZK circuit; here it is
//! a plain SHA-256, which is all the **protocol** logic needs — the ZK layer
//! later re-commits the same fields privately). Participants sign the commitment
//! `S_i` (32 bytes), not the raw struct, so a signature binds to *exactly one*
//! state.
//!
//! The transition is **monotone-decrementing**: `balance` only goes down and
//! `seq` only goes up, by construction of [`ChannelState::spend`].

use crate::crypto::{h, Hash, Sig, VerifyingKey};

/// Domain string for the state commitment.
const STATE_DOMAIN: &[u8] = b"tessera-channel/state/v1";

/// A channel identifier. In the full design this is the pool-derived id the
/// genesis state is opened under; here it is an opaque 32-byte tag.
pub type ChanId = [u8; 32];

/// A salt that blinds the genesis commitment (and thus every state's
/// commitment) in the eventual ZK layer. Carried through every state unchanged
/// so the commitment chain is well-defined.
pub type Salt = [u8; 32];

/// Why a proposed state is not a valid successor of its claimed predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// The proposed state names a different channel than its predecessor.
    ChanIdMismatch,
    /// `seq` did not advance by exactly one (the channel is monotone and has no
    /// gaps — every unit is the immediate successor of the last).
    NonMonotoneSeq,
    /// The proposed `balance` is **greater** than the predecessor's — the
    /// channel is monotone-*decrementing*, so the user can never pay themselves.
    BalanceIncreased,
    /// The proposed `salt` differs from the predecessor's (the salt is fixed for
    /// the life of the channel).
    SaltChanged,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            StateError::ChanIdMismatch => "chan_id changed across the transition",
            StateError::NonMonotoneSeq => "seq did not advance by exactly one",
            StateError::BalanceIncreased => "balance increased across the transition",
            StateError::SaltChanged => "salt changed across the transition",
        })
    }
}

impl std::error::Error for StateError {}

/// The off-chain channel state. Cheap to copy; the on-the-wire identity is its
/// [`commitment`](ChannelState::commitment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelState {
    /// The channel this state belongs to.
    pub chan_id: ChanId,
    /// Remaining escrow that still belongs to the **user** (the relayer is owed
    /// `B0 - balance`). Monotone non-increasing.
    pub balance: u64,
    /// The state sequence number. `0` is genesis; each spend increments by one.
    pub seq: u64,
    /// Per-channel blinding salt, fixed from genesis.
    pub salt: Salt,
}

impl ChannelState {
    /// The genesis state `S_0` for a channel funded with `b0`.
    pub fn genesis(chan_id: ChanId, b0: u64, salt: Salt) -> Self {
        Self {
            chan_id,
            balance: b0,
            seq: 0,
            salt,
        }
    }

    /// The commitment `S_i = SHA256(domain || chan_id || balance || seq || salt)`.
    ///
    /// All integers are encoded big-endian and fixed-width, so the preimage is
    /// unambiguous and the commitment is a deterministic function of the state.
    pub fn commitment(&self) -> Hash {
        let mut buf = [0u8; 32 + 8 + 8 + 32];
        buf[..32].copy_from_slice(&self.chan_id);
        buf[32..40].copy_from_slice(&self.balance.to_be_bytes());
        buf[40..48].copy_from_slice(&self.seq.to_be_bytes());
        buf[48..].copy_from_slice(&self.salt);
        h(STATE_DOMAIN, &buf)
    }

    /// Produce the next state spending `cost`: `balance -= cost`, `seq += 1`,
    /// same `chan_id`/`salt`.
    ///
    /// Returns `None` on underflow (`cost > balance`) — the caller turns that
    /// into a [`ChannelError::Underflow`](crate::ChannelError::Underflow). Note
    /// this is the **only** way to build a successor, so a `ChannelState` reached
    /// via `spend` is monotone by construction; [`ChannelState::is_successor_of`]
    /// re-checks that for states that arrived over the wire.
    pub fn spend(&self, cost: u64) -> Option<ChannelState> {
        let balance = self.balance.checked_sub(cost)?;
        Some(ChannelState {
            chan_id: self.chan_id,
            balance,
            seq: self.seq + 1,
            salt: self.salt,
        })
    }

    /// Check that `self` is a valid immediate successor of `prev`: same channel,
    /// same salt, `seq == prev.seq + 1`, and `balance <= prev.balance`
    /// (the monotone-decrement). Does **not** check signatures — that is the
    /// relayer's job in [`verify_and_cosign`](crate::RelayerChannel::verify_and_cosign).
    pub fn is_successor_of(&self, prev: &ChannelState) -> Result<(), StateError> {
        if self.chan_id != prev.chan_id {
            return Err(StateError::ChanIdMismatch);
        }
        if self.salt != prev.salt {
            return Err(StateError::SaltChanged);
        }
        if self.seq != prev.seq + 1 {
            return Err(StateError::NonMonotoneSeq);
        }
        // A wire-supplied successor could try to *increase* the balance (the
        // user paying themselves); `spend` can't produce that, but an untrusted
        // state can, so reject it explicitly. The relayer is owed `B0 - balance`,
        // so a higher balance would shrink what it's owed.
        if self.balance > prev.balance {
            return Err(StateError::BalanceIncreased);
        }
        Ok(())
    }
}

/// A [`ChannelState`] plus the signatures gathered on its commitment.
///
/// A state with **both** signatures present is the "unit of truth": the user
/// authorized the spend (`sig_user`, present from the moment the user emits it)
/// and the relayer co-signed it before serving (`sig_relayer`). Settlement only
/// ever counts doubly-signed states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedState {
    /// The committed state.
    pub state: ChannelState,
    /// The user's signature over `state.commitment()`. Always present once the
    /// user has emitted a spend (the load-bearing fix: the user signs *every*
    /// state).
    pub sig_user: Sig,
    /// The relayer's co-signature over the same commitment — present iff the
    /// relayer has run [`verify_and_cosign`](crate::RelayerChannel::verify_and_cosign).
    pub sig_relayer: Option<Sig>,
}

impl SignedState {
    /// Verify the **user** signature against `user_pk` over this state's
    /// commitment.
    pub fn user_sig_valid(&self, user_pk: &VerifyingKey) -> bool {
        user_pk.verify(&self.state.commitment(), &self.sig_user)
    }

    /// Verify the **relayer** co-signature against `relayer_pk`. Returns `false`
    /// if the co-signature is absent.
    pub fn relayer_sig_valid(&self, relayer_pk: &VerifyingKey) -> bool {
        match &self.sig_relayer {
            Some(sig) => relayer_pk.verify(&self.state.commitment(), sig),
            None => false,
        }
    }

    /// `true` iff **both** signatures are present and valid — i.e. this is a
    /// doubly-signed unit of truth.
    pub fn is_doubly_signed(&self, user_pk: &VerifyingKey, relayer_pk: &VerifyingKey) -> bool {
        self.user_sig_valid(user_pk) && self.relayer_sig_valid(relayer_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAN: ChanId = [9u8; 32];
    const SALT_A: Salt = [3u8; 32];

    #[test]
    fn commitment_is_deterministic_and_field_sensitive() {
        let g = ChannelState::genesis(CHAN, 100, SALT_A);
        // deterministic
        assert_eq!(g.commitment(), g.commitment());
        // sensitive to each field
        let mut b = g;
        b.balance = 99;
        assert_ne!(g.commitment(), b.commitment());
        let mut s = g;
        s.seq = 1;
        assert_ne!(g.commitment(), s.commitment());
        let mut salted = g;
        salted.salt = [4u8; 32];
        assert_ne!(g.commitment(), salted.commitment());
    }

    #[test]
    fn spend_decrements_and_bumps_seq() {
        let g = ChannelState::genesis(CHAN, 100, SALT_A);
        let n = g.spend(30).unwrap();
        assert_eq!(n.balance, 70);
        assert_eq!(n.seq, 1);
        assert_eq!(n.chan_id, g.chan_id);
        assert_eq!(n.salt, g.salt);
        n.is_successor_of(&g).unwrap();
    }

    #[test]
    fn spend_underflow_is_none() {
        let g = ChannelState::genesis(CHAN, 100, SALT_A);
        assert!(g.spend(101).is_none());
        assert_eq!(g.spend(100).unwrap().balance, 0); // boundary ok
    }

    #[test]
    fn successor_rejects_tampering() {
        let g = ChannelState::genesis(CHAN, 100, SALT_A);
        let good = g.spend(10).unwrap();

        // wrong chan_id
        let mut bad = good;
        bad.chan_id = [0u8; 32];
        assert_eq!(bad.is_successor_of(&g), Err(StateError::ChanIdMismatch));

        // non-monotone seq (skips ahead)
        let mut bad = good;
        bad.seq = 5;
        assert_eq!(bad.is_successor_of(&g), Err(StateError::NonMonotoneSeq));

        // balance increased (paying yourself)
        let mut bad = good;
        bad.balance = 200;
        assert_eq!(bad.is_successor_of(&g), Err(StateError::BalanceIncreased));

        // salt changed
        let mut bad = good;
        bad.salt = [0u8; 32];
        assert_eq!(bad.is_successor_of(&g), Err(StateError::SaltChanged));
    }
}
