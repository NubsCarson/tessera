//! The Spilman channel **watchtower** (M2) — the reactive safety component that
//! `DESIGN.md` §2 and the crate root both name but Phase 2a left out.
//!
//! ## What it defends against
//!
//! The channel's one residual offline risk is a **stale unilateral close**. The
//! on-chain court ([`ChannelRegistry`](../../../contracts)) lets either party
//! start a unilateral close at *any* doubly-signed state and opens a fixed
//! challenge window in which the counterparty may override it with a
//! **strictly-higher-`seq`** doubly-signed state (the latest truth wins). If the
//! disadvantaged party is offline for the whole window, the stale state settles.
//!
//! In this unidirectional, monotone-decrementing channel that concretely means:
//! `balance` only falls, so an **older** state has a **higher** balance and pays
//! the relayer **less**. A party that closes at a stale state is therefore trying
//! to under-pay the relayer (or, symmetrically, claw back spent funds). The
//! watchtower is whoever holds the latest doubly-signed state and stands ready to
//! submit the `challenge` during the window — the relayer for itself, the user,
//! or a delegated third party. Its decision logic is identical in all three
//! roles, which is why it lives here as one component.
//!
//! ## Scope (deliberately the decision, not the plumbing)
//!
//! This module is the **pure, testable decision core**: hold the highest
//! doubly-signed state witnessed, and — on observing an on-chain unilateral close
//! at some seq — decide whether to challenge and with which state. The decision
//! exactly mirrors the court's `challenge` precondition (`state.seq > bestSeq`,
//! `balance <= B0`, both signatures valid), so a [`WatchtowerAction::Challenge`]
//! this module emits is one the contract will accept.
//!
//! The **live wrapper** — polling the chain for the `DisputeStarted` event,
//! signing and broadcasting the `challenge` transaction, and doing so **before**
//! `challengeEnd` — needs an RPC endpoint and a funded key and is an operational
//! integration, not protocol logic; it is out of scope here (and flagged in
//! `docs/DESIGN.md`). The caller MUST act within the court's `CHALLENGE_WINDOW`.
//!
//! ```
//! use rand_core::OsRng;
//! use tessera_channel::{Channel, KeyPair, RelayerChannel, UserChannel};
//! use tessera_channel::watchtower::{Watchtower, WatchtowerAction};
//!
//! let mut rng = OsRng;
//! let uk = KeyPair::generate(&mut rng);
//! let rk = KeyPair::generate(&mut rng);
//! let chan = Channel::open([1u8; 32], 1000, [2u8; 32], uk.verifying_key(), rk.verifying_key());
//! let mut user = UserChannel::new(uk, chan.clone());
//! let mut relayer = RelayerChannel::new(rk, chan.clone(), 1);
//!
//! // A watchtower for this channel, fed the latest doubly-signed state.
//! let mut tower = Watchtower::new(chan.clone());
//! let fresh = relayer.issue_challenge(0, b"packet");
//! let spend = user.spend(40, &fresh).unwrap();
//! let s1 = relayer.verify_and_cosign(&spend, &fresh).unwrap(); // seq 1, balance 960
//! assert!(tower.witness(&s1));
//!
//! // Someone starts a unilateral close at STALE genesis (seq 0, balance 1000) to
//! // under-pay the relayer. The tower holds seq 1 → it challenges.
//! match tower.on_dispute_started(0) {
//!     WatchtowerAction::Challenge(state) => assert_eq!(state.state.seq, 1),
//!     WatchtowerAction::NoAction => panic!("should have challenged the stale close"),
//! }
//!
//! // If the close were already at the latest seq, there is nothing to do.
//! assert!(matches!(tower.on_dispute_started(1), WatchtowerAction::NoAction));
//! ```

use crate::state::SignedState;
use crate::Channel;

/// What the watchtower should do in response to an observed unilateral close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchtowerAction {
    /// Submit `challenge(state)` to the court: the tower holds a
    /// **strictly-higher-`seq`** doubly-signed state than the one the close was
    /// started at, so this overrides the stale close with the latest truth. The
    /// enclosed [`SignedState`] satisfies the court's `challenge` precondition.
    /// (Boxed because a [`SignedState`] dwarfs the empty [`NoAction`](Self::NoAction)
    /// variant — keeps the enum small.)
    Challenge(Box<SignedState>),
    /// Do nothing: the on-chain close is already at (or beyond) the highest state
    /// the tower has witnessed, so a challenge would be rejected as
    /// non-higher-`seq`. This includes the case where the tower holds no state.
    NoAction,
}

/// A watchtower for a single channel. Holds the channel parameters and the
/// highest doubly-signed state it has been shown, and decides whether an observed
/// unilateral close is stale enough to challenge.
#[derive(Clone, Debug)]
pub struct Watchtower {
    params: Channel,
    /// The highest-`seq` doubly-signed state witnessed so far (`None` until the
    /// first valid [`witness`](Watchtower::witness)).
    best: Option<SignedState>,
}

impl Watchtower {
    /// Create a watchtower for `params`, holding no state yet.
    pub fn new(params: Channel) -> Self {
        Self { params, best: None }
    }

    /// Show the tower a doubly-signed state. It is **adopted as the new best**
    /// iff it is valid for this channel and strictly newer than what the tower
    /// holds — specifically, all of:
    ///
    ///   * it is for **this** channel (`chan_id` + `salt` match `params`),
    ///   * its `balance` does not exceed `B0` (a state the court would accept),
    ///   * it is **genuinely doubly-signed** by both registered parties, and
    ///   * its `seq` is **strictly greater** than the current best's (monotone;
    ///     a re-shown old state, or a same-`seq` conflicting state, is ignored —
    ///     equivocation detection is [`settlement`](crate::settlement)'s job, not
    ///     the tower's).
    ///
    /// Returns `true` if the state was adopted. A `false` return is not an error;
    /// it just means the tower already holds something at least as new (or the
    /// state was not valid for this channel).
    pub fn witness(&mut self, state: &SignedState) -> bool {
        // For this channel?
        if state.state.chan_id != self.params.chan_id || state.state.salt != self.params.salt {
            return false;
        }
        // A state the court would accept (balance within escrow).
        if state.state.balance > self.params.b0 {
            return false;
        }
        // Genuinely doubly-signed by BOTH registered parties.
        if !state.is_doubly_signed(&self.params.user_pk, &self.params.relayer_pk) {
            return false;
        }
        // Strictly newer than what we hold.
        if let Some(best) = &self.best {
            if state.state.seq <= best.state.seq {
                return false;
            }
        }
        self.best = Some(state.clone());
        true
    }

    /// React to an observed on-chain unilateral close started at `disputed_seq`.
    ///
    /// Returns [`WatchtowerAction::Challenge`] with the tower's highest
    /// doubly-signed state iff that state's `seq` is **strictly greater** than
    /// `disputed_seq` (so the court's `challenge` will accept it); otherwise
    /// [`WatchtowerAction::NoAction`].
    pub fn on_dispute_started(&self, disputed_seq: u64) -> WatchtowerAction {
        match &self.best {
            Some(best) if best.state.seq > disputed_seq => {
                WatchtowerAction::Challenge(Box::new(best.clone()))
            }
            _ => WatchtowerAction::NoAction,
        }
    }

    /// The `seq` of the highest doubly-signed state the tower holds, if any.
    pub fn best_seq(&self) -> Option<u64> {
        self.best.as_ref().map(|s| s.state.seq)
    }

    /// The highest doubly-signed state the tower holds, if any.
    pub fn best(&self) -> Option<&SignedState> {
        self.best.as_ref()
    }
}
