//! Off-chain **dispute / settlement** resolution — a model of what the on-chain
//! court (`ChannelRegistry` dispute verifier, `DESIGN.md` §6) would decide.
//!
//! There is no chain here: [`settle`] computes a [`Verdict`] from a set of
//! states (and the relay receipts the relayer can show). It does **not** move
//! funds. The three outcomes mirror the design:
//!
//!   * **cooperative / unilateral close** — the **highest `seq` that carries
//!     BOTH signatures wins**; it pays the relayer `B0 - balance` and refunds the
//!     user `balance` (the [`Verdict::Settle`]). A unit is only *counted toward
//!     the relayer's claim* if the relayer can show a [`RelayAck`] for it
//!     (proof-of-relay), so withholding can't be claimed.
//!   * **slash** — if two **doubly-signed** states share a predecessor `seq`
//!     but commit to **different** next states, that is on-its-face user
//!     equivocation, attributable to the user's key → [`Verdict::SlashUser`].
//!   * **refund-on-timeout** — if the relayer never advanced the channel (no
//!     doubly-signed state beyond genesis), the user recovers the last
//!     self-consistent balance → [`Verdict::RefundUser`].
//!
//! Honest limit (stated): a **non-forking linear rollback** — the user just
//! presenting an *older* doubly-signed state — is **not** detectable from the
//! states alone (it yields no conflicting object). `DESIGN.md` §2 covers it with
//! `seq` + countersig + a watchtower; the watchtower is out of scope here, so
//! [`settle`] takes the highest doubly-signed `seq` it is *given* as truth.

use crate::crypto::{Hash, VerifyingKey};
use crate::relay::RelayAck;
use crate::state::SignedState;

/// The verdict an on-chain court would reach for a channel dispute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Settle at the winning doubly-signed state: pay the relayer
    /// `relayer_payout` and refund the user `user_refund` (these sum to `B0`,
    /// the funded balance).
    Settle {
        /// The seq of the winning (highest doubly-signed) state.
        winning_seq: u64,
        /// What the relayer is owed (`B0 - winning_balance`), *capped at what it
        /// can prove it relayed* via proof-of-relay receipts.
        relayer_payout: u64,
        /// What is refunded to the user (`B0 - relayer_payout`).
        user_refund: u64,
    },
    /// User equivocation proven: two doubly-signed states off one predecessor.
    /// The bytes that prove it are returned for the court / a slashing tx.
    SlashUser {
        /// The shared seq the two conflicting states sit at.
        seq: u64,
        /// The two distinct commitments at that seq (the fraud proof).
        conflicting: (Hash, Hash),
    },
    /// The relayer never advanced the channel; the user recovers their full
    /// last self-consistent balance (here, `B0` — genesis).
    RefundUser {
        /// The balance refunded to the user.
        user_refund: u64,
    },
}

/// Resolve a dispute over `b0`-funded channel with public keys
/// `(user_pk, relayer_pk)`, given the `states` each party submits and the set of
/// proof-of-relay `receipts` the relayer can show.
///
/// Algorithm:
///   1. Keep only **doubly-signed** states (the unit of truth). A state missing
///      either valid signature is ignored — including a user-only spend the
///      relayer never co-signed.
///   2. If any two doubly-signed states share a `seq` but differ in commitment →
///      [`Verdict::SlashUser`] (equivocation; both bear the user's valid sig).
///   3. Else the relayer is paid against the **highest-`seq` doubly-signed state
///      for which it can also show a valid proof-of-relay receipt**. Because the
///      balance is cumulative (monotone-decrementing), that one state's balance
///      already accounts for every unit up to it; a later doubly-signed state
///      with *no* receipt is not claimable, so the relayer can't collect for a
///      unit it withheld. The relayer's payout is `B0 - that_balance`, the rest
///      refunds to the user. (Models HOPR fair-exchange: unrelayed ⇒ unclaimable.)
///   4. If there is **no** doubly-signed state at all → [`Verdict::RefundUser`]
///      (relayer-dark, refund-on-timeout). Likewise if there are doubly-signed
///      states but the relayer can show **no** matching receipt, its payout is
///      `0` and the user is refunded in full.
pub fn settle(
    b0: u64,
    user_pk: &VerifyingKey,
    relayer_pk: &VerifyingKey,
    states: &[SignedState],
    receipts: &[RelayAck],
) -> Verdict {
    // (1) doubly-signed states only.
    let doubly: Vec<&SignedState> = states
        .iter()
        .filter(|s| s.is_doubly_signed(user_pk, relayer_pk))
        .collect();

    // (2) equivocation: same seq, different commitment, both doubly-signed.
    for (i, a) in doubly.iter().enumerate() {
        for b in &doubly[i + 1..] {
            if a.state.seq == b.state.seq && a.state.commitment() != b.state.commitment() {
                return Verdict::SlashUser {
                    seq: a.state.seq,
                    conflicting: (a.state.commitment(), b.state.commitment()),
                };
            }
        }
    }

    // (3) The relayer is paid against the highest-seq doubly-signed state for
    //     which it can ALSO show a valid proof-of-relay receipt. The cumulative
    //     balance at that state already prices in every unit up to it, so this
    //     single state determines the whole payout; a later (higher-seq)
    //     doubly-signed state with no receipt is simply not claimable.
    let claimable = doubly
        .iter()
        .filter(|s| {
            let c = s.state.commitment();
            receipts.iter().any(|r| r.is_valid_for(relayer_pk, &c))
        })
        .max_by_key(|s| s.state.seq);

    match claimable {
        // The relayer can claim: pay it `B0 - balance` at the claimable state.
        Some(win) => {
            let relayer_payout = b0.saturating_sub(win.state.balance);
            Verdict::Settle {
                winning_seq: win.state.seq,
                relayer_payout,
                user_refund: b0 - relayer_payout,
            }
        }
        // (4) No claimable unit. Either the relayer never advanced the channel
        //     (no doubly-signed state at all) or it advanced but withheld the
        //     relay (no receipt) — both are relayer-dark from the user's safety
        //     standpoint: refund-on-timeout returns the user's full balance.
        None => Verdict::RefundUser { user_refund: b0 },
    }
}
