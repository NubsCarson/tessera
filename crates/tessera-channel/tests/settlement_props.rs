//! S4 — property-based tests for `settle()`, the heart of payment correctness.
//!
//! Rather than a few hand-picked vectors, these generate thousands of random
//! channel histories (honest monotone spends, injected equivocations, and noise
//! states the court must ignore) with a deterministic seeded generator, and
//! assert the invariants the on-chain court depends on:
//!
//!   * **Conservation** — every `Settle` has `relayer_payout + user_refund == B0`
//!     and `relayer_payout <= B0` (money is never minted or destroyed).
//!   * **Order-independence** — the verdict is identical no matter what order the
//!     states/receipts are presented in (a hostile submitter can't reorder its way
//!     to a better outcome).
//!   * **Equivocation precedence** — any two doubly-signed states at one seq with
//!     different commitments force `SlashUser`, regardless of receipts or order.
//!   * **Highest-with-receipt wins** — absent equivocation, the payout is set by
//!     the highest-seq doubly-signed state that has a proof-of-relay receipt; with
//!     none, the user is refunded in full (`RefundUser{B0}`).
//!   * **Noise is ignored** — singly-signed and wrong-key states never change the
//!     verdict computed from the genuinely doubly-signed subset.
//!
//! Deterministic (seeded xorshift, no `proptest` dependency — consistent with the
//! rest of this crate's tests) so failures reproduce exactly.

use rand_core::OsRng;

use tessera_channel::state::ChannelState;
use tessera_channel::{settle, KeyPair, RelayAck, SignedState, Verdict};

const B0: u64 = 1_000_000;
const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [9u8; 32];

struct Xs(u64);
impl Xs {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// Uniform in `[0, n)` (returns 0 if n == 0).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        // Fisher–Yates.
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

fn keys() -> (KeyPair, KeyPair, KeyPair) {
    let mut r = OsRng;
    (
        KeyPair::generate(&mut r),
        KeyPair::generate(&mut r),
        KeyPair::generate(&mut r), // mallory (wrong key)
    )
}

fn state(balance: u64, seq: u64) -> ChannelState {
    ChannelState {
        chan_id: CHAN_ID,
        balance,
        seq,
        salt: SALT,
    }
}

fn doubly(uk: &KeyPair, rk: &KeyPair, balance: u64, seq: u64) -> SignedState {
    let st = state(balance, seq);
    let d = st.state_digest();
    SignedState {
        state: st,
        sig_user: uk.sign_digest(&d),
        sig_relayer: Some(rk.sign_digest(&d)),
    }
}

fn user_only(uk: &KeyPair, balance: u64, seq: u64) -> SignedState {
    let st = state(balance, seq);
    SignedState {
        state: st,
        sig_user: uk.sign_digest(&st.state_digest()),
        sig_relayer: None,
    }
}

fn wrong_relayer(uk: &KeyPair, mallory: &KeyPair, balance: u64, seq: u64) -> SignedState {
    let st = state(balance, seq);
    let d = st.state_digest();
    SignedState {
        state: st,
        sig_user: uk.sign_digest(&d),
        sig_relayer: Some(mallory.sign_digest(&d)),
    }
}

fn ack(rk: &KeyPair, s: &SignedState) -> RelayAck {
    RelayAck::issue(rk, s.state.commitment())
}

/// One honest monotone-decrementing history of `n` spends (seq 1..=n), with
/// strictly-decreasing balances, and the (seq -> balance) table.
fn honest_history(uk: &KeyPair, rk: &KeyPair, n: u64, rng: &mut Xs) -> Vec<(SignedState, u64)> {
    let mut out = Vec::new();
    let mut balance = B0;
    for seq in 1..=n {
        let cost = 1 + rng.below(balance / (n - seq + 2)); // strictly positive; (n-seq+2) >= 2
        balance = balance.saturating_sub(cost);
        out.push((doubly(uk, rk, balance, seq), balance));
    }
    out
}

fn assert_conservation(v: &Verdict) {
    if let Verdict::Settle {
        relayer_payout,
        user_refund,
        ..
    } = v
    {
        assert!(*relayer_payout <= B0, "payout exceeds escrow");
        assert_eq!(
            relayer_payout + user_refund,
            B0,
            "payout + refund must equal B0"
        );
    }
}

// ---------------------------------------------------------------------------

/// Honest histories: conservation holds, and the payout is set by the
/// highest-seq doubly-signed state carrying a receipt (or full refund if none).
#[test]
fn honest_history_pays_highest_with_receipt_and_conserves() {
    let (uk, rk, _m) = keys();
    let mut rng = Xs(0x1234_5678_9ABC_DEF1);
    for _ in 0..2_000 {
        let n = 1 + rng.below(6); // 1..=6 spends
        let hist = honest_history(&uk, &rk, n, &mut rng);

        // Give a receipt to a random subset; remember the highest receipted seq.
        let mut states = Vec::new();
        let mut receipts = Vec::new();
        let mut best: Option<(u64, u64)> = None; // (seq, balance)
        for (s, bal) in &hist {
            states.push(s.clone());
            if rng.below(2) == 1 {
                receipts.push(ack(&rk, s));
                let seq = s.state.seq;
                // (avoid Option::is_none_or — that's Rust 1.82; MSRV here is 1.74)
                let take = match best {
                    None => true,
                    Some((bs, _)) => seq > bs,
                };
                if take {
                    best = Some((seq, *bal));
                }
            }
        }

        let v = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &states,
            &receipts,
        );
        assert_conservation(&v);
        match (best, &v) {
            (
                Some((seq, bal)),
                Verdict::Settle {
                    winning_seq,
                    relayer_payout,
                    user_refund,
                },
            ) => {
                assert_eq!(
                    *winning_seq, seq,
                    "winning seq must be the highest receipted one"
                );
                assert_eq!(*relayer_payout, B0 - bal, "payout = B0 - balance@winning");
                assert_eq!(*user_refund, bal, "refund = balance@winning");
            }
            (None, Verdict::RefundUser { user_refund }) => {
                assert_eq!(*user_refund, B0, "no receipt anywhere → full refund");
            }
            other => panic!("unexpected (best, verdict): {other:?}"),
        }
    }
}

/// The verdict is invariant under reordering of both states and receipts.
#[test]
fn verdict_is_order_independent() {
    let (uk, rk, m) = keys();
    let mut rng = Xs(0xCAFE_F00D_1357_9BDF);
    for _ in 0..2_000 {
        let n = 1 + rng.below(6);
        let hist = honest_history(&uk, &rk, n, &mut rng);
        let mut states: Vec<SignedState> = hist.iter().map(|(s, _)| s.clone()).collect();
        // Sprinkle in ignorable noise so ordering has more to chew on.
        if rng.below(2) == 1 {
            states.push(user_only(&uk, rng.below(B0), 1 + rng.below(n)));
        }
        if rng.below(2) == 1 {
            states.push(wrong_relayer(&uk, &m, rng.below(B0), 1 + rng.below(n)));
        }
        let mut receipts: Vec<RelayAck> = hist
            .iter()
            .filter(|_| rng.below(2) == 1)
            .map(|(s, _)| ack(&rk, s))
            .collect();

        let v1 = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &states,
            &receipts,
        );
        rng.shuffle(&mut states);
        rng.shuffle(&mut receipts);
        let v2 = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &states,
            &receipts,
        );
        assert_eq!(v1, v2, "settle must not depend on input order");
        assert_conservation(&v1);
    }
}

/// Any doubly-signed equivocation at one seq forces SlashUser, regardless of
/// receipts, noise, or order.
#[test]
fn equivocation_always_slashes() {
    let (uk, rk, _m) = keys();
    let mut rng = Xs(0x0BAD_C0DE_DEAD_BEEF);
    for _ in 0..2_000 {
        let n = 1 + rng.below(5);
        let hist = honest_history(&uk, &rk, n, &mut rng);
        let mut states: Vec<SignedState> = hist.iter().map(|(s, _)| s.clone()).collect();

        // Inject a conflicting doubly-signed state at an existing seq with a
        // DIFFERENT balance → different commitment → equivocation.
        let victim_seq = 1 + rng.below(n);
        let orig_bal = hist[(victim_seq - 1) as usize].1;
        let conflict_bal = orig_bal ^ 1; // guaranteed different
        states.push(doubly(&uk, &rk, conflict_bal, victim_seq));

        // Add receipts + noise to prove they don't suppress the slash.
        let receipts: Vec<RelayAck> = hist.iter().map(|(s, _)| ack(&rk, s)).collect();
        states.push(user_only(&uk, rng.below(B0), 1 + rng.below(n)));
        rng.shuffle(&mut states);

        let v = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &states,
            &receipts,
        );
        match v {
            Verdict::SlashUser { conflicting, .. } => {
                assert_ne!(
                    conflicting.0, conflicting.1,
                    "the fraud proof must be two distinct commitments"
                );
            }
            other => panic!("equivocation must slash, got {other:?}"),
        }
    }
}

/// Singly-signed and wrong-key states never change the verdict computed from the
/// doubly-signed subset alone.
#[test]
fn noise_states_do_not_change_the_verdict() {
    let (uk, rk, m) = keys();
    let mut rng = Xs(0xFEED_FACE_5EED_1234);
    for _ in 0..2_000 {
        let n = 1 + rng.below(6);
        let hist = honest_history(&uk, &rk, n, &mut rng);
        let clean: Vec<SignedState> = hist.iter().map(|(s, _)| s.clone()).collect();
        let receipts: Vec<RelayAck> = hist
            .iter()
            .filter(|_| rng.below(2) == 1)
            .map(|(s, _)| ack(&rk, s))
            .collect();

        let baseline = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &clean,
            &receipts,
        );

        // Same history + arbitrary noise the court must ignore.
        let mut noisy = clean.clone();
        for _ in 0..rng.below(4) {
            let seq = 1 + rng.below(n + 2);
            let bal = rng.below(B0 + 1);
            if rng.below(2) == 1 {
                noisy.push(user_only(&uk, bal, seq));
            } else {
                noisy.push(wrong_relayer(&uk, &m, bal, seq));
            }
        }
        rng.shuffle(&mut noisy);
        let noisy_verdict = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &noisy,
            &receipts,
        );
        assert_eq!(
            baseline, noisy_verdict,
            "noise states must not change the verdict"
        );
    }
}

/// No genuinely doubly-signed state (only noise) ⇒ full refund.
#[test]
fn no_doubly_signed_refunds_in_full() {
    let (uk, rk, m) = keys();
    let mut rng = Xs(0x5151_5151_2727_2727);
    for _ in 0..1_000 {
        let mut states = Vec::new();
        for _ in 0..(1 + rng.below(5)) {
            let seq = 1 + rng.below(5);
            let bal = rng.below(B0);
            if rng.below(2) == 1 {
                states.push(user_only(&uk, bal, seq));
            } else {
                states.push(wrong_relayer(&uk, &m, bal, seq));
            }
        }
        // A receipt for a commitment no doubly-signed state carries changes nothing.
        let receipts = vec![ack(&rk, &states[0])];
        let v = settle(
            B0,
            &uk.verifying_key(),
            &rk.verifying_key(),
            &states,
            &receipts,
        );
        assert_eq!(v, Verdict::RefundUser { user_refund: B0 });
    }
}
