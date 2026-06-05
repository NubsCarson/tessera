//! End-to-end **multi-spend** integration test for the ZK Spilman channel.
//!
//! Drives a single channel through MANY sequential spends — each a full
//! sign-then-serve round trip ([`UserChannel::spend`] →
//! [`RelayerChannel::verify_and_cosign`] → [`UserChannel::accept_cosigned`]) —
//! and asserts the running balance decrements monotonically, every co-signed
//! state is the immediate valid successor of the last, the spend that *would*
//! exceed the remaining budget is REJECTED (and leaves both cursors untouched),
//! and the final off-chain [`settle`] verdict pays the relayer exactly the
//! cumulative spent and refunds the user the surviving balance.
//!
//! Style mirrors `tests/protocol.rs` (shared `setup`/`round_trip` helpers,
//! `OsRng` keys, plain secp256k1 crypto, no ZK).

use rand_core::OsRng;

use tessera_channel::settlement::{settle, Verdict};
use tessera_channel::{
    Channel, ChannelError, ChannelState, KeyPair, RelayAck, RelayerChannel, SignedState,
    UserChannel,
};

const B0: u64 = 1_000;
const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [42u8; 32];
const EPOCH: u64 = 1;

/// Stand up a freshly-opened channel plus both sides, sharing one set of keys.
fn setup() -> (KeyPair, KeyPair, Channel, UserChannel, RelayerChannel) {
    let mut rng = OsRng;
    let user_keys = KeyPair::generate(&mut rng);
    let relayer_keys = KeyPair::generate(&mut rng);
    let chan = Channel::open(
        CHAN_ID,
        B0,
        SALT,
        user_keys.verifying_key(),
        relayer_keys.verifying_key(),
    );
    let user = UserChannel::new(user_keys.clone(), chan.clone());
    let relayer = RelayerChannel::new(relayer_keys.clone(), chan.clone(), EPOCH);
    (user_keys, relayer_keys, chan, user, relayer)
}

/// One full honest round trip for `cost` against the `nonce`-th request, driving
/// the cursor on both sides and returning the doubly-signed state + its receipt.
fn round_trip(
    user: &mut UserChannel,
    relayer: &mut RelayerChannel,
    cost: u64,
    nonce: u64,
) -> (SignedState, RelayAck) {
    let payload = format!("onion-packet-{nonce}");
    let fresh = relayer.issue_challenge(nonce, payload.as_bytes());

    let spend = user.spend(cost, &fresh).expect("within balance");
    let cosigned = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect("honest spend verifies");
    user.accept_cosigned(&cosigned).expect("co-sig good");
    let ack = relayer.issue_relay_ack(&cosigned.state);
    (cosigned, ack)
}

/// A real, long end-to-end multi-spend: 40 sequential unit-cost spends, each
/// verified and co-signed by the relayer. Asserts, *at every step*:
///   * the running balance decrements by exactly `cost` (monotone),
///   * the co-signed state is the immediate successor of the previous one
///     (`seq` bumps by one, `is_successor_of` holds, commitment changed),
///   * the state is doubly-signed, and both cursors agree.
///
/// Then settles and checks the relayer is paid the cumulative spent.
#[test]
fn many_spends_decrement_and_settle() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();
    let upk = uk.verifying_key();
    let rpk = rk.verifying_key();

    // Heterogeneous, deterministic costs that sum to < B0, repeated to make a
    // genuinely long chain (40 round trips). 1+7+3+11+5+13+2+9 = 51 per block.
    let pattern = [1u64, 7, 3, 11, 5, 13, 2, 9];
    let n = 40usize;

    let genesis = _chan.genesis();
    let mut prev: ChannelState = genesis;
    let mut expected_balance = B0;
    let mut total_spent = 0u64;
    let mut states: Vec<SignedState> = Vec::new();
    let mut receipts: Vec<RelayAck> = Vec::new();

    for i in 0..n {
        let cost = pattern[i % pattern.len()];
        let (cosigned, ack) = round_trip(&mut user, &mut relayer, cost, i as u64);

        // running balance decrements by exactly `cost`.
        expected_balance -= cost;
        total_spent += cost;
        assert_eq!(
            cosigned.state.balance, expected_balance,
            "balance after spend {i} must be B0 minus the cumulative cost"
        );

        // seq advances by exactly one each step (no gaps, no repeats).
        assert_eq!(
            cosigned.state.seq,
            (i + 1) as u64,
            "seq must equal the spend index + 1"
        );

        // each co-signed state is the IMMEDIATE valid successor of the last —
        // this is the load-bearing chain property the relayer enforces.
        cosigned
            .state
            .is_successor_of(&prev)
            .expect("each co-signed state must succeed the previous one");

        // the successor is genuinely a *different* state (commitment moved).
        assert_ne!(
            cosigned.state.commitment(),
            prev.commitment(),
            "a real spend must change the commitment"
        );

        // doubly-signed unit of truth, and both parties' cursors agree on it.
        assert!(
            cosigned.is_doubly_signed(&upk, &rpk),
            "every accepted state must carry BOTH valid signatures"
        );
        assert_eq!(user.latest(), cosigned.state, "user cursor advanced");
        assert_eq!(relayer.latest(), cosigned.state, "relayer cursor advanced");

        prev = cosigned.state;
        states.push(cosigned);
        receipts.push(ack);
    }

    // The chain is monotone-decrementing across the whole run.
    assert!(
        total_spent > 0 && total_spent < B0,
        "test fixture must spend a positive amount strictly under the budget"
    );
    let bn = B0 - total_spent;
    assert_eq!(expected_balance, bn);
    assert_eq!(user.latest().balance, bn);
    assert_eq!(relayer.latest().balance, bn);
    assert_eq!(user.latest().seq, n as u64);

    // Settlement against the full receipt set: highest doubly-signed seq wins,
    // the relayer is paid the cumulative spent, the user refunded the rest.
    let verdict = settle(B0, &upk, &rpk, &states, &receipts);
    assert_eq!(
        verdict,
        Verdict::Settle {
            winning_seq: n as u64,
            relayer_payout: total_spent,
            user_refund: bn,
        },
        "final settled balance must reflect every spend in the chain"
    );
}

/// The Nth spend that would push the cumulative cost OVER the budget is
/// REJECTED — and the rejection is non-destructive: both cursors stay on the
/// last good doubly-signed state, and a *fitting* spend afterward still works.
///
/// We deliberately walk the balance down to a small remainder with honest round
/// trips, then attempt one spend strictly larger than the remaining balance.
#[test]
fn spend_exceeding_remaining_budget_is_rejected() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();
    let upk = uk.verifying_key();
    let rpk = rk.verifying_key();

    // Spend down in honest steps until only `REMAINDER` of the budget is left.
    const REMAINDER: u64 = 30;
    let step: u64 = 97; // arbitrary; (B0 - REMAINDER) = 970 = 10 * 97 exactly.
    let n_steps = (B0 - REMAINDER) / step;
    assert_eq!(n_steps * step, B0 - REMAINDER, "fixture must divide evenly");

    for i in 0..n_steps {
        let (cosigned, _ack) = round_trip(&mut user, &mut relayer, step, i);
        assert_eq!(cosigned.state.balance, B0 - step * (i + 1));
    }

    // Cursors now sit on the last good state with exactly REMAINDER left.
    let good_seq = user.latest().seq;
    let good_state = user.latest();
    assert_eq!(good_state.balance, REMAINDER);
    assert_eq!(relayer.latest(), good_state);

    // Attempt a spend ONE unit over the remaining budget. The user side can't
    // even build the successor (the monotone-decrement would underflow), so it
    // returns Underflow with the real remaining balance — the over-budget spend
    // never produces a signed state.
    let fresh = relayer.issue_challenge(good_seq + 100, b"over-budget");
    let over = user.spend(REMAINDER + 1, &fresh);
    assert_eq!(
        over,
        Err(ChannelError::Underflow {
            balance: REMAINDER,
            cost: REMAINDER + 1,
        }),
        "a spend exceeding the remaining budget must be rejected, not silently clamped"
    );

    // The rejection was non-destructive: neither cursor moved, the last state is
    // still the doubly-signed unit of truth.
    assert_eq!(
        user.latest(),
        good_state,
        "rejected spend must not move the user cursor"
    );
    assert_eq!(
        relayer.latest(),
        good_state,
        "rejected spend must not move the relayer cursor"
    );

    // A spend that *exactly* drains the remaining budget is still accepted right
    // after the rejection — proving the channel wasn't wedged by the failure and
    // the boundary (balance == cost) is honored.
    let (drained, drain_ack) = round_trip(&mut user, &mut relayer, REMAINDER, good_seq + 1);
    assert_eq!(drained.state.balance, 0, "draining to zero is the boundary");
    assert_eq!(drained.state.seq, good_seq + 1);
    drained
        .state
        .is_successor_of(&good_state)
        .expect("the draining spend succeeds the last good state");

    // And once at zero, ANY further positive spend underflows immediately.
    let fresh_zero = relayer.issue_challenge(good_seq + 2, b"after-drain");
    assert_eq!(
        user.spend(1, &fresh_zero),
        Err(ChannelError::Underflow {
            balance: 0,
            cost: 1,
        }),
        "no spend is possible once the budget is fully drained"
    );

    // Final settlement: the relayer is paid the WHOLE budget (it was fully
    // drained), the user refunded nothing.
    let verdict = settle(
        B0,
        &upk,
        &rpk,
        std::slice::from_ref(&drained),
        std::slice::from_ref(&drain_ack),
    );
    assert_eq!(
        verdict,
        Verdict::Settle {
            winning_seq: good_seq + 1,
            relayer_payout: B0,
            user_refund: 0,
        },
        "a fully drained channel pays the relayer the entire budget"
    );
}
