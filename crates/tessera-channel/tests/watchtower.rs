//! Tests for the Spilman channel watchtower (M2).
//!
//! The watchtower's job: hold the highest doubly-signed state, and on observing
//! an on-chain unilateral close at a stale seq, challenge with that latest state.
//! Its decision mirrors the on-chain `challenge` precondition
//! (`contracts/ChannelRegistry.sol`): `state.seq > bestSeq`, `balance <= B0`,
//! both signatures valid. These tests prove the decision logic and that the
//! state it would submit always satisfies that precondition.

use rand_core::OsRng;

use tessera_channel::state::ChannelState;
use tessera_channel::watchtower::{Watchtower, WatchtowerAction};
use tessera_channel::{Channel, KeyPair, RelayerChannel, SignedState, UserChannel};

const B0: u64 = 1_000;
const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [42u8; 32];
const EPOCH: u64 = 1;

fn setup() -> (KeyPair, KeyPair, Channel, UserChannel, RelayerChannel) {
    let mut rng = OsRng;
    let uk = KeyPair::generate(&mut rng);
    let rk = KeyPair::generate(&mut rng);
    let chan = Channel::open(CHAN_ID, B0, SALT, uk.verifying_key(), rk.verifying_key());
    let user = UserChannel::new(uk.clone(), chan.clone());
    let relayer = RelayerChannel::new(rk.clone(), chan.clone(), EPOCH);
    (uk, rk, chan, user, relayer)
}

/// One honest round trip; returns the doubly-signed state at the new seq.
fn advance(
    user: &mut UserChannel,
    relayer: &mut RelayerChannel,
    cost: u64,
    nonce: u64,
) -> SignedState {
    let fresh = relayer.issue_challenge(nonce, format!("packet-{nonce}").as_bytes());
    let spend = user.spend(cost, &fresh).expect("within balance");
    let cosigned = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect("honest spend verifies");
    user.accept_cosigned(&cosigned).expect("co-sig good");
    cosigned
}

/// Drive N spends of `cost` each; return the doubly-signed states[1..=N] in order.
fn states_1_to_n(n: u64, cost: u64) -> (KeyPair, KeyPair, Channel, Vec<SignedState>) {
    let (uk, rk, chan, mut user, mut relayer) = setup();
    let mut states = Vec::new();
    for i in 0..n {
        states.push(advance(&mut user, &mut relayer, cost, i));
    }
    (uk, rk, chan, states)
}

// ----- core behavior --------------------------------------------------------

#[test]
fn challenges_a_stale_close_with_the_latest_state() {
    let (_uk, _rk, chan, states) = states_1_to_n(3, 100); // seqs 1,2,3
    let mut tower = Watchtower::new(chan);
    for s in &states {
        assert!(tower.witness(s), "each fresh higher-seq state is adopted");
    }
    assert_eq!(tower.best_seq(), Some(3));

    // A close at genesis (seq 0) or any seq < 3 must be challenged with seq 3.
    for stale in 0..3 {
        match tower.on_dispute_started(stale) {
            WatchtowerAction::Challenge(s) => {
                assert_eq!(s.state.seq, 3, "challenge with the latest state");
                assert!(
                    s.state.seq > stale,
                    "satisfies the court's seq>bestSeq precondition"
                );
                assert!(s.state.balance <= B0, "satisfies balance<=B0");
            }
            WatchtowerAction::NoAction => {
                panic!("should have challenged a stale close at seq {stale}")
            }
        }
    }
}

#[test]
fn no_action_when_close_is_already_latest_or_newer() {
    let (_uk, _rk, chan, states) = states_1_to_n(3, 100);
    let mut tower = Watchtower::new(chan);
    for s in &states {
        tower.witness(s);
    }
    // Close at the latest seq the tower holds → nothing to override.
    assert_eq!(tower.on_dispute_started(3), WatchtowerAction::NoAction);
    // Close at a seq beyond what the tower has seen → also nothing it can do.
    assert_eq!(tower.on_dispute_started(4), WatchtowerAction::NoAction);
}

#[test]
fn empty_tower_never_challenges() {
    let (_uk, _rk, chan, _user, _relayer) = setup();
    let tower = Watchtower::new(chan);
    assert_eq!(tower.best_seq(), None);
    for d in 0..5 {
        assert_eq!(tower.on_dispute_started(d), WatchtowerAction::NoAction);
    }
}

#[test]
fn keeps_the_highest_regardless_of_witness_order() {
    let (_uk, _rk, chan, states) = states_1_to_n(5, 100); // seqs 1..=5
    let mut tower = Watchtower::new(chan);

    // Witness out of order: 3, then 1 (stale), then 5, then 2 (stale), then 4 (stale).
    assert!(tower.witness(&states[2]), "seq 3 adopted");
    assert!(!tower.witness(&states[0]), "seq 1 is stale → not adopted");
    assert!(tower.witness(&states[4]), "seq 5 adopted");
    assert!(!tower.witness(&states[1]), "seq 2 is stale → not adopted");
    assert!(!tower.witness(&states[3]), "seq 4 is stale → not adopted");

    assert_eq!(tower.best_seq(), Some(5));
    match tower.on_dispute_started(2) {
        WatchtowerAction::Challenge(s) => assert_eq!(s.state.seq, 5),
        WatchtowerAction::NoAction => panic!("must challenge"),
    }
}

#[test]
fn re_witnessing_the_same_seq_is_ignored() {
    let (_uk, _rk, chan, states) = states_1_to_n(2, 100);
    let mut tower = Watchtower::new(chan);
    assert!(tower.witness(&states[1]), "seq 2 adopted");
    assert!(
        !tower.witness(&states[1]),
        "same seq again → not re-adopted"
    );
    assert!(!tower.witness(&states[0]), "lower seq → not adopted");
    assert_eq!(tower.best_seq(), Some(2));
}

// ----- input validation (only states the court would accept are adopted) ----

#[test]
fn rejects_a_state_for_a_foreign_channel() {
    let (uk, rk, chan, _user, _relayer) = setup();
    let mut tower = Watchtower::new(chan);
    // A doubly-signed state, but for a DIFFERENT channel id.
    let foreign = ChannelState {
        chan_id: [9u8; 32],
        balance: 900,
        seq: 1,
        salt: SALT,
    };
    let s = doubly_sign(&uk, &rk, foreign);
    assert!(!tower.witness(&s), "foreign-channel state must be rejected");
    assert_eq!(tower.best_seq(), None);
}

#[test]
fn rejects_a_state_with_a_changed_salt() {
    let (uk, rk, chan, _user, _relayer) = setup();
    let mut tower = Watchtower::new(chan);
    let wrong_salt = ChannelState {
        chan_id: CHAN_ID,
        balance: 900,
        seq: 1,
        salt: [0u8; 32],
    };
    let s = doubly_sign(&uk, &rk, wrong_salt);
    assert!(!tower.witness(&s), "salt mismatch must be rejected");
}

#[test]
fn rejects_a_balance_exceeding_b0() {
    let (uk, rk, chan, _user, _relayer) = setup();
    let mut tower = Watchtower::new(chan);
    // balance > B0 is a state the court would reject (BALANCE_GT_B0); the tower
    // must not adopt it either, even though it is doubly-signed.
    let over = ChannelState {
        chan_id: CHAN_ID,
        balance: B0 + 1,
        seq: 1,
        salt: SALT,
    };
    let s = doubly_sign(&uk, &rk, over);
    assert!(!tower.witness(&s), "balance>B0 must be rejected");
}

#[test]
fn rejects_a_singly_signed_state() {
    let (uk, _rk, chan, _user, _relayer) = setup();
    let mut tower = Watchtower::new(chan);
    let st = ChannelState {
        chan_id: CHAN_ID,
        balance: 900,
        seq: 1,
        salt: SALT,
    };
    // Only the user signed; relayer co-signature absent.
    let single = SignedState {
        state: st,
        sig_user: uk.sign_digest(&st.state_digest()),
        sig_relayer: None,
    };
    assert!(
        !tower.witness(&single),
        "a state without the relayer co-sig must be rejected"
    );
}

#[test]
fn rejects_a_state_signed_by_the_wrong_party() {
    let (uk, _rk, chan, _user, _relayer) = setup();
    let mut rng = OsRng;
    let mallory = KeyPair::generate(&mut rng);
    let mut tower = Watchtower::new(chan);
    let st = ChannelState {
        chan_id: CHAN_ID,
        balance: 900,
        seq: 1,
        salt: SALT,
    };
    // "relayer" slot is actually mallory's signature → not doubly-signed by the
    // registered relayer.
    let forged = SignedState {
        state: st,
        sig_user: uk.sign_digest(&st.state_digest()),
        sig_relayer: Some(mallory.sign_digest(&st.state_digest())),
    };
    assert!(
        !tower.witness(&forged),
        "wrong relayer key must be rejected"
    );
}

// ----- bounded-exhaustive property -------------------------------------------

/// For every prefix of witnessed states and every observed dispute seq, the
/// action is `Challenge(best)` iff `best_seq > disputed_seq`, and any challenged
/// state satisfies the court's full `challenge` precondition. (Deterministic and
/// exhaustive over a small range — no proptest dependency needed.)
#[test]
fn exhaustive_decision_matches_court_precondition() {
    const N: u64 = 5;
    let (uk, rk, chan, states) = states_1_to_n(N, 100); // seqs 1..=N, balances 900..500

    // Try witnessing the first `k` states (k = 0..=N), then every dispute seq.
    for k in 0..=N as usize {
        let mut tower = Watchtower::new(chan.clone());
        for s in states.iter().take(k) {
            assert!(tower.witness(s));
        }
        let expected_best = if k == 0 { None } else { Some(k as u64) };
        assert_eq!(tower.best_seq(), expected_best);

        for disputed in 0..=(N + 1) {
            let action = tower.on_dispute_started(disputed);
            match (expected_best, action) {
                (Some(b), WatchtowerAction::Challenge(s)) => {
                    assert!(b > disputed, "challenge only when best>disputed");
                    assert_eq!(s.state.seq, b, "challenge uses the highest state");
                    // The court's `challenge` precondition, in full:
                    assert!(s.state.seq > disputed, "seq>bestSeq");
                    assert!(s.state.balance <= B0, "balance<=B0");
                    assert!(
                        s.is_doubly_signed(&uk.verifying_key(), &rk.verifying_key()),
                        "doubly-signed"
                    );
                }
                (Some(b), WatchtowerAction::NoAction) => {
                    assert!(b <= disputed, "no-action only when best<=disputed");
                }
                (None, WatchtowerAction::NoAction) => {} // empty tower: correct
                (None, WatchtowerAction::Challenge(_)) => {
                    panic!("empty tower must never challenge")
                }
            }
        }
    }
}

// ----- helper ---------------------------------------------------------------

/// Build a `SignedState` doubly-signed by `uk` (user) and `rk` (relayer) over the
/// state's chain-facing digest — used to construct adversarial/edge states the
/// honest flow would never emit.
fn doubly_sign(uk: &KeyPair, rk: &KeyPair, state: ChannelState) -> SignedState {
    let d = state.state_digest();
    SignedState {
        state,
        sig_user: uk.sign_digest(&d),
        sig_relayer: Some(rk.sign_digest(&d)),
    }
}
