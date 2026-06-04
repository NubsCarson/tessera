//! Proof-of-work issuance gate tests.

use rand_core::OsRng;
use tessera_issuer::{solve, ChallengeStore, PowChallenge, PowSolution};

#[test]
fn solved_challenge_verifies_and_meets_difficulty() {
    for difficulty in [1u32, 8, 16] {
        let challenge = PowChallenge::new(&mut OsRng, difficulty);
        let solution = solve(&challenge);
        assert!(challenge.verify(&solution), "solved challenge must verify");
    }
}

#[test]
fn a_solution_does_not_verify_against_a_different_challenge() {
    // Cross-challenge: a solution for A must not satisfy B (difficulty 20 makes a
    // chance match ~2^-20, i.e. negligibly rare).
    let a = PowChallenge::new(&mut OsRng, 20);
    let b = PowChallenge::new(&mut OsRng, 20);
    let sol_a = solve(&a);
    assert!(a.verify(&sol_a));
    assert!(
        !b.verify(&sol_a),
        "solution must be bound to its own challenge"
    );
}

#[test]
fn zero_difficulty_is_trivially_satisfiable() {
    let challenge = PowChallenge::new(&mut OsRng, 0);
    assert!(challenge.verify(&PowSolution { counter: 0 }));
}

#[test]
fn challenge_store_is_one_time_and_anti_replay() {
    let mut rng = OsRng;
    let mut store = ChallengeStore::new();

    // Issue a challenge, solve it, redeem it once.
    let challenge = store.issue(&mut rng, 12);
    let solution = solve(&challenge);
    assert!(store.redeem(&challenge, &solution), "first redeem succeeds");

    // The same challenge cannot be redeemed twice.
    assert!(
        !store.redeem(&challenge, &solution),
        "redeeming a spent challenge must fail"
    );

    // A challenge the store never issued is rejected even with a valid solution.
    let foreign = PowChallenge::new(&mut rng, 12);
    let foreign_sol = solve(&foreign);
    assert!(foreign.verify(&foreign_sol));
    assert!(
        !store.redeem(&foreign, &foreign_sol),
        "a challenge we never issued must not be redeemable"
    );
}

#[test]
fn store_rejects_an_invalid_solution_and_keeps_the_challenge() {
    let mut rng = OsRng;
    let mut store = ChallengeStore::new();
    let challenge = store.issue(&mut rng, 20);

    // A bogus counter (difficulty 20 -> ~2^-20 chance of accidental success).
    assert!(!store.redeem(&challenge, &PowSolution { counter: 1 }));

    // The real solution still works afterwards (the challenge wasn't consumed).
    let solution = solve(&challenge);
    assert!(store.redeem(&challenge, &solution));
}
