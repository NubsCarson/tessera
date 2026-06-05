//! Negative-path tests for the Spilman channel **protocol state machine**.
//!
//! `tests/protocol.rs` proves the *positive* flow (an honest round trip settles)
//! and a handful of refusals; this file is the dedicated adversarial sweep of the
//! `RelayerChannel::verify_and_cosign` gate and the [`ChannelState`] successor
//! rule. For each attack object it asserts the protocol returns the **specific**
//! `Err` (never panics, never silently accepts):
//!
//!   1. a **non-monotone** state — balance *increased* → `BadTransition(BalanceIncreased)`,
//!      and `seq` not exactly `prev.seq + 1` → `BadTransition(NonMonotoneSeq)`;
//!   2. a spend with a **forged / wrong-key** state signature → `BadSignature`;
//!   3. a **replayed nonce** already consumed this epoch → `StaleFreshness`;
//!   4. an **over-budget** spend (`cost > balance`) → `Underflow`;
//!   5. a **malformed / zero** state (tampered chan_id, changed salt, and a
//!      zeroed genesis under the wrong params) → the appropriate `BadTransition`.
//!
//! Everything uses only the public `Channel` / `UserChannel` / `RelayerChannel` /
//! `Spend` / `SignedState` API and the same EVM-native secp256k1 crypto the rest
//! of the crate uses (so a forged signature is a *real* signature under a foreign
//! key, exactly the adversary the on-chain `ecrecover` court must reject).

use rand_core::OsRng;

use tessera_channel::state::StateError;
use tessera_channel::{Channel, ChannelError, ChannelState, KeyPair, RelayerChannel, UserChannel};

const B0: u64 = 1_000;
const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [42u8; 32];
const EPOCH: u64 = 1;

/// Stand up a freshly-opened channel plus both sides, sharing one set of keys.
/// Mirrors `tests/protocol.rs::setup` so the negative tests share its conventions.
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

/// 1a. A **balance increase** (the user paying themselves) is rejected by the
///     relayer's successor check with `BadTransition(BalanceIncreased)` — the
///     channel is monotone-*decrementing*. We tamper the proposed state's balance
///     to be HIGHER than the relayer's cursor (genesis `B0`) before co-signing.
#[test]
fn balance_increase_is_rejected() {
    let (_uk, _rk, _chan, user, mut relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");

    // Honest spend, then forge a balance INCREASE into the proposed state.
    let mut spend = user.spend(100, &fresh).unwrap();
    assert_eq!(spend.signed.state.balance, B0 - 100);
    spend.signed.state.balance = B0 + 1; // > genesis balance → "minting"

    let err = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect_err("a balance increase must be rejected, not co-signed");
    assert_eq!(
        err,
        ChannelError::BadTransition(StateError::BalanceIncreased)
    );
    // And the relayer's cursor must NOT have advanced (still at genesis).
    assert_eq!(relayer.latest().seq, 0);
    assert_eq!(relayer.latest().balance, B0);
}

/// 1b. A **non-monotone seq** (skipping ahead, not `prev.seq + 1`) is rejected
///     with `BadTransition(NonMonotoneSeq)`. We bump the proposed seq past the
///     immediate successor.
#[test]
fn non_monotone_seq_is_rejected() {
    let (_uk, _rk, _chan, user, mut relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");

    let mut spend = user.spend(100, &fresh).unwrap();
    assert_eq!(
        spend.signed.state.seq, 1,
        "honest successor of genesis is seq 1"
    );
    spend.signed.state.seq = 5; // skip ahead — relayer cursor is at seq 0

    let err = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect_err("a seq gap must be rejected");
    assert_eq!(err, ChannelError::BadTransition(StateError::NonMonotoneSeq));
    assert_eq!(
        relayer.latest().seq,
        0,
        "cursor must not advance on a bad transition"
    );

    // The same rule is also visible at the pure-state layer with no signatures:
    let genesis = ChannelState::genesis(CHAN_ID, B0, SALT);
    let mut skip = genesis.spend(10).unwrap();
    skip.seq = 3;
    assert_eq!(
        skip.is_successor_of(&genesis),
        Err(StateError::NonMonotoneSeq)
    );
    // A seq that goes BACKWARD (replaying genesis as its own successor) is equally
    // non-monotone — prev.seq + 1 == 1, not 0.
    assert_eq!(
        genesis.is_successor_of(&genesis),
        Err(StateError::NonMonotoneSeq)
    );
}

/// 2. A spend whose `sig_user` is **forged** (a valid secp256k1 signature, but
///    under a FOREIGN key rather than the channel's user key) is rejected with
///    `BadSignature`. The transition and freshness are otherwise honest, so this
///    isolates the user-state-signature check (check #3 in `verify_and_cosign`).
///
///    This is the load-bearing "the user signs every state" property: a state the
///    real user never authorized must not be co-signable.
#[test]
fn forged_user_signature_is_rejected() {
    let (uk, _rk, _chan, user, mut relayer) = setup();
    let mut rng = OsRng;
    let attacker = KeyPair::generate(&mut rng);

    let fresh = relayer.issue_challenge(0, b"packet");
    let mut spend = user.spend(100, &fresh).unwrap();

    // Sanity: the honest signature is valid before we tamper with it.
    assert!(spend.signed.user_sig_valid(&uk.verifying_key()));

    // Replace sig_user with the ATTACKER's signature over the same digest. It is a
    // perfectly valid signature — just under the wrong key — so it must fail the
    // relayer's `user_sig_valid` check against the channel's user pk.
    let digest = spend.signed.state.state_digest();
    spend.signed.sig_user = attacker.sign_digest(&digest);
    assert!(
        !spend.signed.user_sig_valid(&uk.verifying_key()),
        "the forged sig must NOT verify under the real user key"
    );

    let err = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect_err("a state signed by the wrong key must be rejected");
    assert_eq!(err, ChannelError::BadSignature);
    assert_eq!(
        relayer.latest().seq,
        0,
        "no co-sign on a forged user signature"
    );
}

/// 2b. A spend whose `sig_user` is valid but binds a DIFFERENT state (signed over
///     a different digest) is also `BadSignature`: the relayer verifies the
///     signature against *this* state's digest, so a copied-over signature from an
///     unrelated state does not authorize it.
#[test]
fn signature_bound_to_a_different_state_is_rejected() {
    let (uk, _rk, _chan, user, mut relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");

    // Two honest spends of DIFFERENT cost ⇒ two different state digests/sigs.
    let spend_a = user.spend(100, &fresh).unwrap();
    let spend_b = user.spend(200, &fresh).unwrap();
    assert_ne!(
        spend_a.signed.state.state_digest(),
        spend_b.signed.state.state_digest()
    );

    // Graft B's (validly user-signed) signature onto A's state. The signature is
    // real and the user's — but it does not bind A's digest.
    let mut frankenspend = spend_a.clone();
    frankenspend.signed.sig_user = spend_b.signed.sig_user.clone();
    assert!(
        !frankenspend.signed.user_sig_valid(&uk.verifying_key()),
        "a sig over B's digest must not verify against A's digest"
    );

    let err = relayer
        .verify_and_cosign(&frankenspend, &fresh)
        .expect_err("a signature bound to a different state must be rejected");
    assert_eq!(err, ChannelError::BadSignature);
}

/// 3. A **replayed nonce within an epoch** is rejected with `StaleFreshness`.
///    We consume nonce 7 with a first honest spend (which advances the relayer's
///    cursor to seq 1), then build a *fresh, valid* seq-2 successor but reuse the
///    SAME nonce 7 in the same epoch. The transition (seq 2 from cursor 1) and the
///    user signature are both good, so the only thing that can bite is the burned
///    nonce — isolating the replay-defense check.
#[test]
fn replayed_nonce_within_epoch_is_rejected() {
    let (_uk, _rk, _chan, mut user, mut relayer) = setup();

    // First spend on nonce 7 — accepted, burns nonce 7, cursor → seq 1.
    let fresh1 = relayer.issue_challenge(7, b"request-1");
    let spend1 = user.spend(100, &fresh1).unwrap();
    let cosigned1 = relayer.verify_and_cosign(&spend1, &fresh1).unwrap();
    user.accept_cosigned(&cosigned1).unwrap();
    assert_eq!(relayer.latest().seq, 1);

    // Build a genuinely-fresh seq-2 successor, but REUSE nonce 7 in the same epoch.
    // We must hand `verify_and_cosign` a `fresh` whose epoch+nonce equal the burned
    // challenge AND that the user's sig_fresh was actually signed over, otherwise
    // an unrelated freshness would trip the binding check instead of the nonce-set
    // check. Re-issuing nonce 7 gives the identical RelayRequest bytes.
    let replay_fresh = relayer.issue_challenge(7, b"request-1");
    assert_eq!(
        replay_fresh, fresh1,
        "re-issued challenge is byte-identical"
    );
    let spend2 = user.spend(50, &replay_fresh).unwrap();
    assert_eq!(
        spend2.signed.state.seq, 2,
        "valid successor of the seq-1 cursor"
    );

    let err = relayer
        .verify_and_cosign(&spend2, &replay_fresh)
        .expect_err("a nonce already consumed this epoch must be rejected");
    assert_eq!(err, ChannelError::StaleFreshness);
    // The cursor must not have advanced past the legitimately-accepted seq 1.
    assert_eq!(
        relayer.latest().seq,
        1,
        "a replayed nonce must not move the cursor"
    );
}

/// 3b. A spend carrying a **stale epoch** (an epoch the relayer is no longer in)
///     is rejected with `StaleFreshness`, even with an unused nonce — freshness is
///     (epoch AND unconsumed-nonce). We advance the relayer's epoch, then replay a
///     spend bound to the old epoch.
#[test]
fn stale_epoch_is_rejected() {
    let (_uk, _rk, _chan, user, mut relayer) = setup();

    // A spend bound to the original epoch / nonce 0.
    let fresh_old = relayer.issue_challenge(0, b"packet");
    let spend = user.spend(100, &fresh_old).unwrap();

    // Relayer moves to a new epoch (resetting the nonce budget). The spend is now
    // bound to a stale epoch.
    relayer.advance_epoch(EPOCH + 1).unwrap();

    let err = relayer
        .verify_and_cosign(&spend, &fresh_old)
        .expect_err("a spend bound to a past epoch must be rejected");
    assert_eq!(err, ChannelError::StaleFreshness);
}

/// 4. An **over-budget** spend (`cost > balance`) is rejected at the user side
///    with `Underflow` (the monotone-decrement would underflow the escrow) — the
///    user can't even *construct* the spend, so a forged over-spend never reaches
///    the relayer. Boundary: draining to exactly zero is allowed.
#[test]
fn over_budget_spend_is_rejected() {
    let (_uk, _rk, _chan, user, relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");

    let err = user
        .spend(B0 + 1, &fresh)
        .expect_err("spending more than the balance must underflow");
    assert_eq!(
        err,
        ChannelError::Underflow {
            balance: B0,
            cost: B0 + 1,
        }
    );

    // Even a 1-over-budget spend underflows (off-by-one boundary on the wrong side).
    assert_eq!(
        user.spend(B0 + 1, &fresh).err(),
        Some(ChannelError::Underflow {
            balance: B0,
            cost: B0 + 1
        })
    );

    // Boundary: draining to exactly zero is allowed (cost == balance).
    let drained = user.spend(B0, &fresh).expect("draining to zero is allowed");
    assert_eq!(drained.signed.state.balance, 0);

    // The pure-state layer agrees: `spend` returns None on underflow rather than
    // panicking or wrapping around (it must not mint balance via wraparound).
    let genesis = ChannelState::genesis(CHAN_ID, B0, SALT);
    assert!(genesis.spend(B0 + 1).is_none());
    assert_eq!(genesis.spend(B0).unwrap().balance, 0);
}

/// 5a. A **malformed** state that names a DIFFERENT channel (tampered `chan_id`)
///     or carries a CHANGED `salt` is rejected with the appropriate
///     `BadTransition`, both at the relayer gate and the pure-state layer. These
///     are checked before signatures, so the relayer never co-signs a foreign
///     state.
#[test]
fn malformed_chan_id_or_salt_is_rejected() {
    let (_uk, _rk, _chan, user, mut relayer) = setup();

    // Tampered chan_id.
    let fresh = relayer.issue_challenge(0, b"packet");
    let mut spend = user.spend(100, &fresh).unwrap();
    spend.signed.state.chan_id = [0xAB; 32];
    let err = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect_err("a state for a different channel must be rejected");
    assert_eq!(err, ChannelError::BadTransition(StateError::ChanIdMismatch));
    assert_eq!(relayer.latest().seq, 0);

    // Changed salt (the salt is fixed from genesis for the channel's life).
    let fresh2 = relayer.issue_challenge(1, b"packet");
    let mut spend2 = user.spend(100, &fresh2).unwrap();
    spend2.signed.state.salt = [0xCD; 32];
    let err2 = relayer
        .verify_and_cosign(&spend2, &fresh2)
        .expect_err("a state with a changed salt must be rejected");
    assert_eq!(err2, ChannelError::BadTransition(StateError::SaltChanged));
    assert_eq!(relayer.latest().seq, 0);

    // Pure-state layer mirrors both rejections.
    let genesis = ChannelState::genesis(CHAN_ID, B0, SALT);
    let good = genesis.spend(10).unwrap();
    let mut wrong_chan = good;
    wrong_chan.chan_id = [0u8; 32];
    assert_eq!(
        wrong_chan.is_successor_of(&genesis),
        Err(StateError::ChanIdMismatch)
    );
    let mut wrong_salt = good;
    wrong_salt.salt = [0u8; 32];
    assert_eq!(
        wrong_salt.is_successor_of(&genesis),
        Err(StateError::SaltChanged)
    );
}

/// 5b. A **zeroed / wrong-genesis** state — a state whose every field has been
///     blanked (chan_id = 0, balance = 0, seq = 0, salt = 0) is NOT a valid
///     successor of the real genesis: it names a different channel. The successor
///     check returns an `Err` rather than treating the all-zero state as a no-op
///     spend. (A zero state that *did* match the channel would be caught as a seq
///     non-advance instead — also an `Err`, never accepted.)
#[test]
fn zero_state_is_not_a_valid_successor() {
    let genesis = ChannelState::genesis(CHAN_ID, B0, SALT);

    // The fully-zeroed state names channel 0 ≠ CHAN_ID ⇒ ChanIdMismatch.
    let zero = ChannelState {
        chan_id: [0u8; 32],
        balance: 0,
        seq: 0,
        salt: [0u8; 32],
    };
    assert_eq!(
        zero.is_successor_of(&genesis),
        Err(StateError::ChanIdMismatch),
        "an all-zero state must not be accepted as a successor"
    );

    // A zero-balance state that DOES match the channel/salt still fails because
    // its seq did not advance (seq 0, not genesis.seq + 1 == 1).
    let zero_balance_same_chan = ChannelState {
        chan_id: CHAN_ID,
        balance: 0,
        seq: 0,
        salt: SALT,
    };
    assert_eq!(
        zero_balance_same_chan.is_successor_of(&genesis),
        Err(StateError::NonMonotoneSeq)
    );

    // Driven through the relayer gate too: a zeroed state never co-signs.
    let (_uk, _rk, _chan, user, mut relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");
    let mut spend = user.spend(100, &fresh).unwrap();
    spend.signed.state = zero;
    let err = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect_err("a zeroed state must be rejected by the relayer");
    assert!(
        matches!(err, ChannelError::BadTransition(_)),
        "expected a transition rejection for the zero state, got {err:?}"
    );
    assert_eq!(relayer.latest().seq, 0, "cursor unmoved by a zeroed state");
}

/// 6. Cross-check that an UNTAMPERED honest spend through the same gate is
///    ACCEPTED. Without this, every negative test above could be passing for a
///    trivial reason (e.g. the gate rejecting *everything*); this anchors them by
///    proving the gate co-signs a legitimate spend and advances the cursor.
#[test]
fn honest_spend_is_accepted_anchor() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");
    let spend = user.spend(100, &fresh).unwrap();

    let cosigned = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect("an honest, untampered spend MUST be accepted");
    assert_eq!(cosigned.state.seq, 1);
    assert_eq!(cosigned.state.balance, B0 - 100);
    assert!(cosigned.is_doubly_signed(&uk.verifying_key(), &rk.verifying_key()));
    assert_eq!(
        relayer.latest().seq,
        1,
        "cursor advances on an honest spend"
    );
    user.accept_cosigned(&cosigned)
        .expect("user adopts the doubly-signed state");
}
