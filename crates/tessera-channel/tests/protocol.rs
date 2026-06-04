//! Protocol state-machine tests for the ZK Spilman channel (Phase 2a).
//!
//! These cover exactly the cases the red-team flagged in `DESIGN.md` §2:
//!   1. honest N-spend sequence + settlement,
//!   2. user equivocation → slash,
//!   3. relayer withholding (no proof-of-relay) → unclaimable + refund-on-timeout,
//!   4. replay of a spend bound to one epoch/nonce/request,
//!   5. sign-then-serve ordering,
//!   6. balance underflow.
//!
//! Everything is plain crypto (P-256 ECDSA + SHA-256). No ZK, no chain — those
//! are Phase 2b / 2c and wrap this logic later.

use rand_core::OsRng;

use tessera_channel::settlement::{settle, Verdict};
use tessera_channel::{
    Channel, ChannelError, KeyPair, RelayAck, RelayerChannel, SignedState, UserChannel,
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

    // user: spend (signs S_{i+1} + a freshness binding) — relayer sig absent.
    let spend = user.spend(cost, &fresh).expect("within balance");
    assert!(
        spend.signed.sig_relayer.is_none(),
        "user must not forge a co-sig"
    );

    // relayer: verify + co-sign BEFORE serving (sign-then-serve).
    let cosigned = relayer
        .verify_and_cosign(&spend, &fresh)
        .expect("honest spend verifies");

    // user: adopt the doubly-signed state, then serve is allowed.
    user.accept_cosigned(&cosigned).expect("co-sig good");
    let served = user.serve(&cosigned).expect("serve after co-sign ok");
    assert_eq!(served.seq, cosigned.state.seq);

    // relayer issues the proof-of-relay receipt after forwarding.
    let ack = relayer.issue_relay_ack(&cosigned.state);
    (cosigned, ack)
}

/// 1. Honest sequence of N spends: balances/seqs correct, each state
///    doubly-signed, final settlement pays the relayer `B0 - Bn` and refunds Bn.
#[test]
fn honest_sequence_settles_correctly() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();
    let costs = [100u64, 50, 250, 75, 25];
    let mut states = Vec::new();
    let mut receipts = Vec::new();

    let mut expected_balance = B0;
    for (i, &cost) in costs.iter().enumerate() {
        let (cosigned, ack) = round_trip(&mut user, &mut relayer, cost, i as u64);
        expected_balance -= cost;
        // balances / seqs correct
        assert_eq!(cosigned.state.balance, expected_balance);
        assert_eq!(cosigned.state.seq, (i + 1) as u64);
        // each state is doubly-signed
        assert!(cosigned.is_doubly_signed(&uk.verifying_key(), &rk.verifying_key()));
        states.push(cosigned);
        receipts.push(ack);
    }

    let bn = expected_balance;
    let total_spent = B0 - bn;
    assert_eq!(user.latest().balance, bn);
    assert_eq!(relayer.latest().balance, bn);

    // settlement: highest doubly-signed seq wins; relayer paid B0-Bn, user Bn.
    let verdict = settle(
        B0,
        &uk.verifying_key(),
        &rk.verifying_key(),
        &states,
        &receipts,
    );
    assert_eq!(
        verdict,
        Verdict::Settle {
            winning_seq: costs.len() as u64,
            relayer_payout: total_spent,
            user_refund: bn,
        }
    );
}

/// 2. User rollback / equivocation: two doubly-signed states off ONE predecessor
///    (same seq, conflicting next) is detected → SlashUser.
#[test]
fn equivocation_is_slashed() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();

    // Advance once honestly so there's a shared predecessor at seq 1.
    let (s1, _ack1) = round_trip(&mut user, &mut relayer, 100, 0);
    assert_eq!(s1.state.seq, 1);

    // Now the user forks at seq 2: two DIFFERENT spends off the SAME predecessor,
    // each fully co-signed (a real double-spend the relayer was tricked into, or
    // two relayer instances / a restart). We model both getting co-signed by
    // building a fresh relayer cursor for the second branch (the equivocation is
    // attributable purely from the two doubly-signed states, regardless).
    let fresh_a = relayer.issue_challenge(10, b"req-a");
    let branch_a = user.spend(30, &fresh_a).unwrap();
    let cosig_a = relayer.verify_and_cosign(&branch_a, &fresh_a).unwrap();

    // Second branch off the same seq-1 predecessor: re-open a relayer at the same
    // cursor (seq 1) to co-sign a conflicting seq-2 state. This is exactly the
    // "two doubly-signed states off one predecessor" object.
    let mut relayer2 = RelayerChannel::new(rk.clone(), _chan.clone(), EPOCH);
    // fast-forward relayer2's cursor to the shared seq-1 predecessor:
    let fresh_pre = relayer2.issue_challenge(0, b"onion-packet-0");
    // rebuild the same seq-1 state the user already holds by re-signing it:
    let pre = UserChannel::new(uk.clone(), _chan.clone())
        .spend(100, &fresh_pre)
        .unwrap();
    relayer2.verify_and_cosign(&pre, &fresh_pre).unwrap();

    let fresh_b = relayer2.issue_challenge(11, b"req-b");
    let branch_b = user.spend(70, &fresh_b).unwrap(); // different cost ⇒ different S_2
    let cosig_b = relayer2.verify_and_cosign(&branch_b, &fresh_b).unwrap();
    // Both conflicting seq-2 states carry the user's VALID signature — the user
    // signed each S_2, which is exactly what makes the equivocation attributable.
    assert!(branch_a.signed.user_sig_valid(&uk.verifying_key()));
    assert!(branch_b.signed.user_sig_valid(&uk.verifying_key()));

    assert_eq!(cosig_a.state.seq, cosig_b.state.seq, "same seq");
    assert_ne!(
        cosig_a.state.commitment(),
        cosig_b.state.commitment(),
        "conflicting next states"
    );

    let states = vec![s1, cosig_a.clone(), cosig_b.clone()];
    let verdict = settle(B0, &uk.verifying_key(), &rk.verifying_key(), &states, &[]);
    match verdict {
        Verdict::SlashUser { seq, conflicting } => {
            assert_eq!(seq, 2);
            let set = [conflicting.0, conflicting.1];
            assert!(set.contains(&cosig_a.state.commitment()));
            assert!(set.contains(&cosig_b.state.commitment()));
        }
        other => panic!("expected SlashUser, got {other:?}"),
    }
}

/// 3. Relayer refusal / withholding: without a proof-of-relay receipt the relayer
///    cannot claim the unit; refund-on-timeout returns the user's last balance.
#[test]
fn withholding_without_receipt_refunds_user() {
    let (uk, rk, _chan, mut user, mut relayer) = setup();

    // The user spends and the relayer even co-signs (took the payment authority),
    // but then REFUSES to relay — so it never issues a proof-of-relay receipt.
    let fresh = relayer.issue_challenge(0, b"packet");
    let spend = user.spend(400, &fresh).unwrap();
    let cosigned = relayer.verify_and_cosign(&spend, &fresh).unwrap();
    user.accept_cosigned(&cosigned).unwrap();

    // Settlement with NO receipts: the unit is not claimable; user refunded B0.
    let verdict_no_receipt = settle(
        B0,
        &uk.verifying_key(),
        &rk.verifying_key(),
        std::slice::from_ref(&cosigned),
        &[],
    );
    assert_eq!(verdict_no_receipt, Verdict::RefundUser { user_refund: B0 });

    // Sanity: had the relayer actually relayed (and issued the receipt), the same
    // state WOULD pay it 400 — proving the receipt is the load-bearing gate.
    let ack = relayer.issue_relay_ack(&cosigned.state);
    let verdict_with_receipt = settle(
        B0,
        &uk.verifying_key(),
        &rk.verifying_key(),
        std::slice::from_ref(&cosigned),
        std::slice::from_ref(&ack),
    );
    assert_eq!(
        verdict_with_receipt,
        Verdict::Settle {
            winning_seq: 1,
            relayer_payout: 400,
            user_refund: B0 - 400,
        }
    );

    // A receipt for a DIFFERENT state must not unlock the claim (binding check):
    // a receipt bound to the genesis commitment can't be used to claim the
    // seq-1 spend, so the user is still refunded in full.
    let genesis = _chan.genesis();
    let bogus = relayer.issue_relay_ack(&genesis);
    let verdict_bogus = settle(
        B0,
        &uk.verifying_key(),
        &rk.verifying_key(),
        &[cosigned],
        std::slice::from_ref(&bogus),
    );
    assert_eq!(verdict_bogus, Verdict::RefundUser { user_refund: B0 });
}

/// 4. Replay: a spend bound to one epoch/nonce/request-hash is rejected if
///    replayed.
#[test]
fn replay_is_rejected() {
    let (_uk, _rk, _chan, user, mut relayer) = setup();

    // First spend on nonce 5 against request "A": accepted.
    let fresh = relayer.issue_challenge(5, b"request-A");
    let spend = user.spend(100, &fresh).unwrap();
    let _cosigned = relayer.verify_and_cosign(&spend, &fresh).unwrap();

    // (a) Replaying the EXACT same spend message with the SAME freshness: the
    //     relayer has burned nonce 5 this epoch → StaleFreshness (and the cursor
    //     also advanced, so it is no longer a valid successor — either way the
    //     replay is rejected).
    let replay = relayer.verify_and_cosign(&spend, &fresh);
    assert!(matches!(
        replay,
        Err(ChannelError::StaleFreshness) | Err(ChannelError::BadTransition(_))
    ));

    // (b) Replaying the spend bytes against a DIFFERENT freshness challenge
    //     (fresh nonce, different request): rejected — the cursor advanced so the
    //     transition no longer fits.
    let fresh2 = relayer.issue_challenge(6, b"request-B");
    let replay2 = relayer.verify_and_cosign(&spend, &fresh2);
    assert!(matches!(replay2, Err(ChannelError::BadTransition(_))));
}

/// Tighter replay variant: same predecessor, only the freshness differs, so the
/// transition + state-signature checks pass and we isolate the FRESHNESS binding.
#[test]
fn replay_against_new_freshness_fails_freshness_binding() {
    let (uk, _rk, _chan, user, mut relayer) = setup();

    // Build a spend bound to (epoch=1, nonce=5, "A").
    let fresh = relayer.issue_challenge(5, b"request-A");
    let spend = user.spend(100, &fresh).unwrap();

    // The state signature is over the bare commitment, so it is still valid...
    assert!(spend.signed.user_sig_valid(&uk.verifying_key()));

    // ...but handing the SAME spend against a DIFFERENT freshness challenge fails:
    // the relayer cursor is still at genesis (we didn't co-sign yet) so the
    // transition + state-sig pass, and only `sig_fresh` (over the OLD freshness)
    // mismatches the new challenge ⇒ StaleFreshness. This is the replay binding.
    let fresh2 = relayer.issue_challenge(6, b"request-B");
    let res = relayer.verify_and_cosign(&spend, &fresh2);
    assert_eq!(res, Err(ChannelError::StaleFreshness));
}

/// 5. Sign-then-serve ordering: serving without the relayer's co-signature on the
///    new state is rejected.
#[test]
fn serve_before_cosign_is_rejected() {
    let (_uk, _rk, _chan, user, relayer) = setup();

    let fresh = relayer.issue_challenge(0, b"packet");
    // User has signed S_1 but the relayer has NOT co-signed it yet.
    let spend = user.spend(100, &fresh).unwrap();
    let proposed = spend.signed;
    assert!(proposed.sig_relayer.is_none());

    // Attempting to serve on the not-yet-co-signed state is rejected.
    let res = user.serve(&proposed);
    assert_eq!(res, Err(ChannelError::NotCoSigned));

    // A forged co-signature (the user signing in the relayer's slot) also fails:
    // serve verifies the co-sig against the RELAYER's key, which won't match.
    let forged = SignedState {
        sig_relayer: Some(proposed.sig_user.clone()),
        ..proposed.clone()
    };
    assert_eq!(user.serve(&forged), Err(ChannelError::NotCoSigned));
}

/// 6. Balance underflow (spend > balance) is rejected.
#[test]
fn underflow_is_rejected() {
    let (_uk, _rk, _chan, user, relayer) = setup();
    let fresh = relayer.issue_challenge(0, b"packet");

    // Spend more than the whole channel balance.
    let res = user.spend(B0 + 1, &fresh);
    assert_eq!(
        res.err(),
        Some(ChannelError::Underflow {
            balance: B0,
            cost: B0 + 1,
        })
    );

    // Exactly draining to zero is allowed (boundary).
    let drained = user.spend(B0, &fresh).expect("draining to zero is ok");
    assert_eq!(drained.signed.state.balance, 0);
}
