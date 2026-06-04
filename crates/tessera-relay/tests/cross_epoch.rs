//! S2 — cross-epoch nullifier scoping + replay rejection (the operational and
//! cryptographic halves of the epoch authority spec'd in `docs/EPOCH_AUTHORITY.md`).
//!
//! Two layers:
//!   * the **relay gate** (operational): within an epoch a burned spend/nonce is
//!     rejected; a spend bound to a stale epoch is rejected with zero skew; and a
//!     nonce re-used in a *new* epoch is accepted (the per-epoch budget resets);
//!   * the **Poseidon nullifier/freshness tags** (cryptographic): `nf_rate` and
//!     `fresh` scope exactly as the spec claims.

use rand_core::OsRng;

use tessera_channel::poseidon::{fe_from_be_bytes, freshness_tag, rate_nullifier};
use tessera_channel::{Channel, ChannelError, KeyPair, UserChannel};
use tessera_relay::RelayGate;

const CHAN_ID: [u8; 32] = [3u8; 32];
const SALT: [u8; 32] = [4u8; 32];
const B0: u64 = 1_000;
const E: u64 = 7;

/// The relay gate enforces the epoch/nonce rules end to end.
#[test]
fn within_epoch_replay_rejected_and_cross_epoch_resets() {
    let mut rng = OsRng;
    let uk = KeyPair::generate(&mut rng);
    let rk = KeyPair::generate(&mut rng);
    let chan = Channel::open(CHAN_ID, B0, SALT, uk.verifying_key(), rk.verifying_key());

    // --- Epoch E: open + one honest spend (nonce 0) is accepted. ---
    let gate = RelayGate::new(rk.clone(), E);
    gate.open(chan.clone()).unwrap();
    let mut user = UserChannel::new(uk.clone(), chan.clone());
    let fresh = gate.issue_challenge(&CHAN_ID, 0, b"req").unwrap();
    assert_eq!(fresh.epoch, E, "challenge carries the relayer's epoch");
    let spend = user.spend(100, &fresh).unwrap();
    let cosigned = gate.verify_spend(&CHAN_ID, &spend, &fresh).unwrap();
    user.accept_cosigned(&cosigned).unwrap();

    // --- Within-epoch replay of the same spend/nonce is rejected. ---
    let replay = gate.verify_spend(&CHAN_ID, &spend, &fresh);
    assert!(replay.is_err(), "a within-epoch replay must be rejected");

    // --- The relayer rolls to epoch E+1 (a fresh gate = a fresh cursor). ---
    let gate2 = RelayGate::new(rk.clone(), E + 1);
    gate2.open(chan.clone()).unwrap();

    // Clock-skew / zero tolerance: a spend bound to the OLD epoch's challenge is
    // rejected at E+1 as StaleFreshness (the successor check passes on the fresh
    // genesis cursor, so the epoch mismatch is what trips it).
    let user_skew = UserChannel::new(uk.clone(), chan.clone());
    let fresh_e = gate.issue_challenge(&CHAN_ID, 1, b"req2").unwrap();
    assert_eq!(fresh_e.epoch, E);
    let spend_e = user_skew.spend(100, &fresh_e).unwrap();
    let skew = gate2.verify_spend(&CHAN_ID, &spend_e, &fresh_e);
    assert!(
        matches!(skew, Err(ChannelError::StaleFreshness)),
        "a spend bound to a stale epoch must be rejected with zero skew, got {skew:?}"
    );

    // Budget reset: nonce 0 — burned in epoch E — is accepted again in epoch E+1,
    // because the new epoch's cursor has its own (empty) seen-nonce set.
    let user2 = UserChannel::new(uk.clone(), chan.clone());
    let fresh2 = gate2.issue_challenge(&CHAN_ID, 0, b"req").unwrap();
    assert_eq!(fresh2.epoch, E + 1);
    let spend2 = user2.spend(100, &fresh2).unwrap();
    assert!(
        gate2.verify_spend(&CHAN_ID, &spend2, &fresh2).is_ok(),
        "nonce reused in a new epoch is accepted — the per-epoch budget reset"
    );
}

/// The Poseidon rate nullifier scopes by (channel key, epoch, idx) exactly as the
/// spec's invariants require.
#[test]
fn rate_nullifier_scoping() {
    let k = fe_from_be_bytes(&[1u8; 32]);
    let k2 = fe_from_be_bytes(&[2u8; 32]);

    // Cross-epoch: same (K, idx) at different epochs → DIFFERENT nullifier, so the
    // per-epoch budget resets and an old idx is freely re-usable next epoch.
    assert!(
        rate_nullifier(&k, E, 5) != rate_nullifier(&k, E + 1, 5),
        "cross-epoch nullifiers must differ (budget resets each epoch)"
    );
    // Determinism: same (K, epoch, idx) → identical, so a duplicate is a
    // detectable clash.
    assert!(
        rate_nullifier(&k, E, 5) == rate_nullifier(&k, E, 5),
        "a duplicate (epoch, idx) must collide so it is detectable"
    );
    // Distinct idx within an epoch → distinct nullifier.
    assert!(
        rate_nullifier(&k, E, 5) != rate_nullifier(&k, E, 6),
        "idx must scope"
    );
    // Distinct channel key → distinct nullifier (channels never collide).
    assert!(
        rate_nullifier(&k, E, 5) != rate_nullifier(&k2, E, 5),
        "the nullifier must be anchored to the channel key"
    );
}

/// The freshness tag binds all of (epoch, nonce, request_hash) — a spend can't be
/// replayed across requests or epochs.
#[test]
fn freshness_tag_binding() {
    let h = [9u8; 32];
    let h2 = [10u8; 32];
    assert!(
        freshness_tag(E, 1, &h) == freshness_tag(E, 1, &h),
        "deterministic"
    );
    assert!(
        freshness_tag(E, 1, &h) != freshness_tag(E + 1, 1, &h),
        "binds epoch"
    );
    assert!(
        freshness_tag(E, 1, &h) != freshness_tag(E, 2, &h),
        "binds nonce"
    );
    assert!(
        freshness_tag(E, 1, &h) != freshness_tag(E, 1, &h2),
        "binds request hash"
    );
}
