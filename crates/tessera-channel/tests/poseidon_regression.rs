//! Byte-level regression PINS for the Poseidon-over-BN254 commitments
//! ([`tessera_channel::poseidon`], the `light-poseidon` `new_circom` impl).
//!
//! ## What this guards, and what it does NOT
//!
//! Every constant below is the **canonical 32-byte big-endian `Fr` encoding**
//! ([`fe_to_be_bytes`]) of the value the *current Rust* impl returns for a fixed
//! input. Pinning the byte form (not just `assert_eq!(x, x)`) means any silent
//! drift in the hasher — a constants table change, an arity/`new_circom` swap, a
//! `light-poseidon` bump, or a regression in the field-element encoding
//! ([`fe_from_be_bytes`] / [`fe_to_be_bytes`]) — flips these to red.
//!
//! HONESTY NOTE on scope: these vectors pin the **Rust** output. The crate docs
//! and project memory state that `light-poseidon`'s `new_circom(n)` is
//! byte-for-byte identical to circomlib's `Poseidon(n)` template (and
//! circomlibjs `poseidon([..])`); that equivalence is asserted by the in-crate
//! known-answer test (`poseidon::tests::poseidon_matches_circomlib_known_answers`)
//! and re-checked out-of-band by `circuits/poseidon_ref.mjs`. So this file is a
//! *drift guard for the Rust side*: it ensures the Rust hash can never silently
//! change. FULL cross-language equality additionally relies on those
//! circuit-side / JS reference vectors staying green — this test does NOT and
//! cannot prove the circom witness agrees on its own.
//!
//! To re-establish the bytes-equal-circomlib link, the raw-arity pins below are
//! the SAME inputs the in-crate decimal known-answer test uses, so their byte
//! form here is just the BE encoding of those circomlib-verified decimals.
//!
//! The wrapper inputs (chan_id/balance/seq/salt etc.) are the exact arities and
//! field encodings `circuits/R_dec.circom` proves:
//!   * `C       = Poseidon(chan_id, balance, seq, salt)`  (arity 4)
//!   * `chan_id = Poseidon(K_chan, salt)`                 (arity 2)
//!   * `fresh   = Poseidon(epoch, nonce, request_hash)`   (arity 3)
//!   * `nf_rate = Poseidon(K_chan, epoch, idx)`           (arity 3)
//!
//! with 32-byte tags reduced mod r and u64 amounts injected directly — matching
//! the circuit's "Commitment definition" comment block.

use ark_bn254::Fr;
use tessera_channel::poseidon::{
    chan_id_from_key, fe_from_be_bytes, fe_to_be_bytes, freshness_tag, poseidon, rate_nullifier,
    state_commitment,
};

// ---- fixed inputs ---------------------------------------------------------
// 32-byte tags (reduced mod r inside the impl) and u64 scalars. Chosen distinct
// per field so a cross-wiring of arguments would move the output off its pin.
const CHAN_ID: [u8; 32] = [0x11u8; 32];
const SALT: [u8; 32] = [0x22u8; 32];
const K_CHAN_BYTES: [u8; 32] = [0x05u8; 32];
const REQUEST_HASH: [u8; 32] = [0xABu8; 32];

const BALANCE: u64 = 1_000;
const SEQ: u64 = 0;
const EPOCH: u64 = 7;
const NONCE: u64 = 42;
const IDX: u64 = 3;

// ---- pinned outputs (canonical 32-byte BE encoding, lowercase hex) --------
// Produced by the current Rust impl for the fixed inputs above. Regenerate ONLY
// when the hash is intentionally changed, and cross-check against
// `circuits/poseidon_ref.mjs` + the circom witness before updating.
const EXP_STATE_COMMITMENT: &str =
    "266e7ef105c94cebdf782c21b595786d95a69768d6d3cf8e9f95004a4b28e64d";
const EXP_CHAN_ID_FROM_KEY: &str =
    "003b2d14a5b900072e2fc02a2b521ecb2b3c0ec843d0b19322549c844914fe03";
const EXP_FRESHNESS_TAG: &str = "22e39b73c30f43de7844934b4ff2e13dedc1ec94050e24f4c021f31bee1715ef";
const EXP_RATE_NULLIFIER: &str = "17d7f774d416f25b01f1718d222f34a1dea4c267b4906ad205778cd65128d208";

// Raw-arity pins for arities 2/3/4 (the only arities R_dec uses). The arity-2
// and arity-4 inputs ([1,2] and [1,2,3,4]) are deliberately the SAME ones the
// in-crate decimal known-answer test pins to circomlib, so these byte values
// are exactly the BE encoding of those circomlib-verified decimals — linking
// this drift guard back to the cross-language equivalence claim.
const EXP_POSEIDON2_1_2: &str = "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
const EXP_POSEIDON3_7_42_99: &str =
    "2b6232a45d77532353194827b78352e5db29ee79106c6811693f90885ede7e32";
const EXP_POSEIDON4_1_2_3_4: &str =
    "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465";

/// The four protocol commitments must reproduce their pinned bytes exactly.
/// Any drift in `light-poseidon`, the circomlib constants, the arity, or the
/// field encoding moves at least one of these off its constant and fails.
#[test]
fn protocol_commitments_match_pinned_bytes() {
    let c = state_commitment(&CHAN_ID, BALANCE, SEQ, &SALT);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&c)),
        EXP_STATE_COMMITMENT,
        "state_commitment(chan_id, balance, seq, salt) drifted from its pin"
    );

    let k_chan = fe_from_be_bytes(&K_CHAN_BYTES);
    let cid = chan_id_from_key(&k_chan, &SALT);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&cid)),
        EXP_CHAN_ID_FROM_KEY,
        "chan_id_from_key(K_chan, salt) drifted from its pin"
    );

    let fresh = freshness_tag(EPOCH, NONCE, &REQUEST_HASH);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&fresh)),
        EXP_FRESHNESS_TAG,
        "freshness_tag(epoch, nonce, request_hash) drifted from its pin"
    );

    let nf = rate_nullifier(&k_chan, EPOCH, IDX);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&nf)),
        EXP_RATE_NULLIFIER,
        "rate_nullifier(K_chan, epoch, idx) drifted from its pin"
    );
}

/// Raw `poseidon(&[..])` at the arities R_dec uses (2, 3, 4) must reproduce
/// their pinned bytes. The arity-2 / arity-4 pins double as the BE form of the
/// circomlib-verified decimals from the in-crate known-answer test.
#[test]
fn raw_poseidon_arities_match_pinned_bytes() {
    let h2 = poseidon(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&h2)),
        EXP_POSEIDON2_1_2,
        "poseidon([1,2]) (arity 2) drifted from its pin"
    );

    let h3 = poseidon(&[Fr::from(7u64), Fr::from(42u64), Fr::from(99u64)]);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&h3)),
        EXP_POSEIDON3_7_42_99,
        "poseidon([7,42,99]) (arity 3) drifted from its pin"
    );

    let h4 = poseidon(&[
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ]);
    assert_eq!(
        hex::encode(fe_to_be_bytes(&h4)),
        EXP_POSEIDON4_1_2_3_4,
        "poseidon([1,2,3,4]) (arity 4) drifted from its pin"
    );
}

/// Cross-check that `state_commitment` IS the raw arity-4 `poseidon` over the
/// circuit's exact input vector (chan_id/salt reduced mod r, balance/seq as u64
/// scalars). This wires the high-level wrapper pin to the circuit's commitment
/// definition `C = Poseidon(chan_id, balance, seq, salt)` and would fail if the
/// wrapper reordered, dropped, or re-encoded an input.
#[test]
fn state_commitment_equals_raw_arity4_over_circuit_inputs() {
    let manual = poseidon(&[
        fe_from_be_bytes(&CHAN_ID),
        Fr::from(BALANCE),
        Fr::from(SEQ),
        fe_from_be_bytes(&SALT),
    ]);
    let via_wrapper = state_commitment(&CHAN_ID, BALANCE, SEQ, &SALT);
    assert_eq!(
        via_wrapper, manual,
        "state_commitment must equal Poseidon(chan_id, balance, seq, salt) over the circuit's inputs"
    );
    // ...and that shared value is exactly the pinned commitment.
    assert_eq!(hex::encode(fe_to_be_bytes(&manual)), EXP_STATE_COMMITMENT);
}

/// The pins must be genuinely input-sensitive: distinct fixed inputs map to
/// distinct pinned constants. A degenerate hasher (e.g. one that ignored inputs
/// or collapsed arities) would collide these, so the four pins being mutually
/// distinct is a real property, not a tautology.
#[test]
fn pinned_commitments_are_mutually_distinct() {
    let pins = [
        EXP_STATE_COMMITMENT,
        EXP_CHAN_ID_FROM_KEY,
        EXP_FRESHNESS_TAG,
        EXP_RATE_NULLIFIER,
        EXP_POSEIDON2_1_2,
        EXP_POSEIDON3_7_42_99,
        EXP_POSEIDON4_1_2_3_4,
    ];
    for (i, a) in pins.iter().enumerate() {
        for b in &pins[i + 1..] {
            assert_ne!(
                a, b,
                "two pinned Poseidon vectors collide — pins are not input-sensitive"
            );
        }
    }
}
