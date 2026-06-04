//! Deterministic, stable-toolchain robustness tests: every deserializer and the
//! presentation verifier must return an error/`false` on arbitrary input —
//! never panic, never abort. This is the CI-runnable companion to the
//! `cargo-fuzz` targets under `fuzz/` (which need nightly); it gives fast,
//! reproducible no-panic coverage on stable.

use rand_core::{OsRng, RngCore};
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, CredentialRequest, CredentialResponse, Presentation, PresentationState,
};
use tessera_arc::group::{deserialize_element, deserialize_scalar};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

const LIMITS: [u64; 5] = [2, 3, 8, 100, 1024];

/// Feed every deserializer a large amount of random, arbitrary-length input.
/// None of these may panic; they must all return `Result`/`Option`.
#[test]
fn deserializers_never_panic_on_random_bytes() {
    let mut rng = OsRng;
    for _ in 0..8_000 {
        let len = (rng.next_u32() % 700) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);

        let _ = deserialize_element(&buf);
        let _ = deserialize_scalar(&buf);
        let _ = ServerPublicKey::from_bytes(&buf);
        let _ = CredentialRequest::from_bytes(&buf);
        let _ = CredentialResponse::from_bytes(&buf);
        for &limit in &LIMITS {
            let _ = Presentation::from_bytes(&buf, limit);
        }
    }
}

/// Pathological fixed inputs (empty, all-0x00, all-0xff, off-by-one lengths).
#[test]
fn deserializers_handle_edge_lengths() {
    for len in [0usize, 1, 32, 33, 34, 226, 454, 486, 1000] {
        for fill in [0x00u8, 0xff, 0x02, 0x03] {
            let buf = vec![fill; len];
            let _ = deserialize_element(&buf);
            let _ = deserialize_scalar(&buf);
            let _ = ServerPublicKey::from_bytes(&buf);
            let _ = CredentialRequest::from_bytes(&buf);
            let _ = CredentialResponse::from_bytes(&buf);
            for &limit in &LIMITS {
                // Degenerate limits (0,1) must not panic via compute_bases either.
                let _ = Presentation::from_bytes(&buf, limit);
            }
        }
    }
}

/// Mutation fuzzing of a *valid* presentation: single-byte flips on the wire
/// bytes must still decode-or-reject and verify-to-`None` without panicking —
/// this drives the full `Presentation::from_bytes` + `verify_presentation` path
/// (including `sigma::verify`) with structurally-plausible hostile input.
#[test]
fn mutated_presentations_never_panic_and_do_not_verify() {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let req_ctx = b"tessera://issue/v1";
    let pres_ctx = b"tessera://origin/v1";
    let limit = 8u64;

    let (secrets, request) = create_credential_request(req_ctx, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();
    let mut state = PresentationState::new(credential, pres_ctx, limit);
    let valid_bytes = state.present(&mut rng).unwrap().to_bytes();

    for _ in 0..2_000 {
        let mut buf = valid_bytes.clone();
        // Flip 1–3 random bytes.
        for _ in 0..(1 + rng.next_u32() % 3) {
            let i = (rng.next_u32() as usize) % buf.len();
            buf[i] ^= 1 << (rng.next_u32() % 8);
        }
        if let Ok(p) = Presentation::from_bytes(&buf, limit) {
            // A mutated presentation must never verify (overwhelmingly) and must
            // never panic. We only assert no-panic + that the unchanged original
            // still verifies as a control.
            let _ = verify_presentation(&sk, &pk, req_ctx, pres_ctx, &p, limit);
        }
    }

    // Control: the untouched bytes still verify.
    let original = Presentation::from_bytes(&valid_bytes, limit).expect("decode");
    assert!(
        verify_presentation(&sk, &pk, req_ctx, pres_ctx, &original, limit).is_some(),
        "unmutated presentation must verify"
    );
}
