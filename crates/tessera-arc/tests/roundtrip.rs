//! End-to-end ARC round-trip tests (GOAL milestone 5 acceptance gate).
//!
//! These exercise the full protocol with a real CSPRNG: a server sets up keys,
//! issues a credential to a client, and the client presents it up to the limit.
//! We assert the honest path verifies, the limit is enforced, double-spends are
//! caught, and tampering / wrong-context presentations are rejected.

use p256::Scalar;
use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, ArcError, Presentation, PresentationState, TagStore,
};
use tessera_arc::group::{generator_g, generator_h, hash_to_group, random_scalar, scalar_invert};
use tessera_arc::keys::ServerPrivateKey;
use tessera_arc::proofs::{prove_presentation, PresentationWitness};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://origin.example/v1";
const LIMIT: u64 = 5;

fn issue_credential() -> (
    ServerPrivateKey,
    tessera_arc::keys::ServerPublicKey,
    tessera_arc::arc::Credential,
) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (secrets, request) = create_credential_request(REQUEST_CTX, &mut rng);
    let response =
        create_credential_response(&sk, &pk, &request, &mut rng).expect("request proof valid");
    let credential =
        finalize_credential(&secrets, &pk, &request, &response).expect("response proof valid");
    (sk, pk, credential)
}

#[test]
fn full_roundtrip_presentations_verify_within_limit() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let mut store = TagStore::new();

    let mut tags = Vec::new();
    for i in 0..LIMIT {
        let presentation = state.present(&mut rng).expect("under limit");
        let tag = verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT)
            .unwrap_or_else(|| panic!("presentation {i} must verify"));
        assert!(store.accept(tag), "tag {i} must be fresh");
        tags.push(tag);
    }
    // All tags within a context must be distinct (one per nonce).
    let unique: std::collections::HashSet<_> = tags.iter().collect();
    assert_eq!(
        unique.len(),
        LIMIT as usize,
        "tags must be pairwise distinct"
    );
}

#[test]
fn server_private_key_serialization_roundtrips_and_debug_is_redacted() {
    let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
    let bytes = sk.serialize();
    assert_eq!(bytes.len(), 4 * 32, "private key is 4*Ns bytes");

    let sk2 = ServerPrivateKey::from_bytes(&bytes).expect("decode");
    assert_eq!(
        sk2.public_key().serialize(),
        pk.serialize(),
        "deserialized key derives the same public key"
    );

    // Debug must never reveal the secret scalars.
    assert_eq!(format!("{sk:?}"), "ServerPrivateKey(<redacted>)");

    // Truncated / empty input is rejected, not panicked.
    assert!(ServerPrivateKey::from_bytes(&bytes[..127]).is_err());
    assert!(ServerPrivateKey::from_bytes(&[]).is_err());
}

#[test]
fn presentation_beyond_limit_is_refused() {
    let (_sk, _pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, 2);
    let mut rng = OsRng;
    assert!(state.present(&mut rng).is_ok());
    assert!(state.present(&mut rng).is_ok());
    assert_eq!(
        state.present(&mut rng).unwrap_err(),
        ArcError::LimitExceeded
    );
}

#[test]
fn degenerate_limit_below_two_is_refused_not_panicked() {
    // A limit < 2 has no valid range-proof shape; present() must return an
    // error rather than panicking inside compute_bases (prove-side guard).
    let (_sk, _pk, credential) = issue_credential();
    let mut rng = OsRng;
    for bad in [0u64, 1] {
        let mut state = PresentationState::new(credential.clone(), PRESENT_CTX, bad);
        assert_eq!(
            state.present(&mut rng).unwrap_err(),
            ArcError::LimitExceeded
        );
    }
}

#[test]
fn overlimit_nonce_is_refused_by_the_range_proof_not_just_the_counter() {
    // The honest client counter is advisory; the cryptographic enforcement of
    // "no over-presentation" is the range proof in the verifier. Bypass the
    // counter and hand-build a presentation at nonce == LIMIT (out of range),
    // then assert the verifier rejects it — proving the *crypto* enforces the
    // bound, not just `PresentationState`.
    let (sk, pk, cred) = issue_credential();
    let mut rng = OsRng;

    let g = generator_g();
    let h = generator_h();
    let a = random_scalar(&mut rng);
    let r = random_scalar(&mut rng);
    let z = random_scalar(&mut rng);
    let u = cred.u * a;
    let u_prime_commit = cred.u_prime * a + g * r;
    let m1_commit = u * cred.m1 + h * z;
    let nonce_blinding = random_scalar(&mut rng);
    let nonce_scalar = Scalar::from(LIMIT); // valid slots are 0..LIMIT
    let nonce_commit = g * nonce_scalar + h * nonce_blinding;
    let generator_t = hash_to_group(PRESENT_CTX, b"Tag");
    let tag = generator_t * scalar_invert(&(cred.m1 + nonce_scalar)).unwrap();
    let v = cred.x1 * z - g * r;

    let pp = prove_presentation(
        &PresentationWitness {
            u,
            u_prime_commit,
            m1_commit,
            tag,
            generator_t,
            m1: cred.m1,
            x1: cred.x1,
            v,
            r,
            z,
            nonce: LIMIT,
            nonce_blinding,
            nonce_commit,
            limit: LIMIT,
        },
        &mut rng,
    );
    let presentation = Presentation {
        u,
        u_prime_commit,
        m1_commit,
        tag,
        nonce_commit,
        d: pp.d,
        proof: pp.proof,
    };
    assert!(
        verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT).is_none(),
        "a nonce >= limit must be refused by the verifier's range proof"
    );
}

#[test]
fn tampered_presentation_is_rejected() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let mut presentation = state.present(&mut rng).expect("under limit");

    // Flip a byte of the proof.
    presentation.proof[0] ^= 0x01;
    assert!(
        verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT).is_none(),
        "tampered proof must be rejected"
    );
}

#[test]
fn wrong_presentation_context_is_rejected() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let presentation = state.present(&mut rng).expect("under limit");

    // Verify under a different presentation context than the tag was bound to.
    assert!(
        verify_presentation(
            &sk,
            &pk,
            REQUEST_CTX,
            b"tessera://other-origin/v1",
            &presentation,
            LIMIT,
        )
        .is_none(),
        "presentation bound to another context must fail"
    );
}

#[test]
fn double_spend_same_tag_is_caught() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let mut store = TagStore::new();

    let presentation = state.present(&mut rng).expect("under limit");
    let tag = verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT)
        .expect("first use verifies");
    assert!(store.accept(tag), "first use is fresh");
    // Replaying the identical tag (same nonce) must be rejected by the store.
    assert!(!store.accept(tag), "replay must be caught as double-spend");
}

#[test]
fn forged_credential_cannot_be_minted_from_bad_request() {
    // A client that sends a malformed request proof must be rejected at issuance.
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (_secrets, mut request) = create_credential_request(REQUEST_CTX, &mut rng);
    request.proof[0] ^= 0x01;
    assert_eq!(
        create_credential_response(&sk, &pk, &request, &mut rng).unwrap_err(),
        ArcError::InvalidRequestProof
    );
}
