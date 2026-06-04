//! End-to-end ARC round-trip tests (GOAL milestone 5 acceptance gate).
//!
//! These exercise the full protocol with a real CSPRNG: a server sets up keys,
//! issues a credential to a client, and the client presents it up to the limit.
//! We assert the honest path verifies, the limit is enforced, double-spends are
//! caught, and tampering / wrong-context presentations are rejected.

use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, ArcError, PresentationState, TagStore,
};
use tessera_arc::keys::ServerPrivateKey;

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
        let (valid, tag) =
            verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT);
        assert!(valid, "presentation {i} must verify");
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
fn tampered_presentation_is_rejected() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let mut presentation = state.present(&mut rng).expect("under limit");

    // Flip a byte of the proof.
    presentation.proof[0] ^= 0x01;
    let (valid, _) = verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT);
    assert!(!valid, "tampered proof must be rejected");
}

#[test]
fn wrong_presentation_context_is_rejected() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let presentation = state.present(&mut rng).expect("under limit");

    // Verify under a different presentation context than the tag was bound to.
    let (valid, _) = verify_presentation(
        &sk,
        &pk,
        REQUEST_CTX,
        b"tessera://other-origin/v1",
        &presentation,
        LIMIT,
    );
    assert!(!valid, "presentation bound to another context must fail");
}

#[test]
fn double_spend_same_tag_is_caught() {
    let (sk, pk, credential) = issue_credential();
    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let mut rng = OsRng;
    let mut store = TagStore::new();

    let presentation = state.present(&mut rng).expect("under limit");
    let (valid, tag) =
        verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &presentation, LIMIT);
    assert!(valid);
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
