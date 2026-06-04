//! Wire-format round-trip and spec-length tests (GOAL milestone 6).
//!
//! Confirms every protocol struct survives a serialize → deserialize round
//! trip unchanged, and that encoded lengths match the spec constants
//! (`Nrequest`, `Nresponse`, `NserverPublicKey`, `Npresentation`).

use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, CredentialRequest, CredentialResponse, Presentation, PresentationState,
};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 8; // k = 3 bits, exercises a multi-commitment range proof

#[test]
fn server_public_key_roundtrips() {
    let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
    let bytes = pk.serialize();
    assert_eq!(bytes.len(), 3 * 33, "NserverPublicKey = 3*Ne");
    let pk2 = ServerPublicKey::from_bytes(&bytes).expect("decode");
    assert_eq!(sk.public_key().serialize(), pk2.serialize());
}

#[test]
fn credential_request_roundtrips_with_spec_length() {
    let (_secrets, request) = create_credential_request(REQUEST_CTX, &mut OsRng);
    let bytes = request.to_bytes();
    assert_eq!(bytes.len(), 2 * 33 + 5 * 32, "Nrequest = 2*Ne + 5*Ns");
    let request2 = CredentialRequest::from_bytes(&bytes).expect("decode");
    assert_eq!(request2.to_bytes(), bytes);
}

#[test]
fn credential_response_roundtrips_with_spec_length() {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (_s, request) = create_credential_request(REQUEST_CTX, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let bytes = response.to_bytes();
    assert_eq!(bytes.len(), 6 * 33 + 8 * 32, "Nresponse = 6*Ne + 8*Ns");
    let response2 = CredentialResponse::from_bytes(&bytes).expect("decode");
    assert_eq!(response2.to_bytes(), bytes);
}

#[test]
fn presentation_roundtrips_and_still_verifies_after_transport() {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (secrets, request) = create_credential_request(REQUEST_CTX, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();

    let mut state = PresentationState::new(credential, PRESENT_CTX, LIMIT);
    let presentation = state.present(&mut rng).unwrap();

    let bytes = presentation.to_bytes();
    // k = 3 for limit 8: 5*Ne + 3*Ne + (6 + 9)*Ns
    let k = 3usize;
    assert_eq!(bytes.len(), 5 * 33 + k * 33 + (6 + 3 * k) * 32);

    // Deserialize on the "server side" and verify it still checks out — proves
    // the wire format preserves every field a verifier needs.
    let received = Presentation::from_bytes(&bytes, LIMIT).expect("decode");
    assert!(
        verify_presentation(&sk, &pk, REQUEST_CTX, PRESENT_CTX, &received, LIMIT).is_some(),
        "presentation must verify after a serialize/deserialize round trip"
    );
}

#[test]
fn truncated_inputs_are_rejected() {
    let (_s, request) = create_credential_request(REQUEST_CTX, &mut OsRng);
    let bytes = request.to_bytes();
    assert!(CredentialRequest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(CredentialRequest::from_bytes(&[]).is_err());
}
