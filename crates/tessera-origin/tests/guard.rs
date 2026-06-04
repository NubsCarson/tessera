//! OriginGuard acceptance tests (GOAL milestone 7): a valid presentation is
//! admitted, everything else is refused with the right reason, and the source
//! IP is irrelevant (it is never an input).

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{Decision, OriginGuard, RejectReason};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 4;

/// Issue a credential and return a client ready to present against `CTX`.
fn setup() -> (OriginGuard, TesseraClient) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let guard = OriginGuard::new(sk, pk, REQ, CTX, LIMIT);
    let client = TesseraClient::new(credential, CTX, LIMIT);
    (guard, client)
}

#[test]
fn valid_presentation_is_admitted() {
    let (guard, mut client) = setup();
    let header = client.presentation_header(&mut OsRng).unwrap();
    assert!(guard.check(Some(&header)).is_admit());
}

#[test]
fn missing_credential_is_rejected() {
    let (guard, _client) = setup();
    assert_eq!(
        guard.check(None),
        Decision::Reject(RejectReason::MissingCredential)
    );
}

#[test]
fn malformed_credential_is_rejected() {
    let (guard, _client) = setup();
    assert_eq!(
        guard.check(Some("not-hex!!")),
        Decision::Reject(RejectReason::Malformed)
    );
    // Valid hex but not a valid presentation.
    assert_eq!(
        guard.check(Some("00ff00ff")),
        Decision::Reject(RejectReason::Malformed)
    );
}

#[test]
fn replay_is_rejected_as_double_spend() {
    let (guard, mut client) = setup();
    let header = client.presentation_header(&mut OsRng).unwrap();
    assert!(guard.check(Some(&header)).is_admit());
    // Same presentation again -> double-spend.
    assert_eq!(
        guard.check(Some(&header)),
        Decision::Reject(RejectReason::DoubleSpend)
    );
}

#[test]
fn presentation_for_another_origin_is_rejected() {
    // A credential presented for a different context must not verify here:
    // its proof is bound to the other presentation context.
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();

    // Client presents for a DIFFERENT context than the guard enforces.
    let mut client = TesseraClient::new(credential, b"tessera://somewhere-else/v1", LIMIT);
    let header = client.presentation_header(&mut rng).unwrap();

    let guard = OriginGuard::new(sk, pk, REQ, CTX, LIMIT);
    assert_eq!(
        guard.check(Some(&header)),
        Decision::Reject(RejectReason::InvalidProof)
    );
}

#[test]
fn distinct_presentations_have_distinct_tags() {
    let (guard, mut client) = setup();
    let mut tags = Vec::new();
    for _ in 0..LIMIT {
        let header = client.presentation_header(&mut OsRng).unwrap();
        if let Decision::Admit { tag } = guard.check(Some(&header)) {
            tags.push(tag);
        } else {
            panic!("should admit");
        }
    }
    let unique: std::collections::HashSet<_> = tags.iter().collect();
    assert_eq!(
        unique.len(),
        LIMIT as usize,
        "tags must be unlinkable/distinct"
    );
}
