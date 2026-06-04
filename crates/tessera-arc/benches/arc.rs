//! Criterion benchmarks for the three hot ARC operations: issuance
//! (request + response + finalize), presentation, and verification.
//!
//! Run with `cargo bench -p tessera-arc`.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, PresentationState,
};
use tessera_arc::keys::ServerPrivateKey;

const REQ_CTX: &[u8] = b"tessera://issue/v1";
const PRES_CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 8;

fn bench_arc(c: &mut Criterion) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);

    // Full issuance handshake.
    c.bench_function("issue (request+response+finalize)", |b| {
        b.iter(|| {
            let (secrets, request) = create_credential_request(REQ_CTX, &mut rng);
            let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
            finalize_credential(&secrets, &pk, &request, &response).unwrap()
        })
    });

    // A finalized credential to drive present/verify.
    let credential = {
        let (secrets, request) = create_credential_request(REQ_CTX, &mut rng);
        let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
        finalize_credential(&secrets, &pk, &request, &response).unwrap()
    };

    // Present: fresh state per iteration (presenting advances the nonce).
    c.bench_function("present", |b| {
        b.iter_batched(
            || PresentationState::new(credential.clone(), PRES_CTX, LIMIT),
            |mut state| state.present(&mut rng).unwrap(),
            BatchSize::SmallInput,
        )
    });

    // Verify a fixed presentation (verification is stateless w.r.t. the tag store).
    let mut state = PresentationState::new(credential.clone(), PRES_CTX, LIMIT);
    let presentation = state.present(&mut rng).unwrap();
    c.bench_function("verify presentation", |b| {
        b.iter(|| verify_presentation(&sk, &pk, REQ_CTX, PRES_CTX, &presentation, LIMIT))
    });
}

criterion_group!(benches, bench_arc);
criterion_main!(benches);
