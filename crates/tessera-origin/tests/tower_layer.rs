//! `tower` middleware integration test (ROADMAP track 2): a request carrying a
//! valid presentation reaches the inner service (200); a missing or invalid one
//! is short-circuited with `403` and the inner service is NEVER called; a replay
//! is rejected the same way. Drives the layer end-to-end with a real
//! presentation minted via `tessera-client`.

#![cfg(feature = "tower")]

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{OriginGuard, TesseraGuard, TesseraLayer, PRESENTATION_HEADER};
use tower::util::BoxCloneService;
use tower::{service_fn, Layer, ServiceExt};

/// Tiny synchronous driver for the async layer — avoids pulling a full async
/// runtime (tokio) into this crate's dev-dependency graph just for a test.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_executor::block_on(fut)
}

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 4;

/// Issue a credential and return a guard + a client ready to present against CTX.
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

/// The concrete inner-service type after boxing: cloneable, `Send`, with a
/// `Send` future — exactly the bounds [`TesseraGuard`]'s `Service` impl needs.
type Inner = BoxCloneService<Request<Empty<Bytes>>, Response<Full<Bytes>>, Infallible>;

/// Build the guarded stack over a trivial inner service that increments `hits`
/// and returns `200 OK` with a tiny body. Returns the wired service + counter.
fn guarded(guard: OriginGuard) -> (TesseraGuard<Inner>, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_inner = Arc::clone(&hits);
    let inner = BoxCloneService::new(service_fn(move |_req: Request<Empty<Bytes>>| {
        let hits_inner = Arc::clone(&hits_inner);
        async move {
            hits_inner.fetch_add(1, Ordering::SeqCst);
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"served"))))
        }
    }));
    let svc = TesseraLayer::new(Arc::new(guard)).layer(inner);
    (svc, hits)
}

async fn body_bytes<B>(res: Response<B>) -> Vec<u8>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug,
{
    res.into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec()
}

#[test]
fn valid_presentation_reaches_inner() {
    let (guard, mut client) = setup();
    let header = client.presentation_header(&mut OsRng).unwrap();
    let (svc, hits) = guarded(guard);

    let req = Request::builder()
        .header(PRESENTATION_HEADER, header)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = block_on(svc.oneshot(req)).unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "inner must run on admit");
    assert_eq!(block_on(body_bytes(res)), b"served");
}

#[test]
fn missing_credential_is_403_without_inner() {
    let (guard, _client) = setup();
    let (svc, hits) = guarded(guard);

    let req = Request::builder().body(Empty::<Bytes>::new()).unwrap();
    let res = block_on(svc.oneshot(req)).unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "inner must NOT run on reject"
    );
    assert_eq!(
        res.headers()
            .get("Tessera-Reject")
            .and_then(|v| v.to_str().ok()),
        Some("no credential")
    );
}

#[test]
fn malformed_credential_is_403_without_inner() {
    let (guard, _client) = setup();
    let (svc, hits) = guarded(guard);

    let req = Request::builder()
        .header(PRESENTATION_HEADER, "not-hex!!")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = block_on(svc.oneshot(req)).unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn replay_is_403_without_inner() {
    let (guard, mut client) = setup();
    let header = client.presentation_header(&mut OsRng).unwrap();
    let (svc, hits) = guarded(guard);

    // First use: admitted, inner runs.
    let req1 = Request::builder()
        .header(PRESENTATION_HEADER, &header)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res1 = block_on(svc.clone().oneshot(req1)).unwrap();
    assert_eq!(res1.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Replay the exact same presentation: double-spend -> 403, inner not called.
    let req2 = Request::builder()
        .header(PRESENTATION_HEADER, &header)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res2 = block_on(svc.oneshot(req2)).unwrap();
    assert_eq!(res2.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "replay must not reach inner"
    );
    assert_eq!(
        res2.headers()
            .get("Tessera-Reject")
            .and_then(|v| v.to_str().ok()),
        Some("double-spend (replay)")
    );
}
