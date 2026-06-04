//! End-to-end proof that the `tessera-origin` `tower` middleware (`TesseraLayer`)
//! works in a **real** `axum` server: a multi-threaded `tokio` runtime, a real
//! TCP socket, real HTTP/1.1 requests. This is the deployment claim actually
//! exercised — beyond the crate's single-threaded `block_on` unit test.
//!
//! No HTTP-client dependency: requests go over a raw `tokio` `TcpStream`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{OriginGuard, TesseraLayer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST_CTX: &[u8] = b"tessera-tower-demo/issue/v1";
const PRESENT_CTX: &[u8] = b"tessera-tower-demo/origin/v1";
const LIMIT: u64 = 5;

/// Send one `GET /` over a fresh connection (optionally with a presentation
/// header) and return the HTTP status code from the response's first line.
async fn status(addr: SocketAddr, header: Option<&str>) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut req = String::from("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(h) = header {
        req.push_str("Tessera-Presentation: ");
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf);
    let first = text.lines().next().expect("status line");
    first
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_admits_credential_and_rejects_replay_over_real_http() {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);

    // Client side: obtain a credential and mint two distinct presentations.
    let (pending, request) = begin_issuance(REQUEST_CTX, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    let header1 = client.presentation_header(&mut rng).unwrap();
    let header2 = client.presentation_header(&mut rng).unwrap();

    // Server side: the SAME keys/contexts, guarded by the tower middleware.
    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));
    let app = Router::new().route(
        "/",
        get(|| async { "admitted" }).layer(TesseraLayer::new(guard)),
    );

    // Bind an ephemeral port, then serve on the multi-threaded runtime.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // No credential -> 403, before the handler runs.
    assert_eq!(status(addr, None).await, 403, "no credential must be 403");
    // A garbage header -> 403 (malformed).
    assert_eq!(
        status(addr, Some("not-hex!!")).await,
        403,
        "malformed credential must be 403"
    );
    // A valid presentation -> 200 (admitted).
    assert_eq!(status(addr, Some(&header1)).await, 200, "valid must be 200");
    // Replaying the SAME presentation -> 403 (double-spend, via the shared guard).
    assert_eq!(
        status(addr, Some(&header1)).await,
        403,
        "replay must be 403 (double-spend)"
    );
    // A distinct, in-budget presentation still works.
    assert_eq!(
        status(addr, Some(&header2)).await,
        200,
        "a fresh presentation must be 200"
    );
}
