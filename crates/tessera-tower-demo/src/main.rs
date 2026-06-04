//! A runnable HTTP origin built on the `tessera-origin` `tower` middleware.
//!
//! This is the "deploy it" picture for ROADMAP track 2: a real `axum` server
//! whose `/` route is wrapped in [`TesseraLayer`], so a request is admitted only
//! if it carries a valid, in-budget, unspent ARC presentation — **never** on its
//! IP. The guarded route returns `200`; anything without a good credential gets
//! `403` before the handler runs.
//!
//! ```sh
//! cargo run --manifest-path crates/tessera-tower-demo/Cargo.toml
//! # then, in another shell (the printed commands):
//! curl -i 127.0.0.1:8090/                              # -> 403 (no credential)
//! H=$(curl -s 127.0.0.1:8090/issue)                    # demo issuance -> a header
//! curl -i -H "Tessera-Presentation: $H" 127.0.0.1:8090/  # -> 200 (admitted)
//! curl -i -H "Tessera-Presentation: $H" 127.0.0.1:8090/  # -> 403 (replay/double-spend)
//! ```
//!
//! `/issue` is **demo-only**: it conflates the issuer and the client so you can
//! obtain a working header with one request. A real deployment separates the
//! issuer (which gates minting — see `tessera-issuer`) from the origin.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{OriginGuard, TesseraLayer};

const REQUEST_CTX: &[u8] = b"tessera-tower-demo/issue/v1";
const PRESENT_CTX: &[u8] = b"tessera-tower-demo/origin/v1";
const LIMIT: u64 = 5;
const ADDR: &str = "127.0.0.1:8090";

/// Demo issuer state: the server keys, shared with the `/issue` handler.
#[derive(Clone)]
struct Issuer {
    sk: ServerPrivateKey,
    pk: ServerPublicKey,
}

/// The guarded handler — only reached when the credential check passed.
async fn admitted() -> &'static str {
    "admitted \u{2713}  (this request carried a valid, unspent Tessera credential)\n"
}

/// DEMO-ONLY issuance: mint a credential and return one ready-to-use
/// presentation header. Real deployments separate issuer from origin.
async fn issue(State(issuer): State<Arc<Issuer>>) -> Result<String, StatusCode> {
    let mut rng = OsRng;
    let (pending, request) = begin_issuance(REQUEST_CTX, issuer.pk, &mut rng);
    let response = create_credential_response(&issuer.sk, &issuer.pk, &request, &mut rng)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let credential = pending
        .finalize(&response)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    client
        .presentation_header(&mut rng)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[tokio::main]
async fn main() {
    let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
    let issuer = Arc::new(Issuer { sk: sk.clone(), pk });
    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));

    // The `tower` middleware guards only `/`; `/issue` is the demo issuer.
    let app = Router::new()
        .route("/", get(admitted).layer(TesseraLayer::new(guard)))
        .route("/issue", get(issue))
        .with_state(issuer);

    let listener = tokio::net::TcpListener::bind(ADDR)
        .await
        .expect("bind 127.0.0.1:8090");
    println!("tessera-tower-demo: guarded origin on http://{ADDR}");
    println!("  curl -i http://{ADDR}/                                  # 403 (no credential)");
    println!("  H=$(curl -s http://{ADDR}/issue)                        # demo issuance");
    println!("  curl -i -H \"Tessera-Presentation: $H\" http://{ADDR}/    # 200 (admitted)");
    println!("  curl -i -H \"Tessera-Presentation: $H\" http://{ADDR}/    # 403 (replay)");
    axum::serve(listener, app).await.expect("serve");
}
