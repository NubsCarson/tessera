//! A runnable HTTP origin + issuer built on the `tessera-origin` `tower`
//! middleware — the "deploy it" picture for ROADMAP track 2.
//!
//! Routes:
//! * `GET  /`        — guarded by [`TesseraLayer`]; admits only a valid,
//!   in-budget, unspent ARC presentation (never the IP), else `403`.
//! * `GET  /pubkey`  — the issuer's serialized public key (hex), so a client
//!   (e.g. the `tessera-wasm` browser client) can build a credential request.
//! * `POST /issue`   — the **real issuer**: body is a hex `CredentialRequest`,
//!   response is a hex `CredentialResponse`. No client secret is involved.
//! * `GET  /quick`   — demo convenience: conflates issuer+client and returns a
//!   ready-to-use presentation header so you can `curl` in one step.
//!
//! ```sh
//! cargo run --manifest-path crates/tessera-tower-demo/Cargo.toml
//! curl -i 127.0.0.1:8090/                                  # 403 (no credential)
//! H=$(curl -s 127.0.0.1:8090/quick)                        # demo header
//! curl -i -H "Tessera-Presentation: $H" 127.0.0.1:8090/    # 200 (admitted)
//! curl -i -H "Tessera-Presentation: $H" 127.0.0.1:8090/    # 403 (replay)
//! ```
//!
//! The proper `/pubkey` + `/issue` pair is what the cross-language node ↔ wasm
//! demo drives (see `crates/tessera-wasm/examples/`): a real, separated issuer.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, CredentialRequest};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{OriginGuard, TesseraLayer};

const REQUEST_CTX: &[u8] = b"tessera-tower-demo/issue/v1";
const PRESENT_CTX: &[u8] = b"tessera-tower-demo/origin/v1";
const LIMIT: u64 = 5;
const ADDR: &str = "127.0.0.1:8090";

/// Issuer state: the server keys, shared with the issuance routes.
#[derive(Clone)]
struct Issuer {
    sk: ServerPrivateKey,
    pk: ServerPublicKey,
}

/// The guarded handler — only reached when the credential check passed.
async fn admitted() -> &'static str {
    "admitted \u{2713}  (this request carried a valid, unspent Tessera credential)\n"
}

/// The issuer's public key (hex), so a client can build a credential request.
async fn pubkey(State(issuer): State<Arc<Issuer>>) -> String {
    hex::encode(issuer.pk.serialize())
}

/// Real issuer: hex `CredentialRequest` in, hex `CredentialResponse` out.
async fn issue(State(issuer): State<Arc<Issuer>>, body: String) -> Result<String, StatusCode> {
    let req_bytes = hex::decode(body.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request = CredentialRequest::from_bytes(&req_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let response = create_credential_response(&issuer.sk, &issuer.pk, &request, &mut OsRng)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(hex::encode(response.to_bytes()))
}

/// DEMO-ONLY convenience: conflate issuer+client and return one ready-to-use
/// presentation header (so a human can `curl` in a single step).
async fn quick(State(issuer): State<Arc<Issuer>>) -> Result<String, StatusCode> {
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

    // The `tower` middleware guards only `/`; issuance routes are unguarded.
    let app = Router::new()
        .route("/", get(admitted).layer(TesseraLayer::new(guard)))
        .route("/pubkey", get(pubkey))
        .route("/issue", post(issue))
        .route("/quick", get(quick))
        .with_state(issuer);

    let listener = tokio::net::TcpListener::bind(ADDR)
        .await
        .expect("bind 127.0.0.1:8090");
    println!("tessera-tower-demo: guarded origin + issuer on http://{ADDR}");
    println!("  curl -i http://{ADDR}/                                  # 403 (no credential)");
    println!("  H=$(curl -s http://{ADDR}/quick)                        # demo header");
    println!("  curl -i -H \"Tessera-Presentation: $H\" http://{ADDR}/    # 200 (admitted)");
    println!("  curl -i -H \"Tessera-Presentation: $H\" http://{ADDR}/    # 403 (replay)");
    println!("  (real flow: GET /pubkey -> POST /issue <request hex> -> finalize client-side)");
    axum::serve(listener, app).await.expect("serve");
}
