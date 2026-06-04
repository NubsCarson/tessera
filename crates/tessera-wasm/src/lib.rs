//! # tessera-wasm
//!
//! `wasm-bindgen` browser bindings for the Tessera ARC client. The goal of
//! ROADMAP track 3 ("WASM browser client"): let a *human* browse carrying a
//! credential. This crate compiles the [`tessera-arc`] crypto core +
//! [`tessera-client`] to `wasm32-unknown-unknown` and exposes a tiny, honest
//! JS surface:
//!
//!   * [`TesseraCredential`] — holds a finalized credential + its presentation
//!     budget, and `present()`s the hex `Tessera-Presentation` header. This is
//!     the **exact** value [`tessera_client::TesseraClient::presentation_header`]
//!     produces.
//!   * [`mint_local`] — a self-contained issuance helper that runs a full
//!     server-setup → request → response → finalize round-trip *locally* (no
//!     network), so a credential can be constructed in a demo / test. A real
//!     deployment would instead drive issuance against a live issuer; this
//!     helper exists so the in-browser mint→present round-trip is testable
//!     without standing up a server.
//!
//! ## Honesty
//!
//! This is a compiling, tested wasm **core** plus an extension **scaffold**
//! (`extension/`). The final mile — loading the extension in a real browser
//! and attaching the header to traffic hitting a live origin — needs a human
//! and a browser; it is not exercised here. See `extension/README.md`.
//!
//! Entropy comes from the Web Crypto API via `getrandom`'s `js` feature on
//! wasm32 (and from the OS CSPRNG when this crate's `rlib` is built/tested
//! natively). All JS-facing fallible operations return a `Result` that surfaces
//! as a thrown [`JsError`] rather than a panic/abort.

#![forbid(unsafe_code)]

use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential, Credential,
};
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::TesseraClient;
use wasm_bindgen::prelude::*;

/// A finalized ARC credential wrapped for the browser, tracking its
/// presentation budget for a single presentation context.
///
/// Construct one with [`mint_local`] (or, in a real deployment, from a
/// credential finalized against a live issuer). Each [`TesseraCredential::present`]
/// call yields a fresh, unlinkable hex `Tessera-Presentation` header and spends
/// one unit of budget; once the budget is exhausted, `present()` returns an
/// error.
#[wasm_bindgen]
pub struct TesseraCredential {
    client: TesseraClient,
}

#[wasm_bindgen]
impl TesseraCredential {
    /// Produce the next presentation, hex-encoded for the `Tessera-Presentation`
    /// header. This is byte-identical to
    /// [`tessera_client::TesseraClient::presentation_header`]. Returns an error
    /// (thrown to JS) once the presentation limit is reached.
    pub fn present(&mut self) -> Result<String, JsError> {
        self.client
            .presentation_header(&mut OsRng)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

impl TesseraCredential {
    /// Native constructor used by the `rlib` unit test (not exported to JS).
    fn from_credential(credential: Credential, presentation_context: &[u8], limit: u64) -> Self {
        Self {
            client: TesseraClient::new(credential, presentation_context, limit),
        }
    }
}

/// Mint a credential entirely in-process: set up a fresh server key, run the
/// ARC issuance round-trip (request → response → finalize), and wrap the result
/// for presentation against `presentation_context` up to `limit` times.
///
/// This keeps the **whole** crypto path (issuance *and* presentation) on the
/// wasm side so an in-browser round-trip is demonstrable without a network
/// peer. It is a demo/test helper — the server key is ephemeral and thrown
/// away, so presentations it produces verify only against that same ephemeral
/// key (which is exactly what the round-trip test checks). A production client
/// would obtain its credential from a real, persistent issuer.
///
/// Errors (e.g. an issuance proof failing to verify) are thrown to JS as a
/// `JsError`. `limit` must be at least 2 for a valid range proof.
#[wasm_bindgen]
pub fn mint_local(
    request_context: &[u8],
    presentation_context: &[u8],
    limit: u64,
) -> Result<TesseraCredential, JsError> {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);

    let (secrets, request) = create_credential_request(request_context, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let credential = finalize_credential(&secrets, &pk, &request, &response)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(TesseraCredential::from_credential(
        credential,
        presentation_context,
        limit,
    ))
}

/// Round-trip helper shared by the wasm-bindgen test and the native `rlib`
/// unit test: mint a credential, present once via the exact JS-facing path
/// ([`TesseraClient::presentation_header`]), and return the header string. The
/// credential is also independently verified against the ephemeral server key,
/// so the caller can assert the header is backed by a real proof check — not
/// just a length test.
///
/// This deliberately avoids the `#[wasm_bindgen]` `JsError`-returning functions
/// so it is callable on **both** wasm32 and native targets (calling a
/// `JsError`-returning fn on a non-wasm target panics in wasm-bindgen's shim).
#[doc(hidden)]
pub fn mint_present_roundtrip() -> (String, bool) {
    use tessera_arc::arc::{verify_presentation, PresentationState};

    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (request_ctx, present_ctx, limit) =
        (b"tessera-wasm/issue".as_slice(), b"origin".as_slice(), 4u64);

    let (secrets, request) = create_credential_request(request_ctx, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();

    // Header path (what JS sees): identical to TesseraClient::presentation_header.
    let mut wrapped = TesseraClient::new(credential.clone(), present_ctx, limit);
    let header = wrapped.presentation_header(&mut rng).unwrap();

    // Independently verify a freshly-minted presentation against the server key
    // so "well-formed/non-empty" is backed by an actual proof check.
    let mut state = PresentationState::new(credential, present_ctx, limit);
    let presentation = state.present(&mut rng).unwrap();
    let verified =
        verify_presentation(&sk, &pk, request_ctx, present_ctx, &presentation, limit).is_some();

    (header, verified)
}

/// Budget / unlinkability helper shared by both test targets: mint with a small
/// budget, present until exhausted, and return the per-presentation headers plus
/// whether the over-budget call errored. Like [`mint_present_roundtrip`], this
/// avoids the `JsError` path so it runs on wasm32 and native alike.
#[doc(hidden)]
pub fn budget_roundtrip(limit: u64) -> (Vec<String>, bool) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (request_ctx, present_ctx) = (b"wasm/issue".as_slice(), b"wasm/origin".as_slice());

    let (secrets, request) = create_credential_request(request_ctx, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();

    let mut client = TesseraClient::new(credential, present_ctx, limit);
    let mut headers = Vec::new();
    for _ in 0..limit {
        headers.push(client.presentation_header(&mut rng).unwrap());
    }
    let over_budget_errors = client.presentation_header(&mut rng).is_err();
    (headers, over_budget_errors)
}
