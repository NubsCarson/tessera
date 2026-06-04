//! In-wasm round-trip test: mint → present, then assert the
//! `Tessera-Presentation` header is well-formed (hex, non-empty, sane length)
//! and that an independently-minted presentation actually verifies against the
//! ephemeral server key.
//!
//! Run headlessly with the `wasm-bindgen-test-runner` (from `wasm-bindgen-cli`,
//! pinned to the SAME version as the `wasm-bindgen` crate) + node:
//!
//! ```sh
//! cargo install wasm-bindgen-cli --version 0.2.122
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!   cargo test --manifest-path crates/tessera-wasm/Cargo.toml \
//!   --target wasm32-unknown-unknown
//! ```
//!
//! `wasm-pack test --node` drives the identical test. The same logic also runs
//! natively under plain `cargo test` (see `tests/native_roundtrip.rs`), which
//! is the fallback when no wasm runner is installed.

#![cfg(target_arch = "wasm32")]

use rand_core::OsRng;
use tessera_wasm::{budget_roundtrip, mint_local, mint_present_roundtrip, prepare_issuance};
use wasm_bindgen_test::*;

// No `wasm_bindgen_test_configure!(run_in_browser)`: the default harness runs
// under node via `wasm-bindgen-test-runner`, which is what CI / a headless run
// uses. `wasm-pack test --headless --firefox` (or `--chrome`) drives the same
// tests in a real browser when you want the Web Crypto / extension environment.

#[wasm_bindgen_test]
fn mint_then_present_produces_a_verifiable_header() {
    let (header, verified) = mint_present_roundtrip();
    assert!(verified, "freshly-minted presentation must verify");
    assert!(!header.is_empty(), "header must be non-empty");
    assert!(
        header.bytes().all(|b| b.is_ascii_hexdigit()),
        "header must be hex"
    );
    // Length is even (hex pairs) and substantial (a presentation is several
    // hundred bytes; >= 256 hex chars is a comfortable lower bound).
    assert_eq!(header.len() % 2, 0, "hex string must have even length");
    assert!(header.len() >= 256, "presentation header looks too short");
}

#[wasm_bindgen_test]
fn budget_is_enforced_and_each_presentation_differs() {
    let (headers, over_budget_errors) = budget_roundtrip(2);
    assert_eq!(headers.len(), 2, "should get one header per budget unit");
    assert_ne!(
        headers[0], headers[1],
        "presentations must be unlinkable / distinct"
    );
    assert!(over_budget_errors, "over-budget present must error");
}

#[wasm_bindgen_test]
fn js_facing_mint_local_and_present_work_in_wasm() {
    // Exercise the actual exported JS surface (the `JsError`-returning path),
    // which only behaves correctly on a wasm target.
    let mut cred = mint_local(b"wasm/issue", b"wasm/origin", 2).expect("mint should succeed");
    let h0 = cred.present().expect("first present in budget");
    let h1 = cred.present().expect("second present in budget");
    assert_ne!(h0, h1, "presentations must be distinct");
    assert!(cred.present().is_err(), "over-budget present must error");
}

#[wasm_bindgen_test]
fn real_issuance_against_an_external_key_verifies() {
    // The production path: a credential issued by an EXTERNAL key (the issuer),
    // obtained over the hex wire format, must present-verify against that key —
    // i.e. the wasm client genuinely interoperates with a real Rust issuer/origin.
    use tessera_arc::arc::{create_credential_response, verify_presentation, Presentation};
    use tessera_arc::keys::ServerPrivateKey;

    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let pk_bytes = pk.serialize();

    // Browser: prepare a real issuance bound to the issuer's PUBLIC key only.
    let flow = prepare_issuance(&pk_bytes, b"issue/v1", b"origin/v1", 4).expect("prepare");
    let req = tessera_arc::arc::CredentialRequest::from_bytes(
        &hex::decode(flow.request_hex()).expect("hex"),
    )
    .expect("request decodes");

    // Issuer (external): produce the credential response from the request.
    let response = create_credential_response(&sk, &pk, &req, &mut rng).expect("issue");
    let response_hex = hex::encode(response.to_bytes());

    // Browser: finalize + present, then verify against the EXTERNAL key.
    let mut cred = flow.finalize(&response_hex).expect("finalize");
    let header = cred.present().expect("present");
    let presentation =
        Presentation::from_bytes(&hex::decode(&header).expect("hex"), 4).expect("presentation");
    assert!(
        verify_presentation(&sk, &pk, b"issue/v1", b"origin/v1", &presentation, 4).is_some(),
        "a credential issued by an external key must present-verify against it"
    );
}
