//! Native fallback for the wasm round-trip test. The wasm-bindgen test
//! (`tests/wasm_roundtrip.rs`) only compiles/runs for `wasm32`; this exercises
//! the *identical* mint→present logic under a plain `cargo test` on the host,
//! so the round-trip is verifiable without installing a headless wasm runner.
//!
//! Run: `cargo test --manifest-path crates/tessera-wasm/Cargo.toml`

#![cfg(not(target_arch = "wasm32"))]

use tessera_wasm::{budget_roundtrip, mint_present_roundtrip};

#[test]
fn mint_then_present_produces_a_verifiable_header() {
    let (header, verified) = mint_present_roundtrip();
    assert!(verified, "freshly-minted presentation must verify");
    assert!(!header.is_empty(), "header must be non-empty");
    assert!(
        header.bytes().all(|b| b.is_ascii_hexdigit()),
        "header must be hex"
    );
    assert_eq!(header.len() % 2, 0, "hex string must have even length");
    assert!(header.len() >= 256, "presentation header looks too short");
}

#[test]
fn budget_is_enforced_and_each_presentation_differs() {
    let (headers, over_budget_errors) = budget_roundtrip(2);
    assert_eq!(headers.len(), 2, "should get one header per budget unit");
    assert_ne!(
        headers[0], headers[1],
        "presentations must be unlinkable / distinct"
    );
    assert!(over_budget_errors, "over-budget present must error");
}
