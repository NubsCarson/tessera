#![no_main]
//! Every protocol-struct decoder must reject arbitrary bytes without panicking.
use libfuzzer_sys::fuzz_target;
use tessera_arc::arc::{CredentialRequest, CredentialResponse, Presentation};
use tessera_arc::keys::ServerPublicKey;

fuzz_target!(|data: &[u8]| {
    let _ = ServerPublicKey::from_bytes(data);
    let _ = CredentialRequest::from_bytes(data);
    let _ = CredentialResponse::from_bytes(data);
    // Cover the special-case (limit=2 -> 1 bit) and multi-bit range-proof shapes,
    // plus degenerate limits that must not trip `compute_bases`.
    for limit in [0u64, 1, 2, 3, 8, 1024] {
        let _ = Presentation::from_bytes(data, limit);
    }
});
