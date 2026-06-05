//! `tessera-issuer` binary: the **credential authority**. Serves PoW-gated ARC
//! issuance over TCP (see [`tessera_issuer::net`]) so clients can *obtain* a
//! credential from a running node, then present it at the exit.
//!
//! Because ARC is keyed-verification, the issuer and the exit (`tessera-proxy`)
//! MUST share one server key — point both at the same `TESSERA_KEY_FILE`.
//!
//! Config (env):
//!   `TESSERA_ISSUER_LISTEN`  bind address (default `127.0.0.1:8121`)
//!   `TESSERA_KEY_FILE`       shared ARC server-key path (default: an ephemeral key)
//!   `TESSERA_POW_DIFFICULTY` leading-zero-bit PoW cost per credential (default `16`)

use std::net::TcpListener;

use rand_core::OsRng;
use tessera_arc::keys::ServerPrivateKey;
use tessera_issuer::{ensure_shared_key, serve_issuance};

/// Default PoW difficulty (leading zero bits ≈ `2^difficulty` hashes per mint).
const DEFAULT_DIFFICULTY: u32 = 16;

/// Floor on the PoW difficulty: `0` would make every solution valid, disabling
/// the only issuance abuse-control lever (the threat model). Refuse to run wide open.
const MIN_DIFFICULTY: u32 = 1;

fn main() {
    let listen = std::env::var("TESSERA_ISSUER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8121".into());
    let difficulty = std::env::var("TESSERA_POW_DIFFICULTY")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_DIFFICULTY)
        .max(MIN_DIFFICULTY);

    let (sk, pk, key_src) = match std::env::var("TESSERA_KEY_FILE") {
        Ok(path) if !path.is_empty() => {
            // Convergent shared bootstrap: issuer + exit can never diverge.
            let (sk, pk) = ensure_shared_key(&path);
            (sk, pk, format!("shared key {path}"))
        }
        _ => {
            let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
            (sk, pk, "ephemeral key (single-node only)".to_string())
        }
    };

    let listener = TcpListener::bind(&listen)
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind issuer");
    let addr = listener.local_addr().expect("issuer addr");
    let fingerprint = hex::encode(&pk.serialize()[..8]);

    println!("Tessera ISSUER (credential authority) live on {addr}");
    println!("  key:        {key_src}  ·  pk fingerprint {fingerprint}…");
    println!("  PoW cost:   {difficulty} leading zero bits per credential");
    println!("  the exit (tessera-proxy) MUST share this key to verify presentations.");
    println!(
        "  clients:    set TESSERA_ISSUER={addr} (and TESSERA_ISSUER_PK={fingerprint}… to pin)."
    );

    serve_issuance(listener, sk, pk, difficulty)
        .join()
        .expect("issuer thread");
}
