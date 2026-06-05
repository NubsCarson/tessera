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
//!
//! **Paid mode** (gate on an on-chain `TokenMint` purchase instead of PoW) — set
//! both:
//!   `TESSERA_MINT_RPC`       Ethereum JSON-RPC URL (e.g. `http://127.0.0.1:8545`)
//!   `TESSERA_MINT_CONTRACT`  TokenMint address (0x… 20 bytes)
//!   `TESSERA_MINT_LEDGER`    optional durable redemption-ledger path

use std::net::TcpListener;

use rand_core::OsRng;
use tessera_arc::keys::ServerPrivateKey;
use tessera_issuer::mint::{EthRpc, PaymentGate, RedemptionLedger, TOKENS_PER_CREDENTIAL};
use tessera_issuer::{ensure_shared_key, serve_issuance, serve_issuance_paid};

/// Parse a `0x`-prefixed (or bare) 20-byte hex address.
fn parse_addr(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(s.trim().strip_prefix("0x").unwrap_or(s.trim())).ok()?;
    (bytes.len() == 20).then(|| {
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes);
        a
    })
}

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

    // Paid mode iff both TESSERA_MINT_RPC and TESSERA_MINT_CONTRACT are set.
    let paid = match (
        std::env::var("TESSERA_MINT_RPC")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("TESSERA_MINT_CONTRACT")
            .ok()
            .and_then(|s| parse_addr(&s)),
    ) {
        (Some(rpc), Some(contract)) => Some((rpc, contract)),
        _ => None,
    };

    println!("Tessera ISSUER (credential authority) live on {addr}");
    println!("  key:        {key_src}  ·  pk fingerprint {fingerprint}…");
    println!("  the exit (tessera-proxy) MUST share this key to verify presentations.");

    match paid {
        Some((rpc, contract)) => {
            let ledger = match std::env::var("TESSERA_MINT_LEDGER") {
                Ok(p) if !p.is_empty() => RedemptionLedger::at(p),
                _ => RedemptionLedger::in_memory(),
            };
            let gate = PaymentGate::new(
                EthRpc::new(rpc.clone(), contract),
                ledger,
                TOKENS_PER_CREDENTIAL,
            );
            println!(
                "  gate:       PAID — TokenMint 0x{} via {rpc}  ·  {TOKENS_PER_CREDENTIAL} tokens/credential",
                hex::encode(contract)
            );
            println!("  clients:    set TESSERA_ISSUER={addr} + TESSERA_BUYER_KEY=<hex secp256k1 secret>.");
            serve_issuance_paid(listener, sk, pk, gate)
                .join()
                .expect("issuer thread");
        }
        None => {
            println!("  gate:       PoW — {difficulty} leading zero bits per credential");
            println!(
                "  clients:    set TESSERA_ISSUER={addr} (and TESSERA_ISSUER_PK={fingerprint}… to pin)."
            );
            serve_issuance(listener, sk, pk, difficulty)
                .join()
                .expect("issuer thread");
        }
    }
}
