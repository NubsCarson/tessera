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
//!
//! **Preflight:** run with `--check` to validate all config and bind the listener
//! (then drop it) WITHOUT serving, contacting a peer, or establishing the shared
//! key. Prints `tessera-issuer: config OK` + a one-line summary and exits `0`;
//! on any bad config / bind failure it prints the specific error and exits non-zero.
//! Use it for container healthchecks and CI. Every env var is validated up front:
//! a bad value prints `tessera-issuer: config error: <msg>` and exits `2`; a bind
//! failure prints `tessera-issuer: could not bind <addr>: <err>` and exits `1` —
//! the issuer never silently falls back to a random ephemeral port.

use std::net::{TcpListener, ToSocketAddrs};

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

/// Default issuer bind address (kept identical whether or not the env var is set).
const DEFAULT_LISTEN: &str = "127.0.0.1:8121";

/// Print a config error to stderr in the shared `tessera-<role>:` format and exit
/// `2` — bad config must never panic and never silently proceed.
fn die(msg: &str) -> ! {
    eprintln!("tessera-issuer: config error: {msg}");
    std::process::exit(2);
}

/// The gate the issuer will run, resolved from validated config.
enum Gate {
    /// Proof-of-work gate at the given difficulty.
    Pow(u32),
    /// Paid (on-chain `TokenMint`) gate: validated RPC URL + 20-byte contract.
    Paid { rpc: String, contract: [u8; 20] },
}

/// Every env var this binary reads, parsed and validated. Built once, up front,
/// so both the normal path and `--check` share exactly one validation contract.
struct Config {
    /// The resolved-and-bindable listen address (string form preserved for output).
    listen: String,
    /// Optional shared ARC key path (already checked to be usable, not waited on).
    key_file: Option<String>,
    /// The selected issuance gate.
    gate: Gate,
    /// Optional durable redemption-ledger path (paid mode only; validated usable).
    ledger: Option<String>,
}

impl Config {
    /// A one-line human summary of the resolved config (for `--check`).
    fn summary(&self) -> String {
        let key = match &self.key_file {
            Some(p) => format!("shared key {p}"),
            None => "ephemeral key (single-node only)".to_string(),
        };
        match &self.gate {
            Gate::Pow(d) => format!(
                "listen {}  ·  {key}  ·  gate PoW ({d} leading zero bits)",
                self.listen
            ),
            Gate::Paid { rpc, contract } => {
                let ledger = self.ledger.as_deref().unwrap_or("in-memory");
                format!(
                    "listen {}  ·  {key}  ·  gate PAID (TokenMint 0x{} via {rpc}, ledger {ledger})",
                    self.listen,
                    hex::encode(contract)
                )
            }
        }
    }
}

/// Validate that a filesystem `path` the binary will read/write is plausibly
/// usable WITHOUT blocking (no 60s shared-key wait, no network). We only confirm
/// the parent directory exists, since a non-existent parent guarantees failure
/// later. `what` names the var for the error message.
fn check_path_usable(path: &str, what: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{what} is set but empty"));
    }
    let p = std::path::Path::new(path);
    // The file itself may legitimately not exist yet (it gets created). But its
    // parent directory must exist, or every later open will fail.
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = parent {
        if !dir.exists() {
            return Err(format!(
                "{what} {path}: parent directory {} does not exist",
                dir.display()
            ));
        }
        if !dir.is_dir() {
            return Err(format!(
                "{what} {path}: parent {} is not a directory",
                dir.display()
            ));
        }
    }
    // If the path already exists, it must be a regular file we could read.
    if p.exists() && !p.is_file() {
        return Err(format!("{what} {path}: exists but is not a regular file"));
    }
    Ok(())
}

/// Read, parse, and validate every env var. Returns a fully-resolved [`Config`]
/// or a specific, human-readable error message (the caller turns it into the
/// `config error:` line + exit 2). No side effects, no blocking, no network.
fn load_config() -> Result<Config, String> {
    // ── listen address ──────────────────────────────────────────────────────
    // Keep the DEFAULT value when unset; reject an unresolvable/unparsable value
    // rather than later silently grabbing a random port.
    let listen = std::env::var("TESSERA_ISSUER_LISTEN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LISTEN.to_string());
    // A bind address must resolve to at least one socket address (literal
    // SocketAddr or resolvable HOST:PORT). This does a DNS resolution but binds
    // nothing.
    match listen.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                return Err(format!(
                    "TESSERA_ISSUER_LISTEN {listen:?} resolved to no addresses"
                ));
            }
        }
        Err(e) => {
            return Err(format!(
                "TESSERA_ISSUER_LISTEN {listen:?} is not a valid bind address (expected HOST:PORT): {e}"
            ));
        }
    }

    // ── PoW difficulty ──────────────────────────────────────────────────────
    // If set, it MUST be a valid u32 — do not silently fall back to the default
    // on a typo. The MIN_DIFFICULTY clamp is preserved (refuse a wide-open gate).
    let difficulty = match std::env::var("TESSERA_POW_DIFFICULTY") {
        Ok(s) if !s.is_empty() => s.parse::<u32>().map_err(|_| {
            format!("TESSERA_POW_DIFFICULTY {s:?} is not a non-negative integer (u32)")
        })?,
        _ => DEFAULT_DIFFICULTY,
    }
    .max(MIN_DIFFICULTY);

    // ── shared key file ─────────────────────────────────────────────────────
    let key_file = match std::env::var("TESSERA_KEY_FILE") {
        Ok(path) if !path.is_empty() => {
            check_path_usable(&path, "TESSERA_KEY_FILE")?;
            Some(path)
        }
        Ok(_) => {
            return Err(
                "TESSERA_KEY_FILE is set but empty (unset it for an ephemeral single-node issuer, or give it a path)"
                    .to_string(),
            );
        }
        Err(_) => None,
    };

    // ── paid-mode gate ──────────────────────────────────────────────────────
    // Paid mode iff BOTH TESSERA_MINT_RPC and TESSERA_MINT_CONTRACT are set
    // (preserved from the original). But a half-configured pair, an unsupported
    // RPC scheme, or a malformed contract is a config error, not a silent
    // fall-through to PoW — the operator clearly intended paid mode.
    let rpc_raw = std::env::var("TESSERA_MINT_RPC")
        .ok()
        .filter(|s| !s.is_empty());
    let contract_raw = std::env::var("TESSERA_MINT_CONTRACT")
        .ok()
        .filter(|s| !s.is_empty());

    let (gate, ledger) = match (rpc_raw, contract_raw) {
        (Some(rpc), Some(contract)) => {
            // The EthRpc reader only speaks plaintext http:// (see mint::EthRpc).
            if !rpc.starts_with("http://") {
                return Err(format!(
                    "TESSERA_MINT_RPC {rpc:?} must be an http:// URL (only http:// JSON-RPC is supported)"
                ));
            }
            let contract = parse_addr(&contract).ok_or_else(|| {
                format!(
                    "TESSERA_MINT_CONTRACT {contract:?} is not a 20-byte hex address (0x… 40 hex chars)"
                )
            })?;
            // Optional durable ledger path — validate usability if present.
            let ledger = match std::env::var("TESSERA_MINT_LEDGER") {
                Ok(p) if !p.is_empty() => {
                    check_path_usable(&p, "TESSERA_MINT_LEDGER")?;
                    Some(p)
                }
                _ => None,
            };
            (Gate::Paid { rpc, contract }, ledger)
        }
        (Some(_), None) => {
            return Err(
                "TESSERA_MINT_RPC is set but TESSERA_MINT_CONTRACT is not — paid mode needs both"
                    .to_string(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "TESSERA_MINT_CONTRACT is set but TESSERA_MINT_RPC is not — paid mode needs both"
                    .to_string(),
            );
        }
        (None, None) => (Gate::Pow(difficulty), None),
    };

    Ok(Config {
        listen,
        key_file,
        gate,
        ledger,
    })
}

/// Bind the issuer's listener at the (defaulted-or-explicit) address. On failure
/// print the specific error and exit `1` — NEVER silently fall back to a random
/// ephemeral port, which would quietly break the multi-node topology.
fn bind_listener(listen: &str) -> TcpListener {
    match TcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("tessera-issuer: could not bind {listen}: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    // Validate ALL config up front — bad config is exit 2, never a panic.
    let config = match load_config() {
        Ok(c) => c,
        Err(msg) => die(&msg),
    };

    // ── --check preflight ───────────────────────────────────────────────────
    // Validate config (done above), bind the listener the binary would use (then
    // drop it), report, and exit 0. Do NOT establish the shared key (it can block
    // up to ~60s on a real volume), do NOT serve, do NOT contact a peer.
    if std::env::args().any(|a| a == "--check") {
        let listener = bind_listener(&config.listen);
        let addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| config.listen.clone());
        drop(listener); // release the port — this is only a preflight.
        println!("tessera-issuer: config OK");
        println!("  {}", config.summary());
        println!("  bound {addr} (released)");
        std::process::exit(0);
    }

    // ── normal serving path ─────────────────────────────────────────────────
    // Establish the shared key now (may block briefly until convergence), or mint
    // an ephemeral single-node key.
    let (sk, pk, key_src) = match &config.key_file {
        Some(path) => {
            // Convergent shared bootstrap: issuer + exit can never diverge.
            let (sk, pk) = ensure_shared_key(path);
            (sk, pk, format!("shared key {path}"))
        }
        None => {
            let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
            (sk, pk, "ephemeral key (single-node only)".to_string())
        }
    };

    let listener = bind_listener(&config.listen);
    let addr = listener.local_addr().expect("issuer addr");
    let fingerprint = hex::encode(&pk.serialize()[..8]);

    println!("Tessera ISSUER (credential authority) live on {addr}");
    println!("  key:        {key_src}  ·  pk fingerprint {fingerprint}…");
    println!("  the exit (tessera-proxy) MUST share this key to verify presentations.");

    match config.gate {
        Gate::Paid { rpc, contract } => {
            let ledger = match &config.ledger {
                Some(p) => RedemptionLedger::at(p),
                None => RedemptionLedger::in_memory(),
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
        Gate::Pow(difficulty) => {
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
