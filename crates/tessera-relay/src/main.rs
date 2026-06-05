//! `tessera-relay` binary: stands up the **2-hop split-trust loop** locally —
//! a credential-blind RELAY (first hop) in front of a credential-gated EXIT
//! (`tessera-proxy`) — and prints how to drive it with `curl`.
//!
//! ```text
//! curl --proxy http://RELAY  →  RELAY  →  EXIT (checks the credential)  →  site
//! ```
//!
//! The relay learns only {client, exit}; the exit learns only {destination, a
//! valid credential}; neither sees content. This proves the *protocol*; a real
//! Tor-blocked site returning 200 needs a real clean egress IP (see the README).
//!
//! Run:  `cargo run -p tessera-relay`            (exit egresses directly)
//!       `cargo run -p tessera-relay -- --tor`   (exit egresses via Tor :9050)
//!       `cargo run -p tessera-relay -- --check`  (validate config + bind, then exit)
//!
//! `--check` is a fast PREFLIGHT for healthchecks/CI: it validates every env var
//! the binary reads, binds the listener(s) it would use (then drops them), prints
//! a one-line config summary, and exits 0 — without serving, issuing a credential,
//! or contacting any peer. On a config or bind error it exits non-zero.
//!
//! Config env vars (validated up front; an invalid value is a fatal config error):
//!   `TESSERA_RELAY_LISTEN`  relay first-hop bind `HOST:PORT` (deploy mode; no default)
//!   `TESSERA_EXIT_ADDR`     external exit `HOST:PORT`, resolvable (deploy mode; no default)
//! When BOTH are set the binary runs JUST the relay first hop, forwarding to that
//! external exit. Otherwise it runs the all-in-one local demo (exit on an ephemeral
//! port, relay on the fixed default `127.0.0.1:8119`).

use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::Arc;

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::serve as serve_relay;

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

/// The relay's fixed default first-hop bind in the all-in-one local demo.
const DEFAULT_RELAY_LISTEN: &str = "127.0.0.1:8119";

/// Print `tessera-relay: <msg>` to stderr and exit non-zero (default 2). For
/// config errors this is the only way out — we never panic on bad config and
/// never silently proceed.
fn die(msg: &str) -> ! {
    eprintln!("tessera-relay: {msg}");
    std::process::exit(2)
}

/// Print a "could not bind" error and exit 1 — distinct from a config-grammar
/// error (exit 2) because the address parsed fine but the OS refused the bind
/// (port in use, permission, etc.). We do NOT silently fall back to an ephemeral
/// port: that quietly breaks the multi-node topology.
fn die_bind(addr: &str, err: &std::io::Error) -> ! {
    eprintln!("tessera-relay: could not bind {addr}: {err}");
    std::process::exit(1)
}

/// Resolve a `HOST:PORT` env value to a single `SocketAddr`, erroring clearly
/// (exit 2) on a parse/resolution failure. Used for the external exit address,
/// which may be a container hostname like `exit:8118`.
fn resolve_socket_addr(var: &str, value: &str) -> SocketAddr {
    match value.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => die(&format!(
                "config error: {var}=\"{value}\" resolved to no addresses (expected HOST:PORT)"
            )),
        },
        Err(e) => die(&format!(
            "config error: {var}=\"{value}\" is not a resolvable HOST:PORT ({e})"
        )),
    }
}

/// Validate (parse/resolve) a bind address without binding it. The relay listen
/// address must be a literal `HOST:PORT` we can bind, so we resolve it the same
/// way the OS will. Returns the canonical value string for the summary.
fn validate_bind_addr(var: &str, value: &str) -> String {
    // `TcpListener::bind` takes `ToSocketAddrs`; resolving here surfaces a bad
    // address as a clear config error rather than a late bind failure.
    let _ = resolve_socket_addr(var, value);
    value.to_string()
}

/// The binary's fully-resolved configuration, computed once up front so that
/// both the real run and `--check` share exactly the same validation contract.
struct Config {
    /// `Some((relay_listen, exit_addr))` in deploy mode (both env vars set);
    /// `None` for the all-in-one local demo.
    deploy: Option<(String, SocketAddr)>,
    /// The relay's first-hop bind address (the demo's fixed default, or the
    /// deploy `TESSERA_RELAY_LISTEN`).
    relay_listen: String,
    /// Whether the exit egresses via Tor (the `--tor` flag; demo mode only —
    /// in deploy mode the relay forwards to an external exit and never sets it).
    tor: bool,
}

/// Read + validate every env var / flag the binary uses, exiting (2) on any
/// invalid value. Never panics on bad config; never silently proceeds.
fn load_config() -> Config {
    let tor = std::env::args().any(|a| a == "--tor");

    let relay_listen_env = std::env::var("TESSERA_RELAY_LISTEN").ok();
    let exit_addr_env = std::env::var("TESSERA_EXIT_ADDR").ok();

    // Deploy mode iff BOTH are set (matches the original gating). If exactly one
    // is set the operator almost certainly forgot the other — that is a config
    // error, not a silent drop into the local demo on a surprise address.
    match (relay_listen_env, exit_addr_env) {
        (Some(listen), Some(exit)) => {
            let relay_listen = validate_bind_addr("TESSERA_RELAY_LISTEN", &listen);
            let exit_addr = resolve_socket_addr("TESSERA_EXIT_ADDR", &exit);
            Config {
                deploy: Some((relay_listen.clone(), exit_addr)),
                relay_listen,
                tor,
            }
        }
        (Some(_), None) => die(
            "config error: TESSERA_RELAY_LISTEN is set but TESSERA_EXIT_ADDR is not — \
             deploy mode (forward to an external exit) needs both, or unset both for the local demo",
        ),
        (None, Some(_)) => die(
            "config error: TESSERA_EXIT_ADDR is set but TESSERA_RELAY_LISTEN is not — \
             deploy mode (forward to an external exit) needs both, or unset both for the local demo",
        ),
        (None, None) => Config {
            deploy: None,
            relay_listen: DEFAULT_RELAY_LISTEN.to_string(),
            tor,
        },
    }
}

/// Bind `addr` (explicit/defaulted), exiting 1 with a clear message on failure.
/// CRUCIAL: never falls back to an ephemeral port — a failed bind is fatal so we
/// don't quietly break the multi-node topology.
fn bind_or_die(addr: &str) -> TcpListener {
    match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => die_bind(addr, &e),
    }
}

fn issue(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

/// `--check` PREFLIGHT: validate all config, bind whatever listener(s) the binary
/// would use (then drop them), print a one-line summary, and exit 0. Does NOT
/// serve, issue a credential, contact a peer, or block. On any failure it exits
/// non-zero with a specific error (via `die`/`die_bind`).
fn run_check(cfg: &Config) -> ! {
    match &cfg.deploy {
        Some((relay_listen, exit_addr)) => {
            // Deploy mode: the binary binds exactly one listener (the relay first
            // hop); the exit is external, so we only resolve it (already done).
            let listener = bind_or_die(relay_listen);
            let bound = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| relay_listen.clone());
            drop(listener);
            println!("tessera-relay: config OK");
            println!(
                "  mode=deploy relay_listen={bound} exit_addr={exit_addr} \
                 (forward-only first hop; the external exit gates the credential)"
            );
        }
        None => {
            // Local demo: the binary binds TWO listeners — the co-located exit on
            // an ephemeral port and the relay on its fixed default. Bind both to
            // prove they are bindable, then drop them.
            let exit_listener = bind_or_die("127.0.0.1:0");
            let exit_bound = exit_listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "127.0.0.1:0".to_string());
            let relay_listener = bind_or_die(&cfg.relay_listen);
            let relay_bound = relay_listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| cfg.relay_listen.clone());
            drop(relay_listener);
            drop(exit_listener);
            let route = if cfg.tor {
                "exit via Tor :9050"
            } else {
                "exit direct"
            };
            println!("tessera-relay: config OK");
            println!("  mode=demo relay_listen={relay_bound} exit_listen={exit_bound} ({route})");
        }
    }
    std::process::exit(0)
}

fn main() {
    // Validate ALL config up front — this exits 2 on any invalid env value before
    // we bind, serve, issue a credential, or contact a peer.
    let cfg = load_config();

    // Fast PREFLIGHT: validate + bind (then drop), summarize, exit. Never serves.
    if std::env::args().any(|a| a == "--check") {
        run_check(&cfg);
    }

    // Deploy mode (env): run JUST the relay first hop, forwarding to an EXTERNAL
    // exit — for a containerized/TEE node (see docs/DEPLOY.md). When both are set
    // we skip the all-in-one local demo below. The exit address was resolved once
    // at startup (a hostname like `exit:8118` resolves via the container DNS).
    if let Some((relay_listen, exit_addr)) = cfg.deploy {
        let listener = bind_or_die(&relay_listen);
        let addr = listener.local_addr().expect("relay addr");
        println!(
            "Tessera RELAY node live on {addr} -> exit {exit_addr} \
             (credential-blind first hop; learns {{client, exit}}, never the destination)"
        );
        let _ = serve_relay(listener, exit_addr, None).join();
        return;
    }

    let tor = cfg.tor;
    let mut rng = OsRng;

    // --- EXIT: the credential-gated CONNECT proxy (tessera-proxy) ---
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let credential = issue(&sk, &pk, &mut rng);

    let exit_listener = bind_or_die("127.0.0.1:0");
    let exit_addr = exit_listener.local_addr().expect("exit addr");
    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));
    let upstream = if tor {
        Upstream::Tor("127.0.0.1:9050".to_string())
    } else {
        Upstream::Direct
    };
    serve_exit(exit_listener, guard, upstream);

    // --- RELAY: the credential-blind first hop, fixed to forward to the exit ---
    // A failed bind on the (defaulted) relay address is FATAL: we do NOT silently
    // grab a random ephemeral port, which would quietly break the topology.
    let relay_listener = bind_or_die(&cfg.relay_listen);
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    serve_relay(relay_listener, exit_addr, None);

    // Mint one single-use presentation to paste into the example request.
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    let header = client
        .presentation_header(&mut rng)
        .expect("mint presentation");

    let route = if tor {
        "exit egresses via Tor (SOCKS5 127.0.0.1:9050)"
    } else {
        "exit egresses directly"
    };
    println!("\nTessera 2-hop split-trust loop is live:");
    println!("  RELAY  http://{relay_addr}   (first hop — credential-blind; learns {{client, exit}}, never the destination)");
    println!("  EXIT   http://{exit_addr}   (credential-gated — learns {{destination, a valid credential}}, never the client)");
    println!("  {route}\n");
    println!("Split-trust: no single hop holds who + where + what. TLS is end-to-end (CONNECT),");
    println!("so neither hop sees plaintext. Point curl at the RELAY; it nests the inner CONNECT");
    println!("to the destination (with the credential) through to the exit:\n");
    println!("  curl -sS -x http://{relay_addr} \\");
    println!("    --proxy-header 'Tessera-Presentation: {header}' \\");
    println!("    https://example.com/\n");
    println!("Note: plain `curl -x RELAY` does a single CONNECT to the relay's *outer* target,");
    println!(
        "which the relay forwards as-is to the exit; the credential header rides on the inner"
    );
    println!("CONNECT the exit reads. (The integration test drives the exact nested form via");
    println!(
        "`tessera_relay::open_through_relay`.) A request with no/invalid credential is refused"
    );
    println!("by the EXIT with 407; the relay never sees the credential or the destination.\n");
    println!(
        "HONEST: this proves the loop LOCALLY. A real Tor-403 site returning 200 needs a real"
    );
    println!(
        "clean egress IP behind the exit (run with --tor + a clean exit) — a manual final step."
    );
    println!("Single-use credential (the rate limit). Ctrl-C to stop.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
