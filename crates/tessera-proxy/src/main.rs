//! `tessera-proxy` binary: a credential-gated CONNECT proxy you point a normal
//! HTTPS client at. Admits on a Tessera credential, never the IP; tunnels TLS
//! end-to-end to any HTTPS site (e.g. the Anthropic API), optionally via Tor.
//!
//! Run:  `cargo run -p tessera-proxy`             (direct upstream)
//!       `cargo run -p tessera-proxy -- --tor`    (tunnel through Tor at :9050)
//!       `cargo run -p tessera-proxy -- --check`  (fast preflight: validate
//!                                                 config + bind, then exit)
//!
//! Config is validated FAIL-FAST up front: an invalid env var prints
//! `tessera-exit: config error: <msg>` to stderr and exits 2 (never panics, never
//! silently proceeds). `--check` is a non-serving preflight for healthchecks/CI:
//! it validates all config, binds the listener it would use (then drops it),
//! prints `tessera-exit: config OK` + a one-line summary to stdout, and exits 0 —
//! it does NOT serve, mint/contact anything, or block.

use std::net::{TcpListener, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_issuer::ensure_shared_key;
use tessera_origin::OriginGuard;
use tessera_proxy::{serve_observed_shaped, ShapingConfig, Upstream, VolumeShaper};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

/// This binary's role string, used in every operator-facing diagnostic.
const ROLE: &str = "exit";

/// Default bind address when `TESSERA_LISTEN` is unset (preserves the local demo).
const DEFAULT_LISTEN: &str = "127.0.0.1:8118";

/// Default Tor SOCKS5 endpoint when `--tor`/`TESSERA_UPSTREAM=tor` is selected.
const DEFAULT_TOR: &str = "127.0.0.1:9050";

/// Print a config/operational error to stderr and exit non-zero. Used for every
/// fail-fast path so bad config dies loudly with a specific message — it never
/// panics and never silently proceeds.
fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    // Convention: exit code 2 == invalid config; 1 == bind failure. Callers pass
    // a fully-formed message and pick the code via `die_code`; this default is the
    // config-error code.
    std::process::exit(2);
}

/// Like [`die`], but with an explicit exit code (e.g. 1 for a bind failure).
fn die_code(msg: &str, code: i32) -> ! {
    eprintln!("{msg}");
    std::process::exit(code);
}

/// The resolved, validated upstream selection plus a human label for summaries.
struct UpstreamPlan {
    upstream: Upstream,
    tor: bool,
}

/// Validate `TESSERA_UPSTREAM` against EXACTLY the grammar the code supports —
/// `direct` | `tor` | `tor:HOST:PORT` — falling back to `--tor` then `Direct`
/// when the var is unset. Any *set* value outside that grammar is a config error
/// (the old `_ => Direct` arm silently swallowed typos like `i2p`/`socks5:…`).
/// For `tor:HOST:PORT`, the SOCKS5 address must resolve.
fn resolve_upstream(tor_arg: bool) -> UpstreamPlan {
    let upstream = match std::env::var("TESSERA_UPSTREAM").ok().as_deref() {
        Some("direct") => Upstream::Direct,
        Some("tor") => Upstream::Tor(DEFAULT_TOR.into()),
        Some(s) if s.starts_with("tor:") => {
            let proxy = &s[4..];
            if proxy.is_empty() {
                die(&format!(
                    "tessera-{ROLE}: config error: TESSERA_UPSTREAM 'tor:' is missing a HOST:PORT (use tor:HOST:PORT, e.g. tor:127.0.0.1:9050)"
                ));
            }
            validate_addr("TESSERA_UPSTREAM tor proxy", proxy);
            Upstream::Tor(proxy.to_string())
        }
        // A value is set but is none of direct|tor|tor:HOST:PORT — don't silently
        // proceed as Direct; tell the operator exactly what's accepted.
        Some(other) => die(&format!(
            "tessera-{ROLE}: config error: TESSERA_UPSTREAM {other:?} is not one of: direct | tor | tor:HOST:PORT"
        )),
        // Unset: honor the legacy `--tor` flag, else direct.
        None if tor_arg => Upstream::Tor(DEFAULT_TOR.into()),
        None => Upstream::Direct,
    };
    let tor = matches!(upstream, Upstream::Tor(_));
    UpstreamPlan { upstream, tor }
}

/// Validate that `value` is a resolvable `HOST:PORT` (the form `TcpListener::bind`
/// / `TcpStream::connect` need). Errors clearly and fail-fast on anything that
/// doesn't parse/resolve, naming `field` so the operator knows which var is wrong.
fn validate_addr(field: &str, value: &str) {
    match value.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                die(&format!(
                    "tessera-{ROLE}: config error: {field} {value:?} resolved to no addresses"
                ));
            }
        }
        Err(e) => die(&format!(
            "tessera-{ROLE}: config error: {field} {value:?} is not a valid HOST:PORT: {e}"
        )),
    }
}

/// Validate `TESSERA_KEY_FILE`: it is optional, but if *set* it must be non-empty
/// (an empty value is the "ephemeral self-issuing exit" sentinel only when the var
/// is wholly unset — a present-but-blank value is almost always a misconfigured
/// container env and would silently downgrade to an ephemeral key, breaking
/// issuer/exit key convergence). Returns the non-empty path if one was set.
fn validate_key_file() -> Option<String> {
    match std::env::var("TESSERA_KEY_FILE") {
        Ok(path) if !path.is_empty() => Some(path),
        Ok(_) => die(&format!(
            "tessera-{ROLE}: config error: TESSERA_KEY_FILE is set but empty (unset it for an ephemeral self-issuing exit, or give it a path)"
        )),
        Err(_) => None,
    }
}

fn issue(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

fn main() {
    let mut rng = OsRng;

    // Deploy config via env (ADDITIVE — the defaults preserve the local demo, so
    // `cargo run -p tessera-proxy` is unchanged; a containerized/TEE node sets
    // these — see docs/DEPLOY.md):
    //   TESSERA_LISTEN   bind address (default 127.0.0.1:8118; a node sets 0.0.0.0:PORT)
    //   TESSERA_UPSTREAM "direct" | "tor" | "tor:HOST:PORT" (default direct; `--tor` => tor)
    //   TESSERA_KEY_FILE shared ARC server-key path — set it (same value as the
    //                    issuer's) so the exit verifies credentials minted by the
    //                    issuer; unset => ephemeral self-issuing exit (the demo).
    let args: Vec<String> = std::env::args().collect();
    let tor_arg = args.iter().any(|a| a == "--tor");
    let check = args.iter().any(|a| a == "--check");

    // ---- FAIL-FAST config validation (runs for every mode, before any work) ----
    let listen = std::env::var("TESSERA_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.into());
    validate_addr("TESSERA_LISTEN", &listen);
    let UpstreamPlan { upstream, tor } = resolve_upstream(tor_arg);
    let key_file = validate_key_file();

    // ---- --check: non-serving preflight (validate + bind + drop, then exit) ----
    if check {
        // Bind the exact listener the binary would serve on, to prove the address
        // is actually bindable here — then drop it immediately (no serving, no
        // credential mint, no peer contact, no key-file establishment, no block).
        match TcpListener::bind(&listen) {
            Ok(l) => {
                let addr = l
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| listen.clone());
                drop(l);
                let mode = if tor { "tor" } else { "direct" };
                let upstream_label = match &upstream {
                    Upstream::Direct => "direct".to_string(),
                    Upstream::Tor(p) => format!("tor via {p}"),
                };
                let key = match &key_file {
                    Some(p) => format!("shared:{p}"),
                    None => "ephemeral".to_string(),
                };
                println!("tessera-{ROLE}: config OK");
                println!(
                    "tessera-{ROLE}: listen={addr} upstream={upstream_label} mode={mode} key={key}"
                );
                std::process::exit(0);
            }
            Err(e) => die_code(&format!("tessera-{ROLE}: could not bind {listen}: {e}"), 1),
        }
    }

    // ---- normal serving path (config already validated above) ----

    // Convergent shared-key bootstrap: the exit loads the SAME ARC key as the
    // issuer (they can never diverge — see tessera_issuer::ensure_shared_key).
    let (sk, pk) = match &key_file {
        Some(path) => ensure_shared_key(path),
        None => ServerPrivateKey::setup(&mut rng),
    };
    let credential = issue(&sk, &pk, &mut rng);

    // Bind the (defaulted-or-explicit) listen address. On failure, die loudly with
    // exit 1 — do NOT silently fall back to a random ephemeral port, which would
    // quietly break the multi-node topology (peers expect us on `listen`).
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => die_code(&format!("tessera-{ROLE}: could not bind {listen}: {e}"), 1),
    };
    let addr = listener.local_addr().expect("addr");

    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));
    // Per-egress-IP human-volume shaping (M5): keep this egress IP's outbound
    // traffic within a human-plausible envelope (bounded distinct destinations,
    // concurrency, jitter, sticky sessions) so a clean IP is not burned by
    // bot-shaped fan-out. Over-envelope traffic is paced gracefully, never blocked.
    let shaper = Arc::new(Mutex::new(VolumeShaper::new(
        ShapingConfig::default(),
        addr.port() as u64,
    )));
    serve_observed_shaped(listener, guard, upstream, None, Some(shaper));

    // Mint a few single-use credentials to paste into example requests.
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    let header = client
        .presentation_header(&mut rng)
        .expect("mint presentation");

    let route = if tor {
        "via Tor (SOCKS5 127.0.0.1:9050)"
    } else {
        "direct"
    };
    println!("\nTessera proxy live on http://{addr}  ·  admits on a credential, never your IP  ·  {route}");
    println!("It tunnels TLS end-to-end (CONNECT), so it never sees your plaintext.");
    println!(
        "Egress is human-volume shaped (M5): bot-shaped fan-out is paced, never the IP burned.\n"
    );
    println!(
        "Send any HTTPS request through it (single-use credential — the rate limit; restart for more). Example:\n"
    );
    println!("  curl -sS -x http://{addr} \\");
    println!("    --proxy-header 'Tessera-Presentation: {header}' \\");
    println!("    https://api.anthropic.com/v1/messages \\");
    println!("    -H \"x-api-key: $ANTHROPIC_API_KEY\" -H 'anthropic-version: 2023-06-01' \\");
    println!("    -H 'content-type: application/json' \\");
    println!(
        "    -d '{{\"model\":\"claude-opus-4-8\",\"max_tokens\":64,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}'\n"
    );
    println!("A request with no/invalid credential gets 407 Proxy Authentication Required. Ctrl-C to stop.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
