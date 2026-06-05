//! `tessera-client` binary: the **local client proxy** a person runs. It obtains
//! a credential from a `tessera-issuer` node over the wire (paying the PoW), then
//! exposes a local HTTP `CONNECT` proxy. Point your browser/curl at it and every
//! request is admitted at the **exit** on a fresh, unlinkable token — the exit
//! never sees your IP — routed through the 2-hop loop (relay → exit). When the
//! credential's budget is spent it transparently re-issues.
//!
//! Honest caveat: obtaining the credential connects you **directly to the
//! issuer**, which therefore sees your IP at issuance time. ARC unlinkability
//! still prevents the issuer from tying that to your later browsing, but the act
//! of issuance is not hidden — run this client over Tor if you need to hide it.
//!
//! Config (env):
//!   `TESSERA_ISSUER`        issuer node `HOST:PORT` (default `127.0.0.1:8121`)
//!   `TESSERA_RELAY`         relay node  `HOST:PORT` (default `127.0.0.1:8119`)
//!   `TESSERA_EXIT`          exit node   `HOST:PORT` (default `127.0.0.1:8118`)
//!   `TESSERA_CLIENT_LISTEN` local proxy bind        (default `127.0.0.1:8120`)
//!   `TESSERA_BUYER_KEY`     hex (32 bytes) secp256k1 secret → PAID mode (else PoW)
//!   `TESSERA_ISSUER_PK`     hex pin: the issuer pk (or its fingerprint prefix, ≥ 8
//!                           bytes / 16 hex chars) the issuance must match
//!                           (recommended; else trust-on-first-use). Required in
//!                           paid mode.
//!
//! Run with `--check` for a fast preflight: it validates all config, resolves the
//! issuer/relay/exit peers, and binds the local proxy listener (then drops it),
//! prints `tessera-client: config OK` and a one-line summary, and exits — it does
//! **not** obtain a credential, contact the issuer, or start serving. Use it for
//! healthchecks / CI.
//!
//! Then: `curl -x http://127.0.0.1:8120 https://example.com`

use std::net::{SocketAddr, TcpListener, ToSocketAddrs};

use tessera_client::{obtain_credential, obtain_credential_paid};
use tessera_relay::{serve_client_proxy, CredentialSource};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

/// The issuer-pk pin must be at least this many bytes (16 hex chars) to be a
/// meaningful fingerprint; the client library rejects anything shorter, so we
/// reject it up front rather than fail later at issuance time.
const MIN_PIN_LEN: usize = 8;

/// Print a config/runtime error to stderr in the canonical
/// `tessera-client: <msg>` form and terminate. Used for every fail-fast path so
/// the binary never panics on bad config and never silently proceeds.
fn die(msg: &str) -> ! {
    eprintln!("tessera-client: {msg}");
    std::process::exit(2)
}

/// Resolve a `HOST:PORT` env var (or its default) to a concrete `SocketAddr`,
/// dying with a clear config error if it is malformed or does not resolve.
fn resolve(var: &str, default: &str) -> SocketAddr {
    let spec = std::env::var(var).unwrap_or_else(|_| default.into());
    let mut addrs = match spec.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(e) => die(&format!(
            "config error: {var}={spec} is not a valid HOST:PORT ({e})"
        )),
    };
    match addrs.next() {
        Some(addr) => addr,
        None => die(&format!(
            "config error: {var}={spec} did not resolve to any address"
        )),
    }
}

/// The fully-validated configuration the binary will run with. Building this
/// performs every fail-fast check, so by the time we hold one all env input is
/// known-good.
struct Config {
    /// Issuer is kept in its `HOST:PORT` string form because the client library
    /// connects to it by name (after we've validated it resolves).
    issuer: String,
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    listen: String,
    pin: Option<Vec<u8>>,
    buyer_secret: Option<[u8; 32]>,
}

impl Config {
    /// `paid` (TESSERA_BUYER_KEY set) or `pow` (proof-of-work) — for the
    /// `--check` summary line.
    fn mode(&self) -> &'static str {
        if self.buyer_secret.is_some() {
            "paid"
        } else {
            "pow"
        }
    }
}

/// Validate every env var the binary reads and resolve all peer addresses,
/// dying with a specific `tessera-client: config error: …` on the first problem.
fn load_config() -> Config {
    let issuer = std::env::var("TESSERA_ISSUER").unwrap_or_else(|_| "127.0.0.1:8121".into());
    // The issuer is used as a connect-by-name target, but we still validate that
    // it parses/resolves up front so a typo fails fast rather than at issuance.
    match issuer.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                die(&format!(
                    "config error: TESSERA_ISSUER={issuer} did not resolve to any address"
                ));
            }
        }
        Err(e) => die(&format!(
            "config error: TESSERA_ISSUER={issuer} is not a valid HOST:PORT ({e})"
        )),
    }

    let relay_addr = resolve("TESSERA_RELAY", "127.0.0.1:8119");
    let exit_addr = resolve("TESSERA_EXIT", "127.0.0.1:8118");

    let listen = std::env::var("TESSERA_CLIENT_LISTEN").unwrap_or_else(|_| "127.0.0.1:8120".into());
    // Validate that the listen address parses; we still keep the string form so
    // `TcpListener::bind` resolves it identically to the original behavior.
    match listen.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                die(&format!(
                    "config error: TESSERA_CLIENT_LISTEN={listen} did not resolve to any address"
                ));
            }
        }
        Err(e) => die(&format!(
            "config error: TESSERA_CLIENT_LISTEN={listen} is not a valid HOST:PORT ({e})"
        )),
    }

    // TESSERA_ISSUER_PK: optional hex pin. If present it must be valid hex and a
    // meaningful fingerprint length (>= 8 bytes); empty is treated as unset.
    let pin = match std::env::var("TESSERA_ISSUER_PK") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                let bytes = hex::decode(trimmed).unwrap_or_else(|e| {
                    die(&format!(
                        "config error: TESSERA_ISSUER_PK is not valid hex ({e})"
                    ))
                });
                if bytes.len() < MIN_PIN_LEN {
                    die(&format!(
                        "config error: TESSERA_ISSUER_PK pin too short ({} bytes); need >= {MIN_PIN_LEN} bytes / {} hex chars",
                        bytes.len(),
                        MIN_PIN_LEN * 2
                    ));
                }
                Some(bytes)
            }
        }
        Err(_) => None,
    };

    // PAID mode iff TESSERA_BUYER_KEY (a 32-byte hex secp256k1 secret) is set: the
    // client proves control of that Ethereum address, which must hold a TokenMint
    // entitlement. Otherwise the client pays the issuer's proof of work. If the
    // var is set but malformed we MUST fail loudly — silently falling back to PoW
    // would be a footgun (the user thinks they're paying but isn't).
    let buyer_secret: Option<[u8; 32]> = match std::env::var("TESSERA_BUYER_KEY") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
                let bytes = hex::decode(hex_str).unwrap_or_else(|e| {
                    die(&format!(
                        "config error: TESSERA_BUYER_KEY is not valid hex ({e})"
                    ))
                });
                let arr = <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
                    die(&format!(
                        "config error: TESSERA_BUYER_KEY must be 32 bytes (64 hex chars), got {} bytes",
                        bytes.len()
                    ))
                });
                Some(arr)
            }
        }
        Err(_) => None,
    };

    if buyer_secret.is_some() && pin.is_none() {
        // Paid mode binds the control signature to the issuer pk; without a pin a
        // relay could lure you into signing for a different issuer (wormhole).
        die("config error: paid mode (TESSERA_BUYER_KEY) requires TESSERA_ISSUER_PK (the issuer's pk fingerprint)");
    }

    Config {
        issuer,
        relay_addr,
        exit_addr,
        listen,
        pin,
        buyer_secret,
    }
}

/// Bind the local proxy listener at the configured address. Unlike the old
/// silent `.or_else(|_| bind("127.0.0.1:0"))` fallback, a bind failure is fatal:
/// quietly grabbing a random ephemeral port would break the multi-node topology.
fn bind_listener(cfg: &Config) -> TcpListener {
    TcpListener::bind(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("tessera-client: could not bind {}: {e}", cfg.listen);
        std::process::exit(1)
    })
}

fn main() {
    let check_mode = std::env::args().skip(1).any(|a| a == "--check");

    let cfg = load_config();

    if check_mode {
        // Preflight: validate config (already done) + prove we can bind the local
        // listener, then drop it. Do NOT obtain a credential or contact the issuer.
        let listener = bind_listener(&cfg);
        let bound = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| cfg.listen.clone());
        drop(listener);

        println!("tessera-client: config OK");
        println!(
            "  mode={} listen={bound} issuer={} relay={} exit={} pin={}",
            cfg.mode(),
            cfg.issuer,
            cfg.relay_addr,
            cfg.exit_addr,
            if cfg.pin.is_some() { "set" } else { "unset" },
        );
        std::process::exit(0);
    }

    if cfg.pin.is_none() {
        eprintln!(
            "warning: no TESSERA_ISSUER_PK pin set — trusting the issuer's key on first use. \
             Set it to the issuer's printed fingerprint to prevent a substituted issuer."
        );
    }

    // Bind the local listener BEFORE the (slow, networked) issuance so a bind
    // failure surfaces immediately rather than after paying the PoW.
    let listener = bind_listener(&cfg);

    let Config {
        issuer,
        relay_addr,
        exit_addr,
        listen: _,
        pin,
        buyer_secret,
    } = cfg;

    let credential = match &buyer_secret {
        Some(secret) => {
            eprintln!("Tessera CLIENT: obtaining a PAID credential from issuer {issuer}…");
            obtain_credential_paid(&issuer, REQUEST_CTX, secret, pin.as_deref()).unwrap_or_else(
                |e| {
                    die(&format!(
                        "could not obtain a paid credential from {issuer}: {e}"
                    ))
                },
            )
        }
        None => {
            eprintln!(
                "Tessera CLIENT: obtaining a credential from issuer {issuer} (paying proof-of-work)…"
            );
            obtain_credential(&issuer, REQUEST_CTX, pin.as_deref()).unwrap_or_else(|e| {
                die(&format!("could not obtain a credential from {issuer}: {e}"))
            })
        }
    };
    eprintln!("Tessera CLIENT: credential obtained.");

    let source = CredentialSource::new(
        credential,
        issuer.clone(),
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
        pin,
        buyer_secret,
    );

    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| die(&format!("could not read client proxy addr: {e}")));

    println!("\nTessera client proxy live on http://{addr}");
    println!("  route: you → (this proxy) → RELAY {relay_addr} → EXIT {exit_addr} → destination");
    println!(
        "  the EXIT admits each request on a fresh unlinkable token, never your IP; re-issues when spent."
    );
    println!(
        "  note: issuance connected you to the issuer {issuer}, which saw your IP (ARC still can't link"
    );
    println!("        it to your browsing). Run this client over Tor to hide issuance too.");
    println!("\n  curl -x http://{addr} https://example.com\n");

    serve_client_proxy(listener, relay_addr, exit_addr, source)
        .join()
        .expect("client proxy thread");
}
