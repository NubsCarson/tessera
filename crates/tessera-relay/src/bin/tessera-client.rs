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
//!   `TESSERA_DIRECTORY_FILE` signed directory file; if set, derives issuer/relay/exit/pin
//!   `TESSERA_DIRECTORY_SIGNERS` comma-separated SEC1 directory signer pk hex pins
//!   `TESSERA_DIRECTORY_MIN_SIGNATURES` signature threshold (default `1`)
//!   `TESSERA_DIRECTORY_STATE_FILE` optional sequence/hash/key-epoch state path
//!   `TESSERA_DIRECTORY_MIN_KEY_EPOCH` optional minimum selected entry key epoch
//!   `TESSERA_EXIT_ID`       optional directory entry id to select
//!   `TESSERA_BUYER_KEY`     hex (32 bytes) secp256k1 secret → PAID mode (else PoW)
//!   `TESSERA_ISSUER_PK`     hex pin: the issuer pk (or its fingerprint prefix, ≥ 8
//!                           bytes / 16 hex chars) the issuance must match
//!                           (recommended; else trust-on-first-use). Required in
//!                           paid mode unless a signed directory supplies it.
//!
//! Run with `--check` for a fast preflight: it validates all config, resolves the
//! issuer/relay/exit peers, and binds the local proxy listener (then drops it),
//! prints `tessera-client: config OK` and a one-line summary, and exits — it does
//! **not** obtain a credential, contact the issuer, or start serving. Use it for
//! healthchecks / CI.
//!
//! Then: `curl -x http://127.0.0.1:8120 https://example.com`

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use tessera_client::{
    obtain_credential, obtain_credential_paid, parse_signer_pins_csv, DirectorySelectionPolicy,
    DirectoryState, SignedExitDirectory,
};
use tessera_relay::{
    serve_client_proxy_route, split_onion_host_port, ClientRoute, CredentialSource,
};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

/// Default local Tor SOCKS5 endpoint for the onion lane (`TESSERA_TOR_SOCKS`).
const DEFAULT_TOR_SOCKS: &str = "127.0.0.1:9050";

/// How long the onion preflight waits for the Tor SOCKS port before deciding Tor
/// is down. Tor-native: a Tor-down onion request then **fails loud** unless the
/// operator opts into clearnet via `TESSERA_ALLOW_CLEARNET_FALLBACK`.
const ONION_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(3);

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

/// Resolve a `HOST:PORT` value to a concrete `SocketAddr`, dying with a clear
/// config error if it is malformed or does not resolve.
fn resolve_value(label: &str, spec: &str) -> SocketAddr {
    let mut addrs = match spec.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(e) => die(&format!(
            "config error: {label}={spec} is not a valid HOST:PORT ({e})"
        )),
    };
    match addrs.next() {
        Some(addr) => addr,
        None => die(&format!(
            "config error: {label}={spec} did not resolve to any address"
        )),
    }
}

/// Decide how the client reaches the exit.
///
/// If an exit onion is configured (a directory's SIGNED `.onion`, or the manual
/// `TESSERA_EXIT_ONION`), the single-hop onion lane through the local Tor SOCKS
/// proxy (`TESSERA_TOR_SOCKS`, default `127.0.0.1:9050`) is THE path — the egress
/// *is* a Tor onion service. If that SOCKS port is unreachable, the request
/// **fails loud** (the operator must opt IN to dropping to clearnet via
/// `TESSERA_ALLOW_CLEARNET_FALLBACK`) rather than silently downgrading the
/// anonymity it asked for. With no onion configured, use the clearnet relay loop.
fn resolve_client_route(
    directory_onion: Option<String>,
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
) -> ClientRoute {
    // Onion source: a directory's SIGNED onion endpoint (v2) takes precedence;
    // otherwise the unsigned `TESSERA_EXIT_ONION` env (manual mode). The two are
    // mutually exclusive at config time, so only one is ever present.
    let exit_onion = match directory_onion {
        Some(o) => o,
        None => match std::env::var("TESSERA_EXIT_ONION") {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            Ok(_) => die("config error: TESSERA_EXIT_ONION is set but empty (unset it for the relay loop, or give an ONION:PORT)"),
            Err(_) => {
                return ClientRoute::Relay {
                    relay_addr,
                    exit_addr,
                }
            }
        },
    };
    // Validate ONION:PORT up front (fail-fast) with the EXACT rules the dial path
    // applies, by reusing the relay's onion-authority parser. (A signed directory
    // onion is validated here too — defense in depth.)
    if let Err(e) = split_onion_host_port(&exit_onion) {
        die(&format!(
            "config error: exit onion {exit_onion:?} must be ONION:PORT (e.g. abc…xyz.onion:443): {e}"
        ));
    }
    let socks_addr = std::env::var("TESSERA_TOR_SOCKS")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TOR_SOCKS.to_string());
    let socks_resolved = resolve_value("TESSERA_TOR_SOCKS", &socks_addr);

    // Preflight (the side-effect): is the Tor SOCKS port up? Refused/timeout => down.
    let reachable = match TcpStream::connect_timeout(&socks_resolved, ONION_PREFLIGHT_TIMEOUT) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("warning: the Tor SOCKS proxy {socks_addr} is unreachable ({e}).");
            false
        }
    };
    // Tor-native: a Tor-down onion request FAILS unless the operator explicitly
    // opts into the clearnet relay loop. The onion egress is the point.
    let allow_clearnet_fallback = std::env::var("TESSERA_ALLOW_CLEARNET_FALLBACK")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    match choose_route(
        Some(exit_onion),
        socks_addr,
        reachable,
        allow_clearnet_fallback,
        relay_addr,
        exit_addr,
    ) {
        Ok(route) => route,
        Err(msg) => die(&format!("config error: {msg}")),
    }
}

/// The pure routing decision (no env, no network). **Tor-native:** when an exit
/// onion is configured, the single-hop onion lane is THE path — the egress *is* a
/// Tor onion service. If Tor is unreachable, the lane FAILS (the operator must opt
/// IN to dropping to clearnet via `TESSERA_ALLOW_CLEARNET_FALLBACK`) rather than
/// silently downgrading the anonymity the operator asked for. With no onion
/// configured, the legacy clearnet relay loop is used. Split out from
/// [`resolve_client_route`]'s probe so the four-way contract is testable.
fn choose_route(
    exit_onion: Option<String>,
    socks_addr: String,
    socks_reachable: bool,
    allow_clearnet_fallback: bool,
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
) -> Result<ClientRoute, String> {
    match exit_onion {
        // Onion configured + Tor up: the onion lane (the intended Tor-native path).
        Some(exit_onion) if socks_reachable => Ok(ClientRoute::Onion {
            socks_addr,
            exit_onion,
        }),
        // Onion configured, Tor down, but the operator explicitly allows clearnet.
        Some(_) if allow_clearnet_fallback => Ok(ClientRoute::Relay {
            relay_addr,
            exit_addr,
        }),
        // Onion configured, Tor down, no opt-out: fail loud — never silently drop
        // to clearnet on a route chosen for anonymity.
        Some(_) => Err(format!(
            "onion lane requested but the Tor SOCKS proxy {socks_addr} is unreachable; \
             Tor is required for the onion egress. Start Tor, or set \
             TESSERA_ALLOW_CLEARNET_FALLBACK=1 to drop to the clearnet relay loop."
        )),
        // No onion configured: the legacy clearnet relay loop.
        None => Ok(ClientRoute::Relay {
            relay_addr,
            exit_addr,
        }),
    }
}

/// Resolve a `HOST:PORT` env var (or its default) to a concrete `SocketAddr`.
fn resolve(var: &str, default: &str) -> SocketAddr {
    let spec = std::env::var(var).unwrap_or_else(|_| default.into());
    resolve_value(var, &spec)
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
    directory: Option<DirectorySelection>,
}

struct DirectorySelection {
    path: PathBuf,
    entry_id: String,
    sequence: u64,
    min_signatures: usize,
    key_epoch: u64,
    available_sessions: u64,
    max_sessions: u64,
    state_path: Option<PathBuf>,
    /// The selected entry's **signed** `.onion:port` (directory v2), if it
    /// advertises one. Tor-native: the client routes over this verified onion
    /// rather than an unsigned env string.
    onion_addr: Option<String>,
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
    let directory_path = directory_file_env();

    let (issuer, relay_addr, exit_addr, pin, directory) = match directory_path {
        Some((var, path)) => load_directory_route(var, path),
        None => {
            reject_stray_directory_env();
            load_manual_route()
        }
    };

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
        die("config error: paid mode (TESSERA_BUYER_KEY) requires TESSERA_ISSUER_PK or a signed directory entry with issuer_pk");
    }

    Config {
        issuer,
        relay_addr,
        exit_addr,
        listen,
        pin,
        buyer_secret,
        directory,
    }
}

fn load_manual_route() -> (
    String,
    SocketAddr,
    SocketAddr,
    Option<Vec<u8>>,
    Option<DirectorySelection>,
) {
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

    (issuer, relay_addr, exit_addr, pin, None)
}

fn directory_file_env() -> Option<(&'static str, String)> {
    let current = std::env::var("TESSERA_DIRECTORY_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let legacy = std::env::var("TESSERA_EXIT_DIRECTORY")
        .ok()
        .filter(|s| !s.trim().is_empty());

    match (current, legacy) {
        (Some(path), None) => Some(("TESSERA_DIRECTORY_FILE", path)),
        (None, Some(path)) => Some(("TESSERA_EXIT_DIRECTORY", path)),
        (Some(_), Some(_)) => die(
            "config error: set only one of TESSERA_DIRECTORY_FILE or legacy TESSERA_EXIT_DIRECTORY",
        ),
        (None, None) => None,
    }
}

fn reject_stray_directory_env() {
    for var in [
        "TESSERA_DIRECTORY_SIGNERS",
        "TESSERA_DIRECTORY_MIN_SIGNATURES",
        "TESSERA_DIRECTORY_MIN_KEY_EPOCH",
        "TESSERA_DIRECTORY_STATE_FILE",
        "TESSERA_DIRECTORY_SIGNER_PK",
        "TESSERA_EXIT_ID",
    ] {
        if std::env::var(var).is_ok() {
            die(&format!(
                "config error: {var} requires TESSERA_DIRECTORY_FILE"
            ));
        }
    }
}

fn load_directory_signers(path_var: &str) -> Vec<Vec<u8>> {
    if std::env::var("TESSERA_DIRECTORY_SIGNER_PK").is_ok() {
        die(
            "config error: TESSERA_DIRECTORY_SIGNER_PK is obsolete; use comma-separated TESSERA_DIRECTORY_SIGNERS",
        );
    }
    let raw = std::env::var("TESSERA_DIRECTORY_SIGNERS").unwrap_or_else(|_| {
        die(&format!(
            "config error: TESSERA_DIRECTORY_SIGNERS is required with {path_var}"
        ))
    });
    if raw.trim().is_empty() {
        die("config error: TESSERA_DIRECTORY_SIGNERS cannot be empty");
    }
    parse_signer_pins_csv(&raw).unwrap_or_else(|e| {
        die(&format!(
            "config error: invalid TESSERA_DIRECTORY_SIGNERS: {e}"
        ))
    })
}

fn load_directory_threshold() -> usize {
    match std::env::var("TESSERA_DIRECTORY_MIN_SIGNATURES") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                die("config error: TESSERA_DIRECTORY_MIN_SIGNATURES cannot be empty");
            }
            let threshold = trimmed.parse::<usize>().unwrap_or_else(|e| {
                die(&format!(
                    "config error: TESSERA_DIRECTORY_MIN_SIGNATURES is not a positive integer ({e})"
                ))
            });
            if threshold == 0 {
                die("config error: TESSERA_DIRECTORY_MIN_SIGNATURES must be non-zero");
            }
            threshold
        }
        Err(_) => 1,
    }
}

fn load_directory_min_key_epoch() -> Option<u64> {
    match std::env::var("TESSERA_DIRECTORY_MIN_KEY_EPOCH") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                die("config error: TESSERA_DIRECTORY_MIN_KEY_EPOCH cannot be empty");
            }
            let epoch = trimmed.parse::<u64>().unwrap_or_else(|e| {
                die(&format!(
                    "config error: TESSERA_DIRECTORY_MIN_KEY_EPOCH is not a positive integer ({e})"
                ))
            });
            if epoch == 0 {
                die("config error: TESSERA_DIRECTORY_MIN_KEY_EPOCH must be non-zero");
            }
            Some(epoch)
        }
        Err(_) => None,
    }
}

/// Tor-native opt-in: `TESSERA_DIRECTORY_REQUIRE_ONION=1` (or `true`) makes onion
/// advertisement a hard selection filter, so a clearnet-only (or a higher-weight
/// clearnet) directory entry is rejected at select time rather than silently
/// routing over the clearnet relay loop. Default false: operators may run a
/// clearnet-only directory on purpose, so we warn (below) rather than force.
fn load_directory_require_onion() -> bool {
    std::env::var("TESSERA_DIRECTORY_REQUIRE_ONION")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn load_directory_route(
    path_var: &'static str,
    path: String,
) -> (
    String,
    SocketAddr,
    SocketAddr,
    Option<Vec<u8>>,
    Option<DirectorySelection>,
) {
    for var in [
        "TESSERA_ISSUER",
        "TESSERA_RELAY",
        "TESSERA_EXIT",
        "TESSERA_ISSUER_PK",
        // The directory now supplies the onion endpoint from its SIGNED v2
        // advertisement, so the unsigned `TESSERA_EXIT_ONION` env must not be set
        // alongside it — that would let an unsigned `.onion` override the signed
        // exit. Fail fast, consistent with the peers above.
        "TESSERA_EXIT_ONION",
    ] {
        if std::env::var(var).is_ok() {
            die(&format!(
                "config error: {var} cannot be set with {path_var}; the signed directory supplies issuer/relay/exit/pin/onion"
            ));
        }
    }

    let signers = load_directory_signers(path_var);
    let min_signatures = load_directory_threshold();
    let selection_policy = DirectorySelectionPolicy {
        min_key_epoch: load_directory_min_key_epoch(),
        // Tor-native: the client routes over the selected entry's SIGNED onion
        // endpoint. TESSERA_DIRECTORY_REQUIRE_ONION=1 makes that a hard filter so a
        // clearnet-only entry is rejected at select time; default off, with a loud
        // warning below if selection lands on a no-onion entry anyway.
        require_onion: load_directory_require_onion(),
        ..Default::default()
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        die(&format!(
            "config error: could not read {path_var}={path}: {e}"
        ))
    });
    let directory = SignedExitDirectory::parse(&text)
        .unwrap_or_else(|e| die(&format!("config error: invalid exit directory: {e}")));
    directory
        .verify_now(&signers, min_signatures)
        .unwrap_or_else(|e| die(&format!("config error: exit directory rejected: {e}")));

    let state_path = std::env::var("TESSERA_DIRECTORY_STATE_FILE")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    if let Some(state_path) = &state_path {
        let mut state = DirectoryState::open(state_path).unwrap_or_else(|e| {
            die(&format!(
                "config error: could not open directory state {}: {e}",
                state_path.display()
            ))
        });
        state
            .check_snapshot_and_record(&directory.snapshot)
            .unwrap_or_else(|e| die(&format!("config error: exit directory rejected: {e}")));
    }

    let selected_id = std::env::var("TESSERA_EXIT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let entry = directory
        .snapshot
        .select_with_policy(selected_id.as_deref(), &selection_policy)
        .unwrap_or_else(|e| {
            die(&format!(
                "config error: exit directory selection failed: {e}"
            ))
        });

    // Tor-native downgrade guard: if the selected entry advertises no onion but the
    // directory DOES advertise an onion exit, the client will route over the
    // CLEARNET relay loop. Surface that loudly — a silent drop to clearnet on a
    // directory that offers the onion lane is exactly the anonymity regression the
    // fail-loud env path guards against. (Set TESSERA_DIRECTORY_REQUIRE_ONION=1 to
    // make it a hard error, or TESSERA_EXIT_ID to pin a specific onion exit.)
    if entry.onion_addr.is_none()
        && directory
            .snapshot
            .entries
            .iter()
            .any(|e| e.onion_addr.is_some())
    {
        eprintln!(
            "warning: selected directory entry {} has no onion endpoint, so this client will route \
             over the CLEARNET relay loop even though the directory advertises an onion exit. Set \
             TESSERA_DIRECTORY_REQUIRE_ONION=1 to require the onion lane, or TESSERA_EXIT_ID to \
             select an onion exit.",
            entry.id
        );
    }

    let issuer = entry.issuer_addr.clone();
    match issuer.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                die(&format!(
                    "config error: directory issuer {} did not resolve to any address",
                    entry.issuer_addr
                ));
            }
        }
        Err(e) => die(&format!(
            "config error: directory issuer {} is not a valid HOST:PORT ({e})",
            entry.issuer_addr
        )),
    }
    let relay_addr = resolve_value("directory relay", &entry.relay_addr);
    let exit_addr = resolve_value("directory exit", &entry.exit_addr);
    let selection = DirectorySelection {
        path: PathBuf::from(path),
        entry_id: entry.id.clone(),
        sequence: directory.snapshot.sequence,
        min_signatures,
        key_epoch: entry.capacity.key_epoch,
        available_sessions: entry.capacity.available_sessions,
        max_sessions: entry.capacity.max_sessions,
        state_path,
        // Tor-native: carry the selected entry's SIGNED onion endpoint so the
        // client routes over the verified `.onion` (directory v2), not an
        // unsigned env string.
        onion_addr: entry.onion_addr.clone(),
    };
    (
        issuer,
        relay_addr,
        exit_addr,
        Some(entry.issuer_pk.clone()),
        Some(selection),
    )
}

fn directory_summary(directory: &DirectorySelection) -> String {
    format!(
        " directory={} entry={} seq={} threshold={} key_epoch={} capacity={}/{}{}",
        directory.path.display(),
        directory.entry_id,
        directory.sequence,
        directory.min_signatures,
        directory.key_epoch,
        directory.available_sessions,
        directory.max_sessions,
        directory_state_summary(directory)
    )
}

fn directory_state_summary(directory: &DirectorySelection) -> String {
    directory
        .state_path
        .as_ref()
        .map(|path| format!(" state={}", path.display()))
        .unwrap_or_default()
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
            "  mode={} listen={bound} issuer={} relay={} exit={} pin={}{}",
            cfg.mode(),
            cfg.issuer,
            cfg.relay_addr,
            cfg.exit_addr,
            if cfg.pin.is_some() { "set" } else { "unset" },
            cfg.directory
                .as_ref()
                .map(directory_summary)
                .unwrap_or_default(),
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
        directory,
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

    // Choose the route to the exit: the single-hop onion lane if configured and
    // Tor is up, else the 2-hop clearnet relay loop (self-skip fallback).
    // Tor-native: a directory's SIGNED onion endpoint (v2) drives the route when
    // present; otherwise the env (manual mode).
    let directory_onion = directory.as_ref().and_then(|d| d.onion_addr.clone());
    let route = resolve_client_route(directory_onion, relay_addr, exit_addr);

    println!("\nTessera client proxy live on http://{addr}");
    match &route {
        ClientRoute::Relay {
            relay_addr,
            exit_addr,
        } => {
            println!(
                "  route: you → (this proxy) → RELAY {relay_addr} → EXIT {exit_addr} → destination"
            );
        }
        ClientRoute::Onion {
            socks_addr,
            exit_onion,
        } => {
            println!(
                "  route: you → (this proxy) → Tor SOCKS {socks_addr} → EXIT {exit_onion} (.onion, single hop) → destination"
            );
            println!(
                "         the exit's peer is the Tor circuit, never your IP; no separate relay needed."
            );
        }
    }
    if let Some(directory) = &directory {
        println!(
            "  directory: {} entry={} seq={} threshold={} key_epoch={} capacity={}/{}{} (issuer key pinned from signed snapshot)",
            directory.path.display(),
            directory.entry_id,
            directory.sequence,
            directory.min_signatures,
            directory.key_epoch,
            directory.available_sessions,
            directory.max_sessions,
            directory_state_summary(directory)
        );
    }
    println!(
        "  the EXIT admits each request on a fresh unlinkable token, never your IP; re-issues when spent."
    );
    println!(
        "  note: issuance connected you to the issuer {issuer}, which saw your IP (ARC still can't link"
    );
    println!("        it to your browsing). Run this client over Tor to hide issuance too.");
    println!("\n  curl -x http://{addr} https://example.com\n");

    serve_client_proxy_route(listener, route, source)
        .join()
        .expect("client proxy thread");
}

#[cfg(test)]
mod tests {
    use super::{choose_route, ClientRoute};
    use std::net::SocketAddr;

    fn addr(p: u16) -> SocketAddr {
        ([127, 0, 0, 1], p).into()
    }

    #[test]
    fn choose_route_is_tor_native_four_way_contract() {
        let (relay, exit) = (addr(1), addr(2));
        let socks = "127.0.0.1:9050".to_string();
        let onion = || Some("abc.onion:443".to_string());

        // (1) No onion configured -> the legacy clearnet relay loop.
        assert!(matches!(
            choose_route(None, socks.clone(), true, false, relay, exit),
            Ok(ClientRoute::Relay { .. })
        ));
        // (2) Onion configured + Tor up -> the onion lane (the Tor-native path).
        match choose_route(onion(), socks.clone(), true, false, relay, exit) {
            Ok(ClientRoute::Onion { exit_onion, .. }) => assert_eq!(exit_onion, "abc.onion:443"),
            other => panic!("expected the onion lane, got {other:?}"),
        }
        // (3) Onion configured + Tor DOWN + no opt-out -> FAIL LOUD (no silent
        //     downgrade to clearnet on a route chosen for anonymity).
        let err = choose_route(onion(), socks.clone(), false, false, relay, exit).unwrap_err();
        assert!(err.contains("Tor is required"), "got: {err}");
        // (4) Onion configured + Tor DOWN + explicit opt-out -> clearnet relay.
        assert!(matches!(
            choose_route(onion(), socks.clone(), false, true, relay, exit),
            Ok(ClientRoute::Relay { .. })
        ));
        // (5) Onion configured + Tor UP + opt-out also allowed -> STILL the onion
        //     lane. The opt-out only matters when Tor is DOWN; onion must win
        //     whenever Tor is up. Guards against a match-arm reorder silently
        //     preferring clearnet while the other arms stay green.
        match choose_route(onion(), socks, true, true, relay, exit) {
            Ok(ClientRoute::Onion { exit_onion, .. }) => assert_eq!(exit_onion, "abc.onion:443"),
            other => panic!("expected the onion lane even with clearnet opt-out, got {other:?}"),
        }
    }
}
