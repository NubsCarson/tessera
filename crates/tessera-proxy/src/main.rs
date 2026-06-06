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

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_issuer::{check_path_usable, KeyProviderConfig};
use tessera_origin::{FileTagStore, OriginGuard};
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

/// Held by a live exit process to prove it is the only local exit serving this
/// ARC key domain. On Unix this is an advisory `flock`: the serving path locks
/// the established key file's inode, so symlinks/hardlinks/path aliases to the
/// same local key do not bypass the guard. It is not a distributed lease and it
/// cannot detect someone copying the same key bytes to another host/path. That
/// is intentional: the current proxy uses a process-local spent-tag store unless
/// configured otherwise, so accidentally running two exits against one local key
/// domain would let the same presentation be admitted twice.
struct KeyDomainLease {
    _file: File,
}

impl KeyDomainLease {
    /// Acquire the local single-exit lease for a serving exit. The key must
    /// already exist; this locks the actual key file inode.
    fn acquire_existing_key(key_file: &str) -> Result<Self, String> {
        let path = Path::new(key_file).canonicalize().map_err(|e| {
            format!("TESSERA_KEY_FILE {key_file}: could not canonicalize established key: {e}")
        })?;
        let file = OpenOptions::new().read(true).open(&path).map_err(|e| {
            format!(
                "TESSERA_KEY_FILE {key_file}: could not open key-domain lease target {}: {e}",
                path.display()
            )
        })?;
        Self::lock(file, key_file, &format!("key file {}", path.display()))
    }

    /// Acquire the local single-exit lease for `--check` without creating the key.
    /// If the key exists, lock the real key inode; otherwise lock a sidecar under
    /// the canonical parent as a bind/preflight guard.
    fn acquire_preflight(key_file: &str) -> Result<Self, String> {
        match Path::new(key_file).canonicalize() {
            Ok(path) => {
                let file = OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .map_err(|e| {
                        format!(
                            "TESSERA_KEY_FILE {key_file}: could not open key-domain lease target {}: {e}",
                            path.display()
                        )
                    })?;
                Self::lock(file, key_file, &format!("key file {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let lock_path = preflight_lock_path(key_file)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&lock_path)
                    .map_err(|e| {
                        format!(
                            "TESSERA_KEY_FILE {key_file}: could not open key-domain lease {}: {e}",
                            lock_path.display()
                        )
                    })?;
                Self::lock_sidecar(&mut file, key_file, &lock_path)?;
                Ok(Self { _file: file })
            }
            Err(e) => Err(format!(
                "TESSERA_KEY_FILE {key_file}: could not canonicalize key path for key-domain lease: {e}"
            )),
        }
    }

    fn lock(file: File, key_file: &str, target: &str) -> Result<Self, String> {
        lock_file(&file).map_err(|e| lease_error(key_file, target, e))?;
        Ok(Self { _file: file })
    }

    fn lock_sidecar(file: &mut File, key_file: &str, lock_path: &Path) -> Result<(), String> {
        let target = format!("sidecar {}", lock_path.display());
        lock_file(file).map_err(|e| lease_error(key_file, &target, e))?;
        file.set_len(0).map_err(|e| {
            format!(
                "TESSERA_KEY_FILE {key_file}: could not clear key-domain lease {}: {e}",
                lock_path.display()
            )
        })?;
        writeln!(
            file,
            "pid={} role=exit key_file={key_file}",
            std::process::id()
        )
        .and_then(|_| file.flush())
        .map_err(|e| {
            format!(
                "TESSERA_KEY_FILE {key_file}: could not write key-domain lease {}: {e}",
                lock_path.display()
            )
        })
    }
}

fn preflight_lock_path(key_file: &str) -> Result<PathBuf, String> {
    let p = Path::new(key_file);
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty());
    let parent = match parent {
        Some(dir) => dir.canonicalize().map_err(|e| {
            format!(
                "TESSERA_KEY_FILE {key_file}: could not canonicalize parent {}: {e}",
                dir.display()
            )
        })?,
        None => std::env::current_dir()
            .and_then(|d| d.canonicalize())
            .map_err(|e| {
                format!("TESSERA_KEY_FILE {key_file}: could not canonicalize current dir: {e}")
            })?,
    };
    let name = p
        .file_name()
        .ok_or_else(|| format!("TESSERA_KEY_FILE {key_file}: missing file name"))?
        .to_string_lossy();
    Ok(parent.join(format!("{name}.exit.lock")))
}

fn lease_error(key_file: &str, target: &str, e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        format!(
            "TESSERA_KEY_FILE {key_file}: key-domain lease {target} is already held; one ARC key domain supports one live exit in this build. Use a separate issuer/key file/key pin per independent exit."
        )
    } else {
        format!("TESSERA_KEY_FILE {key_file}: could not lock key-domain lease {target}: {e}")
    }
}

impl Drop for KeyDomainLease {
    fn drop(&mut self) {
        unlock_file(&self._file);
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: `file.as_raw_fd()` is a valid open file descriptor for the lifetime
    // of this call. `flock` does not take ownership of the descriptor.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::fd::AsRawFd;

    // SAFETY: `file.as_raw_fd()` is a valid open file descriptor for the lifetime
    // of this call. Unlocking is best-effort during drop.
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(not(unix))]
fn lock_file(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "key-domain lease requires Unix flock support",
    ))
}

#[cfg(not(unix))]
fn unlock_file(_file: &File) {}

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

/// Optional durable spent-tag file for a single exit. This survives restarts but
/// is still explicitly not a multi-process/distributed tag store.
fn validate_spent_tag_file() -> Option<String> {
    match std::env::var("TESSERA_SPENT_TAG_FILE") {
        Ok(path) if !path.is_empty() => {
            if let Err(msg) = check_path_usable(&path, "TESSERA_SPENT_TAG_FILE") {
                die(&format!("tessera-{ROLE}: config error: {msg}"));
            }
            Some(path)
        }
        Ok(_) => die(&format!(
            "tessera-{ROLE}: config error: TESSERA_SPENT_TAG_FILE is set but empty (unset it for in-memory tags, or give it a path)"
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
    //   TESSERA_KEY_PROVIDER "ephemeral" | "file" | "dstack-kms" (default inferred)
    //   TESSERA_KEY_FILE shared ARC server-key path — set it (same value as the
    //                    issuer's) so the exit verifies credentials minted by the
    //                    issuer; unset => ephemeral self-issuing exit (the demo).
    //   TESSERA_SPENT_TAG_FILE optional durable spent-tag path for a single exit;
    //                    unset => in-memory tags (lost on restart).
    let args: Vec<String> = std::env::args().collect();
    let tor_arg = args.iter().any(|a| a == "--tor");
    let check = args.iter().any(|a| a == "--check");

    // ---- FAIL-FAST config validation (runs for every mode, before any work) ----
    let listen = std::env::var("TESSERA_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.into());
    validate_addr("TESSERA_LISTEN", &listen);
    let UpstreamPlan { upstream, tor } = resolve_upstream(tor_arg);
    let key_provider = KeyProviderConfig::from_env().unwrap_or_else(|msg| {
        die(&format!("tessera-{ROLE}: config error: {msg}"));
    });
    key_provider.preflight().unwrap_or_else(|msg| {
        die(&format!("tessera-{ROLE}: config error: {msg}"));
    });
    let spent_tag_file = validate_spent_tag_file();

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
                // Prove the key domain is not already held by another local exit,
                // then return normally so the lease is dropped. This does not
                // establish a missing key file.
                let _key_domain_lease = key_provider
                    .key_file_path()
                    .map(KeyDomainLease::acquire_preflight)
                    .transpose()
                    .unwrap_or_else(|msg| die(&format!("tessera-{ROLE}: config error: {msg}")));
                let _tag_store_check = spent_tag_file
                    .as_deref()
                    .map(FileTagStore::open)
                    .transpose()
                    .unwrap_or_else(|e| {
                        die(&format!(
                            "tessera-{ROLE}: config error: TESSERA_SPENT_TAG_FILE: could not open tag store during --check: {e}"
                        ))
                    });
                let mode = if tor { "tor" } else { "direct" };
                let upstream_label = match &upstream {
                    Upstream::Direct => "direct".to_string(),
                    Upstream::Tor(p) => format!("tor via {p}"),
                };
                let key = key_provider.label();
                let tags = match &spent_tag_file {
                    Some(p) => format!("file:{p}"),
                    None => "memory".to_string(),
                };
                println!("tessera-{ROLE}: config OK");
                println!(
                    "tessera-{ROLE}: listen={addr} upstream={upstream_label} mode={mode} key={key} tag_store={tags} topology=single-exit-key-domain"
                );
                return;
            }
            Err(e) => die_code(&format!("tessera-{ROLE}: could not bind {listen}: {e}"), 1),
        }
    }

    // ---- normal serving path (config already validated above) ----

    let tag_store = spent_tag_file.as_ref().map(|path| {
        FileTagStore::open(path).unwrap_or_else(|e| {
            die(&format!(
                "tessera-{ROLE}: config error: TESSERA_SPENT_TAG_FILE {path}: could not open tag store: {e}"
            ))
        })
    });

    // Bind the (defaulted-or-explicit) listen address before taking the key-domain
    // lease, so a bind failure cannot leave a stale lease behind.
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => die_code(&format!("tessera-{ROLE}: could not bind {listen}: {e}"), 1),
    };
    let addr = listener.local_addr().expect("addr");

    // Convergent shared-key bootstrap: the exit loads the SAME ARC key as the
    // issuer for file-backed domains; unsupported providers fail closed.
    let (sk, pk) = key_provider.establish(&mut rng).unwrap_or_else(|msg| {
        die(&format!("tessera-{ROLE}: config error: {msg}"));
    });
    // One shared ARC key domain is one live exit in this build. Hold an advisory
    // lock on the established key file's inode for the process lifetime; this
    // closes local symlink/hardlink/path-alias bypasses.
    let _key_domain_lease = key_provider
        .key_file_path()
        .map(KeyDomainLease::acquire_existing_key)
        .transpose()
        .unwrap_or_else(|msg| die(&format!("tessera-{ROLE}: config error: {msg}")));
    let credential = issue(&sk, &pk, &mut rng);

    let guard = match tag_store {
        Some(store) => Arc::new(OriginGuard::with_store(
            sk,
            pk,
            REQUEST_CTX,
            PRESENT_CTX,
            LIMIT,
            Box::new(store),
        )),
        None => Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT)),
    };
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

#[cfg(test)]
mod tests {
    use super::KeyDomainLease;
    use std::io::Write;
    use tessera_issuer::check_path_usable;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tessera-proxy-keyfile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn key_file_validation_accepts_new_or_existing_regular_file() {
        let dir = temp_dir("ok");
        let path = dir.join("server.key");
        let path_str = path.to_string_lossy();

        check_path_usable(&path_str, "TESSERA_KEY_FILE")
            .expect("missing file under an existing parent is valid");

        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"placeholder").unwrap();
        drop(f);
        check_path_usable(&path_str, "TESSERA_KEY_FILE").expect("existing regular file is valid");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn key_file_validation_rejects_missing_parent() {
        let dir = std::env::temp_dir().join(format!(
            "tessera-proxy-keyfile-missing-{}",
            std::process::id()
        ));
        let path = dir.join("server.key");
        let err = check_path_usable(&path.to_string_lossy(), "TESSERA_KEY_FILE")
            .expect_err("missing parent must fail before the 60s key wait");
        assert!(err.contains("parent directory"), "{err}");
    }

    #[test]
    fn key_file_validation_rejects_directory_target() {
        let dir = temp_dir("dir-target");
        let err = check_path_usable(&dir.to_string_lossy(), "TESSERA_KEY_FILE")
            .expect_err("a directory cannot be used as the key file");
        assert!(err.contains("not a regular file"), "{err}");
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_domain_lease_allows_only_one_live_exit_per_key_file() {
        let dir = temp_dir("lease");
        let key = dir.join("server.key");
        std::fs::write(&key, b"placeholder").unwrap();
        let key_str = key.to_string_lossy();

        let lease =
            KeyDomainLease::acquire_existing_key(&key_str).expect("first exit owns the key domain");
        let err = match KeyDomainLease::acquire_existing_key(&key_str) {
            Ok(_) => panic!("second exit for the same key domain must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.contains("one ARC key domain supports one live exit"),
            "{err}"
        );

        drop(lease);
        let _lease2 =
            KeyDomainLease::acquire_existing_key(&key_str).expect("lease releases on clean exit");

        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_domain_lease_rejects_symlink_alias_to_same_key_file() {
        let dir = temp_dir("lease-alias");
        let key = dir.join("server.key");
        let alias = dir.join("alias.key");
        std::fs::write(&key, b"placeholder").unwrap();
        std::os::unix::fs::symlink(&key, &alias).unwrap();

        let key_str = key.to_string_lossy();
        let alias_str = alias.to_string_lossy();
        let lease =
            KeyDomainLease::acquire_existing_key(&key_str).expect("first exit owns the key domain");
        let err = match KeyDomainLease::acquire_existing_key(&alias_str) {
            Ok(_) => panic!("alias to the same key inode must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.contains("one ARC key domain supports one live exit"),
            "{err}"
        );

        drop(lease);
        let _lease2 = KeyDomainLease::acquire_existing_key(&alias_str)
            .expect("alias can acquire after the original lease drops");

        let _ = std::fs::remove_file(&alias);
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(not(unix))]
    #[test]
    fn key_domain_lease_fails_closed_without_unix_flock() {
        let dir = temp_dir("lease-non-unix");
        let key = dir.join("server.key");
        let key_str = key.to_string_lossy();

        let err = match KeyDomainLease::acquire_preflight(&key_str) {
            Ok(_) => panic!("shared-key exits must fail closed without an enforceable lease"),
            Err(err) => err,
        };
        assert!(err.contains("Unix flock"), "{err}");

        let _ = std::fs::remove_file(format!("{key_str}.exit.lock"));
        let _ = std::fs::remove_dir(&dir);
    }
}
