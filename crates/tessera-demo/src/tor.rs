//! Optional `--tor` path: expose the running origin as a Tor onion service and
//! drive it over a real Tor circuit. This proves the thesis end-to-end over an
//! *anonymous transport* — the request literally arrives via Tor, and is
//! admitted (or blocked) purely on its credential.
//!
//! Best-effort and self-contained: it launches its own `tor` process with a
//! dedicated SOCKS port and data dir, waits for the descriptor to publish, then
//! cleans up. Any failure returns an `Err` and the caller degrades gracefully.

use std::io::{Error, ErrorKind, Result};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use rand_core::OsRng;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::TesseraClient;

use crate::net;
use crate::ui;

const SOCKS_PORT: u16 = 9250;

/// Kills the child tor process and removes the temp dir on drop.
struct TorProcess {
    child: Child,
    dir: std::path::PathBuf,
}
impl Drop for TorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// The two transport-agnosticism observations from one onion probe over real Tor.
pub struct OnionProbe {
    /// Status of a NO-credential request over the Tor circuit (expected 403).
    pub blocked_status: u16,
    /// Status of a VALID-credential request over the same circuit (expected 200).
    pub admitted_status: u16,
}

/// Spin up a dedicated Tor instance + onion service in front of the origin at
/// `origin_port`, then make two requests over the real Tor circuit: one with no
/// credential (expected blocked) and one carrying a fresh Tessera credential
/// (expected admitted). UI-free, so both the `--tor` demo and the `tor-test`
/// integration test reuse it. Tor + its descriptor publish make this ~30–60s.
pub fn run_onion_probe(
    origin_port: u16,
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    rng: &mut OsRng,
) -> Result<OnionProbe> {
    if Command::new("tor")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
    {
        return Err(Error::new(ErrorKind::NotFound, "`tor` is not installed"));
    }
    if !port_free(SOCKS_PORT) {
        return Err(Error::new(
            ErrorKind::AddrInUse,
            format!("SOCKS port {SOCKS_PORT} is busy"),
        ));
    }

    let dir = std::env::temp_dir().join(format!("tessera-tor-{origin_port}"));
    let _ = fs::remove_dir_all(&dir);
    let data = dir.join("data");
    let hs = dir.join("hs");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&hs)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&hs, fs::Permissions::from_mode(0o700))?;

    let torrc = dir.join("torrc");
    fs::write(
        &torrc,
        format!(
            "SocksPort 127.0.0.1:{SOCKS_PORT}\n\
             DataDirectory {data}\n\
             HiddenServiceDir {hs}\n\
             HiddenServicePort 80 127.0.0.1:{origin_port}\n\
             Log warn file {log}\n",
            data = data.display(),
            hs = hs.display(),
            log = dir.join("tor.log").display(),
        ),
    )?;

    ui::tor_line("launching a dedicated Tor instance + onion service …");
    let child = Command::new("tor")
        .arg("-f")
        .arg(&torrc)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let tor = TorProcess {
        child,
        dir: dir.clone(),
    };

    // Wait for the onion hostname to appear.
    let hostname_file = hs.join("hostname");
    let onion = wait_for(Duration::from_secs(20), || {
        fs::read_to_string(&hostname_file)
            .ok()
            .map(|s| s.trim().to_string())
    })
    .ok_or_else(|| Error::new(ErrorKind::TimedOut, "onion hostname never appeared"))?;
    ui::tor_line(&format!("onion address: {onion}"));

    // Wait until the service is actually reachable over Tor. A no-credential
    // request returning 403 both proves reachability AND demonstrates the
    // "blocked over Tor" case, so we reuse it.
    ui::tor_line("waiting for the descriptor to publish + circuit to build (can take ~30s) …");
    let proxy = format!("127.0.0.1:{SOCKS_PORT}");
    let blocked = wait_for(Duration::from_secs(90), || {
        net::get_via_socks5(&proxy, &onion, 80, None)
            .ok()
            .filter(|r| r.status != 0)
    })
    .ok_or_else(|| Error::new(ErrorKind::TimedOut, "onion service not reachable in time"))?;

    // Present a real credential over the same Tor circuit.
    let credential = crate::issue_credential(sk, pk, rng);
    let mut client = TesseraClient::new(credential, crate::PRESENT_CTX, crate::LIMIT);
    let header = client
        .presentation_header(rng)
        .map_err(|_| Error::other("presentation failed"))?;
    let admitted = net::get_via_socks5(&proxy, &onion, 80, Some(&header))?;

    drop(tor); // explicit: kill tor + clean up now
    Ok(OnionProbe {
        blocked_status: blocked.status,
        admitted_status: admitted.status,
    })
}

/// `--tor`: the narrated onion demo — run [`run_onion_probe`] over a real Tor
/// circuit and print the two results (no-credential blocked, credentialed
/// admitted), demonstrating the credential path is transport-agnostic.
pub fn run_onion_demo(
    origin_port: u16,
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    rng: &mut OsRng,
) -> Result<()> {
    let probe = run_onion_probe(origin_port, sk, pk, rng)?;
    ui::result(
        probe.blocked_status == 403,
        "over Tor · no credential",
        probe.blocked_status,
        "blocked — same as any Tor exit today",
    );
    ui::result(
        probe.admitted_status == 200,
        "over Tor · with Tessera credential",
        probe.admitted_status,
        "admitted — anonymous transport, trusted on proof alone",
    );
    Ok(())
}

#[cfg(all(test, feature = "tor-test"))]
mod tor_transport_test {
    use super::*;
    use crate::net;
    use std::net::TcpListener;
    use std::sync::Arc;
    use tessera_arc::keys::ServerPrivateKey;
    use tessera_origin::OriginGuard;

    /// M8 capstone (opt-in, live-Tor): the credential admission path is
    /// **transport-agnostic** — the SAME `OriginGuard` that admits a direct
    /// request admits one arriving over a REAL Tor circuit, and rejects one with
    /// no credential.
    ///
    /// It is **opt-in via `TESSERA_TOR_E2E=1`** and otherwise self-skips. This is
    /// deliberate: the test needs a `tor` binary *and* working Tor network egress,
    /// which a plain `cargo test --all-features` (the documented verify command)
    /// has no way to guarantee — so without the opt-in it skips and that command
    /// stays green everywhere (with or without Tor installed). It also skips
    /// gracefully (never panics) if Tor is absent or the circuit can't be built,
    /// so an opted-in run on a host with blocked egress reports a skip, not a
    /// red failure.
    ///
    /// Run for real: `TESSERA_TOR_E2E=1 cargo test -p tessera-demo --features tor-test`
    #[test]
    fn credential_path_is_transport_agnostic_over_real_tor() {
        if std::env::var("TESSERA_TOR_E2E").is_err() {
            eprintln!(
                "skipping live-Tor test: set TESSERA_TOR_E2E=1 to run it \
                 (needs a `tor` binary + working Tor egress)"
            );
            return;
        }
        if Command::new("tor")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping live-Tor test: no `tor` binary on PATH");
            return;
        }

        let mut rng = OsRng;
        let (sk, pk) = ServerPrivateKey::setup(&mut rng);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        let origin_port = listener.local_addr().expect("addr").port();
        let guard = Arc::new(OriginGuard::new(
            sk.clone(),
            pk,
            crate::REQUEST_CTX,
            crate::PRESENT_CTX,
            crate::LIMIT,
        ));
        net::serve(listener, guard, None, None);

        // Graceful skip — never panic — if the circuit can't be built (blocked
        // egress, slow descriptor publish, busy port). The test proves the
        // property when Tor egress works; it does not fail for a flaky network.
        let probe = match run_onion_probe(origin_port, &sk, &pk, &mut rng) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skipping live-Tor test: could not build a Tor circuit: {e}");
                return;
            }
        };

        // The whole point: the guard's verdict is identical regardless of the
        // transport the bytes arrived on.
        assert_eq!(
            probe.blocked_status, 403,
            "no credential must be blocked over Tor"
        );
        assert_eq!(
            probe.admitted_status, 200,
            "valid credential must be admitted over Tor"
        );
    }
}

/// Poll `f` until it returns `Some`, or `timeout` elapses.
fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        thread::sleep(Duration::from_millis(500));
    }
}
