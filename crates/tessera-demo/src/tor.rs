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

pub fn run_onion_demo(
    origin_port: u16,
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    rng: &mut OsRng,
) -> Result<()> {
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

    ui::result(
        blocked.status == 403,
        "over Tor · no credential",
        blocked.status,
        "blocked — same as any Tor exit today",
    );

    // Now present a real credential over the same Tor circuit.
    let credential = crate::issue_credential(sk, pk, rng);
    let mut client = TesseraClient::new(credential, crate::PRESENT_CTX, crate::LIMIT);
    let header = client
        .presentation_header(rng)
        .map_err(|_| Error::other("presentation failed"))?;
    let admitted = net::get_via_socks5(&proxy, &onion, 80, Some(&header))?;
    ui::result(
        admitted.status == 200,
        "over Tor · with Tessera credential",
        admitted.status,
        "admitted — anonymous transport, trusted on proof alone",
    );

    drop(tor); // explicit: kill tor + clean up now
    Ok(())
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
