//! Integration test: the `torrc` Tessera generates for the client is accepted by
//! the **real Tor binary** (`tor --verify-config`), for both the plain SOCKS case
//! and a bridge / pluggable-transport case. This proves we emit syntactically
//! valid Tor configuration (we configure Tor, we do not reimplement it).
//!
//! Self-skips when `tor` is not on `PATH`, so default CI stays green on hosts
//! without Tor installed (mirrors the gated `TESSERA_TOR_E2E` convention).

use std::path::PathBuf;
use std::process::Command;

use tessera_client::{client_torrc, BridgeConfig, PluggableTransport};

fn tor_available() -> bool {
    Command::new("tor")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Write `body` to a temp torrc and run `tor --verify-config` against it.
fn tor_accepts(body: &str, tag: &str) -> bool {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("tessera-torrc-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let torrc = dir.join("torrc");
    std::fs::write(&torrc, body).expect("write torrc");
    let ok = Command::new("tor")
        .arg("--verify-config")
        .arg("-f")
        .arg(&torrc)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&dir);
    ok
}

#[test]
fn generated_torrc_is_valid_tor_config() {
    if !tor_available() {
        eprintln!("skipping: `tor` not on PATH");
        return;
    }
    let data = std::env::temp_dir().join("tessera-torrc-data");
    let data = data.display().to_string();
    let log = std::env::temp_dir().join("tessera-torrc.log");
    let log = log.display().to_string();

    // Plain SOCKS client torrc — must verify.
    let plain = client_torrc(19099, &data, &log, None).unwrap();
    assert!(
        tor_accepts(&plain, "plain"),
        "plain torrc rejected by tor:\n{plain}"
    );

    // Bridge / obfs4 torrc — `/bin/true` is a stand-in plugin (verify-config
    // parses but does not launch it), with a syntactically valid obfs4 line.
    let bridge = BridgeConfig {
        transport: PluggableTransport::Obfs4,
        plugin_path: "/bin/true".to_string(),
        bridge_lines: vec![
            "obfs4 192.0.2.1:443 0000000000000000000000000000000000000000 \
             cert=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0"
                .to_string(),
        ],
    };
    let body = client_torrc(19099, &data, &log, Some(&bridge)).unwrap();
    assert!(
        tor_accepts(&body, "bridge"),
        "bridge torrc rejected by tor:\n{body}"
    );
}
