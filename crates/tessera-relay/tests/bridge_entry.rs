//! Gated obfs4-bridge entry e2e: runs `scripts/demo-bridge-entry.sh`, which stands
//! up a LOCAL obfs4 bridge relay + a Tessera onion exit and pulls a live site over
//! the **obfs4 → real Tor → .onion** path (credentialed request → 200). Self-skips
//! unless `TESSERA_PT_E2E=1` and `tor` + `obfs4proxy` are present, so default CI is
//! green without the pluggable-transport binaries or network egress.
//!
//! The no-credential → 403/407 half of the gate is covered transport-agnostically
//! by the existing onion e2e (`tessera-demo`'s `TESSERA_TOR_E2E` probe) and the
//! live SSRF/credential checks — the obfs4 entry does not change the credential
//! gate, only how the client reaches the network.

use std::process::Command;

fn runs_ok(bin: &str, version_flag: &str) -> bool {
    Command::new(bin)
        .arg(version_flag)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn obfs4_bridge_entry_pulls_a_live_site() {
    if std::env::var("TESSERA_PT_E2E").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping: set TESSERA_PT_E2E=1 to run the obfs4 bridge e2e \
             (needs tor + obfs4proxy + outbound internet)"
        );
        return;
    }
    if !runs_ok("tor", "--version") || !runs_ok("obfs4proxy", "-version") {
        eprintln!("skipping: tor and/or obfs4proxy not on PATH");
        return;
    }
    // Workspace root = this crate's dir, up two levels (crates/tessera-relay).
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let status = Command::new("bash")
        .arg("scripts/demo-bridge-entry.sh")
        .current_dir(root)
        .status()
        .expect("run scripts/demo-bridge-entry.sh");
    assert!(
        status.success(),
        "obfs4 -> Tor -> .onion bridge-entry demo did not pull a live response"
    );
}
