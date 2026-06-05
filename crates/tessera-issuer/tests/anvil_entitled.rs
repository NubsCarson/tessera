//! OPT-IN live integration: prove [`tessera_issuer::mint::EthRpc`] reads a *real*
//! on-chain `entitled(buyer)` from a deployed `TokenMint` on a local **anvil**
//! node. Like the demo's Tor test, this self-skips unless explicitly enabled, so
//! it never runs (or flakes) in CI:
//!
//!   * set `TESSERA_ANVIL_E2E=1`, and
//!   * have `anvil`, `forge`, `cast` on `PATH` (Foundry).
//!
//! Run from the repo root:
//!   `TESSERA_ANVIL_E2E=1 cargo test -p tessera-issuer --test anvil_entitled -- --nocapture`

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tessera_issuer::mint::{EntitlementSource, EthRpc};

// Anvil's deterministic dev accounts (standard mnemonic). Account 0 deploys +
// is the issuer; account 1 is the buyer.
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ISSUER_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const BUYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const BUYER_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const PORT: u16 = 8651; // uncommon, to dodge a stray :8545

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Kills the anvil child on drop.
struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hex20(s: &str) -> [u8; 20] {
    let b = hex::decode(s.trim_start_matches("0x")).unwrap();
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    a
}

#[test]
fn ethrpc_reads_real_entitlement() {
    if std::env::var("TESSERA_ANVIL_E2E").is_err() {
        eprintln!("skipping: set TESSERA_ANVIL_E2E=1 (+ anvil/forge/cast) to run the live test");
        return;
    }
    if !have("anvil") || !have("forge") || !have("cast") {
        eprintln!("skipping: anvil/forge/cast not on PATH");
        return;
    }

    let rpc = format!("http://127.0.0.1:{PORT}");

    // 1. Boot anvil.
    let anvil = Anvil(
        Command::new("anvil")
            .args(["--port", &PORT.to_string(), "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn anvil"),
    );
    // Wait for the RPC to answer (cast block-number polls it).
    let mut up = false;
    for _ in 0..50 {
        if Command::new("cast")
            .args(["block-number", "--rpc-url", &rpc])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(up, "anvil did not come up on {rpc}");

    // 2. Deploy TokenMint(issuer = account0, price = 1 wei) from contracts/.
    let out = Command::new("forge")
        .current_dir("../../contracts")
        .args([
            "create",
            "src/TokenMint.sol:TokenMint",
            "--rpc-url",
            &rpc,
            "--private-key",
            DEPLOYER_KEY,
            "--broadcast",
            "--json",
            "--constructor-args",
            ISSUER_ADDR,
            "1",
        ])
        .output()
        .expect("forge create");
    assert!(
        out.status.success(),
        "forge create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Parse the deployed address from forge's JSON (pretty-printed, so be
    // whitespace-tolerant): find "deployedTo", then the next 0x… string.
    let anchor = stdout
        .find("\"deployedTo\"")
        .expect("forge json has deployedTo");
    let hexstart = stdout[anchor..].find("0x").expect("deployedTo address") + anchor;
    let hexend = stdout[hexstart..].find('"').unwrap() + hexstart;
    let mint = &stdout[hexstart..hexend];

    // 3. Buyer purchases: value 64 wei @ price 1 ⇒ entitled[buyer] = 64.
    let buy = Command::new("cast")
        .args([
            "send",
            mint,
            "purchase()",
            "--value",
            "64",
            "--rpc-url",
            &rpc,
            "--private-key",
            BUYER_KEY,
        ])
        .output()
        .expect("cast send purchase");
    assert!(
        buy.status.success(),
        "cast send purchase failed: {}",
        String::from_utf8_lossy(&buy.stderr)
    );

    // 4. MY EthRpc reads the real on-chain entitlement.
    let rpc_reader = EthRpc::new(rpc, hex20(mint));
    let entitled = rpc_reader
        .entitled(&hex20(BUYER_ADDR))
        .expect("EthRpc.entitled");
    assert_eq!(
        entitled, 64,
        "EthRpc must read the real on-chain entitled[buyer]"
    );

    // A buyer who never purchased reads 0.
    let zero = rpc_reader.entitled(&[0x12u8; 20]).expect("entitled(other)");
    assert_eq!(zero, 0);

    eprintln!("anvil live read OK: entitled[buyer] = {entitled}");
    drop(anvil); // explicit teardown (also happens on scope exit)
}
