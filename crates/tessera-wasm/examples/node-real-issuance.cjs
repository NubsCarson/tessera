// Cross-language end-to-end: a Node program drives the `tessera-wasm` *browser*
// client through a REAL issuance + presentation against a running
// `tessera-tower-demo` origin. It proves a wasm-minted credential is accepted by
// the Rust origin over real HTTP — the browser-client mile, headless (no GUI;
// the extension's declarativeNetRequest plumbing still needs a real browser).
//
// Prereqs:
//   1. Build the wasm for the nodejs target:
//        cargo build --manifest-path crates/tessera-wasm/Cargo.toml \
//          --target wasm32-unknown-unknown --release
//        wasm-bindgen --target nodejs --out-dir <pkg-dir> \
//          crates/tessera-wasm/target/wasm32-unknown-unknown/release/tessera_wasm.wasm
//   2. Run the origin:  cargo run --manifest-path crates/tessera-tower-demo/Cargo.toml
//   3. node crates/tessera-wasm/examples/node-real-issuance.cjs <pkg-dir> [base-url]

const path = require("path");

const pkgDir = process.argv[2];
const base = process.argv[3] || "http://127.0.0.1:8090";
if (!pkgDir) {
  console.error("usage: node node-real-issuance.cjs <pkg-dir> [base-url]");
  process.exit(2);
}
const t = require(path.resolve(pkgDir, "tessera_wasm.js"));

// Must match the origin's configured contexts/limit (tessera-tower-demo).
const REQUEST_CTX = "tessera-tower-demo/issue/v1";
const PRESENT_CTX = "tessera-tower-demo/origin/v1";
const LIMIT = 5n; // u64 -> BigInt

const enc = new TextEncoder();
const fromHex = (h) => Uint8Array.from(Buffer.from(h.trim(), "hex"));

(async () => {
  // 1. Fetch the issuer's public key.
  const pubkeyHex = await (await fetch(base + "/pubkey")).text();

  // 2. Browser side: begin a real issuance bound to that PUBLIC key.
  const flow = t.prepare_issuance(
    fromHex(pubkeyHex),
    enc.encode(REQUEST_CTX),
    enc.encode(PRESENT_CTX),
    LIMIT
  );

  // 3. Send the request to the issuer; get the credential response.
  const respHex = await (
    await fetch(base + "/issue", { method: "POST", body: flow.request_hex() })
  ).text();

  // 4. Browser side: finalize into a credential, then present a header.
  const cred = flow.finalize(respHex);
  const header = cred.present();

  // 5. Hit the guarded origin: no credential, the wasm credential, then a replay.
  const noCred = (await fetch(base + "/")).status;
  const withCred = (
    await fetch(base + "/", { headers: { "Tessera-Presentation": header } })
  ).status;
  const replay = (
    await fetch(base + "/", { headers: { "Tessera-Presentation": header } })
  ).status;

  console.log("no credential   ->", noCred);
  console.log("wasm credential ->", withCred);
  console.log("replay          ->", replay);
  const ok = noCred === 403 && withCred === 200 && replay === 403;
  console.log(
    ok
      ? "PASS: a wasm-issued credential was admitted by the Rust origin; replay rejected"
      : "FAIL: unexpected status codes"
  );
  process.exit(ok ? 0 : 1);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
