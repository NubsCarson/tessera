# Tessera browser extension — Manifest V3 **scaffold**

> ⚠️ **NOT per-request unlinkable — do not use this for privacy.** Chrome's
> `declarativeNetRequest` attaches **one** presentation value to many requests
> (it cannot call wasm per request), which breaks ARC's per-request
> unlinkability. This extension demonstrates in-browser issuance + header
> attachment **mechanics only**. For real per-request unlinkability, point your
> browser at the local **`tessera-client` CONNECT proxy**, which mints a fresh
> single-use token per request.

A minimal MV3 extension that mints a Tessera ARC presentation in-browser (via
the `tessera-wasm` wasm-bindgen glue) and attaches it as a `Tessera-Presentation`
request header to outgoing requests.

> **This is a scaffold**, but a working one: it does **real issuance** against a
> live origin (`prepare_issuance` → POST `/issue` → `finalize`, the same flow
> proven headlessly in `examples/node-real-issuance.cjs`), and the defaults are
> wired to the local [`tessera-tower-demo`](../../tessera-tower-demo) origin so
> you can see it admit you in a real browser (walkthrough below). The one honest
> caveat that remains: header attachment uses `declarativeNetRequest`, whose rule
> value is static, so it reuses one presentation across requests until it rotates
> — i.e. **not unlinkable per-request** (see "Header attachment").

## Local walkthrough — see it work in your browser

The `pkg/` glue is already built and the defaults target `http://127.0.0.1:8090`.

1. **Run the origin** (issuer + guarded `/`), in a terminal:
   ```sh
   cargo run --manifest-path crates/tessera-tower-demo/Cargo.toml
   ```
2. **Confirm raw access is blocked:** open `http://127.0.0.1:8090/` in the browser
   → **403 Forbidden** (this is what every Tor user gets today).
3. **Load the extension:** `chrome://extensions` → toggle **Developer mode** →
   **Load unpacked** → select this `extension/` directory. Give it a second; open
   the card's **"service worker"** console to watch `[tessera]` mint a credential.
4. **Reload** `http://127.0.0.1:8090/` → **200**, body `admitted ✓ …`. Same IP,
   same browser — admitted purely on the credential the extension attached.
5. **Refresh again** → **403**. That's the double-spend protection working: DNR
   replays the *same* presentation (the documented limit below); the extension
   rotates to a fresh one on its timer (~60s), after which a load is 200 again.

If step 4 stays 403: make sure the origin is running, that you reloaded after the
service worker logged a mint, and (Chrome) that the extension shows no errors.

## Build the wasm glue

From the crate root (`crates/tessera-wasm/`):

```sh
# 1. wasm target (idempotent)
rustup target add wasm32-unknown-unknown

# 2a. Recommended: wasm-pack (bundles the JS glue + .wasm into ./pkg)
cargo install wasm-pack          # one-time; compiles a fair bit
wasm-pack build --target web --out-dir extension/pkg --release

# 2b. Or plain wasm-bindgen (no wasm-pack):
cargo build --target wasm32-unknown-unknown --release
cargo install wasm-bindgen-cli --version 0.2.122   # MUST match the wasm-bindgen crate version
wasm-bindgen target/wasm32-unknown-unknown/release/tessera_wasm.wasm \
  --target web --out-dir extension/pkg
```

Either path produces `extension/pkg/tessera_wasm.js` + `extension/pkg/tessera_wasm_bg.wasm`,
which `background.js` imports. The wasm-bindgen-cli version **must equal** the
`wasm-bindgen` crate version pinned in `Cargo.toml` (`0.2.122`) or the glue is
incompatible.

## Load unpacked (Chrome / Chromium / Edge)

1. Build the glue (above) so `extension/pkg/` exists.
2. Open `chrome://extensions`.
3. Toggle **Developer mode** (top-right) on.
4. Click **Load unpacked** and select this `extension/` directory.
5. Open the service-worker console (the extension card → "service worker") to
   watch `[tessera]` logs as it mints and installs the DNR rule.
6. Edit `TARGET_URL_FILTER` in `background.js` and the matching
   `host_permissions` entry in `manifest.json` to the origin you are testing,
   then reload the extension.

Firefox (≥ MV3 support) is similar via `about:debugging` → "This Firefox" →
"Load Temporary Add-on", selecting `manifest.json`.

## Header attachment: declarativeNetRequest (and its limits)

MV3 removed the *blocking* `webRequest` content-modification path, so the
supported way to add a request header that must be present *before* the request
leaves the browser is `declarativeNetRequest` (DNR) `modifyHeaders`. DNR rules
are applied natively, so they work even when the service worker is asleep.

The cost: a DNR rule's header **value is static** — DNR can't call into wasm per
request. `background.js` therefore mints a presentation in JS and writes it into
the rule, rotating on a timer. That means **the same header value is reused
across requests until the next rotation**, which breaks ARC's one-unlinkable-
presentation-per-request property. A faithful client (what `tessera-client`
does on the Rust side) mints a fresh presentation *per request*; achieving that
in an extension needs either a local helper that issues single-use headers, the
now-restricted blocking `webRequest`, or very aggressive rule rotation. This
scaffold uses the timer to demonstrate the mechanism, **not** to be unlinkable.

## Cross-language end-to-end (verified, headless)

The wasm client genuinely interoperates with a real Rust origin. With the
[`tessera-tower-demo`](../../tessera-tower-demo) server running (it exposes
`/pubkey` + `/issue` + a guarded `/`), drive the wasm client from Node:

```sh
# build the nodejs-target glue
cargo build --manifest-path crates/tessera-wasm/Cargo.toml --target wasm32-unknown-unknown --release
wasm-bindgen --target nodejs --out-dir /tmp/tessera-node-pkg \
  crates/tessera-wasm/target/wasm32-unknown-unknown/release/tessera_wasm.wasm
# run the origin, then drive the wasm client through real issuance + present:
cargo run --manifest-path crates/tessera-tower-demo/Cargo.toml &
node crates/tessera-wasm/examples/node-real-issuance.cjs /tmp/tessera-node-pkg
# -> no credential -> 403 ; wasm credential -> 200 ; replay -> 403 ; PASS
```

This proves the browser-side flow (`prepare_issuance` → POST request → `finalize`
→ `present`) produces a credential the Rust origin admits, with double-spend
rejection — the whole thesis, across languages, no GUI required.

## What's real vs. scaffold

| Piece | State |
|-------|-------|
| `tessera-arc` + `tessera-client` crypto on `wasm32` | ✅ compiles; headless round-trip test passes (node) |
| `mint_local` / `present()` wasm-bindgen API | ✅ tested in-wasm |
| **Real issuance** (`prepare_issuance`/`IssuanceFlow`) against a live issuer | ✅ tested in-wasm + verified cross-language vs a Rust origin (above) |
| MV3 manifest + DNR header-attach wiring (`background.js` uses real issuance) | ✅ scaffold, not run in a live browser here |
| Per-request unlinkable presentations | ⬜ DNR reuses a value between rotations (documented limit) |
| Loaded in a **browser** hitting a live origin (GUI/DNR) | ⬜ **human final mile** |
