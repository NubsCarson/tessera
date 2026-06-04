# tessera-wasm

`wasm-bindgen` browser bindings for the Tessera ARC client — ROADMAP track 3
("WASM browser client"). Compiles the [`tessera-arc`](../tessera-arc) crypto core
and [`tessera-client`](../tessera-client) to `wasm32-unknown-unknown` and exposes
a tiny, honest JS surface so a credential can be **minted and presented in a
browser**.

> **Status: compiles to wasm32; the in-browser extension is a scaffold.** The
> wasm core builds and its mint→present round-trip is tested headlessly. The
> [`extension/`](./extension) MV3 scaffold wires a `Tessera-Presentation` header
> via `declarativeNetRequest`, but loading it in a real browser against a live
> origin is the human final mile (see `extension/README.md`).

## Why a separate, excluded crate

Like [`fuzz/`](../../fuzz), this is its **own single-crate workspace** and is
listed in the root `Cargo.toml`'s `[workspace].exclude`. Its wasm-only
dependency (`getrandom`'s `js` feature, for Web Crypto entropy) must never
perturb the host workspace's native fmt/clippy/test/MSRV/doc gates. It has its
own `wasm` CI job instead.

## API

- `TesseraCredential.present() -> string` — the hex `Tessera-Presentation`
  header, byte-identical to `tessera_client::TesseraClient::presentation_header`.
  Spends one unit of presentation budget; errors (thrown to JS) once exhausted.
- `mint_local(request_context, presentation_context, limit) -> TesseraCredential`
  — a self-contained issuance helper (full request → response → finalize
  round-trip against an **ephemeral** server key) so a credential is
  constructible in a demo/test without a network peer. Production clients
  obtain their credential from a real issuer.

All fallible JS-facing calls return a `Result` that surfaces as a thrown
`JsError`, never a panic/abort.

## Build (the core deliverable)

```sh
rustup target add wasm32-unknown-unknown   # idempotent
cargo build --manifest-path crates/tessera-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --release
```

## Test

Native fallback (always available, plain host toolchain — runs the identical
mint→present logic via this crate's `rlib`):

```sh
cargo test --manifest-path crates/tessera-wasm/Cargo.toml
```

Headless wasm (the real in-wasm round-trip, via node). The
`wasm-bindgen-cli` version **must exactly match** the `wasm-bindgen` crate
version (`0.2.122`):

```sh
cargo install wasm-bindgen-cli --version 0.2.122
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --manifest-path crates/tessera-wasm/Cargo.toml \
  --target wasm32-unknown-unknown
```

`wasm-pack test --node` drives the same tests; `wasm-pack test --headless
--firefox` runs them in a real browser.

## Browser extension

See [`extension/README.md`](./extension/README.md) for the MV3 scaffold, the
`wasm-pack build --target web` glue build, and load-unpacked steps.
