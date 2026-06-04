# tessera-origin

Server-side ARC presentation guard: admit anonymous requests on a credential, not on an IP.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This crate is the origin-side guard: it holds the server keys, the agreed request/presentation contexts, a per-credential presentation limit, and an in-memory spent-tag set. Given the value of a single request header, `OriginGuard::check` verifies the zero-knowledge presentation, enforces single-use of each presentation slot, and returns a `Decision`. It is transport-agnostic and never looks at the source IP, so it sits downstream of `tessera-arc` (the crypto core) and accepts presentations built by `tessera-client`.

## Usage

```rust
use rand_core::OsRng;
use tessera_arc::keys::ServerPrivateKey;
use tessera_origin::{Decision, OriginGuard, PRESENTATION_HEADER};

// Server keys (in practice loaded from storage, see ServerPrivateKey::serialize).
let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);

let guard = OriginGuard::new(sk, pk, b"request-ctx", b"this-origin", /* limit */ 5);
// Wire into any HTTP stack: pull the header and hand its value to check().
let header = req_headers.get(PRESENTATION_HEADER); // Option<&str>

match guard.check(header) {
    Decision::Admit { tag } => { /* serve; `tag` is the rate-limit handle */ }
    Decision::Reject(reason) => { /* deny, e.g. log reason.label() */ }
}
```

## `tower` middleware (optional feature)

For a real HTTP service, enable the off-by-default `tower` feature to get a drop-in
[`tower::Layer`] — `TesseraLayer` — that runs the guard for you. It reads the
`Tessera-Presentation` header off each `http::Request`, calls `OriginGuard::check`,
forwards admitted requests to the inner service, and short-circuits rejected ones
with **`403 Forbidden`** (reason in the `Tessera-Reject` response header) *without
ever polling the inner service*. The source IP is still never consulted. The core
crate stays dependency-light; the feature only adds `tower` + `http` +
`http-body-util` + `bytes`.

```toml
[dependencies]
tessera-origin = { version = "0.0", features = ["tower"] }
```

```rust
use std::sync::Arc;
use tessera_origin::{OriginGuard, TesseraLayer};

// `guard: OriginGuard` built as above; share it (and its spent-tag set).
let guard = Arc::new(guard);

// axum:
//   let app = Router::new()
//       .route("/", get(handler))
//       .layer(TesseraLayer::new(guard));
//
// any tower stack:
//   let svc = ServiceBuilder::new()
//       .layer(TesseraLayer::new(guard))
//       .service(inner);
let _layer = TesseraLayer::new(guard);
```

Note: the feature's HTTP deps (`tower 0.5`, `http 1`, …) currently build on the
crate's MSRV (1.74) — the all-features CI job is verified on 1.74. A future minor
bump of those crates may raise their own MSRV above 1.74, at which point pin them
back or build the MSRV job without `--all-features` (the core guard always builds
on 1.74).

## Edge deployment (Cloudflare Worker / WASM) — sketch

The guard is just "header in → `Decision` out", so it maps cleanly onto an edge
runtime. The shape, **not a shipped artifact**:

- Build `tessera-origin` (guard + `tessera-arc`) for `wasm32-unknown-unknown`
  with `getrandom`'s `js` feature, inside a [`workers-rs`](https://github.com/cloudflare/workers-rs)
  Worker. On each `fetch`, read `Tessera-Presentation` and call `check`; on
  `Admit` `fetch()` the origin, on `Reject` return `403` — the same logic as the
  `tower` layer, at the edge.
- **Two real constraints, why this is a sketch and not shipped here:** (1) the
  Worker holds the **server secret key** — it must come from a Worker secret /
  KMS, never the bundle; (2) the in-memory spent-tag set does **not** survive
  across Worker isolates, so double-spend enforcement needs a shared store
  (Durable Object / KV / D1) — i.e. the durable-`TagStore` work, which is not
  done. Until both are addressed, an edge deploy weakens the replay guarantee.

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). The spent-tag set is in-memory and per-process, not a durable or distributed double-spend store.
