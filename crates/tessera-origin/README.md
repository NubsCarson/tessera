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

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). The spent-tag set is in-memory and per-process, not a durable or distributed double-spend store.
