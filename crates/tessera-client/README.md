# tessera-client

Client-side ARC credential holder: attaches an unlinkable presentation to each request.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This crate is the client: it drives issuance (`begin_issuance` → `PendingIssuance::finalize`) to obtain a finalized [`Credential`], then wraps it in a `TesseraClient` that mints a fresh, unlinkable presentation per request and hex-encodes it for the `Tessera-Presentation` header. It is transport-agnostic — it only produces a header string — and pairs with `tessera-origin` (the server guard that verifies presentations) and `tessera-issuer` (the PoW-gated issuance endpoint), both built on the `tessera-arc` crypto core.

## Usage

```rust
use rand_core::OsRng;
use tessera_client::{begin_issuance, TesseraClient};

// Issuance: bind a request to a context, then finalize against the server reply.
let (pending, request) = begin_issuance(b"issuance-ctx", server_public_key, &mut OsRng);
// ... send `request` to the issuer, receive a `CredentialResponse` ...
let credential = pending.finalize(&response)?;

// Presentation: produce up to `limit` unlinkable headers for a context.
let mut client = TesseraClient::new(credential, b"presentation-ctx", 100);
let header = client.presentation_header(&mut OsRng)?; // hex-encoded
// send as `Tessera-Presentation: {header}`
# Ok::<(), tessera_arc::arc::ArcError>(())
```

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md).
