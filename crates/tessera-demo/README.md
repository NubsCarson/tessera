# tessera-demo

End-to-end Tessera demo: an origin that admits anonymous requests on a credential, not an IP.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This binary wires the whole stack together: it pays a `tessera-issuer` proof-of-work gate, mints an anonymous credential, stands up a real localhost HTTP origin guarded by `tessera-origin`, and drives it with a `tessera-client` — showing admit, over-limit, and replay outcomes. It is the runnable narration of the other crates, not a library.

## Usage

```
cargo run -p tessera-demo
```
Runs the localhost flow: solves a 16-bit PoW, issues a credential, then makes real HTTP requests with no credential (403), under the limit (200, distinct unlinkable tags), over the limit (client refuses), and replayed (403).

```
cargo run -p tessera-demo -- --tor
```
Same flow, then additionally exposes the origin as a Tor onion service and drives it over a real Tor circuit to show admission on the credential alone.

```
cargo run -p tessera-demo -- --serve
```
Leaves a guarded origin running on `127.0.0.1:8088` and opens a browser landing page; each "Enter" mints a fresh single-use credential so you can click indefinitely, and reloading an admitted page demonstrates double-spend rejection.

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). This is std-only demo/example tooling (best-effort key persistence, a toy HTTP path), not hardened.
