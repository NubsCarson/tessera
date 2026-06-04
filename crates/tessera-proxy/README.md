# tessera-proxy

A credential-gated HTTP `CONNECT` proxy: admit on a Tessera credential (not an IP), tunnel TLS through Tor.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This crate is a forward `CONNECT` proxy you point a normal HTTPS client at: it reads the `Tessera-Presentation` header, verifies it with [`tessera-origin`](../tessera-origin)'s `OriginGuard`, and only then opens a tunnel to the requested `host:port` — directly or through a Tor SOCKS5 proxy — and pipes raw bytes. Because it's `CONNECT`, the client's TLS runs end-to-end to the real upstream (e.g. `api.anthropic.com`), so the proxy never sees plaintext. It sits at the network edge alongside `tessera-origin`, consuming credentials minted by [`tessera-client`](../tessera-client) from the [`tessera-arc`](../tessera-arc) crypto core.

## Usage

```sh
cargo run -p tessera-proxy           # direct upstream
cargo run -p tessera-proxy -- --tor  # tunnel through Tor at 127.0.0.1:9050
```

On startup it self-issues a credential, binds `127.0.0.1:8118` (or a random port), and prints a ready-to-paste `curl` command using the `Tessera-Presentation` proxy header. Requests with a valid single-use credential are admitted and tunneled; missing or invalid credentials get `407 Proxy Authentication Required`.

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). This is std-only demo/example tooling, not a hardened production proxy.
