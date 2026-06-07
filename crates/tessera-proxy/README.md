# tessera-proxy

A credential-gated HTTP `CONNECT` proxy: admit on a Tessera credential (not an IP), tunnel TLS through Tor.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This crate is a forward `CONNECT` proxy you point a normal HTTPS client at: it reads the `Tessera-Presentation` header, verifies it with [`tessera-origin`](../tessera-origin)'s `OriginGuard`, and only then opens a tunnel to the requested `host:port` — directly or through a Tor SOCKS5 proxy — and pipes raw bytes. Because it's `CONNECT`, the client's TLS runs end-to-end to the real upstream (e.g. `api.anthropic.com`), so the proxy never sees plaintext. It sits at the network edge alongside `tessera-origin`, consuming credentials minted by [`tessera-client`](../tessera-client) from the [`tessera-arc`](../tessera-arc) crypto core.

## Usage

```sh
cargo run -p tessera-proxy           # direct upstream
cargo run -p tessera-proxy -- --tor  # tunnel through Tor at 127.0.0.1:9050
```

On startup it self-issues a credential, binds `127.0.0.1:8118` (overridable via `TESSERA_LISTEN`; it exits rather than fall back to a random port), and prints a ready-to-paste `curl` command using the `Tessera-Presentation` proxy header. Requests with a valid single-use credential are admitted and tunneled; missing or invalid credentials get `407 Proxy Authentication Required`.

Admitted requests then clear a **target policy** before the exit dials: by default (`TESSERA_TARGET_POLICY=secure`) only port `:443` is allowed and private/loopback/link-local/CGNAT/cloud-metadata destinations are refused (`403`), with resolve-then-pin against DNS rebinding — so the exit cannot be turned into an SSRF oracle for its own network. Set `TESSERA_TARGET_POLICY=unrestricted` (or widen `TESSERA_ALLOWED_PORTS`) for local development. The destination-policy is orthogonal to the credential: the credential is judged blind to the target, the target blind to the credential.

For a networked issuer+exit deployment, set `TESSERA_KEY_FILE` on the issuer and
this exit to the same path. That path is one ARC key domain; after key
convergence, the proxy takes a local advisory lock on the established key file
inode and fails closed if a second live local exit reaches the same key through a
symlink/hardlink/path alias. On Unix the lease releases automatically when the
process exits. This is not a distributed lease and cannot detect copied key bytes
on another path or host. Independent exits need separate issuer/key files/key
pins, not one shared fleet key. Set `TESSERA_SPENT_TAG_FILE` to persist spent
tags across a single exit restart; it is not a distributed multi-exit tag store.

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). This is std-only demo/example tooling, not a hardened production proxy.
