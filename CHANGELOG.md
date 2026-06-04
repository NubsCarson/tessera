# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

The pre-1.0 development line. **Research-grade and unaudited** — see
[`SECURITY.md`](./SECURITY.md) and [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md).

### Added
- `tessera-arc` — the IETF ARC(P-256) credential: P-256 group/hashing layer,
  server key generation, issuance (request/response/finalize), presentation with
  an integrated bit-decomposition range proof, the SHAKE128 Fiat-Shamir + Sigma
  proof layer, canonical wire serialization, and a double-spend tag store.
  Validated **byte-for-byte** against the ARC §10.2 arithmetic vectors and the
  authoritative IETF Sigma Protocol proof vectors.
- `ServerPrivateKey` serialization (`serialize`/`from_bytes`) with a **redacted
  `Debug`**, for key persistence.
- `tessera-origin` — `OriginGuard`: admit a request on a valid, in-budget,
  unspent presentation; **never reads the source IP**.
- `tessera-client` — credential holder that mints one unlinkable presentation
  per request.
- `tessera-issuer` — a **proof-of-work issuance gate** (hashcash challenge /
  solve / verify + one-time `ChallengeStore`). A cost gate, **not** strong Sybil
  resistance.
- `tessera-proxy` — a credential-gated forward `CONNECT` proxy: admit on a
  Tessera credential (never the IP) and tunnel TLS **end-to-end** to any HTTPS
  site (e.g. the Anthropic API), optionally over Tor. "Use Claude through Tor."
- `tessera-demo` — a real std-only HTTP origin + client; a narrated terminal
  walkthrough, a `--serve` browser hub (auto-opens; `/enter` mints fresh
  credentials), and a `--tor` onion-service path.
- Hardening: 5 `cargo-fuzz` targets, a stable robustness/mutation test, criterion
  benches, `docs/THREAT_MODEL.md`, and CI (fmt, clippy `-D warnings`, tests,
  docs, MSRV 1.74, `cargo-audit`, nightly fuzz).

### Known issues
- The ARC §10.2 **proof-blob** test vectors do not reconcile with the pinned
  reference (upstream skew); the proof layer is proven against the Sigma vectors
  instead and the ARC-blob tests are `#[ignore]`d. See
  [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md).
- Not third-party audited; best-effort (not audited) constant-time; IETF drafts
  may change.
