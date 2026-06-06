# Tessera

[![CI](https://github.com/NubsCarson/tessera/actions/workflows/ci.yml/badge.svg)](https://github.com/NubsCarson/tessera/actions/workflows/ci.yml)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV 1.74](https://img.shields.io/badge/MSRV-1.74-blue.svg)](#build--run)
![status: research-grade, unaudited](https://img.shields.io/badge/status-research--grade%20%C2%B7%20unaudited-orange.svg)

**Admit a web request on an unlinkable token it can prove — never on its IP.**

Tessera is a from-scratch, **IETF-vector-proven** implementation of *Anonymous
Rate-Limited Credentials (ARC)* plus the tooling around it — including a
self-hostable, credential-gated **`CONNECT` proxy you can run over Tor today**
that admits traffic on a token, not an address. It is **research-grade and
UNAUDITED**: a tested protocol artifact + runnable tool, **not yet** a deployed
network.

> **Where it's heading (vNext — a research-grade *direction*, not a delivered
> property):** a private clearnet-*access* network that pays anonymously, per
> request, to reach sites which blocklist Tor exit IPs — via a **clean
> credentialed egress** + per-IP human-volume shaping, with anonymity provided by
> Tor. The design is [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) (the leaner
> ecash-token path) and [`docs/DESIGN.md`](./docs/DESIGN.md). Honest about its
> limits: it removes the *IP/Tor-exit* block — it does **not** win the anti-bot
> arms race or force a hostile site, and clean-IP supply + a Tor crowd + an audit
> are external. ~85% prior art; the contribution is the composition + the candor.

> A **tessera** was a small token used in ancient Rome as a ticket of
> admission — proof you were allowed in, carried in the hand, tied to no name.
> That is exactly what this is: a cryptographic token that admits a request on
> its own merit, not on who or where it came from.

## What this is / what it is NOT

**It IS, today (tested, CI-green):**
- a from-scratch **ARC (P-256)** anonymous-credential core, proven **byte-for-byte
  against the IETF test vectors** — a **keyed-verification (KVAC)** scheme: the
  issuer is the verifier (verification needs the server private key), so
  presentations are **not publicly verifiable** (see [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md));
- a runnable, self-hostable **credential-gated proxy** — admit on a token, tunnel
  TLS end-to-end, optionally over Tor — plus a narrated end-to-end demo;
- a tested **2-hop split-trust access loop**, **per-IP human-volume shaping**, an
  ETH-paid **token-mint rail**, and an **optional ZK payment-channel tier** (with
  an EVM court), all CI-green;
- **honest** — every limit and external hand-off is named, not hidden.

**It is NOT (yet):**
- a deployed, anonymous **network** a stranger can use — that needs clean
  residential egress IPs at scale **+** a Tor/Nym anonymity crowd (external);
- **audited** — no third-party review yet; do not protect real users or funds;
- a way to defeat a determined anti-bot system or "reach any site" — it removes
  the **IP / Tor-exit** block, not the arms race;
- **post-quantum** — the discrete-log assumption is classical.

## See it

![Tessera demo](docs/demo.svg)

```sh
cargo run -p tessera-demo            # real HTTP origin + client, localhost
cargo run -p tessera-demo -- --tor   # also drive it over a real Tor onion circuit
```

The demo stands up an origin guarded by `tessera-origin`, issues a credential to
a `tessera-client`, and makes **real HTTP requests**: no credential → `403`
(what every Tor user gets today); with a credential → `200` and a fresh,
unlinkable tag each time; over the limit → the client refuses; a replay → `403`
double-spend. The origin never reads the source IP. See [`DEMO.md`](./DEMO.md).

### Reach any HTTPS site, gated on a credential — never on your IP

```sh
cargo run -p tessera-proxy            # or: -- --tor  (tunnel via Tor at :9050)
```

`tessera-proxy` is a forward **`CONNECT`** proxy that admits a request only if it
carries a valid Tessera credential — **never on its IP** — then tunnels it to any
HTTPS endpoint (your TLS stays end-to-end; the proxy never sees plaintext),
optionally over Tor. Point a normal client at it; no credential → `407`. It
prints a ready-to-run `curl` for a sample HTTPS API. The result, end to end:
anonymous, accountable, IP-blind access to the clearnet — admitted on a
credential, not an address.

> **"IP-blind" is about *admission*, not invisibility.** The proxy decides who to
> admit on the token alone and never reads your source IP — but the destination
> still sees the proxy's **egress** IP. Reaching sites that blocklist Tor exit IPs
> therefore depends on a *clean* egress IP (and human-volume shaping to keep it
> clean); it does **not** defeat a site determined to fingerprint/block you. See
> [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) and
> [`docs/IP_EGRESS_IDEAS.md`](./docs/IP_EGRESS_IDEAS.md).

### Run it yourself as a network (Docker / TEE)

```sh
docker compose -f deploy/docker-compose.yaml up --build   # issuer + relay + exit + client
curl -x http://127.0.0.1:8120 https://example.com         # admitted on a token, not your IP
```

This runs the **whole network** as containers: an **issuer** mints PoW-gated
credentials (sharing one ARC key with the exit), the **relay**+**exit** form the
2-hop loop, and a local **client proxy** obtains a credential and routes each
request through it on a fresh, unlinkable token — re-issuing when the budget is
spent. Verified end to end: `crates/tessera-relay/tests/network.rs` (all four
nodes in-process) plus a 4-process binary run reaching a real HTTPS site (`200`).

Issuance can be gated on **proof of work** (default) or a **paid on-chain mint**:
buy tokens from `TokenMint.sol` with ETH, prove control of the buyer address, and
the issuer issues against the live on-chain entitlement (`TESSERA_MINT_RPC` /
`TESSERA_BUYER_KEY`; verified against a real anvil chain). See
[`docs/DEPLOY.md`](./docs/DEPLOY.md).

For a **verifiable, non-logging relay**, deploy it into an Intel TDX **TEE via
dstack** — a client can then *attest* that the node runs this exact open-source
image and physically can't log. That nails the **trust** axis; the **clean-IP**
axis stays external. See [`docs/DEPLOY.md`](./docs/DEPLOY.md).

## The problem it attacks

The web decides whether to trust you by your **IP address**. Tor's exit relays
are published and deterministically blockable, so anonymous traffic is treated
as guilty by default — blocked, CAPTCHA-walled, or rate-limited into
uselessness. Throwing more crypto at *hiding that you're Tor* is a losing
arms race, and it's the wrong layer: the server sees a source IP no matter what.

Tessera changes the trust primitive instead. A client obtains an **ARC
credential** and presents it with each request. The server learns only:

- this presentation came from *some* validly-issued credential, and
- it is within that credential's fixed presentation budget,

…and **nothing else** — not the client's identity, not which credential it is,
and no two presentations are linkable to each other or to issuance. The server
can now rate-limit and trust anonymous clients **without IP reputation**, so it
has no reason to block Tor. Censorship by IP becomes obsolete rather than evaded.

This is the missing adapter between Privacy-Pass-style anonymous credentials
and anonymity networks — see [`GOAL.md`](./GOAL.md) for the full thesis and
roadmap.

## Crates

A Cargo workspace of **ten crates** (eight workspace members + two excluded,
listed separately below) — a verifiable crypto core plus the tooling around it.
Per [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) the **recommended default**
is the token-gated path (ARC token + a credential-gated clean exit reached over
Tor + per-IP shaping); the custom 2-hop loop is **dropped from that target
default** (let Tor provide the anonymity hops), though the **as-shipped**
`deploy/` docker network still runs the relay+exit 2-hop loop today. The ZK
payment **channel / EVM court are an optional-advanced tier**, kept and tested
for when pay-as-you-go-with-refund is genuinely needed.

| Crate | What it is |
|-------|-----------|
| [`tessera-arc`](./crates/tessera-arc) | The cryptographic core: ARC over P-256 — group/hashing, issuance, presentation + integrated range proof, the SHAKE128 Fiat-Shamir / Sigma proofs, wire serialization, and the double-spend tag store. Proven against the IETF test vectors. |
| [`tessera-issuer`](./crates/tessera-issuer) | The credential **authority**. A proof-of-work **issuance gate** ("earn your budget") *plus* **networked issuance** (`serve_issuance` — clients obtain a credential over the wire) and an optional **ETH-paid on-chain mint** (`serve_issuance_paid`: issue against a `TokenMint` purchase, `ecrecover`-proven, verified vs a live anvil chain). Also produces the `tessera-issuer` node binary. |
| [`tessera-origin`](./crates/tessera-origin) | Server-side `OriginGuard`: admit a request on a valid, in-budget, unspent presentation — **never** on the source IP. Transport-agnostic. |
| [`tessera-client`](./crates/tessera-client) | Holds a credential and mints one fresh, unlinkable presentation per request; also **obtains a credential over the wire** from a networked issuer (`obtain_credential` / `obtain_credential_paid`). |
| [`tessera-proxy`](./crates/tessera-proxy) | A credential-gated `CONNECT` proxy: IP-blind, TLS-end-to-end access to any HTTPS site, optionally over Tor. |
| [`tessera-relay`](./crates/tessera-relay) | The first onion hop, forming the **2-hop split-trust loop**: the relay learns {client, exit} but never the destination; the exit learns {destination + that a valid token was presented} but never the client; neither sees content. **Default (recommended): ARC-token mode** — the request is gated on an unlinkable, rate-limited token checked at the credential-gated exit (proven end-to-end, no channel). It *also* has an **optional channel-payment mode** (the relay as channel counterparty, `tessera-channel`) for pay-per-request with the advanced tier. This crate also builds the runnable local **`tessera-client` proxy binary** (`src/bin/tessera-client.rs`, via `serve_client_proxy`/`CredentialSource`) — the thing you point a browser/curl at. Tested end-to-end. |
| — *optional-advanced tier* — | *the ZK payment channel + on-chain court below; kept + tested, not on the default path (see `docs/ARCHITECTURE.md`).* |
| [`tessera-channel`](./crates/tessera-channel) | **(optional-advanced)** The **ZK Spilman channel state machine** (`DESIGN.md` §2): a unidirectional, monotone-decrementing, single-payee off-chain payment channel — user-signed states (equivocation is attributable), sign-then-serve co-signing, HOPR-style proof-of-relay, a watchtower, and off-chain dispute/settlement. Chain-facing sigs are **EVM-native secp256k1 over a recoverable keccak256 digest** (`ecrecover`-verifiable) + a SHA-256 state commitment + a Poseidon commitment for the ZK path. |
| [`contracts/`](./contracts) | The **Foundry on-chain rails**. `TokenMint.sol` is the **leaner default**: an ETH-paid mint (pay → token entitlement → the issuer blind-issues ARC tokens). `ChannelRegistry.sol` is the **optional-advanced** EVM court for the channel — open/close/dispute/slash/refund + a relayer bond + a ZK (`R_dec` Groth16) settlement path — with a **real Rust→Solidity cross-language vector** + a **pinned ZK proof** verified on-chain. Testnet-only, UNAUDITED. |
| [`tessera-demo`](./crates/tessera-demo) | The runnable end-to-end demo: narrated CLI, a `--serve` browser hub, and a `--tor` onion-service path. |

Plus an out-of-workspace wasm client (its own excluded workspace, like `fuzz/`):

| Crate | What it is |
|-------|-----------|
| [`tessera-wasm`](./crates/tessera-wasm) | `wasm-bindgen` browser bindings: real issuance (`prepare_issuance`) + `present()` in-browser. **Compiles to `wasm32`**, headless node tests pass, and a wasm-issued credential is **verified to interoperate with the Rust origin** (`examples/node-real-issuance.cjs`). Ships an MV3 [extension scaffold](./crates/tessera-wasm/extension) — loading it in an actual browser is the human final mile. |
| [`tessera-tower-demo`](./crates/tessera-tower-demo) | A runnable **`axum` server** using the `tessera-origin` `tower` middleware. Run it from its own dir — `cd crates/tessera-tower-demo && cargo run` (it's an excluded workspace, so `-p` from the root won't find it) — then `curl` the printed commands; its end-to-end test drives a real server on a multi-threaded `tokio` runtime over a real socket (admit / malformed / replay / fresh). |

> Not yet published to crates.io — every crate is `publish = false` pending a
> third-party security audit. Use it via a git or path dependency for now.

## Standards

Tessera tracks three IETF drafts. The ARC arithmetic and the Sigma proof layer
are validated against the authoritative official test vectors; the Fiat-Shamir
transform has no standalone vector set and is exercised **indirectly**, through
the Sigma Protocol vectors (the FS-transformed non-interactive proofs):

- [`draft-ietf-privacypass-arc-crypto-01`](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/) — the ARC protocol (Yun, Wood, Faz-Hernández); arithmetic vectors proven byte-exact (the §10.2 *proof* blobs are `#[ignore]`d — see [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md))
- [`draft-irtf-cfrg-sigma-protocols-01`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) — the zero-knowledge proof system; verifier proven byte-for-byte against the official Sigma vectors
- [`draft-irtf-cfrg-fiat-shamir-01`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/) — the non-interactive transform; no separate KAT set, validated via the Sigma vectors above

## Status

| Layer | State |
|-------|-------|
| P-256 group / hashing / serialization | ✅ proven against IETF vectors |
| Server key generation | ✅ proven against IETF vectors |
| Issuance & presentation arithmetic | ✅ proven against IETF vectors |
| Fiat-Shamir + Sigma proofs | ✅ verifier proven against authoritative Sigma vectors; prover exercised via end-to-end round-trip † |
| Full ARC API (issue / present / verify) + range proof + double-spend store | ✅ end-to-end round-trip proven |
| `tessera-issuer` — proof-of-work issuance gate ("earn your budget") | ✅ cost-gate (not strong Sybil resistance — see threat model) |
| `tessera-proxy` — credential-gated CONNECT proxy (any HTTPS site, optionally over Tor) | ✅ admit on credential not IP; TLS tunneled end-to-end |
| `tessera-origin` guard + `tessera-client` (real HTTP demo) | ✅ admit/reject tested; IP never read |
| `tessera-origin` optional `tower` middleware (`TesseraLayer`) | ✅ feature-gated drop-in `Layer`; proven in a real `axum` server over a real socket (`tessera-tower-demo`) — admit/malformed/replay/fresh |
| `tessera-origin` pluggable spent-tag store (`SpentTagStore`) | ✅ in-memory default + durable `FileTagStore`; double-spend survives a guard restart (tested) |
| Tor binding (onion-service end-to-end) | ✅ implemented; live circuit needs host Tor egress |
| `tessera-channel` — ZK Spilman channel protocol state machine (Phase 2a) | ✅ user-signed states / sign-then-serve / proof-of-relay / off-chain settlement; secp256k1+keccak chain-facing sigs |
| `contracts/ChannelRegistry.sol` — EVM on-chain court (Phase 2c) | ✅ escrow/close/challenge/slash/refund via `ecrecover`; **Rust→Solidity cross-language vector verified**; testnet-only, UNAUDITED |
| Hardening — CT fix, fuzzing, benches, threat model | ✅ internal audit applied ([`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md)); **not** third-party audited |

† The ARC §10.2 *proof* blobs are not byte-reproducible from the pinned
reference (an upstream vector inconsistency — the ARC *arithmetic* vectors all
pass; see [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md)).
The Fiat-Shamir layer is instead proven against the authoritative IETF Sigma
Protocol test vectors, which exercise the identical transcript machinery.

The crate currently proves the entire **arithmetic core** of ARC matches the
reference byte-for-byte (`tests/test_vectors.rs`; the full crate has many more
tests — round-trip, wire, sigma-vector, proof, and robustness suites):

```
$ cargo test -p tessera-arc --test test_vectors
running 8 tests
test generator_h_is_deterministic ... ok
test server_public_key_matches_vectors ... ok
test hash_to_scalar_matches_m2 ... ok
test credential_request_encryptions_match ... ok
test credential_response_arithmetic_matches ... ok
test finalize_credential_matches ... ok
test presentation1_arithmetic_matches ... ok
test presentation2_arithmetic_matches ... ok
```

## ⚠️ Security status — read this

This is **research-grade, draft-tracking code**. It has **not** been
third-party audited; the known secret-dependent path (the range-proof bit
decomposition) is constant-time-hardened via `subtle`, but there has been **no
end-to-end constant-time audit**; and the underlying specs are IETF *drafts*
that may change. **Do not use it to protect real users yet.** The path to that
is a **third-party security audit** — the internal hardening pass
([`GOAL.md`](./GOAL.md) milestone 10) is **done**, but that is explicitly *not* an
external audit. The cryptographic
primitives come from the audited [RustCrypto](https://github.com/RustCrypto)
project; the protocol logic on top is what still needs review.

To report a vulnerability, see [`SECURITY.md`](./SECURITY.md). The full trust
model, per-goal guarantees, and known gaps are in
[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md).

## Documentation

| Doc | What's in it |
|-----|--------------|
| [`docs/DESIGN.md`](./docs/DESIGN.md) | **vNext** — the full private-uncensorable-access design: ZK payment-channel rail, mixnet transport, anti-fingerprint, clean egress, the open frontier (cross-epoch anonymity) and honest ceilings. The live direction. |
| [`docs/IP_EGRESS_IDEAS.md`](./docs/IP_EGRESS_IDEAS.md) | The clean-egress (reach IP-blocking sites) portfolio — the hardest part: ranked ideas, build-now vs bets vs traps, and the honest "no silver bullet" verdict. |
| [`GOAL.md`](./GOAL.md) | The v0 thesis, the 10-milestone Definition of Done (all met), and deliberately-deferred future work. |
| [`DEMO.md`](./DEMO.md) | How to run and read the demo, including the `--tor` onion path. |
| [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) | Trust model, per-goal guarantees, threat actors, non-goals, known weaknesses, deployment guidance. |
| [`docs/SECURITY_ARGUMENT.md`](./docs/SECURITY_ARGUMENT.md) | Per-property argument: construction → assumption → gap to a formal proof. An auditor's map. |
| [`docs/ROADMAP.md`](./docs/ROADMAP.md) | The post-v0 frontier — audit-readiness, deployable middleware, WASM client, upstream + PQ research. |
| [`SECURITY.md`](./SECURITY.md) | Vulnerability disclosure policy + in/out of scope. |
| [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md) | The one known upstream vector inconsistency, with full reproduction. |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | The contribution bar + the exact CI gate commands. |
| [`CHANGELOG.md`](./CHANGELOG.md) | Notable changes. |

## Build & run

Requires a stable Rust toolchain (MSRV **1.74**).

```sh
# verify — the same gates CI runs
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check

# run it
cargo run -p tessera-demo             # narrated end-to-end demo
cargo run -p tessera-demo -- --serve  # browser hub at http://127.0.0.1:8088 (auto-opens)
cargo run -p tessera-demo -- --tor    # also drive a real Tor onion circuit
cargo run -p tessera-proxy            # credential-gated CONNECT proxy (any HTTPS site, optionally over Tor)

# fuzz — nightly + `cargo install cargo-fuzz`
cargo +nightly fuzz run wire_from_bytes -- -max_total_time=30

# the Phase 2c on-chain court (Foundry; no external deps)
cd contracts && forge build && forge test    # incl. the Rust->Solidity vector
```

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at
your option — the Rust ecosystem standard.
