# AGENTS.md — Tessera contributor & agent guide

Tessera is an **anonymous-credentials trust layer**: admit a web request on an
unlinkable, rate-limited credential — **never on its source IP**. The
cryptographic core is a from-scratch, vector-proven implementation of IETF
**Anonymous Rate-Limited Credentials (ARC) over NIST P-256** — a
keyed-verification anonymous credential (KVAC) scheme — wrapped in a small
network: an issuance authority, a client, a 2-hop split-trust access loop
(blind relay + credential-gated CONNECT exit), and an optional EVM settlement
tier.

This file is the canonical, tool-agnostic guide for both engineers and AI
agents. Read it before changing anything.

> ### Posture (load-bearing — do not soften)
> **Research-grade. UNAUDITED.** Not constant-time end-to-end. Classical
> discrete-log over P-256 only — **no post-quantum claim** (Shor breaks it).
> Smart contracts are **TESTNET-ONLY**. Do **not** describe any part of Tessera
> as audited, secure, production-ready, or as delivering private/uncensorable
> clearnet access. The honest headline is: *a vector-proven ARC/P-256
> keyed-verification implementation plus supporting network* — not "anonymity."
> The project's credibility is its calibrated candor; every "UNAUDITED" /
> "testnet-only" / "cost knob, not Sybil resistance" / "no post-quantum claim"
> qualifier is intentional. Keep them.

---

## 1. Repo layout

```
crates/        Rust workspace members + two excluded sub-workspaces
contracts/     Foundry / Solidity settlement layer (TESTNET-ONLY)
circuits/      circom R_dec circuit + snarkjs build tooling (TEST-ONLY setup)
docs/          The primary deliverable surface alongside the code (read these)
deploy/        docker-compose + dstack deployment scaffolding
fuzz/          nightly cargo-fuzz targets (excluded sub-workspace)
target/        build output (gitignored)
```

Root long-form docs: `README.md`, `AUDIT.md`, `GOAL.md`, `SECURITY.md`,
`CONTRIBUTING.md`, `CHANGELOG.md`, `DEMO.md`. `Cargo.lock` is committed; license
is `MIT OR Apache-2.0`.

### Workspace crates (members of the root `[workspace]`)

| Crate | Role |
| --- | --- |
| `tessera-arc` | The crypto core: from-scratch IETF ARC over P-256 (KVAC). Issuance + presentation + the deterministic double-spend tag. Keyed-verification — **no public verifiability**. |
| `tessera-issuer` | Credential **authority** node: gates who can *obtain* a credential via a PoW gate (a cost knob) or a paid on-chain TokenMint gate; convergent shared-key bootstrap. |
| `tessera-client` | Thin, transport-agnostic client: drives issuance and mints one fresh unlinkable presentation per request as the hex `Tessera-Presentation` header. Owns no crypto. |
| `tessera-origin` | Server-side admission **guard** (`OriginGuard::check`) + spent-tag stores + optional `tower` middleware (off by default). Source IP is never an input. |
| `tessera-proxy` | Credential-gated CONNECT **exit**: admits on a credential, tunnels opaque bytes (direct or via Tor SOCKS5), applies per-egress human-volume shaping. |
| `tessera-relay` | The credential-**blind** first hop + the 2-hop split-trust loop; ships the relay node binary and the local `tessera-client` proxy binary. |
| `tessera-channel` | Off-chain Spilman payment-channel **protocol** state machine (Phase 2a, plain crypto). **Not ZK, moves no money.** secp256k1 (EVM-native), the workspace exception. |
| `tessera-demo` | Runnable end-to-end narration binary (localhost; `--tor`; `--serve`). Demo tooling, not a library. |

### Excluded sub-workspaces (own manifest, own `Cargo.lock`, own CI job)

Listed in root `Cargo.toml` `[workspace].exclude` so their special deps can
never perturb the host MSRV-1.74 / clippy / test / doc gates. They are **not**
workspace members — you must pass `--manifest-path`.

| Path | Role |
| --- | --- |
| `crates/tessera-wasm` | `tessera-arc` + `tessera-client` compiled to `wasm32` via wasm-bindgen (browser client) + an MV3 extension **scaffold**. Excluded for the wasm32-only `getrandom` `js` dep. |
| `crates/tessera-tower-demo` | Runnable axum origin+issuer using `tessera-origin`'s `TesseraLayer`. Excluded for the axum+tokio deps. |
| `fuzz/` | Nightly-only cargo-fuzz targets. |

### Non-Rust components

- `contracts/` — three Solidity files: `TokenMint.sol` (ETH-paid mint rail, the
  leaner default), `ChannelRegistry.sol` (the optional-advanced on-chain
  "court"), `RDecVerifier.sol` (**generated**, TEST-ONLY trusted setup).
  Dependency-free Foundry project (vendored `test/Std.sol`, pinned solc 0.8.24).
- `circuits/` — the R_dec decrement circuit and its build tooling. Build scratch
  (`build/`, `node_modules`, `*.ptau`, `*.zkey`, `*.wtns`) is gitignored and
  regenerable; **TEST-ONLY**.

---

## 2. Build, test & lint

Toolchain is **stable**, pinned via `rust-toolchain.toml` (rustfmt + clippy
components). **MSRV is 1.74** (`rust-version = "1.74"`). `Cargo.lock` is
committed for reproducible, auditable tooling — keep it. Edition is 2021.

Run the suite rather than trusting any hard-coded test/fuzz **counts** in the
docs — several docs carry stale numbers; `AUDIT.md` + `docs/CEILING_PROGRESS.md`
are the closest to current, but re-measure from source if it matters.

**Main workspace** (cwd `/home/nubs/tessera`):

```sh
cargo fmt --all -- --check
cargo +1.74.0 build --workspace --all-features --locked   # MSRV gate
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
cargo bench --workspace --no-run --locked
cargo deny check
```

**Excluded sub-workspaces** (own manifest; cwd `/home/nubs/tessera`):

```sh
cargo fmt    --all -- --check                 --manifest-path crates/tessera-wasm/Cargo.toml
cargo clippy --all-targets -- -D warnings     --manifest-path crates/tessera-wasm/Cargo.toml
cargo test                                    --manifest-path crates/tessera-wasm/Cargo.toml

cargo fmt    --all -- --check                 --manifest-path crates/tessera-tower-demo/Cargo.toml
cargo clippy --all-targets -- -D warnings     --manifest-path crates/tessera-tower-demo/Cargo.toml
cargo test                                    --manifest-path crates/tessera-tower-demo/Cargo.toml
```

`tessera-wasm` pins `wasm-bindgen = "=0.2.122"` / `wasm-bindgen-test = "=0.3.72"`
exactly; the `wasm-bindgen-cli` used to build glue / run the headless test
**must** equal `0.2.122` or the module is rejected.

**Contracts** (cwd `/home/nubs/tessera/contracts`):

```sh
forge build && forge test -vv
```

**Fuzz** (nightly; cwd `/home/nubs/tessera/fuzz`):

```sh
cargo +nightly fuzz build
```

---

## 3. Architecture in one screen

- **The inversion.** A request is admitted on an unlinkable, rate-limited ARC
  credential, *never* on its source IP. The whole system exists to demonstrate
  this one move. `OriginGuard::check` takes the `Tessera-Presentation` header
  and nothing else; "no header" is exactly what raw Tor traffic looks like.

- **ARC / P-256 keyed-verification core (`tessera-arc`).** A server issues a
  credential to an anonymous client (request → response → finalize); the client
  presents it up to a fixed `limit` times, each presentation mutually
  unlinkable and unlinkable from issuance. Each verified presentation yields a
  deterministic rate-limiting **tag** keyed by `(credential, context, nonce)`.
  **Keyed-verification (KVAC): the issuer IS the verifier** — `verify_presentation`
  needs the server private key. There is **no public verifiability**. A range
  proof (spec §5.4) binds `0 <= nonce < limit`. Tracks three IETF drafts:
  `draft-ietf-privacypass-arc-crypto-01`, `draft-irtf-cfrg-sigma-protocols-01`,
  `draft-irtf-cfrg-fiat-shamir-01`.

- **The tag is not double-spend protection by itself.** `verify_presentation`
  returns `Some(tag)` *only if the proof verified*, but the caller must still
  push that tag through a persistent, correctly-keyed spent-tag store. The
  in-memory store ships for tests; deployment needs a shared/durable one.

- **2-hop split-trust loop.** A blind **relay** (`tessera-relay`) sits in front
  of a credential-gated CONNECT **exit** (`tessera-proxy`). No single hop holds
  {who}+{where}+{what}: the relay learns `{client, exit}` but never the
  destination or credential; the exit learns `{destination, that a valid
  credential was presented}` but never the client's address; neither sees
  content (the client's end-to-end TLS rides through both hops untouched).

- **Credential-gated CONNECT exit + human-volume shaping.** The exit admits on
  the credential, then tunnels opaque bytes (direct or Tor SOCKS5). A per-egress
  `VolumeShaper` keeps an egress IP inside a human-plausible envelope —
  over-envelope traffic is **gracefully throttled (bounded delay), never
  hard-blocked** (a hard refusal is itself a fingerprint). A separate hard
  transport cap (`MAX_INFLIGHT`) drops excess connections; do not conflate them.

- **Paid mint (`TokenMint.sol`).** The recommended-default monetization rail: a
  buyer pays ETH and earns a redeemable entitlement to N access tokens the
  off-chain ARC issuer later blind-issues. Purchase links buyer → "obtained N";
  later presentations are unlinkable to the purchase.

- **On-chain "court" (`ChannelRegistry.sol`, optional-advanced tier).** Escrows
  a unidirectional Spilman channel and slashes **only binary, cryptographically-
  provable badness** (equivocation = two states at the same `seq` with different
  commitments both validly signed by one party). Liveness is deliberately **not**
  slashable. `tessera-channel` is the off-chain model of this court; it computes
  verdicts, it does not move money.

The **leaner default** path is: ARC blind tokens + credential-gated exit over
Tor + per-IP volume shaping — **no channel, dispute window, watchtower, court,
or MPC ceremony**. The ZK Spilman channel / `ChannelRegistry` / `RDecVerifier` /
R_dec circuit are a kept-and-tested **optional-advanced tier**, not the default.

---

## 4. Conventions

- **Edition 2021**, MSRV **1.74** (don't bump deps past it — e.g. `tessera-channel`
  pins `ark` 0.4 / `light-poseidon` 0.2.0 because `ark` 0.5 needs 1.75).
- `cargo fmt --all -- --check` and `cargo clippy ... -- -D warnings` must stay
  clean on the workspace **and** both excluded sub-workspaces.
- `cargo deny check` must pass; keep `Cargo.lock` committed.
- All library crates set `#![forbid(unsafe_code)]`; most set
  `#![deny(missing_docs)]` — every `pub` item needs a doc-comment or the build
  fails. Don't add undocumented public items.
- **Never panic on untrusted/deserialized input.** Deserializers and
  verification paths return `Err`/`false`/`None`, never abort. Protocol-rule
  violations are typed errors; only cryptographically-impossible internal states
  may `expect()`.
- **Dependency-minimal by design.** The network crates are std-only blocking
  sockets with hand-rolled framing; don't "modernize" to tokio/reqwest/TLS
  without a reason. The core `tessera-origin` guard stays dependency-light (the
  `tower` feature is off by default). Contracts stay dependency-free.
- **Deterministic where it matters.** Cross-language Rust↔Solidity crypto
  vectors are pinned and brittle *by design* (a drift alarm); the channel uses
  RFC-6979 deterministic ECDSA so equivocation is attributable. Tests inject
  clocks where timing matters.
- `publish = false` on every crate. Binaries fail-fast on misconfig (loud
  exit-1/exit-2) and never silently fall back to an ephemeral port or downgrade
  a shared key to an ephemeral one.

---

## 5. Do NOT (read this section twice)

- **Do NOT call Tessera audited, secure, production-ready, or post-quantum**, in
  code, comments, or docs. It is research-grade, UNAUDITED, classical-DL-only.
  Preserve every existing qualifier verbatim.
- **Do NOT describe ARC as publicly verifiable.** It is keyed-verification — the
  verifier needs the private key.
- **Do NOT edit the ARC/Sigma/Fiat-Shamir code to chase the draft-arc §10.2
  presentation-proof BLOB vectors.** There is a documented upstream Fiat-Shamir
  transcript skew: the pinned Sigma codec squeezes the challenge at
  `scalar_len+16`, the upstream POC HEAD moved to `+32`, and the committed §10.2
  proof blobs reconcile with **neither** (a brute-force sweep over squeeze
  lengths finds no match). Filed as **draft-arc#68**. Those
  two KATs are intentionally `#[ignore]`d in
  `crates/tessera-arc/tests/proof_vectors.rs`. See
  `docs/ARC_PROOF_VECTOR_DISCREPANCY.md`. **Do not re-investigate or "fix" it.**
  (All ARC *arithmetic* vectors DO reproduce byte-for-byte; the proof layer is
  validated against the authoritative IETF Sigma vectors instead.)
- **Do NOT reorder** scalar/element allocations or witness vectors in
  `tessera-arc/src/proofs.rs`, or change the challenge-squeeze length / sponge
  padding in `sigma.rs` — they feed the Fiat-Shamir transcript and will silently
  break prover/verifier agreement.
- **Do NOT treat a successful `verify_presentation` as double-spend
  protection**, and do NOT rely on the in-memory tag store in production. Use a
  shared, atomic `SpentTagStore` for multi-replica/edge deployments; prune the
  spent set **only** per key/context epoch — **never on a wall clock** (dropping
  live tags silently re-opens the double-spend window).
- **Do NOT make the source IP (or the peer address) an input to admission.**
  IP-blindness is the thesis; at the exit the socket peer is the relay, not the
  client. Treating it as the client breaks split-trust.
- **Do NOT make the relay parse anything inside the tunnel.** It reads only the
  outer CONNECT line (and, in channel mode, the three `Tessera-Channel-*` outer
  headers). Don't replace the one-byte-at-a-time status/CONNECT readers with
  buffered reads (they would swallow tunnel payload). Keep sign-then-serve and
  the "403 not-my-exit before the payment gate" ordering.
- **Do NOT deploy `contracts/src/RDecVerifier.sol` (or a `ChannelRegistry`
  wired to it) with value.** It is generated from a **TEST-ONLY single-party
  trusted setup**; it needs a real multi-party MPC ceremony first. Don't
  hand-edit its pairing constants — regenerate via `circuits/build.sh`.
- **Do NOT change cross-language crypto layouts** (domain strings, commitment/
  digest byte layout, signature encoding) in `tessera-channel` or `contracts/`
  without updating the pinned Rust vectors AND `CrossLanguageVector.t.sol` in
  lockstep. The breakage is intentional. Don't conflate the SHA-256 commitment
  with the Poseidon one, or the cleartext signing domain with the ZK one.
- **Do NOT present the channel / `ChannelRegistry` / `RDecVerifier` / R_dec as
  the default or as deployable-with-value** — it is the optional-advanced tier,
  Phase 2a is plain crypto (not ZK, no money movement), and the ZK pieces run
  and are tested (a pinned Groth16 `R_dec` proof verifies on-chain, and
  `cooperativeCloseZK` settles end-to-end without a cleartext balance) but are
  generated from a **TEST-ONLY single-party trusted setup**, so they are still
  not deployable-with-value.
- **Do NOT claim relationship anonymity for the default docker-compose
  topology.** It provides none if the relay and exit are run by one operator
  (`docs/DEPLOYMENT_TOPOLOGY.md` §6). The split-trust property only holds across
  independent operators. Surface this wherever someone runs the stack.
- **Do NOT describe PoW issuance as Sybil resistance.** It is a per-credential
  cost knob; the difficulty floor (`MIN_DIFFICULTY = 1`) and the paid-mode
  issuer-pk pin (anti-wormhole) are deliberate guards — don't weaken them.
- **Do NOT publish any crate to crates.io** (`publish = false` is intentional,
  gated on a third-party audit). Do NOT remove the committed `Cargo.lock`, and
  do NOT add Foundry dependencies / change the vendored `test/Std.sol` /
  unpin solc 0.8.24.
- **Do NOT add `unsafe` code or panics on untrusted input**, fold the excluded
  sub-workspaces back into the root members, or bump `wasm-bindgen` off its exact
  `=0.2.122` pin.

---

## 6. Docs index (what to read for what)

`docs/` is a primary deliverable, not an afterthought. Start here:

- **`docs/README.md`** — index + 8-point decision log. Read first for "why".
- **`docs/STATUS.md`** — single source-of-truth status table; the reconciliation
  authority when docs disagree (note: its test counts are stale).
- **`AUDIT.md`** — the auditor entry point: component inventory, the exact CI
  gate commands, in/out of scope, and the blunt known-issues list.
- **`docs/ARCHITECTURE.md`** — default (leaner ecash/ARC) path vs the
  optional-advanced channel tier.
- **`docs/THREAT_MODEL.md` / `docs/SECURITY_ARGUMENT.md`** — per-property
  construction → assumption → gap with file:line citations.
- **`docs/DEPLOYMENT_TOPOLOGY.md` / `docs/KEY_MANAGEMENT.md` /
  `docs/OBSERVABILITY.md` / `docs/SAFETY.md`** — operations, key convergence
  (issuer↔exit share one ARC key), the no-per-request-logging rule, the
  anonymity-set (context-partitioning) warning.
- **`docs/ARC_PROOF_VECTOR_DISCREPANCY.md` + `docs/upstream-arc-vector-issue.md`**
  — the draft-arc#68 skew, in full. The final word; don't re-open it.
- **`docs/ECONOMICS.md` / `docs/RELAYER_CHEAT_MATRIX.md` /
  `docs/CHANNEL_RECOVERY.md` / `docs/EPOCH_AUTHORITY.md`** — the channel tier only.
- **`docs/POW_ANALYSIS.md`** — why PoW is a cost knob, not Sybil resistance.
- **`docs/DESIGN.md` / `docs/ROADMAP.md` / `docs/CEILING_PROGRESS.md` /
  `docs/IP_EGRESS_IDEAS.md` / `docs/POST_QUANTUM.md` /
  `docs/PROTOCOL_VERSIONING.md` / `docs/PERFORMANCE.md`** — direction & frontier.
  Treat these as proposed/unbuilt conventions, not shipped features (only the M5
  `VolumeShaper` from the egress portfolio is built).
- Per-crate `README.md` files and `contracts/README.md` / `circuits/README.md`
  for component specifics (note: `contracts/README.md`'s test count/layout is
  stale — trust the `test/` directory).

---

## 7. The three irreducibly-external gaps (nobody can fake these in code)

No code in this repo can manufacture, and you must never imply it does:

1. **A genuinely clean, residential-class egress IP** behind the exit, at scale.
2. **A real Tor/Nym anonymity crowd** — and it must also cover the
   client → issuer hop (issuance itself exposes the client's IP and time; ARC
   unlinkability hides only the *later* presentations).
3. **A third-party security audit.**

(The optional ZK tier adds a fourth: a real ≥5-party MPC ceremony for the R_dec
trusted setup.)

These are documented hand-offs, not bugs. State them; don't paper over them.
