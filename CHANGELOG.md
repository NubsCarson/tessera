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

#### Payment layer — ZK Spilman channel (`DESIGN.md` §2/§6)
- `tessera-channel` (**Phase 2a**) — the off-chain channel **protocol state
  machine**: monotone-decrementing single-payee Spilman channel, **user-signed
  states** (equivocation is attributable), **sign-then-serve** co-signing,
  HOPR-style **proof-of-relay**, and an off-chain `settle` → `Verdict::{Settle,
  SlashUser, RefundUser}` model of the on-chain court.
- `contracts/` (**Phase 2c**) — a Foundry `ChannelRegistry.sol`: the **EVM
  on-chain court** that enforces those verdicts (`open` escrow, `cooperativeClose`,
  `unilateralClose`+`challenge`+`settleDispute`, `slashEquivocation`,
  `refundOnTimeout`), verifying channel states with the **`ecrecover`**
  precompile. Checks-effects-interactions + a `nonReentrant` guard. No external
  Solidity deps (the test harness is vendored; no `forge install`/submodules).
  New `contracts` CI job (Foundry toolchain → `forge build` + `forge test`).
- **The cross-language proof:** `examples/eth_vector.rs` emits a real Rust-signed
  state; `tests/eth_vector.rs` (Rust) and `contracts/test/CrossLanguageVector.t.sol`
  (Solidity) both pin it, and the contract **recovers the same Ethereum address
  via `ecrecover`** from the identical bytes — i.e. a Rust-signed state verifies
  on-chain unchanged.
- `circuits/` + ZK settlement path (**Phase 2b-i**) — the `R_dec.circom`
  decrement circuit (Circom + snarkjs **Groth16/BN254**, ~3.4k constraints):
  proves a monotone-decrementing Spilman transition in zero knowledge — the two
  **Poseidon** commitments (seq++ structural), `B_next + cost === B_i`, **64-bit
  range checks on `B_i`/`cost`/`B_next` (all three — the money-mint footgun)**,
  the freshness tag, the per-epoch rate nullifier, and the **`chan_id ↔ K_chan`**
  binding. **No in-circuit ECDSA** (attribution stays the out-of-band secp256k1
  sig). `tessera-channel` gains a **Poseidon (BN254) commitment** (`light-poseidon`
  `new_circom`, byte-identical to circomlib/circomlibjs — pinned by a Rust
  known-answer test) + a ZK-path signed digest `keccak256(zk-domain ‖ poseidon C)`.
  `ChannelRegistry.cooperativeCloseZK` verifies a Groth16 proof via the generated
  `RDecVerifier.sol` and binds the **same single Poseidon commitment** with
  `ecrecover` — settling **without any cleartext balance in calldata** (on-chain
  settlement privacy). **The ZK cross-language proof:** `examples/rdec_vector.rs`
  emits the witness + a real signed state; `circuits/build.sh` (circom→snarkjs)
  generates a proof; the proof + public signals are **pinned** in
  `contracts/test/RDecVerifier.t.sol` and **verified on-chain in CI without
  circom/snarkjs**. Honest scope: does NOT hide the balance from the relayer (it
  knows it by construction); the private payout split needs the shielded pool
  (a later increment); the trusted setup is **single-party TEST-ONLY** (a real
  multi-party ceremony is required and is not faked). See `circuits/README.md`.

### Changed
- **`tessera-channel` chain-facing signatures: P-256 → EVM-native secp256k1**
  (a deliberate revision of Phase 2a). The channel settles on the EVM, which
  verifies secp256k1 cheaply/universally via `ecrecover` and P-256 only via a
  non-universal precompile (EIP-7212) or an expensive in-EVM library; 2a used
  P-256 purely by workspace convenience. The **durable state signature**
  (`sig_user`), the relayer **co-signature**, and (for a single signature type)
  the freshness-binding and proof-of-relay sigs now use **recoverable secp256k1**
  (`k256`) over a **keccak256 digest** (`keccak256(domain ‖ commitment)`); identity
  is the **20-byte Ethereum address** `keccak256(pubkey[1..])[12..]`. The SHA-256
  state *commitment* is unchanged. New deps: `k256` (workspace) and `sha3` (already
  in-tree). All existing `tessera-channel` tests adapted and still pass.

#### Post-v0 frontier ([`docs/ROADMAP.md`](./docs/ROADMAP.md))
- **Audit-readiness:** [`docs/SECURITY_ARGUMENT.md`](./docs/SECURITY_ARGUMENT.md)
  — every security property as construction → assumption → gap, with `file:line`.
- **Deployable middleware:** `tessera-origin`'s off-by-default `tower` feature —
  `TesseraLayer`/`TesseraGuard`, a drop-in `tower::Layer` that runs the guard and
  short-circuits rejects with `403` (`axum`/`hyper`-compatible). Lean deps
  (`tower`+`http`+`http-body-util`+`bytes`; no `axum`/`tokio`), 1.74-clean. Proven
  end-to-end in `tessera-tower-demo` — a runnable `axum` server (excluded crate,
  own `tower-e2e` CI job) whose test drives it on a multi-threaded `tokio` runtime
  over a real socket (admit / malformed / replay / fresh).
- **Pluggable spent-tag store:** the `SpentTagStore` trait + `OriginGuard::with_store`,
  with `InMemoryTagStore` (default) and a durable single-process `FileTagStore`.
  Double-spend enforcement is tested to survive a guard restart; a distributed
  backend is the deployer's via the trait.
- **WASM browser client:** `crates/tessera-wasm` (out-of-workspace, like `fuzz/`)
  — `wasm-bindgen` `present()`, the ephemeral `mint_local` demo, and **real
  issuance** (`prepare_issuance`/`IssuanceFlow`) against a live issuer's public
  key. Headless node tests (incl. real-issuance-vs-external-key), + an MV3
  extension scaffold (now using the real issuance flow). **Cross-language interop
  verified:** `examples/node-real-issuance.cjs` drives the wasm client through
  issuance + presentation against the `tessera-tower-demo` Rust origin
  (no-cred → 403, wasm credential → 200, replay → 403). The browser GUI/DNR step
  remains the one human final mile.
- **Real-HTTP middleware proof:** `crates/tessera-tower-demo` — a runnable `axum`
  server using `TesseraLayer` (+ `/pubkey` and `/issue` issuer routes), with an
  end-to-end test over a real socket on a multi-threaded `tokio` runtime. New
  `tower-e2e` CI job.
- **Upstream:** filed [`ietf-wg-privacypass/draft-arc#68`](https://github.com/ietf-wg-privacypass/draft-arc/issues/68)
  documenting the §10.2 proof-blob discrepancy; [`docs/POST_QUANTUM.md`](./docs/POST_QUANTUM.md)
  scopes a PQ-sound path.
- CI: a dedicated `wasm` job; GitHub Actions bumped to the Node-24 majors.

### Fixed
- An adversarial multi-agent review of the frontier code confirmed 4 issues
  (the tower middleware's tower-contract handling and the durable-store test were
  cleared): (1) `PresentationState::present` returned via `.expect()` on the
  `m1 + nonce` inversion — a JS-reachable panic (~2⁻²⁵⁶, not attacker-controlled)
  that violated the wasm crate's "no panic on the JS path" contract; now returns
  `ArcError::DegenerateCredential` (regression-tested); (2) a TOCTOU window in
  `FileTagStore::open` (`exists()`-then-open) replaced with open-then-handle-
  `NotFound`; (3) an unhandled `chrome.alarms.create()` promise rejection in the
  extension scaffold now `.catch`-es.

### Known issues
- The ARC §10.2 **proof-blob** test vectors do not reconcile with the pinned
  reference (upstream skew); the proof layer is proven against the Sigma vectors
  instead and the ARC-blob tests are `#[ignore]`d. See
  [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md).
- Not third-party audited; best-effort (not audited) constant-time; IETF drafts
  may change.
