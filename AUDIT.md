# Tessera — Audit-Prep Packet

> The map an auditor reads first. It states what Tessera is, the trust model it
> lives in, the component inventory, the exact commands to build and reproduce
> every gate, what is and is not in scope for a review, and the known issues —
> named bluntly, not buried. It does not soften anything in
> [`README.md`](./README.md), [`GOAL.md`](./GOAL.md),
> [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md),
> [`docs/ABUSE_MODEL.md`](./docs/ABUSE_MODEL.md), or
> [`docs/SECURITY_ARGUMENT.md`](./docs/SECURITY_ARGUMENT.md); where it summarizes
> them it links back.
>
> **Status: research-grade, UNAUDITED.** No third-party review has occurred. This
> document is an *input to* an audit, not evidence of one. Do not use Tessera to
> protect real users or funds. Specs tracked are IETF **drafts** (`-01`) and may
> change.

## 1. What Tessera is (in three sentences)

Tessera is a from-scratch implementation of **Anonymous Rate-Limited Credentials
(ARC)** over NIST P-256 — proven byte-for-byte against the IETF arithmetic test
vectors — plus the tooling around it: a server-side guard, a credential-gated
`CONNECT` proxy, a networked issuer, a 2-hop split-trust relay loop, an ETH-paid
token-mint rail, and an optional-advanced ZK payment-channel tier with an EVM
court. Its single idea is to **admit a web request on an unlinkable, rate-limited
credential it can prove, never on its IP address**, so a cooperating origin can
safely accept anonymous (e.g. Tor) traffic without IP reputation. It is a tested
protocol artifact and a runnable tool — **not** a deployed, anonymous network a
stranger can use, and **not** audited; ~85% of the construction is prior art, and
the contribution is the composition plus the candor about its limits.

## 2. The trust model — keyed-verification (KVAC)

ARC is a **keyed-verification anonymous credential (KVAC)** scheme built from an
algebraic MAC (MACGGM). This single fact shapes the entire threat model, so read
it before anything else (full treatment: [`THREAT_MODEL.md`](./docs/THREAT_MODEL.md)
§1, [`SECURITY_ARGUMENT.md`](./docs/SECURITY_ARGUMENT.md) §Model).

- **The issuer and the verifier are the same party (or share one secret key).**
  Verification needs the server's *private* key, not just a public key. In code:
  the server secret is `(x0, x1, x2, x0Blinding)` (`tessera-arc/src/keys.rs`,
  `ServerPrivateKey`); issuance computes the MAC with those secrets
  (`arc.rs::create_credential_response`); and verification recomputes
  `V = x0·U + x1·m1Commit + x2·m2·U − UPrimeCommit` directly from
  `private_key.x0/x1/x2` (`proofs.rs::verify_presentation_proof`). A holder of
  only the public key **cannot** verify a presentation.
- **Consequence: there is no third party who can independently verify a
  credential.** This is the deliberate ARC trade-off versus pairing-based,
  publicly-verifiable schemes (smaller credential, no pairings, at the cost of
  public verifiability).
- **The "cooperating origin" model.** Tessera changes the trust calculus *only*
  for sites that choose to run `OriginGuard` and hold the keys. It cannot force a
  non-cooperating site (Google, Cloudflare) to accept anything, and it does not
  disguise Tor traffic as non-Tor. The win is local and voluntary: a cooperating
  origin gets a cryptographic, rate-limitable, unlinkable proof of "a budgeted,
  validly-issued client" that is strictly more informative than an IP, so it has
  no reason to block anonymity.
- **The guard never reads the source IP.** `OriginGuard::check` is documented at
  `tessera-origin/src/lib.rs:162` — "Source IP is deliberately not an input." The
  admission decision rests entirely on the presentation.

What ARC provides, within the **classical** discrete-log model: (a) credential
unforgeability, (b) issuance unlinkability, (c) per-context presentation
unlinkability, (d) rate limiting via a deterministic tag + double-spend store.
The tag is the one intentionally-linkable element — it links *iff* the same nonce
slot is reused in the same `presentationContext`, which is exactly the
rate-limiting primitive and nothing more.

## 3. Component / crate inventory

A Cargo workspace of **eight members** (`Cargo.toml`) plus **three excluded,
self-contained workspaces** (`fuzz/`, `crates/tessera-wasm`,
`crates/tessera-tower-demo`) each kept out of the host gates so its heavy/special
deps can't perturb the MSRV-1.74 / clippy / test build, and each with its own CI
job. The on-chain rails live in `contracts/` (a Foundry project, not a Cargo
crate) and the ZK circuit in `circuits/`. Sizes are source LOC, rounded, as a
review-surface gauge.

### Workspace members (the host gate)

| Crate | Role | ~src LOC | ~test LOC |
|---|---|---|---|
| `tessera-arc` | **The cryptographic core.** ARC over P-256: group/hash-to-curve (`group.rs`), keys (`keys.rs`), issuance/presentation arithmetic + tag + `TagStore` (`arc.rs`), the range proof + presentation statement (`proofs.rs`), the SHAKE128 Fiat-Shamir / Sigma linear-relation prover+verifier (`sigma.rs`), and canonical wire codec (`wire.rs`). Vector-proven. | 1828 | 907 |
| `tessera-channel` | **(optional-advanced)** The ZK Spilman payment-channel state machine: user-signed monotone-decrement states (`state.rs`, `channel.rs`), HOPR-style proof-of-relay (`relay.rs`), watchtower (`watchtower.rs`), off-chain settlement (`settlement.rs`), Poseidon commitment (`poseidon.rs`), and secp256k1+keccak `ecrecover`-verifiable chain-facing sigs (`crypto.rs`). | 1799 | 1414 |
| `tessera-relay` | The first onion hop forming the **2-hop split-trust loop** (`lib.rs`); learns `{client, exit}`, never the destination/content. Default is ARC-token mode; an optional channel-payment mode lives in `channel.rs`. Also builds the runnable local **`tessera-client` proxy binary** (`src/bin/tessera-client.rs`). | 1488 | 1352 |
| `tessera-issuer` | The credential **authority**. PoW issuance gate + networked issuance over the wire (`net.rs`, `serve_issuance`) + an optional ETH-paid on-chain mint (`mint.rs`, `serve_issuance_paid`: `ecrecover`-proven, std-only `eth_call`, durable ledger) + the shared-key file logic (`keyfile.rs`) + the node binary (`main.rs`). | 1307 | 234 |
| `tessera-demo` | The runnable narrated end-to-end demo: CLI, a `--serve` browser hub, and a `--tor` onion-service path. An application, not a library. | 965 | — |
| `tessera-proxy` | The credential-gated **`CONNECT` proxy** (the exit): IP-blind, TLS-end-to-end access to any HTTPS site, optionally over Tor (`lib.rs`, `main.rs`), with per-egress-IP human-volume shaping (`shaping.rs`). | 891 | 110 |
| `tessera-origin` | The server-side `OriginGuard` (`lib.rs`): admit on a valid, in-budget, unspent presentation, never on the IP. Pluggable `SpentTagStore` + durable `FileTagStore` (`store.rs`); optional `tower` middleware `TesseraLayer` (`tower_layer.rs`). | 523 | 456 |
| `tessera-client` | Holds a credential and mints one fresh, unlinkable presentation per request; obtains a credential over the wire (`obtain_credential` / `obtain_credential_paid`). | 264 | — |

### Excluded workspaces (own CI jobs)

| Crate | Role | ~src LOC | ~test LOC |
|---|---|---|---|
| `tessera-wasm` | `wasm-bindgen` browser bindings: real `prepare_issuance` + `present()`, compiles to `wasm32`, headless node tests pass, interop-verified against the Rust origin. Ships an MV3 extension scaffold (loading it in a real browser is the human final mile). | 245 | 134 |
| `tessera-tower-demo` | A runnable `axum` server using the `tessera-origin` `tower` middleware; its e2e test drives a real server on a multi-threaded `tokio` runtime over a real socket. | 108 | 95 |
| `fuzz` | The nightly `cargo-fuzz` targets (6, see §6). | — | — |

> The `~test LOC` column counts **separate test-file** LOC. `tessera-demo` and
> `tessera-client` show `—` because their only tests live inline in `src/`
> (counted in `~src LOC`): `tessera-demo` has one `#[test]` in `src/tor.rs:200`
> (the opt-in live-Tor e2e), and `tessera-client` has none. The per-crate
> function counts are in §6.
>
> No crate is published to crates.io — every crate is `publish = false` pending a
> third-party audit. This is gated; do not publish without the maintainer's OK.

## 4. On-chain contracts (`contracts/`)

A self-contained **Foundry** project, deliberately **dependency-free**: no
`lib/`, no `forge install`, no submodules — the test harness is vendored in
`test/Std.sol`, so `forge build` / `forge test` run fully offline. Pinned to
`solc 0.8.24` (`foundry.toml`). **Testnet-only, UNAUDITED.**

| Contract | Role | ~LOC |
|---|---|---|
| `src/TokenMint.sol` | **The leaner default rail.** ETH-paid mint: a buyer `purchase()`s an entitlement to N tokens; the off-chain ARC issuer blind-issues them and `redeem`s to consume the entitlement. The purchase links `buyer → "obtained N tokens"`, but the credentials are blind-issued, so later *presentations* are unlinkable to the purchase. CEI throughout; no external dependency. | 113 |
| `src/ChannelRegistry.sol` | **(optional-advanced)** The EVM **court** for the ZK Spilman channel: escrow / cooperative-close / unilateral-close dispute window at the highest doubly-signed state / equivocation slash / timeout refund, plus a relayer bond and a ZK (`R_dec` Groth16) settlement path. Verifies states via `ecrecover` over the same recoverable secp256k1 sigs `tessera-channel` produces. | 717 |
| `src/RDecVerifier.sol` | The Groth16 verifier for the `R_dec` decrement circuit, **generated** by `snarkjs zkey export solidityverifier` (from `circuits/R_dec.circom`) under a **TEST-ONLY single-party dev ceremony**. Do not hand-edit; a production deploy needs the multi-party MPC ceremony (`circuits/README.md`). | 194 |

Cross-language proofs run in CI **without** external tooling: `CrossLanguageVector.t.sol`
pins a real Rust-signed channel state and verifies it through the contract's
`ecrecover` path; `RDecVerifier.t.sol` pins a real `R_dec` Groth16 proof (built
locally by `circuits/build.sh` via circom+snarkjs) and verifies it on-chain via
the committed verifier — CI needs no circom/snarkjs, only the committed verifier
plus the pinned proof vector.

## 5. Build, run, and reproduce every gate

Requires a stable Rust toolchain, **MSRV 1.74** (`rust-toolchain.toml` selects
stable). The commands below are exactly what CI (`.github/workflows/ci.yml`)
runs.

### Host workspace gate (CI job `test`)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked   # IETF KATs + robustness live here
cargo bench --workspace --no-run --locked        # benches must compile
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

### The single most load-bearing test — the IETF arithmetic vectors

```sh
cargo test -p tessera-arc --test test_vectors    # 8/8: the byte-for-byte ARC oracle
```

### MSRV (CI job `msrv`)

```sh
rustup toolchain install 1.74.0 --profile minimal
cargo +1.74.0 build --workspace --all-features --locked
```

### Supply chain (CI jobs `audit`, `deny`)

```sh
cargo audit                                      # RustSec advisories (also daily cron)
cargo install cargo-deny --version 0.19.8 --locked
cargo deny check                                 # advisories + licenses + sources + bans; policy in deny.toml
```

### Coverage (CI job `coverage`)

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --all-features \
  --ignore-filename-regex '(main\.rs|tessera-demo)' \
  --fail-under-lines 80 --summary-only           # library surface gated ≥80% (measured ~91%)
```

### Fuzz (CI job `fuzz`; nightly)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz build                        # builds all 6 targets
for t in $(cargo +nightly fuzz list); do
  cargo +nightly fuzz run "$t" -- -max_total_time=30 -detect_leaks=0
done
# or one target directly:
cargo +nightly fuzz run wire_from_bytes -- -max_total_time=30
```

### Excluded workspaces (own CI jobs `wasm`, `tower-e2e`)

```sh
# wasm — wasm32 build + headless wasm-bindgen test (pin wasm-bindgen-cli == the crate version, 0.2.122)
cargo build --manifest-path crates/tessera-wasm/Cargo.toml --target wasm32-unknown-unknown --release
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --manifest-path crates/tessera-wasm/Cargo.toml --target wasm32-unknown-unknown
cargo test --manifest-path crates/tessera-wasm/Cargo.toml          # native fallback of identical logic

# tower middleware e2e (real axum server over a real socket)
cargo test --manifest-path crates/tessera-tower-demo/Cargo.toml
```

### Contracts (CI jobs `contracts`, `slither`)

```sh
cd contracts && forge build && forge test -vv    # incl. the Rust->Solidity vector + pinned R_dec ZK proof
# static analysis (gated on High/Medium; verified 0 High / 0 Medium):
slither . --filter-paths "test/"
```

### Run it

```sh
cargo run -p tessera-demo                         # narrated end-to-end demo
cargo run -p tessera-demo -- --serve              # browser hub at http://127.0.0.1:8088
cargo run -p tessera-demo -- --tor                # also drive a real Tor onion circuit
cargo run -p tessera-proxy                        # credential-gated CONNECT proxy
docker compose -f deploy/docker-compose.yaml up --build   # the whole network (issuer+relay+exit+client)
```

> The Tor end-to-end test is opt-in via `TESSERA_TOR_E2E` (graceful skip without
> host Tor egress); the paid-issuance anvil test
> (`tessera-issuer/tests/anvil_entitled.rs`) is opt-in and needs a local anvil.

## 6. Test / fuzz / CI coverage map

Verification, per [`CEILING_PROGRESS.md`](./docs/CEILING_PROGRESS.md): **~162 Rust
test functions + 78 Foundry tests + 7 fuzz targets**, all green; CI green on
`main`. (A `#[test]` / `#[tokio::test]` / `#[wasm_bindgen_test]` grep across
`crates/` + `fuzz/` counts 162; `contracts/test/*.sol` declares 78
`test*`/`testFuzz*`/`invariant_*` functions. Reproduce both with the commands in
§"Build & reproduce" below.)

### CI jobs (`.github/workflows/ci.yml`)

`test` (fmt + clippy `-D warnings` + `cargo test --workspace --all-features` +
benches-compile + doc `-D warnings`) · `msrv` (build on 1.74.0) · `audit`
(cargo-audit, also daily cron) · `deny` (cargo-deny, pinned) · `coverage`
(llvm-cov, library surface gated ≥80%) · `wasm` (wasm32 build + headless test) ·
`tower-e2e` (real axum server) · `contracts` (forge build + test, incl. the
cross-language vector + pinned ZK proof) · `slither` (Solidity static analysis,
fail on High/Medium) · `fuzz` (build all targets + 30s smoke each).

### Rust test surface by crate

| Crate | Notable suites | Approx tests |
|---|---|---|
| `tessera-arc` | `test_vectors.rs` (8 IETF KATs), `sigma_vectors.rs` (2: official `discrete_logarithm` + `dleq`), `roundtrip.rs` (10: issue/present/verify, over-limit, tamper, wrong-context, double-spend), `wire.rs` (5), `robustness.rs` (3, no-panic), `proof_vectors.rs` (5, incl. `#[ignore]`d ARC-blob KATs) | 33 |
| `tessera-channel` | `protocol.rs`, `settlement_props.rs` (property-based, S4), `watchtower.rs`, `eth_vector.rs` (Rust↔Solidity sig vector), `no_mint.rs` ("decrement cannot mint", M7) | 38 |
| `tessera-relay` | `network.rs` (all four nodes in-process: obtain→200→auto-reissue→pin-mismatch reject), `loop.rs`, `channel_loop.rs`, `cross_epoch.rs` (S2) | 23 |
| `tessera-issuer` | `pow.rs` (PoW gate), `anvil_entitled.rs` (paid mode vs real anvil, opt-in) | 16 |
| `tessera-origin` | `guard.rs` (admit/missing/malformed/replay/wrong-context), `store.rs` (double-spend survives restart), `tower_layer.rs` | 15 |
| `tessera-proxy` | `proxy.rs` (admit/reject + shaping flood) | 9 |
| `tessera-wasm` | `wasm_roundtrip.rs`, `native_roundtrip.rs` | 6 (2 native + 4 wasm-bindgen) |
| `tessera-tower-demo` | `e2e.rs` (real socket: admit/malformed/replay/fresh) | 1 (the e2e) |
| `tessera-demo` | `tor.rs` (opt-in live-Tor transport-agnosticism e2e) | 1 (opt-in) |

### Fuzz targets (`fuzz/fuzz_targets/`, libfuzzer)

`deserialize_element` · `deserialize_scalar` · `wire_from_bytes` (the ARC wire
codec) · `presentation_verify` (full `Presentation::from_bytes` + range-sum +
`sigma::verify`; must never panic and never verify random bytes) ·
`origin_guard_check` (the guard) · `channel_wire` (relay/channel header
decoders, S6). All deserializers and the guard are total — they return `Result`
and never panic; the fuzzer previously found and fixed a real `limit < 2` panic
(`GOAL.md` milestone 10).

### Foundry test surface (`contracts/test/`)

`ChannelRegistry.t.sol` (court lifecycle) · `CourtInvariant.t.sol` (invariant +
128k-call interaction-matrix fuzz, S5) · `Reentrancy.t.sol` ·
`CrossLanguageVector.t.sol` (real Rust-signed state via `ecrecover`) ·
`RDecVerifier.t.sol` (pinned real Groth16 proof + malformed-proof negatives, S7) ·
`TokenMint.t.sol`.

## 7. Audit scope — in and out

### In scope (the protocol logic on top of audited primitives)

This is the unreviewed surface and the reason an audit is needed. The
cryptographic primitives come from the audited
[RustCrypto](https://github.com/RustCrypto) project (`p256`, `k256`,
`elliptic-curve`, `sha2`, `sha3`); **the protocol logic on top is what still
needs review.** Priority order (see `SECURITY_ARGUMENT.md` §"For an auditor"):

1. **`tessera-arc`** — the whole core. Specifically:
   `proofs.rs::verify_presentation_proof` (the private-key `V` recomputation that
   binds the MAC; the range-sum + per-bit `{0,1}` constraints);
   `sigma.rs` (special-soundness of the linear-relation verifier; the exact
   SHAKE128 Fiat-Shamir transcript); `arc.rs::present` + `TagStore` (tag
   determinism + double-spend); every `from_bytes`/`deserialize_*` (panic-safety);
   all secret-dependent code paths (constant-time — esp. the `subtle`-hardened
   range-proof bit decomposition in `proofs.rs::prove_presentation`).
2. **`tessera-origin`** — admission logic, the `SpentTagStore`/`FileTagStore`
   durability and atomicity, the `tower` layer.
3. **`tessera-issuer`** — the PoW gate, the networked issuance accept-before-cost
   bounds, and the **paid mint** (`mint.rs`: `ecrecover` control-proof, the
   std-only `eth_call`, the durable double-issue ledger, issuer-pk pinning).
4. **`tessera-relay` / `tessera-proxy`** — the split-trust loop, the
   accept-and-parse DoS bounds (`ABUSE_MODEL.md` vectors 1–5), volume shaping.
5. **Contracts** (`TokenMint.sol`, and for the advanced tier `ChannelRegistry.sol`
   + the generated `RDecVerifier.sol`) — testnet-only; the `ecrecover` and ZK
   settlement paths, CEI, the court's dispute/slash/refund logic.
6. **`tessera-channel`** (optional-advanced tier) — the channel state machine and
   off-chain settlement; lower priority than the default token path.

### Out of scope (won't be fixed by reviewing this code)

- **RustCrypto primitives themselves** — relied upon as audited.
- **The KVAC / ARC / Σ-protocol theorems** — implemented faithfully, not
  re-proven here; correctness of the *constructions* is assumed from
  [CMZ14]/[Revisiting KVAC] and the IETF drafts (`SECURITY_ARGUMENT.md` §1–§5).
- **Network-level anonymity** — delegated entirely to the transport (Tor/Nym).
  Tessera adds zero IP/timing/volume protection (`THREAT_MODEL.md` §3.3).
- **Forcing non-cooperating sites** — impossible and not claimed.
- **Sybil resistance** — PoW is a cost knob, not strong Sybil resistance; per-human
  guarantees are not provided (§8).
- **Clean residential egress IPs, a Tor/Nym anonymity crowd, the multi-party MPC
  ceremony for `R_dec`** — all structurally external (§8, `CEILING_PROGRESS.md`
  §"Irreducibly external").
- **HTTP/application metadata** — cookies, TLS fingerprints, header ordering,
  request timing/size, the bare fact of contacting a guarded endpoint
  (`THREAT_MODEL.md` §4.5).
- **Post-quantum security** — no claim (§8).

## 8. Known issues & gaps — stated bluntly

These are real and named on purpose. None is hidden.

- **UNAUDITED, research-grade.** No third-party review. Do not protect real users
  or funds. (`README.md` "Security status".)
- **The ARC §10.2 proof-blob vector skew.** The ARC draft's committed
  zero-knowledge *proof* blobs do **not** reproduce byte-for-byte under the
  pinned reference's Fiat-Shamir wiring, while **every arithmetic vector matches
  exactly (8/8** in `tessera-arc/tests/test_vectors.rs`). Assessed as an
  **upstream vector/reference inconsistency** (the Σ POC's challenge squeeze
  churned `+16`→`+32`), independently confirmed because the pinned reference's own
  `verify()` rejects its own committed blob. The proof *machinery* is therefore
  validated against the **authoritative** IETF Σ Protocol vectors
  (`sigma_vectors.rs`), which exercise the identical transcript machinery; the
  ARC-blob KATs are kept `#[ignore]`d and will flip green if upstream regenerates
  them. **Residual: the proof layer is not validated against ARC's own end-to-end
  proof KATs — a documented correctness uncertainty, not a known bug.** This is an
  upstream skew; do not re-investigate it as a Tessera defect. Full reproduction:
  [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md).
- **No post-quantum security.** All assumptions are classical (discrete-log / DDH
  over P-256; ROM for Fiat-Shamir). Shor's algorithm breaks credential
  unforgeability and proof soundness, *and* enables the ARC §7.2 issuance-
  unlinkability partition (an active adversary finds a second `(x0', x0Blinding')`
  committing to the same `X0`). No PQ claim. (`docs/POST_QUANTUM.md`,
  `SECURITY_ARGUMENT.md` §PQ.)
- **PoW ≠ Sybil resistance.** `create_credential_response` issues to *anyone*
  whose request proof verifies; the rate limit is meaningless without an issuance
  gate. `tessera-issuer`'s PoW makes each credential cost ~`2^difficulty` hashes —
  a **cost knob, not strong Sybil resistance**: enough compute still scales and it
  penalizes low-power clients. Per-human guarantees (attestation, one-per-person)
  are future work. The issuance gate is *also* the anonymity-set lever
  (`THREAT_MODEL.md` §4.3, §6.3).
- **Anonymity is only as large as the §7.3 per-context set** `Σ_i p_i[context]`.
  Sparse deployments or per-user `presentationContext`s shrink it toward one —
  the most realistic deanonymization vector and it is **operational, not
  cryptographic** (`THREAT_MODEL.md` §3.4).
- **The tag store is the enforcement boundary, and is in-memory/non-durable as
  shipped.** Both `arc.rs::TagStore` and the guard hold tags in a process
  `HashSet`/`Mutex<HashSet>`; a restart, crash, or second replica re-opens the
  double-spend window. A durable `FileTagStore` exists and is tested across a
  restart, but a *distributed, consistent* store is left to the deployer, and safe
  pruning must be **epoch-scoped**, never wall-clock (dropping live tags re-opens
  the window — `ABUSE_MODEL.md` vector 6, `THREAT_MODEL.md` §6.1).
- **Constant-time is best-effort, not audited.** The one known secret-dependent
  path — the nonce bit decomposition in `proofs.rs::prove_presentation` — is
  branchless via `subtle`; RustCrypto's P-256 ops are constant-time. **But no
  end-to-end CT audit** (every secret op, memory-access patterns, compiler-emitted
  code) has been done (`THREAT_MODEL.md` §5).
- **The issuer sees the client's IP at issuance.** Obtaining a credential is a
  direct client→issuer connection. ARC unlinkability still prevents tying that to
  later browsing, but the *act* of issuance is not hidden unless the client
  reaches the issuer over Tor too (`DEPLOY.md` "Honest limits",
  `THREAT_MODEL.md` §3.5).
- **The three external hand-offs.** A deployed network a stranger can safely use
  needs, beyond this code: (1) a **clean residential egress IP at scale**,
  (2) a **Tor/Nym anonymity crowd** (covering the client→issuer hop too), and
  (3) a **third-party audit**. No code or enclave manufactures these
  (`ARCHITECTURE.md`, `CEILING_PROGRESS.md` §"Irreducibly external" E1/E3/E4).
- **DoS / abuse: code-fixed vs deploy-tier.** Five accept-and-parse vectors are
  bounded in code and tested (thread-spawn cap, socket timeouts, shaper/nonce-set
  caps); four are documented as deploy-tier *with the reason a naive code fix
  backfires* (channel-state-trie growth, tag-store growth, per-write flush,
  proof-verify cost on unauthenticated input) — see
  [`docs/ABUSE_MODEL.md`](./docs/ABUSE_MODEL.md).
- **Draft-tracking.** All three IETF specs are `-01` drafts; the wire format,
  transcript, or properties may change.
- **Channel / ZK / court are an optional-advanced tier, not the default path.**
  They are fully built, tested, and CI-green, but the recommended path is the
  leaner **ARC-token + Tor + shaping** loop (`ARCHITECTURE.md`). The
  `RDecVerifier.sol` ceremony is **TEST-ONLY single-party**; the channel maturity
  is "demoted, kept" — review it at lower priority unless pay-as-you-go-with-refund
  is the target. The contracts are **testnet-only**, never deployed with value.

## 9. Security-property → construction → assumption → gap

The full per-property argument — **claim → construction (`file:line`/function) →
assumption → gap to a machine-checked proof** — is
[`docs/SECURITY_ARGUMENT.md`](./docs/SECURITY_ARGUMENT.md). Use this as the index;
read that document for the reasoning and the explicit stopping points.

| Property | Construction (where) | Rests on | Gap → see |
|---|---|---|---|
| Credential unforgeability | `arc.rs::create_credential_response`; `proofs.rs::verify_presentation_proof` (private-key `V`) | MACGGM EUF-CMVA + Σ soundness; DL | KVAC theorem relied on, not re-proven — §1 |
| Issuance unlinkability | `arc.rs::create_credential_request`; `keys.rs::public_key` (`X0`) | statistically-hiding Pedersen + ROM | quantum-DL `X0` partition — §2 |
| Presentation unlinkability | `arc.rs::PresentationState::present` (re-randomize + `nonceCommit`) | DDH + hiding commitments + ROM | only as large as §7.3 set; quantum — §3 |
| Rate-limit soundness | `proofs.rs::verify_presentation_proof` (range sum + bits); `arc.rs::TagStore` | Σ special-soundness + DL + ROM; durable store | store durability is operational; quantum — §4 |
| Σ / Fiat-Shamir soundness & ZK | `sigma.rs` (`init_transcript`, `verifier_challenge`, `verify`) | ROM + DL | ROM-only, not standard-model; not machine-checked; ARC-blob skew — §5 |

Honest gaps to a formal proof (`SECURITY_ARGUMENT.md` §"Gaps"): no machine-checked
proof (no EasyCrypt/Tamarin/ProVerif); reliance on the KVAC theorems; Fiat-Shamir
is ROM-only; constant-time best-effort not verified; not validated against ARC's
own §10.2 proof-blob KATs; no post-quantum soundness.
