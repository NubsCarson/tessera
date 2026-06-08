# Tessera — phase/component status (single source of truth)

> One authoritative table of every major component, its real status, and where
> it lives. The point is that status lives in **one** place that can't drift.
> When a doc disagrees with this table, this table is the reconciliation; the
> known divergences are listed under "Reconciliations" at the end.
>
> Honest posture (unchanged across the repo): Tessera is a **research-grade,
> UNAUDITED** ARC trust-layer + access-loop. It is *complete and CI-green as a
> protocol artifact*, **not** a deployed network. The contribution is the
> *composition + candor*, not a new primitive. ETH paths are **testnet-only**.
> PoW issuance is a **cost knob, not Sybil resistance**. Three hand-offs are
> irreducibly external (clean egress IP at scale, a Tor/Nym anonymity crowd, a
> third-party audit) and are **never faked**.

## Status legend

- **✅ built + tested** — code exists, is exercised by tests, and rides the host
  CI gates (`cargo test` / clippy `-D warnings` / fmt / `cargo doc -D warnings` /
  MSRV-1.74). The default-path components.
- **🔧 optional-advanced** — fully built, tested, and CI-green, but demoted off
  the recommended default path per [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md)
  (the heavier ZK-channel tier). Kept, not deleted.
- **🧩 built, excluded workspace** — built and tested, but kept *out* of the host
  workspace so its special/heavy deps can't perturb the MSRV/clippy/doc gates;
  has its own dedicated CI job (`Cargo.toml` `exclude = [...]`).
- **🔒 external** — a hand-off that cannot be done inside this repo (operational
  or third-party). Documented, never simulated.

## The table

| # | Component / phase | Status | Where it lives |
|---|---|---|---|
| 1 | **ARC credential core** — P-256 group, issuance/presentation arithmetic, Sigma + Fiat-Shamir proofs (SHAKE128 duplex), full `Issue`/`Present`/`Verify` API, range proof, wire codec | ✅ built + tested (proven byte-exact against IETF Sigma vectors; ARC-blob vectors `#[ignore]`d pending upstream — see note †) | `crates/tessera-arc/src/{group,arc,sigma,proofs,wire,keys}.rs`; tests `test_vectors.rs`, `sigma_vectors.rs`, `roundtrip.rs`, `robustness.rs`, `proof_vectors.rs`, `wire.rs` |
| 2 | **Issuance — PoW gate (default)** — hashcash challenge/solve/verify + one-time `ChallengeStore`, served over the wire | ✅ built + tested (cost knob, **not** Sybil resistance) | `crates/tessera-issuer/src/{lib,net}.rs`; tests `tests/pow.rs` |
| 3 | **Issuance — paid mint (ETH, opt-in)** — buyer proves address via `ecrecover` over an issuer-bound challenge; issuer reads live `entitled(buyer)` via a std-only `eth_call`; durable ledger; refundable + double-issue guard | ✅ built + tested vs a real local **anvil** (testnet-only, UNAUDITED) | wire server `crates/tessera-issuer/src/net.rs` (`serve_issuance_paid`); on-chain plumbing `crates/tessera-issuer/src/mint.rs` (`ecrecover` proof-of-control `recover_buyer`/`sign_control`, std-only `eth_call`, `EntitlementSource`, `RedemptionLedger`, `PaymentGate`); client `obtain_credential_paid` in `crates/tessera-client/src/net.rs`; contract `contracts/src/TokenMint.sol`; tests `crates/tessera-issuer/tests/anvil_entitled.rs`, `contracts/test/TokenMint.t.sol` |
| 4 | **2-hop split-trust loop** — relay (hop 1) learns {client, exit} but never the destination; exit learns {destination + valid-token} but never the client; neither sees content (E2E TLS) | ✅ built + tested (default path; ARC-token mode) | `crates/tessera-relay/src/{lib,channel}.rs`; tests `loop.rs`, `network.rs`, `channel_loop.rs`, `cross_epoch.rs` |
| 5 | **Client proxy** — obtains a credential, runs a local `CONNECT` proxy, mints a fresh unlinkable presentation per request, auto-reissues when the budget is spent; signed-directory mode selects one exit key domain, enforces signed capacity/key-epoch policy, and pins its issuer key before issuance | ✅ built + tested (4-process run to a real HTTPS site → 200; binary config tests cover signed directory accept/reject/rollback/key-epoch policy) | `crates/tessera-client/src/{lib,net}.rs`; bin `crates/tessera-relay/src/bin/tessera-client.rs` (`serve_client_proxy`/`CredentialSource`); proven by `crates/tessera-relay/tests/{network,client_config}.rs` |
| 6 | **Credential-gated exit (proxy)** — `CONNECT` forward proxy admitting on the ARC presentation **never the IP**, E2E-TLS, optionally over Tor; per-IP human-volume shaping (M5) | ✅ built + tested | `crates/tessera-proxy/src/{lib,shaping,main}.rs`; tests `tests/proxy.rs` |
| 7 | **Origin guard + tower middleware** — transport-agnostic `OriginGuard` (verify header, enforce limit + double-spend); off-by-default `tower::Layer` (`TesseraLayer`) that short-circuits rejects with `403` | ✅ built + tested (guard in host gates; `tower` feature unit-tested) | `crates/tessera-origin/src/{lib,store,tower_layer}.rs`; tests `guard.rs`, `store.rs`, `tower_layer.rs` |
| 8 | **Pluggable / durable tag store** — `SpentTagStore` trait + `OriginGuard::with_store`; `InMemoryTagStore` (default), durable `FileTagStore`; injection point for a distributed backend | ✅ built + tested (double-spend survives a guard restart; **concrete distributed impl left to the deployer**) | `crates/tessera-origin/src/store.rs`; tests `crates/tessera-origin/tests/store.rs` |
| 9 | **Per-exit key domains + signed directory selection** — convergent single-winner bootstrap so issuer (mints) + one exit (verifies) share one ARC key via `TESSERA_KEY_FILE`; proxy fails closed on a second local exit reaching the same established key-file inode; optional durable spent-tag file for restart safety; `tessera-directory` CLI keygen/snapshot/sign/verify/select; client verifies threshold-signed exit-directory snapshots, rejects sequence/key-epoch rollback, enforces signed capacity, and pins the selected entry's full issuer key | ✅ built + tested (live directory publication/replication remains external deployment work) | `crates/tessera-issuer/src/keyfile.rs` (`ensure_shared_key`); `crates/tessera-proxy/src/main.rs` (`KeyDomainLease`, `TESSERA_SPENT_TAG_FILE`); `crates/tessera-directory/src/{lib,main}.rs`; `crates/tessera-directory/tests/cli.rs`; `crates/tessera-relay/tests/{client_config,network}.rs`; docs [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md), [`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §3 |
| 10 | **Tor binding** — expose the loop/origin as an onion service; client connects over a real Tor circuit (SOCKS5); admitted purely on the credential | ✅ built (onion always created; live rendezvous needs host Tor egress — credential check is byte-identical on either transport) | `crates/tessera-demo/src/tor.rs`; `--tor` flag; env-gated `TESSERA_TOR_E2E` integration test |
| 11 | **Channel tier — ZK Spilman channel** — unidirectional, monotone-decrementing, single-payee off-chain state machine; user-signed states (attributable equivocation), sign-then-serve co-sign, HOPR-style proof-of-relay, watchtower, off-chain settlement; secp256k1+keccak chain-facing sigs | 🔧 optional-advanced (built + tested; off the default path per `ARCHITECTURE.md`) | `crates/tessera-channel/src/{channel,state,relay,watchtower,settlement,crypto,poseidon}.rs`; tests `protocol.rs`, `settlement_props.rs`, `watchtower.rs`, `no_mint.rs`, `eth_vector.rs` |
| 12 | **ZK / on-chain court** — EVM `ChannelRegistry.sol` (open/close/dispute/slash/refund + relayer bond) + Groth16 `R_dec` settlement (`RDecVerifier.sol`); Circom/snarkjs circuit | 🔧 optional-advanced (built + tested incl. a Rust→Solidity cross-language vector + a pinned on-chain proof; **verifier built under a TEST-ONLY single-party dev ceremony — a multi-party MPC ceremony is required before any real value**, see ‡) | `contracts/src/{ChannelRegistry,RDecVerifier}.sol`; `circuits/R_dec.circom`; tests `contracts/test/{ChannelRegistry,CourtInvariant,RDecVerifier,Reentrancy,CrossLanguageVector}.t.sol`; settlement model `crates/tessera-channel/src/settlement.rs` |
| 13 | **TEE deploy path (dstack / Intel TDX)** — verifiable non-logging relay; Docker network compose (issuer+relay+exit+client) + a TEE compose; key-provider interface parses `ephemeral|file|dstack-kms` | 🔧 optional / partial — Docker network is built + E2E-tested; the TEE compose wires the exit to `dstack-kms`; `dstack-kms` is **implemented** (std-only guest-agent `GetKey` client; fail-closed off-TEE; proven against a mock + the dstack simulator, **not** real TDX hardware) | `deploy/docker-compose.yaml`, `deploy/dstack/docker-compose.yaml`, `Dockerfile`; `crates/tessera-issuer/src/{key_provider,dstack_kms}.rs`; docs [`docs/DEPLOY.md`](./DEPLOY.md) §2, [`docs/DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §3 |
| 14 | **WASM browser client** — `tessera-arc`+`tessera-client` built for `wasm32-unknown-unknown`; `wasm-bindgen` API (`present()`, `prepare_issuance`/`IssuanceFlow`); MV3 extension scaffold | 🧩 built, excluded workspace (compiles + headless round-trip tests pass incl. real issuance against a live Rust origin; **loading the extension in a real browser is the human last mile**) | `crates/tessera-wasm/src/lib.rs`; tests **4 `#[wasm_bindgen_test]`** (`wasm_roundtrip.rs`, the headless-`node` round-trip) + **2 native `#[test]`** (`native_roundtrip.rs`); `examples/node-real-issuance.cjs`, MV3 `background.js` |
| 15 | **Tower e2e server** — runnable `axum` server using `TesseraLayer` on a multi-thread `tokio` runtime, driven over a real TCP socket (403/200/replay-403) | 🧩 built, excluded workspace (its own `tower-e2e` CI job; `axum`/`tokio` kept out of the host MSRV gate) | `crates/tessera-tower-demo/src/main.rs`; test `crates/tessera-tower-demo/tests/e2e.rs` |
| 16 | **Edge / Cloudflare Worker deploy** | 🔒 external — documented **sketch only**, not a compiled artifact (needs the server secret at the edge + a wasm guard build + a shared cross-isolate `SpentTagStore`) | sketch in `crates/tessera-origin` README; [`docs/ROADMAP.md`](./ROADMAP.md) track 2 |
| 17 | **Clean onion egress lane** — exit target/SSRF policy (secure-by-default port allowlist + private/loopback/link-local/CGNAT/metadata refusal for v4+v6 + resolve-then-pin, run *before* the credential) + per-tunnel caps; pluggable `transport::Dialer` seam; client→exit single-hop `.onion` route (relay bypassed; exit's peer is the Tor circuit, never the client IP; cold-start retry; **Tor-native fail-loud** when Tor is down, clearnet only via the explicit `TESSERA_ALLOW_CLEARNET_FALLBACK` opt-out); signed directory **v2** onion/`clean_egress` advertisement + `require_onion`/`require_clean_egress` selection | ✅ built + tested (proven live: the real exit `403`s metadata/private/disallowed-port targets — incl. with **no** credential, i.e. cheap-before-credential — and `200`s a public `:443`; onion lane e2e against an in-process SOCKS5-as-Tor stub). **A genuinely clean egress IP + a real Tor/Nym crowd remain external (row 19).** | `crates/tessera-proxy/src/{policy,transport}.rs`, `crates/tessera-relay/src/{lib.rs, bin/tessera-client.rs}`, `crates/tessera-directory/src/lib.rs`; [`CLEAN_ONION_EGRESS.md`](./CLEAN_ONION_EGRESS.md) |
| 18 | **Unblockable bridge entry** — reach the network from a censored environment via Tor's own pluggable transports / bridges (obfs4 / Snowflake / WebTunnel) configured *in front of* the private pipe; `TESSERA_PT` + `TESSERA_BRIDGE_LINES`; PT-binary preflight fails loud; client diagnoses "Tor blocked" vs "Tor down"; the torrc generator is `tor --verify-config`-validated | ✅ built + tested (`tessera-client::torrc` unit tests + tor-verify; gated `TESSERA_PT_E2E=1` ran the real obfs4 → Tor → `.onion` path green via `scripts/demo-bridge-entry.sh`). Reused from Tor — no new circumvention crypto. **A real censor-unknown bridge population + users + the perpetual arms race remain external (row 19).** | `crates/tessera-client/src/torrc.rs`, `crates/tessera-relay/src/bin/tessera-client.rs`, `scripts/{run-onion-client,demo-bridge-entry}.sh`, `crates/tessera-relay/tests/bridge_entry.rs`; [`CENSORSHIP_RESISTANCE.md`](./CENSORSHIP_RESISTANCE.md) |
| 19 | **Deployed clean-IP exits + live replicated directory operation + a real Tor/Nym anonymity crowd + a real censor-unknown bridge population + third-party audit + multi-party MPC ceremony** | 🔒 external / future product — never simulated; the gaps between the runnable artifact and a stranger safely using it | tracked in [`docs/CEILING_PROGRESS.md`](./CEILING_PROGRESS.md) (E1–E16), [`NEXT_STEPS.md`](./NEXT_STEPS.md), and [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md) |

## Verification (counts, re-measured for this doc)

- **Rust:** 253 `#[test]` markers across the **host-workspace** crates (plus
  ignored upstream-vector checks; run the suite for the exact pass count — the
  last full `cargo test --workspace --all-features` run was 255 passing, 0
  failed). The
  excluded crates run in their own CI jobs: `tessera-tower-demo` (1 e2e test)
  and `tessera-wasm` (4 `#[wasm_bindgen_test]` + 2 native `#[test]`).
- **Foundry:** ~78 test/invariant/fuzz functions across the seven
  `contracts/test/*.t.sol` suites (ChannelRegistry, CourtAdversarial,
  CourtInvariant, CrossLanguageVector, RDecVerifier, Reentrancy, TokenMint);
  run `forge test` for the exact figure.
- **Fuzz:** 7 `cargo-fuzz` targets (`fuzz/fuzz_targets/`): `arc_lifecycle`, `channel_wire`, `wire_from_bytes`, the scalar/element deserializers (`deserialize_scalar`/`deserialize_element`), `presentation_verify`, and `origin_guard_check`.
- **CI gates (host):** `cargo test`, `cargo clippy --all-targets --all-features
  --locked -- -D warnings`, `cargo fmt --check`, `cargo doc --workspace`
  (`-D warnings`). All 9 library crates carry `#![deny(missing_docs)]`; the 8
  host-workspace libraries ride that host `cargo doc --workspace` gate, while the
  9th (`tessera-wasm`, an excluded crate) is doc/clippy-gated in its own wasm CI
  job. Plus MSRV 1.74, `cargo deny`, `cargo audit` (RustSec advisories), a
  fuzz-build + 30s/target smoke job, `cargo-llvm-cov` (library surface gated
  ≥80%, measured 91.46% line), and Slither on the production contracts (0 High /
  0 Medium).

## Reconciliations (where the other docs need reading-in-this-light)

- **Test counts.** [`docs/CEILING_PROGRESS.md`](./CEILING_PROGRESS.md)'s snapshot
  tracks current approximate aggregates. Treat them as moving markers, not pins
  — per `CLAUDE.md`/`AGENTS.md`, run the suite rather than trusting any stated
  count. The current Rust marker count is 253 host-workspace `#[test]` markers,
  plus the excluded-crate tests gated separately: `tessera-wasm` (2 native
  `#[test]` in `native_roundtrip.rs` + 4 `#[wasm_bindgen_test]` headless-node
  tests) and `tessera-tower-demo` (1 e2e test). Foundry (78, across
  the seven `contracts/test/*.t.sol` suites) and fuzz (7 targets) match what
  CEILING reports. So measured the same way, the docs agree.
- **TEE status nuance.** README §"Run it yourself" presents the dstack TEE as the
  verifiable-relay deploy; [`docs/DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md)
  §3 is the precise statement and governs: the TEE compose wires **only relay +
  exit**. The key-provider interface exists, but `dstack-kms` intentionally fails
  closed until a real KMS client is wired (row 13 reflects this — *partial*, not
  a turnkey full-network TEE deploy).
- **"Done" vs "external."** [`GOAL.md`](../GOAL.md) marks all 10 v0 milestones
  complete and [`docs/ROADMAP.md`](./ROADMAP.md) marks all 4 frontier tracks
  done. That is consistent with this table: "done" means the **buildable-here**
  artifact is complete and proven; rows 16–17 are the `🔒 external` hand-offs that
  "done" was always explicitly scoped to exclude (clean IP, anonymity crowd,
  audit, MPC ceremony).

---

† **ARC proof-blob vectors.** The proof layer is proven byte-exact against the
authoritative IETF **Sigma Protocol** vectors (same machinery); the ARC §10.2
*proof-blob* vectors are `#[ignore]`d because the committed blobs do not
reconcile with the pinned reference's Fiat-Shamir wiring (an upstream skew, not a
Tessera bug). Full write-up: [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md);
filed upstream as [`draft-arc#68`](https://github.com/ietf-wg-privacypass/draft-arc/issues/68).

‡ **R_dec verifier ceremony.** `contracts/src/RDecVerifier.sol` is generated from
a **TEST-ONLY single-party dev** powers-of-tau + Groth16 phase-2 ceremony
(`circuits/build.sh`, `circuits/README.md`). A real multi-party MPC ceremony is a
hard prerequisite before this path carries any real value — it is one of the
`🔒 external` hand-offs (CEILING E2), not a thing built here.
