# Tessera — "absolute ceiling" progress tracker

> Living checklist for the completion-audit Definition-of-Done (the 99
> buildable-here items + 27 irreducibly-external). Updated on **every** landed
> item so the state is never lost. Legend: ✅ done · 🔨 in progress · ⬜ pending ·
> 🔒 irreducibly external (never faked).
>
> Honest framing (unchanged): Tessera-here can become a **complete, fully-tested,
> CI-green, audit-ready protocol artifact** — *not* a deployed network. Four
> hand-offs are structurally external (auditor signs · ≥5-human MPC ceremony ·
> clean-IP + Tor/Nym crowd · the forever anti-bot arms race). The contribution is
> the composition + the candor, not a new primitive; the novel open frontier is
> cross-epoch statistical-disclosure budgeting.

## Status snapshot

- **MUST tier: 8/8 ✅** — every correctness/safety/honesty hole the audit found is closed.
- **SHOULD tier: 33/34** — hardening + completeness. The ONLY open item is **S34** (PIR / green-routing / x402 egress lanes) — the irreducibly-external clean-egress frontier, not buildable here.
- **NICE tier: 0/15** — polish; pending.
- **Verification:** 187 host-workspace Rust `#[test]` markers + 78 Foundry
  tests + 7 fuzz targets, all green; CI green on `main`.

## MUST — done

| # | Item | Commit |
|---|------|--------|
| M4 | SECURITY.md scope covers the Phase 2 fund rail | `50af23a` |
| M6 | circuits/README production-ceremony checklist | `50af23a` |
| M1 | Relayer on-chain bond + symmetric equivocation slashing (6-lens red-team, 0 findings) | `34616c7` |
| M3 | `docs/ECONOMICS.md` — prices the bond honestly | `3e49530` |
| M2 | Spilman watchtower (`tessera-channel::watchtower`) | `4fb043a` |
| M7 | Systematic "decrement cannot mint" proof (`no_mint.rs`) | `52b8607` |
| M5 | Per-egress-IP human-volume shaping (`tessera-proxy::shaping`) | `6ac22d0` |
| M8 | Env-gated Tor integration test (transport-agnosticism) | `555c18e` |

## 🚀 v0.1.0 — shipped (first tagged release)

Pre-ship readiness review (26-agent, 5-lens) → all blockers fixed → tagged `v0.1.0`.

| Ship item | Status | Commit |
|---|---|---|
| Blocker: documented verify cmd crashed with Tor installed | ✅ fixed (opt-in `TESSERA_TOR_E2E`, graceful skip) | `ce849db` |
| Blocker: README headline overclaimed | ✅ honest reframe + "What this is / is NOT" + clean-egress caveat | `ce849db` |
| Doc-drift: relay default, forge counts, crate count, TokenMint mention | ✅ | `ce849db`, `1c74c39` |
| Release: bump all crates 0.0.1→0.1.0 + lockfiles + CHANGELOG | ✅ | `048fd45` |
| **Tag `v0.1.0`** | ✅ pushed | — |
| Positioning: honest present tense across docs | ✅ | `ac9b9a3` |

**Ship-polish (post-v0.1.0):**
- ✅ **S27 `#![deny(missing_docs)]`** on all 9 library crates — public API fully
  documented (56 items via an 8-agent pass + stragglers by hand), commit `e1076ef`.
- ✅ **cargo-deny** (supply-chain advisories/licenses/sources/bans) — `deny.toml`
  + a pinned CI job; `cargo deny check` passes locally (the two unmaintained
  arkworks transitive deps are explicitly acknowledged, not hidden).
- ✅ **coverage** (`cargo-llvm-cov`) — CI job reports + gates the **library
  surface at ≥80%** (measured **91.46%** line; bins/demo excluded as apps).
- ✅ **Slither** (Solidity static analysis) — CI job on the production `src/`
  contracts, gated on **High/Medium**; verified **0 High / 0 Medium** locally (the
  remaining results are Low/Informational — naming on the generated verifier, the
  checked-transfer pattern, the deliberate dust-refund math).
- ⬜ remaining (cosmetic only): a `forge fmt --check` gate (would reformat the
  generated verifier — deliberately left matching snarkjs), pinning the
  cargo-audit/cargo-fuzz install versions. None blocks the v0.1.0 promotion.

## Architecture pivot (the leaner ecash-token + Tor path — `docs/ARCHITECTURE.md`)

| Item | Status | Commit |
|---|---|---|
| Decision doc (what we built vs. leaner path, why) | ✅ | `dc56d41` |
| Performance/latency analysis (speed matters; pivot is faster) | ✅ | `f5dc1c2` |
| ETH-paid token mint rail (`TokenMint.sol` + 13 forge tests) | ✅ | (this commit) |
| Leaner-default e2e proof (token + 2-hop loop + M5 shaping, no channel) | ✅ | (this commit) |
| Channel/ZK/court demoted to optional-advanced tier (documented, kept) | ✅ | `dc56d41` |
| Networked issuance (PoW-gated issuer node + over-the-wire credential acquisition) | ✅ | (this commit) — `tessera-issuer::net`, `tessera-client::obtain_credential` |
| **Runnable client UX** (local CONNECT proxy: obtain → present → route → auto-reissue) | ✅ | (this commit) — `tessera-client` bin, proven by `tessera-relay/tests/network.rs` + a 4-process run to a real HTTPS site (200) |
| Single-exit shared-key domain (issuer↔exit ARC key sharing, `TESSERA_KEY_FILE`) | ✅ | (this commit) |
| Multi-exit key-custody decision + single-domain proxy guardrails + signed directory verifier/client selector | ✅ | (this commit) — per-exit key domains, key-domain lease, optional durable spent-tag file, `tessera-directory` CLI, signed capacity/key-epoch policy, `tessera-client` directory mode |
| Containerized **full network** (issuer+relay+exit+client) + dstack TEE deploy path | ✅ | `f462be3` + (this commit); dstack KMS provider is reserved/fail-closed, not a real KMS client |
| Paid mint wired (issuer ⟵ `TokenMint.sol` ETH purchase → issue) | ✅ | (this commit) — `tessera-issuer::mint` (ecrecover proof + std-only `eth_call` read + durable ledger), `serve_issuance_paid`/`obtain_credential_paid`; proven vs real **anvil** (`tests/anvil_entitled.rs`) |
| Deployed **clean-IP** exit + Tor/Nym crowd + live mirrored directory operation + distributed spent tags + audit | 🔒 | external (clean egress is one blocker; stranger-safe deployment also needs the listed network/audit work; local signed directory verification/selection is built) |

## SHOULD — in progress

| # | Item | Status | Commit |
|---|------|--------|--------|
| S4 | Property-based settlement suite | ✅ | `519da9a` |
| S5 | Foundry court invariant + interaction-matrix fuzz (128k calls) | ✅ | `74b3acd` |
| S7 | RDecVerifier malformed-proof negative tests | ✅ | (this commit) |
| S6 | Wire-codec fuzz harnesses (relay header decoders) | ✅ | (this commit) |
| S1 | Cross-layer epoch-clock authority spec (`docs/EPOCH_AUTHORITY.md`) | ✅ | (this commit) |
| S2 | Cross-epoch nullifier-clash / replay integration test | ✅ | (this commit) |
| S3 | Abuse/DoS model + bounded buffers (`docs/ABUSE_MODEL.md`) | ✅ | (this commit) |
| S8 | Reentrancy interaction-matrix fuzz | ✅ (subsumed by S5) | `74b3acd` |
| S9 | Adversarial-caller / cross-contract court tests | ✅ | `contracts/test/CourtAdversarial.t.sol` (17 tests: attacker can't fund/close/dispute/slash/reenter) |
| S10 | Negative channel-protocol tests | ✅ | `tessera-channel/tests/negative_protocol.rs` (non-monotone/bad-sig/replay/over-budget/malformed all rejected) |
| S11 | 3-language Poseidon/witness regression test | ✅ | `tessera-channel/tests/poseidon_regression.rs` (pinned BE bytes vs circomlib-verified decimals) |
| S12 | Channel-state durability/recovery model (doc) | ✅ | [`docs/CHANNEL_RECOVERY.md`](./CHANNEL_RECOVERY.md) |
| S13 | Deployment topology / trust-boundary spec (doc) | ✅ | [`docs/DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) |
| S14 | System key-management lifecycle (doc) | ✅ | [`docs/KEY_MANAGEMENT.md`](./KEY_MANAGEMENT.md) |
| S15 | Cross-layer protocol versioning | ✅ | [`docs/PROTOCOL_VERSIONING.md`](./PROTOCOL_VERSIONING.md) (catalog + upgrade convention; explicit version byte recommended, not yet impl) |
| S16 | Observability/metrics spec + privacy review (doc) | ✅ | [`docs/OBSERVABILITY.md`](./OBSERVABILITY.md) |
| S17 | Concurrency double-spend tests for tag stores | ✅ | `tessera-origin/tests/concurrency_double_spend.rs` (Barrier-raced threads, exactly-one-wins; in-mem + file) |
| S18 | `FileTagStore` durability tests | ✅ | `tessera-origin/tests/filetagstore_durability.rs` (spent tags survive store drop+reopen) |
| S19 | Relayer-cheat matrix (doc, reconcile w/ M1) | ✅ | [`docs/RELAYER_CHEAT_MATRIX.md`](./RELAYER_CHEAT_MATRIX.md) |
| S20 | Anonymity-set sparse-deployment warnings | ✅ | [`docs/SAFETY.md`](./SAFETY.md) (sparse-deployment §) |
| S21 | ARC lifecycle + cross-crate fuzz | ✅ | `fuzz/fuzz_targets/arc_lifecycle.rs` (issue→present→verify invariants: no-panic/complete/single-use/sound/rate-limited) |
| S22 | Honest-relayer atomicity spec (doc) | ✅ | [`docs/RELAYER_CHEAT_MATRIX.md`](./RELAYER_CHEAT_MATRIX.md) (atomicity §) |
| S23 | CI: cargo-deny | ✅ | `deny.toml` + the `deny` CI job (advisories/bans/licenses/sources) |
| S24 | CI: deeper fuzz (300s/target) | ✅ | the `fuzz-deep` CI job (300s/target, schedule + workflow_dispatch gated) |
| S25 | CI: Slither static analysis | ✅ | the `slither` CI job (fails on High/Medium) |
| S26 | CI: coverage report | ✅ | the `coverage` CI job (cargo-llvm-cov) |
| S27 | `#![deny(missing_docs)]` all crates | ✅ | all 9 library crates; `cargo doc -D warnings` clean |
| S28 | Known-limitations + claim-boundary in README | ✅ | README "What this is / what it is NOT" + the IP-blind caveat + "Security status" |
| S29 | Phase-status consistency table | ✅ | [`docs/STATUS.md`](./STATUS.md) |
| S30 | `docs/SAFETY.md` (abuse handling) | ✅ | [`docs/SAFETY.md`](./SAFETY.md) |
| S31 | Audit-prep packet (`AUDIT.md`) | ✅ | [`AUDIT.md`](../AUDIT.md) |
| S32 | Multi-spend channel integration test | ✅ | `tessera-channel/tests/multi_spend.rs` (40 round trips + settlement + non-destructive over-budget reject) |
| S33 | PoW honest-difficulty analysis + benches | ✅ | `tessera-issuer/benches/pow.rs` (criterion) + [`docs/POW_ANALYSIS.md`](./POW_ANALYSIS.md) |
| S34 | PIR / green-routing / x402 egress lanes (code parts) | ⬜ | |

## NICE — pending

N1 dispute-gas economics · N2 balance-boundary Foundry tests · N3 `unilateralCloseZK` ·
N4 per-IP-per-epoch ZK rate circuit · N5 Tor timing jitter+cover · N6 EPOCH_BUDGET
witness bounds · N7 cleartext/ZK commitment-asymmetry doc+test · N8 proptest for ARC ·
N9 group non-canonical-encoding tests · N10 verifier drop-in + ceremony-repro CI ·
N11 cleanliness sweep · N12 timing-safety/PQ/changelog docs · N13 client+demo unit tests ·
N14 cachegrind CT analysis · N15 PoW solver timing-leak doc.

## 🔒 Irreducibly external (documented, never faked)

E1 3rd-party audit · E2 multi-party Groth16 ceremony · E3 clean residential egress IP
at scale · E4 Tor/Nym anonymity set · E5 Nym mixnet integration · E6 perpetual anti-bot
defense · E7 production PQ primitives · E8 mainnet deploy w/ real value · E9 cross-epoch
SDA budget (open research) · E10 accountable hostile-exit (open research) · E11 live
replicated multi-exit directory operation + distributed spent-tag consistency · E12
shielded pool (XL) · E13 carrier/CGNAT/Snowflake lanes · E14 legal/liability model ·
E15 real-world anonymity-set measurement · E16 machine-checked soundness proof / full
CT audit.

## Authorship note

All commits are authored `NubsCarson <192162056+NubsCarson@users.noreply.github.com>`
(the canonical GitHub-credit address). On 2026-06-04 the repo's local git config had
leaked a contributor's personal email; it was corrected and main's full history re-authored.
