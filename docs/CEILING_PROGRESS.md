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
- **SHOULD tier: 8/34** — hardening + completeness; in progress (S1, S2, S3, S4, S5, S6, S7, S8).
- **NICE tier: 0/15** — polish; pending.
- **Verification:** ~70 Rust workspace tests + 48 Foundry tests + 6 fuzz targets, all green; CI green on `main`.

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
- ✅ **S27 `#![deny(missing_docs)]`** on all 8 library crates — public API fully
  documented (56 items via an 8-agent pass + stragglers by hand), commit `e1076ef`.
- ✅ **cargo-deny** (supply-chain advisories/licenses/sources/bans) — `deny.toml`
  + a pinned CI job; `cargo deny check` passes locally (the two unmaintained
  arkworks transitive deps are explicitly acknowledged, not hidden).
- ⬜ remaining (lower-value / locally-unverifiable): `cargo llvm-cov` coverage,
  Slither, a `forge fmt --check` gate (would reformat the generated verifier,
  which we deliberately leave matching snarkjs), pinning CI `cargo install`
  versions. None blocks the v0.1.0 promotion.

## Architecture pivot (the leaner ecash-token + Tor path — `docs/ARCHITECTURE.md`)

| Item | Status | Commit |
|---|---|---|
| Decision doc (what we built vs. leaner path, why) | ✅ | `dc56d41` |
| Performance/latency analysis (speed matters; pivot is faster) | ✅ | `f5dc1c2` |
| ETH-paid token mint rail (`TokenMint.sol` + 13 forge tests) | ✅ | (this commit) |
| Leaner-default e2e proof (token + 2-hop loop + M5 shaping, no channel) | ✅ | (this commit) |
| Channel/ZK/court demoted to optional-advanced tier (documented, kept) | ✅ | `dc56d41` |
| Off-chain issuer integration (watch Purchased → blind-issue → redeem) | 🔒 | operational (reuses ARC) |
| Paid-mint client UX + deployed clean-IP exit + crowd | 🔒 | external/frontend |

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
| S9 | Adversarial-caller / cross-contract court tests | ⬜ | |
| S10 | Negative channel-protocol tests | ⬜ | |
| S11 | 3-language Poseidon/witness regression test | ⬜ | |
| S12 | Channel-state durability/recovery model (doc) | ⬜ | |
| S13 | Deployment topology / trust-boundary spec (doc) | ⬜ | |
| S14 | System key-management lifecycle (doc) | ⬜ | |
| S15 | Cross-layer protocol versioning | ⬜ | |
| S16 | Observability/metrics spec + privacy review (doc) | ⬜ | |
| S17 | Concurrency double-spend tests for tag stores | ⬜ | |
| S18 | `FileTagStore` durability tests | ⬜ | |
| S19 | Relayer-cheat matrix (doc, reconcile w/ M1) | ⬜ | |
| S20 | Anonymity-set sparse-deployment warnings | ⬜ | |
| S21 | ARC lifecycle + cross-crate fuzz | ⬜ | |
| S22 | Honest-relayer atomicity spec (doc) | ⬜ | |
| S23 | CI: cargo-deny | ⬜ | |
| S24 | CI: deeper fuzz (300s/target) | ⬜ | |
| S25 | CI: Slither static analysis | ⬜ | |
| S26 | CI: coverage report | ⬜ | |
| S27 | `#![deny(missing_docs)]` all crates | ⬜ | |
| S28 | Known-limitations + claim-boundary in README | ⬜ | |
| S29 | Phase-status consistency table | ⬜ | |
| S30 | `docs/SAFETY.md` (abuse handling) | ⬜ | |
| S31 | Audit-prep packet (`AUDIT.md`) | ⬜ | |
| S32 | Multi-spend channel integration test | ⬜ | |
| S33 | PoW honest-difficulty analysis + benches | ⬜ | |
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
SDA budget (open research) · E10 accountable hostile-exit (open research) · E11 relayer
multi-instance consistency · E12 shielded pool (XL) · E13 carrier/CGNAT/Snowflake lanes ·
E14 legal/liability model · E15 real-world anonymity-set measurement · E16 machine-checked
soundness proof / full CT audit.

## Authorship note

All commits are authored `NubsCarson <192162056+NubsCarson@users.noreply.github.com>`
(the canonical GitHub-credit address). On 2026-06-04 the repo's local git config had
leaked `shawgotbags@gmail.com`; it was corrected and main's full history re-authored.
