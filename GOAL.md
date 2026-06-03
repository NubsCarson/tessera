# Tessera — North Star & Definition of Done

> **The goal:** *Make anonymity carry its own proof of good standing — so a
> request can be trusted without a server ever learning who, or where, it came
> from.*

Today the web judges traffic by **IP reputation**. Tor's exit IPs are public
and deterministically blockable, so anonymous traffic is treated as guilty by
default. Tessera attacks the root assumption: IP reputation is a *bad trust
primitive*. We replace it with an **anonymous, rate-limited cryptographic
credential** (the IETF ARC protocol) that a client carries through any
transport — including Tor — to prove "I am a budgeted, accountable client"
**without revealing identity, and without two requests ever being linkable.**

This is not a censorship-*evasion* tool (disguising Tor as not-Tor). It is a
censorship-*obsolescence* tool: give servers a trust signal so much better than
IP that they have no reason to block anonymity.

---

## The "done" bar — non-negotiable acceptance criteria

A milestone is **done** only when it is *proven*, not merely written. Concretely:

1. **Spec-faithful.** Every cryptographic operation maps to a cited line of
   `draft-ietf-privacypass-arc-crypto-01`, `draft-irtf-cfrg-sigma-protocols-01`,
   or `draft-irtf-cfrg-fiat-shamir-01`. No bespoke crypto.
2. **Test-vector proven.** It reproduces the official IETF test vectors
   **byte-for-byte**. This is the oracle that separates "correct" from
   "plausible." No milestone ships on self-consistency alone.
3. **Round-trip + negative tested.** Honest transcripts verify; tampered
   transcripts, over-budget presentations, and double-spends are rejected.
4. **No warnings, no `unsafe`, clippy-clean.** `cargo test`, `cargo clippy
   --all-targets -- -D warnings`, and `cargo fmt --check` all green in CI.
5. **Honest docs.** Every known limitation (no constant-time hardening, no
   audit, draft-tracking) is stated plainly in the README. We never call
   research-grade code "production-ready."

---

## Milestones

| # | Milestone | Acceptance gate | Status |
|---|-----------|-----------------|--------|
| 1 | **P-256 group layer** — generators, `HashToGroup`, `HashToScalar`, SEC1 ser/de | KAT: `generatorH`, `HashToScalar(m2)`, round-trips | ✅ **proven** |
| 2 | **Issuance arithmetic** — keygen, request/response/finalize math | KAT: `X0/X1/X2`, `m*_enc`, `U`, `encUPrime`, `*Aux`, `UPrime` | ✅ **proven** |
| 3 | **Presentation arithmetic** — re-randomization, commitments, tag | KAT: `U`, `UPrimeCommit`, `m1Commit`, `nonceCommit`, `tag`, `D` | ✅ **proven** |
| 4 | **Fiat-Shamir + Sigma proofs** — SHAKE128 duplex sponge, P256 codec, linear-relation prover/verifier, `SeededPRNG` | KAT: every `proof` blob in §10.2 reproduced byte-exactly | ⬜ next |
| 5 | **Full ARC API** — `SetupServer`, `Issue`, `Present`, `Verify` + double-spend tag store | Round-trip over the limit; tamper/replay rejected | ⬜ |
| 6 | **Wire codec** — canonical serialization of every protocol struct | Cross-check lengths (`Nrequest`, `Nresponse`, `Npresentation`) | ⬜ |
| 7 | **`tessera-origin`** — HTTP middleware (tower/axum) that verifies a credential header and enforces the rate limit, ignoring source IP | Integration test: N requests pass, N+1 rejected, identity never observed | ⬜ |
| 8 | **`tessera-client`** — obtains a credential, attaches presentations to outbound HTTP, transport-agnostic | E2E test through a `tower` mock origin | ⬜ |
| 9 | **Tor binding** — route the client through a real Tor circuit (`arti` or system tor SOCKS); origin admits it purely on the credential | E2E: request lands from a Tor exit IP yet is admitted | ⬜ |
| 10 | **Hardening pass** — constant-time review, fuzzing of all deserializers, criterion benchmarks, threat-model doc | Fuzz targets run clean; CT audit notes published | ⬜ |

**Stretch / research frontier:** an issuer that mints credentials against a
proof-of-work or a one-time payment (the "earn your budget" model), and a study
of the anonymity-set dynamics when ARC rides over Tor.

---

## What would make this *perfect* (not just done)

- A third-party reproduces our test-vector results from the spec alone.
- The Tor E2E demo shows a site that *blocks raw Tor* admitting a
  Tessera-credentialed request from the same exit IP.
- A written security argument mapping our code to the unlinkability claims in
  ARC §7 and the KVAC paper, with the gaps to a formal proof named explicitly.

Until milestone 10 lands, the honest status is: **a proven-correct ARC core, on
the way to a deployable system.** No overclaiming.
