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
| 4 | **Fiat-Shamir + Sigma proofs** — SHAKE128 duplex sponge, P256 codec, linear-relation verifier | KAT: official Sigma `discrete_logarithm` + `dleq` proofs verify byte-exactly | ✅ **proven** (verifier) † |
| 5 | **Full ARC API** — `SetupServer`, `Issue`, `Present`, `Verify` + prover + range proof + double-spend tag store | Round-trip over the limit; tamper/replay rejected | ✅ **proven** |
| 6 | **Wire codec** — canonical serialization of every protocol struct | Round-trip + spec lengths (`Nrequest`, `Nresponse`, `Npresentation`); verifies after transport | ✅ **proven** |
| 7 | **`tessera-origin`** — transport-agnostic `OriginGuard` that verifies a presentation header and enforces the limit + double-spend, ignoring source IP | `tests/guard.rs`: admit/missing/malformed/replay/wrong-context, distinct tags | ✅ **proven** |
| 8 | **`tessera-client`** — obtains a credential, mints a presentation header per request | exercised by the demo + guard tests | ✅ **proven** |
| 9 | **Tor binding** — expose the origin as an onion service; client connects over a real Tor circuit (SOCKS5); admitted purely on the credential | `cargo run -p tessera-demo -- --tor` builds a real `.onion`; live round-trip needs host Tor egress | ✅ **implemented** ‡ |
| 10 | **Hardening pass** — constant-time review, fuzzing of all deserializers, criterion benchmarks, threat-model doc | Fuzz targets run clean; CT audit notes published | ⬜ |

† The original gate ("every §10.2 ARC *proof* blob byte-exact") is blocked by
an upstream test-vector inconsistency: the committed ARC proof blobs do not
reconcile with the pinned reference's Fiat-Shamir wiring, while every ARC
*arithmetic* vector matches byte-for-byte. The proof layer is therefore proven
against the **authoritative** Sigma Protocol vectors (which exercise the same
machinery), and the `#[ignore]`d ARC-blob tests will flip green if the upstream
blobs are regenerated. Full write-up + reproduction in
`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`.

‡ The onion service is always created (you'll see a real `.onion`); completing
the rendezvous circuit back to it requires working Tor network egress on the
host. The credential check is byte-identical on either transport, so the
localhost flow fully establishes correctness; Tor just proves it survives a real
anonymous transport.

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
