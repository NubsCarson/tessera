# Tessera — Security Argument

> A reviewer's map, not a proof. For each security property this states the
> **construction** (with `file:line`), the **assumption** it rests on, and the
> **gap** to a machine-checked proof. It complements [`THREAT_MODEL.md`](./THREAT_MODEL.md)
> (what's in/out of scope) by arguing *why* the in-scope properties hold — and
> exactly where the argument stops. Nothing here is hand-waved; where we rely on
> a paper's theorem rather than re-proving it, that is named as a gap.
>
> **Status: research-grade, UNAUDITED.** This document is an input *to* an audit,
> not a substitute for one.

## Model and assumptions

ARC is a **keyed-verification anonymous credential (KVAC)** from an algebraic MAC
(MACGGM), per [KVAC, CMZ14](https://eprint.iacr.org/2013/516) and
[Revisiting KVAC](https://eprint.iacr.org/2024/1552); the protocol is
`draft-ietf-privacypass-arc-crypto`. The non-interactive zero-knowledge proofs
are Σ-protocols (`draft-irtf-cfrg-sigma-protocols`) compiled with Fiat–Shamir
(`draft-irtf-cfrg-fiat-shamir`).

Everything rests on these assumptions; **all are classical** and fall to a
discrete-log break (see §PQ):

| Assumption | Used for | In Tessera |
|---|---|---|
| Discrete log / DDH over P-256 | MAC unforgeability, commitment binding, Σ soundness | `tessera-arc::group` (RustCrypto `p256`) |
| Random Oracle Model (SHA-256, SHAKE128) | Fiat–Shamir non-interactivity & adaptive soundness; hash-to-curve | `group::hash_to_*`, `sigma` transcript |
| Statistically-hiding Pedersen commitments | issuance & presentation unlinkability | `m*Enc`, `nonceCommit`, `m1Commit` |
| MACGGM EUF-CMVA (KVAC theorem) | credential unforgeability | issuance + presentation verify |

## 1. Credential unforgeability

**Claim.** A client cannot present a credential the server never issued.

**Construction.** Issuance computes the algebraic MAC
`UPrime = b·(X0 + x1·m1Enc + x2·m2Enc)` under the server secrets
(`arc.rs::create_credential_response`). A presentation proves, in zero knowledge,
knowledge of `(m1, U, UPrime)` consistent with the server keys: the verifier
recomputes `V = x0·U + x1·m1Commit + x2·m2·U − UPrimeCommit` from its **private**
keys and checks the joint proof binds `V`, `m1Commit`, and the tag
(`proofs.rs::verify_presentation_proof`, `build_presentation_statement`).

**Assumption.** MACGGM is EUF-CMVA (existential unforgeability under chosen
message and verification queries), proven in the generic group model in [CMZ14]
and under DDH in [Revisiting KVAC]; plus soundness of the presentation Σ-proof
(§5).

**Gap.** We **rely on** the KVAC unforgeability theorem; it is not re-proven or
machine-checked here. Our contribution is a faithful implementation of that
construction (vector-checked, §arithmetic), not a new proof.

## 2. Issuance unlinkability

**Claim.** The server cannot link a credential to its issuance, nor distinguish
two issuance requests.

**Construction.** A request is two Pedersen commitments `m1Enc = m1·G + r1·H`,
`m2Enc = m2·G + r2·H` with fresh blinds (`arc.rs::create_credential_request`),
plus a Σ-proof of well-formedness (`proofs.rs::request_statement`). Pedersen
commitments are **statistically hiding**, so the request reveals nothing about
`m1`/`m2` and two requests are statistically indistinguishable (ARC §7.1). The
server key commitment `X0 = x0·G + x0Blinding·H` (`keys.rs::public_key`)
computationally binds the server to one key across issuances (ARC §7.2).

**Assumption.** Statistically-hiding Pedersen + ROM (for the request proof's ZK).

**Gap (quantum).** Per ARC §7.2, an adversary who breaks discrete log can find a
second `(x0', x0Blinding')` committing to the same `X0` and issue under it,
**partitioning** the anonymity set. Active, classical-infeasible, but a real
ceiling — restated in §PQ.

## 3. Presentation unlinkability

**Claim.** Two presentations (within a context) are unlinkable to each other and
to issuance — except the deliberate tag linkage that *is* the rate limit.

**Construction.** Each presentation freshly re-randomizes the credential —
`U = a·U`, `UPrimeCommit = a·UPrime + r·G`, `m1Commit = m1·U + z·H` with fresh
`a,r,z` — and commits the nonce as `nonceCommit = nonce·G + nonceBlinding·H`
with a fresh blind (`arc.rs::PresentationState::present`). Per ARC §7.3 the
revealed group elements are identically distributed across all presentations
under the same server keys. The **tag** `(m1 + nonce)^{-1}·generatorT`
(`generatorT = HashToGroup(presentationContext, "Tag")`) is *deterministic* in
`(m1, nonce, presentationContext)` — so it links iff the same nonce is reused in
the same context, and is unlinkable across nonces and across contexts. That is
the minimum linkage needed to enforce a budget, and nothing more (§4).

**Assumption.** DDH (re-randomization indistinguishability) + statistically-
hiding commitments + ROM (presentation proof ZK + `generatorT`).

**Gap.** Anonymity is only as large as the §7.3 per-context set
`Σ_i p_i[context]`; a sparse deployment or per-user contexts shrink it (operator
policy, see THREAT_MODEL §3.4). Quantum caveat as in §2.

## 4. Rate-limit soundness (no over-presentation)

**Claim.** A credential admits at most `limit` accepted, unlinkable presentations
per context; exceeding it is caught.

**Construction.** Two independent mechanisms:
1. **Range proof** — the presentation proves in zero knowledge that the
   committed nonce lies in `[0, limit)` via a bit decomposition: each `D[i]` is
   proven a bit (`D[i] = b[i]·D[i] + s2[i]·H`, which forces `b[i]∈{0,1}`) and the
   verifier checks the homomorphic sum `nonceCommit == Σ bases[i]·D[i]`
   (`proofs.rs::verify_presentation_proof`). A nonce `≥ limit` has no satisfying
   proof. *Tested adversarially*: `tests/roundtrip.rs::overlimit_nonce_is_refused_by_the_range_proof_not_just_the_counter`
   forges a presentation at `nonce == limit` and the verifier rejects it.
2. **Deterministic tag + double-spend store** — `limit` accepted presentations
   require `limit` distinct in-range nonces (≤ `limit`); reusing a slot repeats
   the tag, which the server's store rejects (`arc.rs::TagStore`,
   `tessera-origin::OriginGuard::check`).

**Assumption.** Σ special-soundness (§5) + DL (binding of the bit/nonce
commitments) + ROM. The tag-store guarantee additionally needs the store to be
**durable and consistent** in deployment (THREAT_MODEL §6, item 1) — an operational,
not cryptographic, requirement.

**Gap.** Range-proof binding rests on DL; quantum caveat. The shipped tag store
is in-memory/per-process.

## 5. Proof-system soundness & zero-knowledge

**Claim.** The Σ / Fiat–Shamir layer is knowledge-sound and zero-knowledge.

**Construction.** Linear-relation Schnorr proofs over a prime-order group
(`sigma.rs`): **special-sound** (two accepting transcripts sharing a commitment
but with distinct challenges extract the witness) and **honest-verifier ZK**
(the verifier simulates the commitment from a random response and the challenge —
`simulate_commitment` in `verify`). Fiat–Shamir makes them non-interactive and
adaptively sound in the ROM: the SHAKE128 duplex transcript absorbs the
`protocol_id`, a derived `session_id`, the canonical statement label, and the
commitment, then squeezes the challenge (`sigma::init_transcript`,
`verifier_challenge`). `verify` gates on `well_formed()` so a malformed statement
is rejected, never panics.

**Assumption.** ROM (FS hash is a random oracle) + DL (relation hardness).

**Gaps.** (a) FS soundness is **ROM-only**, not standard-model. (b) Not
machine-checked. (c) The challenge codec tracks the *current* Σ POC (64-byte
squeeze); the ARC §10.2 *proof-blob* vectors are upstream-inconsistent, so the
layer is validated against the authoritative Σ Protocol vectors instead — see
[`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md).

## What is actually proven in this repo

Distinct from the arguments above (which cite theorems), these are *mechanically
verified* here:
- The whole ARC **arithmetic** core matches the IETF §10.2 vectors byte-for-byte
  (`tests/test_vectors.rs`, 8/8).
- The Fiat–Shamir/Σ verifier reproduces the authoritative IETF Σ vectors
  (`tests/sigma_vectors.rs`: `discrete_logarithm`, `dleq`).
- End-to-end round-trips + negative cases (issue/present/verify, over-limit,
  tamper, wrong-context, double-spend) — `tests/roundtrip.rs`.
- Deserializers + the guard never panic on arbitrary input (`tests/robustness.rs`
  + the `cargo-fuzz` targets in `fuzz/fuzz_targets/` — run `cargo +nightly fuzz build` to list).

## Post-quantum (§PQ)

Every assumption above is classical. **Shor's algorithm breaks discrete log**,
which (a) forges credentials and breaks proof soundness, and (b) enables the §2
issuance-unlinkability partition. There is **no** post-quantum claim. A PQ path
is scoped in [`ROADMAP.md`](./ROADMAP.md) (track 4) / [`POST_QUANTUM.md`](./POST_QUANTUM.md).

## Gaps to a formal proof — the honest list

1. **No machine-checked proof** (no EasyCrypt/Tamarin/ProVerif model); reductions
   are argued, citing [CMZ14]/[Revisiting KVAC] and the Σ/FS drafts.
2. **Reliance on the KVAC theorems** for MAC unforgeability and the core
   unlinkability statements — implemented faithfully, not re-derived.
3. **Fiat–Shamir is ROM-only.**
4. **Constant-time is best-effort, not verified** — only the secret-dependent
   range-proof decomposition is explicitly branchless (`subtle`); no end-to-end
   CT audit.
5. **Not validated against ARC's own §10.2 proof-blob KATs** (upstream
   discrepancy); validated against the Σ vectors instead.
6. **No post-quantum soundness.**

## For an auditor — where to look first

`proofs.rs::verify_presentation_proof` (the private-key `V` recomputation that
binds the MAC; the range-sum + bit constraints) · `sigma.rs` (special-soundness
of the linear-relation verifier; the exact FS transcript) · `arc.rs::present` +
`TagStore` (tag determinism + double-spend) · every `from_bytes` / `check`
(panic-safety) · all secret-dependent code paths (constant-time).
