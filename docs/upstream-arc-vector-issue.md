# Upstream issue — `ietf-wg-privacypass/draft-arc`

> **Filed 2026-06-04 as [issue #68](https://github.com/ietf-wg-privacypass/draft-arc/issues/68).**
> This is the as-posted text, tightened so every specific value is either the
> draft's own published data or a claim our committed tests support (we dropped
> the per-squeeze-length recomputed challenges from the public post and instead
> link the full write-up). The deeper reproduction lives in
> [`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md).

---

**Title:** §10.2 ARC(P-256) proof-blob test vectors don't reconcile with the pinned Sigma POC

**Body:**

While building an independent Rust implementation of `draft-ietf-privacypass-arc-crypto`
(no shared code with the sage POC), I found that the **arithmetic** test vectors
in §10.2 / `poc/vectors/allVectors.json` reproduce **byte-for-byte**, but the
**zero-knowledge proof blobs** (`CredentialRequest.proof`,
`CredentialResponse.proof`, `Presentation{1,2}.proof`) do not.

**Reproduced exactly (arithmetic):** server public keys `X0/X1/X2`,
`HashToScalar(requestContext)`, `m1Enc`/`m2Enc`, `U`, `encUPrime`, all `*Aux`
points, the finalized `UPrime`, and every presentation commitment + tag — all
byte-identical. So the group, hash-to-curve/scalar, issuance, and presentation
arithmetic in §10.2 are internally consistent and correct.

**Does not reproduce (proofs):** the committed `ARCV1-P256.CredentialRequest.proof`
begins with the challenge scalar `2a088673e302502a3dc80d6100a1bb70…f9a7c52e7cfeaa2ea3`.
Recomputing that challenge from the public statement — using a Fiat-Shamir
transcript that reproduces the **authoritative** `draft-irtf-cfrg-sigma-protocols`
`sigma-proofs_Shake128_P256` vectors (`discrete_logarithm`, `dleq`)
byte-for-byte — yields a different value at **every** squeeze length I tried
(32 / 48 / 64 bytes), and a sweep over session-string, session-id-derivation,
and `protocol_id` variants produced no match.

**Likely cause:** `poc/sigma` (the pinned submodule) and the current Sigma POC
HEAD differ in `codec.sage`'s challenge squeeze — `scalar_byte_length() + 16`
(48 bytes) vs `+ 32` (64 bytes). The committed `allVectors.json` proof blobs
appear to straddle that codec change, i.e. they predate the transcript wiring
the pinned toolchain now produces. (The arithmetic is stable across that change,
which is why it still matches.)

**Why I believe the negative is authoritative, not an implementation bug:** the
same transcript machinery reproduces the official Sigma `discrete_logarithm` and
`dleq` vectors byte-for-byte and rejects tampered ones — so the Σ / Fiat-Shamir
port is correct; only the ARC proof blobs are out of sync.

**Ask:** regenerate the §10.2 / `allVectors.json` proof blobs against the
current `draft-irtf-cfrg-sigma-protocols` POC (and bump the pinned `poc/sigma`
submodule), so independent implementers can validate the proof layer against
ARC's own KATs.

**Reproduction / environment:** independent Rust implementation, no shared code
with the sage POC. Full write-up — including the per-squeeze-length
recomputations and the transcript-variant sweep — is here:
<https://github.com/NubsCarson/tessera/blob/main/docs/ARC_PROOF_VECTOR_DISCREPANCY.md>.
Happy to provide a minimal standalone reproduction on request.
