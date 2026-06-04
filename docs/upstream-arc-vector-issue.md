# Draft upstream issue — `ietf-wg-privacypass/draft-arc`

> Ready-to-post issue text documenting the §10.2 proof-blob vector
> inconsistency we found. **Posting is gated on the maintainer's go-ahead** —
> it goes to a third-party repo under your GitHub identity. Once you OK it, file
> it at <https://github.com/ietf-wg-privacypass/draft-arc/issues>.

---

**Title:** §10.2 ARC(P-256) proof-blob test vectors do not reconcile with the pinned Sigma POC

**Body:**

While building an independent Rust implementation of `draft-ietf-privacypass-arc-crypto`,
I found that the **arithmetic** test vectors in §10.2 reproduce byte-for-byte,
but the **zero-knowledge proof blobs** (`CredentialRequest.proof`,
`CredentialResponse.proof`, `Presentation*.proof`) do not — and they do not
reconcile with the reference POC at the pinned `sigma` submodule either.

**Reproduced exactly (arithmetic):** server public keys `X0/X1/X2`,
`HashToScalar(requestContext) = m2`, `m1Enc`/`m2Enc`, `U`, `encUPrime`, all
`*Aux` points, the finalized `UPrime`, and every presentation commitment + tag.
So the group, hash-to-curve/scalar, issuance, and presentation **arithmetic** in
the doc are internally consistent and correct.

**Does not reproduce (proofs):** recomputing the `CredentialRequest` challenge
from the public statement under the pinned reference's own Fiat-Shamir wiring
gives neither the committed value nor a value at any plausible challenge-squeeze
length. Concretely, the pinned `sigma` submodule's `codec.sage` squeezes
`scalar_byte_length() + 16` (48 bytes); the current `sigma` HEAD squeezes `+ 32`
(64 bytes, PR "use 32 more bytes of challenges"). The committed §10.2 proof
challenge `2a088673…2ea3` matches **neither** 48-byte (`afaf180f…`) nor 64-byte
(`9933a2a8…`) recomputation — i.e. the pinned reference's own `verify()` rejects
its own committed blob.

**Validation that the negative is authoritative:** the same transcript machinery
reproduces the official `draft-irtf-cfrg-sigma-protocols`
`sigma-proofs_Shake128_P256` vectors (`discrete_logarithm`, `dleq`,
`pedersen_commitment`) byte-for-byte at the 64-byte squeeze, and passes the 9
SHAKE128 duplex-sponge vectors — so the Σ/FS port is correct; only the ARC
proof blobs are out of sync.

**Likely cause:** `allVectors.json` and the `sigma` submodule pointer appear to
have been committed across a codec change (`+16` → `+32`), so the published ARC
proof blobs predate the transcript wiring the current toolchain produces.

**Ask:** regenerate the §10.2 proof blobs against the current
`draft-irtf-cfrg-sigma-protocols` POC (and bump the pinned submodule), so
independent implementers can validate the proof layer against ARC's own KATs.

**Environment:** independent Rust impl (no shared code with the sage POC);
reproduction scripts + a pure-Python P-256 cross-check available on request.

---

Our local write-up + reproduction: [`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md).
