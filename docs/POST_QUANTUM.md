# Tessera — Post-Quantum Path (scoping)

> A scoping document, not an implementation. Tessera today is **classical**:
> every security property rests on discrete log over P-256 (see
> [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md)). This maps what a quantum
> adversary breaks and what a PQ-sound successor would take.

## What Shor breaks

A large quantum computer solving discrete log defeats **all** of Tessera's
guarantees, not just one:

- **Unforgeability** — recovering the server secrets `(x0, x1, x2)` from the
  public `(X0, X1, X2)` lets anyone mint credentials.
- **Proof soundness** — the Σ/Schnorr relations are DL statements; a DL solver
  forges proofs without the witness.
- **Issuance unlinkability** — ARC §7.2: a DL break finds a second
  `(x0', x0Blinding')` committing to the same `X0`, partitioning the anonymity
  set (an *active* attack, but real).

Note the *transcript* hash (SHAKE128/SHA-256) is already PQ-ok (Grover only
halves preimage security); the break is entirely in the group.

"Harvest-now-decrypt-later" is **not** a confidentiality concern here (presentations
carry no long-term secret payload), but it **is** an unlinkability concern: a
recorded transcript could be de-anonymized later once DL is broken.

## Options for a PQ-sound successor

Two independent pieces must move: the **proof system** and the **credential/MAC**.

### Proof system (the Σ/Fiat–Shamir layer)

The Sigma-protocols draft itself (§4.2) points at PQ alternatives; the practical
candidates:

1. **MPC-in-the-Head** (ZKBoo/KKW, à la Picnic) — symmetric-crypto-only ZK
   proofs; conservative PQ assumptions, larger proofs. Best fit for "prove
   knowledge of a witness" without a structured group.
2. **Lattice Σ-protocols** — e.g. compressed lattice proofs; smaller than MPCitH
   for some relations but heavier machinery and newer analysis.
3. **Hybrid (migration)** — AND-compose the existing classical proof with a PQ
   proof (Sigma draft §4.2): soundness holds if *either* assumption holds. Lets
   a deployment migrate without a flag day, at the cost of proof size.

### Credential / MAC

The harder half — a PQ **anonymous** credential with unlinkable multi-show:

- **Lattice-based KVAC / anonymous credentials** — active research; no
  deployment-ready, vector-backed standard yet.
- **Hash/symmetric-based tokens** — strong PQ posture but typically single-show
  (closer to Privacy Pass tokens than to multi-show ARC); would change the
  unlinkable-multi-presentation model.
- Pairing-free PQ KVAC is not yet mature (mirrors ARC §8's note that even the
  *classical* keyed-verification BBS variants need more analysis).

## Migration sketch

1. Keep ARC(P-256) as the default; add a **ciphersuite identifier** so a PQ or
   hybrid suite can coexist (the wire format and `contextString` already make
   suite a parameter).
2. Land a **hybrid proof** first (classical AND PQ) — lowest-risk, preserves
   today's guarantees while adding PQ soundness.
3. The PQ **credential** is the research bottleneck; track lattice KVAC progress
   and the CFRG's PQ work rather than rolling our own.

## Honest status

No PQ work is implemented. This is a map of the terrain and the dependency
order, so the classical limitation in `SECURITY_ARGUMENT.md` §PQ has a credible
answer when the primitives mature. **Do not** read this as a claim of any
post-quantum property today — there is none.
