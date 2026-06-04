# Tessera — Threat Model

> Status: **research-grade, UNAUDITED.** This document describes the security
> properties Tessera *intends* to provide, which cryptographic mechanism is
> responsible for each, and — just as importantly — what it does **not** do.
> It is written to be falsifiable: every claim is tied to a line of code or a
> section of the IETF drafts, and known gaps are named rather than glossed.
> Read `README.md` ("Security status") and `GOAL.md` (milestone 10) first; this
> document does not soften anything they say.

Specs tracked (all IETF **drafts**, subject to change):

- `draft-ietf-privacypass-arc-crypto-01` — the ARC protocol (cited below as "ARC §x")
- `draft-irtf-cfrg-sigma-protocols-01` — the Sigma proof system
- `draft-irtf-cfrg-fiat-shamir-01` — the non-interactive transform

---

## 1. What Tessera is, and the trust model

Tessera is an implementation of **Anonymous Rate-Limited Credentials (ARC)**
over NIST P-256, plus a server-side guard (`tessera-origin`) that admits or
refuses an HTTP request **on the strength of an ARC credential presentation
alone, never reading the source IP** (`crates/tessera-origin/src/lib.rs`,
`OriginGuard::check` — "Source IP is deliberately not an input").

### Keyed-verification, not publicly verifiable

ARC is a **keyed-verification anonymous credential (KVAC)** scheme. The
**same** party that issues a credential also verifies its presentations,
because verification requires the server's *private* keys, not just the public
key. This is explicit in the code:

- The server's secret is `(x0, x1, x2, x0Blinding)` (`keys.rs`,
  `ServerPrivateKey`).
- Issuance computes the algebraic MAC with those secrets (`arc.rs`,
  `create_credential_response`: `encUPrime = (X0 + m1Enc·x1 + m2Enc·x2)·b`).
- **Verification also needs them**: `verify_presentation_proof` recomputes
  `V = x0·U + x1·m1Commit + x2·m2·U − UPrimeCommit` directly from
  `private_key.x0/x1/x2` (`proofs.rs`). A holder of only the public key
  cannot verify a presentation.

**Consequence:** there is no third party who can independently verify a
Tessera credential. A presentation is meaningful only to the issuer (or to a
party trusted with the same secret keys). This is the deliberate ARC design
trade-off versus pairing-based, publicly-verifiable schemes like BBS (ARC §8
"Alternatives considered"); it buys a smaller credential and no pairings, at
the cost of public verifiability.

### The "cooperating origin" model — stated bluntly

Tessera changes the trust calculus **only for sites that choose to verify ARC
credentials.** It is an *adapter a server opts into*, not a property of the
network.

- It **cannot** force Google, Cloudflare, or any non-cooperating site to accept
  anything. Those sites do not run `OriginGuard`, do not hold the keys, and will
  go on judging traffic by IP. Tessera does nothing to them.
- It does **not** disguise Tor traffic as non-Tor (that is censorship *evasion*,
  the losing arms race `GOAL.md` explicitly rejects). A cooperating origin still
  sees that the connection is from a Tor exit; it simply no longer has to *care*,
  because it has a better trust signal than IP reputation.
- The win is local and voluntary: a cooperating origin can stop blocking Tor
  because it now has a cryptographic, rate-limitable, unlinkable proof of "a
  budgeted, validly-issued client" that is strictly more informative than an IP
  address.

If you are evaluating Tessera, evaluate it as *"a tool a willing server deploys
to safely admit anonymous traffic,"* not as *"a tool that makes the whole web
accept Tor."* The latter is impossible and is not claimed.

---

## 2. Security goals, and which mechanism delivers each

| Goal | Mechanism | Where |
|---|---|---|
| (a) Unforgeability | Algebraic MAC (MACGGM) + response proof of knowledge | `arc.rs`, `proofs.rs` response statement |
| (b) Issuance unlinkability | Pedersen-committed request + `x0Blinding` | `arc.rs` request, `keys.rs`, ARC §7.1/§7.2 |
| (c) Presentation unlinkability | Re-randomization + Pedersen-committed nonce | `arc.rs` `present`, ARC §7.3 |
| (d) Rate limiting / no over-presentation | Bounded nonce + range proof + server tag store | `proofs.rs`, `arc.rs` `TagStore`, `tessera-origin` |
| (e) Linkability *by design* of reuse | Deterministic tag from `(m1+nonce)` and context | `arc.rs` `present` (the `tag`) |

### (a) Unforgeability

A credential is the server's algebraic MAC `UPrime` over the client's secret
`m1`, the request context `m2`, and the server keys. A client cannot produce a
valid `(U, UPrime, m1)` triple, nor a presentation proof for one, without the
server's secrets. Soundness of the presentation proof reduces to the
discrete-log / Sigma-protocol soundness of the linear relation built in
`build_presentation_statement` (`proofs.rs`) and verified by `sigma::verify`.
The formal unforgeability argument is the KVAC paper's, not re-proven here
(ARC §7 defers to "Formal Security Definitions for KVAC").

### (b) Issuance unlinkability (ARC §7.1, §7.2)

The credential **request** is two Pedersen commitments with fresh blinds —
`m1Enc = m1·G + r1·H`, `m2Enc = m2·G + r2·H` (`arc.rs`,
`create_credential_request`) — accompanied by a proof of knowledge
(`request_statement` in `proofs.rs`). A Pedersen commitment is *statistically
hiding*, so two requests are statistically indistinguishable to the server
(ARC §7.1).

The server's commitment `X0 = x0·G + x0Blinding·H` (`keys.rs`,
`public_key()`) binds the server to a single secret key across all issuances
**computationally** — i.e. *unless discrete log is broken* (ARC §7.2).

> **Quantum caveat (ARC §7.2):** an adversary who can break discrete log (e.g.,
> with a sufficiently large quantum computer) can find a *second* pair
> `(x0', x0Blinding')` also committing to `X0` and issue credentials under it,
> **partitioning the client anonymity set** by which secret was used. ARC notes
> this requires an *active* attack and is "not an immediate concern." It is,
> nonetheless, a real ceiling on issuance unlinkability and is restated under
> non-goals (§4) and known weaknesses (§5).

### (c) Presentation unlinkability (ARC §7.3)

Each presentation freshly re-randomizes the credential and commits everything
revealed:

- `U = a·U`, `UPrimeCommit = a·UPrime + r·G`, `m1Commit = m1·U + z·H` with fresh
  `a, r, z` (`arc.rs`, `present`). Per ARC §7.3, `[U, UPrimeCommit, m1Commit]`
  are indistinguishable across **all** presentations from credentials under the
  same server keys.
- `nonceCommit = nonce·G + nonceBlinding·H` hides the nonce in a Pedersen
  commitment with a fresh blind every time; the nonce value is **never sent**.
- A **range proof** (the bit-decomposition constraints in
  `build_presentation_statement`) proves `nonce ∈ [0, limit)` without revealing
  it.

**Per-context anonymity-set size (ARC §7.3).** For the context-scoped elements
`[tag, nonceCommit, presentationContext, presentationProof, rangeProof]` the
indistinguishability set is

```
sum_{i=0}^{c} p_i[presentationContext]
```

where `c` is the number of credentials issued under the same server keys and
`p_i[presentationContext]` is the number of presentations credential *i* has
made **for that same `presentationContext`**. Two practical reads of this
formula:

1. Anonymity is **per `presentationContext`**. Presentations made under
   different contexts are *not* in each other's set. A deployment that hands
   every origin its own context shrinks each set to the traffic of that one
   origin.
2. The set grows with *both* the issued-credential count *and* per-credential
   presentation volume. A barely-used deployment offers weak anonymity simply
   because the set is small — this is a property of the math, not a bug, and it
   means **the issuance gate doubles as the anonymity-set lever** (see §6).

### (d) Rate limiting / no over-presentation

Three layers, all required:

1. **Client-side counter** (`arc.rs`, `PresentationState`): `next_nonce`
   increments per presentation and `present` returns `LimitExceeded` once
   `next_nonce >= limit`. This is *advisory* — an honest client respects it; a
   malicious client can ignore it. It is **not** the enforcement.
2. **Range proof**: the server's `verify_presentation_proof` recomputes the
   decomposition bases (`compute_bases`) and checks both the homomorphic sum
   `nonceCommit == Σ bases[i]·D[i]` and the per-bit `{0,1}` constraints. A nonce
   `≥ limit` cannot produce a satisfying proof. This bounds the nonce **range**;
   it does not by itself stop reusing an in-range nonce.
3. **Tag store / double-spend** (the actual over-presentation defense): the tag
   is deterministic in `(m1 + nonce)` and the context (below), so reusing a
   slot reproduces the **same tag**. The server records seen tags and rejects
   repeats — `arc.rs` `TagStore::accept` returns `false` on a duplicate, and
   `tessera-origin` maps that to `RejectReason::DoubleSpend`. Range proof bounds
   *how many distinct* slots exist; the tag store enforces *each is used once*.

### (e) The tag, and what it deliberately links (ARC §6 / §7.3)

```
generatorT = HashToGroup(presentationContext, "Tag")
tag        = generatorT · (m1 + nonce)^{-1}
```
(`arc.rs`, `present`.)

The tag is the one intentionally-linkable element, and its linkage is exactly
the rate-limiting primitive:

- **Same credential (`m1`) + same `nonce` + same `presentationContext` ⇒ same
  `tag`.** This is *why* a double-spend is detectable (two presentations with
  the same nonce can be compared for equality via the tag).
- **Different `nonce`, or different `presentationContext`, ⇒ different,
  unlinkable `tag`** (the context changes `generatorT`; the nonce changes the
  exponent). So *within a context*, the only thing the tag links is the
  forbidden act of reusing a slot. Across contexts, nothing.

This is the crux of the whole design: the only linkability Tessera introduces
is the minimum needed to enforce the budget, and it is confined to a single
`presentationContext`.

---

## 3. Threat actors

### 3.1 Malicious client (holds a credential or tries to fake one)

| Capability | Outcome |
|---|---|
| Forge a credential / mint one without issuance | **No.** Requires the server secrets; presentation proof would not verify. |
| Over-present (use more than `limit` slots) | **No.** A nonce `≥ limit` cannot satisfy the range proof. |
| Replay a presentation / reuse a nonce slot | **Caught.** Same `(m1, nonce, context)` ⇒ same tag ⇒ `TagStore` rejects (`DoubleSpend`). *Requires a correct, durable tag store — see §6.* |
| Link itself across presentations | **N/A** — it gains nothing; it already knows its own activity. It cannot make the *server* link them. |
| Tamper with a presentation in transit | Rejected as `InvalidProof` (Fiat-Shamir challenge won't recompute). |
| Submit garbage bytes | Rejected as `Malformed`; deserializers are total and never panic (`wire.rs`, `group.rs` `deserialize_*` return `Result`; `sigma::verify` gates on `well_formed` and never panics). |

### 3.2 Malicious or honest-but-curious server / verifier

| Capability | Outcome |
|---|---|
| Link two presentations to each other (same context) | **No**, except the quantum-DL caveat. `[U, UPrimeCommit, m1Commit]` and the context tuple are indistinguishable within the §7.3 set. |
| Link a presentation back to issuance | **No** (statistically-hiding request commitments, §7.1; re-randomized presentation, §7.3) — again modulo the quantum-DL caveat. |
| Recover the nonce | **No.** Nonce lives only inside a Pedersen commitment; range proof reveals nothing but membership. |
| Deanonymize a client cryptographically | **No** within the classical model. The server learns only "valid, in-budget, fresh slot." |
| Partition the anonymity set via discrete-log break (e.g. quantum) | **Yes**, per ARC §7.2 — an *active* attack finding a second `(x0, x0Blinding)`. The principal cryptographic caveat. |
| Shrink anonymity by handing out unique `presentationContext`s, or issuing few credentials | **Yes — operationally.** Not a crypto break; the §7.3 set is genuinely small. The server *chooses* the contexts and issuance volume. |

Tessera does **not** defend the client against a server correlating *out-of-band*
signals (timing, TLS fingerprint, the very fact that an `OriginGuard`-protected
endpoint was hit). Those are transport/HTTP concerns (§4).

### 3.3 Network adversary — explicitly Tor's job, not Tessera's

Tessera provides **zero** network-level anonymity. A passive or active network
observer sees source/destination IPs, timing, and volume exactly as it would
without Tessera. The presentation header travels in the clear at the Tessera
layer (hex in an HTTP header; confidentiality in transit is whatever TLS the
transport supplies).

Network-level unlinkability is **delegated entirely to the transport** — in the
intended deployment, **Tor** (`tessera-origin` is transport-agnostic; the demo
drives it over a real onion circuit, `GOAL.md` milestone 9). The layering is
strict:

- **Tor** hides *where the request came from* (IP/network identity).
- **Tessera/ARC** hides *which credential, and that two requests are the same
  client*, at the application layer.

Neither substitutes for the other. If you run Tessera **without** an anonymizing
transport, the server still does not read the IP in its admission decision — but
the network and any logging middlebox certainly can, which undermines the
anonymity the credential provides. **Tessera over a non-anonymous transport is
not anonymous.**

### 3.4 Malicious origin operator

The origin operator *is* the keyed verifier, so within the keyed-verification
model they are already maximally trusted for *verification*. They still cannot
forge credentials they did not issue under their own keys, nor break
presentation unlinkability beyond the §7.3 limits and the quantum caveat.

What a malicious origin operator **can** do (and Tessera does not prevent):

- **Refuse service / discriminate** — they choose what to admit; out of scope to
  constrain.
- **De-anonymize via context partitioning** — assign per-user or per-cohort
  `presentationContext`s, or issue credentials sparsely, to make the §7.3
  anonymity set as small as one. **This is the most realistic deanonymization
  vector and it is operational, not cryptographic.** A client cannot detect it
  from the protocol alone; it must trust (or verify) the deployment's context
  policy and issuance breadth.
- **Correlate with HTTP/transport metadata** they collect — out of scope (§4).
- **Mismanage the tag store** to allow over-presentation (their own loss) — §6.

---

## 4. Non-goals / out of scope

These are **not** provided. Treating any of them as solved is a deployment error.

1. **Forcing non-cooperating sites.** Tessera changes only what an opting-in
   origin does. No effect on sites that don't verify ARC. (§1.)
2. **Network-level anonymity.** Delegated to the transport (Tor). Tessera adds
   no IP/timing/volume protection of its own. (§3.3.)
3. **Sybil resistance of issuance.** *Who is allowed to obtain a credential* is
   an **application policy**, deliberately unspecified here. `create_credential_response`
   issues to **anyone** whose request proof verifies. There is no proof-of-work,
   payment, or rate cap on issuance in this codebase (the "earn your budget"
   model is a `GOAL.md` stretch item). Without an issuance gate, one actor can
   obtain unlimited credentials and the rate limit is meaningless — see §6.
4. **Post-quantum soundness/anonymity.** All security rests on the hardness of
   discrete log over P-256. **Shor's algorithm breaks that**, which (a) breaks
   credential unforgeability and proof soundness, and (b) enables the
   issuance-unlinkability partition attack of ARC §7.2. The Sigma/Fiat-Shamir
   layer is likewise classical. There is **no** post-quantum claim.
5. **HTTP-layer / application metadata.** Cookies, TLS fingerprints, header
   ordering, request timing and size, the bare fact of contacting a guarded
   endpoint — none of this is addressed. The credential can be perfectly
   unlinkable while the surrounding request trivially is not.
6. **Audited, end-to-end constant-time guarantees.** Best-effort only; see §5.

---

## 5. Known weaknesses and current status

- **UNAUDITED, research-grade.** No third-party review. The protocol logic on
  top of RustCrypto's audited primitives is precisely what is unreviewed
  (`README.md`, `lib.rs`). **Do not use to protect real users yet.**

- **Constant-time: the known secret-dependent path is hardened; a full
  end-to-end CT audit has not been done.** The nonce bit-decomposition in
  `proofs.rs::prove_presentation` is computed **branchlessly** with the `subtle`
  crate (`ConstantTimeGreater`/`ConstantTimeEq` + `ConditionallySelectable`),
  removing the `if remainder >= base` secret-dependent branch and subtraction
  that ARC §7.4 ("Timing Leaks") forbids; the secret-path witness buffer is
  pre-sized so it does not reallocate, and `reduce_mod_order` is constant-time in
  its input (fixed compile-time modulus). RustCrypto's P-256 scalar/point
  operations are themselves constant-time. **However**, no systematic
  constant-time *audit* (covering every secret-data operation, memory-access
  patterns, and compiler-emitted code across all crates) has been performed, so
  timing-channel resistance must be treated as **best-effort and unaudited**
  until milestone 10's review lands. Re-verify against the current source rather
  than trusting this paragraph.

- **ARC §10.2 proof-blob vector discrepancy.** The ARC draft's committed
  zero-knowledge **proof blobs** do **not** reproduce byte-for-byte under the
  pinned reference's Fiat-Shamir wiring, while **every arithmetic vector matches
  exactly** (8/8 in `tests/test_vectors.rs`). Assessed as an **upstream
  vector/reference inconsistency** (the Sigma POC's challenge squeeze churned
  `+16`→`+32`), not a Tessera bug — independently confirmed by showing the
  pinned reference's own `verify()` rejects its own committed blob. The proof
  layer is therefore validated against the **authoritative** IETF Sigma Protocol
  vectors (`tests/sigma_vectors.rs`: official `discrete_logarithm` + `dleq`,
  accept-good/reject-tampered), which exercise the identical transcript
  machinery; the ARC-blob tests are kept `#[ignore]`d. Full write-up:
  `docs/ARC_PROOF_VECTOR_DISCREPANCY.md`. **Implication:** the proof *machinery*
  is vector-proven, but not against ARC's own end-to-end proof KATs — a residual
  correctness uncertainty until upstream reconciles.

- **Draft-tracking.** All three specs are IETF **drafts** and may change in ways
  that alter the wire format, the transcript, or the security properties. Any
  property here is "as of `-01`."

- **Tag store is in-memory and non-durable as shipped.** Both `arc.rs::TagStore`
  and `tessera-origin`'s guard hold seen tags in a process `HashSet` /
  `Mutex<HashSet>`. A restart, a crash, or a second replica with its own set
  **forgets spent tags and re-opens the double-spend window.** The code itself
  flags this. (§6.)

- **Quantum-DL caveat (ARC §7.2)** — see §2(b)/§3.2/§4. The headline anonymity
  ceiling.

- **Anonymity is only as large as the §7.3 set.** Small deployments and
  per-user contexts give weak anonymity by construction (§2c, §3.4).

---

## 6. Operational considerations for a real deployment

The cryptography is necessary but not sufficient. The properties above hold only
if the deployment gets these right:

1. **The tag store is the enforcement boundary — make it durable, correctly
   keyed, and monotonic.**
   - **Durable**: persist it. An in-memory set (as shipped) re-opens the
     double-spend window on every restart.
   - **Keyed by `(requestContext, presentationContext)`**: the tag's
     uniqueness/linkability is scoped to a context (`generatorT` derives from
     `presentationContext`). Partition the store by the same context pair the
     guard is configured with.
   - **Monotonic**: a tag must stay "spent" at least as long as a credential can
     be presented. Premature eviction = silent over-presentation. Bound storage
     by **rotating keys/context**, not by dropping live tags.
   - **Consistent across replicas**: multiple guard instances MUST share one
     authoritative store (or shard deterministically by tag), or each replica is
     an independent replay oracle. Insert-and-check must be atomic (the shipped
     `Mutex<HashSet>` is atomic only within one process).

2. **Key rotation.** The server keys define the anonymity set (all credentials
   under one key are mutually anonymous, §7.3). Rotating keys **partitions** the
   set and invalidates outstanding credentials; re-issue and carry/retire the
   tag store in lockstep. Protect the private key as any MAC key — its compromise
   breaks unforgeability for everyone.

3. **The issuance gate is the real abuse-control lever.** Rate limiting only
   bounds presentations *per credential per context*. If anyone can obtain
   unlimited credentials, total presentations are unbounded — the limit is
   cosmetic. **Sybil control lives at issuance, and Tessera does not provide it**
   (§4.3). Decide and enforce *who earns a credential* (proof-of-work, payment,
   attestation, allow-list). The same lever governs anonymity: more credentials
   ⇒ larger §7.3 set (better privacy, looser control); fewer / per-user contexts
   ⇒ tighter control but anonymity can shrink toward one.

4. **Run it over an anonymizing transport, or accept that it is not anonymous.**
   The guard ignores the IP, but the network does not. Without Tor (or
   equivalent) and attention to HTTP metadata (§4.5), the credential's anonymity
   is undermined by the surrounding request.

5. **Set the presentation limit with eyes open.** A larger `limit` means more
   range-proof bits (`compute_bases` ⇒ larger presentations,
   `5·Ne + k·Ne + (6+3k)·Ns`) and more presentations before re-issuance. Choose
   per the abuse model, not by default.

---

## Summary

Tessera correctly implements the ARC arithmetic core (vector-proven) and a
keyed-verification guard that admits anonymous traffic on a credential instead
of an IP. Within the **classical** discrete-log model it gives unforgeability,
issuance unlinkability, per-context presentation unlinkability, and
double-spend-based rate limiting — **for cooperating origins only**, **only to
the size of the per-context anonymity set**, and **only when paired with an
anonymizing transport for the network layer**. It does **not** force
non-cooperating sites, provide network anonymity, resist Sybil issuance, or
survive a discrete-log break (quantum). It is **unaudited**, **best-effort (not
audited) constant-time** with the known secret-dependent decomposition hardened
via `subtle`, and **draft-tracking**. Deploy it for real users only after
milestone 10.
