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

**Direction note (vNext) — read this first.** v0 (this document) framed Tessera
as censorship-*obsolescence*, not evasion: give servers a trust signal better
than IP so they have no reason to block anonymity. That remains true and is the
right play for *cooperating* origins. The project is now **evolving to also
pursue privacy-preserving *circumvention*** — reaching sites that do **not**
cooperate, via clean egress behind an anonymous, paid (ZK payment-channel) rail.
The full vNext north-star + Definition of Done is in
[`docs/DESIGN.md`](./docs/DESIGN.md) (§11); the v0 milestones below remain the
proven foundation it builds on.

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
5. **Honest docs.** Every known limitation (no end-to-end constant-time audit,
   no third-party audit, draft-tracking) is stated plainly in the README. We
   never call research-grade code "production-ready."

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
| 10 | **Hardening pass** — constant-time fix, fuzzing of all deserializers, criterion benchmarks, threat-model doc | 18-finding adversarial audit applied; 5 fuzz targets run clean (found+fixed 1 panic); stable robustness test; benches; `docs/THREAT_MODEL.md` | ✅ **done** (audit, not external) § |

† The original gate ("every §10.2 ARC *proof* blob byte-exact") is blocked by
an upstream test-vector inconsistency: the committed ARC proof blobs do not
reconcile with the pinned reference's Fiat-Shamir wiring, while every ARC
*arithmetic* vector matches byte-for-byte. The proof layer is therefore proven
against the **authoritative** Sigma Protocol vectors (which exercise the same
machinery), and the `#[ignore]`d ARC-blob tests will flip green if the upstream
blobs are regenerated. Full write-up + reproduction in
`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`.

§ "Done" here means the internal hardening pass landed: an 18-finding
adversarial multi-agent audit (constant-time, soundness, panic-safety,
cleanliness) was applied; the secret-dependent range-proof bit decomposition is
now branchless (`subtle`); 5 `cargo-fuzz` targets cover every deserializer +
`sigma::verify` + the origin guard and run clean (the fuzzer found and we fixed a
real `limit < 2` panic); a stable-toolchain robustness test gives CI no-panic
coverage; criterion benches exist; and `docs/THREAT_MODEL.md` is published. This
is **not** a third-party security audit — that remains the bar before protecting
real users.

‡ The onion service is always created (you'll see a real `.onion`); completing
the rendezvous circuit back to it requires working Tor network egress on the
host. The credential check is byte-identical on either transport, so the
localhost flow fully establishes correctness; Tor just proves it survives a real
anonymous transport.

**Stretch / research frontier:** a study of the anonymity-set dynamics when ARC
rides over Tor (now also covering the client→issuer hop). *(The issuer that mints
credentials against a proof-of-work **or a one-time payment** — the "earn your
budget" model — is no longer a frontier: both shipped; see "Deliberately
deferred" below.)*

---

## What would make this *perfect* (not just done)

- A third-party reproduces our test-vector results from the spec alone.
- The Tor E2E demo shows a site that *blocks raw Tor* admitting a
  Tessera-credentialed request from the same exit IP.
- ✅ A written security argument mapping our code to the unlinkability claims in
  ARC §7 and the KVAC paper, with the gaps to a formal proof named explicitly —
  [`docs/SECURITY_ARGUMENT.md`](docs/SECURITY_ARGUMENT.md).

All 10 milestones are complete; the honest status is **a proven-correct ARC core
and a runnable trust-layer demo, hardened (internally, not third-party audited)
and CI-gated.** No overclaiming.

---

## Deliberately deferred (considered, not overlooked)

An adversarial review panel triaged the remaining ideas. These are intentionally
**not** done pre-1.0, with reasons — so their absence is a decision, not a gap:

- **Proof-of-work issuance gate** — ✅ **shipped** as `tessera-issuer`
  (hashcash-style challenge/solve/verify + a one-time `ChallengeStore`, wired
  into the narrated demo). It makes minting a credential *cost CPU*, throttling
  bulk/Sybil minting. Honestly scoped: it is a **cost knob, not strong Sybil
  resistance** (enough compute still scales; unfair to low-power clients) — for
  per-human guarantees, gate on payment (✅ shipped, next bullet), attestation, or
  a one-per-person credential; the attestation / one-per-person variants remain
  future research.
- **Payment-gated issuance (ETH-paid mint)** — ✅ **shipped**: `tessera-issuer`'s
  paid mode issues credentials against an on-chain `TokenMint` purchase. The buyer
  proves control of its Ethereum address (`ecrecover` over an issuer-bound
  challenge); the issuer reads the live `entitled(buyer)` via a std-only `eth_call`
  and gates issuance durably (refundable; single-issuer double-issue guard).
  Std-only (`k256`+`sha3`, no `alloy`/`tokio`, MSRV 1.74), proven against a real
  local anvil chain (`tests/anvil_entitled.rs`). Consuming the entitlement on-chain
  (`TokenMint.redeem`) is an operator step. Testnet-only, UNAUDITED. (See
  `docs/ARCHITECTURE.md` step 1.)
- **`axum`/`tower` middleware** — ✅ **shipped** as the off-by-default `tower`
  feature on `tessera-origin` (`TesseraLayer`/`TesseraGuard`): a drop-in
  `tower::Layer` that runs the guard and short-circuits rejects with `403`,
  `axum`/`hyper`-compatible. Kept lean — `tower`+`http`+`http-body-util`+`bytes`,
  no `axum`/`tokio` in the graph, 1.74-clean. (ROADMAP track 2.) The *Cloudflare
  Worker edge deploy* remains a documented sketch, not a compiled artifact — it
  needs the server secret at the edge and a durable cross-isolate tag store.
- **Pluggable/durable `TagStore` backend** — ✅ **shipped** as the
  `SpentTagStore` trait on `tessera-origin` + `OriginGuard::with_store`: the
  default `InMemoryTagStore`, a durable single-process `FileTagStore`, and an
  injection point for a distributed backend (Redis/Postgres/Durable Object).
  Double-spend enforcement is tested to survive a guard restart. (A *concrete*
  distributed impl is intentionally left to the deployer — it depends on their
  infra.)
- **Credential-gated HTTPS proxy** — ✅ **shipped** as `tessera-proxy`: a
  `CONNECT` proxy that tunnels TLS end-to-end to any HTTPS site, optionally over
  Tor — admitting on the credential, never the IP. Anonymous, accountable,
  IP-blind access to the clearnet, realized end to end.
- **Key epochs / rotation on the wire**, **batch verification**, **ristretto255
  ciphersuite**, **wasm build** — each is a real protocol-surface or scope
  expansion better done with a concrete driving use case.
- **`#![deny(missing_docs)]`** — the one remaining cosmetic item; ~52 pub items
  would need doc lines. A pre-0.1.0 docs pass, not blocking.

(Since shipped, no longer deferred: `zeroize`-on-key-drop — `keys.rs` zeroizes
the secret scalars on `Drop`; `CONTRIBUTING.md` / `CHANGELOG.md` / README badges;
per-crate READMEs; and the proof-of-work issuance gate + Tor proxy above.)
