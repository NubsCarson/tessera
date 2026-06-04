# Security Policy

## Status — read this first

Tessera is **research-grade, UNAUDITED** software implementing IETF *draft*
protocols. It has **not** had a third-party security review and is **not** ready
to protect real users. See [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) for
the trust model, the properties it intends to provide, and the known gaps
(notably: keyed-verification only, no Sybil-resistant issuance gate, no
post-quantum soundness, and best-effort — not audited — constant-time behavior).

Do not deploy it where a real adversary could be present.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Preferred: GitHub → the repository's **Security** tab → **Report a
  vulnerability** (private vulnerability reporting is enabled), or
- Email **nubs@nubs.site** with `tessera security` in the subject.

Include: affected component (crate + `file:line` if known), a description, and a
proof-of-concept or reproduction if you have one. You'll get an acknowledgement;
please allow reasonable time for a fix before any public disclosure.

## In scope

- The cryptographic implementation in `tessera-arc` (group/hashing,
  issuance/presentation, the Sigma/Fiat-Shamir proofs, the range proof, wire
  serialization) — e.g. a way to **forge** a credential, **over-present** beyond
  the limit, **replay/double-spend** undetected, or **link** presentations that
  the protocol claims are unlinkable.
- `tessera-origin` admission logic (a way to be admitted without a valid,
  in-budget, unspent credential).
- **The Phase 2 payment rail (handles funds — highest-value target):**
  - `tessera-channel` — the ZK Spilman channel protocol: any way to **mint
    balance**, **double-spend** a state, **equivocate without being slashable**,
    **roll back** to a higher balance undetected, bypass **sign-then-serve**, or
    forge a co-signature / proof-of-relay receipt.
  - `contracts/` (`ChannelRegistry.sol`, `RDecVerifier.sol`) — any way to
    **drain escrow**, settle at a wrong balance, slash an honest party, bypass
    the dispute window, reenter a fund path, or accept an invalid Groth16 proof.
    *(Known gap, already disclosed: the relayer currently posts no separate
    on-chain bond — see `docs/DESIGN.md`; tracked, not a finding.)*
  - `circuits/R_dec.circom` — any way the decrement circuit admits an unsound
    witness (e.g. a wrap-around `cost`, an unbound `chan_id`/`K_chan`, a missing
    range check). The trusted setup is **TEST-ONLY** (forgeable by design until a
    real ceremony) — that is *known*, not a finding.
  - `tessera-relay` channel mode — admitting/serving a request without a valid,
    fresh, in-budget channel spend; the split-trust property leaking the
    destination to the relay or the client address to the exit.
- Any **panic / abort / memory-unsafety** reachable from attacker-controlled
  input (every `from_bytes` / wire decoder, `OriginGuard::check`, the relay's
  header parser). All Rust crates are `#![forbid(unsafe_code)]`.

## Out of scope (by design — see the threat model)

- **Network-level anonymity / traffic analysis** — delegated to the transport
  (e.g. Tor); Tessera adds none of its own.
- **Forcing non-cooperating sites** to accept credentials — impossible and not
  claimed.
- **Sybil resistance of issuance** — an application policy, deliberately not
  provided here.
- **Post-quantum** attacks (the discrete-log assumption is classical).
- The **ARC §10.2 proof-blob vector discrepancy** — a known upstream
  inconsistency, documented in
  [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md).
- The `tessera-demo` HTTP/SOCKS harness (a deliberately tiny, non-production
  std-only demo layer) — unless the issue is in the underlying `tessera-arc` /
  `tessera-origin` logic it exercises.

## Supported versions

Pre-1.0: only the latest `main` is supported. There are no security backports.
