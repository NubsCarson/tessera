# Tessera — Roadmap (post-v0 frontier)

The v0 implementation is complete: all of `GOAL.md`'s milestones, six crates,
CI-green, fuzzed, internally audited, honest about its limits. This doc plans
the genuinely-meaningful work *beyond* polish. Four tracks, each a real effort.

For every track: **Goal · Approach · Done-when · Risks / external dependency · Status.**

---

## 1. Audit-readiness  ·  *doing first, here*

- **Goal.** Make the security story legible to a third-party auditor and to
  reviewers — the only path past the "unaudited" ceiling.
- **Approach.** Write [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md): map each
  security property to its construction in the code, the assumption it rests on,
  and the explicit gap to a machine-checked proof. Cross-reference the KVAC
  paper and the Sigma/Fiat-Shamir drafts. Assemble an audit packet (scope, trust
  model, threat model, test/fuzz coverage, known issues).
- **Done-when.** Every property (unforgeability, issuance + presentation
  unlinkability, rate-limit soundness, proof-system soundness/ZK) has a stated
  construction → assumption → gap; nothing hand-waved; all claims trace to
  `file:line`.
- **Risks / external.** None — fully solo. Does **not** replace a real audit.
- **Status.** ✅ **done** — [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md)
  shipped (every property: construction → assumption → gap, all `file:line`).

## 2. Make it deployable  ·  *done*

- **Goal.** Let a real site verify Tessera with minimal effort — turn the
  framework-agnostic `OriginGuard` into drop-in middleware.
- **Approach.** An optional `tower::Layer` on `tessera-origin` (feature `tower`,
  off by default so the core stays lean) that extracts the header and runs the
  guard, `axum`/`hyper`-compatible; plus a documented Cloudflare Worker
  edge-deploy *sketch*.
- **Done-when.** The `Layer` compiles behind its feature, has a `tower`
  integration test (admit / missing / malformed / replay), and CI builds it on
  all-features incl. the MSRV-1.74 job; the edge-deploy path is documented.
- **Risks / external.** Pulls HTTP deps (feature-gated to contain them; no
  `axum`/`tokio` in the graph — `tower`+`http`+`http-body-util`+`bytes` only,
  all 1.74-clean). A live Cloudflare deploy needs **your** account and a wasm
  build of the guard with the server secret at the edge — out of scope here;
  documented as a sketch, **not** shipped as a compiled Worker.
- **Status.** ✅ **done** — `TesseraLayer`/`TesseraGuard` shipped behind the
  off-by-default `tower` feature (`crates/tessera-origin/src/tower_layer.rs`),
  4-case integration test green, every CI gate (fmt/clippy/test/MSRV-1.74/doc)
  green. Edge-deploy path documented in the origin README; a compiled Worker is
  explicitly deferred (needs the server secret at the edge + a wasm guard build).

## 3. WASM browser client  ·  *background (final mile needs a browser)*

- **Goal.** Let a *human* browse carrying a credential — the most tangible demo.
- **Approach.** Build `tessera-arc` + `tessera-client` for `wasm32-unknown-unknown`
  (`getrandom` `js` feature), expose a tiny `wasm-bindgen` API (`present()` →
  header), and scaffold a Manifest-V3 extension that attaches the header.
- **Done-when.** The wasm target **compiles** and a headless wasm test passes
  (mint → present round-trips in-wasm); the extension scaffold is complete and
  documented.
- **Risks / external.** The extension's real last mile (load in a browser, hit a
  live origin) needs **your** browser — we deliver a compiling, tested wasm core
  + extension scaffold, and flag that final manual step.
- **Status.** ⬜ background workflow.

## 4. Upstream contribution + research  ·  *background (posting needs your OK)*

- **Goal.** Give back to the standard and chart the post-quantum path.
- **Approach.** (a) Draft a precise issue for the IETF Privacy Pass WG's
  `draft-arc` repo documenting the §10.2 proof-blob vector discrepancy we found
  (with our reproduction). (b) A `POST_QUANTUM.md` scoping a PQ-sound proof
  path — the Sigma draft itself points at MPC-in-the-Head / lattice
  alternatives; map what would change.
- **Done-when.** The issue text is written and ready; the PQ scoping doc names
  concrete options, what breaks under Shor, and a migration sketch.
- **Risks / external.** Posting the issue is an outward action under **your**
  GitHub identity to a third-party repo — we draft it; **you** post it (or
  explicitly OK it).
- **Status.** ⬜ background (draft); post gated on your go-ahead.

---

### Honesty note

"Fully done, all four, autonomously" has real boundaries: tracks 2–4 each have a
final mile that needs you (a Cloudflare account, a browser, your GitHub
identity). Everything up to those miles will be built clean, tested, and
CI-green; the human-gated step is called out explicitly in each, never faked.
