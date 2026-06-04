# Tessera — Roadmap (post-v0 frontier)

The v0 implementation is complete: all of `GOAL.md`'s milestones, six crates,
CI-green, fuzzed, internally audited, honest about its limits. This doc plans
the genuinely-meaningful work *beyond* polish. Four tracks, each a real effort.

For every track: **Goal · Approach · Done-when · Risks / external dependency · Status.**

---

## 1. Audit-readiness  ·  *done*

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

## 3. WASM browser client  ·  *done (core + scaffold; browser final mile is yours)*

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
- **Status.** ✅ **done (core + scaffold)** — `crates/tessera-wasm` (its own
  excluded workspace, like `fuzz/`; `getrandom` `js` feature for browser
  entropy) builds for `wasm32-unknown-unknown` and exposes a `wasm-bindgen` API
  (`mint_local` + `TesseraCredential::present()` → the exact
  `TesseraClient::presentation_header` value). The mint→present round-trip is
  **tested headlessly** under node via `wasm-bindgen-test-runner` (3 tests
  pass), with a native `rlib` fallback test of the identical logic. An MV3
  extension scaffold (`crates/tessera-wasm/extension/`) wires a
  `Tessera-Presentation` header via `declarativeNetRequest` (limits documented).
  A dedicated `wasm` CI job builds/tests it separately from the host gates.
  **Human final mile (unchanged):** loading the extension in a real browser
  against a live origin, and wiring issuance to a real issuer.

## 4. Upstream contribution + research  ·  *drafts done; posting needs your OK*

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
- **Status.** ✅ **drafts done** — the IETF issue text
  ([`upstream-arc-vector-issue.md`](./upstream-arc-vector-issue.md)) and
  [`POST_QUANTUM.md`](./POST_QUANTUM.md) (what Shor breaks, MPCitH/lattice
  options, migration sketch) are written. **Posting the issue is gated on your
  explicit go-ahead** — outward action under your GitHub identity.

---

### Honesty note

"Fully done, all four, autonomously" has real boundaries: tracks 2–4 each have a
final mile that needs you (a Cloudflare account, a browser, your GitHub
identity). Everything up to those miles will be built clean, tested, and
CI-green; the human-gated step is called out explicitly in each, never faked.
