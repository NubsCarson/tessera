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
- **Status.** ✅ **done + proven in a real server** — `TesseraLayer`/`TesseraGuard`
  shipped behind the off-by-default `tower` feature
  (`crates/tessera-origin/src/tower_layer.rs`), 4-case unit test green. Beyond
  that, `crates/tessera-tower-demo` is a runnable **`axum` server** using the
  layer plus an end-to-end test that stands it up on a **multi-threaded `tokio`
  runtime** and drives it over a **real TCP socket**: no-credential → `403`,
  malformed → `403`, valid → `200`, replay → `403` (double-spend), fresh → `200`.
  (`axum`/`tokio` live in that excluded crate with its own `tower-e2e` CI job, so
  the host MSRV-1.74 gate stays clean.) Edge-deploy path documented in the origin
  README; a compiled Cloudflare Worker is explicitly deferred (needs the server
  secret at the edge + a wasm guard build + a shared `SpentTagStore`).

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
- **Status.** ✅ **done + cross-language interop proven** — `crates/tessera-wasm`
  (its own excluded workspace, like `fuzz/`; `getrandom` `js` feature for browser
  entropy) builds for `wasm32-unknown-unknown` and exposes a `wasm-bindgen` API:
  `TesseraCredential::present()` (the exact `presentation_header` value),
  `mint_local` (ephemeral demo), and **`prepare_issuance`/`IssuanceFlow`** — the
  real issuance path against a live issuer's public key. 4 tests pass **headlessly
  under node** (incl. `real_issuance_against_an_external_key_verifies`) + a native
  `rlib` fallback. **Wiring issuance to a real issuer is no longer a gap:**
  `examples/node-real-issuance.cjs` drives the wasm client (fetch `/pubkey` →
  `prepare_issuance` → POST `/issue` → `finalize` → `present`) against a running
  `tessera-tower-demo` Rust origin — verified live: no-cred → 403, wasm credential
  → 200, replay → 403. The MV3 `background.js` uses that same real flow.
  **Only remaining human mile:** loading the extension in an actual browser (the
  GUI / `declarativeNetRequest` plumbing), which can't be exercised headlessly.

## 4. Upstream contribution + research  ·  *done (issue filed)*

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
- **Status.** ✅ **done** — the IETF issue is **filed** as
  [`draft-arc#68`](https://github.com/ietf-wg-privacypass/draft-arc/issues/68)
  (as-posted text in [`upstream-arc-vector-issue.md`](./upstream-arc-vector-issue.md);
  tightened to only the draft's own published data + claims our tests support),
  and [`POST_QUANTUM.md`](./POST_QUANTUM.md) (what Shor breaks, MPCitH/lattice
  options, migration sketch) is written.

---

### Honesty note

All four tracks are landed. Track 4's outward action (the GitHub-identity mile)
is **done** — [`draft-arc#68`](https://github.com/ietf-wg-privacypass/draft-arc/issues/68)
is filed. The only remaining human-gated miles are genuinely physical/account
ones, never faked: a live **Cloudflare** deploy (track 2 ships a documented
sketch, not a deploy) and loading the **MV3 extension in a real browser** against
a live origin (track 3 ships a compiling, headless-tested wasm core + scaffold).
