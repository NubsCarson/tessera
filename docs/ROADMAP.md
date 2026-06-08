# Tessera — Roadmap (post-v0 frontier)

The v0 implementation is complete: all of `GOAL.md`'s milestones, nine workspace
crates (plus two excluded), CI-green, fuzzed, internally audited, honest about its
limits. This doc plans the genuinely-meaningful work *beyond* polish. Four tracks,
each a real effort.

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
The current "what next?" queue is tracked in [`NEXT_STEPS.md`](./NEXT_STEPS.md);
those items are forward product/deployment work, not unfinished roadmap blockers.

Since then the **Tor-native onion egress lane** landed (see
[`ONION_EGRESS.md`](./ONION_EGRESS.md),
[`CLEAN_ONION_EGRESS.md`](./CLEAN_ONION_EGRESS.md)): the exit target/SSRF policy +
per-tunnel caps, a pluggable `transport::Dialer` seam, the single-hop client→exit
`.onion` route (relay bypassed; cold-start retry; **Tor-native fail-loud** when
Tor is down, with an opt-out env), the signed directory **v2** onion/`clean_egress`
advertisement + selection (client routes over the signed onion), and two-machine
deploy scripts **demonstrated live** (residential exit IP ≠ client IP). That is
the access-path *software*; the irreducibly-external half (a
genuinely clean egress IP, a real Tor/Nym crowd) is unchanged and still external.

---

## Exploratory ideas (parked — NOT committed, NOT planned work)

> Captured so they aren't lost, **deliberately off the roadmap above**. Each is
> premature for the current state (no deployed multi-operator network, no ecosystem
> interop demand) and would only be built if a concrete need forces it — not
> speculatively. Listed with the honest "why not yet."

### E-a. ERC-8004 Validation Registry for attested-non-logging-relay discovery

Tessera's single best trust claim is "run the relay in a TEE and a client can
*cryptographically attest* it matches the expected non-logging open-source image
under TDX/dstack assumptions." Today there's no standard place to publish or
find that attestation; it's bespoke. [ERC-8004](https://ethereum-magicians.org/t/erc-8004-trustless-agents/25098)'s
**Validation Registry** is, by design, "records verifiable evidence that a node
met a constraint" and is *method-agnostic*. So a relay's TDX attestation ("I'm
running commit X under the expected no-log image") becomes a Validation entry,
and a client/agent queries the registry to find attested non-logging relays
**without trusting a central directory**. It reuses work Tessera already has
(dstack TEE) and positions
Tessera as the privacy layer ERC-8004 deliberately omits (8004 has *no* privacy).
**Why not yet:** purely an operator-*discovery* layer — it does nothing for the
actual hard problem (clean egress IP, anonymity crowd, audit), and "discovery"
is meaningless until there's more than one relay to choose between. Strictly an
operator/node-layer idea: **never** put a Tessera *user* on a persistent ERC-8004
identity — that destroys the unlinkability that is the whole point.

### E-b. Privacy Pass standard issuance transport (replace the bespoke wire framing)

Tessera *is* a Privacy Pass scheme (ARC is the IETF Privacy Pass
[`draft-arc`](https://github.com/ietf-wg-privacypass/draft-arc); the crypto is
proven against its vectors), but the issuance *transport* is a bespoke TCP framing
(`tessera://issue-net/v1`). Adopting the standard Privacy Pass **HTTP issuance +
redemption** architecture ([RFC 9576](https://www.rfc-editor.org/info/rfc9576/) /
[9577](https://www.rfc-editor.org/rfc/rfc9577.html) /
[9578](https://datatracker.ietf.org/doc/html/rfc9578)) as that transport would
drop bespoke code and let **open** Privacy Pass tooling interoperate with Tessera,
in ARC's natural standardized home. **Decentralization is preserved:** the trust
model lives in *policy* (Tessera's "attester" is permissionless PoW / pay-ETH, not
a Big-Tech device gate), not the wire format; the architecture's
attester/issuer/origin role-split is itself decentralization-friendly and an open,
multi-implementer standard (not Cloudflare-owned). **Honest scope:** this means
speaking an open *format*, **not** "Cloudflare/Apple accept our tokens" — those are
centralized, gatekept trust roots (Apple PAT = genuine-Apple-device attestation),
and ARC is a *different token type* than their deployed ones, so we would neither
be drop-in accepted nor want to be. It also doesn't, by itself, harden the
issuer-as-chokepoint (that still needs the issuer reachable over Tor / multiple
issuers — same as today). **Why not yet:** non-trivial implementation; only worth
it if interop with the open Privacy Pass ecosystem becomes a goal.

### E-c. Verifiable no-log without a TEE (reproducible image + transparency log + quorum)

The TEE path (Intel TDX via dstack, [`DEPLOY.md`](./DEPLOY.md) §2) is the strong
answer to "prove you don't log," but it is a *datacenter* box: it trades away the
clean **residential** egress IP that actually reaches Tor-blocking sites, and a box
an operator runs at home can **never** hardware-attest non-logging to a stranger
(the root of trust would have to be a key the operator can't hold — a silicon
vendor's — which commodity/home hardware doesn't provide;
[`TRUST_MODEL.md`](./TRUST_MODEL.md) §3–§4). A **non-TEE** lane raises trust for the
residential case without claiming the impossible: a **reproducible no-log image** +
a published measurement; an **append-only transparency log** of node measurements
(RFC 6962 style, so a node that ever serves two stories is *provably* caught); and a
**multi-operator quorum** (the relay⟂exit non-collusion of
[`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §6, made plural, so a logging
*minority* is harmless). It makes a dishonest operator **catchable** and a logging
minority **useless** — a trust-*raiser*, not a cryptographic "did-not-log" proof
(ZK proves what a node *computed*, not the *absence* of a hidden copy —
[`TRUST_MODEL.md`](./TRUST_MODEL.md) §5). **Why not yet:** every leg needs what
isn't here locally — a reproducible build/publish pipeline, a log service with ≥1
honest witness, and (the real blocker) **more than one independent operator**, an
external hand-off. Pairs with **E-a** (ERC-8004) as the discovery layer. Full
design captured in [`TRUST_MODEL.md`](./TRUST_MODEL.md) §5; **not committed work.**
