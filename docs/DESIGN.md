# Tessera — Design (vNext): private, uncensorable clearnet access

> **Status:** proposed direction, consolidating a multi-pass, adversarially-red-teamed
> design effort. It **extends/supersedes** the v0 "cooperating-origin / censorship-*obsolescence*"
> thesis toward privacy-preserving **circumvention** — a public-facing philosophy change that is
> **gated on the maintainer's explicit OK** before the README/GOAL are reframed.
>
> **Honesty up front:** this is **research-grade and UNAUDITED**. The design is **~85% prior art**
> — its contribution is *composition + candor*, not a new cryptographic primitive. Reaching
> IP-blocking sites fundamentally needs clean egress (no crypto removes that); the anti-bot fight
> has no permanent win; the credential/ecash algebra is classical (falls to Shor). Those are stated
> as boundaries, not papered over.

## 0. Thesis & honest scope

Let a human or AI agent reach **any** clearnet site **privately** and **without being censored** —
admitted on an anonymous, rate-limited **credential/payment, not an IP**. Tor already does this for
many sites; the unsolved part is the **last mile**: Tor exit IPs are a public, blockable list, so
hostile sites (Cloudflare/Akamai/DataDome) reject them. The fix is **a clean (residential-class),
unpublished, rotating egress behind Tor-grade anonymity, paid for anonymously and accountably** —
which neither Tor (blocked exit) nor commercial residential proxies (zero privacy) provide today.

**Realistic envelope (not hype):** universal for the cooperating web + the IP-reputation-only
majority of the clearnet at human volume; **not** "the entire internet, unlimited." Aggressive
behavioral anti-bot remains an arms race that, worst case, degrades to a CAPTCHA.

## 1. Architecture (one flow)

```
CLIENT (real-browser persona; holds an anonymous credential)
  │  funds once: ETH → shielded pool (unlinkable) → opens a ZK payment channel
  ▼  wrap {destination, message, π (per-request spend proof), σ_user, nf_rate}
RELAYER  = single channel counterparty + first onion hop + rate-limiter (bonded, open-source, TEE)
  │  verifies π, co-signs next state BEFORE serving, onion-forwards (never sees destination)
  ▼
TRANSPORT  fast: 2-hop split-trust MASQUE/QUIC   |   bulk: Loopix/Sphinx mixnet (PQ-hedged)
  ▼
EXIT  (clean residential-class IP; dumb byte-transport — carries the client's real TLS untouched)
  ▼  end-to-end TLS (exit sees SNI, never content)
DESTINATION  (sees a coherent residential human)  → CAPTCHA residue = budgeted line item
  ▼  encrypted response back along the same path
ON-CHAIN  (court only): pool open/close, bonds, slashing on provable fraud, per-epoch settlement
```

Layers are **decoupled**: transport hides the client; egress provides reach; the credential pays +
admits + rate-limits; on-chain is a dispute court, never a per-request path.

## 2. Payment layer — ZK Spilman channel (the corrected core)

**Primitive:** a **ZK Spilman channel** — unidirectional, monotone-decrementing, single payee (the
relayer). *Not* Lightning/eltoo/Poon-Dryja. Key realization: **a network-access rail needs a payee,
not a payment network**, so routing/HTLCs/liquidity/revocation/penalty machinery simply don't exist.

- **Funding (unlinkable):** deposit ETH once into a `ShieldedPool` (EVM port of the team's audited
  Tornado-Nova / `cloaksdk`+`privacy-cash` UTXO pool: Poseidon-Merkle tree, per-note nullifiers,
  Groth16). An *internal* join/split mints a pool-fresh key `K_chan`; **open** spends that note
  *inside the pool circuit* into a `ChannelRegistry` (genesis `S₀ = Poseidon(chan_id, B₀, 0, salt)`).
  Escrow is spendable by *(relayer countersig on latest state)* **OR** *(user alone after timeout)* —
  the **refund-on-timeout branch is load-bearing** for payer safety. Never withdraw-to-EOA.
- **Per-request spend (off-chain, one round trip):** state `(chan_id, Bᵢ, seq=i, salt)` committed as
  `Sᵢ`. To spend, send `{Sᵢ₊₁, σ_user(Sᵢ₊₁), πᵢ, nf_rate}` where Groth16 `πᵢ` proves: knowledge of the
  countersigned `Sᵢ`; `Bᵢ₊₁ = Bᵢ − cost ≥ 0`, `seq++`; a **freshness binding** (relayer epoch/nonce +
  request-hash, so proofs aren't wire-replayable); and `nf_rate = Poseidon(K_chan, epoch, idx)`.
  **The user signs each state** (the critical fix — the original "2-of-2" was really 1-of-1, leaving
  equivocation unattributable). Relayer **co-signs `Sᵢ₊₁` and returns it BEFORE serving**
  (sign-then-serve), bounding griefing to one in-flight unit.
- **Fair exchange (impossible off-chain w/o a TTP — EGL / Pagnia-Gärtner):** sign-then-serve +
  **HOPR-style proof-of-relay** (the relayer can only claim a unit against evidence the packet was
  relayed) defeats the refusal-drain; the on-chain dispute is the optimistic-fallback TTP.
- **Settlement:** cooperative close re-mints the remaining balance as a **fresh shielded note**
  (keeps close unlinkable); unilateral close opens a dispute window where the highest doubly-signed
  `seq` wins; relayer-dark → user refund-on-timeout.
- **Slash:** only on an **on-chain-verifiable object** — user equivocation (two doubly-signed states
  off one predecessor) slashes the user; withholding is caught via the proof-of-relay obligation.
  *Honest limit:* a non-forking linear rollback yields no such object — covered by seq + countersig
  + the watchtower, which is therefore a **stated safety component**, not optional.

**Proof-system verdict (decisive, survived all red-teams): per-spend Groth16 on the hot path;
Nova/folding only optionally at close.** Folding *looks* ideal for a decrementing balance but is a
**trap**: the relayer must verify *each* request synchronously *before serving*, and a folded
instance isn't independently checkable mid-stream without the decider SNARK. `R_dec` is tiny
(a few Poseidon + range + sig + nullifier ≈ low-thousands constraints) → single-digit-ms proving.
Nova earns a place only as a close-time **ancestry/genesis-conservation** compressor (Option B), and
only if we want trustless conservation over relayer-attested balance (Option A) — ship A first.

## 3. Transport (hide the client)

Mode-switched (maps to NymVPN, a shipped system): **fast** = 2-hop split-trust **MASQUE/QUIC +
AmneziaWG** (interactive/LLM); **anon** = **Loopix/Sphinx Poisson mixnet** + cover traffic (bulk),
λ/μ as the trilemma knob. Onion-routing ≠ mixnet on the global-passive-adversary axis. **PQ gap is
the biggest upgrade:** Outfox + ML-KEM on the mix path, Rosenpass/ML-KEM-hybrid on the fast path.
The relayer is the first hop and onion-forwards so it never sees the destination. **No novel
mechanism lives here — it is inherited (Nym/Loopix-grade), and we say so.**

## 4. Fingerprint / anti-bot

The 2026 signal is **cross-layer coherence**, not any single hash. Drive a **real current-stable
browser** (nodriver Chrome lane / Camoufox Firefox lane) so TLS-JA4 + Akamai-H2 + QUIC-H3 + JS
surface + the **X25519MLKEM768 PQ key share** + UA/locale/tz/geo all agree by construction;
`curl_cffi`/`uTLS≥1.8.2` for cheap fetches. **Persona lives client-side; the exit is a dumb
byte-transport** (carries the client's real TLS untouched) — which is exactly the onion/TLS-tunnel
design. CAPTCHA = budgeted line item. **No permanent win; continuous fingerprint maintenance.**

## 5. Exit / engine + egress

A credential-gated CONNECT exit that verifies the presentation (never the IP), forwards the client's
real bytes end-to-end (SNI-only), and egresses from a **clean residential-class IP** (sourced from
existing consenting node networks — *not* a bespoke botnet). Encrypted return along the same path.
The v0 engine reuses `tessera-proxy` (CONNECT + e2e TLS) + `tessera-origin` (check) + `tessera-arc`
(ARC credential as the spend stand-in) + `tessera-client`.

## 6. On-chain (court only)

`ShieldedPool` + `ChannelRegistry` + bonds + Groth16 dispute/close verifier (constant gas;
BLS12-381 via EIP-2537 or BN254). Per-epoch aggregate settlement + slashing on provable fraud.
Never a per-request path.

## 7. Sybil / credential

Two doors, one downstream credential (bound to `chan_id`, funding-method-agnostic): **pay-to-open**
(cost-to-Sybil = capital + open fee) and a **proof-of-personhood-gated free faucet channel** (one
small zero-deposit channel per human, checked once at issuance). RLN's *stake/slash* layer is
dropped (the balance is the economic spam-limit); RLN's **per-epoch Shamir nullifier is repurposed
as a bandwidth/DoS rate-limiter**. *Honest:* don't claim paid/free are indistinguishable at the
relayer (balance ceiling leaks tier) — standardize ceilings or downgrade the claim.

## 8. What's genuinely novel vs reused (honest)

**Novel (systems/composition, survives a hostile reviewer):** (1) an access rail needs a *payee not
a network* — a unidirectional single-counterparty channel dissolves Lightning's hard parts; (2)
co-locating balance-authority + first onion hop in one bonded/TEE relayer to **collapse distributed
double-spend into a single in-memory cursor** (paid for with within-session linkability); (3) fusing
admit + RLN-rate-limit + payment + fixed-rate cover-funding into one nullifier-bearing proof; (4) the
correct proof-system fit (Groth16 hot / folding-at-close). **Zero novelty in the anonymity-transport
plane — inherited.**

**Reused (don't reinvent):** Tornado-Nova/Privacy-Pools shielded pool (`cloaksdk`/`privacy-cash`,
Solana→EVM port), Spilman/CLTV channels, RLN/Semaphore, Coconut/zk-nym threshold issuance, Nym
Loopix/Sphinx + Outfox + X-Wing, hintless PIR (for a cacheable "private read" tier), Cashu BDHKE
(considered, **rejected** for the spend in favor of the channel), HOPR proof-of-relay, watchtowers.

## 9. Open problems & hard ceilings

1. **Cross-epoch statistical-disclosure (the frontier).** Every per-request action can be anonymous
   yet the *pattern over time* deanonymizes. The channel **structurally** links all in-channel
   requests + exposes one pseudonym's lifetime timing to the relayer → intersection-attack fuel. The
   genuinely-novel unsolved work: a **cross-epoch anonymity budget** that prices every accountability
   artifact (reputation, rate-id, exit tag, **nullifier-stream cadence**) against the intersection
   adversary. Mitigated (short channels + forced rotation + fixed-rate cover + batched closes) but
   **not closed**. *This is the deanonymization surface the elegant double-spend kill creates.*
2. **Hostile exit.** Residential egress is malicious-by-default (MITM/selective-fail); audit-loops
   can't distinguish honest from logging exits. Accountable, MITM-resistant egress under
   unlinkability is **unsolved**.
3. **Named hard ceilings:** clean-IP supply is external/human-gated (the full
   egress strategy — a portfolio, no silver bullet — is in
   [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md)); "PQ from day one" is honestly
   "PQ transport + everlasting-transcript privacy, computational elsewhere" (PQ anonymous creds
   aren't production-grade); **TEE ≠ trust** (TEE.fail 2025 — a physical-access operator can forge
   quotes, and the relayer *is* that adversary for its own box → zero fund-safety/unlinkability
   weight on attestation; rely on bonds + proof-of-relay + open-source); a 3rd-party audit is the bar
   for production and is external.

## 10. Build phasing + reuse + honest gates

- **Phase 0 — Consolidate (this doc) + scaffold.** Reframe gated on maintainer OK.
- **Phase 1 — Prove the loop (make-or-break, mostly reuse).** `client → Tor → credential-gated exit
  (e2e TLS) → site → return`, ARC as v0 spend stand-in; local first, then **one real clean exit IP**
  → a Tor-`403` site returns `200`, privately. Tested.
- **Phase 2 — Real payment.** **✅ 2a (channel protocol) + ✅ 2c (EVM court) done.**
  `crates/tessera-channel` = the Spilman state machine (user-signed states so equivocation is
  attributable, sign-then-serve co-signing, HOPR proof-of-relay, off-chain `Settle`/`SlashUser`/
  `RefundUser`), with chain-facing sigs now **EVM-native secp256k1/`ecrecover`** (keccak digest;
  identity = the 20-byte ETH address). `contracts/ChannelRegistry.sol` (Foundry) mirrors it:
  open/cooperative-close/unilateral+challenge/slash-equivocation/refund-on-timeout, all verified by
  `ecrecover`, **with a Rust↔Solidity cross-language vector proven on-chain** (61 forge tests; a real
  Rust-signed state closes a channel). **✅ M1 (relayer on-chain bond) done:** the relayer now funds
  separate slashable collateral (`fundRelayerBond`), returned on every honest close and forfeited to
  the user — together with the escrow — on provable relayer equivocation (`slashRelayerEquivocation`,
  the symmetric mirror of user-slashing); liveness is deliberately not slashable. The incentive
  analysis is [`ECONOMICS.md`](./ECONOMICS.md); a six-lens adversarial review found zero findings.
  **✅ 2b-i (R_dec + ZK settlement) done:**
  **Circom + snarkjs Groth16/BN254**. `circuits/R_dec.circom` (~3.4k constraints) proves the
  decrement in ZK — two **Poseidon** commitments (seq++ structural), `B_{i+1}+cost===B_i`,
  **64-bit range checks on `B_i`/`cost`/`B_{i+1}` all three** (the money-mint footgun), the
  freshness tag, the per-epoch rate nullifier, and the **`chan_id`↔`K_chan`** binding; **no
  in-circuit ECDSA** (attribution stays the out-of-band secp256k1 sig). **Commitment
  reconciliation:** `tessera-channel` gains a **Poseidon(BN254)** commitment — one commitment,
  proven in `R_dec` AND bound by the court's `ecrecover` over `keccak256(zk-domain ‖ poseidon-C)`,
  scoped to the ZK path so the cleartext 2c court stays SHA-256 + dependency-free (all pre-existing forge
  tests stay green, zero regeneration; `circuits/README.md` argues why this beats putting Poseidon
  on-chain). `ChannelRegistry.cooperativeCloseZK` verifies a Groth16 proof via the generated
  `RDecVerifier.sol` and settles **without a cleartext balance in calldata**. A **pinned proof
  vector is verified on-chain in CI** (no circom/snarkjs needed). *Rejected* arkworks and halo2 (as
  before). **Honest caveats:** does NOT hide the balance from the relayer (it knows it by
  construction); the private payout split needs the shielded pool; the dev ceremony is **single-party
  TEST-ONLY** (a real multi-party phase-2 ceremony is required, not faked). Funding-unlinkability
  is the next increment. **✅ M2 (Spilman watchtower) done:** `tessera-channel`'s
  `watchtower` module is the reactive safety component — it holds the highest
  doubly-signed state and, on observing a stale unilateral close, emits a
  `challenge` whose state provably satisfies the court's precondition
  (`seq > bestSeq`, `balance ≤ B0`, doubly-signed); the live RPC poll/submit
  wrapper is the documented operational layer. **Then:** the `ShieldedPool`
  (unlinkable funding, Solana→EVM port; reuse `cloaksdk`/`privacy-cash`) → relayer
  node → Sybil/credential (pay + PoP).
- **Phase 3 — Climb to ceiling.** Mode-switched PQ transport · coherent-persona fingerprint stack ·
  residential egress · PIR private-read tier · threshold issuance.
- **Research-track (before any "ceiling" claim):** cross-epoch SDA budget · accountable hostile-exit ·
  PQ credential migration.
- **Phase 4 — Harden + external audit** (the only thing that lifts "research-grade/UNAUDITED").

**Honest gates (flagged, never faked):** clean-IP exit (you) · audited ZK-channel rail · 3rd-party
audit · the browser deploy.

## 11. North star & Definition of Done (proposed goal)

> **North star:** *Make private, uncensorable access to the whole internet something you can simply
> pay for — anonymously, per request, unlinkable end-to-end — so being anonymous, or being a bot,
> stops meaning being blocked.*

**Done (provable, not vibes):** the engine loop runs end-to-end and a Tor-blocked site loads through
a clean exit privately (Phase 1); the ZK Spilman channel proves anonymous pay-per-request with
on-chain-slashable double-spend (Phase 2); privacy holds against the relayer (links in-channel
requests only — not identity/content/destination) **and this within-session linkability is measured
against the cross-epoch budget**; uses the SOTA primitives named here with no naive anti-patterns;
adversarially reviewed, CI-green, fuzzed; honest docs naming every limit. **Out of scope (so it can
be completed):** running a residential exit *network* at scale, a mainnet-audited rail, "winning" the
anti-bot arms race, real money/mainnet.

## 12. Honesty footer

~85% prior art; no new cryptographic primitive; the contribution is composition + the honesty about
what it does and does not buy. The single sentence a reviewer should *not* get to say first, because
we said it: **"you unified the payment rail beautifully and also unified the deanonymization
surface."** That surface — cross-epoch linkability — is the real frontier, and it is named, not
hidden. Research-grade, UNAUDITED; not for protecting real users until a third party says so.
