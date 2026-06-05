# Tessera — relayer-cheat matrix & honest-relayer atomicity

> **Status: research-grade, UNAUDITED, ETH-testnet-only.** This is the SHOULD-tier
> deliverable **S19** (relayer-cheat matrix, reconciled with the M1 bond) and
> **S22** (honest-relayer atomicity spec) from
> [`CEILING_PROGRESS.md`](./CEILING_PROGRESS.md). It scopes the **optional-advanced
> ZK Spilman channel tier** only — per [`ARCHITECTURE.md`](./ARCHITECTURE.md) the
> leaner default rail is ETH-paid `TokenMint` → blind-issued ARC tokens, which has
> no channel, no bond, and is out of scope here. This document does not introduce
> mechanism; it enumerates the relayer's misbehaviors against the code that already
> exists (`crates/tessera-channel`, `contracts/src/ChannelRegistry.sol`) and is the
> adversary-facing companion to [`ECONOMICS.md`](./ECONOMICS.md).

The channel is **unidirectional, monotone-decrementing, single-payee**: one payer
(the *user*) escrows `B0`; one payee (the *relayer*). `balance` is what still
belongs to the user, so the relayer is owed `B0 − balance`. `balance` is
**monotone non-increasing** (`is_successor_of` rejects only `self.balance >
prev.balance`, `state.rs:194`, so a zero-`cost` successor with an equal balance
is legal) while `seq` **strictly rises** (`spend` sets `seq + 1`, `state.rs:171`)
(`ChannelState::spend`, `state.rs:166`; `is_successor_of`, `state.rs:180`).
Every defense below is a consequence of that structure plus four load-bearing
protocol fixes (`lib.rs` "The corrected core"):
the user signs *every* state, sign-then-serve, proof-of-relay, and freshness
binding.

---

## 1. The cheat matrix

Each row is a way the relayer can deviate, the mechanism(s) that bound it, and the
**residual risk** that survives — stated honestly, because some of these are not
eliminated, only capped.

| # | Relayer misbehavior | What stops / bounds it | Where (code) | Residual risk |
|---|---|---|---|---|
| 1 | **Withhold service after taking the co-sign** (take the payment, never relay) | The relayer can only *claim* a spent unit at settlement if it can show a `RelayAck` proof-of-relay receipt for that state. No receipt ⇒ the unit is **not claimable**; the user gets `RefundUser`. The user also never advances past one in-flight decrement. | `settle` filters to states with a valid receipt (`settlement.rs:112`–`118`); no claimable unit ⇒ `RefundUser { user_refund: b0 }` (`settlement.rs:134`); on-chain `refundOnTimeout` returns full `B0` (`ChannelRegistry.sol:688`) | **Exposure is capped at one in-flight request's `cost`** — *not zero*. Fair exchange is impossible off-chain without a TTP (EGL / Pagnia–Gärtner), so serve-and-pay is **deliberately not atomic** (`relay.rs:9`–`15`). The receipt is a claim gate, not a delivery proof: a relayer can relay and *withhold the receipt*, forfeiting its own fee, which buys it nothing. See §2. |
| 2 | **Equivocate** (co-sign two different states at the same `seq`) | An honest relayer counter-signs exactly one state per `seq`. Two distinct relayer-signed states at one `seq` are an attributable on-chain fault: the **relayer's bond AND the full escrow** are awarded to the user. Provable from the relayer's key alone; a malicious user cannot fabricate it (it cannot produce the relayer's signature, and the digest folds in `chanId`). | `slashRelayerEquivocation` (`ChannelRegistry.sol:638`); `toUser = b0 + relayerBond` (`ChannelRegistry.sol:666`) | **Strictly negative-EV, by construction.** Because the channel is unidirectional+monotone, relayer equivocation can't *steal* the way a user double-spend can (the second signature is the *user's*, unforgeable) — so the bond here is symmetric-accountability + restitution, not a theft reserve. Residual = the off-chain "stale unilateral close" (row 3), which is a separate, non-equivocation path. |
| 3 | **Present a stale (lower-`seq`) state at close** (under-pay itself by settling at an older state where `balance` is higher) | Either party can start a unilateral close; it opens a fixed `CHALLENGE_WINDOW` in which the counterparty overrides with a **strictly-higher-`seq`** doubly-signed state. The user (or a delegated watchtower) submits the latest truth. | `unilateralClose` → `challenge` requires `state.seq > ch.bestSeq` (`ChannelRegistry.sol:524`); `settleDispute` pays the highest seq seen (`ChannelRegistry.sol:538`); off-chain decision core `Watchtower::on_dispute_started` (`watchtower.rs:147`) | **Liveness-dependent, not provable.** You cannot prove from-chain that a newer state exists, so this is *not* slashable. If the disadvantaged party is **offline for the entire window**, the stale state settles. The defense is the watchtower being online within `CHALLENGE_WINDOW` (1 day, `ChannelRegistry.sol:108`); the **live polling/broadcast wrapper is out of scope** (`watchtower.rs:30`–`35`). |
| 4 | **Over-charge** (co-sign a decrement larger than the user authorized, or claim a balance lower than the user signed) | The relayer never *originates* a state — the **user** builds and signs `S_{i+1}` (`UserChannel::spend`, `channel.rs:140`). The relayer can only co-sign the exact bytes the user signed; the on-chain court and `settle` only count *doubly-signed* states, so any state the relayer "charges" at must carry the user's own signature over that balance. | User signs the state digest (`channel.rs:147`); `is_doubly_signed` gate (`state.rs:239`); the court requires a valid user sig at every path that pays the **relayer** (`cooperativeClose` recovers both sigs, `ChannelRegistry.sol:357`; `settleDispute` pays out only doubly-signed states, `ChannelRegistry.sol:538`). The signature-free payout, `refundOnTimeout`, pays the *user* the full `B0`, not the relayer, so it is not part of the charge surface. | **None beyond the freshness binding.** The relayer cannot unilaterally inflate the cost — the worst it can do is *refuse* to co-sign (row 1) or equivocate (row 2). A relayer that fabricates a higher-charge state has no user signature for it, so it is uncountable. |
| 5 | **Replay a spend** (reuse the user's spend bytes against a different request / second time) | The user folds a relayer-supplied `(epoch, nonce, request_hash)` into a *freshness* signature (`sig_fresh`). The relayer accepts a spend only if `epoch` matches, the `nonce` is unconsumed this epoch, **and** `sig_fresh` verifies over that exact freshness; it then **burns the nonce**. A replay carries stale freshness or a consumed nonce. | `RelayRequest` binds `request_hash` (`relay.rs:46`–`52`); `verify_and_cosign` freshness checks + nonce burn (`channel.rs:308`, `:326`–`:339`); `spend_message` (`relay.rs:76`) | **Bounded by the per-epoch nonce budget.** `seen_nonces` is capped at `MAX_NONCES_PER_EPOCH = 1024` (`channel.rs:24`, `:316`) to prevent a *memory-exhaustion* DoS, after which the client must wait for `advance_epoch` (`channel.rs:363`). Replay itself gains the relayer nothing — note replay is a *user/3rd-party* attack the relayer defends against, listed here for completeness of the wire surface. |
| 6 | **Go dark / refuse entirely** (stop responding after open, with no advance) | If the relayer never produces a doubly-signed state beyond genesis, the user recovers its **full escrow** after the timeout. The relayer's bond is **returned** (going dark is not a provable fault). | `refundOnTimeout` (`ChannelRegistry.sol:688`); off-chain `Verdict::RefundUser` (`settlement.rs:130`–`134`) | **Liveness is deliberately not slashable** ([`ECONOMICS.md`](./ECONOMICS.md) §4): slashing on suspicion would punish a network partition or a censored victim. The relayer's only penalty is **lost future fees** (reputation), not its collateral. The user loses nothing but time. |

### What is *not* a relayer defense and must come from elsewhere

- **Anonymity of the user toward the relayer** is the transport's job (Tor/Nym),
  not the channel's — the channel only governs *money*, never *who* the payer is
  ([`ECONOMICS.md`](./ECONOMICS.md) §9; [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3.3).
- **A non-forking linear rollback by the user** (re-presenting an *older*
  doubly-signed state, not forking) produces no attributable object and is handled
  by the same dispute-window mechanism as row 3 — symmetric, and explicitly a
  documented limit (`settlement.rs:20`–`24`, `lib.rs` "Honest limits").

---

## 2. Honest-relayer atomicity — what "sign-then-serve" guarantees (S22)

"Sign-then-serve" is the **ordering invariant**: the relayer
`verify_and_cosign`s the user's `S_{i+1}` and hands back the **doubly-signed**
state *before* it forwards the request; the user's `serve` is gated on that
co-signature being present and valid (`channel.rs:191`–`199`; tested by
`serve_before_cosign_is_rejected`, `tests/protocol.rs:339`). The crate models the
two parties as *separate* types exchanging messages precisely so this ordering is
enforceable rather than assumed (`channel.rs:1`–`9`).

### What it DOES guarantee

1. **The user never authorizes a serve on an uncommitted state.** A `Served`
   marker can only be produced from a state carrying the relayer's valid
   co-signature; a not-yet-co-signed spend is rejected with `NotCoSigned`
   (`channel.rs:192`). So if the relayer is going to forward at all, it has
   *already* committed cryptographically to the new balance.
2. **Every paid state is attributable to both parties.** The user signs the
   chain-facing digest of *every* state (`channel.rs:147`), and the relayer
   co-signs the *same* digest (`channel.rs:341`). Settlement and the on-chain
   court only ever count doubly-signed states (`state.rs:239`;
   `settlement.rs:90`–`93`), so neither party can be charged at a state the other
   did not sign.
3. **The relayer's claim is contingent on a relay receipt.** A unit only counts
   toward the relayer's payout if it can show a `RelayAck` for that exact state
   commitment (`is_valid_for`, `relay.rs:117`; used at `settlement.rs:116`). An
   honest relayer issues the receipt *after* forwarding (`relay.rs:99`–`112`), so
   "get paid" and "actually relayed" are aligned for the honest party.
4. **The user's worst-case loss is one in-flight request's `cost`.** The user
   authorizes exactly one decrement at a time and only advances its cursor on the
   returned co-signed state (`accept_cosigned`, `channel.rs:169`). A spend the
   relayer never co-signs leaves the user on the last doubly-signed state
   (`channel.rs:137`–`139`).

### What it explicitly does NOT guarantee

1. **It is not atomic fair exchange.** Sign-then-serve does **not** make
   "the packet was delivered" and "the relayer can claim payment" a single
   indivisible step. Off-chain fair exchange without a trusted third party is
   impossible (Even–Goldreich–Lempel; Pagnia–Gärtner), and the crate says so and
   does not pretend otherwise (`relay.rs:9`–`15`). The co-signature commits the
   relayer to a *balance*, not to *having forwarded bytes to the destination*.
2. **The `RelayAck` is a claim gate, not a delivery proof.** It is a relayer
   self-signature over a state commitment (`relay.rs:106`). It proves the relayer
   *chose to make the unit claimable*; it does not prove the destination received
   anything. Its security value is purely economic (the withholding-is-unprofitable
   argument is row 1 + item 2 above): no receipt ⇒ no claim, and the user's exposure
   is capped at one request (`tests/protocol.rs:231`,
   `withholding_without_receipt_refunds_user`). It is the off-chain stand-in for
   the HOPR ticket / Groth16 proof π of the full design (`relay.rs:9`, `lib.rs`).
3. **It is one-sided commitment, not mutual escrow of the message.** Between the
   user's `spend` and the relayer's `verify_and_cosign` there is a window where the
   user has revealed a signed decrement and the relayer has not yet committed. The
   relayer can decline to co-sign with no penalty (it has no receipt to claim
   with, and the user has not advanced). This is the intended asymmetry — the user
   is protected (its cursor doesn't move), and the *unserved* exposure is bounded,
   not zero.
4. **It says nothing about liveness or the dispute window.** Sign-then-serve is an
   ordering rule on a *single* round trip. A relayer that co-signs honestly and
   then goes dark (row 6) or later tries a stale close (row 3) is outside this
   invariant's scope — those are handled by `refundOnTimeout` and the
   `CHALLENGE_WINDOW` respectively.

---

## 3. Reconciliation with the M1 relayer bond ([`ECONOMICS.md`](./ECONOMICS.md))

The bond and sign-then-serve secure **different** faults, and conflating them is
the overclaim this section exists to prevent.

| Fault class | Bounded by | Bond's role |
|---|---|---|
| **Withholding** (rows 1, 6) — the *dominant* relayer threat | sign-then-serve + proof-of-relay + `refundOnTimeout`, to ≤ one in-flight request | **None.** The bond does not bound withholding at all — withholding is not provable on-chain, so it is not slashable. The user is protected by channel *structure*, independent of the bond. |
| **Equivocation** (row 2) — provable on-chain | `slashRelayerEquivocation` burns the bond + full escrow to the user | **Direct.** This is the bond's keystone use: symmetric accountability (the user's escrow was already slashable for *its* equivocation via `slashEquivocation`, `ChannelRegistry.sol:573`) + user restitution. |
| **Stale close / rollback** (row 3) | the dispute window + watchtower | **None.** Not a provable fault. |

So, exactly as [`ECONOMICS.md`](./ECONOMICS.md) §5 states: **we do NOT claim the
bond secures the user's funds against the dominant relayer threat (withholding).**
The bond's honest roles are symmetric accountability, a Sybil/participation cost,
a user-recovery fund for *provable* relayer equivocation, and forward-compatibility
with richer (bidirectional / multi-payee) channels where relayer equivocation
*would* become profitable.

**Bond sizing is a client policy, not a court constant.** `ChannelRegistry`
enforces **no minimum** `relayerBond` (`open` documents this,
`ChannelRegistry.sol:259`–`263`; `fundRelayerBond`, `:319`). A routing client
SHOULD read `channels[id].relayerBond` and refuse an under-bonded relayer; the
recommended policy is `relayerBond ≥ V` (the value it intends to route, so a
provable equivocation is fully recoverable) plus an absolute Sybil floor
([`ECONOMICS.md`](./ECONOMICS.md) §6). M1 is a **per-channel** bond — sound and
testable, but capital-inefficient at scale; a per-operator shared stake is a
documented future axis with its own one-slash-many-victims allocation problem
([`ECONOMICS.md`](./ECONOMICS.md) §7).

---

## 4. Honest bottom line

The relayer cannot **steal** (it never originates a state; every state it can be
paid against carries the user's own unforgeable signature — row 4), cannot
**profitably equivocate** (negative-EV; `slashRelayerEquivocation` — row 2), and
cannot **profitably withhold** (rows 1, 6 above). What it **can** do, and what no
mechanism here fully eliminates, is: (a) withhold *one* request's service at the cost of its own
fee, leaving the user out one request's `cost`; and (b) attempt a stale unilateral
close that succeeds only if the disadvantaged party is offline for the entire
`CHALLENGE_WINDOW`. Both are documented, both are non-slashable by design (they are
not on-chain-provable faults), and the second is the residual that the watchtower
(decision core present, live wrapper out of scope) exists to close. This matrix is
research-grade and **unaudited**; no numbers here have been audited or deployed.
