# Tessera — economic model of the payment rail

> **Status: research-grade, UNAUDITED.** This document prices the incentives of
> the Phase 2 payment channel + on-chain court (`crates/tessera-channel`,
> `contracts/ChannelRegistry.sol`). All figures are *illustrative*; no fee market,
> token, or issuance mechanism is fixed here. It is the economic companion to
> [`DESIGN.md`](./DESIGN.md) §2/§6 and [`THREAT_MODEL.md`](./THREAT_MODEL.md), and
> it documents specifically what the **M1 relayer bond** does and — just as
> importantly — does **not** buy.

Tessera lets a client pay anonymously, per request, to reach any clearnet site
through a relayer it does not have to trust with its identity, destination, or
content.

> **Scope note.** This prices the **optional-advanced** ZK Spilman channel tier.
> Per [`ARCHITECTURE.md`](./ARCHITECTURE.md), the leaner **default** rail is the
> ETH-paid `TokenMint` → blind-issued ARC tokens (`tessera-issuer`'s paid mode),
> which needs no channel or bond; the analysis below covers the channel for when
> pay-as-you-go *with on-chain refund/dispute* is genuinely required.

For that channel tier, the money rail is a **unidirectional, monotone-decrementing
ZK Spilman channel**: one payer (the **user**), one payee (the **relayer**). This
doc is the "who can lose what, and why misbehavior doesn't pay" analysis.

## 1. The two stakes

| Stake | Who funds it | Where | At risk if… | Recovered by |
|---|---|---|---|---|
| **Escrow `B0`** | user, at `open` | `Channel.b0` | user equivocates (signs two states at one seq) | forfeited to the relayer (`slashEquivocation`) |
| **Relayer bond** | relayer, via `fundRelayerBond` | `Channel.relayerBond` | relayer equivocates (provably, on-chain) | forfeited to the user (`slashRelayerEquivocation`) |

`B0` is the user's prepaid balance **and** its slashable stake — the two are the
same coins, by design (the user's at-risk capital *is* what it prepaid). The
relayer bond is **separate, additional** capital the relayer locks. Before M1 the
court held no relayer stake at all; "bonded relayer" was a claim with nothing
behind it. M1 is the on-chain teeth.

## 2. Per-request economics (the steady state)

Each request is one channel decrement of `cost`:

1. The relayer issues a freshness challenge bound to the request.
2. The user signs `S_{i+1}` (balance −`cost`, seq +1) **and** the freshness
   binding.
3. **Sign-then-serve:** the relayer verifies and *co-signs before forwarding*,
   then serves, then issues a proof-of-relay receipt.
4. Settlement pays the relayer `B0 − balance` against the **highest-seq
   doubly-signed state for which it can also show a receipt**; cumulative, so one
   late receipt-less state is simply not claimable. **(Receipt-gating is a
   property of the *off-chain* settlement model, `settlement.rs`; the deployed
   on-chain `ChannelRegistry` settles on the highest doubly-signed `seq` and does
   *not* verify receipts — on-chain proof-of-relay is the future ZK `R_dec` path.
   See [`RELAYER_CHEAT_MATRIX.md`](./RELAYER_CHEAT_MATRIX.md) §2.)**

**What the user can lose in the worst case: one in-flight request's `cost`.** The
user authorizes exactly one decrement at a time and only treats a request as
served after the relayer has already committed (co-signed). If the relayer takes
the co-sign and then fails to deliver, the user stops advancing and settles /
refunds at the last good state. Fair exchange is impossible off-chain without a
trusted third party (Even–Goldreich–Lempel; Pagnia–Gärtner), so Tessera does
**not** make serve-and-pay atomic and does not pretend to — see
`crates/tessera-channel/src/relay.rs`. The receipt is the relayer's *claim gate*,
not a cryptographic proof of delivery; its economic job is that "take the
payment, refuse to relay" gains the relayer nothing it couldn't already take, and
the *unserved* exposure is capped at one request.

**What the relayer can lose:** if it goes dark after co-signing, the user invokes
`refundOnTimeout` and recovers `B0`; the relayer is paid only for states it can
claim. Going dark is **not** slashable (see §4).

## 3. Why misbehavior is negative-EV

| Fault | Who | On-chain provable? | Outcome | Net to attacker |
|---|---|---|---|---|
| User equivocation (two states, one seq) | user | yes (two user sigs) | escrow → relayer (`slashEquivocation`); relayer bond returned | user loses `B0`; gains nothing |
| Relayer equivocation (two states, one seq) | relayer | yes (two relayer sigs) | bond **and** escrow → user (`slashRelayerEquivocation`) | relayer loses bond; user made whole |
| Relayer presents a stale (lower-seq) state | relayer | no (can't prove a newer one exists from-chain) | user `challenge`s with the higher doubly-signed seq during the window | relayer gains nothing |
| Relayer withholds / goes dark | relayer | no (can't prove a missing relay) | `refundOnTimeout` returns `B0` to user, bond to relayer | relayer loses future fees only |
| User rolls back (presents old state) | user | symmetric to stale-state; latest doubly-signed seq wins | relayer challenges with the higher seq | user gains nothing |

The keystone: **relayer equivocation is strictly negative-EV.** Settlement only
ever counts *doubly-signed* states, and the second signature is the **user's**,
which the relayer cannot forge. So a relayer that signs two conflicting states at
one seq cannot turn either into a payout without the user's cooperation — it only
exposes itself to `slashRelayerEquivocation`. Conversely a user cannot fabricate
relayer equivocation: it cannot produce the relayer's signature, and the signed
digest binds `chanId`, so a relayer signature from another channel cannot be
replayed. (This was checked by a six-lens adversarial review; zero findings.)

## 4. Why liveness is deliberately not slashable

A relayer that simply stops responding has committed no *provable* fault — you
cannot prove a missing relay on-chain without an oracle, and slashing on
suspicion would let a network partition or a censored victim be punished as if it
cheated. So `refundOnTimeout` **returns** the relayer's bond and refunds the user
its escrow. The relayer's penalty for unresponsiveness is the **loss of future
fee revenue** (reputation / repeat business), not its collateral. Only
cryptographically-provable equivocation burns the bond. This is a deliberate,
honest scoping: the bond secures *attributable* faults, not liveness.

## 5. What the relayer bond actually buys (no overclaiming)

In this **unidirectional monotone** channel, the relayer cannot *steal* via
equivocation the way a user can double-spend — so the bond is **not** a
theft-prevention reserve sized against a specific attack. Stated plainly, its
real roles are:

1. **Symmetric accountability.** The court should not punish only one party for
   the identical provable misbehavior. Before M1, a user equivocation was
   slashable but a relayer equivocation was not — an asymmetry an adversarial
   reviewer would (rightly) flag. M1 removes it.
2. **Sybil / participation cost.** Locking capital per channel raises the floor
   on running many throwaway relayers, which matters once relayer selection and
   reputation exist.
3. **User-recovery fund.** If a relayer *does* provably equivocate, the user is
   made whole from the bond — it is the user's restitution, not just a deterrent.
4. **Forward-compatibility.** Richer channel types (bidirectional, multi-payee,
   or batched-settlement) make relayer equivocation genuinely profitable; the
   bond + symmetric slash is the primitive those will need. Building it now keeps
   the court complete rather than retrofitting fund-handling later.

We do **not** claim the bond "secures the user's funds" against the dominant
relayer threat. The dominant threat is **withholding**, and that is bounded by
sign-then-serve + `refundOnTimeout` to ≤ one in-flight request — independent of
the bond.

## 6. Bond sizing — a client policy, not a court constant

`ChannelRegistry` enforces **no minimum** `relayerBond`. This is intentional: the
court cannot know the right number (it depends on the value a given user routes,
the fee market, and the relayer's reputation), and hard-coding one would be
arbitrary. The court's job is to *hold, return, and adjudicate* the bond; sizing
is the routing client's job. Recommended client policy:

- **Recoverability:** require `relayerBond ≥ V`, where `V` is the total value the
  client intends to route through the channel before settling, so a provable
  relayer equivocation is *fully* recoverable.
- **Sybil floor:** also require an absolute minimum bond (independent of `V`) so
  spinning up relayers is not free.
- **Read it on-chain:** `channels[id].relayerBond` is public; a client SHOULD
  refuse to open or route through an under-bonded relayer. `open` documents this.

## 7. Per-channel vs per-operator stake (a design axis, documented)

M1 implements a **per-channel** bond: a relayer locks collateral for each channel
it serves. This is the sound, self-contained, testable unit for a per-channel
court, but it is **capital-inefficient** at scale — a relayer serving thousands of
channels must lock the bond thousands of times.

The capital-efficient alternative is a **per-operator shared stake** (as in RLN,
rollup sequencer bonds, restaking): one large deposit backs all of an operator's
channels, and equivocation on any one slashes the shared stake. Its cost is the
**one-slash-many-victims allocation problem** (how is a single bond divided among
many simultaneously-wronged users?) and a more complex registry. This is a real
future axis, not a defect of M1; it is recorded here so the trade-off is explicit
rather than rediscovered.

## 8. Not priced here (open / out of scope)

- **Dispute gas costs.** Unilateral close + challenge + settle cost gas; a
  rational party weighs that against the amount in dispute. A production court
  would add griefing-resistant gas accounting / partial fee-shifting.
- **The relay fee market.** What a relayer charges per byte/request, and how
  competition sets it, is a deployment concern, not fixed here.
- **The cross-epoch statistical-disclosure budget** — the genuinely-novel open
  research frontier (see `DESIGN.md` §9). It is an *anonymity* budget, not a
  monetary one, and is tracked separately.
- **Issuance / token.** There is none; the channel settles in the chain's native
  asset. Sybil-resistance of relayer *identity* is an application policy
  ([`THREAT_MODEL.md`](./THREAT_MODEL.md)).
- **Clean egress-IP supply.** A genuinely clean, residential-class egress IP at
  scale is the binding *external* cost of the whole system — one of the three
  irreducibly-external gaps no code can manufacture ([`CLAUDE.md`](../CLAUDE.md) /
  [`AGENTS.md`](../AGENTS.md)). Its acquisition/rotation economics are an
  operator/transport concern, deliberately unpriced here: Tessera prices
  *admission* and *relay*, not the IP supply underneath them.

## 9. Honest bottom line

M1 closes a real asymmetry (the relayer now has on-chain skin in the game) and
gives the user restitution for provable relayer equivocation. It does not, and we
do not claim it does, turn the relayer into a trusted custodian or make
withholding impossible — those are handled by the channel's structure
(sign-then-serve, one-decrement-at-a-time, refund-on-timeout), and by the
*transport's* anonymity, not by the bond. The numbers above are illustrative;
nothing here has been audited or deployed.
