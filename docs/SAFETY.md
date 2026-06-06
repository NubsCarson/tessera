# Tessera — Safety, Responsible Use & Anonymity-Set Warnings (S20 + S30)

> For operators who run a Tessera node and for anyone deciding what to promise
> their users. Research-grade, UNAUDITED. This document does not relax anything
> in [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`ABUSE_MODEL.md`](./ABUSE_MODEL.md),
> or [`DEPLOY.md`](./DEPLOY.md); it states the operational and ethical posture
> those docs imply, and it ends with a blunt warning you must read before you
> tell any user they are "anonymous."

This is the "should you run it, and what may you honestly say about it" half of
the docs. The cryptographic guarantees live in `THREAT_MODEL.md`; the
resource-exhaustion surface lives in `ABUSE_MODEL.md`; the wiring lives in
`DEPLOY.md`. Read this one before you put a node on the public internet or hand
the proxy address to a user.

---

## 1. What the credential actually controls — volume, not content

A Tessera credential is a budget, nothing more. The guard's decision is
`OriginGuard::check` (`crates/tessera-origin/src/lib.rs:164`), which takes the
presentation header and **deliberately never reads the source IP** ("Source IP
is deliberately not an input. The decision rests entirely on the cryptographic
credential.", `lib.rs:162`). What that check proves, and all it proves, is:

- the presentation came from *some* credential validly issued under this key;
- the nonce is in `[0, limit)` (range proof); and
- this exact slot has not been spent before (the tag store).

It says **nothing** about *what* the request carries, *where* it is going, or
*who* the holder is. The credential gates the **number of requests** a holder
can make per context (`THREAT_MODEL.md` §2(d)), and it makes reuse of a slot
detectable via the tag (`THREAT_MODEL.md` §2(e)). It does **not** inspect,
classify, or filter the payload — by design the proxy tunnels TLS end-to-end and
never sees plaintext (`README.md`, "Reach any HTTPS site"). So:

> A valid credential means "a budgeted, accountable client," **not** "a
> well-behaved request." Abuse that fits inside the budget is still abuse, and
> the credential will admit it.

If you need content-level policy (malware, CSAM, fraud, spam), that is an
**application/operational** concern layered *on top of* admission — Tessera does
not provide it and does not claim to.

---

## 2. The exit egresses from *your* IP — that is operator responsibility

In the 2-hop loop the **exit makes the outbound connection to the destination
from its own IP**. `DEPLOY.md` states it plainly: "EXIT egresses from its own
IP — the IP the destination sees" (`docs/DEPLOY.md:29`), and the relay crate
docs confirm "the egress IP is external — no code removes that"
(`crates/tessera-relay/src/lib.rs:26-27`). Concretely:

- The destination, its logs, its abuse desk, and law enforcement see **your
  exit's IP**, never the client's. To the outside world, the traffic *is yours*.
- This is the same legal/operational position as running a **Tor exit relay** or
  an open forward proxy: you are the visible origin of traffic you did not
  author and cannot read.
- Tessera's IP-blindness is about **admission** (the guard ignores the client
  IP), not about shifting attribution away from the exit. The README says this
  directly: `"IP-blind" is about *admission*, not invisibility` — the
  destination still sees the proxy's egress IP.

If you run an exit, assume you will receive abuse complaints, takedown notices,
and possibly law-enforcement contact for traffic that egressed from your IP.
That is a deliberate choice you are making, not a bug.

### What the credential does and does not buy you here

- The per-egress-IP **human-volume shaper** (`VolumeShaper`,
  `crates/tessera-proxy/src/shaping.rs:106`, applied by `serve_observed_shaped`) paces
  admitted tunnels into a human-plausible envelope per egress IP. Its purpose is
  to keep a *clean* egress IP clean and to bound burst volume — it is a volume
  control, **not** a content filter and **not** an abuse adjudicator.
- The credential gives you *attributable rate-limiting* of clients: a misbehaving
  holder burns its budget and must re-earn issuance. It does **not** give you a
  way to attribute a specific request to a specific human (that is the whole
  point — see `THREAT_MODEL.md` §3.2).

---

## 3. Running a node responsibly — an operational checklist

Before exposing any node:

1. **Decide your issuance gate first.** Per `THREAT_MODEL.md` §4.3 / §6.3,
   `create_credential_response` issues to *anyone* whose request proof verifies.
   The issuance gate (`tessera-issuer`: PoW or ETH-paid mint) is "the real
   abuse-control lever." **PoW is a cost knob, not Sybil resistance**
   (`GOAL.md`, "Deliberately deferred") — an adversary with compute still scales,
   and it penalizes low-power clients. If you let anyone mint unlimited
   credentials, the rate limit is cosmetic and your exit will be abused at will.

2. **Make the tag store durable and consistent, or you have no rate limit.** The
   shipped default is in-memory and non-durable (`THREAT_MODEL.md` §5, §6.1); a
   restart or a second replica with its own set re-opens the double-spend window.
   Use the durable `FileTagStore`, or a shared store across replicas, and never
   prune live tags on a wall-clock timer (`ABUSE_MODEL.md` #6 — premature
   eviction silently re-enables over-presentation).

3. **Run over an anonymizing transport, or stop calling it anonymous.** The
   guard ignores the IP; the network does not (`THREAT_MODEL.md` §3.3, §6.4).
   "Tessera over a non-anonymous transport is not anonymous."

4. **Protect the server key like a MAC key.** Its compromise breaks
   unforgeability for *everyone* under that key (`THREAT_MODEL.md` §6.2). The
   issuer and exit share it (keyed verification; `docs/DEPLOY.md:34`); treat both
   hosts as holding a signing secret.

5. **Do not clone one key into many exits.** One `TESSERA_KEY_FILE` is one
   issuer+exit key domain. Independent exits need separate issuer/key files/key
   pins; otherwise any exit compromise forges credentials for the whole fleet and
   separate in-memory tag stores can admit the same presentation twice. The proxy
   now fails closed on a second local exit that reaches the same established key
   file inode, but architecture still matters across hosts and copied key
   material.

6. **Know your legal exposure.** Running an exit means egressing third-party
   traffic from your IP (§2). Understand your jurisdiction's intermediary/relay
   liability, logging obligations, and abuse-handling expectations *before* you
   start. A verifiable non-logging deployment (Intel TDX TEE via dstack,
   `docs/DEPLOY.md`) lets a client *attest* the node can't log — that nails the
   **trust** axis but does **not** change your egress attribution or your legal
   posture. A clean egress IP remains external (`docs/DEPLOY.md:156-162`).

7. **Mind the unauthenticated work surface.** The accept-and-parse layer runs
   before any credential check; the shipped accept-layer bounds are the
   `MAX_INFLIGHT` concurrency cap (`ABUSE_MODEL.md` #1) and the 30s socket
   read/write timeout (`ABUSE_MODEL.md` #2). (`ABUSE_MODEL.md` #3–#4 are
   separate internal map-growth caps — the `VolumeShaper.seen`
   distinct-destination cap and the channel per-epoch `seen_nonces` budget — not
   accept-layer bounds.) Proof verification on unauthenticated
   input (~120 EC ops) is irreducible — put a rate-limit/reverse-proxy budget in
   front of the expensive verify (`ABUSE_MODEL.md` #8). A sandbox cannot
   manufacture a production rate-limit appliance; you must.

---

## 4. ⚠️ Anonymity-set warning — in a sparse deployment it can collapse to ~1

This is the single most important thing to understand before you promise a user
anonymity, and the failure mode is **operational, not cryptographic** — the math
is working exactly as specified while the privacy evaporates.

Per ARC §7.3 (quoted in `THREAT_MODEL.md` §2(c)), the indistinguishability set
for the context-scoped presentation elements is

```
sum_{i=0}^{c} p_i[presentationContext]
```

where `c` is the number of credentials issued **under the same server key** and
`p_i[presentationContext]` is how many presentations credential *i* has made
**for that same `presentationContext`**. Two consequences follow directly, and
both bite in small deployments:

- **Anonymity is per `presentationContext`.** Presentations under different
  contexts are *not* in each other's set. The tag generator is derived from the
  context (`generatorT = hash_to_group(presentationContext, "Tag")`,
  `THREAT_MODEL.md` §2(e); `crates/tessera-arc/src/arc.rs:293`, yielding the tag
  `generator_t * (m1 + nonce)⁻¹` at `:299` — the tag-field doc comment at
  `:126` shows the same formula). Hand every origin — or worse, every user or
  every cohort — its own context and you have **partitioned the set by that
  context**.

- **The set grows only with credentials *and* per-credential volume.** A
  barely-used deployment offers weak anonymity *because the set is small*. This
  is a property of the formula, not a defect.

Put bluntly, **`THREAT_MODEL.md` §3.4 names this as the most realistic
deanonymization vector**: a malicious — or merely careless — operator who
"assign[s] per-user or per-cohort `presentationContext`s, or issue[s]
credentials sparsely, [can] make the §7.3 anonymity set as small as one." A
client **cannot detect this from the protocol alone**; it must trust (or
externally verify) your context policy and issuance breadth.

### Concrete collapse scenarios — do not ship these and call them anonymous

- **Few users.** If only a handful of credentials exist under your key, `c` is
  tiny; the set is at most everyone who holds a credential. With only ~5
  credentials under your key, the set is at most 5 — and only if all 5 present
  under the *same* context; per-user contexts collapse it toward 1 (next
  bullet).
- **Per-user / per-cohort contexts.** If each user (or small cohort) gets its own
  `presentationContext`, that user's presentations are only in a set with *its
  own other presentations under that context* — i.e. the set is **one
  credential**. Combined with timing, this is effectively a deanonymized stream.
- **A brand-new or low-traffic origin's context.** "A deployment that hands every
  origin its own context shrinks each set to the traffic of that one origin"
  (`THREAT_MODEL.md` §2(c)). A new origin with one active user is a set of one.

The issuance gate is also the **anonymity lever** (`THREAT_MODEL.md` §6.3): more
credentials and shared, coarse contexts give a *larger* set (better privacy,
looser abuse control); fewer credentials and per-user contexts give *tighter*
control but can shrink anonymity toward one. You are choosing a point on that
trade-off every time you set issuance volume and context granularity — choose it
on purpose.

---

## 5. What NOT to claim to your users

Match the repo's honest posture. Do **not** tell users any of the following,
because none of it is true of Tessera as shipped:

- ❌ **"You are anonymous."** You are anonymous only *within the §7.3 set for
  your context*, only against the *cooperating verifier*, and only if you reach
  the network over an anonymizing transport. In a sparse deployment that set may
  be ~1 (§4). Do not state anonymity without stating its size and its
  preconditions.
- ❌ **"Tessera hides your IP / your network identity."** It does not. Tessera
  provides **zero** network-level anonymity (`THREAT_MODEL.md` §3.3); IP/timing
  protection is delegated entirely to the transport (Tor). Over a non-anonymous
  transport it is not anonymous at all.
- ❌ **"The operator can't see what you do."** A cooperating origin *is* the
  keyed verifier and can correlate out-of-band metadata — timing, TLS
  fingerprint, the bare fact you hit a guarded endpoint (`THREAT_MODEL.md` §3.2,
  §4.5). The exit sees every destination you visit (`crates/tessera-relay/src/lib.rs`
  split-trust note); the credential hides *which client*, not *which destination*.
- ❌ **"Obtaining a credential is private."** The networked issuer learns the
  **client's source IP and the time of issuance** — issuance is a direct
  client→issuer connection (`THREAT_MODEL.md` §3.5). ARC issuance unlinkability
  means the issuer can't tie a credential to later browsing, but the *act* of
  getting one is visible unless the client reaches the issuer over Tor too.
- ❌ **"This defeats blocking / reaches any site."** It removes the *IP / Tor-exit*
  block for *cooperating* origins; it does **not** win the anti-bot arms race or
  force a hostile site (`README.md`, "What this is / what it is NOT"). Reaching
  IP-blocking sites still needs a *clean egress IP*, which is external
  (`docs/IP_EGRESS_IDEAS.md`).
- ❌ **"It's secure / production-ready / audited."** It is **research-grade and
  UNAUDITED**, best-effort (not audited) constant-time, and tracks IETF *drafts*
  that may change (`README.md`, "Security status"; `THREAT_MODEL.md` §5). There
  is **no post-quantum claim** — all security rests on classical discrete log
  over P-256 (`THREAT_MODEL.md` §4.4). **Do not use it to protect real users
  yet.**

### What you *can* honestly say

- "A cooperating origin admits this request on a budgeted, unlinkable credential
  instead of your IP, and cannot link it to your other requests **within the same
  context** — modulo the anonymity-set size and the quantum-DL caveat
  (`THREAT_MODEL.md` §2, §3.2)."
- "Network anonymity is whatever your transport (Tor) provides; Tessera adds
  none of its own."
- "This is a tested research artifact, not a deployed or audited network."

---

## Summary

Tessera gates **volume, not content**, and the **exit egresses from the
operator's own IP** — running one carries the same attribution and legal posture
as a Tor exit or open proxy. The decisive privacy risk is **operational, not
cryptographic**: in a sparse deployment — few users, few credentials, or
per-user/per-cohort `presentationContext`s — the ARC §7.3 anonymity set can
collapse to **one** (`THREAT_MODEL.md` §3.4), and the client cannot detect this
from the protocol. Choose issuance volume and context granularity deliberately,
make the issuance gate and tag store real, run over an anonymizing transport,
and never tell a user they are "anonymous" without naming the set size and the
preconditions. Tessera is research-grade and UNAUDITED — do not protect real
users with it yet.
