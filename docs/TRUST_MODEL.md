# Tessera — Trust Model: why you (mostly) don't have to trust the exit

> Status: **research-grade, UNAUDITED.** This document answers one plain
> question — *"if my traffic leaves through someone else's exit, how do I know it
> isn't quietly saving a log of where I went?"* — and is honest about exactly
> where the answer is **math**, where it is **a promise**, where it is
> **verifiable**, and where it is **none of those yet**.
>
> It is the operator-trust companion to [`THREAT_MODEL.md`](./THREAT_MODEL.md)
> (the cryptographic threat model — read it first), [`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md)
> (who-runs-what / who-must-not-collude), [`OBSERVABILITY.md`](./OBSERVABILITY.md)
> (what the nodes actually emit), and [`DEPLOY.md`](./DEPLOY.md) §2 (the TEE
> deployment path). It does not soften anything any of them say.

---

## 0. The question, and the honest one-line answer

> *"How do I know the exit isn't logging where I went?"*

**You mostly don't have to — and where you still do, you have a choice between
spreading that trust or making it verifiable, each with a real, named cost.**

The reason is that Tessera is built so that **no single node ever holds enough to
deanonymize you**, and so that the one thing a node *could* log is already
**unlinkable**. A fully-malicious, fully-logging exit, run alone, *cannot* tie
your traffic to you. The residual — the one combination that *would* break you —
is narrow, named, and addressed two different ways below.

This doc walks the trust down in four layers, weakest-assumption first:

1. **What's already solved by the design** (§2) — unlinkability + split-trust cap
   what *any* logging operator can learn.
2. **The law of trust** (§3) — why a box's *owner* can never cryptographically
   prove *to a stranger* that it isn't logging, on hardware the owner controls.
3. **The verifiable paths, as designed** (§4–§5) — **neither is built yet (see
   §7)**: a vendor-rooted TEE (whose cost is that it's a datacenter box), and a
   non-TEE quorum/transparency lane (which would make a liar *provable*, not
   *impossible*).
4. **The honest ledger** (§6–§7) — what this means for a residential exit, and a
   flat list of everything we *could/should* do here but haven't, with why.

---

## 1. The shape of the system (one paragraph, so the rest makes sense)

A deployed Tessera path is **four roles** — client → issuer (to get a credential),
then client → **relay** → **exit** → destination for each request
([`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §1). The credential is an
**ARC token**: single-use, rate-limited, and **unlinkable** — two presentations
from the same client are not linkable to each other or to issuance, except under a
discrete-log break ([`THREAT_MODEL.md`](./THREAT_MODEL.md) §2). The split is
strict: the **relay** sees `{client, exit}` but never the destination or the
token; the **exit** sees `{destination, that a valid token was presented}` but
**never the client**; TLS is end-to-end so **neither sees content**. The "log"
question is really: *what can each of those boxes write down, and what does it cost
me if it does?*

---

## 2. What a logging operator can — and cannot — learn (the part that's already solved)

Two structural facts do most of the work here, **before any hardware or
attestation**:

**(a) The exit never sees you.** Its socket peer is the relay (or, in the
single-hop onion lane, a Tor rendezvous circuit) — never your address. So an exit
that logs *everything it can* logs the **destination** and **that some valid
anonymous token was spent** — not who. ([`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md)
§5; [`OBSERVABILITY.md`](./OBSERVABILITY.md) §1.)

**(b) The token it logs is unlinkable.** The presentation tag the exit records is
a fresh per-request nullifier; ARC's unlinkability means two tags from *your*
credential are not linkable to each other or back to issuance
([`THREAT_MODEL.md`](./THREAT_MODEL.md) §2c). So even a logging exit's record
is `{anonymous-token → destination}`, which it cannot tie to you, nor stitch into
"this one user's browsing history."

Put (a) and (b) together: **a logging exit, alone, is mostly toothless against
*you*.** It can build a destination history *for its own egress IP* (the
volume-shaper window is the only destination-side state, and it is RAM-only,
windowed, never persisted — [`OBSERVABILITY.md`](./OBSERVABILITY.md) §3), but it
cannot attach that history to a person.

The same logic, across every node:

| If this set logs / colludes | Can it deanonymize you (client ↔ destination)? | Why |
|---|---|---|
| **Exit alone** | **No** | sees `{destination, anon token}`, never the client |
| **Relay alone** | **No** | sees `{client, exit}`, never the destination or token |
| **Issuer alone** | **No** | sees your IP *at issuance*, but blind issuance hides which later credential is yours |
| **Issuer + Exit** | **No (linkage)** | same key domain already; blind issuance still hides issuance ↔ presentation. Payoff is *operational* (context-partitioning), not a crypto link — see [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3.4 |
| **Relay + Issuer** | **No** | relay's `{client}` ⋈ issuer's `{client IP at issuance}` — but neither holds `{destination}`, so still no client ↔ destination link |
| **Relay + Exit** | **YES** | `{client}` from the relay ⋈ `{destination}` from the exit — **the one boundary that must hold** |

(This is the collusion matrix of [`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md)
§6, re-read as "what if they keep logs.")

**So the entire residual trust question reduces to one line:** *don't let the relay
and the exit both log and share notes.* Everything below is about that one line.

Two more facts to be precise:

- **The shipped nodes emit no per-request logs at all** — not as a policy you set,
  but *structurally*: the relay literally never parses inside the tunnel (so it
  *cannot* print a destination), and the exit's peer is the relay (so it *cannot*
  print a client). Every `println!` on a **relay/exit/issuer node's** request path
  is a startup banner or a config error (the client proxy, on your own machine,
  additionally prints a cold-start onion-retry notice — harmless, since the client
  is the party already allowed to know its own route). This is walked line-by-line
  in [`OBSERVABILITY.md`](./OBSERVABILITY.md) §2/§4.
- **But "the shipped binary doesn't log" is the operator's promise, not your
  proof.** A malicious operator can run a *modified* binary that does. That gap —
  between "the open-source code doesn't log" and "*this running box* runs that
  code" — is the entire reason the rest of this document exists.
- **One client-IP exposure remains — and it is *not* at the exit.** Getting a
  credential is a direct client→issuer connection, so the **issuer** sees your IP
  at issuance (never tied to later browsing, by blind issuance). Hiding that too is
  delegated to Tor: *"the exit never sees you"* is not *"no node ever sees your
  IP."* See [`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §4 and
  [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3.5.

---

## 3. The law of trust: you cannot root trust in a box you own

Here is the uncomfortable, load-bearing fact, stated plainly:

> **A box's *owner* can never cryptographically prove to a *stranger* that the box
> isn't logging — on hardware the owner controls.**

The intuition: an attestation (a "this box is running exactly image X" receipt) is
only believable to a stranger if it's signed by a key **the operator cannot
possibly hold**. Think of a tamper-evident seal: it only proves anything if *you*
didn't print it. If you own the press, you can seal a "no-log" image or a
"logging" image with equal authenticity — your own seal can't bind *you*.

The only parties who can hold such a key are the ones who **design the hardware
root of trust and run its attestation/signing service** (fusing the secret in at
manufacture): **Intel** (TDX), **AMD** (SEV-SNP), **AWS** (Nitro), **Apple**
(Secure Enclave). It is that key custody + an unforgeable signing service they
control — not the act of fabrication, not the orchestration software, not the
datacenter — that the operator can never impersonate, and that turns *"trust me, I
don't log"* into *"verify the code."*

Consequences that follow directly, and that this project does not pretend around:

- **Orchestration software (e.g. dstack) does not create this root — it consumes
  it.** Porting such software to a new CPU does not give that CPU a vendor-rooted
  attestation it doesn't physically have. (Detail in §4.3.)
- **A box you own at home cannot be the stranger-trusted root**, no matter the
  software — because *you* hold the keys to it. (Detail in §4.3.)
- Therefore the verifiable-no-log property and the "I run it myself at home"
  property are **in tension**, and §4–§5 are the two honest ways to live with that.

---

## 4. Path A — a vendor-rooted TEE (verifiable *in principle*; **not built here**; a datacenter box)

This is the path the repo already documents ([`DEPLOY.md`](./DEPLOY.md) §2,
README "Run it yourself as a network (Docker / TEE)").

### 4.1 What it would give you (and what's actually built)

> **Up front:** this path is **not a working feature today.** What exists in-repo is
> the deployment wiring + a *reserved, fails-closed* key-sealing seam (§4.2, §7); the
> sealed-key provider and the client-side quote check are **not built**. Read the
> rest of §4.1 as the *design intent*, in the conditional.

Run the relay (and/or exit) inside an **Intel TDX** confidential VM with **remote
attestation** via **dstack**. A client *would then be able to* check a TDX *quote* —
signed up to Intel's vendor root — that the node is running *this exact open-source
image*, before routing through it. The "no-log" property *would* stop being a
promise and become **attestable**: the relay⟂exit boundary of §2 *would be* enforced
by *verifiable code*, not by operator goodwill. On such a deployment, dstack's
`--public-logs` *would* additionally publish the node's measurement and its
(banner-only) stdout for anyone to check — a dstack feature the path relies on, not
something Tessera ships an attested instance of today
([`OBSERVABILITY.md`](./OBSERVABILITY.md) §7).

### 4.2 The honest costs — three of them, none waved away
1. **It's a datacenter IP.** TDX runs on datacenter Xeons. Datacenter IPs are
   *more* likely to be blocked by the very sites this project exists to reach, not
   less ([`DEPLOY.md`](./DEPLOY.md) "Honest limits"). So the TEE strengthens the
   **trust** axis while *weakening* the **clean-egress** axis. "TEE **and** clean
   residential egress" is the ideal and the genuinely hard part.
2. **The sealed-key path is reserved, not shipped.** The intended design derives
   the ARC server key from the dstack **KMS** and seals it to the enclave so it
   never touches disk. Today the `TESSERA_KEY_PROVIDER=dstack-kms` provider is
   **explicit but fails closed** until a real KMS client is implemented
   ([`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) §3, [`DEPLOY.md`](./DEPLOY.md)
   §2, [`NEXT_STEPS.md`](./NEXT_STEPS.md)). **Do not read this section as "Tessera
   has working TEE key sealing" — it does not yet.** What exists is the deployment
   wiring and the reserved seam; proving real sealing/attestation needs a live TDX
   environment.
3. **You're now trusting Intel.** Attestation moves trust from the operator to the
   *silicon vendor and its attestation service*. That's a real, smaller, and
   widely-accepted trust assumption — but it is not zero, and it is "under TDX/dstack
   attestation assumptions," which include the TEE not being broken. This isn't
   specific to Intel: *every* vendor-rooted TEE replaces trust-in-the-operator with
   trust-in-the-vendor and its attestation service (TDX → Intel, SEV-SNP → AMD,
   Nitro → AWS). Attestation **relocates** trust to a smaller, widely-accepted root;
   it never reduces it to zero.

### 4.3 Why "just port dstack to ARM / use a Raspberry Pi" does **not** fix this
A recurring and reasonable hope is: make the confidential-compute software run on a
cheap ARM board at home, and you'd get residential IP **and** attestation. It does
not work, for hardware reasons, not software ones:

- **dstack consumes a hardware root; it doesn't create one.** It fetches the
  chip's signed quote and forwards it. Porting it to ARM is "writing a new valet
  for a different building" — it cannot install a vault the building lacks.
- **ARM's own confidential-compute answer (CCA / Realms) needs ARMv9** silicon with
  the Realm Management Extension — datacenter-class ARM, not a hobby board. Common
  Raspberry Pi SoCs are older ARMv8 and have **no Realms at all** (and Realm
  attestation is itself rooted in a silicon-vendor-provisioned per-SoC key — so even
  ARMv9 CCA is a vendor-rooted *datacenter* box, never an owner-rootable one).
- **A stock Raspberry Pi has no owner-resistant root**: no secure enclave, its boot
  OTP holds a *public-key hash* (for verifying signed firmware), not a
  **vendor-attested per-device secret**, and code running as root can read it. Its
  secure boot — when even enabled — defends against an *outside* attacker swapping
  firmware, **not against the owner**, who holds the signing key and root.
- **Even a "real-TEE" ARM board (e.g. NXP i.MX-class, with a fused per-die key +
  secure boot) is owner-provisioned**: the operator fuses the **hash of their own
  public root key** into the device and signs images with the matching private key
  they hold, so secure boot certifies *whatever image the owner signed* — including
  a logging one. The fused key stops *outsiders* from extracting secrets; it does
  **not** stop the *operator*, who is exactly Tessera's adversary here. There is no
  silicon-vendor-held provisioning key (the property TDX/SEV/Nitro have) for the
  owner to be unable to forge.

**Net:** an ARM port of confidential-compute software would only help *datacenter
ARM* (ARMv9 CCA servers) — still a vendor-rooted datacenter box, still not your
home Pi. The residential-attestation gap in §3 is a fact about *manufacturing and
who holds the keys*, not a software feature anyone can toggle on.

---

## 5. Path B (as designed) — a non-TEE quorum / transparency lane (provable liar, not impossible one)

When the box can't be vendor-rooted (the residential case), you *could* still raise
trust a lot *without* a TEE — not to "cryptographically impossible to log," but to
"**a liar *would* get caught, provably, and a logging minority *would be*
outvoted**" — once such a quorum exists, **which it doesn't yet (§7)**. This is the
design pattern **demonstrated elsewhere** by transparency-log systems and
multi-prover "proof-of-restraint" devices; the primitives are established, but
**none of it is built in Tessera yet (§7).** The lane *would* compose them as
follows:

1. **Reproducible no-log image + published measurement.** Build the node
   reproducibly and publish the image hash, so the *code that is supposed to run* is
   open and auditable. (Doesn't prove a given box runs it — see the limit below —
   but pins the target everything else checks against.)
2. **Append-only transparency log of node measurements/attestations** (RFC 6962
   style). A node that ever serves two different stories about what it runs is
   **provably caught** by anyone, without a trusted third party. This kills *silent*
   equivocation, which is how a dishonest operator would otherwise show auditors one
   image and users another.
3. **Multi-operator / multi-prover quorum.** Require independent parties to agree
   (this is just the relay⟂exit non-collusion of §2, made explicit and plural). A
   logging *minority* is outvoted and learns nothing useful, because no single
   colluding pair holds both halves of the split.
4. **(Where it applies) ZK-of-computation.** A zero-knowledge proof can show *what
   a node computed* without trusting its hardware. This is powerful for a **bounded
   claim** ("the detector only fired on the one input") — but note its sharp limit
   for *this* use case in the box below.

> **Why the ZK leg helps a microphone more than it helps an exit.** Proving *"I
> only ran this fixed function and output this"* is a **bounded, positive**
> statement a ZK circuit captures well. Proving *"I forwarded your bytes and did
> **not also** secretly copy them somewhere"* is a **negative about an open-ended
> session** — the absence of a hidden side-effect — which ZK does not naturally
> cover. That asymmetry is exactly why "didn't log" leans back toward hardware
> (a TEE whose encrypted memory + fixed image *can't* write a log), and why the
> quorum/transparency lane is a trust-*raiser*, not a trust-*proof*, for an exit.

**Honest limits of path B.** It does **not** hand a stranger a cryptographic
"this box did not log" proof. It (i) makes the intended code auditable, (ii) makes a
caught liar provable, and (iii) reduces the trust to "the whole quorum isn't
colluding." That is meaningfully stronger than a bare promise and meaningfully
weaker than a vendor-rooted TEE — and it is the *right* tool for a residential
exit, which can't offer the TEE anyway. The operator-*discovery* layer that would
pair with this (publishing/finding attested or quorum-backed nodes without a
central directory) is sketched, parked, as [`ROADMAP.md`](./ROADMAP.md) E-a
(ERC-8004 validation registry) and E-c (this lane).

---

## 6. What this means for a residential exit (the "run it at home" box)

A residential exit's value is its **clean IP** — the thing that actually reaches
sites which blocklist Tor/datacenter ranges. It is *good at exactly the thing the
TEE box is bad at*, and bad at exactly the thing the TEE box is good at. So:

- **Don't ask a home box to prove it isn't logging via hardware** — it structurally
  can't (§3, §4.3). Asking it to is chasing a property the silicon can't provide.
- **Do lean on §2 + §5 for it:** unlinkability already caps a logging exit's reach
  to "anonymous-token → destination, never you"; independent relay/exit operators
  cover the one boundary that matters; a reproducible image + transparency log make
  a dishonest home operator *catchable*.
- **The mixable end-state:** residential exits for *reach*, optional TDX/Nitro
  attested exits for users who want the *hard* no-log guarantee, both advertised
  through the signed directory ([`DEPLOY.md`](./DEPLOY.md), `tessera-directory`).
  Each user picks their own point on the reach-vs-verifiability tradeoff. No single
  box has to be both.

---

## 7. The honest ledger — what we *could/should* do here but haven't

Nothing below is built today; each is named with *why not yet* and *what would
close it*. (Consistent with [`NEXT_STEPS.md`](./NEXT_STEPS.md) and its guardrails.)

| Item | Status | Why not yet / what would close it |
|---|---|---|
| **dstack KMS key sealing** (`dstack-kms` provider) | **reserved, fails closed** | Needs a live Intel TDX + dstack/KMS environment to implement and prove real sealing; the wiring + reserved seam exist ([`DEPLOY.md`](./DEPLOY.md) §2). |
| **Client attestation-verification UX** (check a TDX quote before routing) | **not built** | Same external dependency (a TDX host to attest against). Today it's a documented deployment step, not a shipped client flow. |
| **Reproducible-build attestation** of the node image | **not wired** | Pin a reproducible image + publish its measurement; needs a build-and-publish pipeline. Foundational to path B. |
| **Transparency log of node measurements** (RFC 6962-style) | **designed here, not built** | Needs a log service + ≥1 honest witness; only meaningful once >1 operator exists. |
| **Multi-operator quorum** (relay⟂exit as plural independent parties) | **single-operator today** | Needs a real independent operator set — an *external* hand-off, not local code ([`NEXT_STEPS.md`](./NEXT_STEPS.md)). |
| **Attested/quorum-backed node discovery** (ERC-8004 registry) | **parked** | [`ROADMAP.md`](./ROADMAP.md) E-a — meaningless until there's more than one node to choose between; user-side identity must never be put on it. |
| **Owner-resistant attestation on a *residential* box** | **not possible on commodity hardware** | A fact about silicon + key custody (§3, §4.3), not a TODO. Only a vendor-rooted (datacenter) TEE, or hardware that doesn't exist for this at home, would change it. |
| **Third-party audit · clean IPs at scale · a real anonymity crowd** | **external** | The standing irreducible gaps no code closes ([`THREAT_MODEL.md`](./THREAT_MODEL.md) §5, README "What this is NOT"). |

---

## 8. Bottom line

- **You mostly don't have to trust the exit.** It never sees you, and the token it
  *could* log is unlinkable — a logging exit alone cannot tie traffic to you (§2).
- **The one combination that would break you** is the relay *and* the exit both
  logging and colluding. That's the whole residual (§2).
- **You cover that residual two ways:** *spread* it across independent operators
  (split-trust, §2/§5), or *verify* it with a vendor-rooted TEE (§4) — which is a
  **datacenter** box, so it trades away the clean residential IP, and whose
  key-sealing is still **reserved/fails-closed**, not shipped.
- **A box you run at home can never hardware-prove it isn't logging** (§3) — so it
  leans on unlinkability + independent operators + a reproducible image and
  transparency log that make a liar *provable* (§5), not on attestation it can't
  give.
- **None of this is audited.** The candor *is* the point. Deploy it for real users
  only after the external gaps in §7 close.
