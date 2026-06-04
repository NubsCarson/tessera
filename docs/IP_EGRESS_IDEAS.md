# Clean Egress for Tessera — the IP-problem ideas portfolio

> The hardest, most fundamental part of [`DESIGN.md`](./DESIGN.md) §9: to reach a
> site that judges by IP, the destination must see a **clean, non-blocklisted,
> normal-looking** IP — no cryptography removes that. This doc is the honestly-
> assessed *portfolio* of ways to get it, from a multi-angle, adversarially
> red-teamed, web-grounded pass (mid-2026). **Research-grade; no silver bullet.**

## 1. The honest framing: there is no silver bullet

Clean egress is **not one problem** — it's a set of site-classes, each beaten by a
different mechanism, and **no single approach covers more than a slice.**

**Clean IP is necessary but NOT sufficient.** The 2025–26 anti-bot frontier
(Cloudflare Bot Mgmt, Akamai, DataDome, HUMAN) decides on **IP reputation + JA4
TLS fingerprint + HTTP/2 frame order + behavioral ML + attestation**. DataDome
publicly killed a 100k-IP / 80-country residential-proxy attack on a *shared TLS
fingerprint alone*, perfect IP diversity notwithstanding. An IP fix wins the IP
layer and then hits the fingerprint layer.

**Tessera's actual edge — make it the spine, not a footnote:** because the exit
is a **dumb byte-transport carrying the client's *real* end-to-end TLS**, the
client's *genuine* browser/agent JA4 + behavior reach the destination untouched.
**Genuine residential/mobile IP + genuine client TLS is the single hardest
combination for anti-bot to flag.** That property — not any one IP trick — is the
edge.

**Different site-classes need different doors:**
- *Read-only popular content* (Wikipedia, package registries, docs, map tiles,
  chain RPC) → **don't egress at all**; serve/verify it (PIR mirror, content-
  addressing, light-client proofs).
- *Self-syndicating sites* (oEmbed/RSS/sitemap/JSON-LD, declared-crawler paths) →
  walk through the door they hold open.
- *Paid-API / agentic-commerce* (x402) → **pay**; you're a wanted customer.
- *Cooperating origins* (Privacy Pass / PAT) → present an unlinkable credential;
  IP stops mattering.
- *Hardened, web-only, IP-blocking consumer/login sites* (the hard core) → only a
  small pool of genuinely non-blocklisted exits **+ the client's real TLS**, at
  human volume.

The honest envelope — **"most of the web at human volume"** — is *deliverable*,
but only as the **sum of these lanes, with the hard core explicitly bounded.**

## 2. Ranked portfolio

Ranked by *(durability × coverage × ethics × composes-with-Tessera)*.

| # | Idea | How it works | Reaches | Honest durability / ethics |
|---|------|--------------|---------|----------------------------|
| 1 | **Per-IP human-volume *shaping* as a network-wide invariant** | distinct-destination cap + concurrency + jitter + sticky-session, metadata-only — every exit behaves like one household, killing Cloudflare's *confirmed primary* proxy tell ("one IP hits thousands of unrelated domains") **at the source** | all IP-based defenses, on any IP it rides | **Highest** — durable *because of why it works*, not until-adapted. Ethics-positive (a sharer can bound + prove exposure). The rare case where "honest" and "evade" are the **same action**. |
| 2 | **PIR private mirror + verifiable fetch** (SimplePIR/Tiptoe; content-addressing/SRI; **Helios light-client proofs** for chain RPC) | don't reach the destination — serve read-only bytes query-privately, or verify any-source bytes by hash/consensus | Wikipedia, npm/PyPI/crates/apt/Docker, docs, OSM, **all chain RPC** — ~20–40% of read/agent volume | **Arms-race-immune** (no destination to block). Cleanest ethics. Caps: curated low-TB corpora, freshness lag. **Sheds load off the scarce exit pool.** |
| 3 | **First-party "green" routing** (oEmbed/RSS/sitemap/JSON-LD + declared/signed-crawler paths via Web Bot Auth) | hit the door the site holds *open* for indexing/embedding, not the hardened frontend | consumer sites that syndicate (social, news, marketplaces, video, maps) | **Structurally durable** — the site can't block without self-deindexing. ~zero clean IPs. Serves the bot-visible representation, not arbitrary logged-in pages. |
| 4 | **ARC-as-Privacy-Pass** (our ARC/P-256 redeemed via RFC 9577; **PAT** as multiplier) | origin authorizes on an unlinkable, rate-limited, paid-up *token*, not the IP — Tessera *defines the winning condition* | cooperating origins (Cloudflare/Fastly ship the plumbing) — tiny today, architecturally perfect | **Ends the arms race where adopted.** Most-native to our stack. Bottleneck = adoption, not resources. |
| 5 | **CGNAT / mobile-carrier egress** (genuine multi-tenant shared IP; ZK per-user cap) | a destination can't hard-block a shared carrier IP without nuking paying subscribers (Cloudflare *itself* softens CGN aggression — verified ~3× rate-limited but far less *blocked*) | top-tier consumer sites; the hardest IP-blockers | **Strong but CONDITIONAL** — softening only attaches to IPs already classified as carrier-CGN; needs a **real eyeball-ISP partnership** (a BD bet, not a multiplexing trick). |
| 6 | **IPv6-first, stable /64-per-credential** (RIR-allocated, RPKI-signed) | looks like real residential eyeball space; no shared-fate poisoning | dual-stack destinations on rate gates | **Durable supply** (v6 cheap/abundant/clean, escapes the IPv4 blocklist trap). Only helps dual-stack; orthogonal to JA4. |
| 7 | **x402 pay-the-destination** (client buys egress quota over the ZK channel; exit relays a client-authorized `X-PAYMENT`, **never terminates TLS**) | you're a *wanted customer* — nothing to block | x402-speaking paid-API / agentic endpoints (~165M tx, ~$50M cum. by Apr 2026) — **not** DataDome-guarded HTML | **Arms-race-immune.** Ethical (pay the rightsholder). Orthogonal to the IP wall — additive reach. |
| 8 | **AIPREF policy brain** (read robots/AIPREF/x402 price → pay where priced, token where wanted, **stand down where access isn't for sale**) | the routing/compliance + **reputation** layer that makes 7/4 honest | all destinations, as a decision layer | **Not an arms race** (voluntary). The reputation asset that could later get Tessera allow-listed. Honest tension: it will tell you to *stand down* on some targets. |
| 9 | **Snowflake-style relay/exit split** | peers relay anon-wrapped bytes (entry censorship-resistance + ~100k ephemeral IPs); a vetted minority exits | same web the exit pool reaches | **Entry transport, NOT the egress fix** — relays add zero clean-*egress*. Reframe as entry plumbing. |

## 3. Build-now vs bets vs traps

**Build now** (feasible, ethical, compose cleanly): #1 shaping (highest-ROI, pure
metadata policy on the existing credential — ship first) · #2 PIR + **Helios
verifiable RPC** (promote out of the footnotes; makes source-IP irrelevant for a
dynamic real-money workload) · #3 green routing · #4 ARC→RFC 9577 redemption
(mostly already in our stack) · #8 AIPREF brain (to the **vendor-neutral IETF
AIPREF vocab**, not Cloudflare's interim Content-Signals) · #9 relay/exit split as
the **entry** invariant, with a global hard deny-list + per-exit SNI allowlist as
a non-negotiable default.

**Bets** (higher ceiling, gated on others): carrier-CGNAT partnership (#5, a BD
bet with a carrier kill-switch) · IPv6 backbone (#6) · client-driven x402 (#7 —
*never let the exit terminate TLS to inject payment*) · PAT multiplier (#4, supply
hard-capped by Apple's per-device limits) · Web-Bot-Auth allow-listing (needs
explicit Cloudflare/DataDome buy-in; present as the honest "Tessera-Egress"
operator, **never forge per-operator identities**).

**Traps** (sound appealing, don't work):
- **"Just rotate clean residential IPs" as the whole answer** — necessary, not
  sufficient (JA4 + behavioral ML catch the request after the IP gets through).
- **Browser-native "organic" egress framed as Snowflake** — it is **not**
  Snowflake (real Snowflake never exits to destinations). Making a volunteer's
  home IP the destination-facing exit is a consent-washed residential-proxy
  network (the PROXYLIB/Urban-VPN model the FTC actioned) that dumps real legal
  exposure on a private person. Consent UX doesn't remove the 4am-knock liability.
- **Shielded-payment ("z402") egress** — narrower reach than plain x402, least-
  mature rail, and an anonymizing relay paying from a shielded pool at scale is a
  textbook unlicensed-money-transmitter/mixer profile. (The "Zcash Foundation
  declined a grant Feb 2026" detail surfaced in research is **unverified — do not
  repeat as fact.**)
- **Refraction networking (Conjure/TapDance) for egress** — egresses from the
  station's *fixed known* IP → zero clean-egress value. It's a censored-client-to-
  entry transport, full stop.
- **AMP / Google-cache / SXG soft surfaces** — Google Cache removed Sept 2024;
  Cloudflare dropping AMP-cache/SXG from Oct 2025. SXG is dying. Keep content-
  addressing/SRI as the durable static path instead.
- **Gray private-mobile-API replay** — legally hostile (CFAA + DMCA-1201 + ToS;
  *hiQ paid $500K and lost* on contract/trespass). Not a default.
- **A treasury "liability backstop" for anonymous buyers** — a post-hoc treasury
  doesn't deter the marginal abuser or un-raid a house. Be honest: the residential
  sharer's real-world liability is **irreducible**, only rate-limited + revocable.

## 4. The single smartest under-the-radar idea to prototype

**Per-IP human-volume shaping, elevated to a network-wide invariant, decoupled
from the underlying IP type** (#1 as a standalone primitive). It's the **only
mechanism in the portfolio durable *because of why it works* rather than *until
the adversary adapts*.** Cloudflare's confirmed primary residential-proxy tell is
*one IP hitting thousands of unrelated domains in unrealistic ways*; a hard per-IP
**distinct-destination cap + concurrency + jitter + sticky-session**, computed on
metadata only, **removes that signal at the source** — the egress genuinely
behaves like one household because Tessera made it.

Why it's the smartest prototype: it's **the same action for "do the honest thing"
and "evade detection"**; it composes perfectly with content-blindness (metadata-
only, no TLS termination); it applies to **every** IP lane (a cross-cutting
multiplier); it operationalizes the honest envelope *at the protocol level*; and
it **degrades gracefully** (a too-busy IP gets rate-limited, not blocklist-burned)
— directly slowing IP-reputation burn and protecting the scarce exit pool's value.
Prototype it as a metered scope of the existing ARC/P-256 credential with separate
earn/spend caps, and make the path-selector refuse any flow that would push an
exit past its human-volume envelope.

## 5. Honest verdict — is "most of the web at human volume" achievable?

**Yes — but only as a portfolio, with the hard core explicitly bounded, built in
the right order.**
- The **read/agent-heavy slice** (~20–40% of the volume Tessera actually serves)
  is solved **without egress at all** (PIR + verifiable fetch + Helios RPC) —
  arms-race-immune, deployable now.
- The **syndicated slice** is reachable through doors sites hold open — ~zero IPs.
- The **paid-API slice** is reachable by paying — no detection to lose.
- The **cooperating-origin slice** is the right long-term future (ARC-as-PP).
- The **hard core** (login-gated, web-only, anti-scraping-leader consumer sites) is
  reachable *only* by a small pool of genuinely non-blocklisted exits **carrying
  the client's real end-to-end TLS, shaped to human volume** — and is
  **irreducibly capped**: the very per-IP cap that keeps an IP clean also bounds
  its throughput, so **supply and cleanliness are inversely coupled**. High-quality,
  low-volume, ethically-defensible — never unlimited.

**Three honesty constraints to bake into the project's own framing:**
1. The liability vacuum from an anonymous buyer is **never *filled*, only rate-
   limited + credential-revocable**; the residential/exit sharer's real-world risk
   is irreducible. Don't sell it as solved.
2. **Audit must be metadata-only** — that constraint is *binding*, and it's exactly
   *why* shaping works (metadata-computable) and *why* content-based consent (SNI
   allowlists) fights ECH and is on a clock. Plan the post-ECH IP-level fallback now.
3. The honest envelope should explicitly **EXCLUDE the hardened login-gated top
   tier**, not pretend a trick covers it.

**Bottom line:** "most of the web at human volume" is achievable — and the phrase
is load-bearing both ways. *"Human volume"* is not a softener; it is the literal
mechanism (#1) that makes the clean-IP lanes durable. *"Most"* means the
portfolio's union **minus an explicitly-bounded hard core**. There is no version
where Tessera reaches *everything unlimited* — the projects that claim otherwise
are the malware-proxyware networks Tessera exists to *not* be.

---

**Sources:** [Cloudflare — detecting CGNAT to reduce collateral damage](https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/) ·
[The Register — ISPs more likely to throttle CGNAT traffic](https://www.theregister.com/2025/11/03/cloudflare_cgnat_bias_research/) ·
[Linux Foundation — x402 Foundation launch](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol) ·
[Crypto Briefing — x402 surpasses 100M transactions on Base](https://cryptobriefing.com/coinbase-x402-protocol-100m-transactions-base/)
