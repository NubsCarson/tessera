# Tessera docs — index, decision log, and open paths

The map of everything: what each doc covers, **why** the key decisions were made
(so the reasoning is durable, not just the outcome), and the paths not yet taken.
If you read nothing else, read the **honest status** at the bottom.

> Tessera is a **research-grade protocol artifact + self-hostable tool** for
> private, uncensorable clearnet *access*: reach any HTTPS site privately, paying
> anonymously per request, admitted on a credential/token — never an IP — for
> humans and AI agents, with anonymity provided by Tor. It is **not yet a deployed
> network** a stranger can use (that needs a clean egress IP + a Tor crowd + an
> audit — see **Honest status** below). Research-grade, **UNAUDITED**. The
> contribution is the *composition* + the *candor*, not a new primitive.

## Read in this order

| When you want… | Read |
|---|---|
| The big picture / the full vNext design | [`DESIGN.md`](./DESIGN.md) |
| **The architecture decision** (what we built vs. the leaner path, and why) | [`ARCHITECTURE.md`](./ARCHITECTURE.md) |
| Who pays what, and why misbehavior doesn't pay | [`ECONOMICS.md`](./ECONOMICS.md) |
| Speed / latency (yes it matters; the pivot is faster) | [`PERFORMANCE.md`](./PERFORMANCE.md) |
| What's confidential vs. delegated to Tor; the trust model | [`THREAT_MODEL.md`](./THREAT_MODEL.md) |
| Per-property security argument (construction→assumption→gap) | [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md) |
| DoS / abuse surface + the bounds we added | [`ABUSE_MODEL.md`](./ABUSE_MODEL.md) |
| Deployment topology + per-node trust boundaries | [`DEPLOYMENT_TOPOLOGY.md`](./DEPLOYMENT_TOPOLOGY.md) |
| The ARC server-key lifecycle (bootstrap / sharing / rotation / leak) | [`KEY_MANAGEMENT.md`](./KEY_MANAGEMENT.md) |
| Multi-exit key custody (per-exit domains vs shared fleet key vs BBS) | [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md) |
| What's safe to log (observability + privacy review) | [`OBSERVABILITY.md`](./OBSERVABILITY.md) |
| Relayer misbehavior → defense + honest-relayer atomicity | [`RELAYER_CHEAT_MATRIX.md`](./RELAYER_CHEAT_MATRIX.md) |
| Channel durability / crash-recovery (optional-advanced tier) | [`CHANNEL_RECOVERY.md`](./CHANNEL_RECOVERY.md) |
| Responsible use + sparse-deployment anonymity warning | [`SAFETY.md`](./SAFETY.md) |
| Who owns the `epoch` clock + the skew/rejection rules | [`EPOCH_AUTHORITY.md`](./EPOCH_AUTHORITY.md) |
| The clean-egress portfolio (the hardest, no-silver-bullet part) | [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md) |
| PoW difficulty / cost analysis (honest cost knob, not Sybil) | [`POW_ANALYSIS.md`](./POW_ANALYSIS.md) |
| How each wire layer is versioned + the upgrade convention | [`PROTOCOL_VERSIONING.md`](./PROTOCOL_VERSIONING.md) |
| Post-quantum terrain | [`POST_QUANTUM.md`](./POST_QUANTUM.md) |
| The roadmap | [`ROADMAP.md`](./ROADMAP.md) |
| **One status table for the whole system** | [`STATUS.md`](./STATUS.md) |
| **The audit-prep packet** (the map an auditor reads first) | [`../AUDIT.md`](../AUDIT.md) |
| **Live progress / the 99-item Definition-of-Done** | [`CEILING_PROGRESS.md`](./CEILING_PROGRESS.md) |
| The ZK circuit (optional-advanced tier) | [`../circuits/README.md`](../circuits/README.md) |
| The ARC §10.2 vector discrepancy (a known upstream skew) | [`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md) |

## Decision log (the *why*)

1. **v0 → vNext pivot.** v0 was an ARC anonymous-credential *trust layer* for
   cooperating origins ("obsolescence, not evasion"). The real goal is a private
   *access* network — reach any site, not just cooperating ones. ARC became one
   component, not the thesis.
2. **The leaner architecture (the big one, see `ARCHITECTURE.md`).** We built
   ambitious-first — a ZK Spilman payment channel + EVM court + on-chain ZK
   settlement + MPC ceremony. Decision: for *access*, that's over-engineered.
   Refunds aren't needed → **blind ecash tokens** (an ARC presentation) beat a
   channel; the on-chain ZK doesn't even hide the balance from the relayer → it's
   demoted; a blind signature gives funding-unlinkability **for free** → the
   shielded pool *and* the MPC ceremony become optional. **The leaner path is
   mostly already built** (it's v0 + Tor + shaping). The channel/ZK/court are
   kept as a documented **optional-advanced tier** — not deleted.
3. **Payment primitive = blind tokens, not a channel.** Tokens (Privacy
   Pass/Cashu-style) are simpler, battle-tested, and unlinkable by construction.
   The on-chain piece is the small `TokenMint.sol` rail (pay ETH → entitlement →
   issuer blind-issues), not a dispute/watchtower machine.
4. **Transport = Tor.** Don't rebuild the mixnet. Be the accountable, token-gated
   **clean egress reached over Tor**; let Tor provide the anonymity crowd.
5. **Clean egress = a portfolio, no silver bullet** (`IP_EGRESS_IDEAS.md`). The
   highest-ROI mechanism is per-IP **human-volume shaping** (built, M5): the rare
   case where "do the honest thing" and "evade detection" are the same action.
6. **Epoch authority = the relayer**, attested per challenge, zero-skew rejection
   (`EPOCH_AUTHORITY.md`). Not a wall-clock (would introduce the skew we forbid).
7. **Relayer accountability = a per-channel bond** with symmetric equivocation
   slashing (`ECONOMICS.md`); honest that it's accountability/Sybil/forward-compat,
   not a theft reserve in the unidirectional channel.
8. **Multi-exit key custody = per-exit ARC key domains.** A single-exit
   issuer+exit pair shares one `TESSERA_KEY_FILE`, but independent exits must
   not share one fleet-wide ARC server key. That would put every exit inside one
   forge-and-verify trust domain. Use per-exit issuer/key domains now; the local
   signed directory verifier/client selector is built for choosing one domain
   and pinning its issuer key. Keep publicly verifiable BBS-style credentials as
   a future cryptographic track, not a shipped claim (`KEY_CUSTODY_DECISION.md`).
9. **Honesty is a feature.** Every external hand-off and every "doesn't do X" is
   named in docs rather than glossed; an auditor sees the gaps up front.

## Open paths / ideas not yet taken

**Optional-advanced tier (built, tested, kept — use when pay-as-you-go-with-refund
is genuinely needed):** the ZK Spilman channel (`tessera-channel`), the EVM court
(`contracts/src/ChannelRegistry.sol`), on-chain ZK settlement (`circuits/`,
`cooperativeCloseZK`).

**Buildable-here, not yet done** (tracked in `CEILING_PROGRESS.md`): S34
(PIR/green-routing/x402 egress lanes, gated by the clean-egress frontier) and
the NICE tier (polish, `unilateralCloseZK`, a per-IP-per-epoch ZK rate circuit,
etc.).

**Toward "usable" (mostly not core crypto):** a paid-mint client/wallet UX (the
MV3 extension is a scaffold); the off-chain issuer integration (watch
`TokenMint.Purchased` → blind-issue via ARC → `redeem`); a deployed exit.

**Future ideas worth keeping (`DESIGN.md` §3–5, `IP_EGRESS_IDEAS.md`):** the
cacheable read-tier / PIR (skip the egress circuit for ~20–40% of volume); the
mode-switched MASQUE/QUIC interactive fast-path; a per-**operator** shared stake
(capital-efficient vs the per-channel bond); coherent-persona fingerprint
resistance.

**Irreducibly external (never faked):** a third-party audit · a ≥5-human MPC
ceremony (only if the optional ZK tier is deployed) · clean residential IPs at
scale · a Tor/Nym anonymity crowd · the perpetual anti-bot arms race · the
cross-epoch statistical-disclosure budget (open *research*, `DESIGN.md` §9).

## Honest status

As a **protocol artifact** the leaner architecture is essentially complete and
tested (token + Tor + shaping + DoS-bounded accept layer, all CI-green); the
heavier ZK-channel tier is also complete as the optional path. As a **deployed
network a stranger can use**, the blockers are now mostly *not code*: a clean
egress IP, an anonymity crowd, a client UX, and (for trust) an audit. The fastest
real milestone is "you run it yourself to reach a Tor-blocked site," gated mainly
on one clean IP. Nobody should protect real users or real funds with this until
the external hand-offs are done — and that's stated, not hidden.
