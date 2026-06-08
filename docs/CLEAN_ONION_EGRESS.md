# Clean onion egress lane decision

> Decision record for how a clean-egress exit accepts client traffic, gates each
> request, and advertises itself across more than one exit. Research-grade,
> **UNAUDITED**. This document is normative for deployment docs. It does not add a
> live clean-egress service, a Tor/Nym anonymity crowd, or a third-party audit,
> and nothing it decides manufactures a genuinely clean egress IP — that stays an
> operator and resource problem (see `CLAUDE.md`, "Three gaps no code can fake").
> It fixes three rules a clean-egress lane must obey: the client→exit transport,
> the per-request limiter, and the multi-exit key/advertisement model.

This record was prompted by a comparison against the
[`reputation-gated-onion-egress`](https://github.com/dmarzzz/reputation-gated-onion-egress)
(RGOE) proof-of-concept — a Tor onion service that egresses to the clearnet only
for clients who prove, in zero knowledge, that they hold reputation ("anonymous,
sybil-resistant, no exit node"). RGOE has the better *deployment UX* for one
specific shape (local CONNECT shim → onion service → clean-IP gateway). Tessera
has the stronger *protocol core* (unlinkable, single-use ARC credentials; a
fail-closed spent-tag store; a signed per-exit-key-domain directory; human-volume
shaping; CI/tests). The decision below keeps Tessera's core and adopts RGOE's
transport idea — the onion hop — without adopting its credential model.

## Decision

Three sub-decisions, each grounded in code that already exists today.

**1. The client reaches the exit over an `.onion` address via a Tor SOCKS dialer,
not raw public TCP, so the exit never sees the client IP.**

The admission decision is already source-IP-blind: `OriginGuard::check`
(`crates/tessera-origin/src/lib.rs`) operates only on the value of the
`Tessera-Presentation` header and never consults the peer address. It is
byte-identical whether bytes arrive over direct TCP, the 2-hop relay, or a Tor
circuit — `run_onion_probe` (`crates/tessera-demo/src/tor.rs`) already exercises
the guard admitting identically over a real Tor circuit. Because the limiter is
transport-agnostic, the onion hop is a layer *above* the admission contract, not
a change to it. The onion hop is what removes the exit-sees-client-IP leak and
borrows Tor's anonymity crowd; the clearnet 2-hop relay loop (`tessera-relay`)
stays a valid, supported fallback.

**2. ARC presentations remain the primary per-request spend/replay limiter.
Semaphore/RLN, if used at all, is an OPTIONAL issuance/admission signal fed to
the issuer — never the egress-time gate.**

Each request carries an ARC presentation that the exit verifies
(`verify_presentation`, `crates/tessera-arc/src/arc.rs`) and burns single-use via
the fail-closed spent-tag store (`SpentTagStore::record_if_new`,
`crates/tessera-origin/src/store.rs`; a replay returns `RejectReason::DoubleSpend`).
We do **not** gate egress on a Semaphore/RLN membership proof. The reason is
concrete and observed in the RGOE PoC: its Semaphore proof signs a *constant*
message and is cached once per epoch, then re-sent verbatim on every request,
with the gateway never binding the proof to the target. Its own README states
that replay inside an epoch is allowed by design, and that the safety of the
scheme therefore rests on the proof never being observable on the wire. That is a
fragile, transport-coupled assumption — anyone who sees the proof can replay it
for the rest of the epoch. ARC's per-request single-use tag does not depend on
the channel being unobservable, so it is the correct egress-time limiter.
Semaphore-style membership belongs, if ever, at *issuance time* — deciding
whether the issuer mints a credential at all — never on the per-request egress
path.

**3. Multiple exits = per-exit ARC key domains advertised via a signed
`tessera-directory` snapshot, never a shared fleet key.**

This is the already-decided custody rule from
[`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md): one ARC key domain per
independent exit, advertised through the signed directory the client verifies
(`verify_at`) and selects from (`select` / `select_with_policy`). The onion lane
inherits this verbatim and adds only an onion-aware advertisement field; it does
not re-litigate key custody.

## Why not direct public TCP (no onion)?

Direct TCP is simpler and lower-latency, and it already works: the relay/exit are
reachable over plain `TcpStream`, and the 2-hop relay loop already gives a
who/where/what split — the regression test
`valid_credential_reaches_origin_and_split_trust_holds`
(`crates/tessera-relay/tests/loop.rs`) asserts the exit's peer is the relay, never
the client. That is a real upside, and the clearnet loop stays supported.

But on raw public TCP the *first hop* sees the client IP. The relay is what hides
it, which means the split-trust property depends on the relay being operated
independently of the exit — and `CLAUDE.md` / `docs/DEPLOYMENT_TOPOLOGY.md` are
explicit that a single operator running both relay and exit gives **no
relationship anonymity**. An `.onion` client→exit hop collapses that to a single
hop where the exit's peer is the Tor rendezvous circuit, not the client, and it
borrows Tor's existing anonymity crowd instead of asking each operator to stand
up an independent relay.

The cost is real: onion adds latency, a Tor dependency, and a descriptor-publish
cold start. But for this product the onion egress is **the foundation, not an
optional lane** — the exit *is* an onion service. If Tor is unavailable the
client **fails loud** rather than silently downgrading the anonymity the operator
asked for; dropping to the clearnet 2-hop relay loop is an **explicit opt-out**
(`TESSERA_ALLOW_CLEARNET_FALLBACK=1`), never the default. The relay loop stays a
supported fallback for operators who genuinely cannot run Tor, but it is opt-in.

## Why ARC primary, Semaphore optional?

A keyed ARC presentation is unlinkable, rate-limited at mint, and single-use at
spend via a fail-closed tag store. That is exactly the per-request property an
egress gate needs: a presented credential is spent once and any re-presentation
is rejected as `DoubleSpend`. Using a Semaphore/RLN membership proof as the
per-request gate would be wrong on two counts: (a) it conflates *who may obtain a
credential* (issuance/admission) with *may this specific request egress*
(per-request spend), and (b) as the RGOE finding shows, an epoch-scoped membership
proof is replay-allowed by construction and leans on an unobservable channel for
its safety. ARC keeps the per-request limiter independent of the channel.

The cost is real and already recorded: ARC is keyed-verification (the verifier
holds the minting secret), so presentations are not publicly verifiable and an
exit only verifies credentials for its own key domain. That is the deliberate
trade in [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md), not a regression.
Semaphore/RLN is recorded here as an *optional future issuance signal* — a way an
issuer could decide who to mint for — not as built code and not as an egress gate.

## Why per-exit key domains + signed advertisement?

Reused verbatim from [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md): a
shared fleet key makes every exit able to forge credentials valid at every other
exit and turns each operator into a fleet-wide verification oracle. Per-exit
domains make the trust boundary match the egress boundary; a compromised exit
burns only its own key. The client pins the issuer key for the exit it selected,
obtained from a signed `tessera-directory` snapshot it verifies before routing.
The directory already carries the issuer public key, a per-exit key epoch,
capacity, and protocol labels under its signature, so the onion lane adds only an
onion-address advertisement, not a new trust mechanism.

## What about Semaphore-as-admission / publicly verifiable membership?

A publicly verifiable membership/reputation layer (Semaphore/RLN with a real
admission ceremony, or a BBS-style credential) would let an issuer decide
admission with public verifiability and would remove the verifier-secret-sharing
property of keyed ARC. That is architecturally interesting for a large,
independently operated fleet — and it is the same future migration path the BBS
section of [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md) already records.

It is not the current product. RGOE's reputation set is a local member list with
no revocation path and a root cached once at boot; that is honestly a PoC, not
production trust. Adding RLN per-message shares, a revocation accumulator, and a
real admission ceremony (stake / invite / proof-of-personhood) is a new
cryptographic track, new vectors, a new threat model, and a fresh audit surface.
Keep it as a future *issuance-time* migration, not a half-built egress gate.

## Implementation rule

For the code that exists today:

- The ARC presentation is the per-request egress gate. Do not add any membership
  proof to the per-request path. `OriginGuard::check` plus a single-use spent tag
  is the admission contract, and it is source-IP-blind by construction.
- The onion lane is additive transport. The exit's admission, header parsing,
  reject path, and byte pump (`tessera-proxy`) are reused unchanged regardless of
  how the client reached the exit.
- **An exit that egresses to arbitrary destinations MUST first enforce a target
  policy** (a port allowlist, private/loopback/link-local/CGNAT/cloud-metadata
  rejection, and resolve-then-pin against DNS rebinding) *before* it dials. This
  is the gap PR1 closes: previously the exit would dial any `CONNECT host:port`.
  The port allowlist + IP-literal classification are the cheap, pre-credential
  admission step in the cheap-before-expensive ordering `OriginGuard::check`
  already models. The full resolve-then-pin address gate applies to a **Direct**
  upstream (the exit dials from its own clean IP). For a **Tor** upstream, the
  port allowlist and IP-literal classification still apply, but hostname
  address-gating is **deliberately delegated to the Tor exit's `ExitPolicy`**
  (Tor exits refuse private/loopback/reserved destinations by default): resolving
  a name locally just to classify it would leak the destination to the local
  resolver, defeating the point of routing over Tor.
- Each exit is its own ARC key domain (`TESSERA_KEY_FILE`), advertised via a
  signed `tessera-directory` snapshot. Never mount one key file into independent
  exits.
- The onion egress is the foundation: when an exit onion is configured, it is THE
  path. If Tor is unreachable at launch the client **fails loud** — it does NOT
  silently drop to clearnet on a route chosen for anonymity. Dropping to the
  clearnet relay loop is an explicit operator opt-in
  (`TESSERA_ALLOW_CLEARNET_FALLBACK=1`); once the onion route is committed, a
  *later* Tor failure surfaces as a per-request `502` (restart to re-evaluate),
  not a runtime downgrade. The startup preflight is a TCP-liveness check only (a
  wedged or non-Tor listener on the SOCKS port can pass it).

## Target clean onion egress lane shape

- A client dials the selected exit's `.onion:port` through a local Tor SOCKS
  port, presenting an ARC credential for that exit's key domain. The exit's peer
  is the Tor circuit, never the client IP.
- The exit verifies the credential, burns the tag single-use, enforces the target
  policy, applies human-volume shaping on the egress side (`VolumeShaper`), and
  pipes bytes. A note on ordering: the cheap target checks (port allowlist,
  IP-literal classification) run *before* the credential verification, but the
  hostname DNS resolution runs *after* it (so an unauthenticated peer can never
  make the exit resolve a name). A consequence is that a post-credential transport
  refusal (a hostname that resolves into blocked space, or fails to resolve)
  consumes the single-use tag by design — the tag is recorded on admit, before
  DNS — and that is the correct tradeoff: deferring the burn would weaken the
  single-use guarantee and the cheap-before-expensive DoS ordering.
- The directory advertises each exit's `.onion` endpoint and key domain under the
  threshold signature; the client selects an onion-capable exit and pins its
  issuer key before issuance.
- Cold-start onion dials are retried a bounded number of times with a clear
  "service warming up, retrying" narration, so the first request after boot does
  not hard-fail (UX borrowed from the RGOE shim).

## Current status

Built here (the reusable core the lane stands on):

- Source-IP-blind admission: `OriginGuard::check` plus `verify_presentation` plus
  the fail-closed single-use `SpentTagStore::record_if_new`.
- Transport-agnostic ARC mint/verify, exercised byte-identically over a real Tor
  circuit by `run_onion_probe`.
- A credential-gated CONNECT exit (`tessera-proxy`) with a concurrency cap, a
  symmetric client/upstream idle timeout, a bounded upstream `connect`, and
  optional (off-by-default) per-tunnel byte and wall-clock caps
  (`TESSERA_MAX_TUNNEL_BYTES` / `TESSERA_MAX_TUNNEL_SECS`); and a credential-blind
  2-hop relay loop with the split-trust regression test
  `valid_credential_reaches_origin_and_split_trust_holds`.
- A minimal SOCKS5 CONNECT dialer and a Tor egress upstream for the
  exit→destination hop, plus human-volume shaping (`VolumeShaper`).
- A signed per-exit-key-domain directory: parse / `verify_at` / `select` /
  `select_with_policy`, with issuer key, key epoch, capacity, and protocol labels
  under the signature, and local anti-rollback state. Per-exit key custody decided
  and tested ([`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md)).
- **The exit target/SSRF policy gate** (PR1): a configurable port allowlist
  (default `:443`), private/loopback/link-local/CGNAT/cloud-metadata rejection for
  IPv4 and IPv6 (including IPv4-mapped/NAT64/6to4 embedded forms), and
  resolve-then-pin against DNS rebinding, run as a cheap pre-credential check.
- **The pluggable transport seam** (PR2): `tessera_proxy::transport::Dialer` with
  `TcpDialer` + `TorSocksDialer`, so the SOCKS5 client is shared by the exit
  (egress hop) and the client (onion hop).
- **The client→exit onion lane** (PR3): `ClientRoute::Onion` /
  `open_through_onion` — the local client proxy dials the exit's `.onion` through
  Tor SOCKS (single hop, relay bypassed; the exit's peer is the Tor circuit,
  never the client IP), with a bounded cold-start retry + "warming up" narration.
  **Tor-native:** when an onion is configured but the Tor SOCKS proxy is
  unreachable, the client **fails loud** rather than silently downgrading the
  anonymity it was asked for — clearnet is taken only if the operator opts in with
  `TESSERA_ALLOW_CLEARNET_FALLBACK=1`. Configured by `TESSERA_EXIT_ONION` +
  `TESSERA_TOR_SOCKS`; proven end-to-end against a SOCKS5 stub standing in for Tor
  (and live against real Tor — see [`ONION_EGRESS.md`](./ONION_EGRESS.md)).
- **Onion-aware directory advertisement + selection** (PR4): the signed directory
  format `tessera-exit-directory-v2` advertises each exit's optional `onion_addr`
  and a signed `clean_egress` flag under the threshold signature (tamper-evident),
  and `DirectorySelectionPolicy` gains `require_onion` / `require_clean_egress` so
  a client can select an onion-capable exit. The magic bump fails a v1 verifier
  closed against a v2 snapshot. **The client routes over the selected entry's
  SIGNED `.onion`** — preferred over the unsigned `TESSERA_EXIT_ONION` env (which
  is mutually exclusive with directory mode, so an unsigned onion can never
  override a signed one). `TESSERA_DIRECTORY_REQUIRE_ONION=1` makes the onion lane
  a hard selection filter; if selection still lands on a no-onion entry while the
  directory advertises an onion exit, the client warns loudly before it would route
  clearnet.

Not built here (buildable, but forward product/research scope, not hidden
cleanup):

- A **persisted, sealed** exit-side onion key. The exit is reachable over
  `.onion` today via operator Tor configuration (a `HiddenServiceDir` mapping the
  onion to the exit's loopback port — see "Running the exit as an onion service"
  below; the exit binary needs no code change). What is *not* built is sealing
  that HS key to the enclave in a non-logging TEE. The `dstack-kms` provider now
  derives the *ARC server key* from the guest agent (implemented, fail-closed
  off-TEE, simulator-proven not silicon-proven), but sealing the *onion HS key* to
  the enclave the same way is not built.
- Routing **issuance** over Tor: the onion lane hides the *browsing* IP from the
  exit, but issuance still connects the client directly to the issuer (the issuer
  learns the IP at mint/re-issue time; ARC keeps it cryptographically unlinkable).
  Wrapping issuance in the same `TorSocksDialer` is a tightly-coupled follow-up.

## Running the exit as an onion service

The exit is made reachable over `.onion` by operator Tor configuration, not exit
code: Tor maps an onion address to the exit's existing loopback listener. A
minimal `torrc` on the exit host:

```text
HiddenServiceDir /var/lib/tor/tessera-exit/
HiddenServicePort 443 127.0.0.1:8118
```

Tor publishes the descriptor and writes the stable `.onion` to
`/var/lib/tor/tessera-exit/hostname`; clients set `TESSERA_EXIT_ONION` to
`<that-onion>:443`. The exit keeps binding its loopback port (`TESSERA_LISTEN`)
and is otherwise unchanged. **Honesty caveats:** (1) the HS key under
`HiddenServiceDir` is a plain on-disk file — in a non-logging TEE it must instead
be sealed to the enclave the way the implemented `dstack-kms` ARC-key path is
(sealing the *onion HS key* this way is not built), or a host-root/volume
compromise reads it; (2) a freshly published descriptor can take tens of seconds
to become reachable, which is why the client retries with a "warming up"
narration; (3) this borrows Tor's anonymity crowd — it does not manufacture one.

Never-faked externals (no code in this repo manufactures these — `CLAUDE.md`):

- A genuinely clean residential/ISP egress IP — an operator/resource problem.
- A real Tor/Nym anonymity crowd.
- A third-party security audit.
- The one live clean-egress experiment ("a site that 403s Tor returns 200 through
  a Tessera clean exit"), which is gated on an external clean IP.

This is a scoped design that does not overclaim production unblock.
