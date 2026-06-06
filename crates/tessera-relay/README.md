# tessera-relay — the 2-hop split-trust loop (Phase 1: "prove the loop")

`tessera-relay` is Tessera's **first onion hop**: a credential-*blind* relay in
front of the credential-*gated* exit (`tessera-proxy`). Together they form the
local, end-to-end **2-hop split-trust loop** from the design doc (§1, §3, §5):

```text
CLIENT ──CONNECT exit──▶ RELAY ──opaque bytes──▶ EXIT ──CONNECT dest──▶ DESTINATION
        (no credential)  (this crate)            (tessera-proxy)
                          learns {client, exit}  learns {destination, a valid credential}
```

The client opens an **outer** `CONNECT <exit-addr>` to the relay. The relay
tunnels that to the exit and then only pumps opaque bytes. *Through* that tunnel
the client sends a **nested / inner** `CONNECT <destination>` carrying its ARC
`Tessera-Presentation` header — and the relay never parses it.

## The split-trust property (implemented + tested)

No single hop holds *who* + *where* + *what*:

| Hop   | learns who (client addr) | learns where (destination) | learns what (content) | learns a credential is valid |
|-------|:------------------------:|:--------------------------:|:---------------------:|:----------------------------:|
| RELAY | ✅ (+ the exit's addr)   | ❌ (it's inside the bytes) | ❌ (opaque tunnel)    | ❌ (never sees the credential) |
| EXIT  | ❌ (only sees the relay) | ✅ (CONNECT host:port, SNI)| ❌ (opaque tunnel)    | ✅ (verifies the presentation) |

* The **relay** is deliberately credential-blind and forwards only to its one
  fixed next hop (the exit) — it is not an open proxy.
* The **exit** is the unchanged `tessera-proxy`: it verifies the ARC presentation
  via `tessera-origin`'s `OriginGuard` (admit on the credential, **never** the
  IP) and only then tunnels to the destination.
* **Neither** sees content: the client's TLS to the destination runs end-to-end
  through both hops, which only move bytes. Tampering breaks TLS.

The integration tests (`tests/loop.rs` for ARC mode, `tests/channel_loop.rs` for
the channel-payment mode) wire an observation channel into each hop (`Observer`
for the relay, `tessera_proxy::ExitObserver` for the exit) and assert directly
that the relay never recorded the destination and the exit never recorded the
client's real source socket — including in the paid loop, where the relay's
observation is recorded **only after** the spend is accepted, so it also witnesses
"this request was paid for" and still never the destination.

> In **channel mode** the relay is no longer credential-blind about *payment* (it
> is the counterparty), but it stays **destination-blind and content-blind**: it
> reads only its three outer `Tessera-Channel-*` headers, never inside the tunnel.
> The within-session link it does hold (which in-channel requests are yours) is
> the **accepted** linkability of `DESIGN.md` §9, named not hidden.

## The loop also does REAL channel pay-per-request (optional-advanced)

The loop has **two payment modes**. Per the root architecture decision, the
recommended default path is the ARC-token mode (credential minted by the issuer,
verified at the exit). The channel-payment mode is still real, built, and tested,
but it is the optional-advanced tier for pay-as-you-go-with-refund:

* **Channel mode (real, optional-advanced — `DESIGN.md` §1/§2).** The **relay is the
  [`tessera-channel`](../tessera-channel) counterparty + per-request payment
  gate.** The client OPENS a channel with the relay (`RelayGate::open`; the relay
  holds a `RelayerChannel`, the client a `UserChannel`). For **each** request the
  client does a real channel `spend` (`S_{i+1}` + the user signature + a freshness
  signature against the relayer's challenge) and sends it on the **outer CONNECT
  headers** (`Tessera-Channel-Id` / `-Spend` / `-Fresh`). The relay
  `verify_and_cosign`s it and **only then** opens the tunnel to the exit
  (*sign-then-serve*) — handing back the relayer-co-signed state so the client
  advances its cursor. A **missing / bad / replayed / over-budget** spend gets
  `402 Payment Required` and **the request never reaches the destination**. The
  full protocol (how the spend rides the nested-CONNECT tunnel, and the exit's
  role + trust) is documented in the `tessera_relay::channel` module.
* **ARC-token mode (recommended default).** The credential-*blind* relay where
  the ARC presentation gates at the **exit**. This is the leaner default path
  documented in `docs/ARCHITECTURE.md`; it is available through `serve` /
  `open_through_relay` and is tested end to end.

**Why this is the correct trust model** (`DESIGN.md` §1/§2/§8): the relay is the
**single channel counterparty**, so it *necessarily links your in-channel
requests* — the **accepted within-session linkability** (`DESIGN.md` §9
cross-epoch is where that surface is named, not hidden). Co-locating
balance-authority + first hop in one party is exactly what **collapses
distributed double-spend into one in-memory cursor**: a replay simply fails
`verify_and_cosign` against that cursor. The relay **pays the exits downstream**;
we model that as *"the relay is the exit's trusted client."*

**The exit's role + trust.** The exit is the unchanged content-blind
`tessera-proxy`. There is **one payment gate, at the relay** — the exit does
**not** re-verify a channel spend (no redundant double-gating). The exit keeps
its own ARC `OriginGuard` check, but here that is **demoted from "the payment
stand-in" to the exit's *participant token***: its own *"is this a Tessera
participant, never the IP"* admission (`DESIGN.md` §5) so it is not an open proxy.
The real per-request payment is the channel spend at the relay.

### Honest scope of the channel payment

* This is the **Phase 2a protocol** wired into the live loop — a real,
  user-signed, relayer-co-signed, freshness-bound, monotone-decrementing spend per
  request. `cost`/`balance` are in the clear (exactly as in `tessera-channel`).
* It is **NOT** the **ZK settlement (Phase 2b-i)** — balance privacy against an
  observer; the relay knows the balance by construction anyway. That is a separate
  increment (`circuits/` + `cooperativeCloseZK`).
* It is **NOT** the **shielded funding pool** (unlinkable funding) — also separate.
* There is **still no real clean egress** — reaching a Tor-blocked site through a
  clean residential-class IP is a documented **manual** final step (below).

ARC-token mode is the default architecture path; channel mode remains the real,
tested optional-advanced path.

## Run it

```sh
# REAL channel pay-per-request demo: open + a couple of PAID requests + a refused replay
cargo run -p tessera-relay --example paid_loop

# ARC-token loop (recommended default; credential gates at the exit):
cargo run -p tessera-relay            # exit egresses directly
cargo run -p tessera-relay -- --tor   # exit egresses via Tor (SOCKS5 127.0.0.1:9050)
```

`paid_loop` opens a channel and prints each paid request (seq/balance), then shows
the replayed spend getting `402` (no double-spend, destination never touched).

The canonical client moves are `tessera_relay::open_through_relay` (ARC-token
mode) and `tessera_relay::open_through_relay_paid` (channel mode); the tests and
the example/binary use them.

## Design choices (and why)

* **std/blocking + threads, a HOST workspace crate** — *not* an excluded async
  crate. The relay only pumps opaque bytes and parses one outer CONNECT line, so
  it needs no async and no extra deps; it mirrors `tessera-proxy` exactly and
  stays inside the host MSRV-1.74 / clippy / test gates. (`tessera-tower-demo`
  is excluded only because `axum`/`tokio` are heavy async deps — not the case
  here.)
* **Reuses, doesn't reinvent**, `tessera-proxy`'s byte-pump (`pipe`), its
  `CONNECT`/SOCKS5/Tor egress, and `OriginGuard` credential check (the exit *is*
  `tessera-proxy`, untouched). The channel-payment gate reuses
  `tessera-channel`'s `RelayerChannel::verify_and_cosign` /
  `UserChannel::spend`/`serve` verbatim — the relay adds only the **wire framing**
  (the `Tessera-Channel-*` headers, in the `channel` module) and the **per-channel
  cursor registry** (`RelayGate`); no new external deps, still a host MSRV-1.74
  crate. No changes were needed to `tessera-channel` or `tessera-proxy`.

## Honesty — what this proves and what it does NOT

This proves the **protocol / loop**, locally and deterministically: the multi-hop
chain works, the split-trust property holds, the **real channel spend gates each
request at the relay** (verify-and-co-sign before serving; replay/over-budget
refused; the destination never touched on a refusal), and the tunnel carries
opaque bytes both ways (the in-test stand-in for the client's real end-to-end TLS
— a tampered byte is detectable by the caller exactly as a TLS AEAD tag would
catch it).

It does **not** prove the **ZK settlement (Phase 2b-i)** or the **shielded funding
pool** — both separate increments — and the channel does **not** hide the balance
from the relay (it is the counterparty; it knows it by construction).

It does **not** prove the last-mile reach claim. "A real Tor-blocked site returns
`200` through a real *clean* exit IP, privately" needs a real residential-class,
unpublished egress IP behind the exit — which no code can manufacture. That is a
**documented manual final step**: run `cargo run -p tessera-relay -- --tor` (or
point the exit at a clean egress) and drive a known Tor-`403` site. Until then the
egress is whatever your machine's IP is. Research-grade, UNAUDITED.
