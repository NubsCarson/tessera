# Censorship resistance: both *private* and *uncensorable*

> Tessera aims to be **both private AND uncensorable** — these are two distinct
> properties that stack, not a choice. Research-grade, **UNAUDITED**.
>
> * **Private** — the destination never learns *who* you are; requests are
>   unlinkable. (The ARC credential + 2-hop split-trust + clean exit.)
> * **Uncensorable** — you can reach the network *even when someone is actively
>   blocking you*. (Tor pluggable-transport / bridge **entry**, in front of the
>   private pipe.)
>
> A censor doesn't (only) block the destination — it blocks *you reaching the
> anonymity network in the first place*. So "the exit is an onion service" buys
> privacy but not, by itself, censorship resistance: reaching Tor is exactly what
> a national firewall blocks. The missing half is a **disguised, unblockable
> entrance**.

## The two surfaces

Tessera's access path has two independent problems, solved at two layers:

| Surface | Problem | Tessera's answer | New? |
|---|---|---|---|
| **Entry** | reach the anonymity network past a censor who detects & blocks circumvention | **Tor pluggable transports + bridges** (obfs4 / Snowflake / WebTunnel) — disguise the traffic + enter via addresses the censor doesn't know | **the added half** |
| **Egress** | reach a destination that blocks proxy/datacenter/Tor-exit IPs | **clean exit** reached over the `.onion` (no Tor exit node); the destination sees the exit's clean IP | existing ([`ONION_EGRESS.md`](./ONION_EGRESS.md), [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md)) |

## The layering (entry in front of the private pipe)

```text
  you ─▶ tessera-client (local proxy)
        │  mint a fresh, single-use, unlinkable ARC token            ── PRIVATE
        ▼
     [ obfs4 / Snowflake / WebTunnel bridge ]   ← disguised, unblockable ENTRY
        ▼   (looks like noise / a video call / ordinary HTTPS; enters via a
        │    bridge the censor doesn't know)
     [ real Tor: rendezvous, no exit node ]
        ▼
     EXIT.onion  ── ARC-gated + SSRF-hardened ──▶ the destination   (TLS end-to-end)
                                                  (sees the exit's clean IP, not you)
```

The pluggable transport runs **inside Tor** — the client still dials a plain local
SOCKS port; the bridge only changes *how Tor reaches the network*. Nothing in the
private pipe (ARC token, split-trust, clean exit, SSRF gate, fail-loud onion) is
touched: the entry layer sits **in front** of it.

## Reused from Tor — zero new circumvention crypto

The circumvention is **100% Tor's**, not Tessera's. obfs4, Snowflake, and
WebTunnel are the Tor Project's pluggable transports; bridges are Tor's. Tessera
only **writes the `torrc` lines** that point the real `tor` binary at them
(`tessera_client::torrc::client_torrc`, validated against `tor --verify-config`)
and runs the Tor Project's transport binaries unchanged. Reinventing the
circumvention arms race would be the mistake — Tor already fights it.

## The transports (honest per-transport matrix)

| Transport | Disguises traffic as | Cost / latency | When it's the right pick | Failure mode |
|---|---|---|---|---|
| **obfs4** | uniformly random bytes (no recognizable protocol) | low overhead, needs a reachable bridge IP | DPI that fingerprints protocols; you have private bridge addresses | the bridge IP itself can be enumerated/blocked |
| **Snowflake** | a WebRTC (video-call) data channel via ephemeral volunteer proxies | higher latency/jitter; proxies churn | the censor can't block "all of WebRTC"; no fixed bridge to enumerate | throughput/stability varies with the volunteer pool |
| **WebTunnel** | an ordinary HTTPS website behind a real domain | low; needs a fronting site | blocking it means blocking normal HTTPS to that host | the fronting domain can be discovered/blocked |

There is no permanent winner: transports get fingerprinted and must evolve. That
arms race is **external** (below).

## Use it

```sh
# Client, entering via an obfs4 bridge (TESSERA_PT + bridge lines):
TESSERA_EXIT_ONION=<exit>.onion:443 \
TESSERA_ISSUER=<issuer-host>:8121 \
TESSERA_PT=obfs4 \
TESSERA_BRIDGE_LINES='obfs4 <ip:port> <FINGERPRINT> cert=… iat-mode=0' \
scripts/run-onion-client.sh
```

`TESSERA_PT` is `obfs4` | `snowflake` | `webtunnel`; `TESSERA_BRIDGE_LINES` is one
or more `Bridge` lines (or a file path). The client **fails loud** if the
selected transport's plugin binary is missing — a censored user never silently
falls back to plain, blocked Tor. If Tor is reachable but no circuit builds, the
client diagnoses *"likely blocked — try a bridge."*

End-to-end demo on one box (real obfs4 → real Tor → `.onion`):

```sh
scripts/demo-bridge-entry.sh      # stands up a local obfs4 bridge + exit, pulls a live site
```

## What stays external (no code closes these)

`scripts/demo-bridge-entry.sh` runs a **local, self-run** bridge — it proves the
obfs4 entry *datapath*, **not** that it defeats a real censor. Genuinely
uncensorable-at-scale needs, irreducibly:

1. **A real, censor-unknown bridge population** — private obfs4 bridges, a live
   Snowflake broker + volunteer proxies, WebTunnel fronts. Tessera *reuses* Tor's
   bridge ecosystem; it does not run one.
2. **Real users in censored regions** to validate against actual DPI / active
   probing.
3. **The ongoing arms race** — transports get fingerprinted and must evolve;
   there is no permanent win.
4. **A genuinely clean egress IP at scale** + a real Tor/Nym anonymity crowd (the
   egress-side external gaps).
5. **A third-party security audit.**

Code gives the *mechanism*; "full" censorship resistance needs the *network*. This
is the same calibrated candor the project already applies to clean egress IPs —
see [`STATUS.md`](./STATUS.md) and [`THREAT_MODEL.md`](./THREAT_MODEL.md).
