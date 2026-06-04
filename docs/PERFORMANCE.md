# Tessera — performance & latency (does speed matter? yes)

> Speed is not secondary to privacy here — for an access network it's co-primary.
> A perfectly private path nobody will wait for is unused. This is the honest
> where-the-time-goes analysis and the levers. Research-grade; numbers are
> order-of-magnitude.

## The headline: the pivot makes it faster

The leaner architecture (ecash token + Tor, see [`ARCHITECTURE.md`](./ARCHITECTURE.md))
is **faster per request** than the ZK-channel path it replaces, because it removes
the per-request heavy work:

| Per-request cost | Channel path (old) | Token path (leaner) |
|---|---|---|
| Token / spend check | secp256k1 sign + co-sign + cursor | **one ARC verify (~sub-ms)** |
| On-chain settlement | amortized, but dispute/close machinery | **none in the common path** |
| ZK proving | (only at settlement) Groth16 prove is seconds | **none** |

So choosing tokens wasn't only simpler — it shaved the per-request critical path.

## Where the latency actually goes

For a request through the network, end-to-end latency ≈

```
   Tor circuit RTT  (DOMINANT)         ~hundreds of ms … low seconds
 + token verify     (~sub-ms)          negligible
 + shaping jitter   (0–150 ms, tunable) small, and only the pre-connect pace
 + egress→site RTT  (normal internet)  whatever the site is
```

**Tor is the dominant term by far.** Tessera's own added compute (verify one
token, consult the shaper) is sub-millisecond — it is *not* the bottleneck. This
is the honest privacy↔speed tradeoff: the anonymity comes from routing through
Tor's multiple relays, and that routing is the latency. Tessera doesn't make Tor
slower; it rides it.

## Throughput

The per-request server-side work is cheap: an ARC presentation verify is ~tens of
EC point ops (~sub-ms), so a single core verifies thousands/sec. The binding
constraint is therefore **not** crypto throughput but:

- the **DoS concurrency cap** (S3, `MAX_INFLIGHT`) — a deliberate safety bound on
  simultaneous tunnels, tunable per node;
- the **clean-IP egress budget** — the human-volume shaper (M5) intentionally
  *paces* a single IP, so per-IP throughput is bounded *by design* (that's the
  point: it's what keeps the IP clean). Aggregate throughput scales with the
  number of clean egress IPs, which is the external supply problem.

So: plenty of crypto headroom; throughput is gated by the egress portfolio, not
by Tessera's code.

## The speed levers (what we can do)

Several are already present or cheaply buildable, ordered by impact:

1. **Sticky sessions + connection reuse** — the shaper (M5) already treats
   re-visits to a seen destination as free; keeping the egress TCP/TLS connection
   warm avoids re-paying circuit + TLS setup on every request to the same site.
   The single biggest win for real browsing (most page loads hit a few hosts
   repeatedly).
2. **Read-tier / PIR + caching** (`IP_EGRESS_IDEAS.md` §2) — for the ~20–40% of
   volume that is cacheable reads (Wikipedia, package registries, docs), serve
   from a query-private mirror and **skip the egress circuit entirely**. Both a
   latency win and a load-shed off the scarce exit pool.
3. **Mode-switched transport** (`DESIGN.md` §3) — an interactive MASQUE/QUIC
   2-hop fast-path for latency-sensitive traffic vs the bulk mixnet for the rest;
   QUIC's 0-RTT resumption and head-of-line-blocking avoidance help interactive
   loads. (Inherited design; unbuilt.)
4. **Parallel circuits / prefetch** — fan a page's sub-resource fetches across
   circuits; standard browser-over-Tor practice.
5. **Tune the shaper jitter** — the pre-connect jitter (default ≤150 ms) trades a
   little latency for fingerprint resistance; a deployment can lower it when the
   IP's reputation allows.

## Human vs agent

The latency floor (Tor) matters differently by user:

- **AI agents** (a core target) are far less latency-sensitive than humans — a
  few-hundred-ms added RTT is irrelevant to an agent doing a research task. The
  leaner path is already comfortably fast enough here.
- **Interactive human browsing** is where the floor bites; the sticky-session
  reuse (1) + read-tier caching (2) + the QUIC fast-path (3) are the levers that
  make it tolerable. Honest: it will never be faster than direct, non-private
  access — that's the cost of the anonymity, and it's Tor's cost, not ours.

## Bottom line

Speed matters and we optimize for it: the architecture choice already favored the
faster per-request path, our own overhead is sub-millisecond, and the dominant
cost is Tor's (intrinsic to the privacy). The realistic wins are connection
reuse, a cacheable read-tier, and a QUIC fast-path — not shaving our crypto, which
is already negligible.
