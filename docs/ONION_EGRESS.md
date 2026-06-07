# Tessera as a Tor-native onion egress

> A reputation/credential-gated egress proxy **published as a Tor onion service**.
> Same shape as [`reputation-gated-onion-egress`](https://github.com/dmarzzz/reputation-gated-onion-egress)
> (RGOE) — no exit node, rendezvous hides the client, the gateway egresses from
> its own clean IP, TLS end-to-end — but the per-request gate is a **single-use,
> replay-proof ARC token**, the exit has a **real SSRF/target gate**, spent state
> is **durable**, and it's backed by a tested std-only Rust core. Research-grade,
> **UNAUDITED**.

The architecture is **not "Tor plus a bolted-on hop."** The exit *is* an onion
service; the client reaches it over Tor as the path. (Tessera also keeps a
clearnet 2-hop relay loop, but that is an explicit opt-out, not the default — see
[`CLEAN_ONION_EGRESS.md`](./CLEAN_ONION_EGRESS.md).)

```text
  curl ─▶ tessera-client (local proxy) ──Tor SOCKS──▶ EXIT.onion:443
                                         (single hop, no exit node)
  EXIT (ARC-gated + SSRF-hardened) ──clean egress──▶ the live site (TLS e2e)
```

## Run it yourself (one command, real Tor)

```sh
cargo build
scripts/demo-onion-egress.sh          # or: scripts/demo-onion-egress.sh https://example.com
```

It stands up an issuer, the exit, a real Tor onion service in front of the exit,
and the Tor-native client, then pulls a live HTTPS site **through the onion
egress**. A real run (transcript trimmed to the onion-relevant lines; run the
script yourself for the full output):

```text
3) tor — publish the exit as an onion service (.onion:443 -> the exit's loopback)
   onion: kq2werhgb74bbl4khogdps77poihyuuwhq2bmxt3e5rnzino76m4q2yd.onion
4) tessera-client — obtains a credential, routes over the onion (Tor-native)
=== pulling https://api.ipify.org through the onion egress ===
response through the onion egress:
67.245.x.x
```

The request traversed a real onion circuit, was admitted on a single-use ARC
token, cleared the secure target policy, and reached the live internet.

**Honest caveat:** on one machine the egress IP equals your own (the exit
egresses from this box). The *clean egress IP* is a two-machine concern: run the
exit on a separate clean-IP host with `scripts/run-onion-exit.sh` and the client
with `scripts/run-onion-client.sh`. No code manufactures a clean IP — that, a
real Tor/Nym crowd, and a third-party audit stay external.

## Deploy (two machines)

- **Gateway / clean-IP box:** `scripts/run-onion-exit.sh` — publishes the exit as
  an onion service (persisted, stable `.onion`), runs the issuer beside it, binds
  the exit to loopback (reachable *only* through the onion), secure target policy,
  durable spent-tags.
- **Client / laptop:** `scripts/run-onion-client.sh` — a client-only Tor (SOCKS)
  + the local proxy on the onion route. Point curl/browser at it.

The onion-service secret key under `HiddenServiceDir` is a **plain on-disk file**;
a non-logging TEE must seal it to the enclave (the reserved `dstack-kms` path) —
do not treat the on-disk key as enclave-protected.

## Honest head-to-head: Tessera vs RGOE

Same Tor-native shape. Where they differ:

| | RGOE | Tessera |
|---|---|---|
| Transport | onion service, no exit node, rendezvous hides client | **same** |
| Per-request gate | Semaphore proof over a **constant** `MESSAGE = 1n`, cached per epoch, **re-sent verbatim** — its README documents replay-in-epoch as allowed, safe only inside the tunnel | **single-use ARC token**; fail-closed spent-tag store rejects replay (`DoubleSpend`) **regardless of whether the wire is observed** |
| Egress target safety | gateway opens raw `net.connect(target)` with only a `:443` port check — no private/metadata-IP defense (textbook SSRF) | **secure target policy**: refuses private/loopback/link-local/CGNAT/`169.254.169.254` (v4+v6, incl. IPv4-mapped/NAT64/6to4) + non-allowlisted ports, **resolve-then-pin** vs DNS rebinding, run *before* the credential check |
| Spent/rate state | in-memory `Map` — forgotten on restart | durable `FileTagStore` — survives restart |
| Multi-exit | one gateway, `members.json` Merkle set | **signed directory** (per-exit ARC key domains, threshold-signed `.onion` + `clean_egress` advertisement, anti-rollback) |
| Payment rail | — | ETH-paid `TokenMint` + an optional ZK payment channel (the "fancier payments" worth folding in) |
| Rigor | zero tests, zero CI, 14 `npm audit` advisories | a tested std-only Rust core — hundreds of unit/integration tests, a multi-job CI gate, fuzz targets, `cargo-deny`, IETF-vector-proven (run the suite for exact counts) |

**Where RGOE is genuinely ahead (and we should adopt):**
- It's **deployed and tested live** on a real clean-IP box.
- **Semaphore is a real anti-Sybil membership primitive.** ARC's per-request token
  rate-limits but does not itself decide *who may join* — that is exactly what a
  reputation set is for.
- Its one-command deploy/verify UX is polished.

## The synthesis (the actual pitch)

Everything yours does — onion egress, no exit node, rendezvous, TLS e2e — on a
**replay-proof, SSRF-gated, durable, tested** core, with a payment rail and a
signed multi-exit directory. The clean move is not either/or:

> **Keep your Semaphore reputation set — it's the better anti-Sybil primitive —
> but move it to _issuance time_, and let the replay-proof single-use ARC token be
> the _egress_ gate.** Prove membership to the issuer to mint a credential;
> present a fresh unlinkable token per request to the exit. You get anti-Sybil
> admission *and* a per-request gate that doesn't depend on the channel being
> unobservable.

Net: your deployment + your reputation set, on Tessera's hardened, tested,
Tor-native core — and here it is actually pulling a live site through Tor.
