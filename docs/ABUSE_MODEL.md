# Tessera — abuse / DoS model (S3)

> Resource-exhaustion and griefing surface, from a 25-agent adversarial sweep of
> the actual code (relay, exit, issuer, court, proof-verification, tag stores). Each
> vector is code-cited and marked **FIXED here** or **deploy-tier / operational**
> with the honest reason. Companion to [`THREAT_MODEL.md`](./THREAT_MODEL.md)
> (which covers confidentiality/integrity) and [`SECURITY.md`](../SECURITY.md).
> Research-grade; UNAUDITED.

## Principle

The system handles **unauthenticated, attacker-controlled input before any
payment/credential check** (a relay accepts a TCP connection and parses headers
before it can verify a spend; an exit parses the CONNECT request before
`OriginGuard::check`). So the accept-and-parse layer must be bounded in memory,
threads, and time regardless of payment. The fixes below add those bounds; the
remaining items are genuinely deploy-tier (a sandbox can't manufacture a rate-limit
appliance or a fee market) and a *naive* code fix for several would **backfire**,
which we document rather than ship.

## FIXED here

| # | Surface | Vector | Fix |
|---|---------|--------|-----|
| 1 | relay + exit | **Unbounded thread spawn** — one OS thread per accepted connection, no cap → a flood exhausts threads/memory (~MiBs of stack each). | A hard `MAX_INFLIGHT` (1024) concurrency cap enforced **on the accept thread before spawning** (`tessera-relay` `serve`/`serve_channel`, `tessera-proxy` `serve_observed_shaped`); excess gets `503` and is dropped. An `InflightGuard` RAII decrements on every handler return path. |
| 2 | relay + exit | **No socket timeout** — a slow-roll / idle peer pins a worker thread + fd forever (slowloris on the CONNECT line, or a stalled tunnel). | A 30s read+write timeout set on the accepted stream **before** spawning the handler, and on the upstream socket before `pipe()`, so the blocking parse/copy loops unblock on idleness. |
| 3 | exit | **`VolumeShaper.seen` unbounded growth** — the window-prune only shrinks the map once entries *age out*, so a within-window flood of distinct destinations grows it without bound. | A hard `max_distinct_destinations_stored` cap (default 10 000, ≫ the human envelope); when full, the oldest-timestamp entry is evicted before inserting a new host. Tested with a 5 000-host flood. |
| 4 | relay (channel) | **`seen_nonces` unbounded growth** — the relayer's per-channel freshness set grew once per accepted spend with no cap and no in-place epoch reset, so a long-lived channel accumulated nonces for its lifetime. | A per-epoch budget `MAX_NONCES_PER_EPOCH` (1024, mirroring the circuit's `idx ∈ [0,1024)`): a new nonce past the cap is rejected `EpochBudgetExhausted`. New `RelayerChannel::advance_epoch` resets the set in place (preserving the balance cursor), so memory is freed each epoch instead of growing forever (see [`EPOCH_AUTHORITY.md`](./EPOCH_AUTHORITY.md)). |
| 5 | issuer | **Unbounded thread spawn + slow-roll on the networked issuer** (`serve_issuance`/`serve_issuance_paid`) — one OS thread per issuance connection, and the PoW/eth_call work happens after accept. | Same accept-before-cost shape as the relay/exit: a `MAX_INFLIGHT` cap (256 — the issuer's per-credential work is heavier, so a lower bound) enforced on the accept thread before spawning, an `InflightGuard` RAII, and a 30s read/write timeout on the issuance socket; the `eth_call` reply is length-capped (64 KiB). The cap differs from the relay/exit's 1024 by design (cost-per-connection, not an oversight). |

All five are tested (proxy shaping suite, channel protocol suite, issuance/network tests) and CI-green.

## Deploy-tier / operational (documented, NOT shipped — and why a naive fix backfires)

| # | Surface | Vector | Why it is not a code fix here |
|---|---------|--------|-------------------------------|
| 6 | court | **`channels` mapping state-trie growth** — `open()` is permissionless; channels are never pruned, so spam permanently bloats chain state at ~1 wei each. | The naive fixes **backfire**: a `MIN_ESCROW` floor deters nobody (it's refundable via `refundOnTimeout`), and a global `channelCount` cap turns bloat into a *liveness* DoS on the shared namespace. The only sound fix is a **non-refundable creation fee** to an immutable sink + deletion of terminal records — a real economic/parameter choice for a *mainnet* deploy, out of scope for the testnet-only court. Tracked. |
| 7 | tag stores | **Spent-tag set unbounded growth** (memory/disk) in `InMemoryTagStore`/`FileTagStore`. | The obvious time-based eviction (`clear_before(t)`) is **UNSAFE** — dropping old spent tags **re-opens the double-spend window** (`THREAT_MODEL.md` §6.1 names the store as the enforcement boundary). Safe pruning must be **epoch-scoped** (tied to credential epochs, so a tag is dropped only once its credential can no longer be presented) — a deployment-tier design needing the cross-layer epoch authority, not a wall-clock timer. |
| 8 | tag stores | **`FileTagStore` per-write `flush()` + `sync_data()`** on the hot path. | This is a **latency/efficiency** matter, not a DoS. The file store intentionally fails closed and syncs each accepted tag so restart replay protection is real for a single exit. A buffered/batched writer is future perf work only if it preserves a clear durability boundary. |
| 9 | proof verify | **Verification cost on unauthenticated input** — an ARC presentation forces ~120 EC point ops in the sigma/range-proof verify before rejection; an attacker can spam invalid presentations. | This is the irreducible cost of verifying any Schnorr/Groth16 proof; there is no cheap algebraic pre-filter beyond the exact-length deserialization check already present. The mitigation is **operational**: rate-limit / per-IP-or-credential budget **before** the expensive verify, and order cheap checks first (the relay's outer header parse + the exit's length check already precede the crypto). A network appliance / reverse-proxy budget is the production answer. |

## Status

Vectors 1–5 are closed in code and tested. Vectors 6–9 are documented with their
honest deployment-tier mitigations; none is hidden, and for 6 and 7 the doc
explicitly records *why the naive code fix is wrong* so a future implementer
doesn't ship it. This is the abuse-model half of the security posture; the
confidentiality/anonymity surface lives in `THREAT_MODEL.md`.
