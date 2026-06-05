# Observability and privacy review

> Status: research-grade, **UNAUDITED**. This document is the deliverable for
> SHOULD **S16** ("Observability/metrics spec + privacy review (doc)",
> [`docs/CEILING_PROGRESS.md`](CEILING_PROGRESS.md)). It reviews **what the nodes
> actually emit today** (every `println!`/`eprintln!` in the binaries, plus the
> in-memory/on-disk state they keep), evaluates each against the split-trust and
> no-log property, and states what an operator **MAY** safely meter and what must
> **NEVER** be logged. Cross-references: [`docs/THREAT_MODEL.md`](THREAT_MODEL.md)
> §3.3 (transport / no-log), [`docs/ARCHITECTURE.md`](ARCHITECTURE.md),
> [`docs/DEPLOY.md`](DEPLOY.md) §2 (the "verifiable, non-logging relay").

## 1. The property being protected

Tessera's anonymity rests on **split trust**: no single hop holds
`{who}` + `{where}` + `{what}` at once. From
[`tessera-relay/src/lib.rs`](../crates/tessera-relay/src/lib.rs) (crate docs,
lines 14–23):

- the **relay** (first hop) learns the *client's* address and the *exit's*
  address, but **never the destination** (it rides inside the opaque tunnel) and
  **never the credential**;
- the **exit** ([`tessera-proxy`](../crates/tessera-proxy/src/lib.rs)) learns the
  *destination* (the CONNECT host:port, i.e. SNI-level) and that *a valid
  credential* was presented, but **never the client's address** — its socket peer
  is always the relay;
- **neither** sees content: the client's TLS runs end-to-end through both hops
  (`pipe`, [`tessera-proxy/src/lib.rs:300`](../crates/tessera-proxy/src/lib.rs)),
  which only move opaque bytes.

Observability is therefore not a neutral concern. **Any log line that lets one
party reconstruct another party's half of the split breaks the whole scheme.**
The two specific linkages that must never be createable from logs:

1. **client ↔ destination** — the de-anonymizing link. No node may hold both. In
   particular **the relay must never log the destination**, and **the exit must
   never log the client.**
2. **credential ↔ destination** (or credential ↔ client over time) — would let
   the verifier partition the anonymity set (see
   [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.4 context partitioning).

[`THREAT_MODEL.md`](THREAT_MODEL.md) §3.3 already states the standing rule: even
with a clean transport, "the network and any logging middlebox certainly can
[read the IP], which undermines the anonymity the credential provides." The node
itself is the one middlebox the operator controls — so it must not become one.

## 2. What the nodes emit today

The honest headline: **there is no per-request logging anywhere in the request
path.** Every `println!`/`eprintln!` in the tree is either a one-time startup
banner, a fatal-config message, or an I/O-error warning on a non-request path.
`tessera-origin` (the admission guard, `OriginGuard::check`), `tessera-proxy`'s
`handle_connect`, `tessera-relay`'s `handle`/`handle_channel`, the
`tessera-issuer` wire handler (`net.rs`), and the `tower_layer` middleware emit
**nothing** per request — verified by grep: those files contain no print/log
macros at all.

### 2.1 Exit — `tessera-proxy` ([`src/main.rs`](../crates/tessera-proxy/src/main.rs))

All output is the startup banner (lines 86–102), printed once before the accept
loop. It prints the **bind address**, the route mode (`direct` / `via Tor`), a
**freshly minted demo credential** to paste into an example `curl`, and usage
text. None of it is request-derived. After the banner the process just sleeps
(line 104–106); the accept loop logs nothing per connection.

### 2.2 Relay — `tessera-relay` ([`src/main.rs`](../crates/tessera-relay/src/main.rs))

Two cases:

- **Deploy mode** (both `TESSERA_RELAY_LISTEN` and `TESSERA_EXIT_ADDR` set,
  lines 53–57): one startup line printing the relay's bind address and its
  fixed exit address (`-> exit {exit_addr}`). The exit address is the relay's
  one legitimate forwarding target; printing it is not a privacy leak.
- **Local all-in-one demo** (lines 96–121): a multi-line banner describing the
  loop, the relay/exit addresses, a single demo presentation header, and the
  honest "this proves the loop LOCALLY … a real Tor-403 site needs a real clean
  egress IP" caveat.

Per connection the relay prints **nothing**. Its `handle` function
([`src/lib.rs:184`](../crates/tessera-relay/src/lib.rs)) parses only the outer
`CONNECT <exit>` line and explicitly never parses inside the tunnel
(lines 195–197 comment: "we do NOT look for, log, or forward any credential
header"). The channel-mode handler (`handle_channel`,
[`src/lib.rs:401`](../crates/tessera-relay/src/lib.rs)) reads only its three
`Tessera-Channel-*` outer headers; still no logging.

### 2.3 Issuer — `tessera-issuer` ([`src/main.rs`](../crates/tessera-issuer/src/main.rs))

Startup banner (lines 82–113): the issuer's **bind address**, the key source and
an **8-byte public-key fingerprint** (`hex::encode(&pk.serialize()[..8])`,
line 67 — public material, the same fingerprint clients pin via
`TESSERA_ISSUER_PK`), the gate mode (PoW difficulty, or PAID + the public
`TokenMint` address), and client setup hints. Nothing per issuance.

One non-banner emitter: the durable redemption ledger's persist path
([`src/mint.rs:346,351`](../crates/tessera-issuer/src/mint.rs)) prints
`tessera-issuer: WARN redemption ledger {rename,persist} failed: {e}` on a file
I/O error. The error value `e` is a `std::io::Error` (path/OS error), not a
buyer identifier. This only fires in PAID mode and only on disk failure.

### 2.4 Client proxy — `tessera-client` ([`src/bin/tessera-client.rs`](../crates/tessera-relay/src/bin/tessera-client.rs))

Runs on the **user's own machine**, so its output is the least sensitive (it is
the one party already allowed to know everything about itself). It prints to
**stderr**: a TOFU warning when no `TESSERA_ISSUER_PK` pin is set (lines 64–67),
"obtaining a … credential from issuer {issuer}…" (lines 72–82, names the issuer
host the user themselves configured), and "credential obtained." (line 84). To
**stdout**: a startup banner (lines 101–110) including the user's own route
(`you → proxy → RELAY → EXIT → destination`) and the honest issuance-IP caveat.
No per-request output.

### 2.5 Tower demo — `tessera-tower-demo` ([`src/main.rs`](../crates/tessera-tower-demo/src/main.rs))

Banner only (lines 101–106): bind address and curl examples. This crate is a
middleware demo, not a deployment node.

### 2.6 Not request logs: examples, tests, and the `Observer`

Everything under `examples/`, `tests/`, and `tessera-demo` prints freely
(cross-language signature vectors in
[`tessera-channel/examples/eth_vector.rs`](../crates/tessera-channel/examples/eth_vector.rs)
and `rdec_vector.rs`, the demo UI in `tessera-demo/src/ui.rs`, the paid-loop
walk-through in
[`tessera-relay/examples/paid_loop.rs`](../crates/tessera-relay/examples/paid_loop.rs)).
These are developer tooling, not nodes, and are out of scope for the no-log
property — but note `paid_loop.rs` (and the vector generators) **do** print
destinations, balances, and signatures, so **do not repurpose example binaries
as production nodes.**

The `Observer` / `Observation` type
([`tessera-relay/src/lib.rs:96–140`](../crates/tessera-relay/src/lib.rs)) and the
exit-side `ExitObserver` / `ExitObservation`
([`tessera-proxy/src/lib.rs:75–84`](../crates/tessera-proxy/src/lib.rs)) look like
logging hooks but are **not**: they are the in-memory, test-only ledger the
integration test (`tests/loop.rs`) reads to *prove* the split — e.g. assert the
relay's `Observer.targets()` only ever contains the exit, never the destination.
Crucially, the two binaries that run relay/exit serve loops — `tessera-proxy`
and `tessera-relay` — **never wire an observer**: the exit uses
`serve`/`serve_observed_shaped` with observer `None` (`tessera-proxy/src/main.rs:73`;
and `tessera-relay/src/main.rs:76` via `tessera_proxy::serve`, which is
`serve_observed(.., None)` — [`proxy/src/lib.rs:94`](../crates/tessera-proxy/src/lib.rs)),
and the relay uses `tessera_relay::serve(.., None)` (`tessera-relay/src/main.rs:57,83`).
The `tessera-issuer` binary has no observer at all. So the observers record
nothing in any shipped node. They are an assertion harness, not telemetry, and an
operator **MUST NOT** wire a persisting observer into a real node (it would record
the exit's destination ledger or the relay's client ledger — see §4).

## 3. State the nodes keep (the real privacy surface)

No log lines does not mean no state. Three pieces of node state touch
privacy-relevant values; an auditor should treat them as the de-facto "log":

| State | Where | Holds | Risk class |
|---|---|---|---|
| **Spent-tag set** | `FileTagStore` / `InMemoryTagStore` ([`tessera-origin/src/store.rs`](../crates/tessera-origin/src/store.rs)) | each accepted presentation **tag** (a SEC1-compressed P-256 point), needed for double-spend defense | credential-side, see below |
| **Volume-shaper window** | `VolumeShaper.seen: HashMap<dest_host, ts>` ([`tessera-proxy/src/shaping.rs`](../crates/tessera-proxy/src/shaping.rs)) | **destination hosts** seen per egress IP within a sliding window (M5 human-volume shaping) | **destination-side, exit only** |
| **Redemption ledger** | `RedemptionLedger` ([`tessera-issuer/src/mint.rs`](../crates/tessera-issuer/src/mint.rs)) | `(eth_address, redeemed_count)` for PAID-mode mints | issuer-side, on-chain-public address |

Notes for the reviewer:

- **The spent tag is per-presentation, not per-credential.** Each presentation
  derives a fresh tag (the nullifier for one `(credential, context, nonce)`
  slot); ARC's unlinkability means two tags from the same credential are not
  linkable absent a discrete-log break (ARC §7.2 quantum-DL caveat;
  [`THREAT_MODEL.md`](THREAT_MODEL.md) §2(b)/§3.2). The tag set must persist for
  replay defense, but it is **not** a request log: it contains no destination, no
  client IP, no timestamp. `FileTagStore` appends only the hex-encoded tag (one
  tag per line, no metadata — no destination, IP, or timestamp;
  [`store.rs:158–159`](../crates/tessera-origin/src/store.rs)). This is the
  intended, necessary state — do not "enrich" it with destination or peer.
- **The shaper window is the exit's only destination-side state, and it is the
  one piece of in-memory state that, if exfiltrated/persisted, partially recreates
  a destination history for an egress IP.** It is RAM-only, pruned to the window
  (`seen.retain(... ts >= cutoff)`,
  [`shaping.rs`](../crates/tessera-proxy/src/shaping.rs) line 156), and never
  written to disk or stdout. It still must never be paired with the client
  identity — which it cannot be, because the exit never sees the client. Keep it
  that way: do not log shaper decisions keyed by anything but the destination
  host, and never persist the window.
- **The redemption ledger stores Ethereum addresses**, which are already public
  on-chain; it does not link an address to any presentation, destination, or
  client. The address ↔ later-browsing unlinkability is exactly what ARC
  provides (issuer sees the buyer at mint time, never the traffic). Only the
  count is needed; do not add destination/presentation fields.

## 4. Privacy review — per emitter

| Emitter | Could it link client↔dest / leak the protected half? | Verdict |
|---|---|---|
| Exit startup banner (`proxy/main.rs:86–102`) | No request data; the demo header is a *minted* credential, not a presented one | **Safe** |
| Relay startup banner (`relay/main.rs:53–57, 96–121`) | Prints relay+exit addresses (relay's legitimate next hop) and a demo header; never a destination | **Safe** |
| Issuer banner (`issuer/main.rs:82–113`) | Bind addr + public key fingerprint + gate mode; no issuance data | **Safe** |
| Issuer ledger WARN (`mint.rs:346,351`) | Prints an `io::Error`, not a buyer/address; PAID mode + disk-fault only | **Safe** |
| Client banner/stderr (`tessera-client.rs`) | Runs on the user's own host; names the user's own issuer/route | **Safe (local)** |
| `Observer` / `ExitObservation` | *Would* record dest (exit) or client (relay) if persisted — but is `None` in every node | **Safe as shipped; do not wire into prod** |
| Spent-tag store | Persists tags only — no dest, no client, no time | **Necessary; keep minimal** |
| Volume-shaper window | Destination hosts per egress IP, RAM-only, windowed, exit-only | **Safe in-memory; never persist/log** |

**No emitter currently links client↔destination.** The relay literally cannot
print a destination (it never parses inside the tunnel), and the exit literally
cannot print a client (its socket peer is the relay). The split-trust property
is preserved *structurally*, not by log redaction — the safest possible posture.

## 5. What an operator MAY safely meter

Counts and health, never identifiers. The following are derivable today (or with
a small, privacy-preserving counter) and do **not** create a linkage:

- **Aggregate counters with no per-request key**: total connections accepted,
  total admitted, total rejected (optionally bucketed by `RejectReason` —
  `MissingCredential` / `Malformed` / `InvalidProof` / `DoubleSpend`, from
  [`tessera-origin/src/lib.rs`](../crates/tessera-origin/src/lib.rs)), `502`/`503`
  counts. A `407`/`402`/`503` *rate* is a useful health/abuse signal and carries
  no client or destination identity.
- **Concurrency / liveness**: current in-flight count (the relay/exit already
  track this in the `MAX_INFLIGHT` `AtomicUsize`, capped at 1024 —
  [`proxy/src/lib.rs:38`](../crates/tessera-proxy/src/lib.rs)); uptime; whether
  the accept loop is alive.
- **Spent-tag set size**: `InMemoryTagStore::len()`
  ([`store.rs:57`](../crates/tessera-origin/src/store.rs), documented "observability
  / tests") or `FileTagStore::len()`
  ([`store.rs:134`](../crates/tessera-origin/src/store.rs)) — a single integer (how
  many presentations have been spent), with no per-tag detail. Safe as a gauge.
- **Shaper aggregates**: count of throttle decisions, current distinct-destination
  window size as a *number* — never the destination set itself.
- **Issuance counts** (issuer): credentials minted per epoch, PoW-vs-PAID split,
  redemption-ledger total. Not which address minted which credential beyond what
  the ledger already needs.

Rule of thumb: **a metric is safe iff it is a scalar or a histogram with no
high-cardinality, request-identifying label.** No labels for destination host,
client IP, presentation tag, channel id, or Ethereum address.

## 6. What must NEVER be logged or persisted

To preserve split-trust + the no-log property, **no node may emit or store**:

1. **The destination at the relay.** The relay must never parse, log, persist, or
   forward anything from inside the tunnel — i.e. never the inner `CONNECT`
   host:port. (Structurally enforced today; do not add it.)
2. **The client at the exit.** The exit must never log its socket peer in a way
   that could be correlated to a destination — and in the 2-hop loop the peer is
   the relay anyway, so even peer-logging there does not reach the client, but
   **do not log the peer alongside the destination.**
3. **Any client↔destination pairing**, on any node, in any form (one log line,
   two correlatable lines with timestamps, or a persisted `Observation`).
4. **Presentation tags joined to anything else.** The spent-tag store may hold the
   tag for replay defense, but never `tag + destination`, `tag + timestamp`, or
   `tag + peer`. That join would let the verifier partition the anonymity set
   ([`THREAT_MODEL.md`](THREAT_MODEL.md) §3.4) and link a credential's spends.
5. **Ethereum address ↔ presentation / destination / client** at the issuer.
   The ledger keeps `(address, count)` only; never tie it to issued credentials
   or downstream traffic — that would defeat ARC issuer-unlinkability.
6. **Plaintext or per-connection timing/byte-count fingerprints.** The tunnel is
   end-to-end TLS by construction; do not add request/response size or precise
   timing logs that could fingerprint a flow.
7. **The full shaper window or per-decision destination logs.** Keep it the
   in-memory, windowed gauge it is.

## 7. Deployment guidance

- **Default to silent.** The shipped nodes already emit no request data; keep any
  added telemetry to the §5 scalar/histogram set. If you add a metrics endpoint
  (e.g. Prometheus), expose only label-free counters/gauges.
- **TEE deployment makes this enforceable, not just promised.** Per
  [`DEPLOY.md`](DEPLOY.md) §2, running the relay in an Intel TDX enclave with
  remote attestation lets a client *verify* the node is exactly this
  open-source, no-log image before trusting it — "it physically cannot be
  modified to log." That is the strongest available answer to "trust me, I don't
  log": the no-log property becomes attestable rather than asserted. `dstack`'s
  `--public-logs` publishes the node *measurement* and its stdout logs
  ([`DEPLOY.md`](DEPLOY.md) §2); since the shipped nodes emit only the §2 startup
  banner and no per-request data (this review), those public logs contain no
  request data.
- **Never enable the `Observer`/`ExitObserver` in a node.** They are a test-only
  split-trust proof harness (§2.6); a persisting observer is, by construction, a
  destination ledger (exit) or a client ledger (relay).
- **Standard caveats apply.** This is research-grade and **UNAUDITED**; the clean
  egress IP, an anonymizing transport (Tor), and operator honesty/attestation are
  **external** to this codebase ([`THREAT_MODEL.md`](THREAT_MODEL.md) §3.3, the
  README's honest-limits section). Observability discipline protects the
  application-layer split; it does not substitute for the transport.
