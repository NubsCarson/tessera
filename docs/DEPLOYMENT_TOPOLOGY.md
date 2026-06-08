# Deployment Topology & Trust-Boundary Spec

> Ceiling item **S13** (`docs/CEILING_PROGRESS.md`). The honest, code-grounded map
> of *who runs what, who learns what, and who must not collude* in a deployed
> Tessera network. Research-grade, **UNAUDITED** — read the limits in
> [`DEPLOY.md`](./DEPLOY.md) and the threat model in
> [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3 before trusting any of it. This
> document is the deployment-topology companion to those two; where they speak in
> protocol terms, this speaks in *node and operator* terms.

## 1. The four nodes

A deployed network is **four** roles, all built from one image (`Dockerfile`),
the binary selected by `command:` (see `deploy/docker-compose.yaml`). Each is
configured entirely by env vars; no role holds *who* + *where* + *what* at once.

```
                          obtain a credential (PoW or paid ETH) — DIRECT connection
        ┌──────────────────────────────────────────────────────────┐
        │   the ISSUER sees the client's source IP + issuance time   │ ◀── IP exposure
        ▼                                                            │     lives HERE
   ┌─────────┐                                              ┌─────────────────┐
   │ CLIENT  │                                              │ ISSUER          │
   │ proxy   │                                              │ (authority)     │
   │ :8120   │                                              │ :8121           │
   └────┬────┘                                              └────────┬────────┘
        │ you → local proxy                                          │
        │ (TLS end-to-end past here; CONNECT only)         shares one ARC server key
        ▼                                                            │ in this key domain
   ┌─────────┐  outer CONNECT exit   ┌─────────┐  inner CONNECT dest │
   │ RELAY   │ ───── opaque bytes ──▶│ EXIT    │ ───────────────────┘
   │ :8119   │                       │ :8118   │ ──(its own egress IP)──▶ destination
   └─────────┘                       └─────────┘
   learns {client, exit}             learns {destination, a valid token}
   never destination/content         never the client
```

(Layout matches the `deploy/docker-compose.yaml` header flow and the
`tessera-relay` ASCII diagram in `crates/tessera-relay/src/lib.rs`.)

"Bind (compose / node mode)" shows what the compose sets via env; the code default
(when that env var is unset) differs and is noted inline.

| Node | Binary | Bind (compose / node mode) | Crate role |
|---|---|---|---|
| **Client proxy** | `tessera-client` | `127.0.0.1:8120` (code default, `tessera-client.rs:17,120`) | local `CONNECT` proxy the user points a browser/curl at (`crates/tessera-relay/src/bin/tessera-client.rs`) |
| **Issuer** | `tessera-issuer` | `127.0.0.1:8121` | credential authority; PoW- or payment-gated ARC issuance (`crates/tessera-issuer/src/main.rs`) |
| **Relay** | `tessera-relay` | `0.0.0.0:8119` set by compose `TESSERA_RELAY_LISTEN` (`docker-compose.yaml:60`); node mode has no code default (`main.rs:42-59`), the only code default is the local-demo `127.0.0.1:8119` (`main.rs:79`) | credential-blind first hop (`crates/tessera-relay/src/main.rs:42-59`) |
| **Exit** | `tessera-proxy` | `0.0.0.0:8118` set by compose `TESSERA_LISTEN` (`docker-compose.yaml:46`); code default when unset is `127.0.0.1:8118` (`DEFAULT_LISTEN` in `crates/tessera-proxy/src/main.rs`) | credential-gated `CONNECT`; egresses from its own IP (`crates/tessera-proxy/src/main.rs`) |

The full loop is verified end-to-end in-process by
`crates/tessera-relay/tests/network.rs` (credential over the wire → 200 through
the loop → auto re-issue → pin mismatch rejected), and is described in
[`DEPLOY.md`](./DEPLOY.md) §1.

## 2. Data flow & what stays opaque

1. **Client → Issuer (direct).** The client obtains a credential, paying the PoW
   (`obtain_credential`) or proving an on-chain entitlement (`obtain_credential_paid`,
   `tessera-client.rs:34,264-283`). **This connection is direct**, so the issuer sees
   the client's source IP (§4). ARC issuance is blind: the issuer cannot tie the
   credential it signs to any later presentation.
2. **Client → Relay (outer CONNECT).** The client proxy opens an *outer*
   `CONNECT <exit-addr>` to the relay (`tessera-relay/src/lib.rs:9-16`). The relay
   forwards opaque bytes to its one fixed next hop and rejects a `CONNECT` to
   anywhere else — it refuses to be an open proxy (`lib.rs:222-223`,
   `main.rs:144-147`).
3. **Relay → Exit (opaque tunnel).** Inside that tunnel the client sends a
   *nested / inner* `CONNECT <destination>` carrying the `Tessera-Presentation`
   credential header. The relay never parses inside the tunnel; it does **not**
   look for, log, or forward any credential header (`lib.rs:195-197`). Only the
   exit reads the inner CONNECT and the credential.
4. **Exit → destination (its own egress IP).** The exit verifies the credential
   via `OriginGuard` *before* forwarding a byte (sign-then-serve; a bad / replayed /
   over-budget spend → `Decision::Reject` → **407** and never reaches the
   destination, `tessera-proxy/src/lib.rs:205-214`), then egresses `direct` or via
   Tor (`TESSERA_UPSTREAM`, resolved by `resolve_upstream` in
   `crates/tessera-proxy/src/main.rs`). The destination sees the **exit's** IP.

TLS is end-to-end through the whole chain (the tunnel is opaque CONNECT bytes),
so **no node sees plaintext** — the runtime image carries `ca-certificates` only
for tooling, never to terminate TLS (`Dockerfile:24-26`).

## 3. The shared-key boundary (issuer ↔ exit)

ARC is **keyed-verification**: the exit needs the issuer's *server secret* to
verify presentations, so the **issuer and exit share one ARC server key**. They
converge on it via a single `TESSERA_KEY_FILE` — `ensure_shared_key` is a
single-winner create that cannot diverge (`crates/tessera-issuer/src/keyfile.rs`,
called from `crates/tessera-issuer/src/main.rs` and
`crates/tessera-proxy/src/main.rs`). In the local compose this is a shared Docker
volume (`deploy/docker-compose.yaml:35-36,50-51,83-87`).

**Implication for the trust graph:** the issuer↔exit pair is *one keyed-verifier
trust domain*, not two independent parties — they hold the same secret. A
malicious exit and a malicious issuer are, cryptographically, the same actor (the
"malicious origin operator" of `THREAT_MODEL.md` §3.4). The split that matters is
**relay vs. {issuer+exit}**, not relay vs. issuer vs. exit as three peers.

**Multi-exit decision:** one shared ARC server key is correct only for one
single-exit key domain. Independent exits must each have their own issuer/key
domain (`issuer-a + exit-a`, `issuer-b + exit-b`, ...). A credential is therefore
exit/key-domain scoped, not automatically fleet-portable. Sharing one ARC key
across an independent fleet would give every exit the minting-and-verification
secret for every other exit and make one compromise a fleet-wide compromise. The
normative decision is [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md).

The file-based key is fine on a trusted host / shared volume but is the weakest
point of a multi-host deployment: the secret lands on disk. The fix is to
**derive the shared key from the dstack KMS and seal it to the enclaves** so it
never touches a disk. The binaries now **implement** `TESSERA_KEY_PROVIDER=dstack-kms`
(`crates/tessera-issuer/src/dstack_kms.rs`): it derives the shared key from the
dstack guest agent (`GetKey`) and keeps it in enclave memory, never on disk —
fail-closed off-TEE, and proven only against a mock + the dstack simulator, **not**
real TDX hardware. The TEE compose (`deploy/dstack/docker-compose.yaml`) wires the
exit to this provider and mounts the dstack socket; it still omits the issuer.

## 4. Where the client → issuer IP exposure sits

Obtaining a credential is a **direct client→issuer connection**, so the issuer
learns the **client's source IP and the time of issuance** — stated bluntly in
`THREAT_MODEL.md` §3.5, `DEPLOY.md` "Honest limits", and the binary's own doc
comment (`tessera-client.rs:8-11`, runtime warning `:306-308`). ARC issuance
unlinkability still holds: the issuer **cannot** tie that IP to any later
presentation/browsing. But the *act* of issuance is not hidden by this protocol.

This is the one IP exposure inside the system. The browsing path (client → relay
→ exit → destination) never exposes the client IP to the exit or destination,
because the relay is the only node that sees the client and it never sees the
destination. To hide issuance too, the client must reach the issuer over an
anonymity transport (Tor) — `obtain_credential` is transport-agnostic
(`THREAT_MODEL.md` §3.5; `ARCHITECTURE.md` notes that a real Tor/Nym crowd must
also cover this hop). In the all-localhost demo this is moot.

## 5. Per-node trust table

For each node: what it **learns**, what it is **trusted for**, and what it
**cannot see / cannot do**. "Learns" = observable to a fully malicious operator
of that node alone.

| Node | Learns | Trusted for | Cannot see / cannot do |
|---|---|---|---|
| **Client proxy** | everything (it is the user's own machine) | nothing by others — it is *your* agent | n/a (local; bound to `127.0.0.1`, not a public service, `docker-compose.yaml:78-80`) |
| **Issuer** | client **source IP + issuance time** (direct connection); that *some* credential was minted; (paid mode) the buyer's Ethereum address | gating issuance (PoW difficulty floor `MIN_DIFFICULTY=1`, refuses `0`/wide-open, `tessera-issuer/src/main.rs:48-50,178`); not over-issuing entitlements (durable ledger, paid mode) | which presentation/browsing a credential it signed maps to (ARC blind issuance); the destination; plaintext |
| **Relay** | **{client peer, exit address}**; connection timing/volume | being credential-blind and **not logging or colluding** (the core split-trust assumption) | the destination (inside opaque bytes, `lib.rs:213-218`); the credential (`lib.rs:195-197`); plaintext; cannot be an open proxy (`lib.rs:222-223`) |
| **Exit** | **{destination (inner CONNECT host:port), that a valid in-budget token was presented}**; its own egress IP is seen by the destination | verifying credentials for its key domain (holds that exit domain's ARC key); enforcing the per-credential budget (`OriginGuard`, `LIMIT=64`) and per-IP human-volume shaping (`VolumeShaper`, M5, wired in `crates/tessera-proxy/src/main.rs`); operating a **clean** egress IP (external — see below) | the client's IP/identity; plaintext |

(The split-trust ledger types make the asymmetry concrete: the relay's
`Observation` (`crates/tessera-relay/src/lib.rs:97-103`) records the exit's
address as its `connect_target`, while the exit's `ExitObservation`
(`crates/tessera-proxy/src/lib.rs:76`) records the destination. By construction
the relay never records the destination and the exit never records the client.)

## 6. Trust boundaries: who must not collude

The anonymity rests on **non-collusion across one boundary**. The relay sees
*who* (client) + the next hop; the exit sees *where* (destination) + *what token*.
Joining those two views re-links a client to its destination.

- **Relay ⟂ {Issuer + Exit} (the load-bearing boundary).** If the relay and the
  exit collude (or are the same operator, or one logs and hands its log to the
  other), then `{client}` from the relay joins `{destination}` from the exit and
  the split-trust property collapses. **These must be operated by mutually
  distrusting parties and must not log.** This is exactly why the TEE variant
  exists: an attested enclave lets a client *verify* the relay matches the
  expected open-source no-log image under dstack/TDX attestation assumptions
  (see [`DEPLOY.md`](./DEPLOY.md) §2 and
  [`deploy/dstack/docker-compose.yaml`](../deploy/dstack/docker-compose.yaml)).
  The TEE addresses the **trust** axis (non-logging relay), **not** the
  clean-egress axis.
- **Issuer + Exit are *inside* one boundary, not across it.** They already share
  the ARC key (§3); treating them as separate non-colluding parties buys nothing.
  A malicious issuer is just the malicious origin operator of `THREAT_MODEL.md`
  §3.4. What the issuer-side trust *does* add: the client should **pin** the
  issuer key (`TESSERA_ISSUER_PK`) so a substituted/MITM issuer is rejected;
  paid mode **requires** the pin and binds the buyer's control signature to the
  issuer pk, blocking a relay/MITM from wormholing the entitlement to a different
  issuer (`tessera-client.rs:191-195`; `THREAT_MODEL.md` §3.5 last paragraph).
- **Across exits, the boundary is per key domain.** A multi-exit fleet is a set
  of issuer+exit domains, not one shared verifier. The client must select and
  pin the issuer key for the exit domain it intends to use. Explicit per-domain
  configuration is still valid; signed-directory mode now gives the client an
  off-band, threshold-verified snapshot path to select one domain and pin its
  issuer key. Live mirrored directory publication and operator discovery remain
  deployment work.
- **Issuer ⟂ Exit for *linkage* is N/A by construction.** Even full
  issuer↔exit collusion cannot link issuance to presentation, because ARC
  issuance is blind (`THREAT_MODEL.md` §3.2 "Link a presentation back to
  issuance: No"). Collusion's payoff is *operational* (context partitioning,
  sparse issuance — §3.4), not a crypto linkage.
- **Network observer (any hop link).** Out of scope for Tessera; delegated
  entirely to the transport (Tor). Tessera adds **zero** network-level anonymity;
  the presentation header travels in clear at the Tessera layer
  (`THREAT_MODEL.md` §3.3). Front the relay with a Tor onion service in production
  so the relay never sees the client's real address — a deployment step tracked
  in [`DEPLOY.md`](./DEPLOY.md) §2, not wired into the default compose.

### Collusion outcome matrix

| Colluding set | Re-linkable? | Why |
|---|---|---|
| Relay alone | No | sees `{client, exit}`, never destination/credential |
| Exit alone | No | sees `{destination, valid token}`, never client |
| Issuer alone | No | sees client IP at issuance, but blind issuance hides the later credential |
| **Relay + Exit** | **Yes** | `{client}` ⋈ `{destination}` — the boundary that must hold |
| Issuer + Exit | No (linkage) | same key already; blind issuance still hides issuance↔presentation. Operational deanon (context partitioning) only — §3.4 |
| Relay + Issuer | Client IP + that a credential was minted, **but not the destination** | neither holds `{destination}` |

## 7. Honest limits this topology does not fix

These are deployment realities, not bugs (consistent with `DEPLOY.md` "Honest
limits" and `THREAT_MODEL.md` §4):

- **Clean egress IP is external.** A TEE proves the relay does not log; it does
  **not** make the exit's egress clean. TDX hosts are *datacenter* IPs — *more*
  likely to be blocked than residential. No code or enclave manufactures a clean
  IP (see [`DEPLOY.md`](./DEPLOY.md) "Honest limits",
  [`ARCHITECTURE.md`](./ARCHITECTURE.md), and
  [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md)).
- **PoW is a cost knob, not Sybil resistance.** Issuance gating throttles bulk
  minting but does not give a per-human guarantee; an adversary with compute
  still scales (`THREAT_MODEL.md` §4 item 3).
- **Tor fronting of the relay** (so clients reach it anonymously) and **real
  KMS-sealed key derivation** (so the shared ARC key never hits disk) are
  intended next steps; the `dstack-kms` provider currently fails closed.
- **Live multi-exit directory operation is not built.** The repo now defines the
  safe custody rule (per-exit key domains), fail-closed single-domain proxy
  guardrails, and a client-side signed snapshot verifier/selector. It does not
  operate a replicated directory, signer governance process, or independent exit
  fleet for you.
- **No post-quantum claim.** All security rests on discrete log over P-256
  (`THREAT_MODEL.md` §4 item 4).
- **UNAUDITED.** Do not protect real users or funds with this yet.
