# Tessera — running the nodes (local Docker → dstack TEE)

> How to stand up the 2-hop split-trust loop as real nodes: locally with Docker
> for development, and inside an Intel TDX **TEE via dstack** for a *verifiable,
> non-logging* relay. Research-grade, **UNAUDITED** — and read the honest limits
> at the bottom (a clean egress IP is the one piece this can't manufacture).

## The topology

```
                  ┌──────────────────────────────┐ obtain a credential (PoW)
client ──────────▶│ ISSUER (authority, shares a   │  the issuer sees the client's IP here
   │              │ key with EXIT)                │
   └─(Tor)─▶ RELAY ──(internal)──▶ EXIT ──(its egress IP)──▶ destination
```

- **ISSUER** (`tessera-issuer`) — the credential authority. The client connects
  to it **directly** to obtain a credential, so it **sees the client's IP at
  issuance** (ARC unlinkability still prevents tying that to later browsing — see
  limits). Shares one ARC key with the exit.
- **RELAY** (`tessera-relay`) — the credential-blind first hop. Learns
  `{client, exit}`, **never** the destination or the content.
- **EXIT** (`tessera-proxy`) — credential-gated `CONNECT`. Learns
  `{destination, that a valid token was presented}`, **never** the client.
- Split-trust: no single hop holds *who* + *where* + *what*; TLS is end-to-end
  (`CONNECT`), so neither hop sees plaintext.
- The **client reaches the RELAY over Tor** (front the relay with a Tor onion
  service in production), so the relay never sees the client's real address. The
  **EXIT egresses from its own IP** — the IP the destination sees, which must be
  **clean** (see limits).

The full network is **four** nodes: a credential **issuer** (authority), the
**relay**, the **exit**, and the local **client** proxy you point a browser at.
The issuer and exit **share one ARC key** (ARC is keyed-verification — the exit
needs that key to verify presentations); point both at the same `TESSERA_KEY_FILE`.

The nodes are configured entirely by env vars (additive — the defaults preserve
the local `cargo run` demos):

| Var | Node | Meaning |
|---|---|---|
| `TESSERA_ISSUER_LISTEN` | issuer | bind address (default `127.0.0.1:8121`) |
| `TESSERA_POW_DIFFICULTY` | issuer | leading-zero-bit PoW cost per credential (default `16`) |
| `TESSERA_KEY_FILE` | issuer, exit | **shared** ARC server-key path (issuer creates, exit loads) |
| `TESSERA_LISTEN` | exit | bind address (e.g. `0.0.0.0:8118`) |
| `TESSERA_UPSTREAM` | exit | `direct` \| `tor` \| `tor:HOST:PORT` |
| `TESSERA_RELAY_LISTEN` | relay | bind address (e.g. `0.0.0.0:8119`) |
| `TESSERA_EXIT_ADDR` | relay | the exit to forward to (e.g. `exit:8118`) |
| `TESSERA_ISSUER` | client | issuer `HOST:PORT` to obtain a credential from |
| `TESSERA_RELAY` / `TESSERA_EXIT` | client | relay / exit `HOST:PORT` to route through |
| `TESSERA_CLIENT_LISTEN` | client | local proxy bind (default `127.0.0.1:8120`) |
| `TESSERA_ISSUER_PK` | client | hex pin: the issuer pk (or fingerprint prefix) issuance must match |
| `TESSERA_MINT_RPC` + `TESSERA_MINT_CONTRACT` | issuer | **paid mode**: gate issuance on an on-chain `TokenMint` purchase (RPC URL + contract address) instead of PoW |
| `TESSERA_MINT_LEDGER` | issuer | optional durable redemption-ledger path (paid mode) |
| `TESSERA_BUYER_KEY` | client | hex secp256k1 secret of the address holding the entitlement (switches the client to paid issuance) |

**Paid issuance (optional — pay ETH instead of PoW).** Deploy `TokenMint`
(`contracts/src/TokenMint.sol`) with the issuer's Ethereum address; a buyer calls
`purchase()` with ETH to earn `entitled[buyer]` tokens. Run the issuer with
`TESSERA_MINT_RPC` + `TESSERA_MINT_CONTRACT` set (it reads the live entitlement via
`eth_call`); run the client with `TESSERA_BUYER_KEY` set to the buyer's secret **and
`TESSERA_ISSUER_PK` set** (the issuer's pk fingerprint — **required** in paid mode:
it pins the issuer so the control signature can't be wormholed to another issuer;
the client refuses to start without it). The
client proves control of its address (`ecrecover` over a fresh challenge) and the
issuer issues a credential against the on-chain balance, charging
`TOKENS_PER_CREDENTIAL` (64) tokens, tracked durably so an entitlement becomes
credentials at most once. The issuer consuming it on-chain (`TokenMint.redeem`) is
an operator submit step (calldata from `mint::encode_redeem`); the single-issuer
durable ledger is the default double-issue guard. Verified end to end against a
local **anvil** chain (`crates/tessera-issuer/tests/anvil_entitled.rs`, opt-in).

## 1. Local Docker — the whole network

```sh
docker compose -f deploy/docker-compose.yaml up --build
# then point a normal HTTPS client at the local client proxy:
curl -x http://127.0.0.1:8120 https://example.com
```

This builds one `tessera-node` image and runs all four nodes: the **issuer**
mints the shared key, the **exit** loads it, the **relay** fronts the exit, and
the **client** obtains a credential and serves a local `CONNECT` proxy on
`127.0.0.1:8120`. A request through it is admitted on a fresh, unlinkable token
(never your IP), tunneled relay→exit→destination with your TLS end-to-end; when
the credential's budget is spent the client transparently re-issues.

> Verified end to end: `crates/tessera-relay/tests/network.rs` stands up all four
> nodes in-process (credential obtained over the wire → 200 through the loop →
> auto re-issue → pin mismatch rejected), and a 4-process binary run reaches a
> real HTTPS site with `200`.

To run the nodes **without** Docker (each in its own terminal):

```sh
KEY=$(mktemp -u);  export TESSERA_KEY_FILE=$KEY
TESSERA_KEY_FILE=$KEY cargo run -p tessera-issuer          # authority :8121 (creates the key)
TESSERA_KEY_FILE=$KEY cargo run -p tessera-proxy           # exit :8118 (loads the key)
TESSERA_RELAY_LISTEN=127.0.0.1:8119 TESSERA_EXIT_ADDR=127.0.0.1:8118 cargo run -p tessera-relay
cargo run -p tessera-relay --bin tessera-client            # client proxy :8120
curl -x http://127.0.0.1:8120 https://example.com
```

## 2. dstack TEE deployment (the verifiable, non-logging relay)

**Why a TEE.** The relay must not log or collude (`{client, exit}` is sensitive).
In an Intel TDX enclave with **remote attestation**, a client can *verify* the
running node is exactly this open-source image before trusting it — it physically
cannot be modified to log. The ARC server key can be **derived from the dstack
KMS and sealed to the enclave** so it never leaves. This is the **trust** axis.

```sh
# a) Build + push the image to a registry the TEE can pull:
docker build -t ghcr.io/<you>/tessera-node:0.1.0 .
docker push  ghcr.io/<you>/tessera-node:0.1.0

# b) Generate the deployment manifest (registers a gateway + KMS attestation),
#    from the TEE-flavoured compose that mounts /var/run/dstack.sock.
#    NOTE: vmm-cli.py ships with the dstack distribution (see the dstack repo) —
#    it is NOT in this tree; invoke it from your dstack install.
vmm-cli.py compose \
  --docker-compose deploy/dstack/docker-compose.yaml \
  --name tessera --kms --gateway --public-logs \
  --output app-compose.json

# c) Deploy into a TDX confidential VM:
vmm-cli.py deploy --name tessera --compose app-compose.json --vcpu 2 --memory 2G
```

`--public-logs` + `public_tcbinfo` make the node's measurement and logs publicly
verifiable; the dstack **gateway** gives it an attestation-tied TLS endpoint. A
client (or anyone) then checks the TDX quote against the expected image
measurement before routing through it. `deploy/dstack/docker-compose.yaml` mounts
the `dstack.sock` so each node can fetch its quote / derive keys; see the
[dstack docs](https://github.com/dstack-tee/dstack) for the exact VMM/gateway
setup on your host.

## Honest limits (read this)

- **The issuer sees the client's IP at issuance.** Obtaining a credential is a
  **direct** client→issuer connection, so the issuer learns the client's IP and
  the time of issuance. ARC unlinkability still means it **cannot** tie that to
  any later presentation/browsing — but the *act* of getting a credential is not
  hidden. A client that wants anonymity must reach the issuer over Tor too
  (`obtain_credential` is transport-agnostic; the demo runs everything on
  localhost, so this is moot there but matters in a real deployment).
- **A clean egress IP is still external.** A TEE proves the node doesn't log; it
  does **not** make the exit's egress IP clean. TDX hosts are *datacenter* IPs —
  *more* likely to be blocked than residential, not less. Reaching sites that
  blocklist Tor still needs a clean exit IP, which no code (or enclave)
  manufactures (see [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md)). TEE + clean
  residential egress is the ideal and the hard part.
- **Key distribution is file-based here.** The issuer + exit converge on one ARC
  server key via a shared `TESSERA_KEY_FILE` (`tessera_issuer::ensure_shared_key`
  — a single-winner create that can't diverge). That is fine on a trusted host /
  shared volume; a real multi-host or TEE deployment should instead **derive the
  shared key from the dstack KMS and seal it to the enclaves** so it never lands
  on a disk. Wiring that KMS derivation is the next step.
- **Tor onion fronting** for the relay (so clients reach it anonymously) is a
  deployment step, not yet in the compose.
- **UNAUDITED.** Do not protect real users or funds with this yet.
