# Tessera — running the nodes (local Docker → dstack TEE)

> How to stand up the 2-hop split-trust loop as real nodes: locally with Docker
> for development, and inside an Intel TDX **TEE via dstack** for a *verifiable,
> non-logging* relay. Research-grade, **UNAUDITED** — and read the honest limits
> at the bottom (a clean egress IP is the one piece this can't manufacture).

## The topology

```
client --(Tor)--> RELAY --(internal)--> EXIT --(its egress IP)--> destination
```

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

The nodes are configured entirely by env vars (additive — the defaults preserve
the local `cargo run` demos):

| Var | Node | Meaning |
|---|---|---|
| `TESSERA_LISTEN` | exit | bind address (e.g. `0.0.0.0:8118`) |
| `TESSERA_UPSTREAM` | exit | `direct` \| `tor` \| `tor:HOST:PORT` |
| `TESSERA_RELAY_LISTEN` | relay | bind address (e.g. `0.0.0.0:8119`) |
| `TESSERA_EXIT_ADDR` | relay | the exit to forward to (e.g. `exit:8118`) |

## 1. Local Docker

```sh
docker compose -f deploy/docker-compose.yaml up --build
```

This builds one `tessera-node` image and runs the **relay** (on `127.0.0.1:8119`)
in front of the **exit**. The exit logs a ready-to-run `curl` with a fresh
single-use credential. The simplest check hits the exit directly (one `CONNECT`,
so plain `curl` works):

```sh
# grab a credential the exit minted:
HDR=$(docker compose -f deploy/docker-compose.yaml logs exit | grep -o 'Tessera-Presentation: [0-9a-f]*' | head -1 | cut -d' ' -f2)
# no credential -> 407; with the credential -> tunnels to the site:
docker compose -f deploy/docker-compose.yaml exec exit \
  sh -c "true"   # (the exit is reachable inside the compose network as exit:8118)
```

(The full nested relay→exit path is what `tessera_relay::open_through_relay`
drives and what `tests/loop.rs` proves end-to-end; plain `curl` does a single
`CONNECT`, so point it at the exit for a quick check.)

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
#    from the TEE-flavoured compose that mounts /var/run/dstack.sock:
./vmm-cli.py compose \
  --docker-compose deploy/dstack/docker-compose.yaml \
  --name tessera --kms --gateway --public-logs \
  --output app-compose.json

# c) Deploy into a TDX confidential VM:
./vmm-cli.py deploy --name tessera --compose app-compose.json --vcpu 2 --memory 2G
```

`--public-logs` + `public_tcbinfo` make the node's measurement and logs publicly
verifiable; the dstack **gateway** gives it an attestation-tied TLS endpoint. A
client (or anyone) then checks the TDX quote against the expected image
measurement before routing through it. `deploy/dstack/docker-compose.yaml` mounts
the `dstack.sock` so each node can fetch its quote / derive keys; see the
[dstack docs](https://github.com/dstack-tee/dstack) for the exact VMM/gateway
setup on your host.

## Honest limits (read this)

- **A clean egress IP is still external.** A TEE proves the node doesn't log; it
  does **not** make the exit's egress IP clean. TDX hosts are *datacenter* IPs —
  *more* likely to be blocked than residential, not less. Reaching sites that
  blocklist Tor still needs a clean exit IP, which no code (or enclave)
  manufactures (see [`IP_EGRESS_IDEAS.md`](./IP_EGRESS_IDEAS.md)). TEE + clean
  residential egress is the ideal and the hard part.
- **Key distribution is simplified here.** Each node currently mints an ephemeral
  ARC server key on startup (fine for a single self-contained exit). A multi-node
  deployment needs one shared issuer key (ARC is *keyed-verification* — the exit
  needs the secret key to verify), which is exactly what the dstack KMS should
  seal to the enclaves; wiring that derivation is the next step.
- **Tor onion fronting** for the relay (so clients reach it anonymously) is a
  deployment step, not yet in the compose.
- **UNAUDITED.** Do not protect real users or funds with this yet.
