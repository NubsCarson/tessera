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

The integration test (`tests/loop.rs`) wires an observation channel into each hop
(`Observer` for the relay, `tessera_proxy::ExitObserver` for the exit) and
asserts directly that the relay never recorded the destination and the exit never
recorded the client's real source socket.

ARC is the **v0 spend stand-in** here — admit/rate-limit/double-spend on an
anonymous credential. The real ZK Spilman payment channel is Phase 2, not this.

## Run it

```sh
cargo run -p tessera-relay            # exit egresses directly
cargo run -p tessera-relay -- --tor   # exit egresses via Tor (SOCKS5 127.0.0.1:9050)
```

It prints the relay + exit addresses and a ready-to-paste single-use credential.
The canonical client move (the two nested CONNECTs) is
`tessera_relay::open_through_relay`, which the test and the binary use.

## Design choices (and why)

* **std/blocking + threads, a HOST workspace crate** — *not* an excluded async
  crate. The relay only pumps opaque bytes and parses one outer CONNECT line, so
  it needs no async and no extra deps; it mirrors `tessera-proxy` exactly and
  stays inside the host MSRV-1.74 / clippy / test gates. (`tessera-tower-demo`
  is excluded only because `axum`/`tokio` are heavy async deps — not the case
  here.)
* **Reuses, doesn't reinvent**, `tessera-proxy`'s byte-pump (`pipe`), its
  `CONNECT`/SOCKS5/Tor egress, and `OriginGuard` credential check (the exit *is*
  `tessera-proxy`). The only additions to `tessera-proxy` are a `pub` on `pipe`
  and a backward-compatible `serve_observed` (the split-trust observation hook);
  `serve` is unchanged for existing callers.

## Honesty — what this proves and what it does NOT

This proves the **protocol / loop**, locally and deterministically: the multi-hop
chain works, the split-trust property holds, the credential gates the exit, and
the tunnel carries opaque bytes both ways (the in-test stand-in for the client's
real end-to-end TLS — a tampered byte is detectable by the caller exactly as a
TLS AEAD tag would catch it).

It does **not** prove the last-mile reach claim. "A real Tor-blocked site returns
`200` through a real *clean* exit IP, privately" needs a real residential-class,
unpublished egress IP behind the exit — which no code can manufacture. That is a
**documented manual final step**: run `cargo run -p tessera-relay -- --tor` (or
point the exit at a clean egress) and drive a known Tor-`403` site. Until then the
egress is whatever your machine's IP is. Research-grade, UNAUDITED.
