# Tessera demo

A runnable, end-to-end demonstration of the thesis: **an origin admits an
anonymous request on its credential, never on its IP.**

```sh
cargo run -p tessera-demo            # localhost — always works
cargo run -p tessera-demo -- --tor   # also over a real Tor onion circuit
```

## What it does

The demo is real, not a mock:

1. **Server setup** — generates ARC server keys (`tessera-arc`).
2. **Issuance** — a `tessera-client` obtains an anonymous credential. Issuance
   is unlinkable from later use.
3. **Live origin** — a real HTTP server (`crates/tessera-demo/src/net.rs`, std
   only) wraps the [`tessera-origin`] `OriginGuard`. Every request is decided
   solely by `OriginGuard::check` on the `Tessera-Presentation` header. **The
   source IP is never an input.**
4. **Real requests** over HTTP:
   - **no credential → `403`.** This is what a Tor exit IP gets on most of the
     web today.
   - **with a credential → `200`**, three times, each with a *distinct,
     unlinkable* presentation tag. The server cannot correlate them.
   - **a 4th request → refused by the client**: presenting more than the agreed
     limit would break the client's own unlinkability, so it won't.
   - **a replay of an earlier credential → `403` double-spend**, caught by the
     server's tag store.

## The `--tor` path

With `--tor`, the demo additionally:

1. launches a dedicated `tor` process and exposes the origin as a **Tor onion
   service** (you'll see a real `….onion` address printed);
2. waits for the descriptor to publish and a circuit to build;
3. makes the same no-credential (blocked) and with-credential (admitted)
   requests **over Tor**, through a SOCKS5 connection to the onion.

This proves the end-to-end story over a genuinely anonymous transport: the
request arrives via Tor and is admitted purely because it proved good standing.

The onion service is always created; completing the round-trip circuit requires
working Tor network egress on the host. If that's unavailable, the demo says so
and the localhost result already establishes the result — the credential check
is identical on either transport.

## Why this matters

There is no cryptography that forces a *non-cooperating* site to accept Tor. The
point Tessera makes is the other direction: it gives a cooperating site a trust
signal **better than IP** — anonymous, accountable, rate-limited — so blocking
anonymity stops being the rational default. Censorship-by-IP becomes obsolete,
not merely evaded.

[`tessera-origin`]: ./crates/tessera-origin
