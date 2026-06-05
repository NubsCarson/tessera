# Tessera — architecture: what we built, the leaner path, and why

> The honest record of a deliberate simplification. Tessera was built
> "ambitious-first" (a ZK payment channel + on-chain court + on-chain ZK
> settlement). For the actual goal — *private, uncensored per-request access to
> clearnet* — a **leaner architecture is better**, and most of it is already
> built. This doc states both, the decision, and the concrete remaining work.
> Research-grade; UNAUDITED.

## The goal (unchanged)

Reach any clearnet HTTPS site privately, paying anonymously **per request**,
admitted on a **credential/token — never an IP** — for humans and AI agents, with
the transport's anonymity provided by Tor/Nym. The contribution is the
*composition* + the *candor*.

## Two architectures

**What we built first (ambitious):** ARC anonymous credentials · a **ZK Spilman
payment channel** (`tessera-channel`) · an **EVM court** (`ChannelRegistry.sol`:
open/close/dispute/slash/refund + relayer bond) · **on-chain ZK settlement**
(Groth16 `R_dec` + a multi-party MPC ceremony before mainnet) · a custom 2-hop
split-trust loop · Tor transport · per-IP human-volume shaping.

**The leaner target (recommended default):** ARC **blind-signed ecash tokens**
(buy/earn N unlinkable single-use tokens, spend one per request) · a
**credential-gated clean exit reached *over Tor*** · per-IP human-volume shaping.
No channel, no refund, no dispute window, no watchtower, no on-chain court for the
common path, **no MPC ceremony**.

## The decision, and why

1. **Refunds aren't needed for access, so the channel is over-engineered.** A
   Spilman channel's *only* advantage over tokens is pay-as-you-go *with refund*.
   For buying access you pre-buy a small budget of tokens; you don't need to claw
   back unspent funds mid-stream. Drop the refund requirement and the channel's
   cursors, dispute window, watchtower, and common-path on-chain court are all
   dead weight. **Tokens win** — and blind-signed tokens (Privacy Pass / Cashu)
   are battle-tested at scale.

2. **The on-chain ZK settlement is over-engineered for the threat model.** The
   Groth16 layer's only benefit is "don't doxx spending on the public chain" —
   and it **doesn't even hide your balance from the relayer** (the relayer is your
   counterparty; it knows by construction). Its narrow benefit doesn't justify its
   cost: it forces a **multi-party MPC ceremony** + a large audit surface. Demote
   it to optional.

3. **The funding-privacy problem is solved for free by the blind signature.** The
   audited reflow / Tornado-Nova **shielded pool** (a zk mixer) solves
   funding-unlinkability by breaking the deposit↔withdrawal link on-chain. But a
   **blind signature gives the same unlinkability for free** — the issuer cannot
   link the token you spend to the one it signed. So switching to tokens makes the
   shielded pool *and* the deferred `ShieldedPool` *and* the MPC ceremony
   **optional**, needed only to hide the upfront *purchase* (which can also be
   done out-of-band).

4. **We already use Tor; stop rebuilding the mixnet.** The exit tunnels over Tor
   (proven end-to-end in the `tor-test`). Let Tor provide the anonymity hops — it
   has the crowd and the GPA-resistance — and let Tessera be the **accountable,
   token-gated clean egress** reached over it. Drop the custom 2-hop loop from the
   default.

**Net:** the leaner path drops **two of the four external hand-offs** (no MPC
ceremony; the shielded pool becomes optional) and removes the heaviest code
surfaces (channel disputes, watchtower, on-chain ZK).

## What this means in code — most of it is already built

The leaner architecture is **largely v0**:

| Leaner component | Status |
|---|---|
| Unlinkable, rate-limited token (= an ARC presentation) | ✅ built + tested (`tessera-arc`) |
| Token earned via a cost gate (PoW issuance) | ✅ built (`tessera-issuer`) |
| Per-request token-gated access (checked at the exit) | ✅ built + tested (`tessera-proxy` — the credential-gated exit, via `OriginGuard`) |
| Reached over Tor | ✅ built + proven (`--tor`, the `tor-test`) |
| Per-IP human-volume shaping | ✅ built + tested (`VolumeShaper`, M5) |
| DoS-bounded accept layer | ✅ built (S3) |

So the **token + Tor + shaping** path is the existing, tested loop — the channel
was the *addition*, not the foundation.

**Demoted to optional-advanced (kept, documented, NOT deleted):** the ZK Spilman
channel + EVM court + ZK settlement (`tessera-channel`, `contracts/`,
`circuits/`). They remain fully built, tested, and CI-green as the heavier path
for the future case where *pay-as-you-go with on-chain refund/dispute* is
genuinely required. The work is not wasted; it's the advanced tier.

## The honest remaining work to reach "usable"

The leaner path's *components* are built; to be a deployed **payment** network a
stranger can use still needs (mostly NOT the heavy crypto):

1. **Token purchase** — ✅ **built**: pay ETH to `TokenMint.sol` (earn
   `entitled[buyer]` tokens), then the issuer's **paid mode** issues credentials
   against that on-chain entitlement. The buyer proves control of its address
   (`ecrecover` over a fresh issuer challenge); the issuer reads `entitled(buyer)`
   live (`tessera-issuer::mint::EthRpc`, a std-only `eth_call`) and gates issuance
   durably (`tessera-issuer::mint`, `serve_issuance_paid`, `obtain_credential_paid`).
   Proven against a real local **anvil** chain (`tests/anvil_entitled.rs`). PoW
   issuance remains the default; paid is opt-in. Consuming the entitlement on-chain
   (`TokenMint.redeem`) is the operator's submit step (calldata via
   `mint::encode_redeem`).
2. **Client/wallet UX** — ✅ **built**: the network now runs end to end. A
   `tessera-issuer` node serves PoW-gated issuance over the wire; the
   `tessera-client` binary obtains a credential and runs a **local `CONNECT`
   proxy** you point a browser/curl at, routing each request through the loop on
   a fresh unlinkable token and re-issuing when the budget is spent
   (`docs/DEPLOY.md`; proven by `tests/network.rs` + a 4-process run reaching a
   real HTTPS site). A polished GUI/extension on top is the remaining nicety (the
   MV3 extension is a scaffold).
3. **A deployed exit on a clean IP** + **a Tor/Nym crowd** + **an audit** —
   operational + external. The clean-IP and anonymity-set hand-offs remain (the
   crowd must also cover the client→issuer hop, since the issuer sees the
   client's IP at issuance), and a third-party audit is still required. These are
   the remaining gaps between the runnable network and a stranger safely using it.

That's the path: it's short on *new crypto* (the token primitive is ARC, already
built) and gated mainly on the same external realities — a clean IP and a crowd —
not on a ceremony or an audit of a ZK channel.

## Bottom line

We built the ambitious version and proved every piece; the honest engineering
call for *shipping access soonest* is the leaner **ecash-token + Tor + shaping**
path, which is mostly already built and tested. The channel/ZK/court remain as a
documented optional tier. This doc is the record of that choice so it reads as a
deliberate, defensible decision — not an accident.
