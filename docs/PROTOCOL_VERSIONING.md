# Tessera — Protocol Versioning (cross-layer convention, S15)

> A **convention/spec document**, not a description of an implemented negotiation
> mechanism. Tessera is a **pre-1.0 research protocol** (research-grade,
> **UNAUDITED**). This doc catalogs how *each* wire/contract layer is versioned
> **today** — much of it implicit — and specifies the convention for evolving
> each layer compatibly. Where it recommends a change (e.g. an explicit version
> byte in the issuance `HELLO`), that change is **not yet implemented**: it is
> called out as such. Nothing here claims a v2 of any layer exists.

Tessera is a stack of independently-evolving layers, each with its own wire or
on-chain format. There is **no single global protocol version**; each layer
carries (or, in some cases, fails to carry) its own. This document is the map of
*where* the version lives in each, *whether it is explicit or implicit*, and *how
a future v2 of that layer should negotiate or fail closed* against a v1 peer.

The honest one-line summary: **most of Tessera's version markers are
human-readable labels and domain-separator suffixes, not machine-negotiated
discriminants.** Two of the layers (the issuance framing and the relay's outer
channel headers) currently distinguish format variants by *length alone*, with no
explicit version field on the wire. That is the gap this doc names and proposes
the minimal fix for.

---

## 1. The layers, and where each carries its version

| Layer | Where the version lives today | Explicit or implicit | Source of truth |
|---|---|---|---|
| ARC credential crypto | IETF draft `-01`; ciphersuite `contextString = "ARCV1-P256"` | **Explicit** (in the crypto), but **not on the issuance wire** | `crates/tessera-arc/src/group.rs`, the draft |
| ARC wire serialization (`CredentialRequest`/`Response`/`Presentation`) | Fixed-layout, no header; length is the only discriminant | **Implicit** (positional, fixed-width) | `crates/tessera-arc/src/wire.rs` |
| Issuance net protocol | URI label `tessera://issue-net/v1`; frame length distinguishes the two HELLO variants | URI label is explicit (doc only); **on-wire it is implicit (by length)** | `crates/tessera-issuer/src/net.rs`, `crates/tessera-client/src/net.rs` |
| PoW gate | Domain separator `"tessera-pow-v1"` | **Explicit** (in the hash domain), but not negotiated | `crates/tessera-issuer/src/lib.rs` |
| Paid-issuance control proof | Domain separator `"tessera-mint-control-v1"` | **Explicit** (in the hash domain), but not negotiated | `crates/tessera-issuer/src/mint.rs` |
| Relay 2-hop loop (HTTP `CONNECT`) | `HTTP/1.1`; outer `Tessera-Channel-*` / `Tessera-Presentation` header **names** | **Implicit** (the header set *is* the version) | `crates/tessera-relay/src/lib.rs`, `.../channel.rs` |
| Channel state / spend format | Domain separators `"tessera-channel/state/v1"`, `".../state-sig/v1"`, `".../zk-state-sig/v1"`, `".../spend/v1"`, `".../relay-ack/v1"`, `".../request/v1"` | **Explicit** (in the hash domains), but not negotiated | `crates/tessera-channel/src/state.rs`, `.../relay.rs` |
| Solidity contracts | `pragma solidity ^0.8.24` + the `v1`-suffixed domain constants that **must byte-match** Rust | **Explicit** (pragma) + **explicit but unenforced cross-layer** (domains) | `contracts/src/*.sol` |

Two distinct things are being versioned and they should not be confused:

- **Crypto/format versions** — the ARC ciphersuite, the channel-state hash
  domains, the contract domain constants. These are baked into hashes and
  signatures: change the bytes and old and new transcripts simply *don't verify*
  against each other. They are "versioned" in the strongest sense (a mismatch is
  a hard cryptographic failure) but they are **never negotiated** — a peer with a
  different domain just produces signatures the other side rejects, with no
  version-aware error.
- **Transport/framing versions** — the issuance framing, the relay's outer HTTP
  surface. These carry no cryptographic self-protection against a format change;
  a v2 framing must be *recognized* by a v1 peer (or rejected legibly), which is
  exactly where the implicit-by-length design is fragile.

---

## 2. Per-layer catalog and evolution convention

### 2.1 ARC credential crypto (`tessera-arc`)

**Today.** The cryptographic core implements the issuance/presentation protocol
of `draft-ietf-privacypass-arc-crypto-01`
(`crates/tessera-arc/README.md`, `src/wire.rs` module docs). The ciphersuite is
pinned by a single constant, `CONTEXT_STRING: &[u8] = b"ARCV1-P256"`
(`src/group.rs`), which feeds every `hash_to_group` / `hash_to_scalar` DST and
every proof label. This is the closest thing Tessera has to an explicit,
load-bearing crypto-version tag: it is mixed into the random-oracle domains, so a
credential minted under one `contextString` cannot be presented under another —
the proofs simply fail.

The ARC **wire** format (`src/wire.rs`) is a fixed-layout, header-less,
field-by-field serialization (SEC1-compressed elements `Ne = 33`, big-endian
scalars `Ns = 32`); the encoded lengths are asserted against the spec constants in
tests. There is **no version byte** in the serialized blob — the format is
self-describing only by its fixed positional layout and total length.

**Convention for v2.**

1. The draft will advance (`-02`, …, eventually an RFC). When Tessera tracks a new
   draft revision that changes the *crypto*, bump `CONTEXT_STRING` to a new
   ciphersuite label (the ARC spec already makes the suite a parameter; see
   `docs/POST_QUANTUM.md` §"Migration sketch", which relies on exactly this to let
   a PQ or hybrid suite coexist). A new label is a clean break: old credentials
   verify only under the old suite, new under the new — there is no silent
   cross-talk, which is the desired fail-closed behavior for crypto.
2. If only the **serialization** changes (same crypto, new field), do **not**
   reuse the header-less layout — a v1 reader length-checks and would misparse.
   Prefix the new ARC wire blob with an explicit 1-byte format tag, and have v1
   readers reject any blob whose length matches a known struct but whose intended
   meaning differs. (Not implemented; ARC wire is currently positional-only.)
3. **Test-vector tracking** is part of the version contract: the port is validated
   against the draft's official vectors (`crates/tessera-arc/tests/`), and the one
   known upstream skew is documented in
   [`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md). A
   ciphersuite bump must come with the corresponding vectors.

### 2.2 Issuance net protocol (`tessera://issue-net/v1`) — the main gap

**Today.** Issuance is a length-prefixed framed TCP protocol (`4-byte big-endian
length ‖ body`, capped at `MAX_FRAME`; see `tessera-issuer/src/net.rs` module
docs). The label `tessera://issue-net/v1` appears in the module documentation and
in `tessera-client/src/net.rs`, but **it is a human-readable label only — it is
never sent on the wire.** There is **no version byte** in any frame.

There are *two* HELLO variants, and a client tells them apart **by total frame
length alone**:

- PoW HELLO: `pk(99) ‖ difficulty(4, be) ‖ nonce(16)` → 119 bytes
  (`HELLO_PK_LEN + 4 + CHALLENGE_LEN`).
- Paid HELLO: `pk(99) ‖ challenge(32)` → 131 bytes
  (`HELLO_PK_LEN + PAID_CHALLENGE_LEN`).

The client enforces these as exact-length checks:
`obtain_credential` rejects unless `hello.len() == HELLO_PK_LEN + 4 + CHALLENGE_LEN`,
and `obtain_credential_paid` unless `hello.len() == HELLO_PK_LEN + PAID_CHALLENGE_LEN`
(`tessera-client/src/net.rs`). **Length is the discriminant.** This is *implicit
versioning*: the protocol variant is inferred from a byte count, not declared.

Why this is fragile: a future `tessera://issue-net/v2` HELLO that adds or changes
a field could *coincidentally* collide with a v1 length, in which case a v1 client
would parse v2 bytes as v1 and proceed into a silent misparse rather than a clean
"unknown version" rejection. There is also no way for a client to *request* a
particular variant or for an issuer to *advertise* which variants it supports —
the variant is implied by which `serve_*` function the operator launched.

**Recommended minimal change (NOT implemented).** Add **one explicit version byte
as the first byte of the HELLO frame**, before `pk`. Concretely:

```text
HELLO  := ver(1) ‖ kind(1) ‖ <variant body>
ver    =  0x01            (this protocol generation)
kind   =  0x00 PoW  | 0x01 paid    (replaces "guess from length")
body   =  pk(99) ‖ difficulty(4) ‖ nonce(16)   for kind=PoW
       |  pk(99) ‖ challenge(32)               for kind=paid
```

This is a 2-byte prefix on a single frame. It costs nothing on the happy path and
buys: (a) a client reads `ver` first and **fails closed** with an explicit
"unsupported issuance protocol version N" if it doesn't recognize it, instead of a
length-mismatch error that conflates "wrong version" with "corrupt frame"; (b) the
PoW/paid split becomes an explicit `kind` discriminant rather than an inferred
length; (c) a future v2 issuer talking to a v1 client is rejected **legibly and
deterministically**, never silently misparsed. Implementing it means: write the
two bytes in `handle_issuance`/`handle_issuance_paid` before the `pk_bytes`
extend; read+match them in `obtain_credential`/`obtain_credential_paid` before the
existing length checks; bump the documented label to make the two-byte prefix part
of the spec. Until that lands, **the on-wire issuance format is versioned only by
length, and this doc's `v1` is a convention, not a wire field.**

A v1 issuer receiving an unrecognized first byte should reply with an **empty
RESPONSE frame** (the protocol's existing in-band rejection signal, already used
for bad PoW / malformed request / arithmetic failure in `handle_issuance`) and
close. That reuses the one rejection channel the framing already has rather than
inventing a new error frame.

### 2.3 PoW and paid-control sub-protocols

**Today.** Both are explicitly version-tagged *inside their hash domains*, which
is the right instinct even though it isn't negotiated:

- PoW digest is `SHA-256("tessera-pow-v1" ‖ nonce ‖ counter_be)`
  (`POW_DST` in `tessera-issuer/src/lib.rs`). The `-v1` suffix domain-separates so
  a PoW hash "can never collide with another protocol's" (its own doc comment).
- The paid control proof signs `keccak256("tessera-mint-control-v1" ‖ issuer_pk ‖
  challenge)` (`CONTROL_DOMAIN` in `tessera-issuer/src/mint.rs`).

**Convention for v2.** If the PoW preimage layout or the control-proof message
changes, bump the suffix (`tessera-pow-v2`, `tessera-mint-control-v2`). Because
the suffix is inside the hash/signature, a v1 and v2 peer that disagree will
simply fail to verify each other's work — a hard, fail-closed mismatch with no
silent acceptance. That is acceptable *given* §2.2's explicit HELLO version byte
makes the mismatch legible at the framing layer; without it, the failure surfaces
only as "PoW invalid" / "bad control signature", which is correct-but-opaque.

### 2.4 Relay 2-hop loop (HTTP `CONNECT`)

**Today.** The relay speaks `HTTP/1.1` `CONNECT` and is *versioned by its header
vocabulary*, with **no explicit protocol-version header**:

- **Token/ARC mode** (`serve`, the recommended default): the outer `CONNECT
  <exit>` carries no Tessera headers at all; the credential rides as
  `Tessera-Presentation:` on the *inner* CONNECT that only the exit reads
  (`open_through_relay`). The relay is deliberately credential-blind and parses
  nothing inside the tunnel.
- **Channel mode** (`serve_channel`, optional-advanced): the outer CONNECT carries
  three headers — `Tessera-Channel-Id`, `Tessera-Channel-Spend`,
  `Tessera-Channel-Fresh` (the `CHANNEL_*_HEADER` constants in
  `tessera-relay/src/channel.rs`) — and the relay replies with the co-signed state
  on the `200`. The header *values* are compact fixed-layout hex blobs whose own
  format is described in `channel.rs` (e.g. spend = `chan_id(32) ‖ balance(8) ‖
  seq(8) ‖ salt(32) ‖ sig_user(65) ‖ sig_fresh(65)`).

So the relay's "version" is **which header names appear**: a channel-mode relay
ignores headers it doesn't recognize (its parse loop `match`es the three known
names and drops the rest), and a token-mode relay reads no outer headers. There is
no `Tessera-Version:` header; a v2 relay and a v1 client share no explicit version
handshake.

**Convention for v2.**

1. **New capabilities go in new, namespaced headers** (`Tessera-*`). Because the
   relay already silently ignores unknown outer headers, a v1 relay tolerates a v2
   client that *adds* a header — but it will *ignore* it, which is only safe if the
   new header is optional. A header that is *required* for correct/safe behavior
   must instead be gated behind an explicit version signal (next point), otherwise
   a v1 relay would serve a v2 request while silently skipping the new check.
2. **Recommended (NOT implemented): an explicit `Tessera-Version: 1` outer
   header.** A v2 client sends `Tessera-Version: 2`; a v1 relay that doesn't
   understand it ignores it (today's behavior) — so to make this fail *closed*, the
   v2 *relay* must treat a *missing* or lower `Tessera-Version` as "v1 client" and
   only enable v2-required headers when it sees `>= 2`. The fail-closed direction
   that matters is a **v2 relay refusing to silently downgrade** a request that
   needs a v2 check; that is enforced by the relay, not negotiated.
3. The HTTP status line is the natural place for a legible rejection: a relay that
   cannot satisfy a request's version returns a `4xx` with a human reason, exactly
   as it already does for `402 Payment Required (<reason>)`, `403 Forbidden (relay
   forwards only to its exit)`, and `405 Method Not Allowed`
   (`tessera-relay/src/lib.rs`). A version mismatch should follow that pattern,
   e.g. `400 Bad Request (unsupported Tessera-Version)`.

### 2.5 Channel state / spend format (`tessera-channel`)

**Today.** Every signed object is domain-separated with a `…/v1` suffix that is
part of the hashed/signed preimage:

- `STATE_DOMAIN = "tessera-channel/state/v1"` (the `S_i` commitment),
- `STATE_SIG_DOMAIN = "tessera-channel/state-sig/v1"` (the keccak digest the
  user/relayer sign),
- `ZK_STATE_SIG_DOMAIN = "tessera-channel/zk-state-sig/v1"` (the ZK-settlement
  variant, deliberately distinct so a cleartext-path signature can't be replayed
  on the ZK path),
- and in `relay.rs`: `SPEND_DOMAIN = "tessera-channel/spend/v1"`,
  `ACK_DOMAIN = "tessera-channel/relay-ack/v1"`, and the freshness
  `"tessera-channel/request/v1"`.

These are explicit, load-bearing version tags: a signature made under `/v1` will
not verify against a verifier expecting `/v2`. The on-wire spend *encoding*
(`channel.rs`) is, like the ARC and issuance bodies, a fixed-width positional
layout with no embedded version field — its version is implied by the domains the
signatures inside it were made under.

**Convention for v2.** Bump the relevant `…/v1` → `…/v2` domain constant **and the
matching Solidity constant in lockstep** (see §2.6). A version skew here is
self-enforcing (signatures fail), so the failure mode is safe; the burden is
purely operational — every party in a channel and the on-chain registry must move
together, because there is no in-band negotiation, only mutual signature
rejection. Document any such bump in `CHANNEL_RECOVERY.md` since it affects the
durable on-disk/on-chain state.

### 2.6 Solidity contracts

**Today.** Two version surfaces:

- **Compiler pragma:** every contract pins `pragma solidity ^0.8.24`
  (`TokenMint.sol`, `ChannelRegistry.sol`, `RDecVerifier.sol`); `foundry.toml`
  fixes `solc 0.8.24`. The caret allows forward-compatible `0.8.x` patch/minor
  but forbids a `0.9` break.
- **Cross-layer domain constants:** `ChannelRegistry.sol` re-declares the exact
  same `v1` domain strings as Rust — `STATE_DOMAIN`, `STATE_SIG_DOMAIN`,
  `ZK_STATE_SIG_DOMAIN` — with an explicit code comment that they **"MUST
  byte-match `crates/tessera-channel`."** This is an *explicit but unenforced*
  cross-layer version coupling: nothing in CI or the type system guarantees the
  Rust constant and the Solidity constant stay equal; only the comment and the
  settlement tests do.

The contracts are **immutable** (no proxy/upgrade pattern in `src/`): a "new
version" of a contract is a **new deployment at a new address**, and clients pin
the address. There is no on-chain version field or `version()` getter.

**Convention for v2.**

1. **A contract change is a redeploy, not an upgrade.** Versioning is by deployed
   address; a client/relay selects the contract by configured address, which *is*
   the version selector. (`docs/KEY_MANAGEMENT.md` / `DEPLOYMENT_TOPOLOGY.md`
   own the address-distribution story.)
2. **Any domain-constant bump must be made on both sides in the same change** and
   guarded by a settlement round-trip test, because the comment is the only thing
   currently keeping them in sync. Consider (NOT implemented) a generated header or
   a test that asserts the Rust `STATE_SIG_DOMAIN` bytes equal the bytes the
   deployed contract uses, to turn the comment-level contract into a checked one.
3. A `solc` major bump (`0.9.x`) is a deliberate, reviewed event — widen the
   pragma only with the corresponding re-audit of the affected math, since these
   contracts encode the channel court logic.

---

## 3. Cross-layer rules (the convention, in five lines)

1. **One generation, many version markers.** There is no global version number;
   each layer owns its own marker. Don't invent a global one — bump the layer that
   actually changed.
2. **Crypto/format versions live inside the hashed/signed domain** (the
   `…/vN` suffixes, the ARC `contextString`). A mismatch there is a hard,
   fail-closed verification failure — desired, but **opaque**: it surfaces as
   "invalid signature/proof", not "wrong version".
3. **Transport/framing versions must be explicit and read *first*** so a mismatch
   is *legible*, not a silent misparse. Today the issuance HELLO (§2.2) and the
   relay outer headers (§2.4) are the two places this rule is **not yet met** —
   they are versioned by length / header-vocabulary. The recommended minimal fix
   is §2.2's one-byte HELLO version (the highest-value single change) and §2.4's
   optional `Tessera-Version` header.
4. **Default to fail-closed.** An unrecognized version must be *rejected legibly*
   (empty RESPONSE frame for issuance; a `4xx` status line for the relay), never
   parsed on a best-effort basis.
5. **Move coupled layers together.** The channel `…/v1` domains and their Solidity
   twins (§2.5/§2.6) have no in-band negotiation — only mutual rejection — so a
   bump must be deployed across Rust + Solidity + all channel parties in lockstep.

---

## 4. Honest status

- The `v1` labels in this doc — `tessera://issue-net/v1`, the `…/v1` domain
  suffixes, `ARCV1-P256`, `pragma ^0.8.24` — are **real and present in the code**
  (cited per-layer above). The *crypto/format* versions (ARC ciphersuite, channel
  domains, contract domains) are genuinely load-bearing: a mismatch fails
  verification.
- The *transport* version markers are **weaker than they look**: the issuance
  `tessera://issue-net/v1` URI is a documentation label, **not a wire field**; the
  PoW-vs-paid HELLO variants are distinguished **by frame length**, not by an
  explicit discriminant; the relay's mode is its **header vocabulary**, not a
  version header.
- The single most valuable change this doc recommends — **an explicit version byte
  (and a `kind` byte) at the front of the issuance HELLO** — is **not implemented**.
  It is specified here as the minimal, low-cost path from implicit-by-length to
  explicit-and-fail-closed. Treat everything in §2.2's code block and the
  `Tessera-Version` header in §2.4 as **proposed convention**, not shipped
  behavior.
- This is a **pre-1.0 research protocol**: until it stabilizes there is no
  compatibility *promise* across generations — only this convention for how to make
  the next change legible and fail-closed. Research-grade, **UNAUDITED**.

## See also

- [`DESIGN.md`](./DESIGN.md) — the full vNext design the layers implement.
- [`KEY_MANAGEMENT.md`](./KEY_MANAGEMENT.md) — the ARC server-key lifecycle (the
  *key* version/rotation story, distinct from *protocol* version).
- [`EPOCH_AUTHORITY.md`](./EPOCH_AUTHORITY.md) — the channel `epoch` clock (a
  per-session freshness counter, not a protocol version).
- [`POST_QUANTUM.md`](./POST_QUANTUM.md) — the ciphersuite-identifier migration
  this doc's §2.1 convention enables.
- [`ARC_PROOF_VECTOR_DISCREPANCY.md`](./ARC_PROOF_VECTOR_DISCREPANCY.md) — the
  known upstream draft-vector skew that a ciphersuite bump must account for.
