# tessera-channel — the ZK Spilman channel **protocol state machine** (Phase 2a)

`tessera-channel` is the off-chain **protocol / state-machine** of Tessera's
payment layer from [`docs/DESIGN.md`](../../docs/DESIGN.md) §2: a
**unidirectional, monotone-decrementing, single-payee** Spilman channel (the
single payee is the relayer). It is implemented in plain Rust with **plain
crypto** — P-256 ECDSA signatures (via the workspace's existing `p256`) and a
SHA-256 state commitment — so the protocol logic the red-team had to fix can be
*proven correct on its own*, before the privacy and on-chain layers wrap it.

It is **not** Lightning / eltoo / Poon-Dryja: an access rail needs a **payee,
not a payment network**, so there are no HTLCs, routing, liquidity, revocation
or penalty machinery here.

## ⚠️ Scope — what is and is **not** in this crate (read this)

This crate is **Phase 2a only: the protocol correctness.** Be honest about the
boundary:

| Phase | What | In this crate? |
|-------|------|:--------------:|
| **2a** | The off-chain channel **protocol / state machine** — user-signed states, sign-then-serve co-signing, proof-of-relay, off-chain dispute resolution | ✅ **yes — this is it** |
| **2b** | The Groth16 `R_dec` **ZK circuit** that *hides the balance* | ❌ **not here** |
| **2c** | The EVM `ShieldedPool` / `ChannelRegistry` / dispute verifier — the **on-chain court** | ❌ **not here** |

Concretely, the things this crate **does not do** and does not pretend to:

- **No zero-knowledge.** `cost`, `balance` and `seq` are in the clear and checked
  arithmetically. The Phase 2b ZK layer will later prove the *same* transition in
  zero-knowledge; it only adds **balance privacy**, it does **not** change the
  protocol correctness proven here. The state commitment is a plain SHA-256
  where the full design uses a Poseidon-in-circuit commitment.
- **No chain. No money moves.** There is no `ShieldedPool`, no `ChannelRegistry`,
  no CLTV, no bonds, no gas. "Escrow", "open", "refund-on-timeout" and "slash"
  are **verdicts** ([`settle`](src/settlement.rs) returns a `Verdict`) that a
  future on-chain court would *enforce*. This crate computes the verdict; it does
  not settle it. The timeout/refund branch is modeled as **state-machine logic**,
  not as an on-chain timelock.
- **No transport / onion / mixnet.** "Serve" (the relayer forwarding the packet)
  is modeled as a returned `Served` marker / a `RelayAck` receipt, not real
  forwarding. That lives in `tessera-relay` / the transport layer.

## What it proves (the corrected core)

Four properties are load-bearing — each is the fix the red-team flagged in
`DESIGN.md` §2, and each has a test in [`tests/protocol.rs`](tests/protocol.rs):

1. **The user signs every state.** The original "2-of-2" was really 1-of-1
   (only the relayer's signature gated the spend), leaving user equivocation
   *unattributable*. Here `UserChannel::spend` produces `sig_user(S_{i+1})` over
   the state commitment, and the relayer refuses any state without a valid one —
   so a fork is provable against the user's key.
2. **Sign-then-serve.** `RelayerChannel::verify_and_cosign` co-signs `S_{i+1}`
   and returns the doubly-signed state **before** the request is served;
   `UserChannel::serve` refuses to serve a state the relayer has not co-signed.
3. **Proof-of-relay (HOPR-style fair exchange).** Off-chain fair exchange is
   impossible without a TTP (EGL / Pagnia–Gärtner), so we don't make serve-and-pay
   atomic. Instead the relayer can only **claim** a spent unit at settlement if it
   can show a signed `RelayAck` that it forwarded the packet. No receipt ⇒ the
   unit is unclaimable ⇒ the refusal-drain gains the relayer nothing.
4. **Freshness binding.** A spend carries a signature over a relayer-supplied
   `(epoch, nonce)` + request-hash, and the relayer burns the nonce, so a spend
   message is not wire-replayable.

Off-chain **settlement** (`settle`) models the on-chain court's verdict:

- **highest doubly-signed `seq` wins** → pay the relayer `B0 - balance` (capped
  by what it can prove it relayed), refund the user `balance`;
- **equivocation** (two doubly-signed states off one predecessor) → an
  attributable `SlashUser` verdict carrying the fraud proof;
- **relayer-dark / withholding** (no advance, or advanced but no proof-of-relay)
  → `RefundUser` (refund-on-timeout) returns the user's last balance.

## Tests (the red-team cases)

`cargo test -p tessera-channel` — all pass:

| Test | Red-team case |
|------|---------------|
| `honest_sequence_settles_correctly` | N honest spends; balances/seqs correct; each state doubly-signed; final settlement pays relayer `B0 - Bn`, refunds user `Bn` |
| `equivocation_is_slashed` | two doubly-signed states off one predecessor → `SlashUser` |
| `withholding_without_receipt_refunds_user` | no proof-of-relay ⇒ unit unclaimable; refund-on-timeout; a receipt for the *wrong* state doesn't unlock the claim |
| `replay_is_rejected` / `replay_against_new_freshness_fails_freshness_binding` | a spend bound to one epoch/nonce/request is rejected on replay |
| `serve_before_cosign_is_rejected` | serving before the relayer co-signs is rejected (incl. a forged co-sig) |
| `underflow_is_rejected` | `spend > balance` is rejected; draining to exactly zero is allowed |

Plus inline unit tests for commitment determinism / field-sensitivity and the
state-transition rules.

## Honest limits

- A **non-forking linear rollback** (the user re-presenting an *older*
  doubly-signed state, rather than forking) produces **no attributable object** —
  exactly as `DESIGN.md` §2 admits. It is covered there by `seq` + countersig +
  a **watchtower**, which is a stated safety component and is **out of scope**
  here. `settle` takes the highest doubly-signed `seq` it is *given* as truth; it
  cannot, from the states alone, know an older state was substituted.
- The proof-of-relay model is **per-claim, single-receipt**: the relayer is paid
  against the highest-`seq` doubly-signed state for which it can show a receipt
  (the cumulative balance prices in every prior unit). A more granular per-unit
  receipt accounting is straightforward but not modeled.
- This is **research-grade and UNAUDITED**. The crypto primitives are from
  audited RustCrypto (`p256`, `sha2`); the protocol logic on top is exactly what
  still needs review.

## Design / module map

- [`src/state.rs`](src/state.rs) — `ChannelState`, the commitment `S_i`, genesis
  `S_0`, the monotone-decrement transition, and `SignedState`.
- [`src/crypto.rs`](src/crypto.rs) — thin P-256 ECDSA (`KeyPair`/`Sig`/
  `VerifyingKey`) + domain-separated SHA-256 wrappers.
- [`src/relay.rs`](src/relay.rs) — the freshness challenge (`RelayRequest`) and
  the proof-of-relay receipt (`RelayAck`).
- [`src/channel.rs`](src/channel.rs) — the state machine: `Channel::open`,
  `UserChannel` (`spend` / `accept_cosigned` / `serve`), `RelayerChannel`
  (`issue_challenge` / `verify_and_cosign` / `issue_relay_ack`).
- [`src/settlement.rs`](src/settlement.rs) — the off-chain court: `settle` →
  `Verdict::{Settle, SlashUser, RefundUser}`.

Std host crate, `#![forbid(unsafe_code)]`, MSRV 1.74, deps only from the existing
workspace set (`p256` with the `ecdsa` feature, `sha2`, `rand_core`, `hex`).
