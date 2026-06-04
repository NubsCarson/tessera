# tessera-channel — the ZK Spilman channel **protocol state machine** (Phase 2a)

`tessera-channel` is the off-chain **protocol / state-machine** of Tessera's
payment layer from [`docs/DESIGN.md`](../../docs/DESIGN.md) §2: a
**unidirectional, monotone-decrementing, single-payee** Spilman channel (the
single payee is the relayer). It is implemented in plain Rust with **plain
crypto** — **EVM-native secp256k1 ECDSA** signatures over a **recoverable
keccak256 digest** (via the `k256` + `sha3` RustCrypto crates) and a SHA-256
state commitment — so the protocol logic the red-team had to fix can be *proven
correct on its own*, and the **Phase 2c on-chain court verifies the very same
signatures via `ecrecover`** (`contracts/`).

> ### Phase 2c revision — P-256 → secp256k1 (deliberate)
>
> 2a signed with **P-256** ECDSA, a workspace-convenience choice (the curve
> `tessera-arc` ships). This crate now signs the **chain-facing** state
> signatures with **Ethereum-style secp256k1** instead, because the channel
> settles on the EVM, which verifies secp256k1 cheaply/universally via the
> `ecrecover` precompile and P-256 only via a non-universal precompile
> (EIP-7212) or an expensive in-EVM library. The signed message is the
> **keccak256 digest** `keccak256(domain ‖ S_i)`, signed **recoverably**
> (`r‖s‖v`, low-`s`, `v ∈ {27,28}`); identity is the **20-byte Ethereum address**
> `keccak256(pubkey[1..])[12..]`. The SHA-256 *commitment* `S_i` is unchanged.
> The freshness-binding and proof-of-relay signatures **never touch chain**, but
> were moved onto the same recoverable-secp256k1 path so the crate has a single
> signature type (less surface). The Rust↔Solidity match is **pinned by a real
> cross-language vector** (see [Cross-language vector](#cross-language-vector)).

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
| **2c** | The EVM `ChannelRegistry` dispute/settlement court | ✅ **the Solidity court is in [`contracts/`](../../contracts)**; this crate now produces the secp256k1/`ecrecover`-verifiable signatures it consumes |
| **2c** | The `ShieldedPool` (unlinkable funding) + Groth16 dispute verifier | ❌ **not here** |

Concretely, the things this crate **does not do** and does not pretend to:

- **No zero-knowledge.** `cost`, `balance` and `seq` are in the clear and checked
  arithmetically. The Phase 2b ZK layer will later prove the *same* transition in
  zero-knowledge; it only adds **balance privacy**, it does **not** change the
  protocol correctness proven here. The state commitment is a plain SHA-256
  where the full design uses a Poseidon-in-circuit commitment.
- **No chain *in this crate*. No money moves *here*.** `tessera-channel` itself
  has no `ChannelRegistry`, no CLTV, no bonds, no gas: "Escrow", "open",
  "refund-on-timeout" and "slash" are **verdicts** ([`settle`](src/settlement.rs)
  returns a `Verdict`). The Phase 2c **Solidity `ChannelRegistry`** in
  [`contracts/`](../../contracts) is the on-chain court that *enforces* those
  verdicts (escrow, cooperative/unilateral close, equivocation slash,
  refund-on-timeout) and verifies this crate's signatures with `ecrecover`. There
  is still **no `ShieldedPool`** (unlinkable funding) and **no Groth16 verifier**.
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

## Cross-language vector

The whole point of the Phase 2c secp256k1 switch is that **the same signature
verifies in Rust and in the Solidity court**. That match is pinned, not assumed:

- [`examples/eth_vector.rs`](examples/eth_vector.rs) mints a **fixed** keypair,
  builds a **real** signed state `S_1` (open `B0=1000`, spend `400` ⇒
  `balance=600`, `seq=1`), and prints
  `(address, commitment, state_digest, r, s, v)` for both the user sig and the
  relayer co-sig. Run: `cargo run -p tessera-channel --example eth_vector`.
- [`tests/eth_vector.rs`](tests/eth_vector.rs) hard-codes that vector and asserts
  the Rust side still reproduces it byte-for-byte **and** that the Rust
  `ecrecover`-equivalent (`VerifyingKey::recover_from_digest`) recovers the
  signer's address.
- [`../../contracts/test/CrossLanguageVector.t.sol`](../../contracts/test/CrossLanguageVector.t.sol)
  hard-codes the **identical** bytes and asserts Solidity's `ecrecover` recovers
  the **same** address and that `ChannelRegistry`'s verification path accepts the
  state. If the encoding or digest ever drifts, both suites fail.

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
  audited RustCrypto (`k256`, `sha3`, `sha2`); the protocol logic on top — and
  the cross-language encoding match with the contract — is exactly what still
  needs review.

## Design / module map

- [`src/state.rs`](src/state.rs) — `ChannelState`, the SHA-256 commitment `S_i`,
  the chain-facing keccak digest `state_digest()`, genesis `S_0`, the
  monotone-decrement transition, and `SignedState`.
- [`src/crypto.rs`](src/crypto.rs) — secp256k1 ECDSA (`KeyPair`/`Sig`=`EthSig`/
  `VerifyingKey`): recoverable signing over a keccak digest (`sign_digest`),
  `ecrecover`-equivalent recovery (`recover_from_digest`), the 20-byte
  `eth_address`, and the domain-separated `h` (SHA-256) / `keccak_domain`
  (keccak256, the chain-facing digest) hashers.
- [`src/relay.rs`](src/relay.rs) — the freshness challenge (`RelayRequest`) and
  the proof-of-relay receipt (`RelayAck`).
- [`src/channel.rs`](src/channel.rs) — the state machine: `Channel::open`,
  `UserChannel` (`spend` / `accept_cosigned` / `serve`), `RelayerChannel`
  (`issue_challenge` / `verify_and_cosign` / `issue_relay_ack`).
- [`src/settlement.rs`](src/settlement.rs) — the off-chain court: `settle` →
  `Verdict::{Settle, SlashUser, RefundUser}`.

Std host crate, `#![forbid(unsafe_code)]`, MSRV 1.74, deps from the workspace set
(`k256` with the `ecdsa` feature, `sha3` for keccak256, `sha2`, `rand_core`,
`hex`).
