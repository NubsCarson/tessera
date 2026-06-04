# Tessera contracts — the on-chain court (Phase 2c)

> ⚠️ **Research-grade, testnet-only, UNAUDITED.** Not for mainnet or real funds.
> This is the EVM dispute/settlement court for Tessera's ZK Spilman channel; it
> has had **no third-party audit**. See the repo-root security status.

`ChannelRegistry.sol` is the **on-chain court** for the off-chain payment channel
in [`crates/tessera-channel`](../crates/tessera-channel) (`docs/DESIGN.md` §2/§6,
Phase 2c). It is the Solidity analogue of the crate's off-chain verdict logic in
[`settlement.rs`](../crates/tessera-channel/src/settlement.rs): it escrows the
channel balance, settles at the highest doubly-signed state, slashes provable
equivocation, and refunds the user on timeout.

## How it verifies states — secp256k1 / `ecrecover`

The crate signs each channel state with **EVM-native secp256k1 ECDSA over a
recoverable keccak256 digest** (the Phase 2c revision of the original P-256
choice — see the crate README). The contract reconstructs that digest from the
state fields and recovers the signer with the **`ecrecover` precompile**:

```
commitment  = sha256(    be64(len("tessera-channel/state/v1"))     || "tessera-channel/state/v1"
                       || chanId || be64(balance) || be64(seq) || salt )
stateDigest = keccak256( be64(len("tessera-channel/state-sig/v1")) || "tessera-channel/state-sig/v1"
                       || commitment )
signer      = ecrecover(stateDigest, v, r, s)        // == stored user / relayer address
```

The SHA-256 *commitment* is kept from Phase 2a (it is internal / stored opaquely);
only the *signed digest* is keccak256 because that is what the EVM hashes
cheaply. Low-`s` (EIP-2) is enforced so each state has one canonical signature.

This byte-for-byte cross-language match is the load-bearing risk, so it is
**proven, not assumed** — see [the cross-language vector](#cross-language-vector).

## Functions (each mirrors a `settlement.rs` outcome)

| Function | Mirrors | What it does |
|----------|---------|--------------|
| `open(channelId, user, relayer, timeout)` **payable** | channel open / escrow | escrows `B0 = msg.value`; stores genesis params, both addresses, the refund deadline, and a user bond (this model: bond == B0). Spilman escrow: spendable by *relayer-countersig-on-latest* OR *user-after-timeout*. |
| `cooperativeClose(state, userSig, relayerSig)` | `Verdict::Settle` | both sigs valid (`ecrecover` == stored user/relayer); pays relayer `B0 - balance`, refunds user `balance`. CEI + `nonReentrant`. |
| `unilateralClose(state, userSig, relayerSig)` | unilateral close | opens a `CHALLENGE_WINDOW` dispute at a doubly-signed state. |
| `challenge(higherSeqState, …)` | dispute override | within the window, override with a **strictly-higher-seq** doubly-signed state (latest truth wins). |
| `settleDispute(channelId)` | `Verdict::Settle` | after the window, pay out at the highest doubly-signed state. CEI + `nonReentrant`. |
| `slashEquivocation(stateA, stateB, userSigA, userSigB)` | `Verdict::SlashUser` | two states, **same seq, different commitment**, both carrying the user's valid secp256k1 sig → attributable equivocation → the user bond is forfeited to the relayer. CEI + `nonReentrant`. |
| `refundOnTimeout(channelId)` | `Verdict::RefundUser` | after `timeout` with no advance → refund user the full `B0`. CEI + `nonReentrant`. |

The escrow doubling as the slashable bond, the `ShieldedPool` (unlinkable
funding) being absent, and there being no Groth16 verifier yet are the honest
gaps — the contract is the *court*, not the full §6 system.

## Cross-language vector

[`test/CrossLanguageVector.t.sol`](test/CrossLanguageVector.t.sol) hard-codes a
**real** signed state produced by the Rust crate and asserts the contract agrees:

1. Generate the vector in Rust (deterministic, fixed key):
   ```sh
   cargo run -p tessera-channel --example eth_vector
   ```
   It prints `(address, commitment, stateDigest, r, s, v)` for the user sig and
   the relayer co-sig. The Rust side pins the same bytes in
   [`crates/tessera-channel/tests/eth_vector.rs`](../crates/tessera-channel/tests/eth_vector.rs).
2. The Solidity test asserts `commitment()` and `stateDigest()` recompute the
   identical bytes, that `ecrecover` recovers the **same** Ethereum addresses
   Rust derived, and that the Rust-signed state cooperatively closes a real
   on-chain channel (relayer 400 / user 600 of a 1000 escrow).

If the encoding or digest ever drifts in either language, both suites fail.

## Build & test

Foundry `forge`/`cast` (tested with 1.5.1). **No external dependencies** — there
is no `lib/`, no `forge install`, no git submodule. The minimal test harness (a
tiny `Test` base + a self-declared `Vm` cheatcode interface) is vendored in
[`test/Std.sol`](test/Std.sol), so the suite runs fully offline (only `solc`
itself is fetched, which Foundry caches).

```sh
cd contracts
forge build
forge test          # 23 tests across 3 suites
forge test -vvv     # verbose traces
```

## Layout

```
contracts/
├─ foundry.toml                       # solc 0.8.24, optimizer, no libs
├─ src/ChannelRegistry.sol            # the on-chain court
└─ test/
   ├─ Std.sol                         # vendored Vm interface + Test base (no forge-std)
   ├─ CrossLanguageVector.t.sol       # THE PROOF: Rust-signed state verified on-chain
   ├─ ChannelRegistry.t.sol           # cooperativeClose / unilateral+challenge / slash / refund / rejects
   └─ Reentrancy.t.sol                # nonReentrant guard blocks a malicious reentrant payee
```

`out/`, `cache/`, and `lib/` are build artifacts / fetched deps and are
git-ignored.
