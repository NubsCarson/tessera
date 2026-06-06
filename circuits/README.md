# `circuits/` — Tessera Phase 2b-i: the `R_dec` ZK decrement circuit

> **Status: research-grade, UNAUDITED, TEST-ONLY trusted setup.** Not for mainnet,
> not for real funds. See the honesty section at the bottom — read it.

This is the zero-knowledge half of one Tessera channel spend (`docs/DESIGN.md`
§2 / §10): a Circom + snarkjs **Groth16 / BN254** circuit, `R_dec.circom`, that
proves a monotone-decrementing Spilman state transition is well-formed **without
revealing the balance, the cost, the channel key, the salt, or the sequence
number on-chain**.

## What this buys (and what it does NOT)

**It buys on-chain *settlement* privacy.** Today the Phase 2c court
(`contracts/ChannelRegistry.sol`) settles a channel by posting the cleartext
balance in calldata (`cooperativeClose(State, ...)` carries `state.balance`).
That doxxes the user's spending to every chain observer, forever. The ZK path
(`cooperativeCloseZK`) settles against an **opaque Poseidon commitment** plus a
Groth16 proof that a valid decrement happened — so a close need not reveal the
balance/cost/trajectory on-chain.

**It does NOT, and we do not claim it does:**

- **It does not hide the balance from the relayer.** The relayer is the channel
  counterparty and **knows the balance by construction** (it co-signs every
  state). This is accepted and stated in the design: the relayer is
  content/identity/destination-blind and bonded; it is *not* balance-blind. The
  ZK is about the *chain*, not the relayer.
- **It is not the shielded funding pool.** Funding-unlinkability (the
  Tornado-Nova / Privacy-Pools deposit) is a **later increment, out of scope
  here.** See the "settlement payout" caveat below.
- **There is no in-circuit ECDSA.** Attribution / non-equivocation is the
  out-of-band recoverable secp256k1 signature the court already verifies. The
  circuit and the signature are tied together by the **single Poseidon
  commitment** (next section).

## The commitment reconciliation (the key design decision)

The 2c court signs `keccak256(STATE_SIG_DOMAIN ‖ SHA-256-commitment)` and
recomputes the SHA-256 commitment on-chain via the cheap `sha256` precompile.
`R_dec` needs a circuit-efficient **Poseidon** commitment. We reconcile the two
**without double-committing and without an on-chain Poseidon gadget**, as
follows — and we chose this over the literal "replace `commitment()` with
Poseidon everywhere" because that alternative is *less* sound here (justified
below):

- The channel gains **one** new canonical Poseidon commitment for the ZK world:

  ```
  C = Poseidon(chan_id, balance, seq, salt)      // BN254 Fr
  ```

  computed **identically** in three places — Rust
  (`tessera_channel::poseidon`, via `light-poseidon`'s `new_circom`), the Circom
  circuit (circomlib `Poseidon(4)`), and the snarkjs witness. (`light-poseidon`
  is byte-for-byte equal to circomlib / circomlibjs — asserted by a Rust
  known-answer test and `poseidon_ref.mjs`.)

- The user signs the **ZK-path digest**
  `keccak256(ZK_STATE_SIG_DOMAIN ‖ C)` (note the *distinct* domain, so a
  cleartext-path signature can never be replayed on the ZK path or vice versa).
  This is `ChannelState::zk_state_digest()` in Rust and
  `ChannelRegistry.zkStateDigest(bytes32 cNext)` in Solidity — byte-identical.

- So the **same single Poseidon commitment** `C` is *(a)* proven inside `R_dec`
  (as the public signal `C_next`) and *(b)* bound by the secp256k1 signature the
  court verifies with `ecrecover`. No double-commit: the ZK close consumes only
  the Poseidon-bound digest; a channel closes exactly once (`Closed` is
  terminal), so there is no state in which one balance is SHA-signed and a
  different balance is Poseidon-signed *and both settle*.

- **Why not change `commitment()` itself to Poseidon?** That was the suggested
  path. It would force a **Poseidon-BN254 implementation into the on-chain
  court** (the cleartext `cooperativeClose`/`slashEquivocation` recompute the
  commitment from cleartext `State` fields), which is either ~32 KB of opaque
  circomlibjs-generated EVM bytecode (breaks the `pure`, dependency-free,
  reproducible stance of `contracts/`) or a large hand-rolled gadget — a new
  unaudited surface added to the *audited-path* court for **zero** benefit to
  the cleartext path. The ZK path provably needs **no** on-chain Poseidon: the
  SNARK attests `C_next` is a well-formed commitment, and `C_next` arrives as a
  public signal, so the court only has to bind it with `ecrecover`. Scoping the
  Poseidon commitment to the ZK world is therefore the sounder reconciliation,
  and it keeps **every pre-existing Phase-2c court test green with zero
  regeneration** — the ZK path is purely additive, and the Rust↔Solidity
  cross-language sig vector still passes unchanged.

  **Honest cost of this choice:** it is not *literally* "one commitment for the
  whole protocol" — the cleartext path still uses the SHA-256 commitment. It is
  "one commitment for the ZK world (proof + signature)", which is what soundness
  actually requires. The two paths are mutually-exclusive terminal closes, so no
  user can exploit the duality.

### Field-element encoding

Poseidon is over BN254 `Fr` (~254 bits). `chan_id`/`salt` are arbitrary 32-byte
tags possibly ≥ the field modulus `r`, so they are mapped to field elements by
**big-endian reduction mod `r`** (`Fr::from_be_bytes_mod_order` in Rust; the
circom witness generator is fed the same reduced decimal value). `balance`,
`seq`, `cost`, `epoch`, `nonce`, `idx` are all `< 2^64 < r` and inject directly.

## The circuit (`R_dec.circom`)

- **public:** `{C_prev, C_next, fresh, nf_rate}`
- **private:** `{chan_id, salt, K_chan, B_i, B_next, cost, seq_i, epoch, nonce,
  request_hash, idx}`
- **constraints:**
  - the two Poseidon commitments `C_prev = Poseidon(chan_id, B_i, seq_i, salt)`,
    `C_next = Poseidon(chan_id, B_next, seq_i + 1, salt)` (seq++ is structural —
    one shared `seq_i` witness);
  - the decrement identity `B_next + cost === B_i`;
  - **range checks on ALL THREE money amounts** — `B_i`, `cost`, `B_next` each
    `∈ [0, 2^64)` via `Num2Bits(64)` (the money-mint footgun: one missing check
    lets a "decrement" wrap past zero in the field and mint balance);
  - `fresh === Poseidon(epoch, nonce, request_hash)` (replay binding);
  - `nf_rate === Poseidon(K_chan, epoch, idx)` with `idx` range-checked into the
    epoch budget (`idx ∈ [0, 1024)`);
  - **`chan_id === Poseidon(K_chan, salt)`** — binds the channel key, so the rate
    nullifier (keyed on `K_chan`) is anchored to the channel and not cosmetic.

**Constraint count:** ~3.4k (`1596` non-linear + `1837` linear), within the
~2–5k target. `build.sh` prints `snarkjs r1cs info` so the count is visible.

## Building it locally (NOT in CI)

Requires `circom` (≥2.1) and `snarkjs` (≥0.7) on `PATH`:

```sh
npm i -g snarkjs
cargo install --git https://github.com/iden3/circom.git    # or a release binary
cd circuits && npm install            # circomlib (Poseidon) + circomlibjs (ref)
bash build.sh
```

`build.sh` (1) compiles the circuit, (2) runs the **dev/test** ceremony
(powersOfTau phase 1 + a circuit-specific Groth16 phase 2), (3) exports the
Solidity verifier to `../contracts/src/RDecVerifier.sol`, (4) gets the witness
inputs from the Rust example `rdec_vector` (which also self-checks the
cross-language Poseidon commitments + the ecrecover binding), (5) generates +
verifies the proof, and (6) prints the `generatecall` calldata to paste into
`contracts/test/RDecVerifier.t.sol`.

## How CI verifies it WITHOUT circom/snarkjs

The **committed** artifacts are: `R_dec.circom`, `build.sh`, `fixup_verifier.py`,
`poseidon_ref.mjs`, the generated `contracts/src/RDecVerifier.sol`, and the
**pinned proof + public signals** hard-coded in
`contracts/test/RDecVerifier.t.sol`. The Foundry `contracts` CI job runs
`forge test`, which:

1. verifies the pinned R_dec proof on-chain against the committed verifier;
2. asserts the pinned public signals equal the Rust-derived Poseidon commitments
   (`C_prev`/`C_next`/`fresh`/`nf_rate`);
3. asserts the on-chain `zkStateDigest(C_next)` equals the Rust `zk_state_digest`
   and `ecrecover` returns the Rust user address;
4. end-to-end closes a real channel via `cooperativeCloseZK` with no cleartext
   balance in calldata.

The Rust side independently pins the same Poseidon known-answers
(`tessera_channel::poseidon` tests) so a drift in either language fails CI.

## The settlement-payout caveat (read this)

Because the ZK close hides the balance, **the court cannot compute the
user/relayer payout split on-chain.** `cooperativeCloseZK` therefore moves the
**full escrow** to a caller-supplied `reMintTo` (the shielded-pool re-mint
target), where the split would be settled *privately* — and **the shielded pool
is the out-of-scope later increment.** Until it lands, `reMintTo` is whatever
recipient both parties agree on off-chain. So, brutally honest: **this increment
delivers the "no cleartext balance / trajectory on-chain" property and a working
proof-verifying court, but the *private payout split itself* depends on the pool
increment that is not built here.** A close that disburses real ETH to two EOAs
would still reveal the split amounts (an ETH transfer is intrinsically visible);
full amount-hiding needs the pool. We do not pretend otherwise.

**Second caveat — `C_prev` is not anchored on-chain.** `cooperativeCloseZK` does
not check that the proof's `C_prev` equals this channel's genesis commitment (the
cleartext `open` predates the Poseidon commitment and stores no genesis `C`). The
proof only attests `C_prev → C_next` is a valid decrement of *some* channel; what
ties the close to *this* channel is that **both** registered parties co-sign
`C_next` — i.e. it is genuinely *cooperative*. A forced **unilateral** ZK dispute
would additionally need the genesis `C` recorded at open plus a public
`C_prev == genesis` (or higher-seq override) check. That is a follow-up, not built
here.

## The trusted-setup honesty (read this too)

The ceremony `build.sh` runs is a **single party** (this script) with **public,
non-secret entropy strings**. That is **NOT a secure setup**: whoever knows the
toxic waste can forge proofs. It exists only so the repo has a working,
reproducible *dev* verifier + pinned vector. **A real deployment needs a
multi-party phase-2 ceremony** (many independent contributors, at least one
honest, with published transcripts) — an external process we deliberately do
**not** fake here. The verifier in `contracts/src/RDecVerifier.sol` is derived
from these throwaway keys and must be regenerated from a real ceremony before
any non-test use.

### Production ceremony checklist (the external hand-off, not done here)

Before `RDecVerifier.sol` may guard real funds, all of these must happen — none
is something this repo can self-issue:

1. **Finalize the circuit** — no further `R_dec.circom` changes after this point
   (any change invalidates the ceremony; re-run from scratch).
2. **Perpetual Powers of Tau** — use a large, public, already-attested phase-1
   transcript (e.g. Hermez/`snarkjs` PoT) sized ≥ the circuit's constraint count,
   rather than a locally-generated one.
3. **Multi-party phase-2** — ≥ several *independent* contributors (separate
   people, hardware, and entropy; at least one provably honest), each publishing
   a signed contribution transcript; a public coordinator + verifiable
   contribution chain.
4. **Beacon** — finalize with a public, unpredictable randomness beacon (e.g. a
   future block hash / drand round) committed in advance.
5. **Independent verification** — third parties re-verify the full transcript and
   that the deployed `RDecVerifier.sol` matches the ceremony's verification key.
6. **Regenerate + re-pin** — replace the committed verifier and the pinned proof
   vector with the ceremony output; re-run the on-chain verification test.

Until every box is checked, the setup is forgeable and the circuit is test-only.

**UNAUDITED. Research-grade. Do not protect real users with this.**
