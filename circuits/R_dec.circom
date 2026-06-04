pragma circom 2.1.0;

// =============================================================================
// R_dec — Tessera's per-spend balance-DECREMENT circuit (DESIGN.md §2 / §10).
//
// Phase 2b-i. This is the zero-knowledge half of one off-chain channel spend:
// it proves, in zero knowledge, that a monotone-decrementing Spilman state
// transition `S_i -> S_{i+1}` is well-formed — WITHOUT revealing the balances,
// the cost, the channel key, the salt, or the sequence number on-chain.
//
// What it proves (the public statement):
//   * C_prev is the Poseidon commitment of state i;
//   * C_next is the Poseidon commitment of state i+1;
//   * the only legal transition happened: B_{i+1} + cost == B_i, seq_{i+1} ==
//     seq_i + 1, same chan_id, same salt, same K_chan;
//   * B_i, cost, AND B_{i+1} are each a real 64-bit non-negative amount (the
//     "money-mint" range checks — all THREE, so neither a wrap nor a negative
//     can mint balance);
//   * `fresh` binds the spend to one relayer epoch+nonce+request (not wire-
//     replayable);
//   * `nf_rate` is the per-epoch rate-limit nullifier Poseidon(K_chan,epoch,idx)
//     with idx inside the epoch budget;
//   * chan_id is itself bound to the channel key: chan_id == Poseidon(K_chan,salt)
//     — so the rate nullifier is anchored to the SAME key the channel was opened
//     under (otherwise nf_rate would be cosmetic: a prover could pick any K_chan).
//
// What it deliberately does NOT do (honest scope — see circuits/README.md):
//   * NO in-circuit ECDSA. Attribution / non-equivocation is the out-of-band
//     recoverable secp256k1 signature the on-chain court already verifies
//     (contracts/ChannelRegistry.sol). The user signs keccak256(domain || C_next)
//     so the SAME single Poseidon commitment proven here is bound by that sig.
//   * It does NOT hide the balance from the RELAYER (the counterparty knows the
//     balance by construction). The privacy this buys is ON-CHAIN settlement
//     privacy: a close/dispute need not post the cleartext balance to the chain.
//   * It is NOT the shielded funding pool (a later increment).
//
// Commitment definition (MUST byte-match Rust `tessera-channel` + the Solidity
// `ChannelRegistry`): all field inputs are BN254 Fr elements. 32-byte values
// (chan_id, salt, K_chan) are the big-endian bytes reduced mod r; u64 values
// (balance, seq, cost, epoch, nonce, idx) are themselves.
//
//   C = Poseidon(chan_id, balance, seq, salt)
//
// Constraint budget target: ~2-5k. (Reported by circuits/build.sh.)
// =============================================================================

include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

template RDec() {
    // ---- public inputs (what the verifier/on-chain settlement sees) ----
    signal input C_prev;   // Poseidon commitment of S_i
    signal input C_next;   // Poseidon commitment of S_{i+1}
    signal input fresh;    // Poseidon(epoch, nonce, request_hash) freshness tag
    signal input nf_rate;  // Poseidon(K_chan, epoch, idx) rate-limit nullifier

    // ---- private witness ----
    signal input chan_id;       // channel id (Fr; == Poseidon(K_chan, salt))
    signal input salt;          // per-channel blinding salt (Fr)
    signal input K_chan;        // pool-fresh channel key (Fr)
    signal input B_i;           // balance before the spend  (u64)
    signal input B_next;        // balance after  the spend  (u64)  (B_{i+1})
    signal input cost;          // amount spent this request  (u64)
    signal input seq_i;         // sequence number of S_i
    signal input epoch;         // relayer epoch (freshness + rate domain)
    signal input nonce;         // per-request freshness nonce
    signal input request_hash;  // hash of the relayed request (Fr)
    signal input idx;           // rate-limit slot index within the epoch budget

    // -------------------------------------------------------------------------
    // (A) Range-check ALL THREE money amounts to [0, 2^64). This is the
    //     money-mint footgun: a single missing check lets a "decrement" wrap
    //     past zero (field arithmetic has no native u64) and mint balance.
    //     Num2Bits(64) constrains its input to be exactly a 64-bit number.
    // -------------------------------------------------------------------------
    component rb_Bi   = Num2Bits(64);  rb_Bi.in   <== B_i;
    component rb_cost = Num2Bits(64);  rb_cost.in <== cost;
    component rb_Bn   = Num2Bits(64);  rb_Bn.in   <== B_next;

    // -------------------------------------------------------------------------
    // (B) The decrement identity: B_{i+1} + cost == B_i. Combined with the three
    //     range checks above, this forces 0 <= cost <= B_i and B_{i+1} = B_i -
    //     cost with no wraparound (all three sit in [0,2^64), and 2^64+2^64 <<
    //     r, so the sum can't overflow the field either).
    // -------------------------------------------------------------------------
    B_next + cost === B_i;

    // -------------------------------------------------------------------------
    // (C) chan_id is bound to the channel key: chan_id == Poseidon(K_chan, salt).
    //     Without this the rate nullifier nf_rate (which is keyed on K_chan) is
    //     cosmetic — a prover could invent any K_chan unrelated to the channel.
    // -------------------------------------------------------------------------
    component chanBind = Poseidon(2);
    chanBind.inputs[0] <== K_chan;
    chanBind.inputs[1] <== salt;
    chanBind.out === chan_id;

    // -------------------------------------------------------------------------
    // (D) The two state commitments. seq is enforced to increment by exactly one
    //     by committing seq_i in C_prev and (seq_i + 1) in C_next over the SAME
    //     chan_id/salt — a single shared witness `seq_i` makes seq++ structural.
    //       C_prev = Poseidon(chan_id, B_i,     seq_i,     salt)
    //       C_next = Poseidon(chan_id, B_{i+1}, seq_i + 1, salt)
    // -------------------------------------------------------------------------
    component cPrev = Poseidon(4);
    cPrev.inputs[0] <== chan_id;
    cPrev.inputs[1] <== B_i;
    cPrev.inputs[2] <== seq_i;
    cPrev.inputs[3] <== salt;
    cPrev.out === C_prev;

    component cNext = Poseidon(4);
    cNext.inputs[0] <== chan_id;
    cNext.inputs[1] <== B_next;
    cNext.inputs[2] <== seq_i + 1;
    cNext.inputs[3] <== salt;
    cNext.out === C_next;

    // -------------------------------------------------------------------------
    // (E) Freshness binding: fresh == Poseidon(epoch, nonce, request_hash). The
    //     user can't replay a spend against a different request/epoch/nonce.
    // -------------------------------------------------------------------------
    component fr = Poseidon(3);
    fr.inputs[0] <== epoch;
    fr.inputs[1] <== nonce;
    fr.inputs[2] <== request_hash;
    fr.out === fresh;

    // -------------------------------------------------------------------------
    // (F) Per-epoch rate-limit nullifier: nf_rate == Poseidon(K_chan, epoch, idx)
    //     with idx range-checked into the epoch budget. The relayer publishes /
    //     tracks these to cap requests-per-epoch (the RLN-style bandwidth limit).
    //     EPOCH_BUDGET is a compile-time cap (DoS rate); idx in [0, EPOCH_BUDGET).
    // -------------------------------------------------------------------------
    var EPOCH_BUDGET = 1024;  // max rate-limit slots per epoch (compile-time)
    // idx < EPOCH_BUDGET, idx >= 0. LessThan(16) is safe: EPOCH_BUDGET < 2^16
    // and idx is forced < 2^16 below, so the comparator inputs are in range.
    component idxBits = Num2Bits(16);
    idxBits.in <== idx;                 // 0 <= idx < 2^16
    component idxLt = LessThan(16);
    idxLt.in[0] <== idx;
    idxLt.in[1] <== EPOCH_BUDGET;
    idxLt.out === 1;                    // idx < EPOCH_BUDGET

    component nf = Poseidon(3);
    nf.inputs[0] <== K_chan;
    nf.inputs[1] <== epoch;
    nf.inputs[2] <== idx;
    nf.out === nf_rate;
}

// Public signal order is the declaration order of the `input` signals tagged
// public here: [C_prev, C_next, fresh, nf_rate]. snarkjs writes them to
// public.json / the Solidity verifier in this order.
component main {public [C_prev, C_next, fresh, nf_rate]} = RDec();
