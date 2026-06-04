//! R_dec **cross-language proof-vector generator** (Phase 2b-i).
//!
//! This is the Rust half of the load-bearing proof that the Rust commitment
//! derivation, the Circom `R_dec` circuit, and the on-chain ZK court all agree.
//! It models one real channel spend and emits:
//!
//!   1. `input.json` (between the `>>>INPUT_JSON_BEGIN/END<<<` markers) — the
//!      witness `circuits/build.sh` feeds to snarkjs to generate the proof;
//!   2. the Solidity pin-block (Poseidon commitments, the keccak ZK digest, and
//!      the user's recoverable secp256k1 signature) for
//!      `contracts/test/RDecVerifier.t.sol` to assert the public signals + the
//!      sig binding match what Rust derived.
//!
//! It also self-checks (in Rust) that `chan_id == Poseidon(K_chan, salt)` and
//! that the user's ZK-digest signature recovers the user's address — the local
//! mirror of the on-chain `ecrecover` check.
//!
//! Run: `cargo run -p tessera-channel --example rdec_vector`

use ark_bn254::Fr;
use tessera_channel::poseidon::{
    self, chan_id_from_key, fe_decimal, fe_from_be_bytes, freshness_tag, rate_nullifier,
    state_commitment,
};
use tessera_channel::{ChannelState, KeyPair, VerifyingKey};

// Fixed user secret (an arbitrary nonzero scalar — NOT a real key; vectors only).
const USER_SECRET: [u8; 32] = [
    0x4c, 0x0b, 0x4e, 0x2f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
];

// The channel key K_chan (a BN254 Fr element; a small fixed value for the vector).
const K_CHAN_U64: u64 = 0xC0FFEE_u64;
const SALT: [u8; 32] = [0x22u8; 32];
const B0: u64 = 1_000;
const COST: u64 = 400; // ⇒ B_next = 600
const SEQ_I: u64 = 0; // genesis → seq 1
const EPOCH: u64 = 1;
const NONCE: u64 = 0;
const IDX: u64 = 0;
const REQUEST_PAYLOAD: &[u8] = b"onion-packet-0";

fn hex32(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() {
    let user = KeyPair::from_secret_bytes(&USER_SECRET).expect("valid user scalar");

    // K_chan as a field element, and the channel id BOUND to it (circuit C):
    //   chan_id = Poseidon(K_chan, salt).
    let k_chan = Fr::from(K_CHAN_U64);
    let chan_id_fe = chan_id_from_key(&k_chan, &SALT);
    let chan_id = poseidon::fe_to_be_bytes(&chan_id_fe);

    let b_i = B0;
    let b_next = b_i - COST;
    let seq_next = SEQ_I + 1;

    // The two Poseidon state commitments (these are the public signals C_prev/C_next).
    let c_prev_fe = state_commitment(&chan_id, b_i, SEQ_I, &SALT);
    let c_next_fe = state_commitment(&chan_id, b_next, seq_next, &SALT);

    // request_hash as a field element. We SHA-256 the payload (as the protocol's
    // request hash does) and reduce into Fr; the circuit takes that reduced value
    // directly as its `request_hash` input. `request_hash_be` is its canonical
    // 32-byte form, so `freshness_tag` (which reduces mod r, idempotent here)
    // agrees with the circuit's `Poseidon(epoch, nonce, request_hash)`.
    let req_hash_sha = sha256_request(REQUEST_PAYLOAD);
    let req_hash_fe = fe_from_be_bytes(&req_hash_sha);
    let req_hash_be = poseidon::fe_to_be_bytes(&req_hash_fe);

    let fresh_fe = freshness_tag(EPOCH, NONCE, &req_hash_be);
    let nf_fe = rate_nullifier(&k_chan, EPOCH, IDX);

    // ----- the durable ZK-path state we settle on is S_next (seq=1, bal=600).
    let s_next = ChannelState {
        chan_id,
        balance: b_next,
        seq: seq_next,
        salt: SALT,
    };
    // Sanity: the struct-derived poseidon commitment equals c_next.
    assert_eq!(
        s_next.poseidon_commitment(),
        poseidon::fe_to_be_bytes(&c_next_fe),
        "ChannelState::poseidon_commitment must equal the example's C_next"
    );

    // The user signs the ZK-path digest = keccak256(domain || poseidon_commitment).
    let zk_digest = s_next.zk_state_digest();
    let sig_user = user.sign_digest(&zk_digest);
    let recovered =
        VerifyingKey::recover_from_digest(&zk_digest, &sig_user).expect("recover succeeds");
    assert_eq!(
        recovered.eth_address(),
        user.eth_address(),
        "ZK-digest signature must recover the user's address (the on-chain ecrecover check)"
    );

    // ---------------- emit input.json for snarkjs ----------------
    println!(">>>INPUT_JSON_BEGIN<<<");
    println!("{{");
    println!("  \"C_prev\": \"{}\",", fe_decimal(&c_prev_fe));
    println!("  \"C_next\": \"{}\",", fe_decimal(&c_next_fe));
    println!("  \"fresh\": \"{}\",", fe_decimal(&fresh_fe));
    println!("  \"nf_rate\": \"{}\",", fe_decimal(&nf_fe));
    println!("  \"chan_id\": \"{}\",", fe_decimal(&chan_id_fe));
    println!("  \"salt\": \"{}\",", fe_decimal(&fe_from_be_bytes(&SALT)));
    println!("  \"K_chan\": \"{}\",", fe_decimal(&k_chan));
    println!("  \"B_i\": \"{b_i}\",");
    println!("  \"B_next\": \"{b_next}\",");
    println!("  \"cost\": \"{COST}\",");
    println!("  \"seq_i\": \"{SEQ_I}\",");
    println!("  \"epoch\": \"{EPOCH}\",");
    println!("  \"nonce\": \"{NONCE}\",");
    println!("  \"request_hash\": \"{}\",", fe_decimal(&req_hash_fe));
    println!("  \"idx\": \"{IDX}\"");
    println!("}}");
    println!(">>>INPUT_JSON_END<<<");

    // ---------------- emit the Solidity pin-block ----------------
    let ur = sig_user.to_rsv();
    println!();
    println!("// ===== R_dec cross-language vector (paste into RDecVerifier.t.sol) =====");
    println!("// Generated by `cargo run -p tessera-channel --example rdec_vector`.");
    println!(
        "address constant USER_ADDR = {};",
        hex_addr(&user.eth_address())
    );
    println!("// Public signals (decimal field elements, snarkjs order):");
    println!("//   [C_prev, C_next, fresh, nf_rate]");
    println!("uint256 constant PUB_C_PREV  = {};", fe_decimal(&c_prev_fe));
    println!("uint256 constant PUB_C_NEXT  = {};", fe_decimal(&c_next_fe));
    println!("uint256 constant PUB_FRESH   = {};", fe_decimal(&fresh_fe));
    println!("uint256 constant PUB_NF_RATE = {};", fe_decimal(&nf_fe));
    println!("// C_next as bytes32 (the on-chain Poseidon commitment):");
    println!(
        "bytes32 constant C_NEXT_B32 = {};",
        hex32(&poseidon::fe_to_be_bytes(&c_next_fe))
    );
    println!("// keccak256 ZK-path signed digest (what cooperativeCloseZK feeds ecrecover):");
    println!("bytes32 constant ZK_DIGEST = {};", hex32(&zk_digest));
    println!("// user signature over the ZK digest (r,s,v):");
    println!("bytes32 constant USER_R = {};", hex32(&ur[..32]));
    println!("bytes32 constant USER_S = {};", hex32(&ur[32..64]));
    println!("uint8   constant USER_V = {};", ur[64]);
    println!("// =====================================================================");
}

/// SHA-256 of the request payload (mirrors the protocol's request hash), big-endian.
fn sha256_request(payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tessera-channel/request/v1");
    h.update(payload);
    h.finalize().into()
}

fn hex_addr(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}
