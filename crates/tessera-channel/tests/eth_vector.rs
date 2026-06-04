//! Pins the **cross-language signature vector** (Phase 2c) on the Rust side.
//!
//! `examples/eth_vector.rs` prints `(address, digest, r, s, v)` for a fixed key
//! and a real signed state; `contracts/test/CrossLanguageVector.t.sol` hard-codes
//! those bytes and asserts the Solidity `ecrecover` path recovers the same
//! address. THIS test asserts the Rust side still produces those exact bytes, so
//! if the encoding/digest ever drifts, Rust CI fails *before* the (separately
//! run) Foundry test silently goes stale. Keep the constants here, the example's
//! output, and the Solidity vector in lockstep.

use tessera_channel::{Channel, KeyPair, RelayerChannel, UserChannel, VerifyingKey};

const USER_SECRET: [u8; 32] = [
    0x4c, 0x0b, 0x4e, 0x2f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
];
const RELAYER_SECRET: [u8; 32] = [
    0x9a, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
const CHAN_ID: [u8; 32] = [0x11u8; 32];
const SALT: [u8; 32] = [0x22u8; 32];
const B0: u64 = 1_000;
const SPEND: u64 = 400;

// The expected vector — these MUST match examples/eth_vector.rs output and
// contracts/test/CrossLanguageVector.t.sol.
const EXP_USER_ADDR: &str = "0c8da9808f8b12e05404267590e1840c4902103b";
const EXP_RELAYER_ADDR: &str = "cd1dad2554b8059f6d2017227b7bd869823d14bf";
const EXP_COMMITMENT: &str = "2cd0dc6343230c6b74ba9ea24efd5ce61284f361adbdce3c693a67ee4fa7d0da";
const EXP_DIGEST: &str = "08228d974e2c0abb856aa502afd402633851c3cc0a6d1cf97fabeb914b3d99d3";
const EXP_USER_RSV: &str = "526d85aa848f6e047052568b19943dcf23a4aff4b12c52044042f23767bf0cba\
41e5f5c66e870d8d98164fa5eab6d97d405bde36004b3ed149bdbe500fd179631c";
const EXP_RELAYER_RSV: &str = "bbe7591732280a0608363f12541baded329af28209344195fd72cd9652f8b261\
27983815abd630d28e7393643d9e28b6874240167f2bcf30854335ff6cdddb931c";

#[test]
fn cross_language_vector_is_stable_and_self_recovers() {
    let user = KeyPair::from_secret_bytes(&USER_SECRET).unwrap();
    let relayer = KeyPair::from_secret_bytes(&RELAYER_SECRET).unwrap();
    let chan = Channel::open(
        CHAN_ID,
        B0,
        SALT,
        user.verifying_key(),
        relayer.verifying_key(),
    );
    let u = UserChannel::new(user.clone(), chan.clone());
    let mut r = RelayerChannel::new(relayer.clone(), chan.clone(), 1);
    let fresh = r.issue_challenge(0, b"onion-packet-0");
    let spend = u.spend(SPEND, &fresh).unwrap();
    let cosigned = r.verify_and_cosign(&spend, &fresh).unwrap();

    // The vector bytes are exactly reproduced (guards the encoding + digest).
    assert_eq!(hex::encode(user.eth_address()), EXP_USER_ADDR);
    assert_eq!(hex::encode(relayer.eth_address()), EXP_RELAYER_ADDR);
    assert_eq!(hex::encode(cosigned.state.commitment()), EXP_COMMITMENT);
    assert_eq!(hex::encode(cosigned.state.state_digest()), EXP_DIGEST);
    assert_eq!(hex::encode(cosigned.sig_user.to_rsv()), EXP_USER_RSV);
    let rsig = cosigned.sig_relayer.as_ref().unwrap();
    assert_eq!(hex::encode(rsig.to_rsv()), EXP_RELAYER_RSV);

    // ecrecover-equivalent on the Rust side returns the signer's address.
    let digest = cosigned.state.state_digest();
    let rec_user = VerifyingKey::recover_from_digest(&digest, &cosigned.sig_user).unwrap();
    assert_eq!(rec_user.eth_address(), user.eth_address());
    let rec_relayer = VerifyingKey::recover_from_digest(&digest, rsig).unwrap();
    assert_eq!(rec_relayer.eth_address(), relayer.eth_address());

    // v is a valid Ethereum recovery byte.
    assert!(matches!(cosigned.sig_user.v(), 27 | 28));
    assert!(matches!(rsig.v(), 27 | 28));
}
