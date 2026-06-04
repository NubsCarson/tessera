#![no_main]
//! Drive the full presentation-verify path (`Presentation::from_bytes` +
//! `verify_presentation`, which runs the range-sum check and `sigma::verify`)
//! with arbitrary bytes under fixed server keys. Must never panic, and must not
//! verify (no valid proof exists for random bytes).
use libfuzzer_sys::fuzz_target;
use tessera_arc::arc::{verify_presentation, Presentation};
use tessera_arc::group::deserialize_scalar;
use tessera_arc::keys::ServerPrivateKey;

const LIMIT: u64 = 8;

fn sk() -> ServerPrivateKey {
    let s = |h: &str| deserialize_scalar(&hex::decode(h).unwrap()).unwrap();
    ServerPrivateKey::from_scalars(
        s("1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021"),
        s("526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd"),
        s("549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b"),
        s("7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e"),
    )
}

fuzz_target!(|data: &[u8]| {
    let sk = sk();
    let pk = sk.public_key();
    if let Ok(p) = Presentation::from_bytes(data, LIMIT) {
        let outcome = verify_presentation(&sk, &pk, b"req", b"ctx", &p, LIMIT);
        // Random bytes can never produce a valid proof.
        assert!(outcome.is_none(), "random bytes verified as a valid presentation");
    }
});
