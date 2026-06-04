#![no_main]
//! End-to-end attacker surface: arbitrary header bytes (hex-encoded) fed to the
//! origin guard. The whole hex-decode -> deserialize -> verify -> tag-store path
//! must always return a `Decision`, never panic.
use libfuzzer_sys::fuzz_target;
use tessera_arc::group::deserialize_scalar;
use tessera_arc::keys::ServerPrivateKey;
use tessera_origin::OriginGuard;

fn guard() -> OriginGuard {
    let s = |h: &str| deserialize_scalar(&hex::decode(h).unwrap()).unwrap();
    let sk = ServerPrivateKey::from_scalars(
        s("1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021"),
        s("526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd"),
        s("549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b"),
        s("7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e"),
    );
    let pk = sk.public_key();
    OriginGuard::new(sk, pk, b"tessera://issue/v1", b"tessera://origin/v1", 8)
}

fuzz_target!(|data: &[u8]| {
    let guard = guard();
    // Try both the raw bytes as a (lossy) header string and a hex encoding of them.
    let _ = guard.check(std::str::from_utf8(data).ok());
    let _ = guard.check(Some(&hex::encode(data)));
});
