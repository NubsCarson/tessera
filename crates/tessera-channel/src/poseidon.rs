//! Poseidon-over-BN254 commitments for the **Phase 2b-i ZK settlement path**.
//!
//! This is the circuit-efficient commitment the [`R_dec`](../../../circuits/R_dec.circom)
//! Groth16 circuit proves and the on-chain ZK court binds. It is *additional* to
//! (not a replacement for) the SHA-256 state commitment used by the cleartext
//! Phase 2c court — see the reconciliation note in [`state`](crate::state) and
//! `circuits/README.md`.
//!
//! ## One commitment, three languages
//!
//! The whole point is that **one** Poseidon field element is computed identically
//! in (1) Rust here, (2) the Circom circuit, and (3) the snarkjs witness:
//!
//! ```text
//! C = Poseidon(chan_id_fe, balance, seq, salt_fe)            // the state commitment
//! ```
//!
//! [`light_poseidon`]'s `new_circom(n)` is **byte-for-byte identical** to
//! circomlib's `Poseidon(n)` template (and `circomlibjs` `poseidon([..])`); this
//! is asserted by a known-answer test below and re-checked cross-language by the
//! `circuits/` build. There is no novel cryptography here.
//!
//! ## Field-element encoding (the subtle part)
//!
//! Poseidon operates over the BN254 scalar field `Fr` (~254 bits). The channel's
//! `chan_id` and `salt` are arbitrary 32-byte tags that may exceed `r`, so they
//! are mapped to field elements by **big-endian reduction mod r**
//! ([`fe_from_be_bytes`]). `balance`/`seq`/`cost`/`epoch`/`nonce`/`idx`/
//! `request_hash`-as-u64 are all `< 2^64 < r`, so they inject directly. The
//! Circom witness generator (`circuits/`) is fed the **same** decimal strings, so
//! the reduction agrees across languages.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

/// A Poseidon commitment / field element, as the canonical 32-byte **big-endian**
/// encoding of a BN254 `Fr` element (always `< r`, so the high bits are zero).
pub type Felt = [u8; 32];

/// Map 32 big-endian bytes to a BN254 `Fr` element by reduction mod `r`.
///
/// This is how `chan_id` and `salt` (arbitrary 32-byte tags) become field
/// elements. The reduction is the canonical `from_be_bytes_mod_order`, matching
/// what the Circom witness generator does when fed the decimal value (the JS
/// side reduces the same way), so the commitment agrees cross-language.
pub fn fe_from_be_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// The decimal string of a field element — exactly what is written into the
/// circom `input.json` (snarkjs parses field inputs as decimal). Used by the
/// `rdec_vector` example so the Rust-derived witness and the circuit agree.
pub fn fe_decimal(x: &Fr) -> String {
    x.into_bigint().to_string()
}

/// Serialize a field element to its canonical 32-byte big-endian form.
pub fn fe_to_be_bytes(x: &Fr) -> Felt {
    let mut out = [0u8; 32];
    // ark's `to_bytes_be` is big-endian and fixed 32 bytes for BN254 Fr.
    let be = x.into_bigint().to_bytes_be();
    // `to_bytes_be` already yields 32 bytes for this field, but be defensive.
    let start = 32 - be.len();
    out[start..].copy_from_slice(&be);
    out
}

/// `Poseidon(inputs)` over BN254 with the circomlib constants (`new_circom`).
///
/// Panics only if `inputs.is_empty()` or `inputs.len() > 12` (circomlib's
/// supported arities) — both are caller bugs, never reachable from the fixed-
/// arity wrappers below.
pub fn poseidon(inputs: &[Fr]) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .expect("circomlib Poseidon supports arities 1..=12");
    hasher
        .hash(inputs)
        .expect("Poseidon hash over in-field elements cannot fail")
}

/// The state commitment `C = Poseidon(chan_id, balance, seq, salt)` — the single
/// commitment proven by `R_dec` and bound by the ZK-path signature.
///
/// `chan_id`/`salt` are reduced mod `r`; `balance`/`seq` are `u64` (`< r`).
pub fn state_commitment(chan_id: &[u8; 32], balance: u64, seq: u64, salt: &[u8; 32]) -> Fr {
    poseidon(&[
        fe_from_be_bytes(chan_id),
        Fr::from(balance),
        Fr::from(seq),
        fe_from_be_bytes(salt),
    ])
}

/// The channel-key binding `chan_id == Poseidon(K_chan, salt)` (circuit
/// constraint C). The genesis `chan_id` is *defined* this way so the rate
/// nullifier (keyed on `K_chan`) is anchored to the channel — see `R_dec.circom`.
pub fn chan_id_from_key(k_chan: &Fr, salt: &[u8; 32]) -> Fr {
    poseidon(&[*k_chan, fe_from_be_bytes(salt)])
}

/// The freshness tag `fresh = Poseidon(epoch, nonce, request_hash)`. The
/// `request_hash` is mapped into the field by reduction mod `r`.
pub fn freshness_tag(epoch: u64, nonce: u64, request_hash: &[u8; 32]) -> Fr {
    poseidon(&[
        Fr::from(epoch),
        Fr::from(nonce),
        fe_from_be_bytes(request_hash),
    ])
}

/// The per-epoch rate nullifier `nf_rate = Poseidon(K_chan, epoch, idx)`.
pub fn rate_nullifier(k_chan: &Fr, epoch: u64, idx: u64) -> Fr {
    poseidon(&[*k_chan, Fr::from(epoch), Fr::from(idx)])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors: these decimal outputs are produced byte-for-byte by
    /// `circomlibjs` `poseidon([..])` AND the circom `Poseidon(n)` template
    /// (verified out-of-band; see `circuits/`). If `light-poseidon` ever drifts
    /// from circomlib, this fails and the cross-language match is broken.
    #[test]
    fn poseidon_matches_circomlib_known_answers() {
        let h2 = poseidon(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(
            fe_decimal(&h2),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
        let h4 = poseidon(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);
        assert_eq!(
            fe_decimal(&h4),
            "18821383157269793795438455681495246036402687001665670618754263018637548127333"
        );
        let h5 = poseidon(&[
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
            Fr::from(50u64),
        ]);
        assert_eq!(
            fe_decimal(&h5),
            "14653700270114866156633892456692636108484330116476754215161758865742162164337"
        );
    }

    #[test]
    fn state_commitment_is_deterministic_and_field_sensitive() {
        let chan = [9u8; 32];
        let salt = [3u8; 32];
        let c = state_commitment(&chan, 100, 0, &salt);
        assert_eq!(c, state_commitment(&chan, 100, 0, &salt));
        assert_ne!(c, state_commitment(&chan, 99, 0, &salt));
        assert_ne!(c, state_commitment(&chan, 100, 1, &salt));
        assert_ne!(c, state_commitment(&chan, 100, 0, &[4u8; 32]));
    }

    #[test]
    fn be_bytes_roundtrip() {
        let x = Fr::from(123456789u64);
        let bytes = fe_to_be_bytes(&x);
        assert_eq!(fe_from_be_bytes(&bytes), x);
    }
}
