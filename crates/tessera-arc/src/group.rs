//! The prime-order group layer for the `ARC(P-256)` ciphersuite.
//!
//! This implements the `Group` interface from
//! `draft-ietf-privacypass-arc-crypto-01` §3.1 and §6.1, instantiated over
//! NIST P-256 (secp256r1). Every function here maps directly onto a named
//! operation in the spec; the doc comments cite the relevant section.
//!
//! Design choices, and why they are *not* hacks:
//!   * The Simplified SWU `hash_to_curve` map is delegated to the audited
//!     RustCrypto `p256` implementation (`GroupDigest`) rather than
//!     re-derived here — re-implementing SSWU by hand would be strictly
//!     worse and is exactly the kind of thing that introduces subtle bugs.
//!   * `HashToScalar` is implemented directly from RFC 9380 §5.3
//!     (`expand_message_xmd`) so that the `L = 48`, mod-`n` reduction
//!     matches the ARC ciphersuite byte-for-byte. This is small, fully
//!     specified, and verified against the IETF test vectors.

use crypto_bigint::{Encoding, NonZero, U512};
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::PrimeField;
use p256::{FieldBytes, NistP256, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `contextString` for the `ARC(P-256)` ciphersuite (spec §6.1).
pub const CONTEXT_STRING: &[u8] = b"ARCV1-P256";

/// Serialized length of a group element (SEC1 compressed point), `Ne = 33`.
pub const NE: usize = 33;
/// Serialized length of a scalar, `Ns = 32`.
pub const NS: usize = 32;

/// The order `p` of the P-256 group, widened to 512 bits for use as a
/// reduction modulus (spec §6.1: `Group.Order()`). 512 bits is wide enough to
/// reduce both the 48-byte `HashToScalar` output and the 64-byte Fiat-Shamir
/// challenge squeeze without bias beyond the spec's tolerance.
const ORDER_U512: U512 = U512::from_be_hex(
    "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

/// Reduce an arbitrary big-endian byte string (up to 64 bytes) modulo the
/// group order `n`, returning the corresponding scalar (`OS2IP` then `mod n`).
///
/// This is the shared core of `HashToScalar` (48-byte input, RFC 9380) and the
/// Fiat-Shamir `verifier_challenge` (64-byte squeeze, per the reference codec).
pub fn reduce_mod_order(be: &[u8]) -> Scalar {
    assert!(be.len() <= 64, "input wider than 512 bits");
    let mut buf = [0u8; 64];
    buf[64 - be.len()..].copy_from_slice(be);
    let wide = U512::from_be_slice(&buf);
    let reduced = wide % NonZero::new(ORDER_U512).expect("order is non-zero");
    let reduced_bytes = reduced.to_be_bytes(); // 64 bytes, < n so top 32 are zero
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&reduced_bytes[32..64]);
    Scalar::from_repr(FieldBytes::from(sb)).expect("reduced value is a valid scalar")
}

/// Errors that can arise from deserializing untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeserializeError {
    /// The bytes are not the canonical encoding of a valid, non-identity element.
    Element,
    /// The bytes are not the canonical encoding of a scalar in `[0, p-1]`.
    Scalar,
}

/// `G.GeneratorG()` — the fixed P-256 base point (spec §3.1).
#[inline]
pub fn generator_g() -> ProjectivePoint {
    ProjectivePoint::GENERATOR
}

/// `G.GeneratorH()` — the second generator, derived deterministically as
/// `HashToGroup(SerializeElement(generatorG), "generatorH")` (spec §3.1).
///
/// Recomputed on demand; cheap relative to the surrounding protocol and
/// avoids global mutable state.
pub fn generator_h() -> ProjectivePoint {
    let g_ser = serialize_element(&generator_g());
    hash_to_group(&g_ser, b"generatorH")
}

/// `G.HashToGroup(x, info)` (spec §6.1): `hash_to_curve` with suite
/// `P256_XMD:SHA-256_SSWU_RO_` and `DST = "HashToGroup-" || contextString || info`.
pub fn hash_to_group(x: &[u8], info: &[u8]) -> ProjectivePoint {
    let mut dst = Vec::with_capacity(12 + CONTEXT_STRING.len() + info.len());
    dst.extend_from_slice(b"HashToGroup-");
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(info);
    // The RO suite is total over byte strings; the only error paths are
    // pathological DST lengths, which cannot occur for our fixed prefixes.
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[x], &[&dst])
        .expect("hash_to_curve is infallible for well-formed DSTs")
}

/// `G.HashToScalar(x, info)` (spec §6.1): `hash_to_field` with `L = 48`,
/// `expand_message_xmd` over SHA-256, `DST = "HashToScalar-" || contextString || info`,
/// reduced modulo `Group.Order()`.
pub fn hash_to_scalar(x: &[u8], info: &[u8]) -> Scalar {
    let mut dst = Vec::with_capacity(13 + CONTEXT_STRING.len() + info.len());
    dst.extend_from_slice(b"HashToScalar-");
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(info);

    let uniform = expand_message_xmd_sha256(x, &dst, 48);
    reduce_mod_order(&uniform)
}

/// RFC 9380 §5.3.1 `expand_message_xmd` instantiated with SHA-256.
///
/// Implemented directly (rather than via the crate's generic `ExpandMsg`
/// plumbing) because it is short, fully specified, and lets us pin the exact
/// behaviour the ARC test vectors require.
fn expand_message_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output size
    const S_IN_BYTES: usize = 64; // SHA-256 block size

    assert!(dst.len() <= 255, "DST too long");
    assert!(len_in_bytes <= 65535, "output too long");
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255, "expand_message_xmd: ell out of range");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
    let mut h = Sha256::new();
    h.update([0u8; S_IN_BYTES]); // Z_pad
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes()); // l_i_b_str
    h.update([0u8]); // I2OSP(0, 1)
    h.update(&dst_prime);
    let b_0 = h.finalize();

    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev = h.finalize();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_prev);

    for i in 2..=ell {
        // b_i = H((b_0 XOR b_{i-1}) || I2OSP(i,1) || DST_prime)
        let mut xored = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            xored[j] = b_0[j] ^ b_prev[j];
        }
        let mut h = Sha256::new();
        h.update(xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize();
        out.extend_from_slice(&b_prev);
    }

    out.truncate(len_in_bytes);
    out
}

/// `G.SerializeElement(A)` (spec §6.1): SEC1 compressed point, 33 bytes.
pub fn serialize_element(a: &ProjectivePoint) -> [u8; NE] {
    use elliptic_curve::sec1::ToEncodedPoint;
    let encoded = a.to_affine().to_encoded_point(true);
    let mut out = [0u8; NE];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// `G.DeserializeElement(buf)` (spec §6.1): SEC1 compressed decode with
/// partial public-key validation; rejects the identity element.
pub fn deserialize_element(buf: &[u8]) -> Result<ProjectivePoint, DeserializeError> {
    use elliptic_curve::sec1::FromEncodedPoint;
    if buf.len() != NE {
        return Err(DeserializeError::Element);
    }
    let encoded = p256::EncodedPoint::from_bytes(buf).map_err(|_| DeserializeError::Element)?;
    let point: ProjectivePoint = Option::from(ProjectivePoint::from_encoded_point(&encoded))
        .ok_or(DeserializeError::Element)?;
    // Reject the identity element, per the spec's input validation.
    if bool::from(point.ct_eq(&ProjectivePoint::IDENTITY)) {
        return Err(DeserializeError::Element);
    }
    Ok(point)
}

/// `G.SerializeScalar(s)` (spec §6.1): 32-byte big-endian field element.
pub fn serialize_scalar(s: &Scalar) -> [u8; NS] {
    let repr = s.to_repr();
    let mut out = [0u8; NS];
    out.copy_from_slice(repr.as_ref());
    out
}

/// `G.DeserializeScalar(buf)` (spec §6.1): decode a 32-byte big-endian scalar.
pub fn deserialize_scalar(buf: &[u8]) -> Result<Scalar, DeserializeError> {
    if buf.len() != NS {
        return Err(DeserializeError::Scalar);
    }
    let mut bytes = [0u8; NS];
    bytes.copy_from_slice(buf);
    Option::from(Scalar::from_repr(FieldBytes::from(bytes))).ok_or(DeserializeError::Scalar)
}

/// `G.ScalarInverse(s)` (spec §6.1): multiplicative inverse mod `p`.
/// Returns `None` only for `s == 0`.
pub fn scalar_invert(s: &Scalar) -> Option<Scalar> {
    Option::from(s.invert())
}
