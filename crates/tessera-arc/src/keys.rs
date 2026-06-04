//! Server key generation (`draft-ietf-privacypass-arc-crypto-01` §4.1).
//!
//! The server holds four secret scalars `(x0, x1, x2, x0Blinding)` and
//! publishes three group elements `(X0, X1, X2)`. The blinding of `x0`
//! (committing to `x0` under both generators) is what gives ARC its issuance
//! unlinkability property (spec §7.2).

use crate::group::{
    self, deserialize_scalar, generator_g, generator_h, random_scalar, serialize_scalar,
    DeserializeError,
};
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;

/// `ServerPrivateKey` (spec §4.1).
///
/// `Debug` is deliberately redacted: the four secret scalars must never land in
/// a log or panic message. Use [`ServerPrivateKey::serialize`] for deliberate,
/// explicit persistence.
#[derive(Clone)]
pub struct ServerPrivateKey {
    pub x0: Scalar,
    pub x1: Scalar,
    pub x2: Scalar,
    pub x0_blinding: Scalar,
}

impl core::fmt::Debug for ServerPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServerPrivateKey(<redacted>)")
    }
}

/// Wipe the secret scalars from memory when the key is dropped (best-effort
/// defense against later memory/swap disclosure). Each `Scalar` zeroizes via
/// the `p256`/`zeroize` integration.
impl Drop for ServerPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.x0.zeroize();
        self.x1.zeroize();
        self.x2.zeroize();
        self.x0_blinding.zeroize();
    }
}

/// `ServerPublicKey` (spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerPublicKey {
    pub x0: ProjectivePoint,
    pub x1: ProjectivePoint,
    pub x2: ProjectivePoint,
}

impl ServerPrivateKey {
    /// `SetupServer()` (spec §4.1): sample a fresh server key pair from a CSPRNG.
    pub fn setup<R: RngCore + ?Sized>(rng: &mut R) -> (Self, ServerPublicKey) {
        let sk = Self::from_scalars(
            random_scalar(rng),
            random_scalar(rng),
            random_scalar(rng),
            random_scalar(rng),
        );
        let pk = sk.public_key();
        (sk, pk)
    }

    /// Construct a private key from its four scalar components. This is the
    /// explicit-key path the §10.2 test vectors require; for a fresh random
    /// key pair use [`ServerPrivateKey::setup`] (the spec's `SetupServer()`).
    pub fn from_scalars(x0: Scalar, x1: Scalar, x2: Scalar, x0_blinding: Scalar) -> Self {
        Self {
            x0,
            x1,
            x2,
            x0_blinding,
        }
    }

    /// Serialize the private key as `4 * Ns = 128` bytes
    /// (`x0 ‖ x1 ‖ x2 ‖ x0Blinding`, each a 32-byte big-endian scalar), for
    /// persisting server keys across restarts. **Secret material** — store it
    /// the way you would any MAC key.
    pub fn serialize(&self) -> [u8; 4 * group::NS] {
        let mut out = [0u8; 4 * group::NS];
        out[..group::NS].copy_from_slice(&serialize_scalar(&self.x0));
        out[group::NS..2 * group::NS].copy_from_slice(&serialize_scalar(&self.x1));
        out[2 * group::NS..3 * group::NS].copy_from_slice(&serialize_scalar(&self.x2));
        out[3 * group::NS..].copy_from_slice(&serialize_scalar(&self.x0_blinding));
        out
    }

    /// Deserialize a private key from exactly `4 * Ns = 128` bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        if buf.len() != 4 * group::NS {
            return Err(DeserializeError::Scalar);
        }
        Ok(Self::from_scalars(
            deserialize_scalar(&buf[..group::NS])?,
            deserialize_scalar(&buf[group::NS..2 * group::NS])?,
            deserialize_scalar(&buf[2 * group::NS..3 * group::NS])?,
            deserialize_scalar(&buf[3 * group::NS..])?,
        ))
    }

    /// Derive the corresponding [`ServerPublicKey`] (spec §4.1):
    ///   * `X0 = x0 * G + x0Blinding * H`
    ///   * `X1 = x1 * H`
    ///   * `X2 = x2 * H`
    pub fn public_key(&self) -> ServerPublicKey {
        let g = generator_g();
        let h = generator_h();
        ServerPublicKey {
            x0: g * self.x0 + h * self.x0_blinding,
            x1: h * self.x1,
            x2: h * self.x2,
        }
    }
}

impl ServerPublicKey {
    /// `NserverPublicKey = 3 * Ne` byte serialization (spec §4.1).
    pub fn serialize(&self) -> [u8; 3 * group::NE] {
        let mut out = [0u8; 3 * group::NE];
        out[..group::NE].copy_from_slice(&group::serialize_element(&self.x0));
        out[group::NE..2 * group::NE].copy_from_slice(&group::serialize_element(&self.x1));
        out[2 * group::NE..].copy_from_slice(&group::serialize_element(&self.x2));
        out
    }
}
