//! Server key generation (`draft-ietf-privacypass-arc-crypto-01` §4.1).
//!
//! The server holds four secret scalars `(x0, x1, x2, x0Blinding)` and
//! publishes three group elements `(X0, X1, X2)`. The blinding of `x0`
//! (committing to `x0` under both generators) is what gives ARC its issuance
//! unlinkability property (spec §7.2).

use crate::group::{self, generator_g, generator_h, random_scalar};
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;

/// `ServerPrivateKey` (spec §4.1).
#[derive(Debug, Clone)]
pub struct ServerPrivateKey {
    pub x0: Scalar,
    pub x1: Scalar,
    pub x2: Scalar,
    pub x0_blinding: Scalar,
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
