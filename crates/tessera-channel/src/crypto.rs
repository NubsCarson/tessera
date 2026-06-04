//! Plain-crypto primitives for the channel protocol: P-256 ECDSA signatures and
//! a domain-separated SHA-256 hash.
//!
//! These are deliberately thin wrappers over the workspace's existing `p256`
//! (the same audited RustCrypto curve `tessera-arc` uses) and `sha2`. The point
//! of Phase 2a is to prove the **protocol logic** with real-but-plain crypto —
//! signatures make equivocation *attributable*, and a hash *commits* a state —
//! so the Phase 2b ZK layer and Phase 2c on-chain court can wrap it later. There
//! is no novel cryptography here and we do not claim any.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey as P256VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest, used both for the state commitment `S_i` and for
/// the request/serve hashes in the freshness binding.
pub type Hash = [u8; 32];

/// A signing keypair (a P-256 ECDSA key). One belongs to the user, one to the
/// relayer; in the design these are pool-fresh / bonded keys, but the key
/// management is out of scope for the protocol state machine.
#[derive(Clone)]
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    /// Generate a fresh keypair from a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing = SigningKey::random(rng);
        let verifying = VerifyingKey(*signing.verifying_key());
        Self { signing, verifying }
    }

    /// This keypair's public verifying key (what a peer checks signatures
    /// against, and what a slash verdict is attributed to).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying.clone()
    }

    /// Sign a message with deterministic ECDSA (RFC 6979) — no per-signature
    /// randomness, so a signature is a pure function of (key, message). That
    /// determinism is what makes equivocation *attributable*: two valid
    /// signatures over two **conflicting** states are both bound to this key.
    pub fn sign(&self, msg: &[u8]) -> Sig {
        let sig: Signature = self.signing.sign(msg);
        Sig(sig)
    }
}

/// A public verifying key. Equality / hashing are over the SEC1 encoding, so it
/// can index a participant in a dispute set.
#[derive(Clone, Debug)]
pub struct VerifyingKey(P256VerifyingKey);

impl VerifyingKey {
    /// Verify `sig` over `msg`. Returns `true` iff the signature is valid under
    /// this key.
    pub fn verify(&self, msg: &[u8], sig: &Sig) -> bool {
        self.0.verify(msg, &sig.0).is_ok()
    }

    /// The SEC1-compressed encoding (33 bytes), the canonical identity of this
    /// key for equality and for attributing a verdict.
    pub fn to_bytes(&self) -> [u8; 33] {
        let pt = self.0.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(pt.as_bytes());
        out
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for VerifyingKey {}

impl core::hash::Hash for VerifyingKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

/// An ECDSA signature over some protocol message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sig(Signature);

impl Sig {
    /// The fixed-width (64-byte) `r || s` encoding.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes().into()
    }
}

/// Domain-separated SHA-256: `SHA256(len(domain) || domain || msg)`.
///
/// The length prefix on the domain makes the separation unambiguous (no domain
/// is a prefix of another), so a commitment hash can never collide with a
/// request hash or a receipt hash even on identical `msg` bytes.
pub fn h(domain: &[u8], msg: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(msg);
    hasher.finalize().into()
}
