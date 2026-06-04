//! Plain-crypto primitives for the channel protocol.
//!
//! # Phase 2c revision: chain-facing signatures are now EVM-native secp256k1
//!
//! **2a used P-256 ECDSA** purely by workspace convenience (the curve
//! `tessera-arc` ships). That was wrong for the *durable, chain-facing* state
//! signature: the channel settles on the **EVM**, which verifies **secp256k1**
//! cheaply and universally via the `ecrecover` precompile, but verifies P-256
//! only via a non-universal precompile (EIP-7212, not deployed everywhere) or an
//! expensive in-EVM library. So Phase 2c switches **every** channel signature to
//! **Ethereum-style secp256k1**:
//!
//!   * keys are secp256k1 ([`k256`], the RustCrypto sibling of the `p256` the
//!     rest of the workspace uses — same `ecdsa`/`elliptic-curve` 0.13 stack);
//!   * the **signed message is a 32-byte keccak256 digest**, and the signature is
//!     produced **recoverably** ([`EthSig`] = `r ‖ s ‖ v`, low-`s`, `v ∈ {27,28}`)
//!     so a Solidity contract recovers the signer with
//!     `ecrecover(digest, v, r, s)`;
//!   * identity is the **20-byte Ethereum address** `keccak256(pubkey[1..])[12..]`
//!     ([`VerifyingKey::eth_address`]), so the `ChannelRegistry` court and Rust
//!     agree on *who signed* byte-for-byte (`contracts/`, `DESIGN.md` §6).
//!
//! The SHA-256 **state commitment** `S_i` is kept as-is (it is internal to Rust
//! and stored opaquely on-chain); only the *signed digest* is keccak256. Every
//! signature in this crate — the durable state sig (`sig_user`), the relayer
//! co-signature (`sig_relayer`), the freshness binding (`sig_fresh`), and the
//! proof-of-relay receipt — uses this one recoverable-secp256k1 path. The
//! freshness/relay-ack sigs never touch chain and *could* have stayed P-256, but
//! we moved them too so the crate has a **single** signature type (less surface,
//! one verification path to review); this is noted in the README.
//!
//! There is no novel cryptography here and we do not claim any: `k256`/`sha3`
//! are audited RustCrypto crates; the value is the cross-language identity match.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey as K256VerifyingKey};
use rand_core::{CryptoRng, RngCore};
// `digest::Digest` (re-exported by both `sha2` and `sha3` from the same `digest`
// crate) provides `new`/`update`/`finalize` for `Sha256` and `Keccak256` alike.
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// A 32-byte SHA-256 digest, used both for the state commitment `S_i` and for
/// the request hash in the freshness binding.
pub type Hash = [u8; 32];

/// A 32-byte keccak256 digest — the **chain-facing** message that is actually
/// signed (and that an EVM contract feeds to `ecrecover`).
pub type EthDigest = [u8; 32];

/// A 20-byte Ethereum address `keccak256(uncompressed_pubkey[1..])[12..]` — the
/// on-chain identity of a participant. The `ChannelRegistry` stores the user and
/// relayer addresses and checks `ecrecover(...) == address`.
pub type EthAddress = [u8; 20];

/// A signing keypair (a **secp256k1** ECDSA key). One belongs to the user, one
/// to the relayer; in the design these are pool-fresh / bonded keys, but the key
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

    /// Construct a keypair from a fixed 32-byte secret scalar (big-endian).
    ///
    /// This is mainly for **deterministic test vectors** — in particular the
    /// Rust→Solidity cross-language signature vector, which needs a fixed key so
    /// the `(address, digest, r, s, v)` it prints is reproducible and can be
    /// hard-coded into a Foundry test. Returns `None` if `secret` is not a valid
    /// secp256k1 scalar (zero or ≥ the curve order).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Option<Self> {
        let signing = SigningKey::from_bytes(secret.into()).ok()?;
        let verifying = VerifyingKey(*signing.verifying_key());
        Some(Self { signing, verifying })
    }

    /// This keypair's public verifying key (what a peer checks signatures
    /// against, and what a slash verdict is attributed to).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying.clone()
    }

    /// This keypair's 20-byte Ethereum address (the on-chain identity).
    pub fn eth_address(&self) -> EthAddress {
        self.verifying.eth_address()
    }

    /// Sign a **32-byte keccak256 digest** recoverably with deterministic ECDSA
    /// (RFC 6979) — no per-signature randomness, so a signature is a pure
    /// function of (key, digest). That determinism is what makes equivocation
    /// *attributable*: two valid signatures over two **conflicting** states are
    /// both bound to this key.
    ///
    /// The signature is **`s`-normalized to the low half** and carries a recovery
    /// id (`v ∈ {27, 28}`) so an EVM contract recovers the exact signer address
    /// via `ecrecover(digest, v, r, s)`. Panics only on the cryptographically
    /// impossible failure of RFC 6979 deterministic signing.
    pub fn sign_digest(&self, digest: &EthDigest) -> EthSig {
        // `sign_prehash_recoverable` already normalizes `s` to the low half
        // (k256 enforces low-`s`), matching what `ecrecover` consumers expect.
        let (sig, recid) = self
            .signing
            .sign_prehash_recoverable(digest)
            .expect("RFC 6979 deterministic signing over a 32-byte digest cannot fail");
        EthSig::from_parts(sig, recid)
    }
}

/// A public verifying key (secp256k1). Equality / hashing are over the 20-byte
/// Ethereum address (the on-chain identity), so it can index a participant in a
/// dispute set exactly as the contract would.
#[derive(Clone, Debug)]
pub struct VerifyingKey(K256VerifyingKey);

impl VerifyingKey {
    /// Verify `sig` over a **32-byte keccak digest**. Returns `true` iff the
    /// signature is valid under this key.
    ///
    /// This mirrors the on-chain check: it recomputes nothing about the message
    /// (the digest is the message), and a signature whose recovered key is a
    /// *different* key fails — exactly as `ecrecover(...) == storedAddress` would.
    pub fn verify_digest(&self, digest: &EthDigest, sig: &EthSig) -> bool {
        self.0.verify_prehash(digest, &sig.sig).is_ok()
    }

    /// Recover the signer's [`VerifyingKey`] from a digest + signature, the way
    /// the EVM `ecrecover` precompile does. `None` if recovery fails.
    ///
    /// This is the function the cross-language vector test pins: the address
    /// recovered here in Rust must equal the address `ecrecover` returns in
    /// Solidity for the identical `(digest, r, s, v)`.
    pub fn recover_from_digest(digest: &EthDigest, sig: &EthSig) -> Option<Self> {
        K256VerifyingKey::recover_from_prehash(digest, &sig.sig, sig.recid())
            .ok()
            .map(VerifyingKey)
    }

    /// The 20-byte Ethereum address `keccak256(uncompressed_pubkey[1..])[12..]`.
    ///
    /// This is the canonical identity used for equality/hashing and for
    /// attributing a verdict — and is exactly what an EVM contract derives /
    /// stores, so Rust and Solidity agree on *who* a signature is from.
    pub fn eth_address(&self) -> EthAddress {
        // SEC1 *uncompressed* point is `0x04 || X(32) || Y(32)`; Ethereum hashes
        // the 64-byte `X || Y` (dropping the 0x04 tag) and takes the last 20.
        let pt = self.0.to_encoded_point(false);
        let bytes = pt.as_bytes();
        debug_assert_eq!(bytes.len(), 65, "uncompressed secp256k1 point is 65 bytes");
        let mut hasher = Keccak256::new();
        hasher.update(&bytes[1..]);
        let h = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&h[12..]);
        addr
    }

    /// The SEC1-compressed encoding (33 bytes). Retained for completeness; the
    /// *identity* used everywhere is the [`eth_address`](Self::eth_address).
    pub fn to_bytes(&self) -> [u8; 33] {
        let pt = self.0.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(pt.as_bytes());
        out
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.eth_address() == other.eth_address()
    }
}
impl Eq for VerifyingKey {}

impl core::hash::Hash for VerifyingKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.eth_address().hash(state);
    }
}

/// An **Ethereum-style recoverable** secp256k1 ECDSA signature: `(r, s, v)`,
/// with `s` in the low half and `v ∈ {27, 28}` (the values `ecrecover` accepts).
///
/// The on-the-wire / on-chain form is the 65-byte `r ‖ s ‖ v`
/// ([`to_rsv`](Self::to_rsv)), which is what a Solidity test splits and feeds to
/// `ecrecover(digest, v, r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthSig {
    sig: Signature,
    /// Ethereum recovery byte, `27 + recovery_id` (so 27 or 28).
    v: u8,
}

impl EthSig {
    /// Ethereum's `v` recovery byte (27 or 28).
    pub fn v(&self) -> u8 {
        self.v
    }

    /// The 32-byte big-endian `r` component.
    pub fn r(&self) -> [u8; 32] {
        self.sig.r().to_bytes().into()
    }

    /// The 32-byte big-endian `s` component (already low-half normalized).
    pub fn s(&self) -> [u8; 32] {
        self.sig.s().to_bytes().into()
    }

    /// The canonical 65-byte `r ‖ s ‖ v` encoding (what Solidity consumes).
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r());
        out[32..64].copy_from_slice(&self.s());
        out[64] = self.v;
        out
    }

    /// Parse a 65-byte `r ‖ s ‖ v` signature (the on-chain form). `None` if the
    /// `r`/`s` scalars are invalid or `v ∉ {27, 28}`.
    pub fn from_rsv(rsv: &[u8; 65]) -> Option<Self> {
        let sig = Signature::from_slice(&rsv[..64]).ok()?;
        let v = rsv[64];
        if v != 27 && v != 28 {
            return None;
        }
        Some(Self { sig, v })
    }

    fn from_parts(sig: Signature, recid: RecoveryId) -> Self {
        Self {
            sig,
            v: 27 + recid.to_byte(),
        }
    }

    fn recid(&self) -> RecoveryId {
        // `v` is constrained to {27,28} by construction / `from_rsv`, so
        // `v - 27 ∈ {0,1}` is always a valid recovery id.
        RecoveryId::from_byte(self.v - 27).expect("v in {27,28} ⇒ recid in {0,1}")
    }
}

/// Backwards-compatible alias: the rest of the crate refers to the channel
/// signature type as `Sig`. It is now [`EthSig`] (recoverable secp256k1).
pub type Sig = EthSig;

/// Domain-separated SHA-256: `SHA256(len(domain) || domain || msg)`.
///
/// Used for the **state commitment** `S_i` and the request hash. The length
/// prefix on the domain makes the separation unambiguous (no domain is a prefix
/// of another), so a commitment hash can never collide with a request hash even
/// on identical `msg` bytes.
pub fn h(domain: &[u8], msg: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Domain-separated **keccak256**: `keccak256(len(domain) || domain || msg)`.
///
/// This is the **chain-facing** digest — the 32 bytes actually signed (and fed
/// to `ecrecover` on-chain). The exact same byte layout must be reproduced in
/// Solidity (`keccak256(abi.encodePacked(uint64(domain.length), domain, msg))`)
/// for a Rust-made signature to verify on-chain. Length-prefixed for the same
/// unambiguous domain separation as [`h`].
pub fn keccak_domain(domain: &[u8], msg: &[u8]) -> EthDigest {
    let mut hasher = Keccak256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(msg);
    hasher.finalize().into()
}
