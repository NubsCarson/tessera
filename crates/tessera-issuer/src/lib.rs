//! `tessera-issuer` — a **proof-of-work issuance gate** for ARC credentials.
//!
//! ARC's rate limit only bounds presentations *per credential*. If anyone can
//! obtain unlimited credentials, the limit is meaningless — so the real
//! abuse-control lever is **who gets to obtain a credential**
//! (`docs/THREAT_MODEL.md` §4.3/§6.3). This crate provides the simplest
//! deployable gate: a hashcash-style proof of work the client must solve before
//! the server will issue.
//!
//! ## What this does and does NOT provide
//!
//! A PoW gate makes each credential *cost* CPU time: to mint N credentials an
//! attacker pays ~N · 2^difficulty hashes. That throttles bulk minting and
//! raises the price of a Sybil flood. It is **not** strong Sybil resistance — an
//! adversary with enough compute (or ASICs/GPUs) still scales, and it is unfair
//! to low-power clients. Treat it as a cost knob, not an identity check. For
//! real per-human guarantees, gate issuance on a payment, an attestation, or an
//! anonymous one-per-person credential instead (future work). The difficulty is
//! the server's policy dial.
//!
//! ```
//! use rand_core::OsRng;
//! use tessera_issuer::{PowChallenge, solve};
//!
//! let challenge = PowChallenge::new(&mut OsRng, 12); // 12 leading zero bits
//! let solution = solve(&challenge);                  // client pays the cost
//! assert!(challenge.verify(&solution));              // server checks it (cheap)
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub mod keyfile;
pub mod mint;
pub mod net;
pub use keyfile::ensure_shared_key;
pub use net::{serve_issuance, serve_issuance_paid};

/// Length of the random challenge nonce, in bytes.
pub const CHALLENGE_LEN: usize = 16;

/// Domain separator so PoW hashes can never collide with another protocol's.
const POW_DST: &[u8] = b"tessera-pow-v1";

/// A server-issued proof-of-work challenge: a random nonce plus the required
/// number of leading zero bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    /// Random challenge nonce; the client searches for a counter whose digest
    /// over this nonce clears `difficulty`. Also the store key that makes a
    /// solved challenge single-use.
    pub nonce: [u8; CHALLENGE_LEN],
    /// Required leading zero bits of the solution digest — the server's cost
    /// dial (clamped to `0..=64` at mint time).
    pub difficulty: u32,
}

/// A client's solution: the counter whose hash meets the difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    /// The counter the client found: its digest over the challenge nonce has
    /// `difficulty` leading zero bits.
    pub counter: u64,
}

impl PowChallenge {
    /// Mint a fresh random challenge at the given difficulty (leading zero bits
    /// of the SHA-256 digest). Difficulty is clamped to a sane `0..=64`.
    pub fn new<R: RngCore + ?Sized>(rng: &mut R, difficulty: u32) -> Self {
        let mut nonce = [0u8; CHALLENGE_LEN];
        rng.fill_bytes(&mut nonce);
        Self {
            nonce,
            difficulty: difficulty.min(64),
        }
    }

    /// The digest for a candidate counter: `SHA-256(DST ‖ nonce ‖ counter_be)`.
    fn digest(&self, counter: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(POW_DST);
        h.update(self.nonce);
        h.update(counter.to_be_bytes());
        h.finalize().into()
    }

    /// Verify a solution meets the difficulty. Cheap (one hash) for the server.
    pub fn verify(&self, solution: &PowSolution) -> bool {
        leading_zero_bits(&self.digest(solution.counter)) >= self.difficulty
    }
}

/// Count the leading zero bits of a 32-byte digest.
fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in digest {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Solve a challenge by brute-forcing the counter (expected ~`2^difficulty`
/// hashes). This is the cost the *client* pays.
pub fn solve(challenge: &PowChallenge) -> PowSolution {
    let mut counter = 0u64;
    loop {
        if leading_zero_bits(&challenge.digest(counter)) >= challenge.difficulty {
            return PowSolution { counter };
        }
        counter = counter.wrapping_add(1);
    }
}

/// A server-side store of issued, not-yet-redeemed challenges, so each solved
/// challenge admits exactly one issuance (anti-replay), mirroring the
/// presentation tag store. In-memory; a real deployment persists it.
#[derive(Default)]
pub struct ChallengeStore {
    outstanding: HashSet<[u8; CHALLENGE_LEN]>,
}

impl ChallengeStore {
    /// Create an empty challenge store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue and record a fresh challenge at `difficulty`.
    pub fn issue<R: RngCore + ?Sized>(&mut self, rng: &mut R, difficulty: u32) -> PowChallenge {
        let challenge = PowChallenge::new(rng, difficulty);
        self.outstanding.insert(challenge.nonce);
        challenge
    }

    /// Redeem a solved challenge: returns `true` iff the challenge was
    /// outstanding (issued by us, not yet spent) **and** the solution is valid.
    /// On success the challenge is consumed and cannot be reused.
    pub fn redeem(&mut self, challenge: &PowChallenge, solution: &PowSolution) -> bool {
        if !self.outstanding.contains(&challenge.nonce) {
            return false;
        }
        if !challenge.verify(solution) {
            return false;
        }
        self.outstanding.remove(&challenge.nonce)
    }
}
