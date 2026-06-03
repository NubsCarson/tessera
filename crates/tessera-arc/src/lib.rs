//! # tessera-arc
//!
//! A from-scratch, spec-faithful implementation of **Anonymous Rate-Limited
//! Credentials (ARC)** over NIST P-256, following the IETF drafts:
//!
//!   * `draft-ietf-privacypass-arc-crypto-01` (the ARC protocol)
//!   * `draft-irtf-cfrg-sigma-protocols-01` (the proof system)
//!   * `draft-irtf-cfrg-fiat-shamir-01` (non-interactive transform)
//!
//! ARC lets a server issue a credential to an anonymous client that can then
//! be *presented* up to a fixed limit of times, where presentations are
//! mutually unlinkable and unlinkable from issuance. Tessera uses this to let
//! anonymous / Tor traffic carry a cryptographic proof of good standing,
//! instead of being judged on IP reputation.
//!
//! ## Correctness posture
//!
//! Everything in this crate is validated against the official test vectors in
//! `draft-ietf-privacypass-arc-crypto-01` §10.2. The build is staged so that
//! each layer is *proven* before the next is built on it:
//!
//!   1. [`group`] — the P-256 group / hashing / serialization layer.
//!      **Proven**: see `tests/test_vectors.rs`.
//!   2. [`keys`] — server key generation arithmetic. **Proven** against the
//!      `X0/X1/X2` vectors.
//!   3. Issuance / presentation arithmetic — checked against the vector
//!      intermediate points (no zero-knowledge proofs yet).
//!   4. Fiat-Shamir + Sigma proofs — checked against the vector proof blobs.
//!
//! This crate is research-grade and has **not** been audited or hardened for
//! constant-time guarantees end to end. Do not deploy it to protect real
//! users yet. See `GOAL.md` for the path to production readiness.

#![forbid(unsafe_code)]

pub mod group;
pub mod keys;
