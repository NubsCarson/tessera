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
//! ## Example: issue once, present, verify
//!
//! ```
//! use rand_core::OsRng;
//! use tessera_arc::arc::{
//!     create_credential_request, create_credential_response, finalize_credential,
//!     verify_presentation, PresentationState,
//! };
//! use tessera_arc::keys::ServerPrivateKey;
//!
//! let mut rng = OsRng;
//! let (sk, pk) = ServerPrivateKey::setup(&mut rng);
//! let (request_ctx, present_ctx, limit) = (b"issue/v1".as_slice(), b"origin/v1".as_slice(), 4);
//!
//! // Issuance: client requests, server responds, client finalizes.
//! let (secrets, request) = create_credential_request(request_ctx, &mut rng);
//! let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
//! let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();
//!
//! // Presentation: each call yields a fresh, unlinkable token; the verifier
//! // returns the rate-limiting tag iff it checks out — the source IP is never
//! // an input.
//! let mut state = PresentationState::new(credential, present_ctx, limit);
//! let presentation = state.present(&mut rng).unwrap();
//! assert!(verify_presentation(&sk, &pk, request_ctx, present_ctx, &presentation, limit).is_some());
//! ```
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
//!   3. Issuance / presentation arithmetic — **proven** byte-for-byte against
//!      the §10.2 vector intermediate points (`tests/test_vectors.rs`).
//!   4. Fiat-Shamir + Sigma proofs — **proven** against the *authoritative* IETF
//!      Sigma Protocol vectors (`tests/sigma_vectors.rs`), the identical
//!      transcript machinery the ARC proofs use; plus end-to-end issue/present/
//!      verify round-trips (`tests/roundtrip.rs`). The §10.2 ARC *proof blobs*
//!      are not byte-reproducible from the pinned reference (an upstream vector
//!      skew) and their tests are `#[ignore]`d — see
//!      `docs/ARC_PROOF_VECTOR_DISCREPANCY.md`.
//!
//! This crate is research-grade and has **not** been audited or hardened for
//! constant-time guarantees end to end. Do not deploy it to protect real
//! users yet. See `GOAL.md` for the path to production readiness.

#![forbid(unsafe_code)]

pub mod arc;
pub mod group;
pub mod keys;
pub mod proofs;
pub mod sigma;
pub mod wire;
