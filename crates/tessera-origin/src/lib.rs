//! `tessera-origin` — the server-side guard that decides whether to admit a
//! request based on an **anonymous ARC credential presentation**, completely
//! ignoring the source IP address.
//!
//! This is the core of Tessera's thesis: instead of judging traffic by IP
//! reputation (which makes Tor exit nodes trivially blockable), a cooperating
//! origin admits any request that carries a valid, in-budget, not-yet-spent
//! presentation — no matter where it came from.
//!
//! The guard is transport-agnostic: it operates on the value of a single
//! request header (the hex-encoded presentation). Wire it into any HTTP stack
//! by extracting that header and calling [`OriginGuard::check`].
//!
//! ## Optional `tower` middleware
//!
//! Enable the off-by-default `tower` feature to get a drop-in `tower::Layer`
//! (`TesseraLayer`) that wraps any HTTP service: it pulls the
//! [`PRESENTATION_HEADER`] off each `http::Request`, runs [`OriginGuard::check`],
//! and short-circuits rejected requests with `403 Forbidden` before the inner
//! service ever sees them. The layer is `axum`/`hyper`-compatible.
// `TesseraLayer`/`tower_layer` only exist with the `tower` feature on, so the
// intra-doc links to them are feature-gated. This keeps the default-feature
// `cargo doc` gate (which runs without `--all-features`) free of broken links.
#![cfg_attr(
    feature = "tower",
    doc = "See [`TesseraLayer`] and the [`tower_layer`] module for details."
)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use tessera_arc::arc::{verify_presentation, Presentation};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

pub mod store;
pub use store::{FileTagStore, InMemoryTagStore, SpentTagStore};

/// The HTTP header carrying a hex-encoded ARC presentation.
pub const PRESENTATION_HEADER: &str = "Tessera-Presentation";

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// No presentation header was supplied (this is what raw Tor traffic looks like).
    MissingCredential,
    /// The header was not valid hex / not a well-formed presentation.
    Malformed,
    /// The zero-knowledge proof did not verify against the server keys.
    InvalidProof,
    /// The presentation tag was already spent (replay / double-spend).
    DoubleSpend,
}

impl RejectReason {
    /// A short, human-facing label.
    pub fn label(&self) -> &'static str {
        match self {
            RejectReason::MissingCredential => "no credential",
            RejectReason::Malformed => "malformed credential",
            RejectReason::InvalidProof => "invalid proof",
            RejectReason::DoubleSpend => "double-spend (replay)",
        }
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for RejectReason {}

/// The guard's verdict for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Admit the request. Carries the hex presentation tag (the rate-limiting
    /// handle the server just recorded) for logging/observability.
    Admit {
        /// The hex presentation tag just recorded — the per-request rate-limit
        /// handle. Carries no IP or identity, so it is safe to log.
        tag: String,
    },
    /// Refuse the request, with a reason.
    Reject(RejectReason),
}

impl Decision {
    /// Whether this verdict admits the request (`false` means it was rejected).
    pub fn is_admit(&self) -> bool {
        matches!(self, Decision::Admit { .. })
    }
}

/// A configured origin guard. Holds the server keys, the agreed request and
/// presentation contexts, the presentation limit, and the spent-tag store.
pub struct OriginGuard {
    private_key: ServerPrivateKey,
    public_key: ServerPublicKey,
    request_context: Vec<u8>,
    presentation_context: Vec<u8>,
    limit: u64,
    store: Box<dyn SpentTagStore>,
}

impl OriginGuard {
    /// Build a guard backed by the default in-memory spent-tag store.
    /// `request_context` must match what credentials were issued against;
    /// `presentation_context` scopes presentations to this origin.
    ///
    /// The in-memory store is process-local and non-durable; for a durable or
    /// shared spent-set (e.g. behind multiple replicas) use [`with_store`] with
    /// a [`FileTagStore`] or your own [`SpentTagStore`].
    ///
    /// [`with_store`]: OriginGuard::with_store
    pub fn new(
        private_key: ServerPrivateKey,
        public_key: ServerPublicKey,
        request_context: &[u8],
        presentation_context: &[u8],
        limit: u64,
    ) -> Self {
        Self::with_store(
            private_key,
            public_key,
            request_context,
            presentation_context,
            limit,
            Box::new(InMemoryTagStore::new()),
        )
    }

    /// Build a guard with a caller-supplied spent-tag store. Use this to plug a
    /// durable ([`FileTagStore`]) or distributed (your own [`SpentTagStore`] over
    /// Redis/Postgres/etc.) double-spend set. Everything else is identical to
    /// [`new`](OriginGuard::new) — the source IP is still never consulted.
    pub fn with_store(
        private_key: ServerPrivateKey,
        public_key: ServerPublicKey,
        request_context: &[u8],
        presentation_context: &[u8],
        limit: u64,
        store: Box<dyn SpentTagStore>,
    ) -> Self {
        Self {
            private_key,
            public_key,
            request_context: request_context.to_vec(),
            presentation_context: presentation_context.to_vec(),
            limit,
            store,
        }
    }

    /// The presentation limit this guard enforces per credential/context.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Decide whether to admit a request, given the value of the
    /// [`PRESENTATION_HEADER`] header (or `None` if absent).
    ///
    /// Source IP is deliberately not an input. The decision rests entirely on
    /// the cryptographic credential.
    pub fn check(&self, presentation_header: Option<&str>) -> Decision {
        let header = match presentation_header {
            Some(h) => h.trim(),
            None => return Decision::Reject(RejectReason::MissingCredential),
        };
        let bytes = match hex::decode(header) {
            Ok(b) => b,
            Err(_) => return Decision::Reject(RejectReason::Malformed),
        };
        let presentation = match Presentation::from_bytes(&bytes, self.limit) {
            Ok(p) => p,
            Err(_) => return Decision::Reject(RejectReason::Malformed),
        };

        let tag = match verify_presentation(
            &self.private_key,
            &self.public_key,
            &self.request_context,
            &self.presentation_context,
            &presentation,
            self.limit,
        ) {
            Some(tag) => tag,
            None => return Decision::Reject(RejectReason::InvalidProof),
        };

        // Enforce single-use of each (credential, context, nonce) slot via the
        // configured spent-tag store (in-memory by default; durable/shared if
        // injected). `record_if_new` is atomic, so concurrent replays of one
        // presentation yield exactly one admit.
        if !self.store.record_if_new(tag) {
            return Decision::Reject(RejectReason::DoubleSpend);
        }
        Decision::Admit {
            tag: hex::encode(tag),
        }
    }
}

#[cfg(feature = "tower")]
pub mod tower_layer;

#[cfg(feature = "tower")]
pub use tower_layer::{TesseraGuard, TesseraLayer};
