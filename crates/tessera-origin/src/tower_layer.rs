//! Optional [`tower`] middleware around an [`OriginGuard`].
//!
//! Behind the off-by-default `tower` feature, this module turns the
//! framework-agnostic guard into a drop-in [`tower::Layer`]. The layer inspects
//! the [`PRESENTATION_HEADER`] on each `http::Request`, calls
//! [`OriginGuard::check`](crate::OriginGuard::check), and:
//!
//! * on [`Decision::Admit`] — forwards the request to the inner service
//!   unchanged (the rate-limit tag is recorded by the guard);
//! * on [`Decision::Reject`] — short-circuits with **`403 Forbidden`**,
//!   *without* polling the inner service.
//!
//! The source IP is never consulted: exactly like the bare guard, the verdict
//! rests entirely on the cryptographic credential in the header.
//!
//! ## Why `403` (not `407`)
//!
//! A missing or invalid presentation is treated as "you are not allowed",
//! mirroring how an unauthenticated bearer token yields `403`. `407 Proxy
//! Authentication Required` is reserved for proxies and carries
//! `Proxy-Authenticate` challenge semantics that do not apply to an origin
//! guard, so we deliberately use `403`. The reject reason is surfaced in a
//! `Tessera-Reject` response header for observability.
//!
//! ## Usage (axum / hyper)
//!
//! ```no_run
//! # #[cfg(feature = "tower")]
//! # {
//! use std::sync::Arc;
//! use tessera_origin::{OriginGuard, TesseraLayer};
//!
//! # fn build_guard() -> OriginGuard { unimplemented!() }
//! let guard = Arc::new(build_guard());
//!
//! // axum: `Router::new().route(..).layer(TesseraLayer::new(guard));`
//! // any tower stack: `ServiceBuilder::new().layer(TesseraLayer::new(guard));`
//! let _layer = TesseraLayer::new(guard);
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};

use crate::{Decision, OriginGuard, PRESENTATION_HEADER};

/// Response header carrying the human-readable reject reason on a `403`.
pub const REJECT_HEADER: &str = "Tessera-Reject";

/// A [`tower::Layer`] that guards an HTTP service with a shared [`OriginGuard`].
///
/// Cheaply cloneable: it only holds an `Arc<OriginGuard>`.
#[derive(Clone)]
pub struct TesseraLayer {
    guard: Arc<OriginGuard>,
}

impl TesseraLayer {
    /// Wrap a shared guard into a layer. The same guard (and therefore the same
    /// spent-tag store) is shared across every cloned service the stack spawns.
    pub fn new(guard: Arc<OriginGuard>) -> Self {
        Self { guard }
    }
}

impl<S> tower::Layer<S> for TesseraLayer {
    type Service = TesseraGuard<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TesseraGuard {
            guard: Arc::clone(&self.guard),
            inner,
        }
    }
}

/// The [`tower::Service`] produced by [`TesseraLayer`]. Holds the shared guard
/// and the inner service it protects.
#[derive(Clone)]
pub struct TesseraGuard<S> {
    guard: Arc<OriginGuard>,
    inner: S,
}

impl<S> TesseraGuard<S> {
    /// Wrap an inner service directly, without going through a [`tower::Layer`].
    pub fn new(guard: Arc<OriginGuard>, inner: S) -> Self {
        Self { guard, inner }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S, ReqBody, ResBody> tower::Service<Request<ReqBody>> for TesseraGuard<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<UnsyncBoxBody<Bytes, ResBody::Error>>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Read the verdict up front so we never poll the inner service on reject.
        let header = req
            .headers()
            .get(PRESENTATION_HEADER)
            .and_then(|v| v.to_str().ok());
        let decision = self.guard.check(header);

        match decision {
            Decision::Admit { .. } => {
                // `poll_ready` was called on `self.inner`; per tower's contract
                // the readiness belongs to the clone we took, so swap to ensure
                // the *ready* service is the one we drive (the standard pattern).
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(async move {
                    let res = inner.call(req).await?;
                    // Erase the inner body type so admit/reject share a `Response`.
                    Ok(res.map(|b| b.boxed_unsync()))
                })
            }
            Decision::Reject(reason) => {
                let mut res = Response::new(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                );
                *res.status_mut() = StatusCode::FORBIDDEN;
                if let Ok(value) = HeaderValue::from_str(reason.label()) {
                    res.headers_mut().insert(REJECT_HEADER, value);
                }
                Box::pin(async move { Ok(res) })
            }
        }
    }
}
