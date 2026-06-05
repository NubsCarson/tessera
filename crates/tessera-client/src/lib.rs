//! `tessera-client` — the client side of Tessera. Holds a finalized ARC
//! credential and mints a fresh, unlinkable presentation for each outbound
//! request, encoded for the `Tessera-Presentation` header.
//!
//! Transport-agnostic by design: the client just produces a header string;
//! whether it is sent over plain TCP, TLS, or a Tor circuit is up to the caller.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod net;
pub use net::{obtain_credential, obtain_credential_paid};

use rand_core::RngCore;
use tessera_arc::arc::{
    create_credential_request, finalize_credential, ArcError, Credential, CredentialResponse,
    PresentationState,
};
use tessera_arc::keys::ServerPublicKey;

pub use tessera_arc::arc::CredentialRequest;

/// A client that holds a credential and tracks its presentation budget for a
/// single presentation context.
pub struct TesseraClient {
    state: PresentationState,
}

impl TesseraClient {
    /// Wrap an already-finalized credential for presentations against
    /// `presentation_context`, up to `limit` times.
    pub fn new(credential: Credential, presentation_context: &[u8], limit: u64) -> Self {
        Self {
            state: PresentationState::new(credential, presentation_context, limit),
        }
    }

    /// Produce the next presentation, hex-encoded for the
    /// [`tessera_arc`] wire format / the `Tessera-Presentation` header.
    /// Fails once the presentation limit is exhausted.
    pub fn presentation_header<R: RngCore + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<String, ArcError> {
        let presentation = self.state.present(rng)?;
        Ok(hex::encode(presentation.to_bytes()))
    }
}

/// Begin issuance: create a credential request bound to `request_context`.
/// The returned [`PendingIssuance`] is finalized once the server responds.
pub fn begin_issuance<R: RngCore + ?Sized>(
    request_context: &[u8],
    public_key: ServerPublicKey,
    rng: &mut R,
) -> (PendingIssuance, CredentialRequest) {
    let (secrets, request) = create_credential_request(request_context, rng);
    (
        PendingIssuance {
            secrets,
            public_key,
            request: request.clone(),
        },
        request,
    )
}

/// Client state held between sending a credential request and receiving the
/// server's response.
pub struct PendingIssuance {
    secrets: tessera_arc::arc::ClientSecrets,
    public_key: ServerPublicKey,
    request: CredentialRequest,
}

impl PendingIssuance {
    /// Verify the server's response and finalize the credential.
    pub fn finalize(&self, response: &CredentialResponse) -> Result<Credential, ArcError> {
        finalize_credential(&self.secrets, &self.public_key, &self.request, response)
    }
}
