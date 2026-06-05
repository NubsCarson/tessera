//! The high-level ARC protocol API (`draft-ietf-privacypass-arc-crypto-01` §4):
//! issuance (request → response → finalize), presentation, verification, and
//! the server-side double-spend tag store.
//!
//! This ties the proven [`crate::group`], [`crate::keys`], [`crate::sigma`],
//! and [`crate::proofs`] layers into the three-phase protocol a real
//! deployment uses.

use crate::group::{
    generator_g, generator_h, hash_to_group, hash_to_scalar, random_scalar, scalar_invert,
    serialize_element,
};
use crate::keys::{ServerPrivateKey, ServerPublicKey};
use crate::proofs::{
    prove_credential_request, prove_credential_response, prove_presentation,
    verify_credential_request_proof, verify_credential_response_proof, verify_presentation_proof,
    PresentationWitness,
};
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use std::collections::HashSet;

/// Errors surfaced by the ARC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcError {
    /// The client's credential-request proof failed to verify.
    InvalidRequestProof,
    /// The server's credential-response proof failed to verify.
    InvalidResponseProof,
    /// The presentation limit for this credential/context was reached.
    LimitExceeded,
    /// The credential cannot form a presentation because `m1 + nonce` is not
    /// invertible (zero modulo the group order). For a randomly issued
    /// credential this is astronomically unlikely (~2⁻²⁵⁶); it is surfaced as a
    /// recoverable error rather than a panic so a hosted client (e.g. wasm)
    /// never aborts.
    DegenerateCredential,
}

impl core::fmt::Display for ArcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ArcError::InvalidRequestProof => "credential-request proof failed to verify",
            ArcError::InvalidResponseProof => "credential-response proof failed to verify",
            ArcError::LimitExceeded => "presentation limit reached",
            ArcError::DegenerateCredential => {
                "credential cannot form a presentation (m1 + nonce not invertible)"
            }
        })
    }
}

impl std::error::Error for ArcError {}

/// The client secrets retained between request creation and finalization.
#[derive(Debug)]
pub struct ClientSecrets {
    /// The random credential attribute; the client's long-lived secret that
    /// later anchors the presentation tag.
    pub m1: Scalar,
    /// The request-context attribute, derived as `hash_to_scalar(requestContext)`
    /// so the server can recompute and bind it.
    pub m2: Scalar,
    /// Blinding for the `m1` encryption (`m1Enc = m1*G + r1*H`).
    pub r1: Scalar,
    /// Blinding for the `m2` encryption (`m2Enc = m2*G + r2*H`).
    pub r2: Scalar,
}

/// A credential request sent to the server (spec §4.2.1).
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// Pedersen encryption of `m1`: `m1Enc = m1*G + r1*H`.
    pub m1_enc: ProjectivePoint,
    /// Pedersen encryption of `m2`: `m2Enc = m2*G + r2*H`.
    pub m2_enc: ProjectivePoint,
    /// Proof that the client knows the openings of `m1Enc`/`m2Enc`
    /// (`challenge ‖ responses`).
    pub proof: Vec<u8>,
}

/// A credential response returned by the server (spec §4.2.2).
#[derive(Debug)]
pub struct CredentialResponse {
    /// The MAC base `U = b*G` for a fresh per-issuance blind `b`.
    pub u: ProjectivePoint,
    /// The blinded MAC value `encUPrime`; the client unblinds it with `r1`/`r2`
    /// to recover `U'`.
    pub enc_u_prime: ProjectivePoint,
    /// `x0Blinding` contribution `H*(b*x0Blinding)`, removed during unblinding.
    pub x0_aux: ProjectivePoint,
    /// `b`-scaled `X1` (`X1*b`), used to strip the `r1` blinding from `encUPrime`.
    pub x1_aux: ProjectivePoint,
    /// `b`-scaled `X2` (`X2*b`), used to strip the `r2` blinding from `encUPrime`.
    pub x2_aux: ProjectivePoint,
    /// `b`-scaled generator `H*b`, the base the auxiliary points are proven against.
    pub h_aux: ProjectivePoint,
    /// Proof that the response was computed with the server's secret key
    /// (`challenge ‖ responses`).
    pub proof: Vec<u8>,
}

/// A finalized credential the client can present (spec §4.2.3).
#[derive(Debug, Clone)]
pub struct Credential {
    /// The client's secret attribute, re-randomized into every presentation tag.
    pub m1: Scalar,
    /// The MAC base `U`.
    pub u: ProjectivePoint,
    /// The unblinded MAC value `U'` recovered from the response.
    pub u_prime: ProjectivePoint,
    /// The server's public `X1`, retained so the client can build presentations
    /// without holding the full public key.
    pub x1: ProjectivePoint,
}

/// A single presentation of a credential (spec §4.3.2).
#[derive(Debug)]
pub struct Presentation {
    /// Re-randomized MAC base `U = a*U` for a fresh per-presentation blind `a`.
    pub u: ProjectivePoint,
    /// Commitment to the re-randomized MAC value `U'` (`a*U' + r*G`).
    pub u_prime_commit: ProjectivePoint,
    /// Commitment to `m1` against the presentation base (`m1*U + z*H`).
    pub m1_commit: ProjectivePoint,
    /// The double-spend tag `generatorT * (m1 + nonce)⁻¹`; constant for a given
    /// (credential, context, nonce), which is how reuse is detected.
    pub tag: ProjectivePoint,
    /// Pedersen commitment to the presentation nonce (`nonce*G + nonceBlinding*H`).
    pub nonce_commit: ProjectivePoint,
    /// Bit-commitment elements of the range proof showing `0 <= nonce < limit`.
    pub d: Vec<ProjectivePoint>,
    /// The combined presentation + range proof (`challenge ‖ responses`).
    pub proof: Vec<u8>,
}

// ---- Issuance ------------------------------------------------------------

/// Client: create a credential request bound to `request_context` (spec §4.2.1).
pub fn create_credential_request<R: RngCore + ?Sized>(
    request_context: &[u8],
    rng: &mut R,
) -> (ClientSecrets, CredentialRequest) {
    let g = generator_g();
    let h = generator_h();
    let m1 = random_scalar(rng);
    let m2 = hash_to_scalar(request_context, b"requestContext");
    let r1 = random_scalar(rng);
    let r2 = random_scalar(rng);
    let m1_enc = g * m1 + h * r1;
    let m2_enc = g * m2 + h * r2;
    let proof = prove_credential_request(m1, m2, r1, r2, m1_enc, m2_enc, rng);
    (
        ClientSecrets { m1, m2, r1, r2 },
        CredentialRequest {
            m1_enc,
            m2_enc,
            proof,
        },
    )
}

/// Server: verify the request and produce a credential response (spec §4.2.2).
pub fn create_credential_response<R: RngCore + ?Sized>(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    rng: &mut R,
) -> Result<CredentialResponse, ArcError> {
    if !verify_credential_request_proof(request.m1_enc, request.m2_enc, &request.proof) {
        return Err(ArcError::InvalidRequestProof);
    }
    let g = generator_g();
    let h = generator_h();
    let b = random_scalar(rng);
    let u = g * b;
    let enc_u_prime =
        (public_key.x0 + request.m1_enc * private_key.x1 + request.m2_enc * private_key.x2) * b;
    let x0_aux = h * (b * private_key.x0_blinding);
    let x1_aux = public_key.x1 * b;
    let x2_aux = public_key.x2 * b;
    let h_aux = h * b;

    let proof = prove_credential_response(
        private_key,
        public_key,
        request.m1_enc,
        request.m2_enc,
        b,
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
        rng,
    );
    Ok(CredentialResponse {
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
        proof,
    })
}

/// Client: verify the response and finalize the credential (spec §4.2.3).
pub fn finalize_credential(
    secrets: &ClientSecrets,
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> Result<Credential, ArcError> {
    if !verify_credential_response_proof(
        public_key,
        request.m1_enc,
        request.m2_enc,
        response.u,
        response.enc_u_prime,
        response.x0_aux,
        response.x1_aux,
        response.x2_aux,
        response.h_aux,
        &response.proof,
    ) {
        return Err(ArcError::InvalidResponseProof);
    }
    // UPrime = encUPrime - X0Aux - r1*X1Aux - r2*X2Aux
    let u_prime = response.enc_u_prime
        - response.x0_aux
        - response.x1_aux * secrets.r1
        - response.x2_aux * secrets.r2;
    Ok(Credential {
        m1: secrets.m1,
        u: response.u,
        u_prime,
        x1: public_key.x1,
    })
}

// ---- Presentation --------------------------------------------------------

/// Client-side presentation state: tracks the next nonce so a credential is not
/// presented more than `limit` times for a given context (spec §4.3.1).
pub struct PresentationState {
    credential: Credential,
    presentation_context: Vec<u8>,
    next_nonce: u64,
    limit: u64,
}

impl PresentationState {
    /// Initialize presentation state for a credential, context, and limit.
    pub fn new(credential: Credential, presentation_context: &[u8], limit: u64) -> Self {
        Self {
            credential,
            presentation_context: presentation_context.to_vec(),
            next_nonce: 0,
            limit,
        }
    }

    /// Create the next presentation, advancing the nonce (spec §4.3.2). Fails
    /// once the presentation limit is reached. A limit below 2 admits no valid
    /// range proof, so it yields `LimitExceeded` rather than panicking in
    /// `compute_bases` (mirrors the verify-side `limit < 2` guard).
    pub fn present<R: RngCore + ?Sized>(&mut self, rng: &mut R) -> Result<Presentation, ArcError> {
        if self.limit < 2 || self.next_nonce >= self.limit {
            return Err(ArcError::LimitExceeded);
        }
        let nonce = self.next_nonce;
        self.next_nonce += 1;

        let g = generator_g();
        let h = generator_h();
        let cred = &self.credential;

        let a = random_scalar(rng);
        let r = random_scalar(rng);
        let z = random_scalar(rng);

        let u = cred.u * a;
        let u_prime = cred.u_prime * a;
        let u_prime_commit = u_prime + g * r;
        let m1_commit = u * cred.m1 + h * z;

        let nonce_blinding = random_scalar(rng);
        let nonce_scalar = Scalar::from(nonce);
        let nonce_commit = g * nonce_scalar + h * nonce_blinding;

        let generator_t = hash_to_group(&self.presentation_context, b"Tag");
        // `m1 + nonce` is non-zero (hence invertible) for any randomly issued
        // credential; the `ok_or` makes the ~2⁻²⁵⁶ degenerate case a recoverable
        // error instead of a panic, so a hosted (wasm) client never aborts.
        let m1_nonce_inv =
            scalar_invert(&(cred.m1 + nonce_scalar)).ok_or(ArcError::DegenerateCredential)?;
        let tag = generator_t * m1_nonce_inv;
        let v = cred.x1 * z - g * r;

        let pp = prove_presentation(
            &PresentationWitness {
                u,
                u_prime_commit,
                m1_commit,
                tag,
                generator_t,
                m1: cred.m1,
                x1: cred.x1,
                v,
                r,
                z,
                nonce,
                nonce_blinding,
                nonce_commit,
                limit: self.limit,
            },
            rng,
        );

        Ok(Presentation {
            u,
            u_prime_commit,
            m1_commit,
            tag,
            nonce_commit,
            d: pp.d,
            proof: pp.proof,
        })
    }
}

/// Server: verify a presentation (spec §4.3.3). Returns `Some(tag_bytes)` **iff**
/// the proof verified — making it impossible to use a tag from an invalid
/// presentation. The caller must still pass `tag_bytes` through a [`TagStore`]
/// to enforce single-use of each (credential, context, nonce) slot.
pub fn verify_presentation(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    presentation: &Presentation,
    limit: u64,
) -> Option<[u8; 33]> {
    let valid = verify_presentation_proof(
        private_key,
        public_key,
        request_context,
        presentation_context,
        presentation.u,
        presentation.u_prime_commit,
        presentation.m1_commit,
        presentation.tag,
        presentation.nonce_commit,
        &presentation.d,
        &presentation.proof,
        limit,
    );
    valid.then(|| serialize_element(&presentation.tag))
}

/// A server-side store of spent presentation tags, for double-spend prevention
/// (spec §4.3.3, implementation note). A real deployment would key this by
/// `(requestContext, presentationContext)` and persist it.
#[derive(Default)]
pub struct TagStore {
    seen: HashSet<[u8; 33]>,
}

impl TagStore {
    /// Create an empty tag store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a tag; returns `true` if it is fresh (accept) or `false` if it
    /// has been seen before (double-spend; reject).
    pub fn accept(&mut self, tag: [u8; 33]) -> bool {
        self.seen.insert(tag)
    }
}
