//! ARC's zero-knowledge proof statements, expressed as linear relations over
//! the [`crate::sigma`] layer (`draft-ietf-privacypass-arc-crypto-01` §5).
//!
//! Each function rebuilds the exact statement from the spec / reference POC
//! (`arc_proofs.sage`) and delegates to the generic Schnorr verifier. The
//! variable allocation order is significant: it determines the instance label
//! and therefore the Fiat-Shamir challenge, so it mirrors the reference
//! one-for-one.

use crate::group::{generator_g, generator_h};
use crate::keys::ServerPublicKey;
use crate::sigma::{verify, LinearRelation};
use p256::ProjectivePoint;

/// `contextString` for `ARC(P-256)` — the prefix of every proof session string.
pub const CONTEXT_STRING: &[u8] = b"ARCV1-P256";

fn session(suffix: &[u8]) -> Vec<u8> {
    [CONTEXT_STRING, suffix].concat()
}

/// Verify a `CredentialRequest` proof (spec §5.1): a proof of knowledge of
/// `(m1, m2, r1, r2)` such that the two encrypted secrets are well-formed.
pub fn verify_credential_request_proof(
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    proof: &[u8],
) -> bool {
    let mut s = LinearRelation::new();
    let sv = s.allocate_scalars(4); // m1, m2, r1, r2
    let ev = s.allocate_elements(4); // genG, genH, m1Enc, m2Enc
    s.set_element(ev[0], generator_g());
    s.set_element(ev[1], generator_h());
    s.set_element(ev[2], m1_enc);
    s.set_element(ev[3], m2_enc);

    // m1Enc = m1*genG + r1*genH
    s.append_equation(ev[2], vec![(sv[0], ev[0]), (sv[2], ev[1])]);
    // m2Enc = m2*genG + r2*genH
    s.append_equation(ev[3], vec![(sv[1], ev[0]), (sv[3], ev[1])]);

    verify(&session(b"CredentialRequest"), &s, proof)
}

/// Verify a `CredentialResponse` proof (spec §5.2): a proof of knowledge of
/// `(x0, x1, x2, x0Blinding, b)` (plus the helper products `t1 = b*x1`,
/// `t2 = b*x2`) binding the response and auxiliary points to the server keys.
#[allow(clippy::too_many_arguments)]
pub fn verify_credential_response_proof(
    public_key: &ServerPublicKey,
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    u: ProjectivePoint,
    enc_u_prime: ProjectivePoint,
    x0_aux: ProjectivePoint,
    x1_aux: ProjectivePoint,
    x2_aux: ProjectivePoint,
    h_aux: ProjectivePoint,
    proof: &[u8],
) -> bool {
    let mut s = LinearRelation::new();
    // x0, x1, x2, xb, b, t1, t2
    let sv = s.allocate_scalars(7);
    // genG, genH, m1Enc, m2Enc, U, encUPrime, X0, X1, X2, X0Aux, X1Aux, X2Aux, HAux
    let ev = s.allocate_elements(13);
    s.set_element(ev[0], generator_g());
    s.set_element(ev[1], generator_h());
    s.set_element(ev[2], m1_enc);
    s.set_element(ev[3], m2_enc);
    s.set_element(ev[4], u);
    s.set_element(ev[5], enc_u_prime);
    s.set_element(ev[6], public_key.x0);
    s.set_element(ev[7], public_key.x1);
    s.set_element(ev[8], public_key.x2);
    s.set_element(ev[9], x0_aux);
    s.set_element(ev[10], x1_aux);
    s.set_element(ev[11], x2_aux);
    s.set_element(ev[12], h_aux);

    let (x0, x1, x2, xb, b, t1, t2) = (sv[0], sv[1], sv[2], sv[3], sv[4], sv[5], sv[6]);
    let (gen_g, gen_h, m1e, m2e, u_v, encu, x0p, x1p, x2p, x0a, x1a, x2a, ha) = (
        ev[0], ev[1], ev[2], ev[3], ev[4], ev[5], ev[6], ev[7], ev[8], ev[9], ev[10], ev[11],
        ev[12],
    );

    // 1. X0 = x0*genG + xb*genH
    s.append_equation(x0p, vec![(x0, gen_g), (xb, gen_h)]);
    // 2. X1 = x1*genH
    s.append_equation(x1p, vec![(x1, gen_h)]);
    // 3. X2 = x2*genH
    s.append_equation(x2p, vec![(x2, gen_h)]);
    // 4a. HAux = b*genH
    s.append_equation(ha, vec![(b, gen_h)]);
    // 4b. X0Aux = xb*HAux
    s.append_equation(x0a, vec![(xb, ha)]);
    // 5a. X1Aux = t1*genH
    s.append_equation(x1a, vec![(t1, gen_h)]);
    // 5b. X1Aux = b*X1
    s.append_equation(x1a, vec![(b, x1p)]);
    // 6a. X2Aux = b*X2
    s.append_equation(x2a, vec![(b, x2p)]);
    // 6b. X2Aux = t2*genH
    s.append_equation(x2a, vec![(t2, gen_h)]);
    // 7. U = b*genG
    s.append_equation(u_v, vec![(b, gen_g)]);
    // 8. encUPrime = b*X0 + t1*m1Enc + t2*m2Enc
    s.append_equation(encu, vec![(b, x0p), (t1, m1e), (t2, m2e)]);

    verify(&session(b"CredentialResponse"), &s, proof)
}
