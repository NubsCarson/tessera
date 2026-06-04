//! ARC's zero-knowledge proof statements, expressed as linear relations over
//! the [`crate::sigma`] layer (`draft-ietf-privacypass-arc-crypto-01` §5).
//!
//! Each statement is built once by a `*_statement` helper and shared between
//! the prover and verifier, so the instance label (and therefore the
//! Fiat-Shamir challenge) is identical on both sides. Variable allocation order
//! mirrors the reference POC exactly.

use crate::group::{generator_g, generator_h, scalar_invert};
use crate::keys::{ServerPrivateKey, ServerPublicKey};
use crate::sigma::{prove, verify, LinearRelation};
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;

/// `contextString` for `ARC(P-256)` — the prefix of every proof session string.
pub const CONTEXT_STRING: &[u8] = b"ARCV1-P256";

fn session(suffix: &[u8]) -> Vec<u8> {
    [CONTEXT_STRING, suffix].concat()
}

// ===========================================================================
// CredentialRequest proof (spec §5.1)
// ===========================================================================

fn request_statement(m1_enc: ProjectivePoint, m2_enc: ProjectivePoint) -> LinearRelation {
    let mut s = LinearRelation::new();
    let sv = s.allocate_scalars(4); // m1, m2, r1, r2
    let ev = s.allocate_elements(4); // genG, genH, m1Enc, m2Enc
    s.set_element(ev[0], generator_g());
    s.set_element(ev[1], generator_h());
    s.set_element(ev[2], m1_enc);
    s.set_element(ev[3], m2_enc);
    // m1Enc = m1*genG + r1*genH ; m2Enc = m2*genG + r2*genH
    s.append_equation(ev[2], vec![(sv[0], ev[0]), (sv[2], ev[1])]);
    s.append_equation(ev[3], vec![(sv[1], ev[0]), (sv[3], ev[1])]);
    s
}

/// Produce a `CredentialRequest` proof of knowledge of `(m1, m2, r1, r2)`.
#[allow(clippy::too_many_arguments)]
pub fn prove_credential_request<R: RngCore + ?Sized>(
    m1: Scalar,
    m2: Scalar,
    r1: Scalar,
    r2: Scalar,
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    rng: &mut R,
) -> Vec<u8> {
    let s = request_statement(m1_enc, m2_enc);
    prove(&session(b"CredentialRequest"), &s, &[m1, m2, r1, r2], rng)
}

/// Verify a `CredentialRequest` proof (spec §5.1).
pub fn verify_credential_request_proof(
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    proof: &[u8],
) -> bool {
    verify(
        &session(b"CredentialRequest"),
        &request_statement(m1_enc, m2_enc),
        proof,
    )
}

// ===========================================================================
// CredentialResponse proof (spec §5.2)
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn response_statement(
    public_key: &ServerPublicKey,
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    u: ProjectivePoint,
    enc_u_prime: ProjectivePoint,
    x0_aux: ProjectivePoint,
    x1_aux: ProjectivePoint,
    x2_aux: ProjectivePoint,
    h_aux: ProjectivePoint,
) -> LinearRelation {
    let mut s = LinearRelation::new();
    let sv = s.allocate_scalars(7); // x0, x1, x2, xb, b, t1, t2
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

    s.append_equation(x0p, vec![(x0, gen_g), (xb, gen_h)]); // X0 = x0*G + xb*H
    s.append_equation(x1p, vec![(x1, gen_h)]); // X1 = x1*H
    s.append_equation(x2p, vec![(x2, gen_h)]); // X2 = x2*H
    s.append_equation(ha, vec![(b, gen_h)]); // HAux = b*H
    s.append_equation(x0a, vec![(xb, ha)]); // X0Aux = xb*HAux
    s.append_equation(x1a, vec![(t1, gen_h)]); // X1Aux = t1*H
    s.append_equation(x1a, vec![(b, x1p)]); // X1Aux = b*X1
    s.append_equation(x2a, vec![(b, x2p)]); // X2Aux = b*X2
    s.append_equation(x2a, vec![(t2, gen_h)]); // X2Aux = t2*H
    s.append_equation(u_v, vec![(b, gen_g)]); // U = b*G
    s.append_equation(encu, vec![(b, x0p), (t1, m1e), (t2, m2e)]); // encUPrime
    s
}

/// Produce a `CredentialResponse` proof. `b` is the server's response blind.
#[allow(clippy::too_many_arguments)]
pub fn prove_credential_response<R: RngCore + ?Sized>(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    m1_enc: ProjectivePoint,
    m2_enc: ProjectivePoint,
    b: Scalar,
    u: ProjectivePoint,
    enc_u_prime: ProjectivePoint,
    x0_aux: ProjectivePoint,
    x1_aux: ProjectivePoint,
    x2_aux: ProjectivePoint,
    h_aux: ProjectivePoint,
    rng: &mut R,
) -> Vec<u8> {
    let s = response_statement(
        public_key,
        m1_enc,
        m2_enc,
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
    );
    let witness = [
        private_key.x0,
        private_key.x1,
        private_key.x2,
        private_key.x0_blinding,
        b,
        b * private_key.x1, // t1
        b * private_key.x2, // t2
    ];
    prove(&session(b"CredentialResponse"), &s, &witness, rng)
}

/// Verify a `CredentialResponse` proof (spec §5.2).
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
    let s = response_statement(
        public_key,
        m1_enc,
        m2_enc,
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
    );
    verify(&session(b"CredentialResponse"), &s, proof)
}

// ===========================================================================
// Range proof (spec §5.4) + Presentation proof (spec §5.3)
// ===========================================================================

/// `ComputeBases(presentationLimit)` (spec §5.4): the decomposition bases,
/// descending. For a power of two this is just `[2^(k-1), …, 2, 1]`; otherwise
/// a non-binary remainder base closes the gap.
pub fn compute_bases(limit: u64) -> Vec<u64> {
    assert!(limit >= 2, "presentation limit must be >= 2");
    let num_bits = 64 - (limit - 1).leading_zeros();
    let mut bases = Vec::new();
    let mut remainder = limit;
    for i in 0..num_bits.saturating_sub(1) {
        let base = 1u64 << i;
        remainder -= base;
        bases.push(base);
    }
    bases.push(remainder - 1);
    bases.sort_unstable_by(|a, b| b.cmp(a)); // descending
    bases
}

/// Inputs for building/proving a presentation, shared by prover and verifier.
struct PresentationStatement {
    u: ProjectivePoint,
    u_prime_commit: ProjectivePoint,
    m1_commit: ProjectivePoint,
    v: ProjectivePoint,
    x1: ProjectivePoint,
    tag: ProjectivePoint,
    generator_t: ProjectivePoint,
    nonce_commit: ProjectivePoint,
    d: Vec<ProjectivePoint>,
    limit: u64,
}

/// Build the presentation statement (4 presentation constraints + 2 range
/// constraints per bit), binding the bit-commitment elements `D`. Shared by
/// prover and verifier so the instance label matches.
fn build_presentation_statement(p: &PresentationStatement) -> LinearRelation {
    let g = generator_g();
    let h = generator_h();
    let mut s = LinearRelation::new();

    // 5 presentation scalars: m1, z, -r, nonce, nonceBlinding
    let sv = s.allocate_scalars(5);
    let (m1, z, r_neg, nonce, nonce_blinding) = (sv[0], sv[1], sv[2], sv[3], sv[4]);
    // 10 presentation elements
    let ev = s.allocate_elements(10);
    s.set_element(ev[0], g);
    s.set_element(ev[1], h);
    s.set_element(ev[2], p.u);
    s.set_element(ev[3], p.u_prime_commit);
    s.set_element(ev[4], p.m1_commit);
    s.set_element(ev[5], p.v);
    s.set_element(ev[6], p.x1);
    s.set_element(ev[7], p.tag);
    s.set_element(ev[8], p.generator_t);
    s.set_element(ev[9], p.nonce_commit);
    let (gen_g, gen_h, u_v, _upc, m1c, v_v, x1_v, tag_v, gent_v, ncommit_v) = (
        ev[0], ev[1], ev[2], ev[3], ev[4], ev[5], ev[6], ev[7], ev[8], ev[9],
    );

    // 1. m1Commit = m1*U + z*H
    s.append_equation(m1c, vec![(m1, u_v), (z, gen_h)]);
    // 2. V = z*X1 - r*G   (witness carries -r)
    s.append_equation(v_v, vec![(z, x1_v), (r_neg, gen_g)]);
    // 3. nonceCommit = nonce*G + nonceBlinding*H
    s.append_equation(ncommit_v, vec![(nonce, gen_g), (nonce_blinding, gen_h)]);
    // 4. generatorT = m1*tag + nonce*tag
    s.append_equation(gent_v, vec![(m1, tag_v), (nonce, tag_v)]);

    // Range proof constraints over the bit commitments D.
    let bases = compute_bases(p.limit);
    let num_bits = bases.len();
    let vars_b = s.allocate_scalars(num_bits);
    let vars_s = s.allocate_scalars(num_bits);
    let vars_s2 = s.allocate_scalars(num_bits);

    // Special case (spec/reference): when there is a single bit and D[0] equals
    // the nonce commitment, reuse the nonceCommit element variable.
    let vars_d: Vec<usize> = if num_bits == 1 && p.d[0] == p.nonce_commit {
        vec![ncommit_v]
    } else {
        let dv = s.allocate_elements(num_bits);
        for (i, &idx) in dv.iter().enumerate() {
            s.set_element(idx, p.d[i]);
        }
        dv
    };

    for i in 0..num_bits {
        // D[i] = b[i]*G + s[i]*H
        s.append_equation(vars_d[i], vec![(vars_b[i], gen_g), (vars_s[i], gen_h)]);
        // D[i] = b[i]*D[i] + s2[i]*H  (proves b[i] in {0,1})
        s.append_equation(vars_d[i], vec![(vars_b[i], vars_d[i]), (vars_s2[i], gen_h)]);
    }
    s
}

/// Result of constructing a presentation proof.
pub struct PresentationProof {
    /// Bit-decomposition commitments.
    pub d: Vec<ProjectivePoint>,
    /// `serialize(challenge) || serialize(responses)`.
    pub proof: Vec<u8>,
}

/// All values needed to prove a presentation (computed by the caller in
/// `Present`).
#[allow(clippy::too_many_arguments)]
pub struct PresentationWitness {
    pub u: ProjectivePoint,
    pub u_prime_commit: ProjectivePoint,
    pub m1_commit: ProjectivePoint,
    pub tag: ProjectivePoint,
    pub generator_t: ProjectivePoint,
    pub m1: Scalar,
    pub x1: ProjectivePoint,
    pub v: ProjectivePoint,
    pub r: Scalar,
    pub z: Scalar,
    pub nonce: u64,
    pub nonce_blinding: Scalar,
    pub nonce_commit: ProjectivePoint,
    pub limit: u64,
}

/// Produce a presentation proof (spec §5.3, with the integrated range proof).
pub fn prove_presentation<R: RngCore + ?Sized>(
    w: &PresentationWitness,
    rng: &mut R,
) -> PresentationProof {
    let g = generator_g();
    let h = generator_h();
    let bases = compute_bases(w.limit);
    let num_bits = bases.len();

    // Bit decomposition of the nonce against the (descending) bases.
    let mut bits = Vec::with_capacity(num_bits);
    let mut remainder = w.nonce;
    for &base in &bases {
        let bit = if remainder >= base { 1u64 } else { 0 };
        remainder -= bit * base;
        bits.push(bit);
    }

    // Bit commitments. The last blinding is chosen so Σ bases[i]·D[i] = nonceCommit.
    let mut s_blind = Vec::with_capacity(num_bits);
    let mut s2 = Vec::with_capacity(num_bits);
    let mut d = Vec::with_capacity(num_bits);
    let mut partial_scalar = Scalar::ZERO; // Σ bases[i]·s[i] for the strategic last blind
    for i in 0..num_bits - 1 {
        let s_i = crate::group::random_scalar(rng);
        s_blind.push(s_i);
        partial_scalar += Scalar::from(bases[i]) * s_i;
        s2.push((Scalar::ONE - Scalar::from(bits[i])) * s_i);
        d.push(g * Scalar::from(bits[i]) + h * s_i);
    }
    let idx = num_bits - 1;
    let base_inv = scalar_invert(&Scalar::from(bases[idx])).expect("base is non-zero");
    let s_last = base_inv * (w.nonce_blinding - partial_scalar);
    s_blind.push(s_last);
    s2.push((Scalar::ONE - Scalar::from(bits[idx])) * s_last);
    d.push(g * Scalar::from(bits[idx]) + h * s_last);

    let stmt = build_presentation_statement(&PresentationStatement {
        u: w.u,
        u_prime_commit: w.u_prime_commit,
        m1_commit: w.m1_commit,
        v: w.v,
        x1: w.x1,
        tag: w.tag,
        generator_t: w.generator_t,
        nonce_commit: w.nonce_commit,
        d: d.clone(),
        limit: w.limit,
    });

    // Witness order: [m1, z, -r, nonce, nonceBlinding] ++ b ++ s ++ s2
    let mut witness = vec![w.m1, w.z, -w.r, Scalar::from(w.nonce), w.nonce_blinding];
    witness.extend(bits.iter().map(|&x| Scalar::from(x)));
    witness.extend(s_blind.iter().copied());
    witness.extend(s2.iter().copied());

    let proof = prove(&session(b"CredentialPresentation"), &stmt, &witness, rng);
    PresentationProof { d, proof }
}

/// Verify a presentation proof (spec §5.3): recompute `V` from the server keys,
/// rebuild the statement, check the homomorphic range-sum, and verify the proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_presentation_proof(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    u: ProjectivePoint,
    u_prime_commit: ProjectivePoint,
    m1_commit: ProjectivePoint,
    tag: ProjectivePoint,
    nonce_commit: ProjectivePoint,
    d: &[ProjectivePoint],
    proof: &[u8],
    limit: u64,
) -> bool {
    use crate::group::{hash_to_group, hash_to_scalar};

    // V = x0*U + x1*m1Commit + x2*m2*U - UPrimeCommit
    let m2 = hash_to_scalar(request_context, b"requestContext");
    let v = u * private_key.x0 + m1_commit * private_key.x1 + u * (private_key.x2 * m2)
        - u_prime_commit;
    let generator_t = hash_to_group(presentation_context, b"Tag");

    // Homomorphic range-sum check: nonceCommit == Σ bases[i]·D[i].
    let bases = compute_bases(limit);
    if d.len() != bases.len() {
        return false;
    }
    let mut sum = ProjectivePoint::IDENTITY;
    for (i, &base) in bases.iter().enumerate() {
        sum += d[i] * Scalar::from(base);
    }
    if sum != nonce_commit {
        return false;
    }

    let stmt = build_presentation_statement(&PresentationStatement {
        u,
        u_prime_commit,
        m1_commit,
        v,
        x1: public_key.x1,
        tag,
        generator_t,
        nonce_commit,
        d: d.to_vec(),
        limit,
    });
    verify(&session(b"CredentialPresentation"), &stmt, proof)
}
