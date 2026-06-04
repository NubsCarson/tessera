//! The Sigma-protocol + Fiat-Shamir layer that ARC's zero-knowledge proofs are
//! built on, following `draft-irtf-cfrg-sigma-protocols-01` and
//! `draft-irtf-cfrg-fiat-shamir-01`, instantiated as `NISchnorrProofShake128P256`.
//!
//! This is a direct, byte-faithful port of the reference proof-of-concept used
//! to generate the IETF test vectors (the prose drafts under-specify a few
//! constants — e.g. the challenge squeeze length and the session-id
//! derivation — so the POC is the authoritative oracle here). The crate's KAT
//! suite proves this port reproduces the reference by *verifying the official
//! proof blobs* and rejecting tampered ones.
//!
//! Only the verifier and the statement machinery live here for now; the prover
//! (which additionally needs a spec-defined RNG) lands with the full ARC API.

use crate::group::{self, deserialize_scalar, random_scalar, reduce_mod_order, serialize_element};
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

/// `protocol_id` for `NISchnorrProofShake128P256`: the suite name padded to
/// 64 bytes with zeros (reference `ciphersuite.sage::get_protocol_id`).
fn protocol_id() -> [u8; 64] {
    let mut id = [0u8; 64];
    let name = b"sigma-proofs_Shake128_P256";
    id[..name.len()].copy_from_slice(name);
    id
}

/// A SHAKE128 duplex sponge, matching the reference `SHAKE128` interface
/// (`draft-irtf-cfrg-fiat-shamir-01` §7.1): the 64-byte IV is padded to the
/// 168-byte SHAKE128 rate with zeros, `absorb` is `update`, and `squeeze`
/// operates on a *copy* of the state so it does not advance the absorbed state.
#[derive(Clone)]
pub struct Sponge {
    hasher: Shake128,
}

impl Sponge {
    /// Initialize with a 64-byte IV (padded to the SHAKE128 rate of 168 bytes).
    pub fn new(iv: &[u8; 64]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(iv);
        hasher.update(&[0u8; 168 - 64]);
        Self { hasher }
    }

    /// Absorb bytes into the sponge state.
    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Squeeze `len` bytes from a copy of the current state (non-mutating).
    pub fn squeeze(&self, len: usize) -> Vec<u8> {
        let mut reader = self.hasher.clone().finalize_xof();
        let mut out = vec![0u8; len];
        reader.read(&mut out);
        out
    }
}

/// Build the Fiat-Shamir transcript sponge for a given session string and
/// statement label, exactly as `NISigmaProtocol.__init__` does:
///   * derive a fixed 64-byte `session_id` by hashing the arbitrary-length
///     session string under the `"fiat-shamir/session-id"` IV, then prefixing
///     32 zero bytes to the 32-byte squeeze;
///   * initialize the main sponge with `protocol_id`, then absorb the
///     `session_id` and the (prefix-free) instance label.
fn init_transcript(session: &[u8], instance_label: &[u8]) -> Sponge {
    let mut session_iv = [0u8; 64];
    let tag = b"fiat-shamir/session-id";
    session_iv[..tag.len()].copy_from_slice(tag);

    let mut session_sponge = Sponge::new(&session_iv);
    session_sponge.absorb(session);
    let squeezed = session_sponge.squeeze(32);

    let mut session_id = [0u8; 64];
    session_id[32..].copy_from_slice(&squeezed);

    let mut sponge = Sponge::new(&protocol_id());
    sponge.absorb(&session_id);
    sponge.absorb(instance_label);
    sponge
}

/// `verifier_challenge` (reference `ByteSchnorrCodec`): squeeze
/// `scalar_byte_length + 32 = 64` bytes and reduce modulo the group order.
fn verifier_challenge(sponge: &Sponge) -> Scalar {
    reduce_mod_order(&sponge.squeeze(group::NS + 32))
}

/// `prover_message`: absorb the serialized commitment (a list of group
/// elements, SEC1-compressed and concatenated).
fn absorb_commitment(sponge: &mut Sponge, commitment: &[ProjectivePoint]) {
    let mut buf = Vec::with_capacity(commitment.len() * group::NE);
    for c in commitment {
        buf.extend_from_slice(&serialize_element(c));
    }
    sponge.absorb(&buf);
}

/// A linear-relation statement: a sparse system of equations
/// `image[i] = Σ_j scalar[s_ij] * element[e_ij]` over allocated scalar and
/// element variables (`draft-irtf-cfrg-sigma-protocols-01` §2.2).
pub struct LinearRelation {
    num_scalars: usize,
    elements: Vec<Option<ProjectivePoint>>,
    /// Each constraint: `(lhs element index, [(scalar index, element index)])`.
    constraints: Vec<(usize, Vec<(usize, usize)>)>,
}

impl Default for LinearRelation {
    fn default() -> Self {
        Self::new()
    }
}

impl LinearRelation {
    pub fn new() -> Self {
        Self {
            num_scalars: 0,
            elements: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// Allocate `n` scalar variables, returning their indices.
    pub fn allocate_scalars(&mut self, n: usize) -> Vec<usize> {
        let start = self.num_scalars;
        self.num_scalars += n;
        (start..self.num_scalars).collect()
    }

    /// Allocate `n` (initially unset) element variables, returning their indices.
    pub fn allocate_elements(&mut self, n: usize) -> Vec<usize> {
        let start = self.elements.len();
        self.elements.extend(std::iter::repeat(None).take(n));
        (start..self.elements.len()).collect()
    }

    /// Bind a concrete group element to a previously allocated element index.
    pub fn set_element(&mut self, index: usize, value: ProjectivePoint) {
        self.elements[index] = Some(value);
    }

    /// Append the equation `element[lhs] = Σ rhs`, where each `rhs` term is a
    /// `(scalar index, element index)` pair.
    pub fn append_equation(&mut self, lhs: usize, rhs: Vec<(usize, usize)>) {
        self.constraints.push((lhs, rhs));
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Number of allocated scalar (witness) variables.
    pub fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    fn element(&self, index: usize) -> ProjectivePoint {
        self.elements[index].expect("element must be set before use")
    }

    /// Evaluate the linear map on a witness/response vector of scalars,
    /// producing one group element per constraint.
    fn map(&self, scalars: &[Scalar]) -> Vec<ProjectivePoint> {
        self.constraints
            .iter()
            .map(|(_, terms)| {
                let mut acc = ProjectivePoint::IDENTITY;
                for &(s_idx, e_idx) in terms {
                    acc += self.element(e_idx) * scalars[s_idx];
                }
                acc
            })
            .collect()
    }

    /// The image vector: the left-hand-side element of each constraint.
    fn image(&self) -> Vec<ProjectivePoint> {
        self.constraints
            .iter()
            .map(|(lhs, _)| self.element(*lhs))
            .collect()
    }

    /// The canonical instance label (reference `LinearRelation.get_label`):
    /// 32-bit little-endian encodings of the constraint structure, followed by
    /// the SEC1-compressed serialization of every allocated element, in order.
    pub fn label(&self) -> Vec<u8> {
        // All allocated elements must be set and pairwise distinct.
        assert!(
            self.elements.iter().all(|e| e.is_some()),
            "all elements must be set"
        );
        let mut out = Vec::new();
        let w = |out: &mut Vec<u8>, v: usize| out.extend_from_slice(&(v as u32).to_le_bytes());

        w(&mut out, self.num_constraints());
        for (lhs, terms) in &self.constraints {
            w(&mut out, *lhs);
            w(&mut out, terms.len());
            for &(s_idx, e_idx) in terms {
                w(&mut out, s_idx);
                w(&mut out, e_idx);
            }
        }
        for e in &self.elements {
            out.extend_from_slice(&serialize_element(&e.expect("set above")));
        }
        out
    }
}

/// Produce a non-interactive Schnorr proof in challenge-response (short) format
/// (`draft-irtf-cfrg-fiat-shamir-01` §5, reference `NISigmaProtocol.prove`):
/// sample one nonce per scalar variable, commit via the linear map, derive the
/// Fiat-Shamir challenge, and respond `response = nonce + witness * challenge`.
///
/// `witness` must have exactly `statement.num_scalars()` entries, ordered to
/// match the scalar allocation. Returns `serialize(challenge) || serialize(response)`.
pub fn prove<R: RngCore + ?Sized>(
    session: &[u8],
    statement: &LinearRelation,
    witness: &[Scalar],
    rng: &mut R,
) -> Vec<u8> {
    assert_eq!(
        witness.len(),
        statement.num_scalars,
        "witness length must match the number of allocated scalars"
    );
    let nonces: Vec<Scalar> = (0..statement.num_scalars)
        .map(|_| random_scalar(rng))
        .collect();
    let commitment = statement.map(&nonces);

    let mut sponge = init_transcript(session, &statement.label());
    absorb_commitment(&mut sponge, &commitment);
    let challenge = verifier_challenge(&sponge);

    let response: Vec<Scalar> = (0..statement.num_scalars)
        .map(|i| nonces[i] + witness[i] * challenge)
        .collect();

    let mut out = Vec::with_capacity((1 + statement.num_scalars) * group::NS);
    out.extend_from_slice(&group::serialize_scalar(&challenge));
    for r in &response {
        out.extend_from_slice(&group::serialize_scalar(r));
    }
    out
}

/// Verify a non-interactive Schnorr proof in challenge-response (short) format
/// against a statement and session string, per the reference
/// `NISigmaProtocol.verify`.
///
/// The proof is `serialize(challenge) || serialize(response)`: a 32-byte
/// challenge scalar followed by `num_scalars` response scalars. Verification
/// re-derives the commitment via the zero-knowledge simulator, recomputes the
/// Fiat-Shamir challenge from it, and accepts iff it equals the stored
/// challenge. Returns `false` on any malformed input — never panics.
pub fn verify(session: &[u8], statement: &LinearRelation, proof: &[u8]) -> bool {
    let num_scalars = statement.num_scalars;
    let expected_len = group::NS + num_scalars * group::NS;
    if proof.len() != expected_len {
        return false;
    }

    let challenge = match deserialize_scalar(&proof[..group::NS]) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut response = Vec::with_capacity(num_scalars);
    for chunk in proof[group::NS..].chunks(group::NS) {
        match deserialize_scalar(chunk) {
            Ok(s) => response.push(s),
            Err(_) => return false,
        }
    }

    // simulate_commitment(response, challenge): commitment_i = map(response)_i - challenge * image_i
    let image = statement.image();
    let mapped = statement.map(&response);
    let commitment: Vec<ProjectivePoint> = mapped
        .iter()
        .zip(image.iter())
        .map(|(m, img)| *m - *img * challenge)
        .collect();

    // Recompute the challenge from the simulated commitment and compare.
    let mut sponge = init_transcript(session, &statement.label());
    absorb_commitment(&mut sponge, &commitment);
    let expected_challenge = verifier_challenge(&sponge);

    expected_challenge == challenge
}
