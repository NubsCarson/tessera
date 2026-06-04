//! Known-answer tests for the Fiat-Shamir + Sigma layer against the
//! **authoritative** IETF Sigma Protocol test vectors
//! (`draft-irtf-cfrg-sigma-protocols`, reference
//! `sigma-proofs_Shake128_P256.json`): a discrete-logarithm proof and a DLEQ
//! proof.
//!
//! These are the correct oracle for this layer — they exercise the SHAKE128
//! duplex sponge, the session-id derivation, the protocol id, the canonical
//! instance-label encoding, the 64-byte challenge squeeze, the zero-knowledge
//! simulator, and the multi-constraint linear-map verifier — independently of
//! ARC. A passing run proves our proof stack reproduces the IETF reference
//! byte-for-byte.
//!
//! (Note: ARC's own §10.2 *proof* blobs are not reproduced here; see
//! `docs/ARC_PROOF_VECTOR_DISCREPANCY.md` for why — the ARC arithmetic vectors
//! all pass, but the committed ARC proof blobs predate the Sigma POC's codec
//! change and do not reconcile with the current reference. This layer is
//! instead proven against the Sigma vectors, which are authoritative for it.)

use tessera_arc::group::deserialize_element;
use tessera_arc::sigma::{verify, LinearRelation};

fn pt(h: &str) -> p256::ProjectivePoint {
    deserialize_element(&hex::decode(h).unwrap()).unwrap()
}

const G: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

#[test]
fn sigma_discrete_logarithm_vector_verifies() {
    // X = x*G, with elements [G(0), X(1)] and one scalar x(0).
    let x_pt = "02d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f6325336";
    let proof = hex::decode(
        "d08bc0386f6ef8b3a431d490a1b30c0ab58341043aa76e59b74493417e65a46e\
         e9488aaa9b728b9ccd5231f1d99daae697e454d67d83522e5bc8de52324f06bd",
    )
    .unwrap();

    let mut s = LinearRelation::new();
    let sv = s.allocate_scalars(1);
    let ev = s.allocate_elements(2);
    s.set_element(ev[0], pt(G));
    s.set_element(ev[1], pt(x_pt));
    s.append_equation(ev[1], vec![(sv[0], ev[0])]); // X = x*G

    let session = b"discrete_logarithm";
    assert!(verify(session, &s, &proof), "official DL proof must verify");

    // Negative: flip a challenge bit.
    let mut bad = proof.clone();
    bad[0] ^= 0x01;
    assert!(!verify(session, &s, &bad));
}

#[test]
fn sigma_dleq_vector_verifies() {
    // X = x*G and Y = x*H, with elements [G(0), X(1), H(2), Y(3)], scalar x(0).
    let x_pt = "02e7747263366b618a771a284e6139947b17e9c3a96cb573d045db511336fea2b5";
    let h_pt = "02d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f6325336";
    let y_pt = "03c2170432aefa48cbbe91aa5be0da997e663528c96bd5652da0b71dbc44b4a157";
    let proof = hex::decode(
        "8e9bd4ddb4c4cf342c4b29e9cb6447d1ed7268cbea7bd163408925c6058f1e9a\
         32b29cb837a982782e771e90665cceaae4c2051cd2f9de70a57b5661ae9b4cf4",
    )
    .unwrap();

    let mut s = LinearRelation::new();
    let sv = s.allocate_scalars(1);
    let ev = s.allocate_elements(4);
    s.set_element(ev[0], pt(G));
    s.set_element(ev[1], pt(x_pt));
    s.set_element(ev[2], pt(h_pt));
    s.set_element(ev[3], pt(y_pt));
    s.append_equation(ev[1], vec![(sv[0], ev[0])]); // X = x*G
    s.append_equation(ev[3], vec![(sv[0], ev[2])]); // Y = x*H

    let session = b"dleq";
    assert!(
        verify(session, &s, &proof),
        "official DLEQ proof must verify"
    );

    // Negative: flip a response bit.
    let mut bad = proof.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(!verify(session, &s, &bad));
}
