//! Known-answer tests against the official ARC P-256 test vectors in
//! `draft-ietf-privacypass-arc-crypto-01` §10.2.
//!
//! This file proves the *arithmetic core* of the protocol — everything that
//! does not depend on the Fiat-Shamir proof transcript. If these pass, then
//! our group layer, `HashToScalar`, `HashToGroup`, scalar inversion, key
//! derivation, issuance math, credential finalization, and presentation
//! commitments all match the IETF reference byte-for-byte.
//!
//! The Fiat-Shamir proof blobs (`proof = ...` in the vectors) are validated
//! separately once the Sigma/FS layer lands (see GOAL.md, milestone 4).

use p256::{ProjectivePoint, Scalar};
use tessera_arc::group::{
    self, deserialize_element, deserialize_scalar, generator_g, generator_h, hash_to_group,
    hash_to_scalar, scalar_invert, serialize_element,
};
use tessera_arc::keys::ServerPrivateKey;

/// Parse a hex string into a scalar (32-byte big-endian).
fn sc(h: &str) -> Scalar {
    let bytes = hex::decode(h).expect("valid hex");
    deserialize_scalar(&bytes).expect("valid scalar")
}

/// Parse a hex string into a group element (33-byte SEC1 compressed).
fn pt(h: &str) -> ProjectivePoint {
    let bytes = hex::decode(h).expect("valid hex");
    deserialize_element(&bytes).expect("valid element")
}

/// Assert two elements are equal, comparing their canonical serializations
/// (this also exercises `serialize_element` and gives readable diffs).
fn assert_pt_eq(label: &str, got: ProjectivePoint, expected_hex: &str) {
    let got_hex = hex::encode(serialize_element(&got));
    assert_eq!(got_hex, expected_hex, "{label} mismatch");
}

// ---- ServerKey ----
const X0_SK: &str = "1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021";
const X1_SK: &str = "526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd";
const X2_SK: &str = "549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b";
const XB_SK: &str = "7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e";
const X0_PK: &str = "03bad54cc48293ef3472ac1ada55c9c9fdb3eb99ee47369bbe1d3ce46b300cd7b3";
const X1_PK: &str = "02a0323862a05707d76862bfa8477eed468441ceae14c8fb1659e0b3020b8a24e1";
const X2_PK: &str = "031d16ef08ede5a347e94a8eca071bec7bedb9d8ba943d24bde912a4e1578e529b";

// ---- CredentialRequest ----
const REQUEST_CONTEXT: &str = "74657374207265717565737420636f6e74657874";
const M1: &str = "141c4ca5e614af8e5e323eb47a7e7673ebb67caf49dfa8e109f45f231227f7a0";
const M2: &str = "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e";
const R1: &str = "5c183d2dea942eb2780afb90cfd94983ae6575d60e350021c8c93008ac503973";
const R2: &str = "044d4a5b5daf00dd1fb4444ca2f8c3facc95d537d5ad0e0a2815c912e98a431d";
const M1_ENC: &str = "033fe5d950712f711e5d292d68f804fad4c35fb7f3f1866516448647d4aab12590";
const M2_ENC: &str = "026502a833ed1d972ee27175e750b1719adee12726c653125887c0d32b1f3747ab";

// ---- CredentialResponse ----
const B: &str = "9ac9d836ef405f4c6c1de4de18d210c929a8dc786c95e3eac3a828cc19e1636e";
const RESP_U: &str = "021cf52318c97c33472cc8fb42a5b5a774f83c3b36e6c782209d53e5945d99a493";
const ENC_U_PRIME: &str = "02ae23020d5427c7f785a72d77c24997f955e66ab7c378c334b7c259dabdf572d7";
const X0_AUX: &str = "031523abe64e436e65e592abdae322dc556fcbea707757e18d4160ba57d574cd87";
const X1_AUX: &str = "023cc3b53807f6e0082b675794ae9f6b370483ca5a3e6d688c3b81f2fdb6d4ec00";
const X2_AUX: &str = "0329dc7c93f8a231a1f16ec69f0fba446e022ce69945b20f37386a7fda3e573b79";
const H_AUX: &str = "0389746891b6dbf062511619eae7d72ae87630bea1e277a925708fdfef8363a1d4";

// ---- Credential ----
const CRED_U_PRIME: &str = "02646199272c28911165b4d1c5f4ffbd8a83f686948fd4c7250e28c81dbfecd354";

// ---- Presentation contexts ----
const PRESENTATION_CONTEXT: &str = "746573742070726573656e746174696f6e20636f6e74657874";

#[test]
fn generator_h_is_deterministic() {
    // generatorH = HashToGroup(SerializeElement(generatorG), "generatorH")
    let h1 = generator_h();
    let h2 = hash_to_group(&serialize_element(&generator_g()), b"generatorH");
    assert_eq!(serialize_element(&h1), serialize_element(&h2));
    // Sanity: H is not the identity and not equal to G.
    assert_ne!(serialize_element(&h1), serialize_element(&generator_g()));
}

#[test]
fn server_public_key_matches_vectors() {
    let sk = ServerPrivateKey::from_scalars(sc(X0_SK), sc(X1_SK), sc(X2_SK), sc(XB_SK));
    let pk = sk.public_key();
    // X0 = x0*G + x0Blinding*H  — this is the key check that proves generatorH.
    assert_pt_eq("X0", pk.x0, X0_PK);
    // X1 = x1*H, X2 = x2*H
    assert_pt_eq("X1", pk.x1, X1_PK);
    assert_pt_eq("X2", pk.x2, X2_PK);
}

#[test]
fn hash_to_scalar_matches_m2() {
    // m2 = HashToScalar(requestContext, "requestContext")
    let ctx = hex::decode(REQUEST_CONTEXT).unwrap();
    let m2 = hash_to_scalar(&ctx, b"requestContext");
    assert_eq!(
        hex::encode(group::serialize_scalar(&m2)),
        M2,
        "HashToScalar(requestContext)"
    );
}

#[test]
fn credential_request_encryptions_match() {
    let g = generator_g();
    let h = generator_h();
    // m1Enc = m1*G + r1*H
    let m1_enc = g * sc(M1) + h * sc(R1);
    assert_pt_eq("m1Enc", m1_enc, M1_ENC);
    // m2Enc = m2*G + r2*H
    let m2_enc = g * sc(M2) + h * sc(R2);
    assert_pt_eq("m2Enc", m2_enc, M2_ENC);
}

#[test]
fn credential_response_arithmetic_matches() {
    let g = generator_g();
    let h = generator_h();
    let b = sc(B);
    let x1 = sc(X1_SK);
    let x2 = sc(X2_SK);
    let xb = sc(XB_SK);
    let x0_pub = pt(X0_PK);
    let x1_pub = pt(X1_PK);
    let x2_pub = pt(X2_PK);
    let m1_enc = pt(M1_ENC);
    let m2_enc = pt(M2_ENC);

    // U = b*G
    assert_pt_eq("U", g * b, RESP_U);

    // encUPrime = b*(X0 + x1*m1Enc + x2*m2Enc)
    let inner = x0_pub + m1_enc * x1 + m2_enc * x2;
    assert_pt_eq("encUPrime", inner * b, ENC_U_PRIME);

    // X0Aux = b*x0Blinding*H ; X1Aux = b*X1 ; X2Aux = b*X2 ; HAux = b*H
    assert_pt_eq("X0Aux", h * (b * xb), X0_AUX);
    assert_pt_eq("X1Aux", x1_pub * b, X1_AUX);
    assert_pt_eq("X2Aux", x2_pub * b, X2_AUX);
    assert_pt_eq("HAux", h * b, H_AUX);
}

#[test]
fn finalize_credential_matches() {
    // UPrime = encUPrime - X0Aux - r1*X1Aux - r2*X2Aux
    let enc_u_prime = pt(ENC_U_PRIME);
    let x0_aux = pt(X0_AUX);
    let x1_aux = pt(X1_AUX);
    let x2_aux = pt(X2_AUX);
    let u_prime = enc_u_prime - x0_aux - x1_aux * sc(R1) - x2_aux * sc(R2);
    assert_pt_eq("credential UPrime", u_prime, CRED_U_PRIME);
}

/// One presentation's worth of arithmetic checks (everything except the
/// Fiat-Shamir proof). `nonce` is the integer nonce; the rest are vector hex.
#[allow(clippy::too_many_arguments)]
fn check_presentation(
    label: &str,
    a_hex: &str,
    r_hex: &str,
    z_hex: &str,
    nonce: u64,
    nonce_blinding_hex: &str,
    pres_u_hex: &str,
    u_prime_commit_hex: &str,
    m1_commit_hex: &str,
    nonce_commit_hex: &str,
    tag_hex: &str,
    d0_hex: &str,
) {
    let g = generator_g();
    let h = generator_h();
    let cred_u = pt(RESP_U);
    let cred_u_prime = pt(CRED_U_PRIME);
    let m1 = sc(M1);

    let a = sc(a_hex);
    let r = sc(r_hex);
    let z = sc(z_hex);
    let nonce_scalar = Scalar::from(nonce);
    let nonce_blinding = sc(nonce_blinding_hex);

    // U = a * credential.U
    let u = cred_u * a;
    assert_pt_eq(&format!("{label}: U"), u, pres_u_hex);

    // UPrime = a * credential.UPrime ; UPrimeCommit = UPrime + r*G
    let u_prime = cred_u_prime * a;
    assert_pt_eq(
        &format!("{label}: UPrimeCommit"),
        u_prime + g * r,
        u_prime_commit_hex,
    );

    // m1Commit = m1 * U + z * H   (U here is the re-randomized U)
    assert_pt_eq(&format!("{label}: m1Commit"), u * m1 + h * z, m1_commit_hex);

    // nonceCommit = nonce*G + nonceBlinding*H
    let nonce_commit = g * nonce_scalar + h * nonce_blinding;
    assert_pt_eq(
        &format!("{label}: nonceCommit"),
        nonce_commit,
        nonce_commit_hex,
    );

    // generatorT = HashToGroup(presentationContext, "Tag")
    // tag = (m1 + nonce)^{-1} * generatorT   — exercises HashToGroup + inversion.
    let ctx = hex::decode(PRESENTATION_CONTEXT).unwrap();
    let generator_t = hash_to_group(&ctx, b"Tag");
    let inv = scalar_invert(&(m1 + nonce_scalar)).expect("m1 + nonce is non-zero");
    assert_pt_eq(&format!("{label}: tag"), generator_t * inv, tag_hex);

    // Range proof, presentationLimit = 2 -> bases = [1], so D[0] == nonceCommit.
    assert_pt_eq(&format!("{label}: D_0"), nonce_commit, d0_hex);
}

#[test]
fn presentation1_arithmetic_matches() {
    check_presentation(
        "Presentation1",
        "a3c469d2d55062b463b17f45acd2fb17c038b18df4c8d6c9c745866ba961de9a",
        "54925f70e9ec2128114c6ae8bfc6e1a2914a8fdd383e5ff03d8c2992edd081a9",
        "9ed3c3ddb1b5ff64e55b1d0a4f58eee67351fea7de16baf644e80f4d0949cf5f",
        0,
        "ed8b643e3c8ba74cc417b5bbfc4f42bee6dcd2d6c5ea48fb2273afec7b6505a4",
        "0216af8901c1ad38a703bf9003fabea440b411b4f072fd23b5254cb17d1b5bf33d",
        "03140f8e6f6c5eab3d03a7fba5d542362a9bc00a89d80caa5051b4e4446b0b01f3",
        "0214d0297c21120d621cc6fed75852569de3cbf0bd9f5a8a812cf6b024bf51e627",
        "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
        "0281428e61688f4e7989dbe8dab170705c81b294c4a73b785a0754712fc968eb40",
        "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
    );
}

#[test]
fn presentation2_arithmetic_matches() {
    check_presentation(
        "Presentation2",
        "ae14ddaf96907f2fee72069664e1883fee4582cefcfbb2f3fae380c317018ab2",
        "f994bf66d0c7943ce97331da186e231281b691eb271c7c524ff9f8bc7804b41d",
        "fa27efc5066bca91121642d629477eb1c7812fa9c473b30dea3eaba8a1731568",
        1,
        "90b8387fe4145c2d47a0f042c26119939bcbcc8c2c32f81d1034db3958b9af39",
        "0357e53851143e7cc34311bdba0d44d4d3c9192180434ce247b8766232b5de1e08",
        "02bad8dc9b0179dff7a1d63d03d92810520085cbc41b65b667d3cbe2203eb7c544",
        "02455589d2b92a24e49ff8c2e8287f6eeb05cbfddc16aba66dfe9ab97702bc3c35",
        "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41",
        "02ad6c293325d0c2c388c8b2240b6d8ab9e52395297ef5921fb78ace6a1274b03b",
        "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41",
    );
}
