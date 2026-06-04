//! Canonical wire serialization for the ARC protocol structs
//! (`draft-ietf-privacypass-arc-crypto-01` §4), so credentials and
//! presentations can be carried over a transport (e.g. an HTTP header).
//!
//! All elements are SEC1-compressed (`Ne = 33`) and scalars are 32-byte
//! big-endian (`Ns = 32`); the field orders match the spec's struct layouts,
//! and the encoded lengths are asserted against the spec constants in tests.

use crate::arc::{CredentialRequest, CredentialResponse, Presentation};
use crate::group::{deserialize_element, serialize_element, DeserializeError, NE, NS};
use crate::keys::ServerPublicKey;
use crate::proofs::compute_bases;
use p256::ProjectivePoint;

/// A cursor over a byte buffer that yields fixed-size elements and raw chunks.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn element(&mut self) -> Result<ProjectivePoint, DeserializeError> {
        let end = self.pos + NE;
        if end > self.buf.len() {
            return Err(DeserializeError::Element);
        }
        let e = deserialize_element(&self.buf[self.pos..end])?;
        self.pos = end;
        Ok(e)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DeserializeError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(DeserializeError::Scalar);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn finish(self) -> Result<(), DeserializeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DeserializeError::Element)
        }
    }
}

impl ServerPublicKey {
    /// Deserialize a public key from `3*Ne` bytes (`X0 ‖ X1 ‖ X2`).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        let mut r = Reader::new(buf);
        let x0 = r.element()?;
        let x1 = r.element()?;
        let x2 = r.element()?;
        r.finish()?;
        Ok(ServerPublicKey { x0, x1, x2 })
    }
}

impl CredentialRequest {
    /// `Nrequest = 2*Ne + 5*Ns` bytes: `m1Enc ‖ m2Enc ‖ proof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * NE + self.proof.len());
        out.extend_from_slice(&serialize_element(&self.m1_enc));
        out.extend_from_slice(&serialize_element(&self.m2_enc));
        out.extend_from_slice(&self.proof);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        let mut r = Reader::new(buf);
        let m1_enc = r.element()?;
        let m2_enc = r.element()?;
        let proof = r.take(5 * NS)?.to_vec(); // challenge + 4 responses
        r.finish()?;
        Ok(CredentialRequest {
            m1_enc,
            m2_enc,
            proof,
        })
    }
}

impl CredentialResponse {
    /// `Nresponse = 6*Ne + 8*Ns` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 * NE + self.proof.len());
        for e in [
            &self.u,
            &self.enc_u_prime,
            &self.x0_aux,
            &self.x1_aux,
            &self.x2_aux,
            &self.h_aux,
        ] {
            out.extend_from_slice(&serialize_element(e));
        }
        out.extend_from_slice(&self.proof);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        let mut r = Reader::new(buf);
        let u = r.element()?;
        let enc_u_prime = r.element()?;
        let x0_aux = r.element()?;
        let x1_aux = r.element()?;
        let x2_aux = r.element()?;
        let h_aux = r.element()?;
        let proof = r.take(8 * NS)?.to_vec(); // challenge + 7 responses
        r.finish()?;
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
}

impl Presentation {
    /// Serialize a presentation: the five elements, then the `k` range-proof
    /// commitments `D`, then `challenge ‖ responses`. Length is
    /// `5*Ne + k*Ne + (6 + 3k)*Ns` where `k = len(ComputeBases(limit))`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for e in [
            &self.u,
            &self.u_prime_commit,
            &self.m1_commit,
            &self.tag,
            &self.nonce_commit,
        ] {
            out.extend_from_slice(&serialize_element(e));
        }
        for d in &self.d {
            out.extend_from_slice(&serialize_element(d));
        }
        out.extend_from_slice(&self.proof);
        out
    }

    /// Deserialize a presentation. The `limit` is required (and agreed
    /// out-of-band) to know how many `D` commitments and response scalars to
    /// expect — `k = len(ComputeBases(limit))`.
    pub fn from_bytes(buf: &[u8], limit: u64) -> Result<Self, DeserializeError> {
        let k = compute_bases(limit).len();
        let mut r = Reader::new(buf);
        let u = r.element()?;
        let u_prime_commit = r.element()?;
        let m1_commit = r.element()?;
        let tag = r.element()?;
        let nonce_commit = r.element()?;
        let mut d = Vec::with_capacity(k);
        for _ in 0..k {
            d.push(r.element()?);
        }
        // proof = challenge (1 scalar) + responses (5 + 3k scalars)
        let proof = r.take((6 + 3 * k) * NS)?.to_vec();
        r.finish()?;
        Ok(Presentation {
            u,
            u_prime_commit,
            m1_commit,
            tag,
            nonce_commit,
            d,
            proof,
        })
    }
}
