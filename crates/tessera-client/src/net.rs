//! Obtain a credential from a running [`tessera-issuer`](tessera_issuer) node
//! over the wire: solve the proof of work, run the blinded ARC issuance, and
//! return a finalized [`Credential`]. The client side of the
//! `tessera://issue-net/v1` protocol documented in [`tessera_issuer::net`].

use std::io::{Error, Result};
use std::net::TcpStream;
use std::time::Duration;

use rand_core::OsRng;
use tessera_arc::arc::{Credential, CredentialResponse};
use tessera_arc::keys::ServerPublicKey;
use tessera_issuer::net::{read_frame, write_frame, HELLO_PK_LEN};
use tessera_issuer::{solve, PowChallenge, CHALLENGE_LEN};

use crate::begin_issuance;

/// A client-side ceiling on the PoW difficulty it will attempt. `solve` is an
/// unbounded local brute force (~`2^difficulty` hashes), so a hostile/misconfigured
/// issuer advertising e.g. `64` could hang the caller forever — refuse anything
/// implausible. `28` ≈ a few hundred million hashes (seconds), well above any
/// sane gate.
const MAX_ACCEPTABLE_DIFFICULTY: u32 = 28;

/// Minimum length of a pk pin. A prefix pin shorter than this gives negligible
/// protection (a substituted key satisfies a 1-byte pin ~1/256 of the time), so
/// reject it rather than provide false assurance. `8` bytes = the issuer's
/// printed fingerprint (64-bit); a full `99`-byte pin is strongest.
const MIN_PIN_LEN: usize = 8;

/// Connect to the issuer at `issuer_addr`, pay the proof of work, and obtain a
/// finalized credential bound to `request_context`.
///
/// If `expected_pk_prefix` is `Some`, the issuer's advertised public key must
/// start with those bytes (a pin against a substituted/MITM issuer — e.g. the
/// fingerprint the issuer prints); a pin shorter than 8 bytes is rejected.
///
/// **ARC issuance is *cryptographically* unlinkable** — the issuer cannot tie the
/// returned credential to its later presentations. It is **not** anonymous at the
/// transport layer: this opens a **direct connection to `issuer_addr`, so the
/// issuer sees the caller's source IP and the time of issuance**. To hide that
/// too, wrap this call in an anonymity transport (e.g. obtain the credential over
/// Tor). ARC is keyed-verification, so the credential only verifies at an exit
/// holding the **same** key as this issuer.
pub fn obtain_credential(
    issuer_addr: &str,
    request_context: &[u8],
    expected_pk_prefix: Option<&[u8]>,
) -> Result<Credential> {
    if let Some(prefix) = expected_pk_prefix {
        if prefix.len() < MIN_PIN_LEN {
            return Err(Error::other(
                "issuer pk pin too short (need >= 8 bytes / 16 hex chars)",
            ));
        }
    }
    let mut s = TcpStream::connect(issuer_addr)?;
    // The issuer does real arithmetic; allow generous slack but never block forever.
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;

    // 1. HELLO: pk(99) ‖ difficulty(4) ‖ nonce(16).
    let hello = read_frame(&mut s)?;
    if hello.len() != HELLO_PK_LEN + 4 + CHALLENGE_LEN {
        return Err(Error::other("issuer sent a malformed HELLO"));
    }
    let pk_bytes = &hello[..HELLO_PK_LEN];
    if let Some(prefix) = expected_pk_prefix {
        if !pk_bytes.starts_with(prefix) {
            return Err(Error::other("issuer public key did not match the pin"));
        }
    }
    let public_key =
        ServerPublicKey::from_bytes(pk_bytes).map_err(|_| Error::other("bad issuer public key"))?;
    let difficulty = u32::from_be_bytes(hello[HELLO_PK_LEN..HELLO_PK_LEN + 4].try_into().unwrap());
    if difficulty > MAX_ACCEPTABLE_DIFFICULTY {
        return Err(Error::other(
            "issuer demanded an implausible proof-of-work difficulty",
        ));
    }
    let mut nonce = [0u8; CHALLENGE_LEN];
    nonce.copy_from_slice(&hello[HELLO_PK_LEN + 4..]);

    // 2. Pay the proof of work (bounded by the difficulty ceiling above).
    let solution = solve(&PowChallenge { nonce, difficulty });

    // 3. REQUEST: counter(8) ‖ CredentialRequest.
    let mut rng = OsRng;
    let (pending, request) = begin_issuance(request_context, public_key, &mut rng);
    let req_bytes = request.to_bytes();
    let mut frame = Vec::with_capacity(8 + req_bytes.len());
    frame.extend_from_slice(&solution.counter.to_be_bytes());
    frame.extend_from_slice(&req_bytes);
    write_frame(&mut s, &frame)?;

    // 4. RESPONSE: the signed CredentialResponse (empty frame = rejected).
    let resp = read_frame(&mut s)?;
    if resp.is_empty() {
        return Err(Error::other(
            "issuer rejected the request (proof-of-work or arithmetic)",
        ));
    }
    let response = CredentialResponse::from_bytes(&resp)
        .map_err(|_| Error::other("malformed CredentialResponse"))?;
    pending
        .finalize(&response)
        .map_err(|e| Error::other(format!("credential finalize failed: {e:?}")))
}
