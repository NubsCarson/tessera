//! Networked issuance: serve ARC credentials over TCP behind the proof-of-work
//! gate, so a client can *obtain* a credential from a running authority instead
//! of having one minted in-process.
//!
//! ## The wire protocol (`tessera://issue-net/v1`)
//!
//! All frames are length-prefixed: a 4-byte big-endian length, then that many
//! bytes (capped at [`MAX_FRAME`]). One credential per connection:
//!
//! 1. **Server → client `HELLO`**: `pk(99) ‖ difficulty(4, be) ‖ nonce(16)` —
//!    the issuer's [`ServerPublicKey`] (SEC1, `3·Ne`), the PoW difficulty, and a
//!    fresh challenge nonce. The client pins/uses the `pk` to build its request.
//! 2. *(client solves the PoW: finds a counter whose hash over `nonce` clears
//!    `difficulty`, paying ~`2^difficulty` hashes.)*
//! 3. **Client → server `REQUEST`**: `counter(8, be) ‖ CredentialRequest` — the
//!    PoW solution then the blinded ARC request ([`CredentialRequest::to_bytes`]).
//! 4. **Server → client `RESPONSE`**: `CredentialResponse` on success, or an
//!    **empty frame** on rejection (bad PoW / malformed / arithmetic failure).
//!
//! The PoW challenge is held per-connection (a fresh nonce each accept), so a
//! solution cannot be replayed onto another connection. Issuance is
//! *cryptographically* unlinkable — the issuer cannot tie the credential it signs
//! to any later presentation. It is **not** anonymous at the transport layer: the
//! client connects directly here, so the issuer **does** see the client's source
//! IP and the time of issuance. A client wanting anonymity must reach the issuer
//! over an anonymity transport (e.g. Tor); the unlinkability then holds *between*
//! issuance and browsing, but the act of issuance is not hidden by this protocol.

use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, CredentialRequest};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

use crate::{PowChallenge, PowSolution, CHALLENGE_LEN};

/// Largest accepted frame body. The real messages are tiny (`CredentialRequest`
/// is 226 B, `CredentialResponse` 454 B); the cap just bounds a hostile peer.
pub const MAX_FRAME: usize = 64 * 1024;

/// Serialized [`ServerPublicKey`] length in the `HELLO` frame (`3·Ne`, SEC1).
pub const HELLO_PK_LEN: usize = 99;

/// Read/write timeout on an issuance socket, so a slow-roll peer cannot pin a
/// handler thread + fd forever.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on concurrent issuance handlers (a flood backstop).
const MAX_INFLIGHT: usize = 256;

/// Write one length-prefixed frame: `len(4, be) ‖ body`.
pub fn write_frame(s: &mut TcpStream, body: &[u8]) -> Result<()> {
    s.write_all(&(body.len() as u32).to_be_bytes())?;
    s.write_all(body)?;
    s.flush()
}

/// Read one length-prefixed frame, rejecting a length over [`MAX_FRAME`].
pub fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok(body)
}

/// RAII permit for the [`MAX_INFLIGHT`] cap.
struct InflightGuard(Arc<AtomicUsize>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve PoW-gated ARC issuance on `listener` using the authority key
/// `(sk, pk)`, requiring `difficulty` leading zero bits of proof of work per
/// credential. Spawns an accept loop and returns its [`JoinHandle`]; each
/// connection is handled on its own thread (bounded by a fixed in-flight cap).
///
/// `pk` MUST be the same key the verifying exit holds — ARC is
/// keyed-verification, so the credential only verifies against this issuer's
/// key (see `docs/DEPLOY.md`).
pub fn serve_issuance(
    listener: TcpListener,
    sk: ServerPrivateKey,
    pk: ServerPublicKey,
    difficulty: u32,
) -> JoinHandle<()> {
    let sk = Arc::new(sk);
    let inflight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(IO_TIMEOUT));
            let _ = s.set_write_timeout(Some(IO_TIMEOUT));
            if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
                inflight.fetch_sub(1, Ordering::AcqRel);
                // Drop without a HELLO: an over-capacity issuer just closes.
                continue;
            }
            let permit = InflightGuard(Arc::clone(&inflight));
            let sk = Arc::clone(&sk);
            thread::spawn(move || {
                let _permit = permit;
                let _ = handle_issuance(&mut s, &sk, &pk, difficulty);
            });
        }
    })
}

/// One issuance exchange (see the module protocol). Returns `Err` on any
/// protocol/PoW/arithmetic failure (after signalling the client with an empty
/// `RESPONSE` frame where the connection is still usable).
fn handle_issuance(
    s: &mut TcpStream,
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    difficulty: u32,
) -> Result<()> {
    let mut rng = OsRng;

    // 1. HELLO — pk ‖ difficulty ‖ nonce (fresh challenge for THIS connection).
    let challenge = PowChallenge::new(&mut rng, difficulty);
    let pk_bytes = pk.serialize();
    debug_assert_eq!(pk_bytes.len(), HELLO_PK_LEN);
    let mut hello = Vec::with_capacity(HELLO_PK_LEN + 4 + CHALLENGE_LEN);
    hello.extend_from_slice(&pk_bytes);
    hello.extend_from_slice(&challenge.difficulty.to_be_bytes());
    hello.extend_from_slice(&challenge.nonce);
    write_frame(s, &hello)?;

    // 3. REQUEST — counter ‖ CredentialRequest.
    let req = read_frame(s)?;
    if req.len() < 8 {
        let _ = write_frame(s, &[]);
        return Err(Error::new(ErrorKind::InvalidData, "REQUEST too short"));
    }
    let counter = u64::from_be_bytes(req[..8].try_into().unwrap());
    if !challenge.verify(&PowSolution { counter }) {
        let _ = write_frame(s, &[]); // reject: PoW not met
        return Err(Error::new(ErrorKind::InvalidData, "proof-of-work invalid"));
    }
    let request = match CredentialRequest::from_bytes(&req[8..]) {
        Ok(r) => r,
        Err(_) => {
            let _ = write_frame(s, &[]);
            return Err(Error::new(
                ErrorKind::InvalidData,
                "malformed CredentialRequest",
            ));
        }
    };

    // 4. RESPONSE — the signed CredentialResponse, or empty on arithmetic reject.
    match create_credential_response(sk, pk, &request, &mut rng) {
        Ok(resp) => write_frame(s, &resp.to_bytes()),
        Err(_) => {
            let _ = write_frame(s, &[]);
            Err(Error::new(ErrorKind::InvalidData, "request proof rejected"))
        }
    }
}
