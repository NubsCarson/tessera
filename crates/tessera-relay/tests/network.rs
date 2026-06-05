//! End-to-end **network** test: a real over-the-wire issuance + the local client
//! proxy, all four nodes in-process. Proves the "run it yourself" path:
//!
//! ```text
//! client-proxy ──┐                          obtains a credential from
//!  (CONNECT)      │  open_through_relay      ┌───────────────┐
//! browser ──▶ CLIENT-PROXY ──▶ RELAY ──▶ EXIT ──▶ echo dest   ISSUER (PoW-gated)
//!                                   (verifies the token against the SHARED key)
//! ```
//!
//! The issuer and exit share ONE ARC key (keyed-verification); the client pays
//! the PoW, gets a credential over the wire, and its presentations verify at the
//! exit. No external network, no TLS — the destination is a local echo server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use tessera_arc::keys::ServerPrivateKey;
use tessera_client::obtain_credential;
use tessera_issuer::serve_issuance;
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::{serve as serve_relay, serve_client_proxy, CredentialSource};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const DIFFICULTY: u32 = 8; // low so the test's PoW is instant

/// One-shot echo destination: replies `PONG\n` to a `PING\n`.
fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut line = String::new();
                let mut r = BufReader::new(s.try_clone().unwrap());
                if r.read_line(&mut line).is_ok() {
                    let _ = s.write_all(b"PONG\n");
                    let _ = s.flush();
                }
            });
        }
    });
    addr
}

/// Stand up issuer + relay + exit + local client proxy sharing one ARC key, with
/// the given per-credential `limit`. Returns the local client-proxy address.
fn spawn_network(limit: u64) -> SocketAddr {
    // ONE key shared by the issuer (authority) and the exit (verifier).
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let sk_exit = ServerPrivateKey::from_bytes(&sk.serialize()).unwrap();

    // EXIT — credential-gated, egresses Direct to the echo dest.
    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(
        sk_exit,
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        limit,
    ));
    serve_exit(exit_listener, guard, Upstream::Direct);

    // RELAY — credential-blind first hop, forwards to the exit.
    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    serve_relay(relay_listener, exit_addr, None);

    // ISSUER — PoW-gated authority holding the same key.
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);
    let issuer_str = issuer_addr.to_string();

    // CLIENT — obtain a credential over the wire, run the local proxy.
    let credential = obtain_credential(&issuer_str, REQUEST_CTX, None)
        .expect("obtain a credential from the issuer");
    let source = CredentialSource::new(
        credential,
        issuer_str,
        REQUEST_CTX,
        PRESENT_CTX,
        limit,
        None,
    );
    let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    serve_client_proxy(client_listener, relay_addr, exit_addr, source);

    client_addr
}

/// Drive one request through the client proxy to `dest`; returns true iff the
/// tunnel established (`200`) and the echo round-tripped (`PONG`).
fn request_through(proxy: SocketAddr, dest: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect(proxy) else {
        return false;
    };
    if s.write_all(format!("CONNECT {dest} HTTP/1.1\r\n\r\n").as_bytes())
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    if BufReader::new(s.try_clone().unwrap())
        .read_line(&mut line)
        .is_err()
    {
        return false;
    }
    if !line.contains("200") {
        return false;
    }
    if s.write_all(b"PING\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).is_ok() && &buf == b"PONG\n"
}

#[test]
fn full_network_loop_credential_over_the_wire() {
    let echo = spawn_echo();
    let proxy = spawn_network(64);
    assert!(
        request_through(proxy, echo),
        "a request through the client proxy (token obtained over the wire) must reach the dest"
    );
}

#[test]
fn client_proxy_reissues_when_budget_spent() {
    let echo = spawn_echo();
    // limit = 2: the 3rd request forces a transparent re-issue from the issuer.
    let proxy = spawn_network(2);
    for i in 0..5 {
        assert!(
            request_through(proxy, echo),
            "request {i} must succeed (auto re-issue past the per-credential budget)"
        );
    }
}

#[test]
fn issuer_pk_pin_mismatch_is_rejected() {
    // Stand up just an issuer; obtaining with a wrong pin must fail closed.
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap().to_string();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);

    // The real fingerprint would match; a deliberately wrong prefix must not.
    let wrong_pin = [0xAAu8; 8];
    let err = obtain_credential(&issuer_addr, REQUEST_CTX, Some(&wrong_pin));
    assert!(err.is_err(), "a mismatched issuer-pk pin must be rejected");

    // And the correct pin (the issuer's real pk prefix) must succeed.
    let good_prefix = pk.serialize()[..8].to_vec();
    let ok = obtain_credential(&issuer_addr, REQUEST_CTX, Some(&good_prefix));
    assert!(ok.is_ok(), "the correct issuer-pk pin must be accepted");
}
