//! Issuance-over-Tor: `obtain_credential_on` runs the issuance exchange over an
//! already-connected stream, so the client can dial the issuer through a Tor
//! SOCKS proxy (a `.onion` issuer) instead of a direct `TcpStream` — closing the
//! issuance-time IP leak. No real Tor: a SOCKS5 stub stands in (as in the
//! onion-lane test) and forwards to a real `serve_issuance`. The stub reports the
//! `(host, port)` the client asked it to reach, which PROVES the connection went
//! through the dialer (SOCKS) rather than straight to the issuer.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tessera_arc::keys::ServerPrivateKey;
use tessera_client::obtain_credential_on;
use tessera_issuer::serve_issuance;
use tessera_proxy::transport::{Dialer, TorSocksDialer};

const ISSUE_CTX: &[u8] = b"tessera://issue/v1";

/// A SOCKS5 stub (no-auth, domain-ATYP CONNECT) that forwards every connection to
/// a fixed `target` and reports the `(host, port)` the client asked to reach.
fn spawn_socks5_to(target: SocketAddr) -> (SocketAddr, mpsc::Receiver<(String, u16)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut c) = stream else { break };
            let tx = tx.clone();
            thread::spawn(move || {
                // greeting: VER=5, NMETHODS, METHODS…
                let mut greet = [0u8; 2];
                if c.read_exact(&mut greet).is_err() || greet[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; greet[1] as usize];
                if c.read_exact(&mut methods).is_err() || c.write_all(&[0x05, 0x00]).is_err() {
                    return;
                }
                // request: VER, CMD=CONNECT, RSV, ATYP=3 (domain), len, host, port
                let mut head = [0u8; 4];
                if c.read_exact(&mut head).is_err() || head[3] != 0x03 {
                    return;
                }
                let mut len = [0u8; 1];
                let mut port = [0u8; 2];
                if c.read_exact(&mut len).is_err() {
                    return;
                }
                let mut host = vec![0u8; len[0] as usize];
                if c.read_exact(&mut host).is_err() || c.read_exact(&mut port).is_err() {
                    return;
                }
                let _ = tx.send((
                    String::from_utf8_lossy(&host).into_owned(),
                    u16::from_be_bytes(port),
                ));
                let Ok(up) = TcpStream::connect(target) else {
                    let _ = c.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                    return;
                };
                if c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .is_err()
                {
                    return;
                }
                // splice both directions
                let mut c_to_up = c.try_clone().unwrap();
                let mut up_to_c = up.try_clone().unwrap();
                let t = thread::spawn(move || {
                    let _ = std::io::copy(&mut c_to_up, &mut { up });
                });
                let _ = std::io::copy(&mut up_to_c, &mut c);
                let _ = t.join();
            });
        }
    });
    (proxy_addr, rx)
}

fn spawn_issuer() -> SocketAddr {
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    serve_issuance(listener, sk, pk, 1); // difficulty 1: fast PoW for the test
    addr
}

#[test]
fn issuance_runs_over_the_socks_dialer_not_a_direct_connect() {
    let issuer = spawn_issuer();
    let (socks_addr, asked) = spawn_socks5_to(issuer);

    // Dial the issuer's (fake) .onion THROUGH the Tor SOCKS dialer.
    let onion = "issuerfake000000000000000000000000000000000000000000.onion";
    let mut stream = TorSocksDialer::new(socks_addr.to_string())
        .connect(onion, 443)
        .expect("dial issuer onion via SOCKS");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();

    let credential = obtain_credential_on(&mut stream, ISSUE_CTX, None);
    assert!(
        credential.is_ok(),
        "issuance over the SOCKS dialer should succeed: {credential:?}"
    );

    // Proof the path went through the dialer (SOCKS), not a direct TcpStream to
    // the issuer: the stub saw a CONNECT for the .onion host:port we asked for.
    let (host, port) = asked
        .recv_timeout(Duration::from_secs(5))
        .expect("the SOCKS stub must have received a CONNECT");
    assert_eq!(
        host, onion,
        "issuance must be dialed via the .onion over SOCKS"
    );
    assert_eq!(port, 443);
}

#[test]
fn issuer_pk_pin_still_binds_over_the_dialer() {
    let issuer = spawn_issuer();
    let (socks_addr, _asked) = spawn_socks5_to(issuer);

    let mut stream = TorSocksDialer::new(socks_addr.to_string())
        .connect("x.onion", 443)
        .expect("dial via SOCKS");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();

    // A pin the issuer's real pk will (overwhelmingly) not start with -> rejected,
    // proving the pin is enforced even on the Tor-dialed path.
    let wrong_pin = [0xFFu8; 8];
    let err = obtain_credential_on(&mut stream, ISSUE_CTX, Some(&wrong_pin))
        .expect_err("a wrong issuer-pk pin must be rejected over the dialer");
    assert!(
        err.to_string().contains("did not match the pin"),
        "expected a pin-mismatch error, got: {err}"
    );
}
