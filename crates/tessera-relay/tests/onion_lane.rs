//! Onion-lane end-to-end test with NO real Tor: a SOCKS5 stub stands in for the
//! Tor daemon — it does the no-auth handshake + domain-ATYP CONNECT, then maps
//! the requested `.onion` to the real exit, exactly as a Tor hidden service maps
//! `onion → exit`. Proves the single-hop onion route (`ClientRoute::Onion` /
//! `open_through_onion`) carries the ARC credential + opaque bytes end-to-end with
//! the relay bypassed:
//!
//! ```text
//! browser ─▶ CLIENT-PROXY ─(SOCKS5 = Tor)▶ EXIT ─▶ echo dest
//!                                  (verifies the token against the shared key)
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;

use tessera_arc::keys::ServerPrivateKey;
use tessera_client::obtain_credential;
use tessera_issuer::serve_issuance;
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::{serve_client_proxy_route, ClientRoute, CredentialSource};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const DIFFICULTY: u32 = 8; // low so the PoW is instant
const LIMIT: u64 = 64;

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

/// A SOCKS5 stub standing in for Tor: no-auth handshake + domain-ATYP CONNECT,
/// then — regardless of the requested `.onion` host — forwards to a FIXED
/// `exit_addr`, exactly as a Tor hidden service maps the onion to the exit.
/// Sends the `(host, port)` the client asked it to reach over `asked` so the test
/// can assert the dialer delivered the operator's `.onion:port` UNRESOLVED.
/// Returns its own (proxy) address.
fn spawn_socks5_to_exit(exit_addr: SocketAddr) -> (SocketAddr, mpsc::Receiver<(String, u16)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut c) = stream else { continue };
            let tx = tx.clone();
            thread::spawn(move || {
                // no-auth handshake
                let mut greet = [0u8; 2];
                if c.read_exact(&mut greet).is_err() || greet[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; greet[1] as usize];
                if c.read_exact(&mut methods).is_err() {
                    return;
                }
                if c.write_all(&[0x05, 0x00]).is_err() {
                    return;
                }
                // request: VER, CMD=CONNECT, RSV, ATYP=3(domain)
                let mut head = [0u8; 4];
                if c.read_exact(&mut head).is_err() || head[1] != 0x01 || head[3] != 0x03 {
                    return;
                }
                let mut len = [0u8; 1];
                if c.read_exact(&mut len).is_err() {
                    return;
                }
                let mut host = vec![0u8; len[0] as usize];
                let mut port = [0u8; 2];
                if c.read_exact(&mut host).is_err() || c.read_exact(&mut port).is_err() {
                    return;
                }
                // Report what the client asked us to reach (the framing under test),
                // then — like a Tor HS — map any .onion to the real exit.
                let _ = tx.send((
                    String::from_utf8_lossy(&host).into_owned(),
                    u16::from_be_bytes(port),
                ));
                let exit = match TcpStream::connect(exit_addr) {
                    Ok(u) => u,
                    Err(_) => {
                        let _ = c.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                        return;
                    }
                };
                if c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .is_err()
                {
                    return;
                }
                let _ = c.flush();
                // splice both directions
                let (mut c_rd, mut e_wr) = (c.try_clone().unwrap(), exit.try_clone().unwrap());
                let t = thread::spawn(move || {
                    let _ = std::io::copy(&mut c_rd, &mut e_wr);
                });
                let mut e_rd = exit;
                let _ = std::io::copy(&mut e_rd, &mut c);
                let _ = t.join();
            });
        }
    });
    (proxy_addr, rx)
}

#[test]
fn client_reaches_exit_over_onion_socks() {
    // Issuer + exit share ONE ARC key (keyed-verification).
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let sk_exit = ServerPrivateKey::from_bytes(&sk.serialize()).unwrap();

    // EXIT — credential-gated, egresses Direct to the loopback echo destination.
    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(
        sk_exit,
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
    ));
    serve_exit(exit_listener, guard, Upstream::Direct);

    // ISSUER — PoW-gated authority holding the same key.
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap().to_string();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);

    // "Tor": a SOCKS5 proxy that maps any .onion to the real exit.
    let (socks_addr, asked) = spawn_socks5_to_exit(exit_addr);

    // CLIENT — obtain a credential, run the local proxy on the ONION route.
    let credential = obtain_credential(&issuer_addr, REQUEST_CTX, None).expect("obtain credential");
    let source = CredentialSource::new(
        credential,
        issuer_addr,
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
        None,
        None,
    );
    let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let onion = "testexitaddress0000000000000000000000000000000000000000.onion";
    let route = ClientRoute::Onion {
        socks_addr: socks_addr.to_string(),
        exit_onion: format!("{onion}:443"),
    };
    serve_client_proxy_route(client_listener, route, source);

    // browser → client proxy → (SOCKS5 = Tor) → exit → echo dest
    let dest = spawn_echo();
    let mut s = TcpStream::connect(client_addr).unwrap();
    s.write_all(format!("CONNECT {dest} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut line = String::new();
    BufReader::new(s.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(
        line.contains("200"),
        "the onion tunnel must establish, got: {line}"
    );

    s.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(
        &buf, b"PONG\n",
        "opaque bytes must flow through the onion lane (relay bypassed)"
    );

    // The framing path is asserted, not just executed: the client must have
    // handed the operator's exact `.onion:port` to the SOCKS proxy UNRESOLVED.
    let (got_host, got_port) = asked.recv().unwrap();
    assert_eq!(
        got_host, onion,
        "the exact .onion host must reach the proxy"
    );
    assert_eq!(got_port, 443, "the onion port must reach the proxy");
}
