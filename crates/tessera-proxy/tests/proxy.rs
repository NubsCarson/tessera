//! Deterministic end-to-end test: a credential tunnels through the proxy to a
//! mock upstream and bytes flow; no credential is refused with 407. No TLS / Tor
//! / external network needed — the upstream is a local echo server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve, Upstream};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 8;

/// A one-shot upstream that, after the tunnel is established, replies `PONG\n`
/// to a `PING\n`.
fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
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
    port
}

/// Stand up a proxy with a fresh keypair; return (proxy_port, a client that can
/// mint presentations against it).
fn spawn_proxy() -> (u16, TesseraClient) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let client = TesseraClient::new(credential, CTX, LIMIT);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let guard = Arc::new(OriginGuard::new(sk, pk, REQ, CTX, LIMIT));
    serve(listener, guard, Upstream::Direct);
    (port, client)
}

/// Read the proxy's HTTP status line.
fn read_status(stream: &mut TcpStream) -> String {
    let mut line = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    line.trim_end().to_string()
}

#[test]
fn credentialed_connect_tunnels_bytes() {
    let upstream_port = spawn_echo_upstream();
    let (proxy_port, mut client) = spawn_proxy();
    let header = client.presentation_header(&mut OsRng).unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let status = read_status(&mut s);
    assert!(
        status.contains("200"),
        "expected tunnel established, got: {status}"
    );

    // Tunnel is open: talk to the upstream end to end.
    s.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"PONG\n", "bytes must flow through the tunnel");
}

#[test]
fn connect_without_credential_is_refused() {
    let upstream_port = spawn_echo_upstream();
    let (proxy_port, _client) = spawn_proxy();

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();

    let status = read_status(&mut s);
    assert!(
        status.contains("407"),
        "no credential must be refused, got: {status}"
    );
}
