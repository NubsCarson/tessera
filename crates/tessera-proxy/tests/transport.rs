//! Deterministic test for the `TorSocksDialer` SOCKS5 path with NO real Tor: an
//! in-process SOCKS5 server stub does the no-auth handshake, parses the
//! domain-ATYP CONNECT, dials the onward target, and splices bytes — so the
//! dialer's wire framing is proven against a real (mock) SOCKS5 peer, and the
//! "host passed UNRESOLVED to the proxy" invariant (the reason `connect` takes a
//! `&str`, not a `SocketAddr`) is a tested property. Mirrors the ephemeral-port /
//! spawn / echo idioms in `tests/proxy.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use tessera_proxy::transport::{Dialer, TcpDialer, TorSocksDialer};

/// A one-shot upstream the SOCKS stub will be asked to reach: echoes one read.
fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]); // echo verbatim
                    let _ = s.flush();
                }
            });
        }
    });
    port
}

/// In-process SOCKS5 server stub (no-auth, domain ATYP). Performs the handshake
/// the real `socks5_connect` speaks, parses the requested `host:port`, connects
/// onward, returns REP=0x00, then splices both directions. Sends the asked-for
/// `(host, port)` over a channel so the test can assert the dialer passed the
/// destination UNRESOLVED.
fn spawn_socks5_stub() -> (u16, mpsc::Receiver<(String, u16)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut c) = stream else { continue };
            let tx = tx.clone();
            thread::spawn(move || {
                // greeting: VER=5, NMETHODS, METHODS...
                let mut greet = [0u8; 2];
                if c.read_exact(&mut greet).is_err() || greet[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; greet[1] as usize];
                if c.read_exact(&mut methods).is_err() {
                    return;
                }
                if c.write_all(&[0x05, 0x00]).is_err() {
                    return; // choose no-auth
                }
                // request: VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(domain)
                let mut head = [0u8; 4];
                if c.read_exact(&mut head).is_err()
                    || head[0] != 0x05
                    || head[1] != 0x01
                    || head[3] != 0x03
                {
                    return;
                }
                let mut len = [0u8; 1];
                if c.read_exact(&mut len).is_err() {
                    return;
                }
                let mut host = vec![0u8; len[0] as usize];
                let mut port_be = [0u8; 2];
                if c.read_exact(&mut host).is_err() || c.read_exact(&mut port_be).is_err() {
                    return;
                }
                let host = String::from_utf8_lossy(&host).into_owned();
                let port = u16::from_be_bytes(port_be);
                let _ = tx.send((host.clone(), port));

                // dial onward (the stub resolves the name, like Tor would)
                let upstream = match TcpStream::connect((host.as_str(), port)) {
                    Ok(u) => u,
                    Err(_) => {
                        let _ = c.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                        return;
                    }
                };
                // reply: VER, REP=0, RSV, ATYP=1, BND.ADDR(4)=0, BND.PORT(2)=0
                if c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .is_err()
                {
                    return;
                }
                let _ = c.flush();
                // splice both directions
                let (mut c_rd, mut up_wr) = (c.try_clone().unwrap(), upstream.try_clone().unwrap());
                let t = thread::spawn(move || {
                    let _ = std::io::copy(&mut c_rd, &mut up_wr);
                });
                let mut up_rd = upstream;
                let _ = std::io::copy(&mut up_rd, &mut c);
                let _ = t.join();
            });
        }
    });
    (proxy_port, rx)
}

#[test]
fn tor_socks_dialer_connects_through_a_socks5_proxy() {
    let upstream_port = spawn_echo_upstream();
    let (proxy_port, asked) = spawn_socks5_stub();

    let dialer = TorSocksDialer::new(format!("127.0.0.1:{proxy_port}"));
    // Dial by NAME — the dialer must hand the unresolved host to the proxy.
    let mut s = dialer
        .connect("localhost", upstream_port)
        .expect("SOCKS5 handshake + onward connect must succeed");

    let (got_host, got_port) = asked.recv().unwrap();
    assert_eq!(
        got_host, "localhost",
        "host must be passed UNRESOLVED to the proxy"
    );
    assert_eq!(got_port, upstream_port);

    s.write_all(b"ping-through-socks").unwrap();
    s.flush().unwrap();
    let mut buf = [0u8; 18];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(
        &buf, b"ping-through-socks",
        "opaque bytes must survive the SOCKS5 tunnel"
    );
}

#[test]
fn tor_socks_dialer_surfaces_a_proxy_failure_rep() {
    // A stub that rejects with REP=0x05 must become an Err.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut c) = stream else { continue };
            let mut greet = [0u8; 2];
            let _ = c.read_exact(&mut greet);
            let mut m = vec![0u8; greet[1] as usize];
            let _ = c.read_exact(&mut m);
            let _ = c.write_all(&[0x05, 0x00]); // no-auth ok
            let mut head = [0u8; 4];
            let _ = c.read_exact(&mut head);
            let mut len = [0u8; 1];
            let _ = c.read_exact(&mut len);
            let mut rest = vec![0u8; len[0] as usize + 2];
            let _ = c.read_exact(&mut rest);
            let _ = c.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        }
    });
    let dialer = TorSocksDialer::new(format!("127.0.0.1:{proxy_port}"));
    let err = dialer.connect("example.invalid", 443).unwrap_err();
    assert!(
        err.to_string().contains("REP=5"),
        "a non-zero SOCKS5 REP must error, got: {err}"
    );
}

#[test]
fn tcp_dialer_connects_directly_and_passes_bytes() {
    // TcpDialer reaches a loopback echo upstream directly (IP literal => no DNS).
    let upstream_port = spawn_echo_upstream();
    let mut s = TcpDialer
        .connect("127.0.0.1", upstream_port)
        .expect("direct dial must succeed");
    s.write_all(b"direct-bytes").unwrap();
    s.flush().unwrap();
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(
        &buf, b"direct-bytes",
        "bytes must survive the direct tunnel"
    );
}
