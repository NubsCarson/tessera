//! `tessera-proxy` — a forward HTTP **`CONNECT`** proxy whose admission decision
//! is a **Tessera credential, never the source IP**.
//!
//! A client sends `CONNECT host:443` with a `Tessera-Presentation` header; the
//! proxy verifies it via [`tessera_origin::OriginGuard`], and only then opens a
//! tunnel to `host:443` — directly or, with [`Upstream::Tor`], through a Tor
//! SOCKS5 proxy — and pipes raw bytes. Because it's `CONNECT`, the client's TLS
//! runs **end-to-end** to the real upstream (e.g. `api.anthropic.com`): the
//! proxy never sees plaintext and needs no TLS of its own.
//!
//! This is the "use Claude through Tor, gated on a credential not an IP"
//! endpoint: a cooperating proxy admits anonymous, accountable traffic and
//! relays it to any HTTPS site over Tor.
//!
//! Demo/example tooling — std-only, not a hardened production proxy.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use tessera_origin::{Decision, OriginGuard, PRESENTATION_HEADER};

/// Where the proxy sends admitted tunnels.
#[derive(Debug, Clone)]
pub enum Upstream {
    /// Connect straight to the requested host:port.
    Direct,
    /// Route through a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`).
    Tor(String),
}

/// Start the proxy on an already-bound listener, in a background thread.
pub fn serve(
    listener: TcpListener,
    guard: Arc<OriginGuard>,
    upstream: Upstream,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let guard = Arc::clone(&guard);
            let upstream = upstream.clone();
            thread::spawn(move || {
                let _ = handle_connect(stream, &guard, &upstream);
            });
        }
    })
}

fn write_status(stream: &mut TcpStream, status: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes());
    let _ = stream.flush();
}

fn handle_connect(mut stream: TcpStream, guard: &OriginGuard, upstream: &Upstream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?.take(64 * 1024));

    // Request line: `CONNECT host:port HTTP/1.1`.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("").to_string();

    // Headers (we only care about the credential).
    let mut presentation: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(PRESENTATION_HEADER) {
                presentation = Some(value.trim().to_string());
            }
        }
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        write_status(&mut stream, "405 Method Not Allowed");
        return Ok(());
    }

    // The admission decision: the credential, nothing else.
    match guard.check(presentation.as_deref()) {
        Decision::Admit { .. } => {}
        Decision::Reject(reason) => {
            // 407 is the canonical "proxy auth required"; carry the reason.
            write_status(
                &mut stream,
                &format!("407 Proxy Authentication Required ({})", reason.label()),
            );
            return Ok(());
        }
    }

    // Open the tunnel to the requested host:port.
    let (host, port) = split_host_port(&target)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "bad CONNECT target"))?;
    let upstream_conn = match upstream {
        Upstream::Direct => TcpStream::connect((host.as_str(), port)),
        Upstream::Tor(proxy) => socks5_connect(proxy, &host, port),
    };
    let upstream_conn = match upstream_conn {
        Ok(c) => c,
        Err(_) => {
            write_status(&mut stream, "502 Bad Gateway");
            return Ok(());
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;

    // Pipe bytes both ways until either side closes. The client's TLS is
    // end-to-end with the upstream; the proxy only moves opaque bytes.
    pipe(stream, upstream_conn);
    Ok(())
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// Bidirectional copy between two streams (one thread per direction).
fn pipe(a: TcpStream, b: TcpStream) {
    let (mut a_read, mut a_write) = (a.try_clone(), a);
    let (mut b_read, mut b_write) = (b.try_clone(), b);
    let t = thread::spawn(move || {
        if let Ok(ref mut ar) = a_read {
            let _ = std::io::copy(ar, &mut b_write);
            let _ = b_write.shutdown(std::net::Shutdown::Write);
        }
    });
    if let Ok(ref mut br) = b_read {
        let _ = std::io::copy(br, &mut a_write);
        let _ = a_write.shutdown(std::net::Shutdown::Write);
    }
    let _ = t.join();
}

/// Minimal SOCKS5 CONNECT (no auth, domain target) — enough to reach any host
/// (including a `.onion` or `api.anthropic.com`) through the local Tor port.
fn socks5_connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(Error::other("SOCKS5: no acceptable method"));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::other("SOCKS5: host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(Error::other(format!(
            "SOCKS5 connect failed (REP={})",
            head[1]
        )));
    }
    let bnd = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(Error::other("SOCKS5: bad ATYP")),
    };
    let mut skip = vec![0u8; bnd + 2];
    s.read_exact(&mut skip)?;
    Ok(s)
}
