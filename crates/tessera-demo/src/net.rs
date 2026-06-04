//! A deliberately tiny, dependency-free HTTP/1.1 + SOCKS5 layer used *only* by
//! the demo harness. It is not part of the Tessera product — the reusable
//! pieces are `tessera-origin` and `tessera-client`. Keeping this std-only
//! means the demo compiles in seconds and runs identically everywhere.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use tessera_origin::{Decision, OriginGuard, PRESENTATION_HEADER};

/// Pages the origin serves, so a browser or `curl` sees something clean too.
fn admit_page(tag: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>Tessera · admitted</title>\
         <body style='font:16px system-ui;max-width:40rem;margin:4rem auto;color:#1a1b26'>\
         <h1>🔓 Admitted</h1>\
         <p>You proved you hold a valid, in-budget credential — without revealing \
         who you are or where you connected from. Your IP was never consulted.</p>\
         <p style='color:#565f89'>presentation tag: <code>{tag}</code></p></body>"
    )
}

fn block_page(reason: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>Tessera · blocked</title>\
         <body style='font:16px system-ui;max-width:40rem;margin:4rem auto;color:#1a1b26'>\
         <h1>🔒 Blocked</h1>\
         <p>This request carried no acceptable credential ({reason}). On most of \
         today's web this is exactly what a Tor exit IP gets — blocked on sight.</p></body>"
    )
}

/// The outcome of a single client request, as seen by the client.
pub struct HttpResult {
    pub status: u16,
    /// Value of the `Tessera-Result` response header (the guard's reason/tag).
    pub result: String,
}

/// Start the origin HTTP server on an already-bound listener, in a background
/// thread. Each connection is handled by [`OriginGuard::check`] on the
/// `Tessera-Presentation` header — the source IP is never examined.
pub fn serve(listener: TcpListener, guard: Arc<OriginGuard>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let guard = Arc::clone(&guard);
            // One thread per connection is plenty for a demo.
            thread::spawn(move || handle_connection(stream, &guard));
        }
    })
}

fn handle_connection(mut stream: TcpStream, guard: &OriginGuard) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    // Read the request line + headers (we ignore the body; this is a GET demo).
    let mut presentation: Option<String> = None;
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() {
            return;
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case(PRESENTATION_HEADER) {
                presentation = Some(value.trim().to_string());
            }
        }
    }

    let decision = guard.check(presentation.as_deref());
    let (status_line, result, body) = match &decision {
        Decision::Admit { tag } => ("200 OK", format!("admit tag={tag}"), admit_page(tag)),
        Decision::Reject(reason) => (
            "403 Forbidden",
            format!("reject {}", reason.label()),
            block_page(reason.label()),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Tessera-Result: {result}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Perform a GET over an established stream, optionally attaching a
/// presentation header. Returns the parsed status and `Tessera-Result`.
fn http_get(
    mut stream: TcpStream,
    host: &str,
    presentation: Option<&str>,
) -> std::io::Result<HttpResult> {
    let mut req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(p) = presentation {
        req.push_str(&format!("{PRESENTATION_HEADER}: {p}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = String::new();
    BufReader::new(stream).read_to_string(&mut raw)?;
    parse_response(&raw)
}

fn parse_response(raw: &str) -> std::io::Result<HttpResult> {
    let mut lines = raw.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    // "HTTP/1.1 200 OK"
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut result = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Tessera-Result") {
                result = value.trim().to_string();
            }
        }
    }
    Ok(HttpResult { status, result })
}

/// A GET directly to a TCP address (the non-Tor path).
pub fn get_direct(addr: &str, presentation: Option<&str>) -> std::io::Result<HttpResult> {
    let stream = TcpStream::connect(addr)?;
    http_get(stream, addr, presentation)
}

/// A GET to `host:port` routed through a SOCKS5 proxy (e.g. Tor at
/// 127.0.0.1:9050). `host` may be a `.onion` address — Tor resolves it.
pub fn get_via_socks5(
    proxy: &str,
    host: &str,
    port: u16,
    presentation: Option<&str>,
) -> std::io::Result<HttpResult> {
    let stream = socks5_connect(proxy, host, port)?;
    http_get(stream, &format!("{host}:{port}"), presentation)
}

/// Minimal SOCKS5 CONNECT (no auth, domain target) — enough to reach a Tor
/// hidden service through the local Tor SOCKS port.
fn socks5_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    use std::io::Error;
    let mut s = TcpStream::connect(proxy)?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(Error::other("SOCKS5: no acceptable method"));
    }

    // CONNECT request, ATYP=3 (domain name).
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::other("SOCKS5: host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(Error::other(format!(
            "SOCKS5 connect failed (REP={})",
            head[1]
        )));
    }
    let bnd_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(Error::other("SOCKS5: bad ATYP")),
    };
    let mut skip = vec![0u8; bnd_len + 2]; // address + port
    s.read_exact(&mut skip)?;
    Ok(s)
}
