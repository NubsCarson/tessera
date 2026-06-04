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
use std::sync::{Arc, Mutex};
use std::thread;

use tessera_origin::{Decision, OriginGuard, PRESENTATION_HEADER};

pub mod shaping;
pub use shaping::{ShapingConfig, ShapingDecision, VolumeShaper};

/// A per-egress-IP human-volume shaper shared across the proxy's connection
/// threads. See [`shaping`].
pub type SharedShaper = Arc<Mutex<VolumeShaper>>;

/// Where the proxy sends admitted tunnels.
#[derive(Debug, Clone)]
pub enum Upstream {
    /// Connect straight to the requested host:port.
    Direct,
    /// Route through a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`).
    Tor(String),
}

/// What the exit observed about one *admitted* tunnel: the peer socket it
/// accepted from and the CONNECT target (`host:port`, SNI-level destination) it
/// is about to tunnel to. Reported only after the credential check passes, so it
/// also witnesses "a valid credential was presented."
///
/// This is the EXIT's side of the split-trust ledger: it sees the destination
/// and that a credential was valid, but its `peer` is whoever connected to it —
/// the relay, never the client. `tessera-relay`'s integration test reads this to
/// prove the exit never learns the client's real address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitObservation {
    /// The socket this connection came from. In the 2-hop loop this is the relay.
    pub peer: std::net::SocketAddr,
    /// The CONNECT target being tunneled to (the final destination, SNI-level).
    pub connect_target: String,
}

/// A callback invoked once per admitted tunnel with its [`ExitObservation`].
pub type ExitObserver = Arc<dyn Fn(ExitObservation) + Send + Sync>;

/// Start the proxy on an already-bound listener, in a background thread.
///
/// Equivalent to [`serve_observed`] with no observer.
pub fn serve(
    listener: TcpListener,
    guard: Arc<OriginGuard>,
    upstream: Upstream,
) -> thread::JoinHandle<()> {
    serve_observed(listener, guard, upstream, None)
}

/// Like [`serve`], but with an optional [`ExitObserver`] called once per
/// *admitted* tunnel — used by `tessera-relay` to witness, and assert on, what
/// the exit learns (destination + a valid credential) and crucially does *not*
/// (the client's address). Production code uses [`serve`]; this is for the
/// split-trust proof.
pub fn serve_observed(
    listener: TcpListener,
    guard: Arc<OriginGuard>,
    upstream: Upstream,
    observer: Option<ExitObserver>,
) -> thread::JoinHandle<()> {
    serve_observed_shaped(listener, guard, upstream, observer, None)
}

/// Like [`serve_observed`], but additionally applies per-egress-IP **human-volume
/// shaping** (M5, see [`shaping`]) via a shared [`VolumeShaper`]. Each admitted
/// tunnel is paced according to the shaper's verdict (a graceful, bounded delay
/// when over the human envelope — never a hard block) before connecting, and the
/// shaper's concurrency count is bracketed around the tunnel. Pass one shaper per
/// egress IP; `None` disables shaping (equivalent to [`serve_observed`]).
pub fn serve_observed_shaped(
    listener: TcpListener,
    guard: Arc<OriginGuard>,
    upstream: Upstream,
    observer: Option<ExitObserver>,
    shaper: Option<SharedShaper>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let guard = Arc::clone(&guard);
            let upstream = upstream.clone();
            let observer = observer.clone();
            let shaper = shaper.clone();
            thread::spawn(move || {
                let _ = handle_connect(
                    stream,
                    &guard,
                    &upstream,
                    observer.as_ref(),
                    shaper.as_ref(),
                );
            });
        }
    })
}

fn write_status(stream: &mut TcpStream, status: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes());
    let _ = stream.flush();
}

fn handle_connect(
    mut stream: TcpStream,
    guard: &OriginGuard,
    upstream: &Upstream,
    observer: Option<&ExitObserver>,
    shaper: Option<&SharedShaper>,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
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

    // Admitted: witness what the exit learned — the destination + that a valid
    // credential was presented — for the split-trust ledger. `peer` is whoever
    // connected (the relay in the 2-hop loop), never the client.
    if let (Some(obs), Some(peer)) = (observer, peer) {
        obs(ExitObservation {
            peer,
            connect_target: target.clone(),
        });
    }

    // Open the tunnel to the requested host:port.
    let (host, port) = split_host_port(&target)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "bad CONNECT target"))?;

    // Per-egress-IP human-volume shaping (M5): pace this tunnel to stay within a
    // human-plausible envelope for the egress IP. Over-envelope traffic is delayed
    // gracefully (never hard-blocked — a refusal is itself a detectable signal),
    // and the tunnel is bracketed in the shaper's concurrency count. Keyed on the
    // destination host (metadata only; the tunnel stays end-to-end TLS). The
    // `ShaperPermit` guarantees the `note_open` taken here is matched by a
    // `note_close` on every return path (including the early 502 below).
    let _permit = shaper.map(|sh| {
        let delay = match sh.lock() {
            Ok(mut g) => {
                let d = g.decide_now(&host);
                g.note_open();
                d.delay
            }
            Err(_) => std::time::Duration::ZERO,
        };
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        ShaperPermit { shaper: sh }
    });

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

/// Releases the shaper's concurrency permit when the tunnel handler returns
/// (including on the early `502` path), so `note_open`/`note_close` always pair.
struct ShaperPermit<'a> {
    shaper: &'a SharedShaper,
}

impl Drop for ShaperPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.shaper.lock() {
            g.note_close();
        }
    }
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// Bidirectional copy between two streams (one thread per direction): copy `a→b`
/// on a spawned thread and `b→a` on this one, half-closing each direction on EOF.
///
/// This is the byte-transport heart of the tunnel — both the EXIT here and the
/// first-hop RELAY (`tessera-relay`, which reuses this) only ever move opaque
/// bytes. The client's TLS runs end-to-end through it untouched, so neither hop
/// sees plaintext and any tampering surfaces as a TLS error at the real endpoint.
pub fn pipe(a: TcpStream, b: TcpStream) {
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
