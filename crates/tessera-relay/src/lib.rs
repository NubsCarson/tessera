//! `tessera-relay` — the **first onion hop** in Tessera's 2-hop split-trust
//! loop, and the piece that makes the privacy claim concrete and testable:
//!
//! ```text
//! CLIENT ──CONNECT exit──▶ RELAY ──opaque bytes──▶ EXIT ──CONNECT dest──▶ DESTINATION
//!                          (this crate)            (tessera-proxy: credential-gated)
//! ```
//!
//! The client opens an **outer** `CONNECT <exit-addr>` to the relay. The relay
//! tunnels that to the exit and then only pumps opaque bytes. Through that tunnel
//! the client sends a **nested / inner** `CONNECT <destination>` carrying its
//! ARC `Tessera-Presentation` header — but the relay never parses it, so:
//!
//! * the **RELAY** learns the *client's* address and the *exit's* address, but
//!   **never the final destination** (it's inside the bytes the relay just
//!   forwards) and never the credential;
//! * the **EXIT** ([`tessera_proxy`]) learns the *destination* (CONNECT host:port,
//!   i.e. SNI-level) and that *a valid credential* was presented, but **never the
//!   client's address** — it only ever sees the relay's socket;
//! * **neither** sees content: the client's TLS to the destination runs
//!   end-to-end through both hops, which only move bytes (tampering breaks TLS).
//!
//! That split — no single hop holds {who} + {where} + {what} — is the property
//! the integration test asserts by inspecting an [`Observer`] wired into each
//! hop. This proves the *protocol/loop* locally; reaching a real Tor-blocked
//! site through a real clean exit IP is a documented manual final step (the
//! egress IP is external — no code removes that). See the crate README.
//!
//! Like [`tessera_proxy`], this is std-only (blocking sockets + one thread per
//! direction), demo/example tooling — not a hardened production relay.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Result, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

// The relay reuses tessera-proxy's byte-pump (`pipe`) verbatim — the exact same
// transport heart the EXIT uses — rather than reinventing it.
use tessera_proxy::pipe;

/// What a hop observed about a single forwarded connection. Wired into each hop
/// so a test (or an operator) can prove the **split-trust** property: assert the
/// relay never recorded the destination, and the exit never recorded the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The peer socket the hop accepted the connection *from*.
    pub peer: SocketAddr,
    /// The CONNECT target the hop parsed off the wire (`host:port`). For the
    /// relay this is the *exit's* address; for the exit this is the *destination*.
    pub connect_target: String,
}

/// A thread-safe, append-only log of [`Observation`]s for one hop.
///
/// Clone it and hand a clone to a hop (the inner [`Mutex<Vec<_>>`] is shared);
/// read the accumulated observations back with [`snapshot`](Observer::snapshot).
#[derive(Debug, Clone, Default)]
pub struct Observer {
    log: Arc<Mutex<Vec<Observation>>>,
}

impl Observer {
    /// A fresh, empty observer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation (called by a hop as it forwards a connection).
    pub fn record(&self, obs: Observation) {
        // A poisoned lock can't lose us correctness here (append-only); recover.
        let mut g = self.log.lock().unwrap_or_else(|e| e.into_inner());
        g.push(obs);
    }

    /// A copy of everything recorded so far.
    pub fn snapshot(&self) -> Vec<Observation> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The set of distinct CONNECT targets this hop has seen — convenience for
    /// the split-trust assertions ("did this hop ever see `X`?").
    pub fn targets(&self) -> Vec<String> {
        self.snapshot()
            .into_iter()
            .map(|o| o.connect_target)
            .collect()
    }
}

/// Start the relay on an already-bound listener, in a background thread.
///
/// `exit_addr` is the only forwarding target the relay knows; it forwards every
/// admitted outer `CONNECT` there (and rejects a `CONNECT` to anywhere else — a
/// real relay's hop is fixed, it is not an open proxy). `observer`, if given,
/// records what the relay saw (peer + outer CONNECT target) per connection.
pub fn serve(
    listener: TcpListener,
    exit_addr: SocketAddr,
    observer: Option<Observer>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let observer = observer.clone();
            thread::spawn(move || {
                let _ = handle(stream, exit_addr, observer.as_ref());
            });
        }
    })
}

fn write_status(stream: &mut TcpStream, status: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes());
    let _ = stream.flush();
}

/// Handle one client connection: read the outer `CONNECT <exit-addr>`, open a
/// plain TCP tunnel to the exit, `200`, then pipe opaque bytes. The relay does
/// **no** credential check — it is deliberately credential-blind — and never
/// parses anything inside the tunnel, so the inner CONNECT (and the destination
/// it names) is invisible to it.
fn handle(mut stream: TcpStream, exit_addr: SocketAddr, observer: Option<&Observer>) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut reader = BufReader::new(stream.try_clone()?.take(64 * 1024));

    // Outer request line: `CONNECT host:port HTTP/1.1`.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let outer_target = parts.next().unwrap_or("").to_string();

    // Drain the rest of the outer header block (we forward nothing from it; in
    // particular we do NOT look for, log, or forward any credential header — the
    // credential is only inside the inner CONNECT, which the exit reads).
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim_end().is_empty() {
            break;
        }
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        write_status(&mut stream, "405 Method Not Allowed");
        return Ok(());
    }

    // The relay's single observation: who connected, and the outer target. By
    // construction this records the EXIT's address, never the destination.
    if let Some(obs) = observer {
        obs.record(Observation {
            peer,
            connect_target: outer_target.clone(),
        });
    }

    // A relay forwards only to its fixed next hop (the exit). Refuse to be an
    // open proxy to an arbitrary outer target.
    if outer_target != exit_addr.to_string() {
        write_status(
            &mut stream,
            "403 Forbidden (relay forwards only to its exit)",
        );
        return Ok(());
    }

    let upstream = match TcpStream::connect(exit_addr) {
        Ok(c) => c,
        Err(_) => {
            write_status(&mut stream, "502 Bad Gateway");
            return Ok(());
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;

    // From here the relay only moves opaque bytes between the client and the
    // exit. The inner CONNECT + credential + the client's end-to-end TLS all ride
    // inside this stream and are never inspected. Reuses tessera-proxy's pipe.
    pipe(stream, upstream);
    Ok(())
}

/// Drive the 2-hop loop from the client side: open the outer tunnel to the
/// `relay`, then write the inner `CONNECT <destination>` (carrying the ARC
/// presentation header) *through* it to the exit. Returns the opened stream,
/// positioned right after the exit's `200 Connection Established` — i.e. an
/// end-to-end byte pipe straight to `destination`, ready to carry the client's
/// own TLS (or any opaque protocol).
///
/// This is the canonical client move the integration test and the binary use; it
/// makes the nesting explicit so callers don't hand-roll the two CONNECT lines.
pub fn open_through_relay(
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    destination: &str,
    presentation_header: &str,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(relay_addr)?;

    // OUTER hop: ask the relay to connect us to the EXIT. No credential here —
    // the relay is credential-blind, and this names only the exit, not the dest.
    stream.write_all(format!("CONNECT {exit_addr} HTTP/1.1\r\n\r\n").as_bytes())?;
    stream.flush()?;
    expect_200(&mut stream, "relay")?;

    // INNER hop: now tunneled to the EXIT, send the real CONNECT to the
    // destination, carrying the ARC presentation. Only the exit reads this.
    stream.write_all(
        format!(
            "CONNECT {destination} HTTP/1.1\r\nTessera-Presentation: {presentation_header}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    stream.flush()?;
    expect_200(&mut stream, "exit")?;

    Ok(stream)
}

/// Read exactly one HTTP status block (status line + headers up to the blank
/// line) off `stream`, one byte at a time so we never buffer past the
/// terminating `\r\n\r\n` into the tunnel payload, and require a `200`. `who`
/// names the hop for the error message (so a `407`/`403` is attributed
/// correctly). Reading unbuffered is essential: the very next bytes after the
/// exit's `200` are the destination's reply, which the caller must not lose.
fn expect_200(stream: &mut TcpStream, who: &str) -> Result<()> {
    let mut block = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            return Err(std::io::Error::other(format!(
                "{who} closed the connection before any status line"
            )));
        }
        block.push(byte[0]);
        if block.ends_with(b"\r\n\r\n") {
            break;
        }
        if block.len() > 16 * 1024 {
            return Err(std::io::Error::other(format!(
                "{who} status block too large"
            )));
        }
    }
    let text = String::from_utf8_lossy(&block);
    let status_line = text.lines().next().unwrap_or("");
    if status_line.contains("200") {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{who} refused the tunnel: {}",
            status_line.trim_end()
        )))
    }
}
