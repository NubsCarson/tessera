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
//! A cooperating proxy admits anonymous, accountable traffic and relays it to
//! any HTTPS site over Tor.
//!
//! Demo/example tooling — std-only, not a hardened production proxy.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io::{BufRead, BufReader, ErrorKind, Read, Result, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tessera_origin::{Decision, OriginGuard, PRESENTATION_HEADER};

pub mod policy;
pub mod shaping;
pub mod transport;
pub use policy::{is_blocked_addr, PortRule, TargetPolicy, TargetReject};
pub use shaping::{ShapingConfig, ShapingDecision, VolumeShaper};
pub use transport::{Dialer, TcpDialer, TorSocksDialer};

use policy::Precheck;

/// Hard cap on simultaneously-handled connections (S3 DoS bound). This is a
/// *transport* backstop distinct from the [`VolumeShaper`]'s *soft* per-egress
/// concurrency pacing: the shaper paces a paying user's tunnels to look human,
/// whereas this prevents an unauthenticated flood from spawning unbounded OS
/// threads (each ~MiBs of stack) and exhausting the node. Excess connections get
/// `503` on the accept thread and are dropped *before* a worker is spawned.
const MAX_INFLIGHT: usize = 1024;

/// Read/write timeout on a tunnel socket (S3): a slow-roll / idle peer cannot pin
/// a worker thread + fd forever — the blocking copy/parse loops unblock on it.
/// Applied symmetrically to BOTH the accepted client socket and the upstream
/// socket (the latter inside each [`transport::Dialer`]), so a stalled upstream
/// cannot pin a handler either.
pub(crate) const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the upstream `connect` (S3): a black-holed destination cannot pin a
/// handler for the kernel's full SYN-retry window (~127s) holding a concurrency
/// permit. Applied by each [`transport::Dialer`] (Direct dial and SOCKS5 dial).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// RAII permit for the [`MAX_INFLIGHT`] concurrency cap: decrements the active
/// counter when the handler thread returns, on every path.
struct InflightGuard(Arc<AtomicUsize>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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

impl Upstream {
    /// The runtime dial mechanism for this configured upstream: a [`TcpDialer`]
    /// for [`Direct`](Upstream::Direct), a [`TorSocksDialer`] for
    /// [`Tor`](Upstream::Tor). `Upstream` stays the operator-facing config knob;
    /// [`Dialer`] is the mechanism the handler invokes.
    pub fn dialer(&self) -> Box<dyn Dialer> {
        match self {
            Upstream::Direct => Box::new(TcpDialer),
            Upstream::Tor(proxy) => Box::new(TorSocksDialer::new(proxy.clone())),
        }
    }
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
    serve_observed_shaped_policy(
        listener,
        guard,
        upstream,
        observer,
        shaper,
        Arc::new(TargetPolicy::unrestricted()),
    )
}

/// Like [`serve_observed_shaped`], but also enforces a [`TargetPolicy`] on every
/// `CONNECT` target: a port allowlist plus an SSRF/private-address guard with
/// resolve-then-pin, run as the cheap pre-credential admission step (see the
/// [`policy`] module). A deployed exit uses this with [`TargetPolicy::secure`];
/// the other `serve_*` entry points delegate here with
/// [`TargetPolicy::unrestricted`], which preserves the prior
/// connect-to-any-target behavior (and the existing in-process tests / relay
/// loop that tunnel to ephemeral loopback ports).
pub fn serve_observed_shaped_policy(
    listener: TcpListener,
    guard: Arc<OriginGuard>,
    upstream: Upstream,
    observer: Option<ExitObserver>,
    shaper: Option<SharedShaper>,
    policy: Arc<TargetPolicy>,
) -> thread::JoinHandle<()> {
    let inflight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Idle/slow-roll defense: a peer that never finishes the request (or a
            // stalled tunnel) unblocks on these timeouts instead of pinning the
            // worker forever. Inherited by the try_clone'd fd in the handler.
            let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
            // Hard concurrency cap: reject (and drop) on the accept thread BEFORE
            // spawning a worker, so a flood can't exhaust threads/memory.
            if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
                inflight.fetch_sub(1, Ordering::AcqRel);
                write_status(&mut stream, "503 Service Unavailable");
                continue;
            }
            let permit = InflightGuard(Arc::clone(&inflight));
            let guard = Arc::clone(&guard);
            let upstream = upstream.clone();
            let observer = observer.clone();
            let shaper = shaper.clone();
            let policy = Arc::clone(&policy);
            thread::spawn(move || {
                let _permit = permit; // released when this handler thread returns
                let _ = handle_connect(
                    stream,
                    &guard,
                    &upstream,
                    observer.as_ref(),
                    shaper.as_ref(),
                    &policy,
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
    policy: &TargetPolicy,
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

    // Cheap target pre-check (port allowlist + IP-literal SSRF classification),
    // BEFORE the expensive credential verification — mirroring `OriginGuard`'s own
    // cheap-before-expensive ordering. This refuses a junk/blocked target without
    // forcing P-256 work, and any DNS for a hostname is deferred to *after* the
    // credential check (so an unauthenticated peer can never make the exit resolve
    // a name). A target refusal is `403 Forbidden` — the credential may be fine;
    // it is the destination that is disallowed (distinct from the credential 407).
    let (host, port) = match split_host_port(&target) {
        Some(hp) => hp,
        None => {
            write_status(
                &mut stream,
                &format!(
                    "403 Forbidden (target policy: {})",
                    TargetReject::MalformedTarget.label()
                ),
            );
            return Ok(());
        }
    };
    let precheck = match policy.precheck(&host, port) {
        Ok(p) => p,
        Err(reason) => {
            write_status(
                &mut stream,
                &format!("403 Forbidden (target policy: {})", reason.label()),
            );
            return Ok(());
        }
    };

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

    // Open the upstream connection.
    //
    // For a **Direct** upstream we resolve-then-pin (DNS only now, post-credential)
    // and connect to the *pinned* address the policy classified — never by
    // re-resolving the name — so the address that was checked is the address that
    // is dialed (DNS rebinding defense). The full SSRF address gate applies.
    //
    // For a **Tor** upstream the port allowlist and IP-literal classification from
    // the precheck still applied, but the SSRF *address* gate for a hostname is
    // **deliberately delegated to the Tor exit's ExitPolicy**, not enforced here:
    // the exit resolves the name from its own vantage point, and Tor exits refuse
    // private/loopback/reserved destinations by default. Resolving the hostname
    // locally just to classify it would leak the destination to our local resolver
    // — exactly what routing over Tor is meant to avoid — so we pass the name
    // through unresolved. (Documented in docs/CLEAN_ONION_EGRESS.md.)
    // The transport is chosen by the configured `Upstream`; the SSRF/target policy
    // (resolve-then-pin for Direct, deliberate don't-resolve for Tor) stays here so
    // the dialer abstracts only the transport, never the policy. Each dialer arms
    // its own connect/idle timeouts (S3).
    let dialer = upstream.dialer();
    let upstream_conn = match upstream {
        Upstream::Direct => {
            let ip = match &precheck {
                Precheck::Pinned(ip) => *ip,
                Precheck::Hostname(h) => match policy.resolve_pinned(h, port) {
                    Ok(ip) => ip,
                    Err(reason) => {
                        write_status(
                            &mut stream,
                            &format!("403 Forbidden (target policy: {})", reason.label()),
                        );
                        return Ok(());
                    }
                },
            };
            // Dial the *pinned* address (the dialer re-parses the IP literal with
            // no DNS, preserving the rebinding defense).
            dialer.connect(&ip.to_string(), port)
        }
        Upstream::Tor(_) => {
            // Pass the name UNRESOLVED to the Tor proxy (it resolves from its own
            // vantage; local resolution would leak the destination's DNS).
            let target_host = match &precheck {
                Precheck::Pinned(ip) => ip.to_string(),
                Precheck::Hostname(h) => h.clone(),
            };
            dialer.connect(&target_host, port)
        }
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

    // Pipe bytes both ways until either side closes, subject to the policy's
    // optional per-tunnel byte/wall-clock caps. The client's TLS is end-to-end
    // with the upstream; the proxy only moves opaque bytes.
    pipe_capped(
        stream,
        upstream_conn,
        policy.max_tunnel_bytes(),
        policy.max_tunnel_duration(),
    );
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
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    // Reject userinfo smuggling (`user@host`) and, for a non-bracketed host, a
    // stray ':' (an unbracketed IPv6 literal or otherwise malformed authority).
    // A bracketed IPv6 literal (`[::1]`) legitimately contains ':' inside the
    // brackets and is unwrapped later in `TargetPolicy::precheck`.
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.contains('@') || (!bracketed && host.contains(':')) {
        return None;
    }
    Some((host.to_string(), port))
}

/// Bidirectional copy between two streams (one thread per direction): copy `a→b`
/// on a spawned thread and `b→a` on this one, half-closing each direction on EOF.
///
/// This is the byte-transport heart of the tunnel — both the EXIT here and the
/// first-hop RELAY (`tessera-relay`, which reuses this) only ever move opaque
/// bytes. The client's TLS runs end-to-end through it untouched, so neither hop
/// sees plaintext and any tampering surfaces as a TLS error at the real endpoint.
///
/// Equivalent to [`pipe_capped`] with no caps.
pub fn pipe(a: TcpStream, b: TcpStream) {
    pipe_capped(a, b, None, None);
}

/// Like [`pipe`], but enforces optional per-tunnel caps: a total-bytes ceiling
/// (summed across both directions) and a wall-clock lifetime. On a natural EOF a
/// direction is half-closed (preserving half-open protocols, exactly like
/// [`pipe`]); when a byte cap or the deadline fires, the whole tunnel is torn
/// down. `None`/`None` reproduces [`pipe`]'s behavior byte-for-byte.
pub fn pipe_capped(
    a: TcpStream,
    b: TcpStream,
    max_bytes: Option<u64>,
    max_duration: Option<Duration>,
) {
    // `checked_add` rather than `+`: a pathologically large lifetime must not
    // panic the handler (the config layer also clamps it, but defend here too).
    // An un-representable deadline degrades to "no wall-clock cap".
    let deadline = max_duration.and_then(|d| Instant::now().checked_add(d));
    let counter = Arc::new(AtomicU64::new(0));

    // Clone both handles so the spawned direction owns one pair and this thread
    // the other; clones share the underlying socket, so a `shutdown` from either
    // direction unblocks the other.
    let (a_fwd, b_fwd) = match (a.try_clone(), b.try_clone()) {
        (Ok(a2), Ok(b2)) => (a2, b2),
        // Clone failed (rare): best-effort single-direction copy so the tunnel is
        // never silently dropped.
        _ => {
            let mut a = a;
            let mut b = b;
            let _ = std::io::copy(&mut a, &mut b);
            return;
        }
    };
    let c_fwd = Arc::clone(&counter);
    let t = thread::spawn(move || {
        let stop = copy_capped(&a_fwd, &b_fwd, max_bytes, deadline, &c_fwd);
        finish(&a_fwd, &b_fwd, stop);
    });
    let stop = copy_capped(&b, &a, max_bytes, deadline, &counter);
    finish(&b, &a, stop);
    let _ = t.join();
}

/// Why a [`copy_capped`] direction stopped.
enum Stop {
    /// Natural end of stream (or a benign read/write error): half-close only, so
    /// the reverse direction can still drain (half-open protocols keep working).
    Eof,
    /// A byte cap or the wall-clock deadline fired: tear the whole tunnel down.
    Capped,
}

/// On stop, either half-close the write side (EOF) or hard-close both sockets (a
/// cap fired).
fn finish(from: &TcpStream, to: &TcpStream, stop: Stop) {
    match stop {
        Stop::Eof => {
            let _ = to.shutdown(Shutdown::Write);
        }
        Stop::Capped => {
            let _ = to.shutdown(Shutdown::Both);
            let _ = from.shutdown(Shutdown::Both);
        }
    }
}

/// Copy `from → to` until EOF, a write error, the shared byte cap, or the
/// deadline. Operates on `&TcpStream` (which impls `Read`/`Write`) so the same
/// handle can be torn down by [`finish`]. With a `deadline` set, the read timeout
/// is sliced so the loop wakes to re-check it; with no deadline an idle-timeout
/// read ends the copy (matching the prior `std::io::copy` behavior under
/// `SOCKET_TIMEOUT`).
fn copy_capped(
    from: &TcpStream,
    to: &TcpStream,
    max_bytes: Option<u64>,
    deadline: Option<Instant>,
    counter: &AtomicU64,
) -> Stop {
    let mut rd: &TcpStream = from;
    let mut wr: &TcpStream = to;
    let mut buf = [0u8; 16 * 1024];
    loop {
        if let Some(dl) = deadline {
            let now = Instant::now();
            if now >= dl {
                return Stop::Capped;
            }
            // Wake at least once per SOCKET_TIMEOUT (or sooner) to re-check.
            let slice = (dl - now).min(SOCKET_TIMEOUT).max(Duration::from_millis(1));
            let _ = from.set_read_timeout(Some(slice));
        }
        match rd.read(&mut buf) {
            Ok(0) => return Stop::Eof,
            Ok(n) => {
                if let Some(max) = max_bytes {
                    if counter.fetch_add(n as u64, Ordering::AcqRel) + n as u64 > max {
                        return Stop::Capped;
                    }
                }
                if wr.write_all(&buf[..n]).is_err() {
                    return Stop::Eof;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // A timed-out read slice. With a deadline, loop and re-check it;
                // without one, this is the idle SOCKET_TIMEOUT — end the copy.
                if deadline.is_some() {
                    continue;
                }
                return Stop::Eof;
            }
            Err(_) => return Stop::Eof,
        }
    }
}
