//! Opt-in, counts-only health / readiness / metrics endpoint for a deployed node.
//!
//! Per [`docs/OBSERVABILITY.md`](../../../docs/OBSERVABILITY.md) §5: **scalars
//! only, never identifiers** — no client IP, destination host, presentation tag,
//! channel id, or Ethereum address, and no per-request labels. It exists so an
//! operator can run a liveness/readiness healthcheck (systemd, Docker, k8s) and
//! scrape label-free counters; it is **off unless** the operator sets a bind
//! address, and should be bound to loopback / a private interface, not the public.
//!
//! Endpoints: `GET /healthz` → 200 (process alive), `GET /readyz` → 200 once the
//! node is serving else 503, `GET /metrics` → label-free `tessera_*` scalars.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Process-level, label-free health state. Cheap to share across threads (`Arc`).
pub struct HealthState {
    role: String,
    started: Instant,
    ready: AtomicBool,
}

impl HealthState {
    /// A new state for `role` (e.g. `"exit"`), not yet ready.
    pub fn new(role: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            role: role.into(),
            started: Instant::now(),
            ready: AtomicBool::new(false),
        })
    }

    /// Mark the node as serving — flips `/readyz` from 503 to 200.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// Bind the health endpoint at `addr` and serve it on a background thread. A bind
/// failure is returned (so the caller can fail fast); per-connection errors are
/// swallowed (best-effort telemetry must never take the node down).
pub fn spawn(addr: &str, state: Arc<HealthState>) -> std::io::Result<()> {
    let sock = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("health: {addr} did not resolve")))?;
    let listener = TcpListener::bind(sock)?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let st = Arc::clone(&state);
            // One request per connection, best-effort; never propagate errors.
            let mut stream = stream;
            let _ = handle(&mut stream, &st);
        }
    });
    Ok(())
}

fn handle(stream: &mut TcpStream, st: &HealthState) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    // "GET /path HTTP/1.1" — we only route on the path; we log/keep nothing.
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let (code, body) = response(path, st);
    let resp = format!(
        "HTTP/1.1 {code}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())
}

/// The pure routing/body decision (no I/O) — unit-testable.
fn response(path: &str, st: &HealthState) -> (&'static str, String) {
    // Strip any query string; route on the leading path segment only.
    let path = path.split('?').next().unwrap_or(path);
    if path == "/healthz" || path == "/health" {
        ("200 OK", "ok\n".to_string())
    } else if path == "/readyz" {
        if st.is_ready() {
            ("200 OK", "ready\n".to_string())
        } else {
            ("503 Service Unavailable", "not ready\n".to_string())
        }
    } else if path == "/metrics" {
        (
            "200 OK",
            format!(
                "# label-free, counts-only (docs/OBSERVABILITY.md §5) — role: {}\n\
                 tessera_up 1\n\
                 tessera_ready {}\n\
                 tessera_uptime_seconds {}\n",
                st.role,
                u8::from(st.is_ready()),
                st.uptime_secs()
            ),
        )
    } else {
        ("404 Not Found", "not found\n".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_counts_only_and_readiness_flips() {
        let st = HealthState::new("exit");
        // Liveness is always up once the process answers.
        assert_eq!(response("/healthz", &st).0, "200 OK");
        // Readiness is 503 until set, then 200.
        assert_eq!(response("/readyz", &st).0, "503 Service Unavailable");
        st.set_ready();
        assert_eq!(response("/readyz", &st).0, "200 OK");
        // Metrics are label-free scalars — assert no identifier-ish content.
        let (code, body) = response("/metrics", &st);
        assert_eq!(code, "200 OK");
        assert!(body.contains("tessera_up 1") && body.contains("tessera_ready 1"));
        assert!(body.contains("tessera_uptime_seconds"));
        for forbidden in ["onion", "127.0.0.1", "tag", "addr", "dest", "client"] {
            assert!(
                !body.contains(forbidden),
                "metrics leaked {forbidden:?}: {body}"
            );
        }
        // Unknown paths 404.
        assert_eq!(response("/secret", &st).0, "404 Not Found");
        // Query strings are ignored.
        assert_eq!(response("/healthz?x=1", &st).0, "200 OK");
    }

    #[test]
    fn served_over_a_real_socket() {
        let st = HealthState::new("exit");
        // Bind to grab a free port, drop it, then hand that addr to the health server.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        spawn(&addr.to_string(), Arc::clone(&st)).expect("spawn health");
        st.set_ready();
        std::thread::sleep(Duration::from_millis(50));
        let mut c = TcpStream::connect(addr).expect("connect health");
        c.write_all(b"GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.trim_end().ends_with("ready"));
    }
}
