//! Adversarial target-policy regression: admission is the credential, but the
//! *target* still has to clear the exit's cheap-before-expensive policy gate.
//! These exercise the gate end-to-end through the real CONNECT surface (no TLS,
//! no Tor, all on loopback), asserting on the proxy's HTTP status line — a target
//! refusal is `403 Forbidden (target policy: ...)`, distinct from the credential
//! `407`.
//!
//! Idioms mirror `tests/proxy.rs` (ephemeral loopback listener, raw CONNECT,
//! `read_status`); the only addition is `serve_observed_shaped_policy`, which
//! injects a [`TargetPolicy`] so a test can build a gate that blocks one target
//! and admits another deterministically.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve_observed_shaped_policy, PortRule, TargetPolicy, Upstream};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

/// Stand up a credential-gated proxy with an explicit [`TargetPolicy`] on an
/// ephemeral loopback port; return the proxy port and a client that mints valid
/// presentations against it. (Same credential recipe as `tests/proxy.rs`.)
fn spawn_policy_proxy(policy: TargetPolicy) -> (u16, TesseraClient) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let client = TesseraClient::new(credential, CTX, LIMIT);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let guard = Arc::new(OriginGuard::new(sk, pk, REQ, CTX, LIMIT));
    serve_observed_shaped_policy(
        listener,
        guard,
        Upstream::Direct,
        None,
        None,
        Arc::new(policy),
    );
    (port, client)
}

/// A one-shot echo upstream: replies `PONG\n` once it sees a line.
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

/// A sink upstream that accepts a connection and drains bytes forever without
/// replying or closing — so a tunnel stays open until a cap/deadline tears it
/// down (used by the byte-cap and wall-clock-cap tests).
fn spawn_sink_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Read the proxy's HTTP status line.
fn read_status(stream: &mut TcpStream) -> String {
    let mut line = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    line.trim_end().to_string()
}

/// Send one CONNECT with a *fresh valid* credential (so the only thing under test
/// is the target gate) and return the proxy's status line.
fn connect_status(proxy_port: u16, client: &mut TesseraClient, target: &str) -> String {
    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!("CONNECT {target} HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n").as_bytes(),
    )
    .unwrap();
    read_status(&mut s)
}

fn assert_blocked(proxy_port: u16, client: &mut TesseraClient, target: &str, why: &str) {
    let status = connect_status(proxy_port, client, target);
    assert!(
        status.contains("403") && status.contains("target policy"),
        "target {target} must be blocked by policy ({why}), got: {status}"
    );
}

// --- private / link-local / loopback address space is never a valid target ---

#[test]
fn secure_policy_blocks_private_ipv4_targets() {
    let policy = TargetPolicy::secure().with_ports(PortRule::Any); // isolate the addr check
    let (proxy_port, mut client) = spawn_policy_proxy(policy);
    for target in [
        "10.0.0.1:443",
        "172.16.0.1:443",
        "192.168.1.1:443",
        "127.0.0.1:443",
        "169.254.169.254:443", // cloud metadata endpoint
        "100.64.0.1:443",      // CGNAT
        "0.0.0.0:443",
    ] {
        assert_blocked(
            proxy_port,
            &mut client,
            target,
            "private/loopback/link-local v4",
        );
    }
}

#[test]
fn secure_policy_blocks_private_ipv6_targets() {
    let policy = TargetPolicy::secure().with_ports(PortRule::Any);
    let (proxy_port, mut client) = spawn_policy_proxy(policy);
    for target in [
        "[::1]:443",              // loopback
        "[fc00::1]:443",          // unique-local
        "[fe80::1]:443",          // link-local
        "[::ffff:10.0.0.1]:443",  // IPv4-mapped private (must not bypass the v4 check)
        "[::ffff:127.0.0.1]:443", // IPv4-mapped loopback
    ] {
        assert_blocked(
            proxy_port,
            &mut client,
            target,
            "private/loopback/link-local v6",
        );
    }
}

// --- port allowlist ---

#[test]
fn secure_policy_blocks_disallowed_ports() {
    // Default secure() allows only :443. A public-shaped host on another port is
    // refused on the (cheap) port check before any address work.
    let (proxy_port, mut client) = spawn_policy_proxy(TargetPolicy::secure());
    for target in ["93.184.216.34:25", "93.184.216.34:80", "93.184.216.34:22"] {
        assert_blocked(proxy_port, &mut client, target, "disallowed port");
    }
}

// --- DNS resolve-then-pin: a name that resolves into blocked space is refused ---

#[test]
fn secure_policy_blocks_localhost_via_resolve_then_pin() {
    let policy = TargetPolicy::secure().with_ports(PortRule::Any);
    let (proxy_port, mut client) = spawn_policy_proxy(policy);
    // `localhost` resolves to loopback on every platform we build on; the post-
    // credential resolve-then-pin must reject it.
    assert_blocked(
        proxy_port,
        &mut client,
        "localhost:443",
        "hostname resolves to loopback",
    );
}

// --- the gate must still ADMIT a permitted target end-to-end ---

#[test]
fn permitted_target_tunnels_through_the_gate() {
    let upstream_port = spawn_echo_upstream();
    // Allow private addrs (so we can use a loopback upstream) but restrict ports
    // to exactly the upstream's port — proving the gate passes good traffic.
    let policy = TargetPolicy::unrestricted().with_ports(PortRule::Only(vec![upstream_port]));
    let (proxy_port, mut client) = spawn_policy_proxy(policy);

    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(
        read_status(&mut s).contains("200"),
        "a permitted target must tunnel"
    );
    s.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(
        &buf, b"PONG\n",
        "bytes must flow through the permitted tunnel"
    );
}

#[test]
fn same_policy_blocks_a_disallowed_port_while_admitting_the_allowed_one() {
    // One policy instance, two outcomes: the allowed port tunnels, a neighbor port
    // is refused on the cheap port check (regardless of whether anything listens).
    let upstream_port = spawn_echo_upstream();
    let policy = TargetPolicy::unrestricted().with_ports(PortRule::Only(vec![upstream_port]));
    let (proxy_port, mut client) = spawn_policy_proxy(policy);

    let other = upstream_port.wrapping_add(1).max(1);
    assert_blocked(
        proxy_port,
        &mut client,
        &format!("127.0.0.1:{other}"),
        "neighbor port not in allowlist",
    );
}

// --- cheap-before-expensive: a blocked target is refused even with NO credential,
//     proving the target check short-circuits before the credential verify ---

#[test]
fn blocked_target_is_refused_before_credential_check() {
    let policy = TargetPolicy::secure(); // :443 only
    let (proxy_port, _client) = spawn_policy_proxy(policy);
    // No credential header at all, and a disallowed port. If the port check runs
    // first (cheap-before-expensive), the refusal is a 403 target-policy line —
    // NOT the 407 we'd get if the credential check ran first.
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(b"CONNECT 93.184.216.34:25 HTTP/1.1\r\n\r\n")
        .unwrap();
    let status = read_status(&mut s);
    assert!(
        status.contains("403") && status.contains("target policy"),
        "blocked target must be refused cheaply (before the credential), got: {status}"
    );
}

// --- per-tunnel byte cap ---

#[test]
fn byte_cap_tears_down_oversized_tunnel() {
    let upstream_port = spawn_sink_upstream();
    let cap = 256 * 1024u64;
    let policy = TargetPolicy::unrestricted()
        .with_ports(PortRule::Only(vec![upstream_port]))
        .with_caps(Some(cap), None);
    let (proxy_port, mut client) = spawn_policy_proxy(policy);

    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(
        read_status(&mut s).contains("200"),
        "tunnel must open first"
    );
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Push well past the cap (up to 8 MiB >> the 256 KiB cap). A working cap tears
    // the tunnel down, surfacing as a write error on this non-draining side. We
    // require that write error within the bulk we send — NOT a read-timeout
    // fallback, which would pass even if the cap did nothing.
    let t0 = Instant::now();
    let chunk = vec![0u8; 32 * 1024];
    let mut wrote_err = false;
    for _ in 0..256 {
        if s.write_all(&chunk).is_err() {
            wrote_err = true;
            break;
        }
    }
    assert!(
        wrote_err,
        "byte cap must tear down the write side once exceeded (no write error after 8 MiB on a 256 KiB cap)"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "teardown must come from the cap, not the read-timeout net: {:?}",
        t0.elapsed()
    );
}

// --- per-tunnel wall-clock cap ---

#[test]
fn wall_clock_cap_tears_down_idle_tunnel() {
    let upstream_port = spawn_sink_upstream();
    let policy = TargetPolicy::unrestricted()
        .with_ports(PortRule::Only(vec![upstream_port]))
        .with_caps(None, Some(Duration::from_millis(200)));
    let (proxy_port, mut client) = spawn_policy_proxy(policy);

    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!(
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(
        read_status(&mut s).contains("200"),
        "tunnel must open first"
    );

    // Hold idle past the 200 ms lifetime; the proxy must hard-close it. The 5 s
    // read timeout is only a safety net so a regression fails fast instead of
    // hanging; the elapsed-time assertion is what makes this NON-vacuous — a
    // broken cap would close (if at all) at the 5 s net, not near 200 ms.
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sink = [0u8; 1];
    let t0 = Instant::now();
    let r = s.read(&mut sink);
    let elapsed = t0.elapsed();
    assert!(
        matches!(r, Ok(0) | Err(_)),
        "tunnel must be torn down at the wall-clock cap"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "must close near the 200 ms cap, not at the 5 s read-timeout net: {elapsed:?}"
    );
}

// --- the gate's other status paths (405 / 502) and the Tor pre-dial gate ---

#[test]
fn non_connect_method_is_405() {
    let (proxy_port, mut client) = spawn_policy_proxy(TargetPolicy::unrestricted());
    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.write_all(
        format!("GET http://example.com/ HTTP/1.1\r\nTessera-Presentation: {header}\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    assert!(
        read_status(&mut s).contains("405"),
        "a non-CONNECT method must be 405"
    );
}

#[test]
fn permitted_but_dead_upstream_is_502() {
    // Bind then drop a listener to get a guaranteed-closed loopback port, allow it
    // through the policy: the gate admits the target, but the dial fails => 502.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let policy = TargetPolicy::unrestricted().with_ports(PortRule::Only(vec![dead_port]));
    let (proxy_port, mut client) = spawn_policy_proxy(policy);

    let status = connect_status(proxy_port, &mut client, &format!("127.0.0.1:{dead_port}"));
    assert!(
        status.contains("502"),
        "a permitted-but-unreachable upstream must be 502, got: {status}"
    );
}

#[test]
fn tor_upstream_still_enforces_precheck_before_dialing() {
    // Under Upstream::Tor, the cheap precheck (port allowlist + IP-literal SSRF
    // classification) still applies and refuses BEFORE any SOCKS dial — so this
    // needs no Tor running. (Hostname address-gating is delegated to the Tor exit
    // by design; that path is not exercised here.)
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let mut client = TesseraClient::new(credential, CTX, LIMIT);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let guard = Arc::new(OriginGuard::new(sk, pk, REQ, CTX, LIMIT));
    serve_observed_shaped_policy(
        listener,
        guard,
        // A bogus Tor SOCKS endpoint: if the precheck failed to reject first, the
        // dial here would be attempted (and the test would not see a clean 403).
        Upstream::Tor("127.0.0.1:1".to_string()),
        None,
        None,
        Arc::new(TargetPolicy::secure()),
    );

    // Blocked IP literal and disallowed port: both refused by the precheck, 403.
    assert_blocked(
        proxy_port,
        &mut client,
        "169.254.169.254:443",
        "Tor: metadata literal blocked pre-dial",
    );
    assert_blocked(
        proxy_port,
        &mut client,
        "93.184.216.34:25",
        "Tor: disallowed port blocked pre-dial",
    );
}
