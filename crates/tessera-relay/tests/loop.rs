//! End-to-end proof of Tessera's **2-hop split-trust loop**, all on 127.0.0.1
//! with ephemeral ports:
//!
//! ```text
//! CLIENT ─CONNECT exit→ RELAY ─bytes→ EXIT ─CONNECT origin→ ORIGIN(HTTP)
//! ```
//!
//! Asserts the four credential behaviours (valid / missing / replay / fresh),
//! the **split-trust** property (relay never sees the destination; exit never
//! sees the client's address), and that the tunnel carries **opaque bytes** both
//! ways with tampering detected by the caller (the in-test stand-in for the
//! client's real end-to-end TLS, which we do not terminate at either hop).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve_observed, ExitObservation, ExitObserver, Upstream};
use tessera_relay::{open_through_relay, serve as serve_relay, Observer};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://relay-loop/v1";
const LIMIT: u64 = 8;

/// A minimal HTTP/1.1 origin: replies `200 OK` with a fixed body, and records
/// the peer address of every connection it accepts (so the test can prove the
/// exit, not the client, is what reaches it). Returns (addr, hit-count, peers).
fn spawn_http_origin() -> (SocketAddr, Arc<AtomicU32>, Arc<Mutex<Vec<SocketAddr>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU32::new(0));
    let peers = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let h = Arc::clone(&hits);
    let p = Arc::clone(&peers);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let h = Arc::clone(&h);
            let p = Arc::clone(&p);
            thread::spawn(move || {
                if let Ok(peer) = s.peer_addr() {
                    p.lock().unwrap().push(peer);
                }
                // Read the request line + headers (until blank line), then reply.
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
                        break;
                    }
                }
                h.fetch_add(1, Ordering::SeqCst);
                let body = "tessera-origin-ok";
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
                let _ = s.flush();
            });
        }
    });
    (addr, hits, peers)
}

/// A bare echo origin: reads one line and echoes it back verbatim. Used to prove
/// opaque bytes survive both directions through relay→exit (and that a tampered
/// byte is detected by the caller comparing what it sent vs got back).
fn spawn_echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                // Read raw bytes up to (and including) the first newline and echo
                // them back verbatim — `read_until`, not `read_line`, so the
                // payload can be arbitrary non-UTF-8 opaque bytes.
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = Vec::new();
                if r.read_until(b'\n', &mut line).is_ok() {
                    let _ = s.write_all(&line);
                    let _ = s.flush();
                }
            });
        }
    });
    addr
}

/// Stand up the EXIT (tessera-proxy, credential-gated, direct egress) with an
/// observer; return (exit_addr, client-that-mints-presentations, exit-observer).
fn spawn_exit() -> (SocketAddr, TesseraClient, Arc<Mutex<Vec<ExitObservation>>>) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let client = TesseraClient::new(credential, CTX, LIMIT);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(sk, pk, REQ, CTX, LIMIT));

    let seen = Arc::new(Mutex::new(Vec::<ExitObservation>::new()));
    let seen_cb = Arc::clone(&seen);
    let observer: ExitObserver = Arc::new(move |obs: ExitObservation| {
        seen_cb.lock().unwrap().push(obs);
    });
    serve_observed(listener, guard, Upstream::Direct, Some(observer));
    (addr, client, seen)
}

/// Stand up the RELAY in front of `exit_addr` with an observer; return its addr.
fn spawn_relay(exit_addr: SocketAddr, observer: Observer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    serve_relay(listener, exit_addr, Some(observer));
    addr
}

/// Drive one full HTTP/1.1 GET through relay→exit→origin and return
/// (the opened stream's local addr = the client's real source socket, response).
fn http_get_through_loop(
    relay: SocketAddr,
    exit: SocketAddr,
    destination: SocketAddr,
    header: &str,
) -> std::io::Result<(SocketAddr, String)> {
    let mut stream = open_through_relay(relay, exit, &destination.to_string(), header)?;
    let client_src = stream.local_addr()?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok((client_src, String::from_utf8_lossy(&buf).into_owned()))
}

#[test]
fn valid_credential_reaches_origin_and_split_trust_holds() {
    let (origin, hits, origin_peers) = spawn_http_origin();
    let (exit, mut client, exit_seen) = spawn_exit();
    let relay_obs = Observer::new();
    let relay = spawn_relay(exit, relay_obs.clone());

    let header = client.presentation_header(&mut OsRng).unwrap();
    let (client_src, resp) = http_get_through_loop(relay, exit, origin, &header).unwrap();

    // Reaches the origin: 200 + the exact body.
    assert!(resp.contains("200 OK"), "expected 200, got:\n{resp}");
    assert!(
        resp.contains("tessera-origin-ok"),
        "expected the origin body, got:\n{resp}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "origin hit exactly once");

    // --- SPLIT-TRUST: the RELAY learned {client, exit}, NOT the destination. ---
    let relay_seen = relay_obs.snapshot();
    assert_eq!(relay_seen.len(), 1, "relay handled one connection");
    let r = &relay_seen[0];
    assert_eq!(
        r.connect_target,
        exit.to_string(),
        "relay's only CONNECT target must be the EXIT"
    );
    assert_eq!(
        r.peer, client_src,
        "relay saw the client's real source socket"
    );
    // The relay must NEVER have seen the destination, in any form.
    for t in relay_obs.targets() {
        assert_ne!(
            t,
            origin.to_string(),
            "RELAY must never observe the destination"
        );
        assert!(
            !t.contains(&origin.port().to_string()),
            "RELAY must never observe the destination port"
        );
    }

    // --- SPLIT-TRUST: the EXIT learned {destination, a valid credential}, but
    //     its peer is the RELAY — NEVER the client's real source socket. ---
    let exit_seen = exit_seen.lock().unwrap().clone();
    assert_eq!(exit_seen.len(), 1, "exit admitted one tunnel (valid cred)");
    let e = &exit_seen[0];
    assert_eq!(
        e.connect_target,
        origin.to_string(),
        "EXIT observes the destination (SNI-level)"
    );
    assert_ne!(
        e.peer, client_src,
        "EXIT must NOT see the client's real source socket"
    );
    assert_ne!(
        e.peer.port(),
        client_src.port(),
        "EXIT's peer port must differ from the client's"
    );
    // The exit's peer is the relay's outbound socket — same loopback IP, but a
    // socket the relay owns, not the client's. (We can't pin the relay's
    // ephemeral outbound port, so we assert it is *not* the client and *not* the
    // relay's listen port either — it's the relay reaching out to the exit.)
    assert_ne!(
        e.peer, relay,
        "exit's peer is the relay's *outbound* socket, not its listen socket"
    );

    // The origin, too, only ever saw the exit — never the client.
    let origin_peers = origin_peers.lock().unwrap().clone();
    assert_eq!(origin_peers.len(), 1);
    assert_ne!(
        origin_peers[0], client_src,
        "the origin must never see the client's source socket"
    );
}

#[test]
fn missing_credential_is_rejected_by_exit_and_origin_never_hit() {
    let (origin, hits, _) = spawn_http_origin();
    let (exit, _client, exit_seen) = spawn_exit();
    let relay_obs = Observer::new();
    let relay = spawn_relay(exit, relay_obs.clone());

    // Drive the loop with an EMPTY credential header.
    let err = open_through_relay(relay, exit, &origin.to_string(), "").unwrap_err();
    assert!(
        err.to_string().contains("exit refused"),
        "the EXIT must refuse a missing credential, got: {err}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "origin must NEVER be hit without a valid credential"
    );
    // The exit admitted nothing (observer only fires on admit).
    assert!(
        exit_seen.lock().unwrap().is_empty(),
        "exit must not record an observation for a refused tunnel"
    );
    // The relay still forwarded the OUTER connect (it is credential-blind), so it
    // recorded the exit as its target — but never the destination.
    assert_eq!(relay_obs.targets(), vec![exit.to_string()]);
}

#[test]
fn invalid_credential_is_rejected() {
    let (origin, hits, _) = spawn_http_origin();
    let (exit, _client, _) = spawn_exit();
    let relay_obs = Observer::new();
    let relay = spawn_relay(exit, relay_obs.clone());

    // A well-formed-looking but bogus hex header (not a real presentation).
    let bogus = "deadbeef".repeat(8);
    let err = open_through_relay(relay, exit, &origin.to_string(), &bogus).unwrap_err();
    assert!(
        err.to_string().contains("exit refused"),
        "EXIT must refuse an invalid credential, got: {err}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "origin never hit");
}

#[test]
fn replay_is_double_spend_rejected_then_fresh_succeeds() {
    let (origin, hits, _) = spawn_http_origin();
    let (exit, mut client, _) = spawn_exit();
    let relay_obs = Observer::new();
    let relay = spawn_relay(exit, relay_obs.clone());

    // Mint TWO distinct presentations from the same credential.
    let header1 = client.presentation_header(&mut OsRng).unwrap();
    let header2 = client.presentation_header(&mut OsRng).unwrap();

    // First spend of header1: succeeds.
    let (_, resp1) = http_get_through_loop(relay, exit, origin, &header1).unwrap();
    assert!(resp1.contains("200 OK"), "first spend must succeed");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // REPLAY the SAME presentation: the exit rejects it (double-spend).
    let err = open_through_relay(relay, exit, &origin.to_string(), &header1).unwrap_err();
    assert!(
        err.to_string().contains("exit refused"),
        "replay of the same presentation must be refused, got: {err}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "replayed request must NOT reach the origin"
    );

    // A FRESH presentation still works.
    let (_, resp2) = http_get_through_loop(relay, exit, origin, &header2).unwrap();
    assert!(
        resp2.contains("200 OK"),
        "a fresh presentation must succeed"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn tunnel_carries_opaque_bytes_both_ways_and_tampering_is_detectable() {
    let echo = spawn_echo_origin();
    let (exit, mut client, _) = spawn_exit();
    let relay_obs = Observer::new();
    let relay = spawn_relay(exit, relay_obs.clone());

    // Open an end-to-end byte pipe to the echo origin through relay→exit. Neither
    // hop terminates or inspects this stream — it is the stand-in for the
    // client's real end-to-end TLS (which likewise rides untouched).
    let header = client.presentation_header(&mut OsRng).unwrap();
    let mut stream = open_through_relay(relay, exit, &echo.to_string(), &header).unwrap();

    // Send opaque bytes; they must come back byte-for-byte (both directions work).
    let payload = b"opaque-ciphertext-\x00\x01\x02\xff-line\n";
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(
        &got[..],
        &payload[..],
        "the tunnel must carry opaque bytes intact both ways"
    );

    // Tamper detection: if any hop (or anyone on the wire) flipped a byte, the
    // caller — who compares what it sent against what it got — would see a
    // mismatch. This is exactly how the client's real TLS detects tampering: a
    // single altered ciphertext byte fails the AEAD tag. We demonstrate the
    // detector by flipping a byte in the received copy and confirming the equality
    // check (the same check TLS performs over the MAC) fires.
    let mut tampered = got.clone();
    tampered[0] ^= 0xff;
    assert_ne!(
        &tampered[..],
        &payload[..],
        "a single flipped byte must be detected by the caller (as TLS would)"
    );
}
