//! End-to-end **network** test: a real over-the-wire issuance + the local client
//! proxy, all four nodes in-process. Proves the "run it yourself" path:
//!
//! ```text
//! client-proxy ──┐                          obtains a credential from
//!  (CONNECT)      │  open_through_relay      ┌───────────────┐
//! browser ──▶ CLIENT-PROXY ──▶ RELAY ──▶ EXIT ──▶ echo dest   ISSUER (PoW-gated)
//!                                   (verifies the token against the SHARED key)
//! ```
//!
//! The issuer and exit share ONE ARC key (keyed-verification); the client pays
//! the PoW, gets a credential over the wire, and its presentations verify at the
//! exit. No external network, no TLS — the destination is a local echo server.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{
    obtain_credential, obtain_credential_paid, CapacityEnvelope, DirectorySnapshot,
    ExitDirectoryEntry, SignedExitDirectory, TesseraClient,
};
use tessera_issuer::mint::{
    address_of, InMemoryEntitlement, PaymentGate, RedemptionLedger, TOKENS_PER_CREDENTIAL,
};
use tessera_issuer::{serve_issuance, serve_issuance_paid};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::open_through_relay;
use tessera_relay::{serve as serve_relay, serve_client_proxy, CredentialSource};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const DIFFICULTY: u32 = 8; // low so the test's PoW is instant

/// One-shot echo destination: replies `PONG\n` to a `PING\n`.
fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
    addr
}

/// Stand up issuer + relay + exit + local client proxy sharing one ARC key, with
/// the given per-credential `limit`. Returns the local client-proxy address.
fn spawn_network(limit: u64) -> SocketAddr {
    // ONE key shared by the issuer (authority) and the exit (verifier).
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let sk_exit = ServerPrivateKey::from_bytes(&sk.serialize()).unwrap();

    // EXIT — credential-gated, egresses Direct to the echo dest.
    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(
        sk_exit,
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        limit,
    ));
    serve_exit(exit_listener, guard, Upstream::Direct);

    // RELAY — credential-blind first hop, forwards to the exit.
    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    serve_relay(relay_listener, exit_addr, None);

    // ISSUER — PoW-gated authority holding the same key.
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);
    let issuer_str = issuer_addr.to_string();

    // CLIENT — obtain a credential over the wire, run the local proxy.
    let credential = obtain_credential(&issuer_str, REQUEST_CTX, None)
        .expect("obtain a credential from the issuer");
    let source = CredentialSource::new(
        credential,
        issuer_str,
        REQUEST_CTX,
        PRESENT_CTX,
        limit,
        None,
        None,
    );
    let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    serve_client_proxy(client_listener, relay_addr, exit_addr, source);

    client_addr
}

struct ExitDomain {
    issuer_addr: String,
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    issuer_pk: Vec<u8>,
}

fn spawn_exit_domain(limit: u64) -> ExitDomain {
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let sk_exit = ServerPrivateKey::from_bytes(&sk.serialize()).unwrap();

    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(
        sk_exit,
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        limit,
    ));
    serve_exit(exit_listener, guard, Upstream::Direct);

    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    serve_relay(relay_listener, exit_addr, None);

    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap().to_string();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);

    ExitDomain {
        issuer_addr,
        relay_addr,
        exit_addr,
        issuer_pk: pk.serialize().to_vec(),
    }
}

/// Drive one request through the client proxy to `dest`; returns true iff the
/// tunnel established (`200`) and the echo round-tripped (`PONG`).
fn request_through(proxy: SocketAddr, dest: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect(proxy) else {
        return false;
    };
    if s.write_all(format!("CONNECT {dest} HTTP/1.1\r\n\r\n").as_bytes())
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    if BufReader::new(s.try_clone().unwrap())
        .read_line(&mut line)
        .is_err()
    {
        return false;
    }
    if !line.contains("200") {
        return false;
    }
    if s.write_all(b"PING\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).is_ok() && &buf == b"PONG\n"
}

#[test]
fn full_network_loop_credential_over_the_wire() {
    let echo = spawn_echo();
    let proxy = spawn_network(64);
    assert!(
        request_through(proxy, echo),
        "a request through the client proxy (token obtained over the wire) must reach the dest"
    );
}

#[test]
fn client_proxy_reissues_when_budget_spent() {
    let echo = spawn_echo();
    // limit = 2: the 3rd request forces a transparent re-issue from the issuer.
    let proxy = spawn_network(2);
    for i in 0..5 {
        assert!(
            request_through(proxy, echo),
            "request {i} must succeed (auto re-issue past the per-credential budget)"
        );
    }
}

#[test]
fn issuer_pk_pin_mismatch_is_rejected() {
    // Stand up just an issuer; obtaining with a wrong pin must fail closed.
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap().to_string();
    serve_issuance(issuer_listener, sk, pk, DIFFICULTY);

    // The real fingerprint would match; a deliberately wrong prefix must not.
    let wrong_pin = [0xAAu8; 8];
    let err = obtain_credential(&issuer_addr, REQUEST_CTX, Some(&wrong_pin));
    assert!(err.is_err(), "a mismatched issuer-pk pin must be rejected");

    // And the correct pin (the issuer's real pk prefix) must succeed.
    let good_prefix = pk.serialize()[..8].to_vec();
    let ok = obtain_credential(&issuer_addr, REQUEST_CTX, Some(&good_prefix));
    assert!(ok.is_ok(), "the correct issuer-pk pin must be accepted");
}

#[test]
fn signed_directory_selects_one_exit_domain_and_cross_domain_credentials_fail() {
    let echo = spawn_echo();
    let domain_a = spawn_exit_domain(64);
    let domain_b = spawn_exit_domain(64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signer = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let snapshot = DirectorySnapshot::new(
        1,
        now.saturating_sub(60),
        now + 3600,
        vec![
            ExitDirectoryEntry::current_protocols_with_capacity(
                "exit-a",
                domain_a.relay_addr.to_string(),
                domain_a.exit_addr.to_string(),
                domain_a.issuer_addr.clone(),
                domain_a.issuer_pk.clone(),
                10,
                true,
                CapacityEnvelope::new(1, 10, 10, 3600, 1000).unwrap(),
            )
            .unwrap(),
            ExitDirectoryEntry::current_protocols_with_capacity(
                "exit-b",
                domain_b.relay_addr.to_string(),
                domain_b.exit_addr.to_string(),
                domain_b.issuer_addr.clone(),
                domain_b.issuer_pk.clone(),
                20,
                true,
                CapacityEnvelope::new(1, 10, 10, 3600, 1000).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let directory = SignedExitDirectory::sign(snapshot, std::slice::from_ref(&signer)).unwrap();
    directory
        .verify_at(
            &[signer
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()],
            1,
            now,
        )
        .unwrap();

    let selected = directory.snapshot.select(None).unwrap();
    assert_eq!(selected.id, "exit-b", "default route uses highest weight");
    let credential = obtain_credential(
        &selected.issuer_addr,
        REQUEST_CTX,
        Some(&selected.issuer_pk),
    )
    .expect("selected directory issuer key pin must match");
    let mut client = TesseraClient::new(credential, PRESENT_CTX, 64);
    let header = client.presentation_header(&mut rand_core::OsRng).unwrap();
    let mut stream = open_through_relay(
        selected.relay_addr.parse().unwrap(),
        selected.exit_addr.parse().unwrap(),
        &echo.to_string(),
        &header,
    )
    .expect("selected domain route opens");
    stream.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"PONG\n", "selected domain reaches origin");

    let credential_a = obtain_credential(
        &domain_a.issuer_addr,
        REQUEST_CTX,
        Some(&domain_a.issuer_pk),
    )
    .expect("domain A issuance works");
    let mut client_a = TesseraClient::new(credential_a, PRESENT_CTX, 64);
    let header_a = client_a.presentation_header(&mut rand_core::OsRng).unwrap();
    assert!(
        open_through_relay(
            domain_b.relay_addr,
            domain_b.exit_addr,
            &echo.to_string(),
            &header_a
        )
        .is_err(),
        "domain A credential must not verify at domain B exit"
    );

    let wrong_issuer_pin = obtain_credential(
        &domain_a.issuer_addr,
        REQUEST_CTX,
        Some(&domain_b.issuer_pk),
    );
    assert!(
        wrong_issuer_pin.is_err(),
        "directory entry with issuer_addr=A but issuer_pk=B must fail during issuance pin check"
    );

    let credential_b = obtain_credential(
        &domain_b.issuer_addr,
        REQUEST_CTX,
        Some(&domain_b.issuer_pk),
    )
    .expect("domain B issuance works");
    let mut client_b = TesseraClient::new(credential_b, PRESENT_CTX, 64);
    let header_b = client_b.presentation_header(&mut rand_core::OsRng).unwrap();
    assert!(
        open_through_relay(
            domain_a.relay_addr,
            domain_a.exit_addr,
            &echo.to_string(),
            &header_b
        )
        .is_err(),
        "directory entry with issuer=B but exit=A must fail at exit verification"
    );
}

#[test]
fn paid_issuance_admits_buyer_routes_and_rejects_unpaid() {
    // A PAID issuer (TokenMint-gated) instead of PoW: the buyer proves control of
    // an address holding entitlement, gets a credential, and routes through the
    // loop; a buyer who never paid is refused.
    let echo = spawn_echo();

    // issuer + exit share one ARC key.
    let (sk, pk) = ServerPrivateKey::setup(&mut rand_core::OsRng);
    let sk_exit = ServerPrivateKey::from_bytes(&sk.serialize()).unwrap();

    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(sk_exit, pk, REQUEST_CTX, PRESENT_CTX, 64));
    serve_exit(exit_listener, guard, Upstream::Direct);

    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    serve_relay(relay_listener, exit_addr, None);

    // The buyer paid for one credential's worth of tokens; the issuer gates on it.
    let buyer_secret = [5u8; 32];
    let buyer = address_of(&buyer_secret).unwrap();
    let mut entitlement = HashMap::new();
    entitlement.insert(buyer, TOKENS_PER_CREDENTIAL);
    let gate = PaymentGate::new(
        InMemoryEntitlement(entitlement),
        RedemptionLedger::in_memory(),
        TOKENS_PER_CREDENTIAL,
    );
    let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer_addr = issuer_listener.local_addr().unwrap().to_string();
    let pin = pk.serialize()[..8].to_vec(); // paid mode requires pinning the issuer pk
    serve_issuance_paid(issuer_listener, sk, pk, gate);

    // Paid buyer: obtain a credential, route a request through the loop.
    let cred = obtain_credential_paid(&issuer_addr, REQUEST_CTX, &buyer_secret, Some(&pin))
        .expect("paid issuance");
    let mut client = TesseraClient::new(cred, PRESENT_CTX, 64);
    let header = client.presentation_header(&mut rand_core::OsRng).unwrap();
    let mut stream =
        open_through_relay(relay_addr, exit_addr, &echo.to_string(), &header).expect("loop opens");
    stream.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"PONG\n", "paid credential routes through the loop");

    // The buyer's single credential's worth is now spent -> a second is refused.
    assert!(
        obtain_credential_paid(&issuer_addr, REQUEST_CTX, &buyer_secret, Some(&pin)).is_err(),
        "entitlement exhausted -> refused"
    );
    // A buyer who never paid is refused outright.
    let broke = [6u8; 32];
    assert!(
        obtain_credential_paid(&issuer_addr, REQUEST_CTX, &broke, Some(&pin)).is_err(),
        "unpaid buyer -> refused"
    );
    // And a missing pin is refused (the wormhole guard).
    assert!(
        obtain_credential_paid(&issuer_addr, REQUEST_CTX, &buyer_secret, None).is_err(),
        "paid issuance without a pin -> refused"
    );
}
