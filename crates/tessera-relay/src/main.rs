//! `tessera-relay` binary: stands up the **2-hop split-trust loop** locally —
//! a credential-blind RELAY (first hop) in front of a credential-gated EXIT
//! (`tessera-proxy`) — and prints how to drive it with `curl`.
//!
//! ```text
//! curl --proxy http://RELAY  →  RELAY  →  EXIT (checks the credential)  →  site
//! ```
//!
//! The relay learns only {client, exit}; the exit learns only {destination, a
//! valid credential}; neither sees content. This proves the *protocol*; a real
//! Tor-blocked site returning 200 needs a real clean egress IP (see the README).
//!
//! Run:  `cargo run -p tessera-relay`            (exit egresses directly)
//!       `cargo run -p tessera-relay -- --tor`   (exit egresses via Tor :9050)

use std::net::{TcpListener, ToSocketAddrs};
use std::sync::Arc;

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::serve as serve_relay;

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

fn issue(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

fn main() {
    // Deploy mode (env): run JUST the relay first hop, forwarding to an EXTERNAL
    // exit — for a containerized/TEE node (see docs/DEPLOY.md). When both are set
    // we skip the all-in-one local demo below. The exit address is resolved once
    // at startup (a hostname like `exit:8118` resolves via the container DNS).
    if let (Ok(listen), Ok(exit)) = (
        std::env::var("TESSERA_RELAY_LISTEN"),
        std::env::var("TESSERA_EXIT_ADDR"),
    ) {
        let exit_addr = exit
            .to_socket_addrs()
            .expect("TESSERA_EXIT_ADDR must be HOST:PORT")
            .next()
            .expect("TESSERA_EXIT_ADDR did not resolve");
        let listener = TcpListener::bind(&listen).expect("bind relay");
        let addr = listener.local_addr().expect("relay addr");
        println!(
            "Tessera RELAY node live on {addr} -> exit {exit_addr} \
             (credential-blind first hop; learns {{client, exit}}, never the destination)"
        );
        let _ = serve_relay(listener, exit_addr, None).join();
        return;
    }

    let tor = std::env::args().any(|a| a == "--tor");
    let mut rng = OsRng;

    // --- EXIT: the credential-gated CONNECT proxy (tessera-proxy) ---
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let credential = issue(&sk, &pk, &mut rng);

    let exit_listener = TcpListener::bind("127.0.0.1:0").expect("bind exit");
    let exit_addr = exit_listener.local_addr().expect("exit addr");
    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));
    let upstream = if tor {
        Upstream::Tor("127.0.0.1:9050".to_string())
    } else {
        Upstream::Direct
    };
    serve_exit(exit_listener, guard, upstream);

    // --- RELAY: the credential-blind first hop, fixed to forward to the exit ---
    let relay_listener = TcpListener::bind("127.0.0.1:8119")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    serve_relay(relay_listener, exit_addr, None);

    // Mint one single-use presentation to paste into the example request.
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    let header = client
        .presentation_header(&mut rng)
        .expect("mint presentation");

    let route = if tor {
        "exit egresses via Tor (SOCKS5 127.0.0.1:9050)"
    } else {
        "exit egresses directly"
    };
    println!("\nTessera 2-hop split-trust loop is live:");
    println!("  RELAY  http://{relay_addr}   (first hop — credential-blind; learns {{client, exit}}, never the destination)");
    println!("  EXIT   http://{exit_addr}   (credential-gated — learns {{destination, a valid credential}}, never the client)");
    println!("  {route}\n");
    println!("Split-trust: no single hop holds who + where + what. TLS is end-to-end (CONNECT),");
    println!("so neither hop sees plaintext. Point curl at the RELAY; it nests the inner CONNECT");
    println!("to the destination (with the credential) through to the exit:\n");
    println!("  curl -sS -x http://{relay_addr} \\");
    println!("    --proxy-header 'Tessera-Presentation: {header}' \\");
    println!("    https://example.com/\n");
    println!("Note: plain `curl -x RELAY` does a single CONNECT to the relay's *outer* target,");
    println!(
        "which the relay forwards as-is to the exit; the credential header rides on the inner"
    );
    println!("CONNECT the exit reads. (The integration test drives the exact nested form via");
    println!(
        "`tessera_relay::open_through_relay`.) A request with no/invalid credential is refused"
    );
    println!("by the EXIT with 407; the relay never sees the credential or the destination.\n");
    println!(
        "HONEST: this proves the loop LOCALLY. A real Tor-403 site returning 200 needs a real"
    );
    println!(
        "clean egress IP behind the exit (run with --tor + a clean exit) — a manual final step."
    );
    println!("Single-use credential (the rate limit). Ctrl-C to stop.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
