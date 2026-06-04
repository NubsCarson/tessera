//! `tessera-proxy` binary: a credential-gated CONNECT proxy you point a normal
//! HTTPS client at. Admits on a Tessera credential, never the IP; tunnels TLS
//! end-to-end to any HTTPS site (e.g. the Anthropic API), optionally via Tor.
//!
//! Run:  `cargo run -p tessera-proxy`           (direct upstream)
//!       `cargo run -p tessera-proxy -- --tor`  (tunnel through Tor at :9050)

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve_observed_shaped, ShapingConfig, Upstream, VolumeShaper};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

fn issue(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

fn main() {
    let tor = std::env::args().any(|a| a == "--tor");
    let mut rng = OsRng;

    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let credential = issue(&sk, &pk, &mut rng);

    let listener = TcpListener::bind("127.0.0.1:8118")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let guard = Arc::new(OriginGuard::new(sk, pk, REQUEST_CTX, PRESENT_CTX, LIMIT));
    let upstream = if tor {
        Upstream::Tor("127.0.0.1:9050".to_string())
    } else {
        Upstream::Direct
    };
    // Per-egress-IP human-volume shaping (M5): keep this egress IP's outbound
    // traffic within a human-plausible envelope (bounded distinct destinations,
    // concurrency, jitter, sticky sessions) so a clean IP is not burned by
    // bot-shaped fan-out. Over-envelope traffic is paced gracefully, never blocked.
    let shaper = Arc::new(Mutex::new(VolumeShaper::new(
        ShapingConfig::default(),
        addr.port() as u64,
    )));
    serve_observed_shaped(listener, guard, upstream, None, Some(shaper));

    // Mint a few single-use credentials to paste into example requests.
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);
    let header = client
        .presentation_header(&mut rng)
        .expect("mint presentation");

    let route = if tor {
        "via Tor (SOCKS5 127.0.0.1:9050)"
    } else {
        "direct"
    };
    println!("\nTessera proxy live on http://{addr}  ·  admits on a credential, never your IP  ·  {route}");
    println!("It tunnels TLS end-to-end (CONNECT), so it never sees your plaintext.");
    println!(
        "Egress is human-volume shaped (M5): bot-shaped fan-out is paced, never the IP burned.\n"
    );
    println!(
        "Send any HTTPS request through it (single-use credential — the rate limit; restart for more). Example:\n"
    );
    println!("  curl -sS -x http://{addr} \\");
    println!("    --proxy-header 'Tessera-Presentation: {header}' \\");
    println!("    https://api.anthropic.com/v1/messages \\");
    println!("    -H \"x-api-key: $ANTHROPIC_API_KEY\" -H 'anthropic-version: 2023-06-01' \\");
    println!("    -H 'content-type: application/json' \\");
    println!(
        "    -d '{{\"model\":\"claude-opus-4-8\",\"max_tokens\":64,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}'\n"
    );
    println!("A request with no/invalid credential gets 407 Proxy Authentication Required. Ctrl-C to stop.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
