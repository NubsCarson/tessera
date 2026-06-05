//! `tessera-client` binary: the **local client proxy** a person runs. It obtains
//! a credential from a `tessera-issuer` node over the wire (paying the PoW), then
//! exposes a local HTTP `CONNECT` proxy. Point your browser/curl at it and every
//! request is admitted at the **exit** on a fresh, unlinkable token — the exit
//! never sees your IP — routed through the 2-hop loop (relay → exit). When the
//! credential's budget is spent it transparently re-issues.
//!
//! Honest caveat: obtaining the credential connects you **directly to the
//! issuer**, which therefore sees your IP at issuance time. ARC unlinkability
//! still prevents the issuer from tying that to your later browsing, but the act
//! of issuance is not hidden — run this client over Tor if you need to hide it.
//!
//! Config (env):
//!   `TESSERA_ISSUER`        issuer node `HOST:PORT` (default `127.0.0.1:8121`)
//!   `TESSERA_RELAY`         relay node  `HOST:PORT` (default `127.0.0.1:8119`)
//!   `TESSERA_EXIT`          exit node   `HOST:PORT` (default `127.0.0.1:8118`)
//!   `TESSERA_CLIENT_LISTEN` local proxy bind        (default `127.0.0.1:8120`)
//!   `TESSERA_ISSUER_PK`     hex pin: the issuer pk (or its fingerprint prefix)
//!                           the issuance must match (recommended; else trust-on-first-use)
//!
//! Then: `curl -x http://127.0.0.1:8120 https://example.com`

use std::net::{TcpListener, ToSocketAddrs};

use tessera_client::obtain_credential;
use tessera_relay::{serve_client_proxy, CredentialSource};

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://proxy/v1";
const LIMIT: u64 = 64;

fn resolve(var: &str, default: &str) -> std::net::SocketAddr {
    let spec = std::env::var(var).unwrap_or_else(|_| default.into());
    spec.to_socket_addrs()
        .unwrap_or_else(|_| panic!("{var}={spec} must be HOST:PORT"))
        .next()
        .unwrap_or_else(|| panic!("{var}={spec} did not resolve"))
}

fn main() {
    let issuer = std::env::var("TESSERA_ISSUER").unwrap_or_else(|_| "127.0.0.1:8121".into());
    let relay_addr = resolve("TESSERA_RELAY", "127.0.0.1:8119");
    let exit_addr = resolve("TESSERA_EXIT", "127.0.0.1:8118");
    let listen = std::env::var("TESSERA_CLIENT_LISTEN").unwrap_or_else(|_| "127.0.0.1:8120".into());
    let pin = std::env::var("TESSERA_ISSUER_PK")
        .ok()
        .and_then(|h| hex::decode(h.trim()).ok())
        .filter(|p| !p.is_empty());

    if pin.is_none() {
        eprintln!(
            "warning: no TESSERA_ISSUER_PK pin set — trusting the issuer's key on first use. \
             Set it to the issuer's printed fingerprint to prevent a substituted issuer."
        );
    }

    eprintln!(
        "Tessera CLIENT: obtaining a credential from issuer {issuer} (paying proof-of-work)…"
    );
    let credential = obtain_credential(&issuer, REQUEST_CTX, pin.as_deref())
        .unwrap_or_else(|e| panic!("could not obtain a credential from {issuer}: {e}"));
    eprintln!("Tessera CLIENT: credential obtained.");

    let source = CredentialSource::new(
        credential,
        issuer.clone(),
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
        pin,
    );

    let listener = TcpListener::bind(&listen)
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind client proxy");
    let addr = listener.local_addr().expect("client proxy addr");

    println!("\nTessera client proxy live on http://{addr}");
    println!("  route: you → (this proxy) → RELAY {relay_addr} → EXIT {exit_addr} → destination");
    println!(
        "  the EXIT admits each request on a fresh unlinkable token, never your IP; re-issues when spent."
    );
    println!(
        "  note: issuance connected you to the issuer {issuer}, which saw your IP (ARC still can't link"
    );
    println!("        it to your browsing). Run this client over Tor to hide issuance too.");
    println!("\n  curl -x http://{addr} https://example.com\n");

    serve_client_proxy(listener, relay_addr, exit_addr, source)
        .join()
        .expect("client proxy thread");
}
