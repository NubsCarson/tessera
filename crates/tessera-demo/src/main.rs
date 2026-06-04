//! Tessera end-to-end demo.
//!
//! Spins up a real (localhost) HTTP origin guarded by `tessera-origin`, issues
//! an anonymous ARC credential to a `tessera-client`, and makes real HTTP
//! requests through it — with and without a credential, over the limit, and
//! replayed — narrating the whole thing. With `--tor` it additionally exposes
//! the origin as a Tor onion service and drives it over a real Tor circuit, to
//! show that *anonymous transport* is admitted purely on the credential.
//!
//! Run:  `cargo run -p tessera-demo`        (rock-solid localhost flow)
//!       `cargo run -p tessera-demo -- --tor`  (also prove it over Tor)

mod net;
mod tor;
mod ui;

use std::net::TcpListener;
use std::sync::Arc;

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;

const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://origin.demo/v1";
const LIMIT: u64 = 3;

fn issue_credential(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--serve") {
        serve_mode();
        return;
    }
    let want_tor = args.iter().any(|a| a == "--tor");
    let mut rng = OsRng;

    ui::banner();

    // ---- 1. Server key setup -------------------------------------------
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let fp = hex::encode(&pk.serialize()[..8]);
    ui::step(
        "Server set up its keys",
        &format!("public key fingerprint {fp}…  ·  presentation limit {LIMIT}"),
    );

    // ---- 2. Issue a credential to the client ---------------------------
    let credential = issue_credential(&sk, &pk, &mut rng);
    ui::step(
        "Client obtained an anonymous credential",
        "issuance is unlinkable: the server cannot tie this credential to any later request",
    );

    // ---- 3. Stand up the guarded origin --------------------------------
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let guard = Arc::new(OriginGuard::new(
        sk.clone(),
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
    ));
    net::serve(listener, Arc::clone(&guard), None);
    ui::step(
        "Origin is live",
        &format!("listening on http://{addr}  ·  it will NEVER inspect your IP address"),
    );

    let addr_s = addr.to_string();
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);

    // ---- 4. The world as it is today -----------------------------------
    ui::section("What every Tor user gets today");
    let r = net::get_direct(&addr_s, None).expect("request");
    ui::result(
        r.status == 403,
        "anonymous request, no credential",
        r.status,
        &r.result,
    );

    // ---- 5. The world with Tessera -------------------------------------
    ui::section("The same anonymous client, now carrying a credential");
    let mut first_header = None;
    for i in 1..=LIMIT {
        let header = client.presentation_header(&mut rng).expect("under limit");
        if i == 1 {
            first_header = Some(header.clone());
        }
        let r = net::get_direct(&addr_s, Some(&header)).expect("request");
        let tag = r.result.strip_prefix("admit tag=").unwrap_or(&r.result);
        // Char-based truncation: never slices a multi-byte boundary even if a
        // hostile server returned a non-ASCII Tessera-Result header.
        let tag_short: String = tag.chars().take(16).collect();
        ui::result(
            r.status == 200,
            &format!("request #{i}  ·  tag {tag_short}…"),
            r.status,
            "admitted — distinct, unlinkable tag each time",
        );
    }

    // ---- 6. Abuse is bounded -------------------------------------------
    ui::section("Abuse is cryptographically bounded");
    match client.presentation_header(&mut rng) {
        Err(_) => ui::result(
            true,
            "request #4 (over the limit)",
            0,
            "client refuses to over-present — doing so would break its own unlinkability",
        ),
        Ok(_) => unreachable!("limit must be enforced client-side"),
    }
    let replay = first_header.expect("captured");
    let r = net::get_direct(&addr_s, Some(&replay)).expect("request");
    ui::result(
        r.status == 403,
        "replay of request #1's credential",
        r.status,
        &r.result,
    );

    ui::summary();

    // ---- 7. Optional: prove it over a real Tor circuit -----------------
    if want_tor {
        ui::section("Bonus: over a real Tor circuit (onion service)");
        match tor::run_onion_demo(addr.port(), &sk, &pk, &mut rng) {
            Ok(()) => {}
            Err(e) => ui::note(&format!(
                "Tor path skipped ({e}). The localhost result above already proves the thesis; \
                 the onion service just shows it surviving a real anonymous transport."
            )),
        }
    } else {
        ui::note("Re-run with `--tor` to additionally prove this over a real Tor onion circuit.");
    }
}

/// `--serve`: stand up the guarded origin and leave it running so you can hit it
/// from a browser. Prints the blocked URL plus a batch of single-use "admit"
/// links (credential carried in a `?t=` query param for browser convenience).
fn serve_mode() {
    const SERVE_LIMIT: u64 = 24;
    let mut rng = OsRng;

    ui::banner();
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let credential = issue_credential(&sk, &pk, &mut rng);

    // Prefer a stable, shareable port; fall back to an ephemeral one if taken.
    let listener = TcpListener::bind("127.0.0.1:8088")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");

    let guard = Arc::new(OriginGuard::new(
        sk,
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        SERVE_LIMIT,
    ));

    // Mint a batch of single-use "enter with a credential" links.
    let mut client = TesseraClient::new(credential, PRESENT_CTX, SERVE_LIMIT);
    let mut buttons = String::new();
    let mut n = 0;
    while let Ok(header) = client.presentation_header(&mut rng) {
        n += 1;
        buttons.push_str(&format!(
            "<a href='/?t={header}' style='display:inline-block;margin:.35rem;padding:.7rem 1.1rem;\
             background:#9ece6a;color:#1a1b26;border-radius:9px;text-decoration:none;font-weight:600'>\
             🔓 Enter with credential #{n}</a>"
        ));
    }

    // The origin serves this self-explanatory hub at `/`.
    let landing = format!(
        "<!doctype html><meta charset=utf-8><title>Tessera — live demo</title>\
         <body style='font:17px/1.65 system-ui;max-width:46rem;margin:3rem auto;\
         background:#24283b;color:#c0caf5;padding:0 1.25rem'>\
         <h1 style='color:#7dcfff'>Tessera — live demo</h1>\
         <p>This is a real web origin. It decides whether to let you in <b>purely from a \
         cryptographic credential</b> — it never looks at your IP address. Click a button and \
         watch the page.</p>\
         <h3 style='color:#9ece6a'>1 · Enter carrying an anonymous credential</h3>\
         <p style='color:#565f89'>Each button is one credential. You'll be admitted, and shown a \
         tag the server can't link to any other visit. <b>Reload</b> an admitted page → blocked \
         for double-spend (the rate limit).</p>\
         <div>{buttons}</div>\
         <h3 style='color:#f7768e;margin-top:2rem'>2 · Enter with no credential (what Tor gets today)</h3>\
         <p><a href='/blocked' style='display:inline-block;padding:.7rem 1.1rem;background:#f7768e;\
         color:#1a1b26;border-radius:9px;text-decoration:none;font-weight:600'>🔒 Enter with NO credential</a></p>\
         <p style='color:#565f89;margin-top:2rem'>{n} credentials minted for this session. The whole \
         point: a cooperating site can safely admit anonymous traffic, so it has no reason to block Tor.</p>\
         </body>"
    );

    net::serve(listener, guard, Some(landing));

    ui::step(
        "Origin is LIVE — your browser should open automatically",
        &format!("serving on {base}  ·  it never reads your IP  ·  Ctrl-C here to stop"),
    );
    ui::note(&format!("If the browser didn't open, go to:  {base}"));

    // Best-effort: open the user's browser straight to the hub page.
    let _ = std::process::Command::new("xdg-open").arg(&base).spawn();

    // Keep the process (and the origin thread) alive.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
