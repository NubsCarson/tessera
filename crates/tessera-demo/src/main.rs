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
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use tessera_arc::arc::{create_credential_response, Credential};
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_issuer::{solve, ChallengeStore};
use tessera_origin::OriginGuard;

/// Proof-of-work difficulty (leading zero bits) the demo's issuer requires.
/// 16 is sub-second to solve; a real deployment tunes this to its abuse model.
const POW_DIFFICULTY: u32 = 16;
const REQUEST_CTX: &[u8] = b"tessera://issue/v1";
const PRESENT_CTX: &[u8] = b"tessera://origin.demo/v1";
const LIMIT: u64 = 3;
/// Per-credential presentation budget in `--serve` mode (the minter re-issues
/// when it runs out, so this is just how often a fresh credential is minted).
const SERVE_LIMIT: u64 = 1000;

fn issue_credential(sk: &ServerPrivateKey, pk: &ServerPublicKey, rng: &mut OsRng) -> Credential {
    let (pending, request) = begin_issuance(REQUEST_CTX, *pk, rng);
    let response = create_credential_response(sk, pk, &request, rng).expect("request verifies");
    pending.finalize(&response).expect("response verifies")
}

/// Load the server key from a (0600) file so restarts keep the same identity,
/// or generate + persist one on first run. Demonstrates `ServerPrivateKey`
/// serialization; best-effort, demo-only persistence.
fn load_or_create_server_key(rng: &mut OsRng) -> (ServerPrivateKey, ServerPublicKey, bool) {
    let path = std::env::temp_dir().join("tessera-demo-server.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(sk) = ServerPrivateKey::from_bytes(&bytes) {
            let pk = sk.public_key();
            return (sk, pk, true);
        }
    }
    let (sk, pk) = ServerPrivateKey::setup(rng);
    if std::fs::write(&path, sk.serialize()).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    (sk, pk, false)
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

    // ---- 2. Earn the right to be issued: proof-of-work gate ------------
    ui::section("Earning a credential (issuance gate)");
    let mut challenges = ChallengeStore::new();
    let challenge = challenges.issue(&mut rng, POW_DIFFICULTY);
    let solution = solve(&challenge); // the client pays CPU here
    let earned = challenges.redeem(&challenge, &solution);
    ui::result(
        earned,
        &format!("client solved a {POW_DIFFICULTY}-bit proof-of-work"),
        if earned { 200 } else { 0 },
        "makes bulk credential-minting cost CPU — the real abuse lever is issuance",
    );

    // ---- 3. Issue a credential to the client ---------------------------
    let credential = issue_credential(&sk, &pk, &mut rng);
    ui::step(
        "Client obtained an anonymous credential",
        "issuance is unlinkable: the server cannot tie this credential to any later request",
    );

    // ---- 4. Stand up the guarded origin --------------------------------
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let guard = Arc::new(OriginGuard::new(
        sk.clone(),
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        LIMIT,
    ));
    net::serve(listener, Arc::clone(&guard), None, None);
    ui::step(
        "Origin is live",
        &format!("listening on http://{addr}  ·  it will NEVER inspect your IP address"),
    );

    let addr_s = addr.to_string();
    let mut client = TesseraClient::new(credential, PRESENT_CTX, LIMIT);

    // ---- 5. The world as it is today -----------------------------------
    ui::section("What every Tor user gets today");
    let r = net::get_direct(&addr_s, None).expect("request");
    ui::result(
        r.status == 403,
        "anonymous request, no credential",
        r.status,
        &r.result,
    );

    // ---- 6. The world with Tessera -------------------------------------
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

    // ---- 7. Abuse is bounded -------------------------------------------
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

    // ---- 8. Optional: prove it over a real Tor circuit -----------------
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
/// from a browser, and auto-open it. Each click of "Enter" mints a *fresh*
/// single-use credential via the `/enter` route, so the demo never gets "used
/// up" — you only see a double-spend by deliberately reloading an admitted page.
fn serve_mode() {
    let mut rng = OsRng;

    ui::banner();
    let (sk, pk, loaded) = load_or_create_server_key(&mut rng);
    ui::step(
        if loaded {
            "Server key loaded from disk (identity persists across restarts)"
        } else {
            "Server key generated and persisted (0600)"
        },
        "demonstrates ServerPrivateKey serialization; the key is secret material",
    );

    // Prefer a stable, shareable port; fall back to an ephemeral one if taken.
    let listener = TcpListener::bind("127.0.0.1:8088")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");

    let guard = Arc::new(OriginGuard::new(
        sk.clone(),
        pk,
        REQUEST_CTX,
        PRESENT_CTX,
        SERVE_LIMIT,
    ));

    // A self-refilling minter: hands out a fresh presentation on each `/enter`,
    // transparently re-issuing a new credential when the budget runs out, so the
    // demo can be clicked indefinitely.
    let initial = issue_credential(&sk, &pk, &mut rng);
    let minter_state = Mutex::new(MinterState {
        sk,
        pk,
        client: TesseraClient::new(initial, PRESENT_CTX, SERVE_LIMIT),
    });
    let minter: net::Minter = Arc::new(move || minter_state.lock().expect("minter mutex").fresh());

    // One green button (always works) + one red button (no credential).
    let landing = "<!doctype html><meta charset=utf-8><title>Tessera — live demo</title>\
         <body style='font:17px/1.65 system-ui;max-width:46rem;margin:3rem auto;\
         background:#24283b;color:#c0caf5;padding:0 1.25rem'>\
         <h1 style='color:#7dcfff'>Tessera — live demo</h1>\
         <p>This is a real web origin. It decides whether to let you in <b>purely from a \
         cryptographic credential</b> — it never looks at your IP address. Click a button:</p>\
         <p style='margin:1.5rem 0'>\
         <a href='/enter' style='display:inline-block;padding:.8rem 1.3rem;background:#9ece6a;\
         color:#1a1b26;border-radius:10px;text-decoration:none;font-weight:700;font-size:1.05rem'>\
         🔓 Enter with an anonymous credential</a></p>\
         <p style='margin:1.5rem 0'>\
         <a href='/blocked' style='display:inline-block;padding:.8rem 1.3rem;background:#f7768e;\
         color:#1a1b26;border-radius:10px;text-decoration:none;font-weight:700;font-size:1.05rem'>\
         🔒 Enter with NO credential</a>\
         <span style='color:#565f89'> &nbsp;— what every Tor user gets today</span></p>\
         <p style='color:#565f89;margin-top:1.5rem'>Green admits you and shows an unlinkable tag; \
         the server can't tie it to any other visit. On the admitted page, <b>reload</b> to watch \
         the same credential get rejected for double-spend — that's the rate limit. Each green \
         click mints a brand-new credential, so it always works.</p>\
         </body>"
        .to_string();

    net::serve(listener, guard, Some(landing), Some(minter));

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

/// Holds the issuer keys + a client, and mints a fresh presentation on demand,
/// re-issuing a new credential whenever the current one's budget is exhausted.
struct MinterState {
    sk: ServerPrivateKey,
    pk: ServerPublicKey,
    client: TesseraClient,
}

impl MinterState {
    /// A fresh, hex-encoded presentation — never fails, never runs dry.
    fn fresh(&mut self) -> String {
        let mut rng = OsRng;
        loop {
            match self.client.presentation_header(&mut rng) {
                Ok(header) => return header,
                Err(_) => {
                    // Budget exhausted: issue a new credential and keep going.
                    let cred = issue_credential(&self.sk, &self.pk, &mut rng);
                    self.client = TesseraClient::new(cred, PRESENT_CTX, SERVE_LIMIT);
                }
            }
        }
    }
}
