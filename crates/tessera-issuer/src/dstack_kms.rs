//! `dstack-kms` key provider: derive the ARC server key from the dstack guest
//! agent inside an Intel TDX confidential VM, sealed to the enclave, never on disk.
//!
//! ## What this is
//! In a [dstack](https://github.com/Dstack-TEE/dstack) deployment the per-app
//! root key is released to the CVM by the dstack **KMS** (itself a TEE) only after
//! it verifies the CVM's TDX attestation quote. Inside the CVM, the **guest agent**
//! exposes a small HTTP/1.1 + JSON API over a Unix-domain socket (default
//! `/var/run/dstack.sock`). We `POST /GetKey` to obtain a deterministic,
//! attested, enclave-bound secret and expand it into the ARC [`ServerPrivateKey`].
//! Because the derivation is deterministic in the app identity + key path, an
//! issuer and its paired exit in the same app converge on the **same** ARC key
//! with no shared key file — and the key only ever lives in process memory.
//!
//! The transport is hand-rolled std-only (a minimal HTTP request over
//! [`UnixStream`]), mirroring the issuer's existing `mint::eth_call` reader — no
//! async runtime, no SDK, no protobuf (despite the "pRPC" name the agent speaks
//! JSON on this socket). The 32-byte secret is **never** used as a curve scalar
//! directly: it seeds the canonical `SetupServer()` keygen through a SHAKE256 XOF
//! DRBG, so all four ARC scalars stay uniform on the P-256 group.
//!
//! ## Trust / status (read this)
//! Research-grade, **UNAUDITED**. This client is validated only against a faithful
//! in-process mock and the official dstack **simulator** — it has **not** been
//! proven against real Intel TDX hardware + a live KMS, so a simulator/mock key
//! carries **no** security guarantee. It does not itself verify the returned
//! `signature_chain` / TDX quote (the KMS already gated key release on the quote
//! before the app key reached this CVM; remote *clients* verify the quote
//! out-of-band — see `docs/TRUST_MODEL.md` §4 and `docs/DEPLOY.md` §2).
//!
//! ## Fail-closed
//! Any transport, status, parse, or length error returns `Err`. The caller
//! **must not** fall back to an ephemeral or on-disk key: under keyed
//! verification a divergent or attacker-chosen ARC key both *forges* and
//! *verifies*, so a wrong key is catastrophic, not merely unavailable.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rand_core::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

use crate::key_provider::DEFAULT_DSTACK_SOCKET;

/// Cap on the guest-agent response read. A `GetKey`/`Info` body is small; even a
/// TDX quote is a few KB. Bounds a hostile/buggy socket from streaming forever.
const MAX_AGENT_RESP: u64 = 256 * 1024;

/// Socket read/write timeout — a local Unix socket answers fast or not at all.
const AGENT_TIMEOUT: Duration = Duration::from_secs(15);

/// Minimum acceptable derived-secret length. The default `secp256k1` HKDF output
/// is 32 bytes; anything shorter is rejected (fail closed) rather than stretched.
const MIN_SEED_LEN: usize = 32;

/// Domain separator mixed in before the dstack secret when seeding ARC keygen, so
/// the same dstack secret used for another purpose can never collide with this one.
const KDF_DOMAIN: &[u8] = b"tessera/dstack-kms/arc-server-key/v1";

/// Stable derivation labels. `GetKey` derives `key = HKDF(app_key, [path])`, so
/// the *path* (plus app identity) fixes the secret. Pinning these constants is
/// what makes the issuer and exit converge on one key — do not vary them.
const KEY_PURPOSE: &str = "tessera-arc-server-key";
const KEY_ALGORITHM: &str = "secp256k1";

/// Fallback socket paths probed when the configured path is the default and is
/// not connectable, mirroring the dstack SDK probe order.
const FALLBACK_SOCKETS: [&str; 3] = [
    "/run/dstack.sock",
    "/var/run/dstack/dstack.sock",
    "/run/dstack/dstack.sock",
];

/// Validate that the dstack guest-agent socket is reachable, **without** deriving
/// the key. A live agent (inside a dstack CVM) accepts the connection; off-TEE the
/// socket is absent and this fails closed — which is the correct, honest outcome
/// (you can only run a `dstack-kms` node inside a dstack CVM or against the
/// simulator).
pub fn preflight(socket: &str, _key_id: &str) -> Result<(), String> {
    for candidate in socket_candidates(socket) {
        if UnixStream::connect(&candidate).is_ok() {
            return Ok(());
        }
    }
    Err(format!(
        "dstack guest-agent socket not reachable at {socket} (or its fallbacks); \
         TESSERA_KEY_PROVIDER=dstack-kms must run inside a dstack CVM with the \
         guest-agent socket mounted (or point TESSERA_DSTACK_SOCKET at the dstack \
         simulator for testing)"
    ))
}

/// Derive the ARC server key from the dstack KMS via the guest agent's `GetKey`,
/// then expand it into a [`ServerPrivateKey`]/[`ServerPublicKey`] pair.
/// Deterministic for a fixed app identity + `key_id`, so issuer and exit converge.
pub fn establish(
    socket: &str,
    key_id: &str,
) -> Result<(ServerPrivateKey, ServerPublicKey), String> {
    let seed = get_key(socket, key_id)?;
    Ok(derive_server_key(&seed))
}

/// Expand `seed` bytes into the ARC server key by seeding the canonical
/// `SetupServer()` keygen from a domain-separated SHAKE256 XOF DRBG. The raw seed
/// is never used as a curve scalar; reusing the real keygen keeps all four scalars
/// uniform on the group. Deterministic in `seed`.
pub fn derive_server_key(seed: &[u8]) -> (ServerPrivateKey, ServerPublicKey) {
    let mut rng = SeedRng::new(seed);
    ServerPrivateKey::setup(&mut rng)
}

/// Call `GetKey` and return the raw derived secret (hex-decoded), failing closed
/// on any transport, status, parse, or length problem.
fn get_key(socket: &str, key_id: &str) -> Result<Vec<u8>, String> {
    let body = format!(
        r#"{{"path":"{path}","purpose":"{KEY_PURPOSE}","algorithm":"{KEY_ALGORITHM}"}}"#,
        path = json_escape(key_id),
    );
    let (resp, used) = agent_call(socket, "POST", "/GetKey", &body)?;
    let hexkey = extract_json_string(&resp, "key")
        .ok_or_else(|| format!("dstack GetKey response from {used} had no \"key\" field"))?;
    let trimmed = hexkey
        .strip_prefix("0x")
        .or_else(|| hexkey.strip_prefix("0X"))
        .unwrap_or(&hexkey);
    let seed =
        hex::decode(trimmed).map_err(|_| "dstack GetKey \"key\" was not valid hex".to_string())?;
    if seed.len() < MIN_SEED_LEN {
        return Err(format!(
            "dstack GetKey returned {} secret byte(s) (need >= {MIN_SEED_LEN}) — failing closed",
            seed.len()
        ));
    }
    // Defense-in-depth: an all-zero (or otherwise degenerate) secret would make the
    // ARC key fully predictable — and under keyed verification a predictable key
    // both forges AND verifies. The in-TEE agent should never return this; reject
    // it loudly (it is the unmistakable signature of a broken/stub/misconfig agent).
    if seed.iter().all(|&b| b == 0) {
        return Err("dstack GetKey returned an all-zero secret — failing closed".to_string());
    }
    Ok(seed)
}

/// The configured socket, plus the SDK fallback paths when it is the default.
fn socket_candidates(socket: &str) -> Vec<String> {
    let mut v = vec![socket.to_string()];
    if socket == DEFAULT_DSTACK_SOCKET {
        v.extend(FALLBACK_SOCKETS.iter().map(|s| s.to_string()));
    }
    v
}

/// One HTTP/1.1 request to the guest agent over the Unix socket, trying the
/// configured path then fallbacks; returns `(response_body, socket_used)`.
fn agent_call(
    socket: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(String, String), String> {
    let mut last_err = format!("no candidate socket for {socket}");
    for candidate in socket_candidates(socket) {
        match agent_call_one(&candidate, method, path, body) {
            Ok(resp) => return Ok((resp, candidate)),
            Err(e) => last_err = format!("{candidate}: {e}"),
        }
    }
    Err(format!(
        "dstack guest-agent request {method} {path} failed: {last_err}"
    ))
}

fn agent_call_one(socket: &str, method: &str, path: &str, body: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(AGENT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(AGENT_TIMEOUT));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: dstack\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    // The agent honours `Connection: close`, so read to EOF (bounded).
    let mut bytes = Vec::new();
    stream
        .take(MAX_AGENT_RESP)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read: {e}"))?;
    let resp = String::from_utf8_lossy(&bytes).into_owned();
    let (head, payload) = resp
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response (no header/body separator)".to_string())?;
    // Match the numeric status token exactly — a loose ` 200` substring could be
    // satisfied by a non-200 status whose reason phrase contains "200".
    let status_line = head.lines().next().unwrap_or_default();
    if status_line.split(' ').nth(1) != Some("200") {
        return Err(format!("non-200 status from guest agent: {status_line:?}"));
    }
    // We frame the body on Content-Length / `Connection: close`, not chunked
    // transfer-encoding; reject chunked loudly rather than silently mis-parsing it.
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return Err("guest agent used chunked transfer-encoding (unsupported)".to_string());
    }
    Ok(payload.to_string())
}

/// Extract the string value of a JSON field `"name":"<value>"` with a tolerant
/// substring scan (same style as `mint::eth_call`), sufficient for the small,
/// well-formed guest-agent responses (hex values contain no quotes/escapes).
fn extract_json_string(body: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let rest = &body[body.find(&needle)? + needle.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Minimal JSON string escaping for the operator-supplied key path/id.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Deterministic CSPRNG: a SHAKE256 extendable-output function keyed by a
/// domain-separated seed, yielding a reproducible byte stream so the ARC keygen is
/// deterministic in the seed. Used only to seed `SetupServer()` — never to produce
/// security-bearing randomness on its own.
struct SeedRng {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl SeedRng {
    fn new(seed: &[u8]) -> Self {
        let mut xof = Shake256::default();
        xof.update(KDF_DOMAIN);
        xof.update(seed);
        SeedRng {
            reader: xof.finalize_xof(),
        }
    }
}

impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.read(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.reader.read(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    static SOCK_SEQ: AtomicU32 = AtomicU32::new(0);

    fn unique_sock_path() -> String {
        let n = SOCK_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "tessera-dstack-mock-{}-{n}.sock",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    /// A faithful in-process mock of the dstack guest agent: HTTP/1.1 + JSON over a
    /// Unix socket. Captures the full request (headers + body) for assertions, and
    /// serves up to `conns` connections; the thread is detached (never joined) so a
    /// failing assertion can never hang the test run.
    struct MockAgent {
        path: String,
        captured: Arc<Mutex<Vec<u8>>>,
    }

    impl MockAgent {
        /// Answer `GetKey` with the configured hex secret at `status`.
        fn start(key_hex: Option<String>, status: u16, conns: usize) -> Self {
            Self::spawn(conns, move |req| {
                let body = if req.contains("/GetKey") {
                    match &key_hex {
                        Some(k) => format!(r#"{{"key":"{k}","signature_chain":[]}}"#),
                        None => "{}".to_string(),
                    }
                } else {
                    "{}".to_string()
                };
                if status == 200 {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    format!(
                        "HTTP/1.1 {status} ERR\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                }
            })
        }

        /// Serve a verbatim raw response (to exercise odd HTTP framing).
        fn start_raw(raw: String, conns: usize) -> Self {
            Self::spawn(conns, move |_req| raw.clone())
        }

        fn spawn(conns: usize, respond: impl Fn(&str) -> String + Send + 'static) -> Self {
            let path = unique_sock_path();
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind mock socket");
            let captured = Arc::new(Mutex::new(Vec::new()));
            let cap = Arc::clone(&captured);
            std::thread::spawn(move || {
                for _ in 0..conns {
                    let mut stream = match listener.accept() {
                        Ok((s, _)) => s,
                        Err(_) => break,
                    };
                    let req = read_http_request(&mut stream);
                    *cap.lock().unwrap() = req.clone().into_bytes();
                    let _ = stream.write_all(respond(&req).as_bytes());
                    let _ = stream.flush();
                }
            });
            MockAgent { path, captured }
        }

        fn captured_request(&self) -> String {
            String::from_utf8_lossy(&self.captured.lock().unwrap()).into_owned()
        }
    }

    /// Read a full HTTP/1.1 request (headers + any Content-Length body) off a stream.
    fn read_http_request(stream: &mut std::os::unix::net::UnixStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                        let want = head
                            .split("content-length:")
                            .nth(1)
                            .and_then(|s| s.trim().split([' ', '\r', '\n']).next())
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let mut remaining = want.saturating_sub(buf.len() - (p + 4));
                        while remaining > 0 {
                            match stream.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    remaining = remaining.saturating_sub(n);
                                }
                                Err(_) => break,
                            }
                        }
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    impl Drop for MockAgent {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn key_bytes(sk: &ServerPrivateKey) -> [u8; 128] {
        sk.serialize()
    }

    #[test]
    fn derive_server_key_is_deterministic_in_seed() {
        let seed = [7u8; 32];
        let (a, _) = derive_server_key(&seed);
        let (b, _) = derive_server_key(&seed);
        assert_eq!(key_bytes(&a), key_bytes(&b), "same seed must give same key");

        let (c, _) = derive_server_key(&[8u8; 32]);
        assert_ne!(
            key_bytes(&a),
            key_bytes(&c),
            "different seed must give a different key"
        );
    }

    #[test]
    fn derived_public_key_matches_private() {
        let (sk, pk) = derive_server_key(&[42u8; 32]);
        assert_eq!(sk.public_key().serialize(), pk.serialize());
    }

    #[test]
    fn establish_derives_same_key_across_two_calls() {
        // Two calls model an issuer and an exit in the same app: same GetKey
        // secret => identical ARC key, with no shared key file.
        let hexkey = "a".repeat(64); // 32 bytes
        let mock = MockAgent::start(Some(hexkey), 200, 2);
        let (k1, _) = establish(&mock.path, "tessera/arc-server-key").expect("establish 1");
        let (k2, _) = establish(&mock.path, "tessera/arc-server-key").expect("establish 2");
        assert_eq!(key_bytes(&k1), key_bytes(&k2));
    }

    #[test]
    fn establish_distinct_secrets_give_distinct_keys() {
        let m1 = MockAgent::start(Some("11".repeat(32)), 200, 1);
        let m2 = MockAgent::start(Some("22".repeat(32)), 200, 1);
        let (k1, _) = establish(&m1.path, "p").expect("establish m1");
        let (k2, _) = establish(&m2.path, "p").expect("establish m2");
        assert_ne!(key_bytes(&k1), key_bytes(&k2));
    }

    #[test]
    fn fails_closed_when_socket_absent() {
        let path = unique_sock_path(); // never bound
        let err = establish(&path, "k").expect_err("must fail closed");
        assert!(err.contains("dstack guest-agent"), "{err}");
    }

    #[test]
    fn fails_closed_on_short_secret() {
        let mock = MockAgent::start(Some("abcd".to_string()), 200, 1); // 2 bytes
        let err = establish(&mock.path, "k").expect_err("short secret must fail closed");
        assert!(err.contains("need >="), "{err}");
    }

    #[test]
    fn fails_closed_on_non_200() {
        let mock = MockAgent::start(Some("aa".repeat(32)), 500, 1);
        let err = establish(&mock.path, "k").expect_err("non-200 must fail closed");
        assert!(err.contains("non-200"), "{err}");
    }

    #[test]
    fn fails_closed_on_missing_key_field() {
        let mock = MockAgent::start(None, 200, 1); // GetKey returns "{}"
        let err = establish(&mock.path, "k").expect_err("missing key field must fail closed");
        assert!(err.contains("no \"key\" field"), "{err}");
    }

    #[test]
    fn preflight_ok_when_socket_present_errs_when_absent() {
        // preflight connects (consumes conn 1); establish consumes conn 2.
        let mock = MockAgent::start(Some("aa".repeat(32)), 200, 2);
        assert!(preflight(&mock.path, "k").is_ok());
        assert!(establish(&mock.path, "k").is_ok());

        let absent = unique_sock_path();
        assert!(preflight(&absent, "k").is_err());
    }

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn extract_json_string_tolerates_spacing() {
        assert_eq!(
            extract_json_string(r#"{ "key" : "deadbeef" }"#, "key").as_deref(),
            Some("deadbeef")
        );
        assert_eq!(extract_json_string(r#"{"other":"x"}"#, "key"), None);
    }

    #[test]
    fn fails_closed_on_non_hex_key() {
        let mock = MockAgent::start(Some("zzzznothex".to_string()), 200, 1);
        let err = establish(&mock.path, "k").expect_err("non-hex key must fail closed");
        assert!(err.contains("not valid hex"), "{err}");
    }

    #[test]
    fn establish_accepts_0x_prefixed_key() {
        let bare = "5b".repeat(32);
        let m_bare = MockAgent::start(Some(bare.clone()), 200, 1);
        let (k_bare, _) = establish(&m_bare.path, "k").expect("bare hex");
        let m_pref = MockAgent::start(Some(format!("0x{bare}")), 200, 1);
        let (k_pref, _) = establish(&m_pref.path, "k").expect("0x-prefixed hex");
        assert_eq!(
            key_bytes(&k_bare),
            key_bytes(&k_pref),
            "0x prefix must be stripped, not folded into the seed"
        );
    }

    #[test]
    fn establish_rejects_all_zero_secret() {
        let mock = MockAgent::start(Some("00".repeat(32)), 200, 1);
        let err = establish(&mock.path, "k").expect_err("all-zero secret must fail closed");
        assert!(err.contains("all-zero"), "{err}");
    }

    #[test]
    fn establish_with_quoted_key_id_sends_valid_json() {
        // Proves json_escape is wired into the live request path, not just unit-correct.
        let mock = MockAgent::start(Some("c3".repeat(32)), 200, 1);
        let weird = r#"weird"id\path"#;
        establish(&mock.path, weird).expect("establish");
        let req = mock.captured_request();
        assert!(
            req.contains(r#""path":"weird\"id\\path""#),
            "key_id was not JSON-escaped in the request body:\n{req}"
        );
    }

    #[test]
    fn fails_closed_on_missing_header_separator() {
        let mock = MockAgent::start_raw("HTTP/1.1 200 OK no proper crlf body".to_string(), 1);
        let err = establish(&mock.path, "k").expect_err("malformed HTTP must fail closed");
        assert!(err.contains("malformed HTTP"), "{err}");
    }

    #[test]
    fn fails_closed_on_empty_body() {
        let mock = MockAgent::start_raw(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            1,
        );
        let err = establish(&mock.path, "k").expect_err("empty body must fail closed");
        assert!(err.contains("no \"key\" field"), "{err}");
    }

    #[test]
    fn establish_handles_200_without_content_length() {
        // Proves the read-to-EOF path (no Content-Length; relies on Connection: close).
        let body = format!(r#"{{"key":"{}"}}"#, "7e".repeat(32));
        let mock = MockAgent::start_raw(
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"),
            1,
        );
        assert!(establish(&mock.path, "k").is_ok());
    }

    #[test]
    fn rejects_chunked_encoding() {
        let mock = MockAgent::start_raw(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
                .to_string(),
            1,
        );
        let err = establish(&mock.path, "k").expect_err("chunked must be rejected");
        assert!(err.contains("chunked"), "{err}");
    }

    #[test]
    fn socket_candidates_adds_fallbacks_only_for_default() {
        assert_eq!(
            socket_candidates("/custom/path.sock"),
            vec!["/custom/path.sock".to_string()]
        );
        let def = socket_candidates(DEFAULT_DSTACK_SOCKET);
        assert_eq!(def.len(), 1 + FALLBACK_SOCKETS.len());
        assert_eq!(def[0], DEFAULT_DSTACK_SOCKET);
    }

    #[test]
    fn derive_server_key_known_answer() {
        // KAT: freeze the seed->key derivation so an accidental change to KDF_DOMAIN,
        // the SHAKE update order, or SeedRng endianness can't silently break
        // issuer/exit convergence across separately-built binaries.
        let (sk, _) = derive_server_key(&[0x5au8; 32]);
        assert_eq!(
            hex::encode(key_bytes(&sk)),
            KAT_KEY_0X5A,
            "derivation contract changed"
        );
    }

    const KAT_KEY_0X5A: &str = "8cd07abfe95e34abc8d78b240b1050206edd439888b0276ec1f86b6eb56e592cb65ddd4b6a66734dffad55f1826956fa51fc30e7f1dd6667c29911a323fbc59605fb6f1f8177100d04fc45a4295266593ccf3b66d69daea5245b81695c641b26906ee5a0f1d6f05abc011bcf3a717acb7457c2563b8df6b5d313ea28ecedaf01";
}
