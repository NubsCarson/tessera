//! Spent-tag store tests: the in-memory default, the durable [`FileTagStore`],
//! and end-to-end double-spend enforcement that **survives a guard restart**
//! when a `FileTagStore` is injected via [`OriginGuard::with_store`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{
    Decision, FileTagStore, InMemoryTagStore, OriginGuard, RejectReason, SpentTagStore, StoreError,
};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 4;

/// A unique temp path per call (process id + nanos + a counter), so parallel
/// tests never collide. Removed by the caller when done.
fn temp_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tessera-{tag}-{}-{nanos}-{n}.tags",
        std::process::id()
    ))
}

#[test]
fn in_memory_store_detects_repeats() {
    let store = InMemoryTagStore::new();
    assert!(store.is_empty());
    let tag = [9u8; 33];
    assert!(store.record_if_new(tag).unwrap(), "first record is new");
    assert!(
        !store.record_if_new(tag).unwrap(),
        "repeat is a double-spend"
    );
    assert_eq!(store.len(), 1);
    assert!(
        store.record_if_new([1u8; 33]).unwrap(),
        "a different tag is new"
    );
    assert_eq!(store.len(), 2);
}

#[test]
fn file_store_detects_repeats_and_persists() {
    let path = temp_path("filestore");
    let tag_a = [7u8; 33];
    let tag_b = [8u8; 33];

    {
        let store = FileTagStore::open(&path).expect("open");
        assert!(store.is_empty());
        assert!(store.record_if_new(tag_a).unwrap());
        assert!(
            !store.record_if_new(tag_a).unwrap(),
            "repeat within the run"
        );
        assert!(store.record_if_new(tag_b).unwrap());
        assert_eq!(store.len(), 2);
    } // drop -> file flushed/closed

    // Re-open the SAME file: previously-seen tags are loaded and still rejected.
    let reopened = FileTagStore::open(&path).expect("reopen");
    assert_eq!(reopened.len(), 2, "tags survive across re-open");
    assert!(
        !reopened.record_if_new(tag_a).unwrap(),
        "a tag from a prior run must still be a double-spend"
    );
    assert!(
        reopened.record_if_new([3u8; 33]).unwrap(),
        "a fresh tag is admitted"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_store_rejects_malformed_lines() {
    let path = temp_path("malformed");
    std::fs::write(
        &path,
        // a valid 33-byte hex tag, a blank line, junk, a short hex blob
        format!("{}\n\nnot-hex!!\nbeef\n", hex::encode([5u8; 33])),
    )
    .unwrap();

    let err = match FileTagStore::open(&path) {
        Ok(_) => panic!("malformed rows fail closed"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let _ = std::fs::remove_file(&path);
}

/// Issue a credential against `sk`/`pk` and return a client to present with.
fn issue(sk: &ServerPrivateKey, pk: tessera_arc::keys::ServerPublicKey) -> TesseraClient {
    let mut rng = OsRng;
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    TesseraClient::new(credential, CTX, LIMIT)
}

#[test]
fn double_spend_is_enforced_across_a_guard_restart() {
    let path = temp_path("guard-durable");
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let mut client = issue(&sk, pk);

    // One presentation, captured so we can replay the exact header.
    let header = client.presentation_header(&mut OsRng).unwrap();

    // Guard #1, backed by a file store: admits the presentation and records it.
    {
        let guard = OriginGuard::with_store(
            sk.clone(),
            pk,
            REQ,
            CTX,
            LIMIT,
            Box::new(FileTagStore::open(&path).expect("open")),
        );
        assert!(guard.check(Some(&header)).is_admit(), "first use admitted");
    } // guard #1 dropped — simulates a process restart

    // Guard #2: a brand-new guard with the same key, re-opening the same file.
    let guard2 = OriginGuard::with_store(
        sk,
        pk,
        REQ,
        CTX,
        LIMIT,
        Box::new(FileTagStore::open(&path).expect("reopen")),
    );
    assert_eq!(
        guard2.check(Some(&header)),
        Decision::Reject(RejectReason::DoubleSpend),
        "a replay after restart must still be rejected — durability"
    );

    // A fresh, in-budget presentation on the new guard is still admitted.
    let fresh = client.presentation_header(&mut OsRng).unwrap();
    assert!(
        guard2.check(Some(&fresh)).is_admit(),
        "a distinct presentation is still accepted after restart"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn separate_in_memory_exits_do_not_share_double_spend_state() {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let mut client = issue(&sk, pk);
    let header = client.presentation_header(&mut OsRng).unwrap();

    let exit_a = OriginGuard::new(sk.clone(), pk, REQ, CTX, LIMIT);
    let exit_b = OriginGuard::new(sk, pk, REQ, CTX, LIMIT);

    assert!(
        exit_a.check(Some(&header)).is_admit(),
        "first exit admits the fresh presentation"
    );
    assert_eq!(
        exit_a.check(Some(&header)),
        Decision::Reject(RejectReason::DoubleSpend),
        "one exit catches its own replay"
    );
    assert!(
        exit_b.check(Some(&header)).is_admit(),
        "a second process-local exit with the same key has no shared tag state"
    );
}

/// A custom store wired through the trait works exactly like the built-ins —
/// this is the extension point real deployments use (Redis/Postgres/DO).
#[test]
fn a_custom_store_can_be_injected() {
    use std::sync::Mutex;

    /// A toy "reject everything as already-spent" store, to prove injection.
    struct AlwaysSpent(Mutex<u64>);
    impl SpentTagStore for AlwaysSpent {
        fn record_if_new(&self, _tag: [u8; 33]) -> Result<bool, StoreError> {
            *self.0.lock().unwrap() += 1;
            Ok(false)
        }
    }

    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let mut client = issue(&sk, pk);
    let header = client.presentation_header(&mut OsRng).unwrap();

    let guard = OriginGuard::with_store(
        sk,
        pk,
        REQ,
        CTX,
        LIMIT,
        Box::new(AlwaysSpent(Mutex::new(0))),
    );
    // The proof verifies, but our custom store vetoes it as a double-spend.
    assert_eq!(
        guard.check(Some(&header)),
        Decision::Reject(RejectReason::DoubleSpend),
        "the injected store's verdict is honored"
    );
}

#[test]
fn an_unavailable_store_fails_closed() {
    /// A toy store that cannot safely record, to prove failures are not admitted.
    struct Unavailable;
    impl SpentTagStore for Unavailable {
        fn record_if_new(&self, _tag: [u8; 33]) -> Result<bool, StoreError> {
            Err(StoreError::new("test store unavailable"))
        }
    }

    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let mut client = issue(&sk, pk);
    let header = client.presentation_header(&mut OsRng).unwrap();

    let guard = OriginGuard::with_store(sk, pk, REQ, CTX, LIMIT, Box::new(Unavailable));
    assert_eq!(
        guard.check(Some(&header)),
        Decision::Reject(RejectReason::StoreUnavailable),
        "a verified presentation is rejected when the store cannot record it"
    );
}
