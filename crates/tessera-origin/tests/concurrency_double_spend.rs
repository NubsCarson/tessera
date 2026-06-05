//! Concurrency stress: many threads present the **same** captured presentation
//! against one shared [`OriginGuard`] at once. The spent-tag store's
//! `record_if_new` is documented as atomic, so under any interleaving **exactly
//! one** thread must be admitted and every other must be rejected as a
//! [`RejectReason::DoubleSpend`] — no race may let two requests through on a
//! single-use credential. This is the property that makes the per-credential
//! rate limit sound; a race here would silently double a client's budget.
//!
//! Both built-in stores are exercised: the default [`InMemoryTagStore`]
//! (`Mutex<HashSet>`) and the durable [`FileTagStore`] (`Mutex` + append-only
//! file). The latter is the more interesting case — its `record_if_new` does
//! real I/O while holding the lock — so racing it proves the lock, not luck,
//! is what serializes the spend.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{Decision, FileTagStore, InMemoryTagStore, OriginGuard, RejectReason};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 4;
const THREADS: usize = 32;

/// A unique temp path per call (pid + nanos + counter) so parallel test
/// binaries never collide on the file-backed store. Caller removes it.
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

/// Issue a fresh credential and a client primed to present against `CTX`.
fn issue() -> (ServerPrivateKey, ServerPublicKey, TesseraClient) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let client = TesseraClient::new(credential, CTX, LIMIT);
    (sk, pk, client)
}

/// Drive `THREADS` threads that each call `guard.check(Some(&header))` with the
/// SAME header at (as near as a `Barrier` allows) the same instant. Returns
/// `(admits, double_spends, other)` tallied across all threads.
fn race_same_presentation(guard: Arc<OriginGuard>, header: String) -> (usize, usize, usize) {
    let header = Arc::new(header);
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let guard = Arc::clone(&guard);
            let header = Arc::clone(&header);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Line all threads up so the contention is real, not staggered.
                barrier.wait();
                guard.check(Some(header.as_str()))
            })
        })
        .collect();

    let mut admits = 0usize;
    let mut double_spends = 0usize;
    let mut other = 0usize;
    for h in handles {
        match h.join().expect("worker thread panicked") {
            Decision::Admit { .. } => admits += 1,
            Decision::Reject(RejectReason::DoubleSpend) => double_spends += 1,
            // Any other verdict (Malformed / InvalidProof / MissingCredential)
            // would mean the *same valid header* was judged inconsistently —
            // itself a bug. Count it separately so the asserts can pin it.
            Decision::Reject(_) => other += 1,
        }
    }
    (admits, double_spends, other)
}

#[test]
fn in_memory_store_admits_exactly_one_under_concurrent_replay() {
    let (sk, pk, mut client) = issue();
    // One presentation, captured once; every thread will replay this exact wire
    // value, so they all resolve to the same spent-tag.
    let header = client.presentation_header(&mut OsRng).unwrap();

    let store = InMemoryTagStore::new();
    let guard = Arc::new(OriginGuard::with_store(
        sk,
        pk,
        REQ,
        CTX,
        LIMIT,
        Box::new(store),
    ));

    let (admits, double_spends, other) = race_same_presentation(Arc::clone(&guard), header);

    assert_eq!(
        admits, 1,
        "EXACTLY one concurrent replay may be admitted (got {admits}); \
         a race that admits >1 doubles the credential's budget"
    );
    assert_eq!(
        other, 0,
        "a valid header must never be judged Malformed/InvalidProof (got {other} such verdicts)"
    );
    assert_eq!(
        double_spends,
        THREADS - 1,
        "every losing thread must be rejected as a double-spend"
    );
    // Total accounting: nothing vanished or was double-counted.
    assert_eq!(admits + double_spends + other, THREADS);
}

#[test]
fn file_store_admits_exactly_one_under_concurrent_replay() {
    let path = temp_path("concurrency-filestore");
    let (sk, pk, mut client) = issue();
    let header = client.presentation_header(&mut OsRng).unwrap();

    let store = FileTagStore::open(&path).expect("open file-backed store");
    assert!(store.is_empty(), "store starts empty");
    let guard = Arc::new(OriginGuard::with_store(
        sk,
        pk,
        REQ,
        CTX,
        LIMIT,
        Box::new(store),
    ));

    let (admits, double_spends, other) = race_same_presentation(Arc::clone(&guard), header);

    assert_eq!(
        admits, 1,
        "the durable store must also admit EXACTLY one concurrent replay (got {admits})"
    );
    assert_eq!(
        other, 0,
        "a valid header is never malformed/invalid (got {other})"
    );
    assert_eq!(
        double_spends,
        THREADS - 1,
        "all but one concurrent replay are double-spends on the file store"
    );
    assert_eq!(admits + double_spends + other, THREADS);

    let _ = std::fs::remove_file(&path);
}

/// Distinct presentations raced together must ALL be admitted: the guard only
/// serializes on the *tag*, so independent in-budget spends never collide.
/// This is the converse of the double-spend test — it proves the "exactly one"
/// result above is the store rejecting genuine replays, not the guard
/// over-serializing and starving concurrent honest traffic.
#[test]
fn in_memory_store_admits_all_distinct_concurrent_presentations() {
    let (sk, pk, mut client) = issue();

    // Pre-generate LIMIT distinct, in-budget presentations (different nonces ->
    // different tags). Generating them up front keeps the client off the racing
    // threads (TesseraClient::presentation_header takes &mut self).
    let headers: Vec<String> = (0..LIMIT)
        .map(|_| client.presentation_header(&mut OsRng).unwrap())
        .collect();

    let guard = Arc::new(OriginGuard::with_store(
        sk,
        pk,
        REQ,
        CTX,
        LIMIT,
        Box::new(InMemoryTagStore::new()),
    ));

    let barrier = Arc::new(Barrier::new(headers.len()));
    let handles: Vec<_> = headers
        .into_iter()
        .map(|header| {
            let guard = Arc::clone(&guard);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                guard.check(Some(&header))
            })
        })
        .collect();

    let mut admits = 0usize;
    let mut admitted_tags = std::collections::HashSet::new();
    for h in handles {
        if let Decision::Admit { tag } = h.join().expect("worker thread panicked") {
            admits += 1;
            admitted_tags.insert(tag);
        }
    }

    assert_eq!(
        admits, LIMIT as usize,
        "distinct in-budget presentations must ALL be admitted concurrently (got {admits})"
    );
    assert_eq!(
        admitted_tags.len(),
        LIMIT as usize,
        "each admit recorded a distinct tag — no two honest spends collapsed"
    );
}
