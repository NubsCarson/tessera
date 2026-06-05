//! Durability test for the file-backed spent-tag store: SEVERAL presentations
//! spent through a guard backed by a [`FileTagStore`] must all stay spent after
//! the guard/store is dropped and a brand-new guard re-opens the SAME file —
//! i.e. a replay after a simulated process restart is still rejected, while a
//! genuinely fresh presentation is still admitted.
//!
//! This complements `tests/store.rs::double_spend_is_enforced_across_a_guard_restart`
//! (which spends a single tag) by exercising the *multi-tag* load path: every
//! recorded tag must be reconstructed from the file, not just the last one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::{Decision, FileTagStore, OriginGuard, RejectReason};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://origin/v1";
const LIMIT: u64 = 4;

/// A unique temp path per call (process id + nanos + a counter), so parallel
/// tests never collide. Removed by the caller when done. Mirrors `tests/store.rs`.
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

/// Issue a credential against `sk`/`pk` and return a client to present with.
/// Mirrors the issuance harness shared by the sibling tests.
fn issue(sk: &ServerPrivateKey, pk: ServerPublicKey) -> TesseraClient {
    let mut rng = OsRng;
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    TesseraClient::new(credential, CTX, LIMIT)
}

/// Spend SEVERAL presentations through a `FileTagStore`-backed guard, drop it,
/// reopen a NEW guard + store from the same path, and assert every prior tag is
/// still rejected as a double-spend while a fresh presentation is admitted.
#[test]
fn several_spent_tags_survive_a_filetagstore_restart() {
    let path = temp_path("filetagstore-durability");
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let mut client = issue(&sk, pk);

    // Capture three distinct presentation headers up front so we can replay the
    // EXACT bytes after the restart. Each is a distinct, in-budget use of the
    // one credential (3 < LIMIT == 4).
    let spent_headers: Vec<String> = (0..3)
        .map(|_| client.presentation_header(&mut OsRng).unwrap())
        .collect();

    // Guard #1, backed by the file store: admit and record every presentation,
    // and collect the distinct tags it hands back so we can sanity-check the
    // file actually recorded several rows (not one tag re-counted).
    let mut admitted_tags = Vec::new();
    {
        let guard = OriginGuard::with_store(
            sk.clone(),
            pk,
            REQ,
            CTX,
            LIMIT,
            Box::new(FileTagStore::open(&path).expect("open")),
        );
        for (i, header) in spent_headers.iter().enumerate() {
            match guard.check(Some(header)) {
                Decision::Admit { tag } => admitted_tags.push(tag),
                other => panic!("presentation {i} should be admitted, got {other:?}"),
            }
        }
    } // guard #1 + its FileTagStore dropped — simulates a process restart.

    // The three presentations must have produced three DISTINCT tags; otherwise
    // the durability assertion below would be vacuous (only one row to load).
    let unique: std::collections::HashSet<_> = admitted_tags.iter().collect();
    assert_eq!(
        unique.len(),
        spent_headers.len(),
        "the spent presentations must have distinct tags for this test to be meaningful"
    );

    // Guard #2: a brand-new guard with the same key, re-opening the same file.
    // Every one of the previously-spent tags must be loaded from disk: the store
    // reports them all, and the count is not off-by-one (e.g. only the last
    // append surviving) or inflated.
    let store2 = FileTagStore::open(&path).expect("reopen");
    assert_eq!(
        store2.len(),
        spent_headers.len(),
        "every spent tag must be reconstructed from the file after restart"
    );
    let guard2 = OriginGuard::with_store(sk, pk, REQ, CTX, LIMIT, Box::new(store2));

    // Each captured presentation, replayed after the restart, must still be a
    // double-spend — proving the spent-set is durable, not just process-local.
    for (i, header) in spent_headers.iter().enumerate() {
        assert_eq!(
            guard2.check(Some(header)),
            Decision::Reject(RejectReason::DoubleSpend),
            "replay of prior-run presentation {i} must be rejected after restart"
        );
    }

    // A genuinely fresh, still-in-budget presentation (the 4th, == LIMIT) on the
    // new guard is admitted — durability rejects only the actual replays, it does
    // not wedge the guard into refusing everything.
    let fresh = client.presentation_header(&mut OsRng).unwrap();
    match guard2.check(Some(&fresh)) {
        Decision::Admit { tag } => assert!(
            !unique.contains(&tag),
            "the fresh presentation's tag must differ from every spent tag"
        ),
        other => panic!(
            "a distinct in-budget presentation must be admitted after restart, got {other:?}"
        ),
    }

    let _ = std::fs::remove_file(&path);
}
