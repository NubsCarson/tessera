//! Pluggable double-spend (spent-tag) stores for [`OriginGuard`](crate::OriginGuard).
//!
//! A presentation's tag is single-use within its context: the guard records
//! every accepted tag and rejects any repeat (replay / double-spend). *Which*
//! store backs that set is a deployment choice:
//!
//! * [`InMemoryTagStore`] (the default) — fast, process-local; **not** durable
//!   across restarts and **not** shared across processes/replicas.
//! * [`FileTagStore`] — an append-only file; durable across restarts within a
//!   single process (honest limits on the type).
//! * **your own** — implement [`SpentTagStore`] over Redis / Postgres / a
//!   Cloudflare Durable Object for a *distributed, shared* spent-set. Behind
//!   multiple replicas or at the edge this is the only correct choice: a
//!   per-process set lets the same presentation be replayed against a different
//!   replica.
//!
//! Inject a custom store with
//! [`OriginGuard::with_store`](crate::OriginGuard::with_store).

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

/// The presentation tag the guard records — a SEC1-compressed P-256 point.
pub type Tag = [u8; 33];

/// A spent-tag set: records accepted presentation tags and detects repeats.
///
/// The single operation must be **atomic**: for concurrent calls with the same
/// tag, exactly one must observe `true` (admit) and the rest `false`
/// (double-spend). The store is shared behind `&self` and must be `Send + Sync`
/// (the guard is typically wrapped in an `Arc` and driven from many threads).
pub trait SpentTagStore: Send + Sync {
    /// Record `tag` as spent. Returns `true` if it was newly recorded (the
    /// presentation is fresh — **admit**), or `false` if it was already present
    /// (replay / double-spend — **reject**).
    fn record_if_new(&self, tag: Tag) -> bool;
}

/// The default store: an in-memory `HashSet` behind a `Mutex`. Process-local and
/// **non-durable** — every accepted tag is forgotten on restart, and nothing is
/// shared across processes. Fine for a single long-lived process, tests, and the
/// demo; not for multiple replicas (see the module docs).
#[derive(Default)]
pub struct InMemoryTagStore {
    spent: Mutex<HashSet<Tag>>,
}

impl InMemoryTagStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct tags recorded so far (observability / tests).
    pub fn len(&self) -> usize {
        self.spent.lock().expect("tag store mutex poisoned").len()
    }

    /// Whether no tag has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SpentTagStore for InMemoryTagStore {
    fn record_if_new(&self, tag: Tag) -> bool {
        self.spent
            .lock()
            .expect("tag store mutex poisoned")
            .insert(tag)
    }
}

/// A spent-tag store backed by an **append-only file**. Existing tags are loaded
/// into memory on [`open`](FileTagStore::open) and each accepted tag is appended
/// (hex, one per line), so the spent-set **survives a process restart** — a
/// replay after restart is still rejected.
///
/// Honest limits — read before deploying:
/// * **Single-process only.** Atomicity is an in-process `Mutex`; two processes
///   sharing one file would race and could both admit the same tag. For
///   multiple replicas, implement [`SpentTagStore`] over a shared store instead.
/// * **Unbounded growth.** The file grows by 66 bytes per accepted presentation
///   and is never compacted. Rotate it per key-epoch / context in deployment.
/// * **Durability is a best-effort flush**, not `fsync`-per-write (kept off the
///   hot path). A crash can lose the last few appends; the in-memory set still
///   rejects replays for the current run. Wrap your own store if you need
///   stronger durability.
pub struct FileTagStore {
    inner: Mutex<FileTagInner>,
}

struct FileTagInner {
    spent: HashSet<Tag>,
    file: File,
}

impl FileTagStore {
    /// Open (creating if absent) a spent-tag file at `path`, loading any tags
    /// already recorded in it. Malformed lines are skipped (forward-compatible).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let mut spent = HashSet::new();
        // Open-then-handle-NotFound rather than `exists()`-then-open: that
        // check-then-use pattern has a TOCTOU window (the file could vanish
        // between the two), and a single open is also one fewer syscall.
        match File::open(path) {
            Ok(f) => {
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(bytes) = hex::decode(line) {
                        if let Ok(tag) = Tag::try_from(bytes.as_slice()) {
                            spent.insert(tag);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // fresh start
            Err(e) => return Err(e),
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner: Mutex::new(FileTagInner { spent, file }),
        })
    }

    /// Number of distinct tags recorded (in memory + loaded from the file).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("file tag store mutex poisoned")
            .spent
            .len()
    }

    /// Whether no tag has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SpentTagStore for FileTagStore {
    fn record_if_new(&self, tag: Tag) -> bool {
        let mut inner = self.inner.lock().expect("file tag store mutex poisoned");
        if !inner.spent.insert(tag) {
            return false;
        }
        // Persist append-only. If the write fails, the tag stays in the
        // in-memory set (so it is still rejected this run); only cross-restart
        // durability of this one tag is lost — see the type's doc.
        let line = hex::encode(tag);
        let _ = writeln!(inner.file, "{line}");
        let _ = inner.file.flush();
        true
    }
}
