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

/// Error returned when a spent-tag store cannot safely record a fresh tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
}

impl StoreError {
    /// Build a store error with a human-readable diagnostic.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

/// A spent-tag set: records accepted presentation tags and detects repeats.
///
/// The single operation must be **atomic**: for concurrent calls with the same
/// tag, exactly one must observe `Ok(true)` (admit) and the rest `Ok(false)`
/// (double-spend). `Err` means the store cannot durably/authoritatively decide,
/// so callers must fail closed. The store is shared behind `&self` and must be
/// `Send + Sync` (the guard is typically wrapped in an `Arc` and driven from
/// many threads).
pub trait SpentTagStore: Send + Sync {
    /// Record `tag` as spent. Returns `Ok(true)` if it was newly recorded (the
    /// presentation is fresh — **admit**), `Ok(false)` if it was already present
    /// (replay / double-spend — **reject**), or `Err` if the store is unavailable
    /// or cannot make the record durable/authoritative (**reject**).
    fn record_if_new(&self, tag: Tag) -> Result<bool, StoreError>;
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
    fn record_if_new(&self, tag: Tag) -> Result<bool, StoreError> {
        Ok(self
            .spent
            .lock()
            .expect("tag store mutex poisoned")
            .insert(tag))
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
/// * **Durability is fail-closed.** A fresh tag is appended, flushed, and synced
///   before it is admitted. If persistence fails, the call returns an error and
///   the presentation is rejected rather than becoming replayable after restart.
///   This is intentionally conservative and slower than an in-memory store.
pub struct FileTagStore {
    inner: Mutex<FileTagInner>,
}

struct FileTagInner {
    spent: HashSet<Tag>,
    file: File,
}

impl FileTagStore {
    /// Open (creating if absent) a spent-tag file at `path`, loading any tags
    /// already recorded in it. Malformed non-empty lines are a startup error: a
    /// replay ledger must fail closed instead of silently treating corrupted rows
    /// as unspent.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let mut spent = HashSet::new();
        // Open-then-handle-NotFound rather than `exists()`-then-open: that
        // check-then-use pattern has a TOCTOU window (the file could vanish
        // between the two), and a single open is also one fewer syscall.
        match File::open(path) {
            Ok(f) => {
                for (line_no, line) in BufReader::new(f).lines().enumerate() {
                    let line = line?;
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let bytes = hex::decode(line).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "malformed spent-tag line {} in {}: {e}",
                                line_no + 1,
                                path.display()
                            ),
                        )
                    })?;
                    let tag = Tag::try_from(bytes.as_slice()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "malformed spent-tag line {} in {}: expected 33 bytes, got {}",
                                line_no + 1,
                                path.display(),
                                bytes.len()
                            ),
                        )
                    })?;
                    spent.insert(tag);
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
    fn record_if_new(&self, tag: Tag) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("file tag store mutex poisoned");
        if inner.spent.contains(&tag) {
            return Ok(false);
        }

        let line = hex::encode(tag);
        writeln!(inner.file, "{line}")
            .and_then(|_| inner.file.flush())
            .and_then(|_| inner.file.sync_data())
            .map_err(|e| StoreError::new(format!("could not persist spent tag: {e}")))?;
        inner.spent.insert(tag);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{FileTagInner, FileTagStore, SpentTagStore};
    use std::collections::HashSet;
    use std::fs::OpenOptions;
    use std::sync::Mutex;

    #[cfg(target_os = "linux")]
    #[test]
    fn file_store_fails_closed_when_append_fails() {
        let file = OpenOptions::new()
            .append(true)
            .open("/dev/full")
            .expect("/dev/full exists on linux");
        let store = FileTagStore {
            inner: Mutex::new(FileTagInner {
                spent: HashSet::new(),
                file,
            }),
        };
        let tag = [42u8; 33];

        let err = store
            .record_if_new(tag)
            .expect_err("/dev/full must make persistence fail");
        assert!(err.to_string().contains("could not persist"), "{err}");
        assert_eq!(
            store.len(),
            0,
            "failed persistence must not mark the tag spent in memory"
        );
    }
}
