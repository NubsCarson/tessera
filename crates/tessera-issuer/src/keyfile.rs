//! Convergent shared-key bootstrap for the issuer + exit.
//!
//! ARC is keyed-verification: the issuer (authority) and the exit (verifier)
//! MUST hold the *same* server key, or every credential fails (407) forever.
//! When several nodes start against one `TESSERA_KEY_FILE` (e.g. a Docker volume),
//! they must converge on a single key no matter who starts first or how the
//! timing skews.
//!
//! [`ensure_shared_key`] guarantees that. It is **single-winner**: a fresh key is
//! written to a per-process temp (`O_EXCL`), then published by [`std::fs::hard_link`]
//! onto the target path — which atomically *fails* if the path already exists. So
//! exactly one process ever creates the file; every other process (including the
//! race loser) re-reads the path and adopts whatever key is there. There is no
//! last-writer-wins window, so the keys cannot diverge.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand_core::OsRng;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

/// Per-call sequence so each attempt's temp file is unique even within one
/// process (pid alone collides across threads).
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Read the shared ARC key at `path`, or create it exactly once and have all
/// racing nodes converge on the single on-disk key. Blocks (briefly) until the
/// key is established; returns the `(private, public)` pair every node agrees on.
///
/// Convergence is guaranteed: the first node to win the `hard_link` publish owns
/// the key, and all others read it back — so the issuer and exit never end up
/// with different keys.
pub fn ensure_shared_key(path: &str) -> (ServerPrivateKey, ServerPublicKey) {
    for _ in 0..600 {
        // 1. Adopt an existing, valid key (the common case after the first win).
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(sk) = ServerPrivateKey::from_bytes(&bytes) {
                let pk = sk.public_key();
                return (sk, pk);
            }
            // File exists but isn't a valid key yet (a partial write by a
            // non-atomic external tool); wait and re-read rather than clobber it.
        } else {
            // 2. No key yet — try to become the single creator. Write our
            //    candidate to a process-unique temp (O_EXCL), then publish it by
            //    hard-linking onto `path`, which fails if anyone already won.
            let (sk, pk) = ServerPrivateKey::setup(&mut OsRng);
            // Unique per attempt (pid + a process-local counter), so a writer
            // only ever touches its OWN temp — never another racer's.
            let tmp = format!(
                "{path}.{}.{}.tmp",
                std::process::id(),
                TMP_SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let wrote = opts
                .open(&tmp)
                .and_then(|mut f| {
                    f.write_all(&sk.serialize())?;
                    f.flush()?;
                    f.sync_data()
                })
                .is_ok();
            if wrote {
                match std::fs::hard_link(&tmp, path) {
                    Ok(()) => {
                        // We are the single winner: clean the temp, return our key.
                        let _ = std::fs::remove_file(&tmp);
                        return (sk, pk);
                    }
                    Err(_) => {
                        // Someone else won the publish; drop ours and re-read theirs.
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
            } else {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // ~60s with no readable key and no successful create: the path is unusable
    // (bad mount/permissions). Fail loudly rather than fork a divergent key.
    panic!("could not establish a shared key at {path} (check the path/volume permissions)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "tessera-key-{}-{}-{}",
                tag,
                std::process::id(),
                TMP_SEQ.fetch_add(1, Ordering::Relaxed)
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn second_node_adopts_the_first_nodes_key() {
        let path = temp_path("seq");
        let _ = std::fs::remove_file(&path);
        let (_, pk1) = ensure_shared_key(&path); // creator
        let (_, pk2) = ensure_shared_key(&path); // adopter
        assert_eq!(
            pk1.serialize(),
            pk2.serialize(),
            "issuer + exit must converge on ONE key"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn racing_nodes_never_diverge() {
        // Eight nodes start simultaneously on a fresh path; exactly one wins the
        // hard-link publish and the rest adopt it — they MUST all agree.
        let path = temp_path("race");
        let _ = std::fs::remove_file(&path);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || ensure_shared_key(&p).1.serialize())
            })
            .collect();
        let keys: Vec<[u8; 99]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            keys.iter().all(|k| *k == keys[0]),
            "all racing nodes must converge on exactly one key (no divergence)"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn created_shared_key_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("mode");
        let _ = std::fs::remove_file(&path);
        let _ = ensure_shared_key(&path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "shared ARC key file must be owner-only");

        let _ = std::fs::remove_file(&path);
    }
}
