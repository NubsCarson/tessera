//! Binary-level config tests for `tessera-proxy --check`.

use std::fs::OpenOptions;
use std::process::Command;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tessera-proxy-config-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn check_command(key_file: &std::path::Path, tag_file: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tessera-proxy"));
    cmd.arg("--check")
        .env_clear()
        .env("TESSERA_LISTEN", "127.0.0.1:0")
        .env("TESSERA_KEY_FILE", key_file)
        .env("TESSERA_SPENT_TAG_FILE", tag_file);
    cmd
}

#[test]
fn check_mode_reports_single_exit_topology_and_releases_lease() {
    let dir = temp_dir("check-ok");
    let key = dir.join("server.key");
    let tags = dir.join("spent-tags.log");

    let first = check_command(&key, &tags).output().unwrap();
    assert!(
        first.status.success(),
        "first --check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        stdout.contains("topology=single-exit-key-domain"),
        "{stdout}"
    );
    assert!(stdout.contains("tag_store=file:"), "{stdout}");

    let second = check_command(&key, &tags).output().unwrap();
    assert!(
        second.status.success(),
        "second --check should prove the first check released the lease\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    let _ = std::fs::remove_file(format!("{}.exit.lock", key.to_string_lossy()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn check_mode_rejects_already_held_key_domain_lease() {
    use std::os::fd::AsRawFd;

    let dir = temp_dir("check-locked");
    let key = dir.join("server.key");
    let tags = dir.join("spent-tags.log");
    let lock_path = std::path::PathBuf::from(format!("{}.exit.lock", key.to_string_lossy()));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();

    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "test setup must hold the key-domain lock");

    let out = check_command(&key, &tags).output().unwrap();
    assert!(
        !out.status.success(),
        "second local exit must fail closed while the lock is held\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("key-domain lease"), "{stderr}");
    assert!(stderr.contains("already held"), "{stderr}");

    let _ = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    drop(lock);
    let _ = std::fs::remove_file(lock_path);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn check_mode_rejects_already_held_existing_key_file_lease() {
    use std::os::fd::AsRawFd;

    let dir = temp_dir("check-existing-key-locked");
    let key = dir.join("server.key");
    let tags = dir.join("spent-tags.log");
    std::fs::write(&key, b"placeholder").unwrap();
    let lock = OpenOptions::new().read(true).open(&key).unwrap();

    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "test setup must hold the key-file lock");

    let out = check_command(&key, &tags).output().unwrap();
    assert!(
        !out.status.success(),
        "second local exit must fail closed while the existing key file is locked\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("key-domain lease"), "{stderr}");
    assert!(stderr.contains("already held"), "{stderr}");

    let _ = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    drop(lock);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_rejects_malformed_spent_tag_file() {
    let dir = temp_dir("check-bad-tags");
    let key = dir.join("server.key");
    let tags = dir.join("spent-tags.log");
    std::fs::write(&tags, "not a tag\n").unwrap();

    let out = check_command(&key, &tags).output().unwrap();
    assert!(
        !out.status.success(),
        "malformed durable tag state must fail closed in --check\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("could not open tag store"), "{stderr}");
    assert!(stderr.contains("malformed spent-tag"), "{stderr}");

    let _ = std::fs::remove_file(format!("{}.exit.lock", key.to_string_lossy()));
    let _ = std::fs::remove_dir_all(&dir);
}
