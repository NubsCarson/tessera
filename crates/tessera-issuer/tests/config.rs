//! Binary-level config tests for `tessera-issuer --check`.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tessera-issuer-config-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn issuer_check() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tessera-issuer"));
    cmd.arg("--check")
        .env_clear()
        .env("TESSERA_ISSUER_LISTEN", "127.0.0.1:0");
    cmd
}

#[test]
fn check_mode_rejects_empty_key_file_env() {
    let out = issuer_check().env("TESSERA_KEY_FILE", "").output().unwrap();

    assert!(
        !out.status.success(),
        "empty TESSERA_KEY_FILE must be a config error\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TESSERA_KEY_FILE is set but empty"),
        "{stderr}"
    );
}

#[test]
fn check_mode_rejects_unknown_key_provider() {
    let out = issuer_check()
        .env("TESSERA_KEY_PROVIDER", "kms-ish")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "unknown provider must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not one of"), "{stderr}");
}

#[test]
fn check_mode_rejects_file_provider_without_key_file() {
    let out = issuer_check()
        .env("TESSERA_KEY_PROVIDER", "file")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "file provider without key file must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires TESSERA_KEY_FILE"), "{stderr}");
}

#[test]
fn check_mode_preserves_legacy_key_file_provider() {
    let dir = temp_dir("legacy-key-file");
    let key = dir.join("server.key");
    let out = issuer_check()
        .env("TESSERA_KEY_FILE", &key)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "legacy key file should infer file provider\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("shared key"), "{stdout}");
    assert!(
        stdout.contains(&key.to_string_lossy().to_string()),
        "{stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_fails_closed_dstack_provider_without_socket() {
    let out = issuer_check()
        .env("TESSERA_KEY_PROVIDER", "dstack-kms")
        .env("TESSERA_DSTACK_KMS_KEY_ID", "arc-key")
        .env(
            "TESSERA_DSTACK_SOCKET",
            "/nonexistent/tessera-dstack-test.sock",
        )
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "dstack provider must fail closed without a reachable guest agent\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dstack guest-agent"), "{stderr}");
}

#[test]
fn check_mode_rejects_ephemeral_provider_with_key_file() {
    let dir = temp_dir("ephemeral-conflict");
    let key = dir.join("server.key");
    let out = issuer_check()
        .env("TESSERA_KEY_PROVIDER", "ephemeral")
        .env("TESSERA_KEY_FILE", &key)
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "ephemeral provider with key file must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be combined"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
