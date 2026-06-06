//! Binary-level config tests for `tessera-issuer --check`.

use std::process::Command;

#[test]
fn check_mode_rejects_empty_key_file_env() {
    let out = Command::new(env!("CARGO_BIN_EXE_tessera-issuer"))
        .arg("--check")
        .env_clear()
        .env("TESSERA_ISSUER_LISTEN", "127.0.0.1:0")
        .env("TESSERA_KEY_FILE", "")
        .output()
        .unwrap();

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
