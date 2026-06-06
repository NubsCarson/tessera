//! Binary-level config tests for `tessera-client --check`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::SigningKey;
use tessera_client::{
    CapacityEnvelope, DirectorySnapshot, DirectoryState, ExitDirectoryEntry, SignedExitDirectory,
};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tessera-client-config-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn signer_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

fn issuer_pk(byte: u8) -> Vec<u8> {
    vec![byte; 99]
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn directory_text(sequence: u64, signing_keys: &[SigningKey]) -> String {
    directory_text_with_entries(
        sequence,
        vec![
            ExitDirectoryEntry::current_protocols(
                "exit-a",
                "127.0.0.1:9119",
                "127.0.0.1:9118",
                "127.0.0.1:9121",
                issuer_pk(1),
                10,
                true,
            )
            .unwrap(),
            ExitDirectoryEntry::current_protocols_with_capacity(
                "exit-b",
                "127.0.0.1:8119",
                "127.0.0.1:8118",
                "127.0.0.1:8121",
                issuer_pk(2),
                20,
                true,
                CapacityEnvelope::new(2, 10, 10, 3600, 1000).unwrap(),
            )
            .unwrap(),
        ],
        signing_keys,
    )
}

fn directory_text_with_entries(
    sequence: u64,
    entries: Vec<ExitDirectoryEntry>,
    signing_keys: &[SigningKey],
) -> String {
    let now = now_unix();
    let snapshot =
        DirectorySnapshot::new(sequence, now.saturating_sub(60), now + 3600, entries).unwrap();
    SignedExitDirectory::sign(snapshot, signing_keys)
        .unwrap()
        .to_text()
        .unwrap()
}

fn write_directory(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("exits.tessera-directory");
    std::fs::write(&path, text).unwrap();
    path
}

fn client_check() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tessera-client"));
    cmd.arg("--check")
        .env_clear()
        .env("TESSERA_CLIENT_LISTEN", "127.0.0.1:0");
    cmd
}

fn output_text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_mode_accepts_signed_directory_and_records_state() {
    let dir = temp_dir("ok");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(7, std::slice::from_ref(&k1)));
    let state = dir.join("directory.state");

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_DIRECTORY_STATE_FILE", &state)
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        out.status.success(),
        "--check should accept the signed directory\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("tessera-client: config OK"), "{stdout}");
    assert!(stdout.contains("entry=exit-b"), "{stdout}");
    assert!(stdout.contains("seq=7"), "{stdout}");
    assert!(stdout.contains("threshold=1"), "{stdout}");
    assert!(stdout.contains("key_epoch=2"), "{stdout}");
    assert!(stdout.contains("capacity=10/10"), "{stdout}");
    assert!(stdout.contains("pin=set"), "{stdout}");
    assert!(stdout.contains("state="), "{stdout}");
    let state_text = std::fs::read_to_string(&state).unwrap();
    assert!(state_text.contains("last_sequence=7"), "{state_text}");
    assert!(state_text.contains("snapshot_hash="), "{state_text}");
    assert!(state_text.contains("entry_epoch=exit-b|2"), "{state_text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_rejects_tampered_directory() {
    let dir = temp_dir("tampered");
    let k1 = signing_key(7);
    let text =
        directory_text(1, std::slice::from_ref(&k1)).replace("127.0.0.1:8121", "127.0.0.1:9999");
    let path = write_directory(&dir, &text);

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "tampered directory must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("exit directory rejected"), "{stderr}");
    assert!(stderr.contains("did not verify"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_enforces_signature_threshold() {
    let dir = temp_dir("threshold");
    let k1 = signing_key(7);
    let k2 = signing_key(8);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));
    let signers = format!("{},{}", signer_hex(&k1), signer_hex(&k2));

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signers)
        .env("TESSERA_DIRECTORY_MIN_SIGNATURES", "2")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "directory below threshold must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("threshold not met"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_rejects_directory_rollback_state() {
    let dir = temp_dir("rollback");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(9, std::slice::from_ref(&k1)));
    let state_path = dir.join("directory.state");
    let mut state = DirectoryState::open(&state_path).unwrap();
    state.check_and_record(10).unwrap();

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_DIRECTORY_STATE_FILE", &state_path)
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "lower directory sequence must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("rollback rejected"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn paid_mode_accepts_directory_supplied_issuer_pin() {
    let dir = temp_dir("paid");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_BUYER_KEY", hex::encode([5u8; 32]))
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        out.status.success(),
        "directory-supplied full issuer pin should satisfy paid mode\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("mode=paid"), "{stdout}");
    assert!(stdout.contains("pin=set"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_mode_can_select_explicit_lower_weight_exit() {
    let dir = temp_dir("explicit");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_EXIT_ID", "exit-a")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        out.status.success(),
        "explicit lower-weight exit should be selectable\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("entry=exit-a"), "{stdout}");
    assert!(stdout.contains("issuer=127.0.0.1:9121"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_mode_rejects_closed_explicit_exit() {
    let dir = temp_dir("closed");
    let k1 = signing_key(7);
    let text = directory_text_with_entries(
        1,
        vec![ExitDirectoryEntry::current_protocols(
            "exit-a",
            "127.0.0.1:9119",
            "127.0.0.1:9118",
            "127.0.0.1:9121",
            issuer_pk(1),
            10,
            false,
        )
        .unwrap()],
        std::slice::from_ref(&k1),
    );
    let path = write_directory(&dir, &text);

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_EXIT_ID", "exit-a")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "closed explicit exit must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("not accepting new clients"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_mode_enforces_min_key_epoch() {
    let dir = temp_dir("min-epoch");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_EXIT_ID", "exit-a")
        .env("TESSERA_DIRECTORY_MIN_KEY_EPOCH", "2")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "stale selected key epoch must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("below required"), "{stderr}");

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_DIRECTORY_MIN_KEY_EPOCH", "2")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        out.status.success(),
        "default selection should skip stale exit and use epoch-2 exit\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("entry=exit-b"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_mode_rejects_manual_route_overrides() {
    let dir = temp_dir("override");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .env("TESSERA_RELAY", "127.0.0.1:1")
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "directory mode must reject manual route overrides\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("TESSERA_RELAY cannot be set"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stray_directory_env_fails_without_directory_file() {
    let k1 = signing_key(7);

    let out = client_check()
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "directory signer pins without a directory file must fail closed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("requires TESSERA_DIRECTORY_FILE"),
        "{stderr}"
    );
}

#[test]
fn legacy_directory_alias_works_and_conflict_fails() {
    let dir = temp_dir("alias");
    let k1 = signing_key(7);
    let path = write_directory(&dir, &directory_text(1, std::slice::from_ref(&k1)));

    let out = client_check()
        .env("TESSERA_EXIT_DIRECTORY", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        out.status.success(),
        "legacy alias should still work\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("tessera-client: config OK"), "{stdout}");

    let out = client_check()
        .env("TESSERA_DIRECTORY_FILE", &path)
        .env("TESSERA_EXIT_DIRECTORY", &path)
        .env("TESSERA_DIRECTORY_SIGNERS", signer_hex(&k1))
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&out);
    assert!(
        !out.status.success(),
        "new and legacy directory env vars together must fail\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("set only one"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
