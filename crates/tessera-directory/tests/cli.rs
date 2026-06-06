//! Binary-level tests for the `tessera-directory` operator CLI.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::SigningKey;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tessera-directory-cli-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tessera-directory"))
}

fn output_text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn signer_hex(byte: u8) -> String {
    hex::encode(
        signing_key(byte)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

fn write_key(dir: &Path, name: &str, byte: u8) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{}\n", hex::encode([byte; 32]))).unwrap();
    path
}

fn issuer_hex(byte: u8) -> String {
    hex::encode(vec![byte; 99])
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn entry_spec(id: &str, issuer_byte: u8, weight: u64, epoch: u64, available: u64) -> String {
    format!(
        "{id},127.0.0.1:{},127.0.0.1:{},127.0.0.1:{},{},{weight},true,{epoch},{available},10,3600,1000",
        8000 + issuer_byte as u16,
        8100 + issuer_byte as u16,
        8200 + issuer_byte as u16,
        issuer_hex(issuer_byte),
    )
}

fn assert_success(out: &Output, msg: &str) {
    let (stdout, stderr) = output_text(out);
    assert!(
        out.status.success(),
        "{msg}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn assert_failure(out: &Output, msg: &str) -> (String, String) {
    let (stdout, stderr) = output_text(out);
    assert!(
        !out.status.success(),
        "{msg}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

#[test]
fn keygen_writes_owner_only_key_and_refuses_overwrite() {
    let dir = temp_dir("keygen");
    let key = dir.join("signer.key");

    let first = cli().arg("keygen").arg("--out").arg(&key).output().unwrap();
    assert_success(&first, "keygen should create a signer key");
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.starts_with("signer_pk="), "{stdout}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "directory signer key must be owner-only");
    }

    let pin = cli().arg("pin").arg("--key").arg(&key).output().unwrap();
    assert_success(&pin, "pin should print the key's signer pin");
    assert_eq!(first.stdout, pin.stdout, "keygen and pin must agree");

    let second = cli().arg("keygen").arg("--out").arg(&key).output().unwrap();
    let (_stdout, stderr) = assert_failure(&second, "keygen must refuse overwrite");
    assert!(stderr.contains("could not create"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_sign_verify_select_and_state_guards_work() {
    let dir = temp_dir("flow");
    let k1 = write_key(&dir, "k1.hex", 7);
    let k2 = write_key(&dir, "k2.hex", 8);
    let signed = dir.join("exits.signed");
    let unsigned = dir.join("exits.unsigned");
    let state = dir.join("directory.state");
    let now = now_unix();

    let snapshot = cli()
        .arg("snapshot")
        .arg("--sequence")
        .arg("5")
        .arg("--valid-from")
        .arg((now - 60).to_string())
        .arg("--valid-until")
        .arg((now + 3600).to_string())
        .arg("--entry")
        .arg(entry_spec("exit-a", 1, 10, 1, 10))
        .arg("--entry")
        .arg(entry_spec("exit-b", 2, 20, 2, 10))
        .arg("--out")
        .arg(&unsigned)
        .output()
        .unwrap();
    assert_success(&snapshot, "snapshot should write unsigned directory text");

    let sign = cli()
        .arg("sign")
        .arg("--snapshot")
        .arg(&unsigned)
        .arg("--key")
        .arg(&k1)
        .arg("--key")
        .arg(&k2)
        .arg("--out")
        .arg(&signed)
        .output()
        .unwrap();
    assert_success(&sign, "sign should write a signed directory");

    let signers = format!("{},{}", signer_hex(7), signer_hex(8));
    let verify = cli()
        .arg("verify")
        .arg("--directory")
        .arg(&signed)
        .arg("--signers")
        .arg(&signers)
        .arg("--min-signatures")
        .arg("2")
        .arg("--now")
        .arg(now.to_string())
        .arg("--state-file")
        .arg(&state)
        .output()
        .unwrap();
    assert_success(&verify, "2-of-2 signed directory should verify");
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("sequence=5"), "{stdout}");
    let state_text = std::fs::read_to_string(&state).unwrap();
    assert!(state_text.contains("entry_epoch=exit-a|1"), "{state_text}");
    assert!(state_text.contains("entry_epoch=exit-b|2"), "{state_text}");

    let selected = cli()
        .arg("select")
        .arg("--directory")
        .arg(&signed)
        .arg("--signers")
        .arg(&signers)
        .arg("--min-signatures")
        .arg("2")
        .arg("--now")
        .arg(now.to_string())
        .arg("--min-key-epoch")
        .arg("2")
        .output()
        .unwrap();
    assert_success(
        &selected,
        "selection should pick the highest-weight current epoch",
    );
    let stdout = String::from_utf8_lossy(&selected.stdout);
    assert!(stdout.contains("entry_id=exit-b"), "{stdout}");
    assert!(stdout.contains("key_epoch=2"), "{stdout}");

    let stale = cli()
        .arg("select")
        .arg("--directory")
        .arg(&signed)
        .arg("--signers")
        .arg(&signers)
        .arg("--min-signatures")
        .arg("2")
        .arg("--now")
        .arg(now.to_string())
        .arg("--exit-id")
        .arg("exit-a")
        .arg("--min-key-epoch")
        .arg("2")
        .output()
        .unwrap();
    let (_stdout, stderr) = assert_failure(&stale, "stale explicit selection must fail");
    assert!(stderr.contains("below required"), "{stderr}");

    let threshold = cli()
        .arg("verify")
        .arg("--directory")
        .arg(&signed)
        .arg("--signers")
        .arg(format!(
            "{},{},{}",
            signer_hex(7),
            signer_hex(8),
            signer_hex(9)
        ))
        .arg("--min-signatures")
        .arg("3")
        .arg("--now")
        .arg(now.to_string())
        .output()
        .unwrap();
    let (_stdout, stderr) = assert_failure(&threshold, "3-of-3 must fail with two signatures");
    assert!(stderr.contains("threshold not met"), "{stderr}");

    let mut tampered = std::fs::read_to_string(&signed).unwrap();
    tampered = tampered.replace("|2|10|10|3600|1000|", "|2|0|10|3600|1000|");
    let tampered_path = dir.join("tampered.signed");
    std::fs::write(&tampered_path, tampered).unwrap();
    let out = cli()
        .arg("verify")
        .arg("--directory")
        .arg(&tampered_path)
        .arg("--signers")
        .arg(&signers)
        .arg("--min-signatures")
        .arg("2")
        .arg("--now")
        .arg(now.to_string())
        .output()
        .unwrap();
    let (_stdout, stderr) = assert_failure(&out, "capacity tampering must break signatures");
    assert!(stderr.contains("did not verify"), "{stderr}");

    let lower_unsigned = dir.join("lower.unsigned");
    let lower_signed = dir.join("lower.signed");
    let lower_snapshot = cli()
        .arg("snapshot")
        .arg("--sequence")
        .arg("4")
        .arg("--valid-from")
        .arg((now - 60).to_string())
        .arg("--valid-until")
        .arg((now + 3600).to_string())
        .arg("--entry")
        .arg(entry_spec("exit-a", 1, 10, 1, 10))
        .arg("--out")
        .arg(&lower_unsigned)
        .output()
        .unwrap();
    assert_success(&lower_snapshot, "lower snapshot should serialize");
    let lower_sign = cli()
        .arg("sign")
        .arg("--snapshot")
        .arg(&lower_unsigned)
        .arg("--key")
        .arg(&k1)
        .arg("--out")
        .arg(&lower_signed)
        .output()
        .unwrap();
    assert_success(&lower_sign, "lower snapshot should sign");
    let rollback = cli()
        .arg("verify")
        .arg("--directory")
        .arg(&lower_signed)
        .arg("--signers")
        .arg(signer_hex(7))
        .arg("--now")
        .arg(now.to_string())
        .arg("--state-file")
        .arg(&state)
        .output()
        .unwrap();
    let (_stdout, stderr) = assert_failure(&rollback, "state must reject sequence rollback");
    assert!(stderr.contains("rollback rejected"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
