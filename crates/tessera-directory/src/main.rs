//! Operator CLI for signed Tessera exit-directory snapshots.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::PathBuf;

use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use tessera_directory::{
    CapacityEnvelope, DirectorySelectionPolicy, DirectorySnapshot, DirectoryState,
    ExitDirectoryEntry, SignedExitDirectory,
};

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("tessera-directory: {}", msg.as_ref());
    std::process::exit(2)
}

fn usage() -> ! {
    die(
        "usage: tessera-directory <keygen|pin|snapshot|sign|verify|select> [flags]\n\
         keygen --out PATH\n\
         pin --key PATH\n\
         snapshot --sequence N --valid-from N --valid-until N --entry SPEC [--out PATH|-]\n\
         sign --snapshot PATH --key PATH [--key PATH...] [--out PATH|-]\n\
         verify --directory PATH --signers CSV [--min-signatures N] [--now UNIX] [--state-file PATH]\n\
         select --directory PATH --signers CSV [--min-signatures N] [--now UNIX] [--exit-id ID] [--min-key-epoch N]",
    )
}

fn take_one(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let idx = args.iter().position(|arg| arg == flag)?;
    args.remove(idx);
    if idx >= args.len() {
        die(format!("{flag} requires a value"));
    }
    Some(args.remove(idx))
}

fn take_required(args: &mut Vec<String>, flag: &str) -> String {
    take_one(args, flag).unwrap_or_else(|| die(format!("missing required {flag}")))
}

fn take_many(args: &mut Vec<String>, flag: &str) -> Vec<String> {
    let mut values = Vec::new();
    while let Some(value) = take_one(args, flag) {
        values.push(value);
    }
    values
}

fn finish_args(args: &[String]) {
    if !args.is_empty() {
        die(format!("unexpected arguments: {}", args.join(" ")));
    }
}

fn read_text(path: &str) -> String {
    if path == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|e| die(format!("could not read stdin: {e}")));
        text
    } else {
        std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("could not read {path}: {e}")))
    }
}

fn write_text(path: Option<String>, text: &str) {
    match path.as_deref() {
        None | Some("-") => print!("{text}"),
        Some(path) => {
            std::fs::write(path, text)
                .unwrap_or_else(|e| die(format!("could not write {path}: {e}")));
        }
    }
}

fn parse_u64(raw: &str, label: &str) -> u64 {
    raw.parse::<u64>()
        .unwrap_or_else(|e| die(format!("{label} is not a u64: {e}")))
}

fn parse_usize(raw: &str, label: &str) -> usize {
    raw.parse::<usize>()
        .unwrap_or_else(|e| die(format!("{label} is not a positive integer: {e}")))
}

fn parse_private_key(path: &str) -> SigningKey {
    let text = read_text(path);
    let raw = text.trim();
    if raw.is_empty() {
        die(format!("{path}: private key file is empty"));
    }
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(hex).unwrap_or_else(|e| die(format!("{path}: key is not hex: {e}")));
    if bytes.len() != 32 {
        die(format!(
            "{path}: private key must be 32 bytes, got {} bytes",
            bytes.len()
        ));
    }
    SigningKey::from_slice(&bytes).unwrap_or_else(|_| {
        die(format!(
            "{path}: private key is not a valid secp256k1 scalar"
        ))
    })
}

fn signer_pin_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

fn parse_signer_pins(raw: &str) -> Vec<Vec<u8>> {
    if raw.trim().is_empty() {
        die("--signers cannot be empty");
    }
    raw.split(',')
        .enumerate()
        .map(|(idx, part)| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                die(format!("--signers entry {} is empty", idx + 1));
            }
            let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            hex::decode(hex)
                .unwrap_or_else(|e| die(format!("--signers entry {} is not hex: {e}", idx + 1)))
        })
        .collect()
}

fn parse_bool(raw: &str, label: &str) -> bool {
    match raw {
        "1" | "true" | "TRUE" | "True" => true,
        "0" | "false" | "FALSE" | "False" => false,
        other => die(format!("{label} must be 1/0/true/false, got {other}")),
    }
}

fn parse_entry_spec(spec: &str) -> ExitDirectoryEntry {
    let parts: Vec<_> = spec.split(',').collect();
    if parts.len() != 12 {
        die(
            "--entry must have 12 comma-separated fields: id,relay,exit,issuer,issuer_pk_hex,weight,accepting,key_epoch,available_sessions,max_sessions,window_seconds,max_destinations_per_window",
        );
    }
    let issuer_hex = parts[4].strip_prefix("0x").unwrap_or(parts[4]);
    let issuer_pk =
        hex::decode(issuer_hex).unwrap_or_else(|e| die(format!("entry issuer_pk is not hex: {e}")));
    let capacity = CapacityEnvelope::new(
        parse_u64(parts[7], "entry key_epoch"),
        parse_u64(parts[8], "entry available_sessions"),
        parse_u64(parts[9], "entry max_sessions"),
        parse_u64(parts[10], "entry window_seconds"),
        parse_u64(parts[11], "entry max_destinations_per_window"),
    )
    .unwrap_or_else(|e| die(format!("entry capacity invalid: {e}")));
    ExitDirectoryEntry::current_protocols_with_capacity(
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        issuer_pk,
        parse_u64(parts[5], "entry weight"),
        parse_bool(parts[6], "entry accepting"),
        capacity,
    )
    .unwrap_or_else(|e| die(format!("entry invalid: {e}")))
}

fn load_verified_directory(
    args: &mut Vec<String>,
) -> (SignedExitDirectory, String, usize, Option<PathBuf>) {
    let path = take_required(args, "--directory");
    let signers = parse_signer_pins(&take_required(args, "--signers"));
    let min_signatures = take_one(args, "--min-signatures")
        .map(|raw| parse_usize(&raw, "--min-signatures"))
        .unwrap_or(1);
    if min_signatures == 0 {
        die("--min-signatures must be non-zero");
    }
    let now = take_one(args, "--now").map(|raw| parse_u64(&raw, "--now"));
    let state_path = take_one(args, "--state-file").map(PathBuf::from);

    let text = read_text(&path);
    let directory = SignedExitDirectory::parse(&text)
        .unwrap_or_else(|e| die(format!("invalid signed directory: {e}")));
    match now {
        Some(now) => directory
            .verify_at(&signers, min_signatures, now)
            .unwrap_or_else(|e| die(format!("directory rejected: {e}"))),
        None => directory
            .verify_now(&signers, min_signatures)
            .unwrap_or_else(|e| die(format!("directory rejected: {e}"))),
    }
    if let Some(state_path) = &state_path {
        let mut state = DirectoryState::open(state_path).unwrap_or_else(|e| {
            die(format!(
                "could not open state {}: {e}",
                state_path.display()
            ))
        });
        state
            .check_snapshot_and_record(&directory.snapshot)
            .unwrap_or_else(|e| die(format!("directory rejected by state: {e}")));
    }
    (directory, path, min_signatures, state_path)
}

fn cmd_keygen(mut args: Vec<String>) {
    let out = take_required(&mut args, "--out");
    finish_args(&args);
    let key = SigningKey::random(&mut OsRng);
    let secret = hex::encode(key.to_bytes());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&out)
        .unwrap_or_else(|e| die(format!("could not create {out}: {e}")));
    writeln!(file, "{secret}")
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_data())
        .unwrap_or_else(|e| die(format!("could not write {out}: {e}")));
    println!("signer_pk={}", signer_pin_hex(&key));
}

fn cmd_pin(mut args: Vec<String>) {
    let key = parse_private_key(&take_required(&mut args, "--key"));
    finish_args(&args);
    println!("signer_pk={}", signer_pin_hex(&key));
}

fn cmd_snapshot(mut args: Vec<String>) {
    let sequence = parse_u64(&take_required(&mut args, "--sequence"), "--sequence");
    let valid_from = parse_u64(&take_required(&mut args, "--valid-from"), "--valid-from");
    let valid_until = parse_u64(&take_required(&mut args, "--valid-until"), "--valid-until");
    let entries: Vec<_> = take_many(&mut args, "--entry")
        .into_iter()
        .map(|spec| parse_entry_spec(&spec))
        .collect();
    let out = take_one(&mut args, "--out");
    finish_args(&args);
    let snapshot = DirectorySnapshot::new(sequence, valid_from, valid_until, entries)
        .unwrap_or_else(|e| die(format!("snapshot invalid: {e}")));
    let text = snapshot
        .to_text()
        .unwrap_or_else(|e| die(format!("could not serialize snapshot: {e}")));
    write_text(out, &text);
}

fn cmd_sign(mut args: Vec<String>) {
    let snapshot_path = take_required(&mut args, "--snapshot");
    let key_paths = take_many(&mut args, "--key");
    if key_paths.is_empty() {
        die("missing required --key");
    }
    let out = take_one(&mut args, "--out");
    finish_args(&args);
    let snapshot = DirectorySnapshot::parse_unsigned(&read_text(&snapshot_path))
        .unwrap_or_else(|e| die(format!("invalid unsigned snapshot: {e}")));
    let keys: Vec<_> = key_paths
        .iter()
        .map(|path| parse_private_key(path))
        .collect();
    let signed = SignedExitDirectory::sign(snapshot, &keys)
        .unwrap_or_else(|e| die(format!("could not sign snapshot: {e}")));
    let text = signed
        .to_text()
        .unwrap_or_else(|e| die(format!("could not serialize signed directory: {e}")));
    write_text(out, &text);
}

fn cmd_verify(mut args: Vec<String>) {
    let (directory, _path, min_signatures, state_path) = load_verified_directory(&mut args);
    finish_args(&args);
    println!(
        "tessera-directory: verify OK sequence={} entries={} threshold={}{}",
        directory.snapshot.sequence,
        directory.snapshot.entries.len(),
        min_signatures,
        state_path
            .as_ref()
            .map(|path| format!(" state={}", path.display()))
            .unwrap_or_default()
    );
}

fn cmd_select(mut args: Vec<String>) {
    let exit_id = take_one(&mut args, "--exit-id");
    let min_key_epoch =
        take_one(&mut args, "--min-key-epoch").map(|raw| parse_u64(&raw, "--min-key-epoch"));
    if matches!(min_key_epoch, Some(0)) {
        die("--min-key-epoch must be non-zero");
    }
    let (directory, _path, _min_signatures, _state_path) = load_verified_directory(&mut args);
    finish_args(&args);
    let policy = DirectorySelectionPolicy { min_key_epoch };
    let entry = directory
        .snapshot
        .select_with_policy(exit_id.as_deref(), &policy)
        .unwrap_or_else(|e| die(format!("selection failed: {e}")));
    println!("entry_id={}", entry.id);
    println!("issuer_addr={}", entry.issuer_addr);
    println!("relay_addr={}", entry.relay_addr);
    println!("exit_addr={}", entry.exit_addr);
    println!("issuer_pk={}", hex::encode(&entry.issuer_pk));
    println!("weight={}", entry.weight);
    println!("accepting_new_clients={}", entry.accepting_new_clients);
    println!("key_epoch={}", entry.capacity.key_epoch);
    println!(
        "capacity={}/{}",
        entry.capacity.available_sessions, entry.capacity.max_sessions
    );
    println!("window_seconds={}", entry.capacity.window_seconds);
    println!(
        "max_destinations_per_window={}",
        entry.capacity.max_destinations_per_window
    );
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "keygen" => cmd_keygen(args),
        "pin" => cmd_pin(args),
        "snapshot" => cmd_snapshot(args),
        "sign" => cmd_sign(args),
        "verify" => cmd_verify(args),
        "select" => cmd_select(args),
        "-h" | "--help" | "help" => usage(),
        other => die(format!("unknown command {other:?}")),
    }
}
