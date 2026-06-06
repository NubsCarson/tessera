//! Signed exit-directory snapshots for multi-exit client route selection.
//!
//! The directory is off-band: it does not change ARC issuance, relay CONNECT, or
//! proxy presentation wire formats. A client pins a directory signer set, verifies
//! a snapshot threshold, selects one exit key domain, and pins that entry's full
//! ARC issuer public key before obtaining a credential.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use tessera_arc::group::NE;

const MAGIC: &str = "tessera-exit-directory-v1";
const STATE_MAGIC: &str = "tessera-directory-state-v1";
const MIN_SIGNER_PK_LEN: usize = 33;
const ISSUER_PK_LEN: usize = 3 * NE;

/// A directory parse, validation, signature, selection, or state error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryError {
    message: String,
}

impl DirectoryError {
    /// Build a directory error with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for DirectoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DirectoryError {}

/// One independently operated exit key domain advertised by a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDirectoryEntry {
    /// Stable identifier clients may select with `TESSERA_EXIT_ID`.
    pub id: String,
    /// Relay `HOST:PORT` for the credential-blind first hop.
    pub relay_addr: String,
    /// Exit `HOST:PORT` for the credential-gated second hop.
    pub exit_addr: String,
    /// Issuer `HOST:PORT` for this exit key domain.
    pub issuer_addr: String,
    /// Full serialized ARC issuer public key. The client pins this before issuance.
    pub issuer_pk: Vec<u8>,
    /// Relative selection weight/capacity. Must be non-zero.
    pub weight: u64,
    /// Whether this exit is accepting new client sessions.
    pub accepting_new_clients: bool,
    /// Issuance protocol label expected by this entry.
    pub issue_protocol: String,
    /// Relay protocol label expected by this entry.
    pub relay_protocol: String,
    /// Credential primitive label expected by this entry.
    pub credential_protocol: String,
}

impl ExitDirectoryEntry {
    /// Build and validate one directory entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        relay_addr: impl Into<String>,
        exit_addr: impl Into<String>,
        issuer_addr: impl Into<String>,
        issuer_pk: Vec<u8>,
        weight: u64,
        accepting_new_clients: bool,
        issue_protocol: impl Into<String>,
        relay_protocol: impl Into<String>,
        credential_protocol: impl Into<String>,
    ) -> Result<Self, DirectoryError> {
        let entry = Self {
            id: id.into(),
            relay_addr: relay_addr.into(),
            exit_addr: exit_addr.into(),
            issuer_addr: issuer_addr.into(),
            issuer_pk,
            weight,
            accepting_new_clients,
            issue_protocol: issue_protocol.into(),
            relay_protocol: relay_protocol.into(),
            credential_protocol: credential_protocol.into(),
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Build an entry using the current Tessera protocol labels.
    pub fn current_protocols(
        id: impl Into<String>,
        relay_addr: impl Into<String>,
        exit_addr: impl Into<String>,
        issuer_addr: impl Into<String>,
        issuer_pk: Vec<u8>,
        weight: u64,
        accepting_new_clients: bool,
    ) -> Result<Self, DirectoryError> {
        Self::new(
            id,
            relay_addr,
            exit_addr,
            issuer_addr,
            issuer_pk,
            weight,
            accepting_new_clients,
            "issue-net/v1",
            "relay-connect/v1",
            "arcv1-p256",
        )
    }

    fn validate(&self) -> Result<(), DirectoryError> {
        validate_token("entry id", &self.id)?;
        validate_field("relay address", &self.relay_addr)?;
        validate_field("exit address", &self.exit_addr)?;
        validate_field("issuer address", &self.issuer_addr)?;
        validate_token("issue protocol", &self.issue_protocol)?;
        validate_token("relay protocol", &self.relay_protocol)?;
        validate_token("credential protocol", &self.credential_protocol)?;
        if self.issue_protocol != "issue-net/v1" {
            return Err(DirectoryError::new(format!(
                "entry {} unsupported issue protocol {}",
                self.id, self.issue_protocol
            )));
        }
        if self.relay_protocol != "relay-connect/v1" {
            return Err(DirectoryError::new(format!(
                "entry {} unsupported relay protocol {}",
                self.id, self.relay_protocol
            )));
        }
        if self.credential_protocol != "arcv1-p256" {
            return Err(DirectoryError::new(format!(
                "entry {} unsupported credential protocol {}",
                self.id, self.credential_protocol
            )));
        }
        if self.issuer_pk.len() != ISSUER_PK_LEN {
            return Err(DirectoryError::new(format!(
                "entry {} issuer_pk must be {ISSUER_PK_LEN} bytes, got {}",
                self.id,
                self.issuer_pk.len()
            )));
        }
        if self.weight == 0 {
            return Err(DirectoryError::new(format!(
                "entry {} weight must be non-zero",
                self.id
            )));
        }
        Ok(())
    }

    fn canonical_line(&self) -> String {
        format!(
            "entry={}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.relay_addr,
            self.exit_addr,
            self.issuer_addr,
            hex::encode(&self.issuer_pk),
            self.weight,
            if self.accepting_new_clients { "1" } else { "0" },
            self.issue_protocol,
            self.relay_protocol,
            self.credential_protocol
        )
    }
}

/// The unsigned contents of an exit-directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySnapshot {
    /// Monotonic directory sequence number. Clients may persist it to reject rollback.
    pub sequence: u64,
    /// Unix timestamp when this snapshot becomes valid.
    pub valid_from_unix: u64,
    /// Unix timestamp when this snapshot expires.
    pub valid_until_unix: u64,
    /// Advertised exit key domains.
    pub entries: Vec<ExitDirectoryEntry>,
}

impl DirectorySnapshot {
    /// Build and validate a snapshot.
    pub fn new(
        sequence: u64,
        valid_from_unix: u64,
        valid_until_unix: u64,
        entries: Vec<ExitDirectoryEntry>,
    ) -> Result<Self, DirectoryError> {
        let snapshot = Self {
            sequence,
            valid_from_unix,
            valid_until_unix,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), DirectoryError> {
        if self.valid_until_unix <= self.valid_from_unix {
            return Err(DirectoryError::new(
                "directory valid_until_unix must be after valid_from_unix",
            ));
        }
        if self.entries.is_empty() {
            return Err(DirectoryError::new(
                "directory must contain at least one entry",
            ));
        }
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !ids.insert(entry.id.clone()) {
                return Err(DirectoryError::new(format!(
                    "duplicate directory entry id {}",
                    entry.id
                )));
            }
        }
        Ok(())
    }

    fn sorted_entries(&self) -> Vec<&ExitDirectoryEntry> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        entries
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, DirectoryError> {
        self.validate()?;
        let mut text = String::new();
        text.push_str(MAGIC);
        text.push('\n');
        text.push_str(&format!("sequence={}\n", self.sequence));
        text.push_str(&format!("valid_from_unix={}\n", self.valid_from_unix));
        text.push_str(&format!("valid_until_unix={}\n", self.valid_until_unix));
        for entry in self.sorted_entries() {
            text.push_str(&entry.canonical_line());
            text.push('\n');
        }
        Ok(text.into_bytes())
    }

    /// Select an accepting entry by id, or pick the highest-weight accepting entry.
    pub fn select(&self, id: Option<&str>) -> Result<&ExitDirectoryEntry, DirectoryError> {
        self.validate()?;
        match id {
            Some(id) => {
                let entry = self.entries.iter().find(|e| e.id == id).ok_or_else(|| {
                    DirectoryError::new(format!("directory has no entry with id {id}"))
                })?;
                if !entry.accepting_new_clients {
                    return Err(DirectoryError::new(format!(
                        "directory entry {id} is not accepting new clients"
                    )));
                }
                Ok(entry)
            }
            None => self
                .entries
                .iter()
                .filter(|e| e.accepting_new_clients)
                .max_by(|a, b| a.weight.cmp(&b.weight).then_with(|| b.id.cmp(&a.id)))
                .ok_or_else(|| DirectoryError::new("directory has no accepting entries")),
        }
    }
}

/// One compact secp256k1 ECDSA directory signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySignature {
    /// SEC1-encoded signer public key.
    pub signer_pk: Vec<u8>,
    /// Compact 64-byte ECDSA signature over the canonical snapshot payload.
    pub signature: Vec<u8>,
}

/// A signed exit-directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedExitDirectory {
    /// Snapshot payload.
    pub snapshot: DirectorySnapshot,
    /// Signatures over the canonical snapshot payload.
    pub signatures: Vec<DirectorySignature>,
}

impl SignedExitDirectory {
    /// Sign a snapshot with one or more secp256k1 directory signers.
    pub fn sign(
        snapshot: DirectorySnapshot,
        signing_keys: &[SigningKey],
    ) -> Result<Self, DirectoryError> {
        if signing_keys.is_empty() {
            return Err(DirectoryError::new("directory needs at least one signer"));
        }
        let payload = snapshot.canonical_payload()?;
        let mut signatures = Vec::with_capacity(signing_keys.len());
        let mut seen = BTreeSet::new();
        for key in signing_keys {
            let signer_pk = key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec();
            if !seen.insert(hex::encode(&signer_pk)) {
                return Err(DirectoryError::new("duplicate signing key"));
            }
            let sig: Signature = key.sign(&payload);
            signatures.push(DirectorySignature {
                signer_pk,
                signature: sig.to_bytes().to_vec(),
            });
        }
        Ok(Self {
            snapshot,
            signatures,
        })
    }

    /// Parse a line-oriented signed directory snapshot.
    pub fn parse(text: &str) -> Result<Self, DirectoryError> {
        let mut lines = text.lines();
        match lines.next() {
            Some(MAGIC) => {}
            _ => return Err(DirectoryError::new("missing directory magic")),
        }

        let sequence = parse_u64_line(lines.next(), "sequence=", "missing sequence line")?;
        let valid_from_unix = parse_u64_line(
            lines.next(),
            "valid_from_unix=",
            "missing valid_from_unix line",
        )?;
        let valid_until_unix = parse_u64_line(
            lines.next(),
            "valid_until_unix=",
            "missing valid_until_unix line",
        )?;

        let mut entries = Vec::new();
        let mut signatures = Vec::new();
        let mut saw_signature = false;
        for line in lines {
            if let Some(rest) = line.strip_prefix("signature=") {
                saw_signature = true;
                signatures.push(parse_signature(rest)?);
            } else if let Some(rest) = line.strip_prefix("entry=") {
                if saw_signature {
                    return Err(DirectoryError::new("entry appears after signature"));
                }
                entries.push(parse_entry(rest)?);
            } else if line.trim().is_empty() {
                return Err(DirectoryError::new(
                    "blank lines are not allowed in directory",
                ));
            } else {
                return Err(DirectoryError::new(format!(
                    "unknown directory line: {line}"
                )));
            }
        }
        if signatures.is_empty() {
            return Err(DirectoryError::new("missing directory signature"));
        }
        let snapshot =
            DirectorySnapshot::new(sequence, valid_from_unix, valid_until_unix, entries)?;
        Ok(Self {
            snapshot,
            signatures,
        })
    }

    /// Serialize this directory in canonical signed form.
    pub fn to_text(&self) -> Result<String, DirectoryError> {
        let mut text = String::from_utf8(self.snapshot.canonical_payload()?)
            .map_err(|e| DirectoryError::new(format!("canonical payload was not utf8: {e}")))?;
        let mut signatures = self.signatures.clone();
        signatures.sort_by(|a, b| a.signer_pk.cmp(&b.signer_pk));
        for sig in &signatures {
            validate_signer_pk(&sig.signer_pk)?;
            if sig.signature.len() != 64 {
                return Err(DirectoryError::new(format!(
                    "signature must be 64 bytes, got {}",
                    sig.signature.len()
                )));
            }
            text.push_str("signature=");
            text.push_str(&hex::encode(&sig.signer_pk));
            text.push('|');
            text.push_str(&hex::encode(&sig.signature));
            text.push('\n');
        }
        Ok(text)
    }

    /// Verify signature threshold, signer pins, and snapshot validity window.
    pub fn verify_at(
        &self,
        pinned_signers: &[Vec<u8>],
        min_signatures: usize,
        unix_time: u64,
    ) -> Result<(), DirectoryError> {
        if min_signatures == 0 {
            return Err(DirectoryError::new(
                "directory min signatures must be non-zero",
            ));
        }
        if pinned_signers.len() < min_signatures {
            return Err(DirectoryError::new(
                "directory signer set smaller than signature threshold",
            ));
        }
        if unix_time < self.snapshot.valid_from_unix {
            return Err(DirectoryError::new("directory snapshot is not valid yet"));
        }
        if unix_time >= self.snapshot.valid_until_unix {
            return Err(DirectoryError::new("directory snapshot is expired"));
        }

        let pinned = pinned_set(pinned_signers)?;
        let payload = self.snapshot.canonical_payload()?;
        let mut satisfied = BTreeSet::new();
        for sig in &self.signatures {
            validate_signer_pk(&sig.signer_pk)?;
            if sig.signature.len() != 64 {
                return Err(DirectoryError::new(format!(
                    "signature must be 64 bytes, got {}",
                    sig.signature.len()
                )));
            }
            let signer_hex = hex::encode(&sig.signer_pk);
            if !pinned.contains(&signer_hex) {
                continue;
            }
            if !satisfied.insert(signer_hex) {
                return Err(DirectoryError::new("duplicate directory signer signature"));
            }
            let verifying_key = VerifyingKey::from_sec1_bytes(&sig.signer_pk).map_err(|_| {
                DirectoryError::new("directory signer key is not a valid secp256k1 key")
            })?;
            let signature = Signature::from_slice(&sig.signature)
                .map_err(|_| DirectoryError::new("directory signature is malformed"))?;
            verifying_key
                .verify(&payload, &signature)
                .map_err(|_| DirectoryError::new("directory signature did not verify"))?;
        }
        if satisfied.len() < min_signatures {
            return Err(DirectoryError::new(format!(
                "directory signature threshold not met: got {}, need {min_signatures}",
                satisfied.len()
            )));
        }
        Ok(())
    }

    /// Verify against the current system time.
    pub fn verify_now(
        &self,
        pinned_signers: &[Vec<u8>],
        min_signatures: usize,
    ) -> Result<(), DirectoryError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DirectoryError::new(format!("system clock before Unix epoch: {e}")))?
            .as_secs();
        self.verify_at(pinned_signers, min_signatures, now)
    }
}

/// Result of checking a directory sequence against local rollback state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryStateCheck {
    /// The sequence equals the last accepted sequence.
    Same,
    /// The sequence advanced and state was updated.
    Advanced,
}

/// Local anti-rollback state for a pinned directory signer set.
pub struct DirectoryState {
    path: PathBuf,
    last_sequence: Option<u64>,
}

impl DirectoryState {
    /// Open or create a directory state file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref().to_path_buf();
        let last_sequence = match std::fs::read_to_string(&path) {
            Ok(text) => Some(parse_state(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(DirectoryError::new(format!(
                    "could not read directory state {}: {e}",
                    path.display()
                )));
            }
        };
        Ok(Self {
            path,
            last_sequence,
        })
    }

    /// Reject lower sequence numbers and persist higher ones.
    pub fn check_and_record(
        &mut self,
        sequence: u64,
    ) -> Result<DirectoryStateCheck, DirectoryError> {
        if let Some(last) = self.last_sequence {
            if sequence < last {
                return Err(DirectoryError::new(format!(
                    "directory rollback rejected: sequence {sequence} < last accepted {last}"
                )));
            }
            if sequence == last {
                return Ok(DirectoryStateCheck::Same);
            }
        }
        self.write(sequence)?;
        self.last_sequence = Some(sequence);
        Ok(DirectoryStateCheck::Advanced)
    }

    /// Return the last accepted sequence, if any.
    pub fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    fn write(&self, sequence: u64) -> Result<(), DirectoryError> {
        let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            if !parent.is_dir() {
                return Err(DirectoryError::new(format!(
                    "directory state parent {} is not a directory",
                    parent.display()
                )));
            }
        }
        let tmp = self
            .path
            .with_extension(format!("tmp.{}.{}", std::process::id(), sequence));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| {
                DirectoryError::new(format!(
                    "could not create directory state temp {}: {e}",
                    tmp.display()
                ))
            })?;
        write!(file, "{STATE_MAGIC}\nlast_sequence={sequence}\n")
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_data())
            .map_err(|e| DirectoryError::new(format!("could not write directory state: {e}")))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            DirectoryError::new(format!(
                "could not publish directory state {}: {e}",
                self.path.display()
            ))
        })?;
        Ok(())
    }
}

fn validate_field(name: &str, value: &str) -> Result<(), DirectoryError> {
    if value.is_empty() {
        return Err(DirectoryError::new(format!("{name} is empty")));
    }
    if value.contains('|') || value.contains('\n') || value.contains('\r') {
        return Err(DirectoryError::new(format!(
            "{name} contains a forbidden separator"
        )));
    }
    Ok(())
}

fn validate_token(name: &str, value: &str) -> Result<(), DirectoryError> {
    validate_field(name, value)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(DirectoryError::new(format!(
            "{name} must use only ASCII alnum, dash, underscore, dot, or slash"
        )));
    }
    Ok(())
}

fn validate_signer_pk(signer_pk: &[u8]) -> Result<(), DirectoryError> {
    if signer_pk.len() < MIN_SIGNER_PK_LEN {
        return Err(DirectoryError::new(format!(
            "directory signer pin must be a full SEC1 key, got {} bytes",
            signer_pk.len()
        )));
    }
    VerifyingKey::from_sec1_bytes(signer_pk)
        .map_err(|_| DirectoryError::new("directory signer key is not a valid secp256k1 key"))?;
    Ok(())
}

fn pinned_set(pinned_signers: &[Vec<u8>]) -> Result<BTreeSet<String>, DirectoryError> {
    let mut set = BTreeSet::new();
    for signer in pinned_signers {
        validate_signer_pk(signer)?;
        let hex = hex::encode(signer);
        if !set.insert(hex) {
            return Err(DirectoryError::new("duplicate pinned directory signer"));
        }
    }
    Ok(set)
}

fn parse_u64_line(line: Option<&str>, prefix: &str, missing: &str) -> Result<u64, DirectoryError> {
    let line = line.ok_or_else(|| DirectoryError::new(missing))?;
    let raw = line
        .strip_prefix(prefix)
        .ok_or_else(|| DirectoryError::new(missing))?;
    raw.parse::<u64>()
        .map_err(|e| DirectoryError::new(format!("{prefix} value is not a u64: {e}")))
}

fn parse_entry(rest: &str) -> Result<ExitDirectoryEntry, DirectoryError> {
    let parts: Vec<_> = rest.split('|').collect();
    if parts.len() != 10 {
        return Err(DirectoryError::new(
            "entry must have 10 fields: id|relay|exit|issuer|issuer_pk|weight|accepting|issue|relay_proto|credential",
        ));
    }
    let issuer_pk = hex::decode(parts[4])
        .map_err(|e| DirectoryError::new(format!("entry issuer_pk is not valid hex: {e}")))?;
    let weight = parts[5]
        .parse::<u64>()
        .map_err(|e| DirectoryError::new(format!("entry weight is not a u64: {e}")))?;
    let accepting_new_clients = match parts[6] {
        "1" => true,
        "0" => false,
        other => {
            return Err(DirectoryError::new(format!(
                "entry accepting flag must be 0 or 1, got {other}"
            )));
        }
    };
    ExitDirectoryEntry::new(
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        issuer_pk,
        weight,
        accepting_new_clients,
        parts[7],
        parts[8],
        parts[9],
    )
}

fn parse_signature(rest: &str) -> Result<DirectorySignature, DirectoryError> {
    let (pk_hex, sig_hex) = rest
        .split_once('|')
        .ok_or_else(|| DirectoryError::new("signature must be signer_pk|signature"))?;
    let signer_pk = hex::decode(pk_hex)
        .map_err(|e| DirectoryError::new(format!("signature signer is not valid hex: {e}")))?;
    validate_signer_pk(&signer_pk)?;
    let signature = hex::decode(sig_hex)
        .map_err(|e| DirectoryError::new(format!("signature is not valid hex: {e}")))?;
    if signature.len() != 64 {
        return Err(DirectoryError::new(format!(
            "signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    Ok(DirectorySignature {
        signer_pk,
        signature,
    })
}

fn parse_state(text: &str) -> Result<u64, DirectoryError> {
    let mut lines = text.lines();
    match lines.next() {
        Some(STATE_MAGIC) => {}
        _ => return Err(DirectoryError::new("bad directory state magic")),
    }
    let seq = parse_u64_line(lines.next(), "last_sequence=", "missing last_sequence")?;
    if lines.next().is_some() {
        return Err(DirectoryError::new("trailing data in directory state"));
    }
    Ok(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap()
    }

    fn signer_pk(key: &SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn issuer_pk(byte: u8) -> Vec<u8> {
        vec![byte; ISSUER_PK_LEN]
    }

    fn snapshot(sequence: u64) -> DirectorySnapshot {
        DirectorySnapshot::new(
            sequence,
            100,
            200,
            vec![
                ExitDirectoryEntry::current_protocols(
                    "exit-b",
                    "127.0.0.1:8119",
                    "127.0.0.1:8118",
                    "127.0.0.1:8121",
                    issuer_pk(2),
                    20,
                    true,
                )
                .unwrap(),
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
            ],
        )
        .unwrap()
    }

    #[test]
    fn signed_directory_round_trips_and_verifies_threshold() {
        let k1 = signing_key(7);
        let k2 = signing_key(8);
        let signed = SignedExitDirectory::sign(snapshot(3), &[k1.clone(), k2.clone()]).unwrap();
        let text = signed.to_text().unwrap();
        let parsed = SignedExitDirectory::parse(&text).unwrap();

        parsed
            .verify_at(&[signer_pk(&k1), signer_pk(&k2)], 2, 150)
            .unwrap();
        assert_eq!(
            parsed.snapshot.select(None).unwrap().id,
            "exit-b",
            "default selection uses highest weight"
        );
        assert_eq!(
            parsed.snapshot.select(Some("exit-a")).unwrap().issuer_pk,
            issuer_pk(1)
        );
    }

    #[test]
    fn threshold_not_met_is_rejected() {
        let k1 = signing_key(7);
        let k2 = signing_key(8);
        let signed = SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&k1)).unwrap();
        let err = signed
            .verify_at(&[signer_pk(&k1), signer_pk(&k2)], 2, 150)
            .expect_err("threshold must fail");
        assert!(err.to_string().contains("threshold"), "{err}");
    }

    #[test]
    fn unknown_signer_is_ignored_and_fails_threshold() {
        let k1 = signing_key(7);
        let k2 = signing_key(8);
        let signed = SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&k2)).unwrap();
        let err = signed
            .verify_at(&[signer_pk(&k1)], 1, 150)
            .expect_err("unknown signer cannot satisfy threshold");
        assert!(err.to_string().contains("threshold"), "{err}");
    }

    #[test]
    fn tampered_entry_is_rejected() {
        let k1 = signing_key(7);
        let signed = SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&k1)).unwrap();
        let mut text = signed.to_text().unwrap();
        text = text.replace("127.0.0.1:8121", "127.0.0.1:9999");
        let parsed = SignedExitDirectory::parse(&text).unwrap();

        let err = parsed
            .verify_at(&[signer_pk(&k1)], 1, 150)
            .expect_err("tampering must break the signature");
        assert!(err.to_string().contains("did not verify"), "{err}");
    }

    #[test]
    fn expired_snapshot_is_rejected() {
        let k1 = signing_key(7);
        let signed = SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&k1)).unwrap();
        let err = signed
            .verify_at(&[signer_pk(&k1)], 1, 250)
            .expect_err("expired snapshot must fail closed");
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let entry = ExitDirectoryEntry::current_protocols(
            "dup",
            "127.0.0.1:1",
            "127.0.0.1:2",
            "127.0.0.1:3",
            issuer_pk(1),
            1,
            true,
        )
        .unwrap();
        let err = DirectorySnapshot::new(1, 1, 2, vec![entry.clone(), entry])
            .expect_err("duplicate ids fail");
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn non_accepting_entries_are_not_selected() {
        let snapshot = DirectorySnapshot::new(
            1,
            1,
            2,
            vec![ExitDirectoryEntry::current_protocols(
                "closed",
                "127.0.0.1:1",
                "127.0.0.1:2",
                "127.0.0.1:3",
                issuer_pk(1),
                100,
                false,
            )
            .unwrap()],
        )
        .unwrap();
        assert!(snapshot.select(None).is_err());
        assert!(snapshot.select(Some("closed")).is_err());
    }

    #[test]
    fn rollback_state_rejects_lower_sequence() {
        let dir = std::env::temp_dir().join(format!(
            "tessera-directory-state-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut state = DirectoryState::open(&dir).unwrap();
        assert_eq!(
            state.check_and_record(10).unwrap(),
            DirectoryStateCheck::Advanced
        );
        assert_eq!(
            state.check_and_record(10).unwrap(),
            DirectoryStateCheck::Same
        );
        let err = state
            .check_and_record(9)
            .expect_err("rollback must fail closed");
        assert!(err.to_string().contains("rollback"), "{err}");
        let reopened = DirectoryState::open(&dir).unwrap();
        assert_eq!(reopened.last_sequence(), Some(10));
        let _ = std::fs::remove_file(&dir);
    }
}
