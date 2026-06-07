//! Signed exit-directory snapshots for multi-exit client route selection.
//!
//! The directory is off-band: it does not change ARC issuance, relay CONNECT, or
//! proxy presentation wire formats. A client pins a directory signer set, verifies
//! a snapshot threshold, selects one exit key domain, and pins that entry's full
//! ARC issuer public key before obtaining a credential.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tessera_arc::group::NE;

const MAGIC: &str = "tessera-exit-directory-v2";
const STATE_MAGIC: &str = "tessera-directory-state-v1";
const MIN_SIGNER_PK_LEN: usize = 33;
const ISSUER_PK_LEN: usize = 3 * NE;
const DEFAULT_CAPACITY_WINDOW_SECONDS: u64 = 3600;
const DEFAULT_MAX_DESTINATIONS_PER_WINDOW: u64 = 1000;

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

/// Parse comma-separated SEC1 directory signer public-key pins from hex.
pub fn parse_signer_pins_csv(raw: &str) -> Result<Vec<Vec<u8>>, DirectoryError> {
    if raw.trim().is_empty() {
        return Err(DirectoryError::new(
            "directory signer pin list cannot be empty",
        ));
    }
    raw.split(',')
        .enumerate()
        .map(|(idx, part)| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return Err(DirectoryError::new(format!(
                    "directory signer pin entry {} is empty",
                    idx + 1
                )));
            }
            let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            let signer = hex::decode(hex_str).map_err(|e| {
                DirectoryError::new(format!(
                    "directory signer pin entry {} is not valid hex: {e}",
                    idx + 1
                ))
            })?;
            validate_signer_pk(&signer)?;
            Ok(signer)
        })
        .collect()
}

/// Signed capacity and key-epoch metadata for one exit key domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEnvelope {
    /// Monotonic per-exit ARC key epoch. Clients persist this to reject rollback.
    pub key_epoch: u64,
    /// Currently advertised available client sessions.
    pub available_sessions: u64,
    /// Maximum client sessions this exit is willing to advertise for the window.
    pub max_sessions: u64,
    /// Capacity-policy accounting window in seconds.
    pub window_seconds: u64,
    /// Maximum distinct destinations per accounting window for this exit.
    pub max_destinations_per_window: u64,
}

impl CapacityEnvelope {
    /// Build and validate a capacity envelope.
    pub fn new(
        key_epoch: u64,
        available_sessions: u64,
        max_sessions: u64,
        window_seconds: u64,
        max_destinations_per_window: u64,
    ) -> Result<Self, DirectoryError> {
        let envelope = Self {
            key_epoch,
            available_sessions,
            max_sessions,
            window_seconds,
            max_destinations_per_window,
        };
        envelope.validate("capacity")?;
        Ok(envelope)
    }

    /// Conservative default for entries that use the current protocol labels.
    pub fn current_default() -> Self {
        Self {
            key_epoch: 1,
            available_sessions: 1,
            max_sessions: 1,
            window_seconds: DEFAULT_CAPACITY_WINDOW_SECONDS,
            max_destinations_per_window: DEFAULT_MAX_DESTINATIONS_PER_WINDOW,
        }
    }

    fn validate(&self, label: &str) -> Result<(), DirectoryError> {
        if self.key_epoch == 0 {
            return Err(DirectoryError::new(format!(
                "{label} key_epoch must be non-zero"
            )));
        }
        if self.max_sessions == 0 {
            return Err(DirectoryError::new(format!(
                "{label} max_sessions must be non-zero"
            )));
        }
        if self.available_sessions > self.max_sessions {
            return Err(DirectoryError::new(format!(
                "{label} available_sessions {} exceeds max_sessions {}",
                self.available_sessions, self.max_sessions
            )));
        }
        if self.window_seconds == 0 {
            return Err(DirectoryError::new(format!(
                "{label} window_seconds must be non-zero"
            )));
        }
        if self.max_destinations_per_window == 0 {
            return Err(DirectoryError::new(format!(
                "{label} max_destinations_per_window must be non-zero"
            )));
        }
        Ok(())
    }
}

/// Client-side policy applied after a signed directory snapshot verifies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectorySelectionPolicy {
    /// Reject entries below this per-exit ARC key epoch, when set.
    pub min_key_epoch: Option<u64>,
    /// Require the exit to advertise an `.onion` endpoint (the onion lane).
    pub require_onion: bool,
    /// Require the exit's signed clean-egress capability flag to be set.
    pub require_clean_egress: bool,
}

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
    /// Signed capacity and per-exit key-epoch metadata.
    pub capacity: CapacityEnvelope,
    /// Issuance protocol label expected by this entry.
    pub issue_protocol: String,
    /// Relay protocol label expected by this entry.
    pub relay_protocol: String,
    /// Credential primitive label expected by this entry.
    pub credential_protocol: String,
    /// Optional `.onion:port` for the single-hop onion lane (the client dials it
    /// over Tor SOCKS). `None` => a clearnet-only exit (reach it via the relay).
    pub onion_addr: Option<String>,
    /// The operator's **signed** clean-egress capability claim. This is an
    /// attestation a client can require/prefer, NOT a cryptographic proof that the
    /// egress IP is clean (no code can prove that — see CLAUDE.md "three gaps").
    pub clean_egress: bool,
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
        capacity: CapacityEnvelope,
        issue_protocol: impl Into<String>,
        relay_protocol: impl Into<String>,
        credential_protocol: impl Into<String>,
        onion_addr: Option<String>,
        clean_egress: bool,
    ) -> Result<Self, DirectoryError> {
        let entry = Self {
            id: id.into(),
            relay_addr: relay_addr.into(),
            exit_addr: exit_addr.into(),
            issuer_addr: issuer_addr.into(),
            issuer_pk,
            weight,
            accepting_new_clients,
            capacity,
            issue_protocol: issue_protocol.into(),
            relay_protocol: relay_protocol.into(),
            credential_protocol: credential_protocol.into(),
            onion_addr,
            clean_egress,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Set the onion-lane advertisement (`onion_addr` + `clean_egress`) on an
    /// already-built entry and re-validate. Convenience for the convenience ctors,
    /// which default these to `None`/`false`.
    pub fn with_onion(
        mut self,
        onion_addr: Option<String>,
        clean_egress: bool,
    ) -> Result<Self, DirectoryError> {
        self.onion_addr = onion_addr;
        self.clean_egress = clean_egress;
        self.validate()?;
        Ok(self)
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
        Self::current_protocols_with_capacity(
            id,
            relay_addr,
            exit_addr,
            issuer_addr,
            issuer_pk,
            weight,
            accepting_new_clients,
            CapacityEnvelope::current_default(),
        )
    }

    /// Build an entry using the current Tessera protocol labels and capacity.
    #[allow(clippy::too_many_arguments)]
    pub fn current_protocols_with_capacity(
        id: impl Into<String>,
        relay_addr: impl Into<String>,
        exit_addr: impl Into<String>,
        issuer_addr: impl Into<String>,
        issuer_pk: Vec<u8>,
        weight: u64,
        accepting_new_clients: bool,
        capacity: CapacityEnvelope,
    ) -> Result<Self, DirectoryError> {
        Self::new(
            id,
            relay_addr,
            exit_addr,
            issuer_addr,
            issuer_pk,
            weight,
            accepting_new_clients,
            capacity,
            "issue-net/v1",
            "relay-connect/v1",
            "arcv1-p256",
            None,
            false,
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
        self.capacity
            .validate(&format!("entry {} capacity", self.id))?;
        if let Some(onion) = &self.onion_addr {
            if onion.is_empty() {
                return Err(DirectoryError::new(format!(
                    "entry {} onion_addr is set but empty (use None for a clearnet-only exit)",
                    self.id
                )));
            }
            // An `.onion:port` is a token (base32 + `.onion` + `:port`); it must
            // not contain the field/line delimiters. Same charset as the addresses.
            validate_field("onion address", onion)?;
        }
        Ok(())
    }

    fn canonical_line(&self) -> String {
        // The onion fields are APPENDED (positions 16/17) so the original 15 field
        // indices are unchanged. An empty onion field encodes `None`.
        format!(
            "entry={}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.relay_addr,
            self.exit_addr,
            self.issuer_addr,
            hex::encode(&self.issuer_pk),
            self.weight,
            if self.accepting_new_clients { "1" } else { "0" },
            self.capacity.key_epoch,
            self.capacity.available_sessions,
            self.capacity.max_sessions,
            self.capacity.window_seconds,
            self.capacity.max_destinations_per_window,
            self.issue_protocol,
            self.relay_protocol,
            self.credential_protocol,
            self.onion_addr.as_deref().unwrap_or(""),
            if self.clean_egress { "1" } else { "0" }
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

    /// Parse an unsigned directory snapshot in canonical text form.
    pub fn parse_unsigned(text: &str) -> Result<Self, DirectoryError> {
        let ParsedDirectoryText {
            snapshot,
            signatures,
        } = parse_directory_text(text, false)?;
        if !signatures.is_empty() {
            return Err(DirectoryError::new(
                "unsigned directory snapshot must not contain signatures",
            ));
        }
        Ok(snapshot)
    }

    /// Serialize this unsigned snapshot in canonical text form.
    pub fn to_text(&self) -> Result<String, DirectoryError> {
        String::from_utf8(self.canonical_payload()?)
            .map_err(|e| DirectoryError::new(format!("canonical payload was not utf8: {e}")))
    }

    fn canonical_hash_hex(&self) -> Result<String, DirectoryError> {
        Ok(hex::encode(Sha256::digest(self.canonical_payload()?)))
    }

    /// Select an accepting entry by id, or pick the highest-weight accepting entry.
    pub fn select(&self, id: Option<&str>) -> Result<&ExitDirectoryEntry, DirectoryError> {
        self.select_with_policy(id, &DirectorySelectionPolicy::default())
    }

    /// Select an entry using an explicit client policy.
    pub fn select_with_policy(
        &self,
        id: Option<&str>,
        policy: &DirectorySelectionPolicy,
    ) -> Result<&ExitDirectoryEntry, DirectoryError> {
        self.validate()?;
        match id {
            Some(id) => {
                let entry = self.entries.iter().find(|e| e.id == id).ok_or_else(|| {
                    DirectoryError::new(format!("directory has no entry with id {id}"))
                })?;
                if let Some(err) = selection_error(entry, policy) {
                    return Err(err);
                }
                Ok(entry)
            }
            None => self
                .entries
                .iter()
                .filter(|e| entry_selectable(e, policy))
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
        let ParsedDirectoryText {
            snapshot,
            signatures,
        } = parse_directory_text(text, true)?;

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
    last_snapshot_hash: Option<String>,
    last_key_epochs: BTreeMap<String, u64>,
}

impl DirectoryState {
    /// Open or create a directory state file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref().to_path_buf();
        let state = match std::fs::read_to_string(&path) {
            Ok(text) => parse_state(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFile::default(),
            Err(e) => {
                return Err(DirectoryError::new(format!(
                    "could not read directory state {}: {e}",
                    path.display()
                )));
            }
        };
        Ok(Self {
            path,
            last_sequence: state.last_sequence,
            last_snapshot_hash: state.last_snapshot_hash,
            last_key_epochs: state.last_key_epochs,
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
        self.write(sequence, None, &self.last_key_epochs)?;
        self.last_sequence = Some(sequence);
        self.last_snapshot_hash = None;
        Ok(DirectoryStateCheck::Advanced)
    }

    /// Reject lower sequence numbers and per-entry key-epoch rollback.
    pub fn check_snapshot_and_record(
        &mut self,
        snapshot: &DirectorySnapshot,
    ) -> Result<DirectoryStateCheck, DirectoryError> {
        snapshot.validate()?;
        let sequence = snapshot.sequence;
        let snapshot_hash = snapshot.canonical_hash_hex()?;
        let mut snapshot_epochs = BTreeMap::new();
        for entry in &snapshot.entries {
            snapshot_epochs.insert(entry.id.clone(), entry.capacity.key_epoch);
        }

        if let Some(last) = self.last_sequence {
            if sequence < last {
                return Err(DirectoryError::new(format!(
                    "directory rollback rejected: sequence {sequence} < last accepted {last}"
                )));
            }
            if sequence == last {
                match &self.last_snapshot_hash {
                    Some(last_hash) if &snapshot_hash == last_hash => {
                        return Ok(DirectoryStateCheck::Same);
                    }
                    Some(last_hash) => {
                        return Err(DirectoryError::new(format!(
                            "directory same-sequence equivocation rejected: sequence {sequence} snapshot hash {snapshot_hash} != last accepted {last_hash}"
                        )));
                    }
                    None => {
                        return Err(DirectoryError::new(format!(
                            "directory same-sequence snapshot rejected: state for sequence {sequence} does not include a snapshot hash; publish a higher sequence"
                        )));
                    }
                }
            }
        }

        let mut merged_epochs = self.last_key_epochs.clone();
        for (id, epoch) in &snapshot_epochs {
            if let Some(last_epoch) = merged_epochs.get(id) {
                if epoch < last_epoch {
                    return Err(DirectoryError::new(format!(
                        "directory key-epoch rollback rejected for {id}: epoch {epoch} < last accepted {last_epoch}"
                    )));
                }
            }
            merged_epochs.insert(id.clone(), *epoch);
        }

        self.write(sequence, Some(&snapshot_hash), &merged_epochs)?;
        self.last_sequence = Some(sequence);
        self.last_snapshot_hash = Some(snapshot_hash);
        self.last_key_epochs = merged_epochs;
        Ok(DirectoryStateCheck::Advanced)
    }

    /// Return the last accepted sequence, if any.
    pub fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Return the last accepted key epoch for an entry, if known.
    pub fn last_key_epoch(&self, entry_id: &str) -> Option<u64> {
        self.last_key_epochs.get(entry_id).copied()
    }

    fn write(
        &self,
        sequence: u64,
        snapshot_hash: Option<&str>,
        key_epochs: &BTreeMap<String, u64>,
    ) -> Result<(), DirectoryError> {
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
            .map_err(|e| DirectoryError::new(format!("could not write directory state: {e}")))?;
        if let Some(hash) = snapshot_hash {
            validate_snapshot_hash(hash)?;
            writeln!(file, "snapshot_hash={hash}").map_err(|e| {
                DirectoryError::new(format!("could not write directory state: {e}"))
            })?;
        }
        for (id, epoch) in key_epochs {
            validate_token("state entry id", id)?;
            writeln!(file, "entry_epoch={id}|{epoch}").map_err(|e| {
                DirectoryError::new(format!("could not write directory state: {e}"))
            })?;
        }
        file.flush()
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

#[derive(Default)]
struct StateFile {
    last_sequence: Option<u64>,
    last_snapshot_hash: Option<String>,
    last_key_epochs: BTreeMap<String, u64>,
}

struct ParsedDirectoryText {
    snapshot: DirectorySnapshot,
    signatures: Vec<DirectorySignature>,
}

fn entry_selectable(entry: &ExitDirectoryEntry, policy: &DirectorySelectionPolicy) -> bool {
    selection_error(entry, policy).is_none()
}

fn selection_error(
    entry: &ExitDirectoryEntry,
    policy: &DirectorySelectionPolicy,
) -> Option<DirectoryError> {
    if !entry.accepting_new_clients {
        return Some(DirectoryError::new(format!(
            "directory entry {} is not accepting new clients",
            entry.id
        )));
    }
    if entry.capacity.available_sessions == 0 {
        return Some(DirectoryError::new(format!(
            "directory entry {} has no available session capacity",
            entry.id
        )));
    }
    if let Some(min_epoch) = policy.min_key_epoch {
        if entry.capacity.key_epoch < min_epoch {
            return Some(DirectoryError::new(format!(
                "directory entry {} key epoch {} is below required {min_epoch}",
                entry.id, entry.capacity.key_epoch
            )));
        }
    }
    if policy.require_onion && entry.onion_addr.is_none() {
        return Some(DirectoryError::new(format!(
            "directory entry {} does not advertise an onion endpoint",
            entry.id
        )));
    }
    if policy.require_clean_egress && !entry.clean_egress {
        return Some(DirectoryError::new(format!(
            "directory entry {} does not advertise clean egress",
            entry.id
        )));
    }
    None
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

fn parse_directory_text(
    text: &str,
    require_signature: bool,
) -> Result<ParsedDirectoryText, DirectoryError> {
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
    if require_signature && signatures.is_empty() {
        return Err(DirectoryError::new("missing directory signature"));
    }
    let snapshot = DirectorySnapshot::new(sequence, valid_from_unix, valid_until_unix, entries)?;
    Ok(ParsedDirectoryText {
        snapshot,
        signatures,
    })
}

fn parse_entry(rest: &str) -> Result<ExitDirectoryEntry, DirectoryError> {
    let parts: Vec<_> = rest.split('|').collect();
    if parts.len() != 17 {
        return Err(DirectoryError::new(
            "entry must have 17 fields: id|relay|exit|issuer|issuer_pk|weight|accepting|key_epoch|available_sessions|max_sessions|window_seconds|max_destinations_per_window|issue|relay_proto|credential|onion_addr|clean_egress",
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
    let capacity = CapacityEnvelope::new(
        parse_entry_u64(parts[7], "key_epoch")?,
        parse_entry_u64(parts[8], "available_sessions")?,
        parse_entry_u64(parts[9], "max_sessions")?,
        parse_entry_u64(parts[10], "window_seconds")?,
        parse_entry_u64(parts[11], "max_destinations_per_window")?,
    )?;
    // Appended v2 fields: an empty onion field decodes to `None`.
    let onion_addr = if parts[15].is_empty() {
        None
    } else {
        Some(parts[15].to_string())
    };
    let clean_egress = match parts[16] {
        "1" => true,
        "0" => false,
        other => {
            return Err(DirectoryError::new(format!(
                "entry clean_egress flag must be 0 or 1, got {other}"
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
        capacity,
        parts[12],
        parts[13],
        parts[14],
        onion_addr,
        clean_egress,
    )
}

fn parse_entry_u64(raw: &str, name: &str) -> Result<u64, DirectoryError> {
    raw.parse::<u64>()
        .map_err(|e| DirectoryError::new(format!("entry {name} is not a u64: {e}")))
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

fn parse_state(text: &str) -> Result<StateFile, DirectoryError> {
    let mut lines = text.lines();
    match lines.next() {
        Some(STATE_MAGIC) => {}
        _ => return Err(DirectoryError::new("bad directory state magic")),
    }
    let seq = parse_u64_line(lines.next(), "last_sequence=", "missing last_sequence")?;
    let mut state = StateFile {
        last_sequence: Some(seq),
        last_snapshot_hash: None,
        last_key_epochs: BTreeMap::new(),
    };
    for line in lines {
        if let Some(hash) = line.strip_prefix("snapshot_hash=") {
            validate_snapshot_hash(hash)?;
            if state.last_snapshot_hash.replace(hash.to_string()).is_some() {
                return Err(DirectoryError::new("duplicate snapshot_hash line"));
            }
        } else if let Some(rest) = line.strip_prefix("entry_epoch=") {
            let (id, epoch) = rest
                .split_once('|')
                .ok_or_else(|| DirectoryError::new("entry_epoch must be id|epoch"))?;
            validate_token("state entry id", id)?;
            let epoch = epoch
                .parse::<u64>()
                .map_err(|e| DirectoryError::new(format!("entry_epoch is not a u64: {e}")))?;
            if epoch == 0 {
                return Err(DirectoryError::new(
                    "entry_epoch key epoch must be non-zero",
                ));
            }
            if state
                .last_key_epochs
                .insert(id.to_string(), epoch)
                .is_some()
            {
                return Err(DirectoryError::new(format!(
                    "duplicate entry_epoch for {id}"
                )));
            }
        } else if line.trim().is_empty() {
            return Err(DirectoryError::new(
                "blank lines are not allowed in directory state",
            ));
        } else {
            return Err(DirectoryError::new(format!(
                "unknown directory state line: {line}"
            )));
        }
    }
    Ok(state)
}

fn validate_snapshot_hash(hash: &str) -> Result<(), DirectoryError> {
    let bytes = hex::decode(hash)
        .map_err(|e| DirectoryError::new(format!("snapshot_hash is not valid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(DirectoryError::new(format!(
            "snapshot_hash must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
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

    fn capacity(epoch: u64, available: u64, max: u64) -> CapacityEnvelope {
        CapacityEnvelope::new(epoch, available, max, 3600, 1000).unwrap()
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

    fn onion_entry(
        id: &str,
        byte: u8,
        weight: u64,
        onion: Option<&str>,
        clean: bool,
    ) -> ExitDirectoryEntry {
        let base = 8000 + byte as u16;
        ExitDirectoryEntry::current_protocols(
            id,
            format!("127.0.0.1:{}", base),
            format!("127.0.0.1:{}", base + 1),
            format!("127.0.0.1:{}", base + 2),
            issuer_pk(byte),
            weight,
            true,
        )
        .unwrap()
        .with_onion(onion.map(|s| s.to_string()), clean)
        .unwrap()
    }

    #[test]
    fn onion_advertisement_round_trips_and_is_v2() {
        let entry = onion_entry("onion-exit", 3, 30, Some("abc.onion:443"), true);
        let snap = DirectorySnapshot::new(5, 100, 200, vec![entry]).unwrap();
        let k = signing_key(7);
        let signed = SignedExitDirectory::sign(snap, std::slice::from_ref(&k)).unwrap();
        let text = signed.to_text().unwrap();
        assert!(
            text.contains("tessera-exit-directory-v2"),
            "must serialize as the v2 format"
        );
        let parsed = SignedExitDirectory::parse(&text).unwrap();
        parsed.verify_at(&[signer_pk(&k)], 1, 150).unwrap();
        let got = parsed.snapshot.select(None).unwrap();
        assert_eq!(got.onion_addr.as_deref(), Some("abc.onion:443"));
        assert!(got.clean_egress, "clean_egress must round-trip");
    }

    #[test]
    fn onion_fields_are_signed_and_tamper_checked() {
        let entry = onion_entry("onion-exit", 3, 30, Some("abc.onion:443"), true);
        let snap = DirectorySnapshot::new(5, 100, 200, vec![entry]).unwrap();
        let k = signing_key(7);
        let signed = SignedExitDirectory::sign(snap, std::slice::from_ref(&k)).unwrap();
        let text = signed.to_text().unwrap();
        // Swap the advertised .onion — it is under the signature, so verify fails.
        let tampered = text.replace("abc.onion:443", "evil.onion:443");
        assert_ne!(text, tampered, "the onion address must be in the payload");
        let parsed = SignedExitDirectory::parse(&tampered).unwrap();
        let err = parsed.verify_at(&[signer_pk(&k)], 1, 150).unwrap_err();
        assert!(
            err.to_string().contains("did not verify"),
            "tampered onion must fail verification, got: {err}"
        );
    }

    #[test]
    fn selection_policy_requires_onion() {
        let onion = onion_entry("onion-exit", 3, 10, Some("abc.onion:443"), true);
        // The clearnet exit has HIGHER weight, so it would win without the policy.
        let clearnet = onion_entry("clearnet-exit", 4, 20, None, false);
        let snap = DirectorySnapshot::new(5, 100, 200, vec![onion, clearnet]).unwrap();

        let require = DirectorySelectionPolicy {
            require_onion: true,
            ..Default::default()
        };
        // Auto-select must pick the onion exit despite its lower weight.
        assert_eq!(
            snap.select_with_policy(None, &require).unwrap().id,
            "onion-exit"
        );
        // Explicit select of the clearnet exit under require_onion is a clean error.
        let err = snap
            .select_with_policy(Some("clearnet-exit"), &require)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not advertise an onion endpoint"),
            "got: {err}"
        );
        // Without the requirement, the highest-weight (clearnet) entry wins.
        assert_eq!(snap.select(None).unwrap().id, "clearnet-exit");
    }

    #[test]
    fn rollback_state_rejects_same_sequence_onion_mutation() {
        // The new v2 fields are under the anti-rollback snapshot hash too: a
        // same-sequence snapshot that only swaps the .onion or flips clean_egress
        // must be rejected as equivocation.
        let dir = std::env::temp_dir().join(format!(
            "tessera-directory-state-onion-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut state = DirectoryState::open(&dir).unwrap();
        let snap = |onion: &str, clean: bool| {
            DirectorySnapshot::new(
                10,
                100,
                200,
                vec![onion_entry("e", 3, 10, Some(onion), clean)],
            )
            .unwrap()
        };
        state
            .check_snapshot_and_record(&snap("a.onion:443", true))
            .unwrap();

        // Swap only the advertised .onion at the same sequence => equivocation.
        let err = state
            .check_snapshot_and_record(&snap("b.onion:443", true))
            .expect_err("same-sequence onion swap must fail closed");
        assert!(
            err.to_string().contains("same-sequence equivocation"),
            "{err}"
        );

        // Flip only clean_egress at the same sequence => equivocation (the reject
        // above did not record, so this is still vs the original).
        let err2 = state
            .check_snapshot_and_record(&snap("a.onion:443", false))
            .expect_err("same-sequence clean_egress flip must fail closed");
        assert!(
            err2.to_string().contains("same-sequence equivocation"),
            "{err2}"
        );

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn selection_policy_requires_clean_egress() {
        let clean = onion_entry("clean-exit", 3, 10, Some("a.onion:443"), true);
        // The non-clean exit has HIGHER weight, so it would win without the policy.
        let dirty = onion_entry("dirty-exit", 4, 20, Some("b.onion:443"), false);
        let snap = DirectorySnapshot::new(5, 100, 200, vec![clean, dirty]).unwrap();

        let require = DirectorySelectionPolicy {
            require_clean_egress: true,
            ..Default::default()
        };
        assert_eq!(
            snap.select_with_policy(None, &require).unwrap().id,
            "clean-exit"
        );
        let err = snap
            .select_with_policy(Some("dirty-exit"), &require)
            .unwrap_err();
        assert!(
            err.to_string().contains("does not advertise clean egress"),
            "{err}"
        );
        // Without the requirement, the higher-weight (non-clean) entry wins.
        assert_eq!(snap.select(None).unwrap().id, "dirty-exit");
    }

    #[test]
    fn parse_unsigned_rejects_a_signed_snapshot() {
        let signed =
            SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&signing_key(7))).unwrap();
        let text = signed.to_text().unwrap();
        let err = DirectorySnapshot::parse_unsigned(&text).unwrap_err();
        assert!(
            err.to_string().contains("must not contain signatures"),
            "{err}"
        );
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
    fn exhausted_capacity_entries_are_not_selected() {
        let snapshot = DirectorySnapshot::new(
            1,
            1,
            2,
            vec![ExitDirectoryEntry::current_protocols_with_capacity(
                "full",
                "127.0.0.1:1",
                "127.0.0.1:2",
                "127.0.0.1:3",
                issuer_pk(1),
                100,
                true,
                capacity(1, 0, 100),
            )
            .unwrap()],
        )
        .unwrap();
        assert!(snapshot.select(None).is_err());
        assert!(snapshot.select(Some("full")).is_err());
    }

    #[test]
    fn selection_policy_rejects_stale_key_epoch() {
        let snapshot = DirectorySnapshot::new(
            1,
            1,
            2,
            vec![
                ExitDirectoryEntry::current_protocols_with_capacity(
                    "old",
                    "127.0.0.1:1",
                    "127.0.0.1:2",
                    "127.0.0.1:3",
                    issuer_pk(1),
                    100,
                    true,
                    capacity(1, 10, 10),
                )
                .unwrap(),
                ExitDirectoryEntry::current_protocols_with_capacity(
                    "new",
                    "127.0.0.1:4",
                    "127.0.0.1:5",
                    "127.0.0.1:6",
                    issuer_pk(2),
                    10,
                    true,
                    capacity(3, 10, 10),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let policy = DirectorySelectionPolicy {
            min_key_epoch: Some(2),
            ..Default::default()
        };
        assert_eq!(
            snapshot.select_with_policy(None, &policy).unwrap().id,
            "new"
        );
        let err = snapshot
            .select_with_policy(Some("old"), &policy)
            .expect_err("explicit stale selection must fail");
        assert!(err.to_string().contains("below required"), "{err}");
    }

    #[test]
    fn capacity_is_signed_and_tamper_checked() {
        let k1 = signing_key(7);
        let signed = SignedExitDirectory::sign(snapshot(3), std::slice::from_ref(&k1)).unwrap();
        let mut text = signed.to_text().unwrap();
        text = text.replace("|1|1|1|3600|1000|", "|1|0|1|3600|1000|");
        let parsed = SignedExitDirectory::parse(&text).unwrap();

        let err = parsed
            .verify_at(&[signer_pk(&k1)], 1, 150)
            .expect_err("capacity tampering must break the signature");
        assert!(err.to_string().contains("did not verify"), "{err}");
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

    #[test]
    fn rollback_state_rejects_key_epoch_rollback() {
        let dir = std::env::temp_dir().join(format!(
            "tessera-directory-state-epoch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut state = DirectoryState::open(&dir).unwrap();
        let mut advanced = snapshot(10);
        advanced.entries[0].capacity.key_epoch = 3;
        state.check_snapshot_and_record(&advanced).unwrap();
        assert_eq!(state.last_key_epoch("exit-b"), Some(3));

        let mut rolled_back = snapshot(11);
        rolled_back.entries[0].capacity.key_epoch = 2;
        let err = state
            .check_snapshot_and_record(&rolled_back)
            .expect_err("lower key epoch must fail closed even with a higher sequence");
        assert!(err.to_string().contains("key-epoch rollback"), "{err}");

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn rollback_state_rejects_epoch_change_without_sequence_advance() {
        let dir = std::env::temp_dir().join(format!(
            "tessera-directory-state-same-epoch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut state = DirectoryState::open(&dir).unwrap();
        state.check_snapshot_and_record(&snapshot(10)).unwrap();

        let mut changed = snapshot(10);
        changed.entries[0].capacity.key_epoch = 2;
        let err = state
            .check_snapshot_and_record(&changed)
            .expect_err("same-sequence epoch changes must fail closed");
        assert!(
            err.to_string().contains("same-sequence equivocation"),
            "{err}"
        );

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn rollback_state_rejects_same_sequence_snapshot_mutation() {
        let dir = std::env::temp_dir().join(format!(
            "tessera-directory-state-same-hash-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut state = DirectoryState::open(&dir).unwrap();
        let original = snapshot(10);
        state.check_snapshot_and_record(&original).unwrap();
        assert_eq!(
            state.check_snapshot_and_record(&original).unwrap(),
            DirectoryStateCheck::Same
        );

        let mut changed_addr = snapshot(10);
        changed_addr.entries[0].relay_addr = "127.0.0.1:9999".to_string();
        let err = state
            .check_snapshot_and_record(&changed_addr)
            .expect_err("same-sequence address changes must fail closed");
        assert!(
            err.to_string().contains("same-sequence equivocation"),
            "{err}"
        );

        let mut changed_capacity = snapshot(10);
        changed_capacity.entries[0].capacity.available_sessions = 0;
        let err = state
            .check_snapshot_and_record(&changed_capacity)
            .expect_err("same-sequence capacity changes must fail closed");
        assert!(
            err.to_string().contains("same-sequence equivocation"),
            "{err}"
        );

        let mut removed_entry = snapshot(10);
        removed_entry.entries.pop();
        let err = state
            .check_snapshot_and_record(&removed_entry)
            .expect_err("same-sequence entry removal must fail closed");
        assert!(
            err.to_string().contains("same-sequence equivocation"),
            "{err}"
        );

        let _ = std::fs::remove_file(&dir);
    }
}
