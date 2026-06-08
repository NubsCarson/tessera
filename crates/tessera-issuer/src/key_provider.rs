//! Shared ARC server-key provider parsing and establishment.
//!
//! Supports `ephemeral`, `file`, and `dstack-kms` — the last derives the ARC key
//! from the dstack guest agent inside an Intel TDX CVM (see [`crate::dstack_kms`]).
//! The `dstack-kms` path **fails closed** off-TEE (no socket) and is validated
//! only against a mock / the dstack simulator, not real TDX hardware
//! (research-grade, UNAUDITED).

use rand_core::OsRng;
use tessera_arc::keys::{ServerPrivateKey, ServerPublicKey};

use crate::keyfile::ensure_shared_key;

/// Default dstack guest-agent socket path.
pub const DEFAULT_DSTACK_SOCKET: &str = "/var/run/dstack.sock";

/// Validated ARC server-key provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProviderConfig {
    /// Generate an in-memory key for a single-node demo process.
    Ephemeral,
    /// Read or converge on a shared ARC key at the given filesystem path.
    File {
        /// Shared ARC server-key path.
        path: String,
    },
    /// dstack KMS provider: derive the ARC key from the guest agent in a TDX CVM
    /// (see [`crate::dstack_kms`]). Fails closed off-TEE.
    DstackKms {
        /// dstack guest-agent socket path.
        socket: String,
        /// KMS key identifier to derive.
        key_id: String,
    },
}

impl KeyProviderConfig {
    /// Parse `TESSERA_KEY_PROVIDER` and related env vars.
    pub fn from_env() -> Result<Self, String> {
        let provider = std::env::var("TESSERA_KEY_PROVIDER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let key_file = std::env::var("TESSERA_KEY_FILE").ok();

        match provider.as_deref() {
            None => {
                reject_dstack_env_without_provider()?;
                match key_file {
                    Some(path) if !path.is_empty() => {
                        check_path_usable(&path, "TESSERA_KEY_FILE")?;
                        Ok(Self::File { path })
                    }
                    Some(_) => Err(
                        "TESSERA_KEY_FILE is set but empty (unset it for an ephemeral single-node key, or give it a path)"
                            .to_string(),
                    ),
                    None => Ok(Self::Ephemeral),
                }
            }
            Some("ephemeral") => {
                reject_key_file_with_provider("ephemeral", key_file.as_deref())?;
                reject_dstack_env_without_provider()?;
                Ok(Self::Ephemeral)
            }
            Some("file") => {
                reject_dstack_env_without_provider()?;
                match key_file {
                    Some(path) if !path.is_empty() => {
                        check_path_usable(&path, "TESSERA_KEY_FILE")?;
                        Ok(Self::File { path })
                    }
                    Some(_) => Err(
                        "TESSERA_KEY_PROVIDER=file requires non-empty TESSERA_KEY_FILE".to_string(),
                    ),
                    None => Err("TESSERA_KEY_PROVIDER=file requires TESSERA_KEY_FILE".to_string()),
                }
            }
            Some("dstack-kms") => {
                reject_key_file_with_provider("dstack-kms", key_file.as_deref())?;
                let socket = std::env::var("TESSERA_DSTACK_SOCKET")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| DEFAULT_DSTACK_SOCKET.to_string());
                let key_id = std::env::var("TESSERA_DSTACK_KMS_KEY_ID")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        "TESSERA_KEY_PROVIDER=dstack-kms requires TESSERA_DSTACK_KMS_KEY_ID"
                            .to_string()
                    })?;
                Ok(Self::DstackKms { socket, key_id })
            }
            Some(other) => Err(format!(
                "TESSERA_KEY_PROVIDER {other:?} is not one of: ephemeral | file | dstack-kms"
            )),
        }
    }

    /// Validate provider prerequisites without creating or deriving the key.
    pub fn preflight(&self) -> Result<(), String> {
        match self {
            Self::Ephemeral => Ok(()),
            Self::File { path } => check_path_usable(path, "TESSERA_KEY_FILE"),
            Self::DstackKms { socket, key_id } => crate::dstack_kms::preflight(socket, key_id),
        }
    }

    /// Establish the ARC server key for normal serving.
    pub fn establish(
        &self,
        rng: &mut OsRng,
    ) -> Result<(ServerPrivateKey, ServerPublicKey), String> {
        match self {
            Self::Ephemeral => Ok(ServerPrivateKey::setup(rng)),
            Self::File { path } => Ok(ensure_shared_key(path)),
            Self::DstackKms { socket, key_id } => crate::dstack_kms::establish(socket, key_id),
        }
    }

    /// Return the backing key-file path when the provider is `file`.
    pub fn key_file_path(&self) -> Option<&str> {
        match self {
            Self::File { path } => Some(path),
            Self::Ephemeral | Self::DstackKms { .. } => None,
        }
    }

    /// Human-readable provider label for operator summaries.
    pub fn label(&self) -> String {
        match self {
            Self::Ephemeral => "ephemeral key (single-node only)".to_string(),
            Self::File { path } => format!("shared key {path}"),
            Self::DstackKms { socket, key_id } => {
                format!("dstack-kms key_id={key_id} socket={socket}")
            }
        }
    }
}

fn reject_key_file_with_provider(provider: &str, key_file: Option<&str>) -> Result<(), String> {
    if key_file.is_some() {
        Err(format!(
            "TESSERA_KEY_PROVIDER={provider} cannot be combined with TESSERA_KEY_FILE"
        ))
    } else {
        Ok(())
    }
}

fn reject_dstack_env_without_provider() -> Result<(), String> {
    for var in ["TESSERA_DSTACK_SOCKET", "TESSERA_DSTACK_KMS_KEY_ID"] {
        if std::env::var(var).is_ok() {
            return Err(format!("{var} requires TESSERA_KEY_PROVIDER=dstack-kms"));
        }
    }
    Ok(())
}

/// Validate that a file path a Tessera binary will read or write is usable.
///
/// The target file may be absent because several call sites create it later, but
/// any parent directory must exist and any existing target must be a regular
/// file. `what` is the env var or setting name used in the error message.
pub fn check_path_usable(path: &str, what: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{what} is set but empty"));
    }
    let p = std::path::Path::new(path);
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = parent {
        if !dir.exists() {
            return Err(format!(
                "{what} {path}: parent directory {} does not exist",
                dir.display()
            ));
        }
        if !dir.is_dir() {
            return Err(format!(
                "{what} {path}: parent {} is not a directory",
                dir.display()
            ));
        }
    }
    if p.exists() && !p.is_file() {
        return Err(format!("{what} {path}: exists but is not a regular file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        for var in [
            "TESSERA_KEY_PROVIDER",
            "TESSERA_KEY_FILE",
            "TESSERA_DSTACK_SOCKET",
            "TESSERA_DSTACK_KMS_KEY_ID",
        ] {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn parses_legacy_file_and_default_ephemeral() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        assert_eq!(
            KeyProviderConfig::from_env().unwrap(),
            KeyProviderConfig::Ephemeral
        );

        let dir = std::env::temp_dir().join(format!("tessera-key-provider-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.key");
        std::env::set_var("TESSERA_KEY_FILE", &path);
        assert_eq!(
            KeyProviderConfig::from_env().unwrap(),
            KeyProviderConfig::File {
                path: path.to_string_lossy().into_owned()
            }
        );
        clear_env();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dstack_provider_fails_closed_without_socket() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("TESSERA_KEY_PROVIDER", "dstack-kms");
        std::env::set_var("TESSERA_DSTACK_KMS_KEY_ID", "arc-key");
        std::env::set_var(
            "TESSERA_DSTACK_SOCKET",
            "/nonexistent/tessera-dstack-test.sock",
        );
        let provider = KeyProviderConfig::from_env().unwrap();
        let err = provider
            .preflight()
            .expect_err("dstack-kms must fail closed without a reachable guest agent");
        assert!(err.contains("dstack guest-agent"), "{err}");
        clear_env();
    }

    #[test]
    fn rejects_conflicting_provider_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("TESSERA_KEY_PROVIDER", "ephemeral");
        std::env::set_var("TESSERA_KEY_FILE", "/tmp/arc.key");
        let err = KeyProviderConfig::from_env().expect_err("conflict must fail");
        assert!(err.contains("cannot be combined"), "{err}");
        clear_env();
    }
}
