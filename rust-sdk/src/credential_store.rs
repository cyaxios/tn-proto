//! Credential-store helpers for cached vault account keys.
//!
//! The store caches derived account AWKs, never account passphrases. This
//! mirrors the Python and TypeScript credential-store model while keeping the
//! first Rust implementation explicit and file-backed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;

use crate::vault::VaultAwk;
#[cfg(feature = "http")]
use crate::vault::VaultHttpProjectClient;
use crate::{Error, Result};

/// Store key under which an account's AWK is cached.
pub fn awk_key_name(account_id: &str) -> String {
    format!("awk:{account_id}")
}

/// Return the machine-global TN identity directory.
///
/// This mirrors Python `_default_identity_dir` and TypeScript
/// `defaultIdentityDir`:
///
/// 1. `TN_IDENTITY_DIR` when set.
/// 2. `$XDG_DATA_HOME/tn` when set.
/// 3. `%APPDATA%\tn` on Windows.
/// 4. `~/.local/share/tn` on other platforms.
pub fn default_identity_dir() -> PathBuf {
    if let Some(path) = env_path("TN_IDENTITY_DIR") {
        return path;
    }
    if let Some(path) = env_path("XDG_DATA_HOME") {
        return path.join("tn");
    }
    platform_identity_dir()
}

/// Return the default machine-global `identity.json` path.
pub fn default_identity_path() -> PathBuf {
    default_identity_dir().join("identity.json")
}

/// Return the default file-backed credential store.
///
/// Rust does not depend on an OS keychain backend yet, so this intentionally
/// matches the Python/TypeScript file fallback: `credentials.json` beside the
/// machine-global `identity.json`.
pub fn default_credential_store() -> FileCredentialStore {
    FileCredentialStore::new(default_identity_dir().join("credentials.json"))
}

/// Read a cached account AWK, returning `None` when the value is missing,
/// unreadable, or malformed.
///
/// This mirrors the Python/TypeScript warm-cache path: a broken local
/// credential store should not break initialization or sync discovery.
pub fn load_cached_account_awk<S: CredentialStore + ?Sized>(
    store: &S,
    account_id: &str,
) -> Option<VaultAwk> {
    store
        .get(&awk_key_name(account_id))
        .ok()
        .flatten()
        .and_then(|bytes| VaultAwk::from_slice(&bytes).ok())
}

/// Derive an account AWK through an authenticated vault HTTP client and cache
/// it under [`awk_key_name`].
///
/// The passphrase is never persisted. Only the derived 32-byte account AWK is
/// stored, matching the Python/TypeScript "connect once, use cached key later"
/// model.
///
/// # Errors
///
/// Returns [`crate::Error`] when `account_id` is empty, the vault credential
/// fetch fails, the passphrase cannot unwrap the account AWK, or the store
/// cannot persist the derived key.
#[cfg(feature = "http")]
pub fn cache_account_awk_with_client<S: CredentialStore + ?Sized>(
    store: &S,
    client: &VaultHttpProjectClient,
    account_id: &str,
    passphrase: &str,
    credential_id: Option<&str>,
) -> Result<VaultAwk> {
    let account_id = normalize_account_id(account_id)?;
    let awk = client.derive_awk_from_passphrase(passphrase, credential_id)?;
    store.set(&awk_key_name(account_id), awk.as_bytes())?;
    Ok(awk)
}

/// Minimal get/set/delete interface for cached credential bytes.
pub trait CredentialStore {
    /// Read a named credential, returning `None` when absent or undecodable.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be read.
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;

    /// Store a named credential.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    fn set(&self, name: &str, value: &[u8]) -> Result<()>;

    /// Delete a named credential. Missing entries are not an error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    fn delete(&self, name: &str) -> Result<()>;
}

/// File-backed credential store mapping names to base64-encoded values.
///
/// The file format matches the Python/TypeScript fallback store: a JSON object
/// with credential names as keys and standard base64 strings as values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    /// Create a file-backed credential store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Return the backing JSON file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a named credential, returning `None` when absent or undecodable.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be read.
    pub fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        <Self as CredentialStore>::get(self, name)
    }

    /// Store a named credential.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    pub fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        <Self as CredentialStore>::set(self, name, value)
    }

    /// Delete a named credential. Missing entries are not an error.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    pub fn delete(&self, name: &str) -> Result<()> {
        <Self as CredentialStore>::delete(self, name)
    }

    /// Store an account AWK under [`awk_key_name`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    pub fn set_account_awk(&self, account_id: &str, awk: &VaultAwk) -> Result<()> {
        self.set(&awk_key_name(account_id), awk.as_bytes())
    }

    /// Load an account AWK from [`awk_key_name`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the stored value exists but is not a
    /// 32-byte AWK.
    pub fn get_account_awk(&self, account_id: &str) -> Result<Option<VaultAwk>> {
        self.get(&awk_key_name(account_id))?
            .map(|bytes| VaultAwk::from_slice(&bytes))
            .transpose()
    }

    /// Delete an account AWK stored under [`awk_key_name`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the backend cannot be written.
    pub fn delete_account_awk(&self, account_id: &str) -> Result<()> {
        self.delete(&awk_key_name(account_id))
    }

    fn load(&self) -> BTreeMap<String, String> {
        let Ok(raw) = fs::read_to_string(&self.path) else {
            return BTreeMap::new();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn save(&self, doc: &BTreeMap<String, String>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let rendered = serde_json::to_vec_pretty(doc)?;
        let tmp = self.path.with_extension(format!(
            "{}.tmp",
            self.path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("json")
        ));
        write_owner_only(&tmp, &rendered)?;
        replace_file(&tmp, &self.path)?;
        Ok(())
    }
}

impl CredentialStore for FileCredentialStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(encoded) = self.load().get(name).cloned() else {
            return Ok(None);
        };
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None),
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        let mut doc = self.load();
        doc.insert(
            name.to_string(),
            base64::engine::general_purpose::STANDARD.encode(value),
        );
        self.save(&doc)
    }

    fn delete(&self, name: &str) -> Result<()> {
        let mut doc = self.load();
        if doc.remove(name).is_some() {
            self.save(&doc)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn write_owner_only(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn replace_file(from: &Path, to: &Path) -> Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(err) if to.exists() => {
            fs::remove_file(to)?;
            fs::rename(from, to).map_err(|second| {
                Error::Io(std::io::Error::new(
                    second.kind(),
                    format!(
                        "replace {} failed after initial rename error {err}; \
                         second rename error: {second}",
                        to.display()
                    ),
                ))
            })
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(feature = "http")]
fn normalize_account_id(account_id: &str) -> Result<&str> {
    let account_id = account_id.trim();
    if account_id.is_empty() {
        return Err(Error::InvalidArgument("account_id is required".into()));
    }
    Ok(account_id)
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(windows)]
fn platform_identity_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
        .join("tn")
}

#[cfg(not(windows))]
fn platform_identity_dir() -> PathBuf {
    home_dir().join(".local").join("share").join("tn")
}

fn home_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var_os("HOMEDRIVE")?;
                let path = std::env::var_os("HOMEPATH")?;
                Some(PathBuf::from(drive).join(path))
            })
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
