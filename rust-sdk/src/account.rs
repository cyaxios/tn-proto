//! Account binding helpers.
//!
//! This namespace mirrors the Python/TypeScript connect-code redeem flow. A
//! vault connect code is authorized by signing `SHA-256(code)` with an Ed25519
//! TN identity and posting that signature to the vault. The first Rust chunk
//! uses the active ceremony identity; machine/supplied identity cascade support
//! can be layered on top without changing the wire contract.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "http")]
use base64::Engine;
#[cfg(feature = "http")]
use serde_json::Value as JsonValue;
#[cfg(feature = "http")]
use serde_yml::{Mapping as YamlMapping, Value as YamlValue};
#[cfg(feature = "http")]
use sha2::{Digest, Sha256};

use crate::credential_store::{
    awk_key_name, default_credential_store, default_identity_path, CredentialStore,
};
use crate::tn::Tn;
use crate::vault::VaultLinkStateInfo;
use crate::{Error, Result};

/// Runtime account namespace for a [`Tn`] handle.
pub struct Account<'a> {
    tn: &'a Tn,
}

/// Account sync-state view for this ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    /// Vault account id persisted in `.tn/sync/state.json`, when present.
    pub account_id: Option<String>,
    /// True when this ceremony has been bound to a vault account.
    pub account_bound: bool,
}

/// High-level local account status for an opened ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatus {
    /// DID for the active ceremony/device.
    pub device_did: String,
    /// Vault account id persisted in `.tn/sync/state.json`, when present.
    pub account_id: Option<String>,
    /// True when this ceremony has been bound to a vault account.
    pub account_bound: bool,
    /// Local vault link-state read from ceremony YAML.
    pub vault: VaultLinkStateInfo,
    /// True when a cached account wrap key exists for `account_id`.
    pub key_cached: bool,
    /// Convenience verdict computed from local signals.
    pub verdict: AccountVerdict,
}

/// Local account status verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountVerdict {
    /// No local account binding exists for this ceremony.
    NotLoggedIn,
    /// The ceremony is account-bound, but no cached backup key was found.
    LinkedNoKey,
    /// The ceremony is account-bound and has a cached backup key.
    BackedUp,
}

impl AccountVerdict {
    /// Human-readable parity message for this verdict.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotLoggedIn => "Not logged in - run account connect/login.",
            Self::LinkedNoKey => {
                "Linked, but no backup key cached - backups require an account passphrase."
            }
            Self::BackedUp => "Backed up and ready.",
        }
    }
}

/// Result from clearing local account binding state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLogoutResult {
    /// Account id that was locally bound before logout, when present.
    pub previous_account_id: Option<String>,
    /// True when a cached account wrap key existed and was deleted.
    pub deleted_cached_key: bool,
    /// Status after local logout is complete.
    pub status: AccountStatus,
}

/// Machine-global `identity.json` account/vault metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountIdentityMetadata {
    /// Path to the identity file that was read.
    pub path: PathBuf,
    /// Vault URL remembered by Python/TypeScript `auth.use`.
    pub linked_vault: Option<String>,
    /// Vault account id remembered by Python/TypeScript `auth.connect`.
    pub linked_account_id: Option<String>,
}

/// Result from updating the machine-global vault default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUseVaultResult {
    /// Previous remembered vault URL, when present.
    pub previous_linked_vault: Option<String>,
    /// Previous remembered account id, when present.
    pub previous_linked_account_id: Option<String>,
    /// Metadata after the update.
    pub metadata: AccountIdentityMetadata,
}

/// Result from connect-code redemption.
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct AccountConnectResult {
    /// Vault account id the DID is now bound to.
    pub account_id: String,
    /// DID that signed and redeemed the code.
    pub did: String,
    /// Signing identity tier used for the redeem request.
    pub signing_tier: SigningIdentityTier,
    /// Path the signing identity was loaded from.
    pub signing_source_path: PathBuf,
    /// Echoed vault project id when the code was project-scoped.
    pub project_id: Option<String>,
    /// Echoed vault project name when supplied by the vault.
    pub project_name: Option<String>,
    /// Raw vault response for callers that need extra fields.
    pub raw: JsonValue,
}

/// Options for [`Account::connect_code_http`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountConnectOptions {
    /// Vault base URL, for example `https://vault.tn-proto.org`.
    pub vault_base_url: String,
    /// Explicit identity.json path. When supplied, it wins over machine and
    /// ceremony identities and must load successfully.
    pub supplied_identity_path: Option<PathBuf>,
    /// Machine identity path override. Defaults to
    /// [`crate::default_identity_path`].
    pub machine_identity_path: Option<PathBuf>,
}

#[cfg(feature = "http")]
impl AccountConnectOptions {
    /// Create connect-code options for `vault_base_url`.
    pub fn new(vault_base_url: impl Into<String>) -> Self {
        Self {
            vault_base_url: vault_base_url.into(),
            supplied_identity_path: None,
            machine_identity_path: None,
        }
    }
}

/// Signing identity tier used for account connect-code redemption.
#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningIdentityTier {
    /// Explicit caller-supplied identity path.
    Supplied,
    /// Machine-global identity.json.
    Machine,
    /// Per-ceremony keystore identity fallback.
    Ceremony,
}

/// Resolved signing identity for account connect-code redemption.
#[cfg(feature = "http")]
pub struct ResolvedSigningIdentity {
    /// DID that will be bound to the vault account.
    pub did: String,
    /// Which tier produced this signing identity.
    pub tier: SigningIdentityTier,
    /// Source file path used for diagnostics.
    pub source_path: PathBuf,
    device: tn_core::DeviceKey,
}

#[cfg(feature = "http")]
impl std::fmt::Debug for ResolvedSigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSigningIdentity")
            .field("did", &self.did)
            .field("tier", &self.tier)
            .field("source_path", &self.source_path)
            .finish_non_exhaustive()
    }
}

impl<'a> Account<'a> {
    pub(crate) fn new(tn: &'a Tn) -> Self {
        Self { tn }
    }

    /// Return the local account binding state for this ceremony.
    ///
    /// Missing, unreadable, or malformed sync-state files are treated as empty,
    /// matching Python/TypeScript.
    pub fn state(&self) -> AccountState {
        account_state(self.tn.yaml_path())
    }

    /// Vault account id persisted for this ceremony, if any.
    pub fn account_id(&self) -> Option<String> {
        self.state().account_id
    }

    /// True when this ceremony has been bound to a vault account.
    pub fn is_bound(&self) -> bool {
        self.state().account_bound
    }

    /// Return a high-level local status view for this ceremony.
    ///
    /// This is the Rust SDK equivalent of the Python/TypeScript auth
    /// `whoami`/verify-less status layer, scoped to an already-open [`Tn`].
    /// It does not call the vault; it combines the ceremony DID, sync-state
    /// account binding, YAML vault link-state, and local cached-AWK presence.
    pub fn status(&self) -> AccountStatus {
        self.status_with_store(&default_credential_store())
    }

    /// Alias for [`Account::status`] for Python/TypeScript naming parity.
    pub fn whoami(&self) -> AccountStatus {
        self.status()
    }

    /// Return local account status using an explicit credential store.
    pub fn status_with_store<S: CredentialStore + ?Sized>(&self, store: &S) -> AccountStatus {
        account_status(self.tn, store)
    }

    /// Clear local account binding and any cached account wrap key.
    ///
    /// This mirrors the local side effects of Python/TypeScript
    /// `auth.logout`: it removes local account binding, clears any in-flight
    /// pending claim, and deletes the cached AWK for the bound account. It does
    /// not revoke the vault account server-side or unlink the ceremony YAML.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when sync-state or credential-store writes
    /// fail.
    pub fn logout(&self) -> Result<AccountLogoutResult> {
        self.logout_with_store(&default_credential_store())
    }

    /// Clear local account binding using an explicit credential store.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when sync-state or credential-store writes
    /// fail.
    pub fn logout_with_store<S: CredentialStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<AccountLogoutResult> {
        let previous = self.state().account_id;
        let mut deleted_cached_key = false;
        if let Some(account_id) = previous.as_deref() {
            let key_name = awk_key_name(account_id);
            deleted_cached_key = store.get(&key_name)?.is_some();
            store.delete(&key_name)?;
        }
        clear_account_bound(self.tn.yaml_path())?;
        Ok(AccountLogoutResult {
            previous_account_id: previous,
            deleted_cached_key,
            status: self.status_with_store(store),
        })
    }

    /// Read machine-global account/vault metadata from the default
    /// `identity.json`.
    ///
    /// Missing identity files return `Ok(None)`. Malformed identity files are
    /// returned as errors so callers do not silently mutate a corrupt login.
    pub fn identity_metadata(&self) -> Result<Option<AccountIdentityMetadata>> {
        self.identity_metadata_at(&default_identity_path())
    }

    /// Read machine-global account/vault metadata from an explicit
    /// `identity.json` path.
    pub fn identity_metadata_at(&self, path: &Path) -> Result<Option<AccountIdentityMetadata>> {
        identity_metadata(path)
    }

    /// Remember `vault` in the default machine-global `identity.json`.
    ///
    /// If the identity was linked to a different vault, the stale
    /// `linked_account_id` is cleared just like Python/TypeScript `auth.use`.
    /// This method requires an existing identity file; Rust identity minting is
    /// kept separate until the SDK supports the full Python/TS mnemonic schema.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `vault` is empty, `identity.json` is
    /// missing/corrupt, or the file cannot be written.
    pub fn use_vault(&self, vault: impl AsRef<str>) -> Result<AccountUseVaultResult> {
        self.use_vault_at(&default_identity_path(), vault)
    }

    /// Remember `vault` in an explicit `identity.json` file.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `vault` is empty, `identity.json` is
    /// missing/corrupt, or the file cannot be written.
    pub fn use_vault_at(
        &self,
        path: &Path,
        vault: impl AsRef<str>,
    ) -> Result<AccountUseVaultResult> {
        let vault = normalize_vault_url(vault.as_ref())?;
        use_vault_at(path, &vault)
    }

    /// Redeem a vault connect code using the active ceremony identity.
    ///
    /// This mirrors Python `redeem_connect_code` and TypeScript
    /// `AccountNamespace.connect`: Rust signs `SHA-256(code.utf8())`, posts
    /// `{ code, did, signature_b64 }` to
    /// `/api/v1/account/connect-codes/redeem`, then marks this ceremony
    /// account-bound in `.tn/sync/state.json`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the code/base URL is empty, the local
    /// ceremony key cannot be loaded, the vault request fails, the vault
    /// rejects the code, or the response is missing `account_id`.
    #[cfg(feature = "http")]
    pub fn connect_code_http(
        &self,
        code: impl AsRef<str>,
        options: AccountConnectOptions,
    ) -> Result<AccountConnectResult> {
        let code = normalize_required("connect code", code.as_ref())?;
        let base_url = normalize_required("vault base_url", &options.vault_base_url)?
            .trim_end_matches('/')
            .to_string();
        let identity = self.resolve_signing_identity(
            options.supplied_identity_path.as_deref(),
            options.machine_identity_path.as_deref(),
        )?;
        let message = Sha256::digest(code.as_bytes());
        let signature = identity.device.sign(&message);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_slice());

        let body = serde_json::json!({
            "code": code,
            "did": identity.did,
            "signature_b64": signature_b64,
        });
        let client = reqwest::blocking::Client::builder()
            .user_agent(format!("tn-proto-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        let path = "/api/v1/account/connect-codes/redeem";
        let response = client
            .post(format!("{base_url}{path}"))
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()?;
        if !response.status().is_success() {
            return Err(account_status_error("POST", path, response));
        }
        let raw: JsonValue = response.json()?;
        let account_id = json_field_str(&raw, "account_id", "connect-code response")?.to_string();
        mark_account_bound(self.tn.yaml_path(), &account_id)?;
        if matches!(
            identity.tier,
            SigningIdentityTier::Supplied | SigningIdentityTier::Machine
        ) {
            persist_identity_binding(&identity.source_path, &base_url, &account_id)?;
        }

        Ok(AccountConnectResult {
            account_id,
            did: identity.did,
            signing_tier: identity.tier,
            signing_source_path: identity.source_path,
            project_id: optional_json_string(&raw, "project_id"),
            project_name: optional_json_string(&raw, "project_name"),
            raw,
        })
    }

    /// Resolve which local identity signs an account connect-code redeem.
    ///
    /// Cascade order matches Python and TypeScript:
    ///
    /// 1. supplied identity path
    /// 2. machine-global identity.json
    /// 3. ceremony `keys/local.private`
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when an explicit supplied identity cannot be
    /// loaded, or when no identity tier can be resolved.
    #[cfg(feature = "http")]
    pub fn resolve_signing_identity(
        &self,
        supplied_identity_path: Option<&Path>,
        machine_identity_path: Option<&Path>,
    ) -> Result<ResolvedSigningIdentity> {
        if let Some(path) = supplied_identity_path {
            let device = load_identity_json_device(path).map_err(|err| {
                Error::InvalidArgument(format!(
                    "--identity {} could not be loaded: {err}",
                    path.display()
                ))
            })?;
            return Ok(ResolvedSigningIdentity {
                did: device.did().to_string(),
                tier: SigningIdentityTier::Supplied,
                source_path: path.to_path_buf(),
                device,
            });
        }

        let machine_path = machine_identity_path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_identity_path);
        if machine_path.is_file() {
            if let Ok(device) = load_identity_json_device(&machine_path) {
                return Ok(ResolvedSigningIdentity {
                    did: device.did().to_string(),
                    tier: SigningIdentityTier::Machine,
                    source_path: machine_path,
                    device,
                });
            }
        }

        if let Some((source_path, device)) = ceremony_device(self.tn.yaml_path())? {
            return Ok(ResolvedSigningIdentity {
                did: device.did().to_string(),
                tier: SigningIdentityTier::Ceremony,
                source_path,
                device,
            });
        }

        Err(Error::InvalidArgument(format!(
            "no signing identity for account connect: no machine identity at {} \
             and no ceremony keystore key for {}. Run init_project, or pass \
             AccountConnectOptions::supplied_identity_path.",
            machine_path.display(),
            self.tn.yaml_path().display()
        )))
    }
}

fn account_status<S: CredentialStore + ?Sized>(tn: &Tn, store: &S) -> AccountStatus {
    let state = account_state(tn.yaml_path());
    let key_cached = state
        .account_id
        .as_deref()
        .and_then(|account_id| store.get(&awk_key_name(account_id)).ok().flatten())
        .is_some();
    let verdict = if !state.account_bound {
        AccountVerdict::NotLoggedIn
    } else if key_cached {
        AccountVerdict::BackedUp
    } else {
        AccountVerdict::LinkedNoKey
    };
    AccountStatus {
        device_did: tn.did().to_string(),
        account_id: state.account_id,
        account_bound: state.account_bound,
        vault: tn
            .vault()
            .link_state()
            .unwrap_or_else(|_| VaultLinkStateInfo {
                state: crate::VaultLinkState::Local,
                yaml_path: tn.yaml_path().to_path_buf(),
                linked_vault: None,
                linked_project_id: None,
                vault_enabled: false,
                autosync: false,
                sync_interval_seconds: None,
            }),
        key_cached,
        verdict,
    }
}

fn account_state(yaml_path: &Path) -> AccountState {
    let state = load_sync_state(yaml_path);
    let account_id = state
        .get("account_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let account_bound = state
        .get("account_bound")
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    AccountState {
        account_id,
        account_bound,
    }
}

#[cfg(feature = "http")]
fn mark_account_bound(yaml_path: &Path, account_id: &str) -> Result<()> {
    let mut state = load_sync_state(yaml_path);
    state.insert(
        "account_id".to_string(),
        serde_json::Value::String(account_id.to_string()),
    );
    state.insert("account_bound".to_string(), serde_json::Value::Bool(true));
    state.remove("pending_claim");
    save_sync_state(yaml_path, state)
}

fn clear_account_bound(yaml_path: &Path) -> Result<()> {
    let mut state = load_sync_state(yaml_path);
    state.remove("account_id");
    state.insert("account_bound".to_string(), serde_json::Value::Bool(false));
    state.remove("pending_claim");
    save_sync_state(yaml_path, state)
}

fn identity_metadata(path: &Path) -> Result<Option<AccountIdentityMetadata>> {
    let Some(doc) = load_identity_doc_optional(path)? else {
        return Ok(None);
    };
    Ok(Some(AccountIdentityMetadata {
        path: path.to_path_buf(),
        linked_vault: doc
            .get("linked_vault")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        linked_account_id: doc
            .get("linked_account_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    }))
}

fn use_vault_at(path: &Path, vault: &str) -> Result<AccountUseVaultResult> {
    let mut doc = load_identity_doc_required(path)?;
    let previous = identity_metadata(path)?.expect("required doc was just loaded");
    set_json_string_or_null(&mut doc, "linked_vault", Some(vault));
    if previous
        .linked_vault
        .as_deref()
        .is_some_and(|prior| prior != vault)
    {
        set_json_string_or_null(&mut doc, "linked_account_id", None);
    }
    save_identity_doc(path, &doc)?;
    Ok(AccountUseVaultResult {
        previous_linked_vault: previous.linked_vault,
        previous_linked_account_id: previous.linked_account_id,
        metadata: identity_metadata(path)?.expect("identity was just saved"),
    })
}

#[cfg(feature = "http")]
fn persist_identity_binding(path: &Path, vault: &str, account_id: &str) -> Result<()> {
    let mut doc = load_identity_doc_required(path)?;
    set_json_string_or_null(&mut doc, "linked_vault", Some(vault));
    set_json_string_or_null(&mut doc, "linked_account_id", Some(account_id));
    save_identity_doc(path, &doc)
}

fn load_identity_doc_optional(
    path: &Path,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    match value {
        serde_json::Value::Object(object) => Ok(Some(object)),
        _ => Err(Error::InvalidArgument(format!(
            "identity.json at {} must contain a JSON object",
            path.display()
        ))),
    }
}

fn load_identity_doc_required(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
    load_identity_doc_optional(path)?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "identity.json not found at {}; create or restore an identity first",
            path.display()
        ))
    })
}

fn save_identity_doc(path: &Path, doc: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(doc.clone()))?;
    tn_core::keystore_backend::atomic_write_bytes(path, &bytes)?;
    Ok(())
}

fn set_json_string_or_null(
    doc: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
) {
    let value = value
        .map(|value| serde_json::Value::String(value.to_string()))
        .unwrap_or(serde_json::Value::Null);
    doc.insert(key.to_string(), value);
}

fn load_sync_state(yaml_path: &Path) -> serde_json::Map<String, serde_json::Value> {
    fs::read(sync_state_path(yaml_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| match value {
            serde_json::Value::Object(object) => Some(object),
            _ => None,
        })
        .unwrap_or_default()
}

fn save_sync_state(
    yaml_path: &Path,
    state: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let path = sync_state_path(yaml_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(state))?;
    tn_core::keystore_backend::atomic_write_bytes(&path, &bytes)?;
    Ok(())
}

fn sync_state_path(yaml_path: &Path) -> PathBuf {
    yaml_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(".tn")
        .join("sync")
        .join("state.json")
}

#[cfg(feature = "http")]
fn ceremony_device(yaml_path: &Path) -> Result<Option<(PathBuf, tn_core::DeviceKey)>> {
    let doc = read_yaml_mapping(yaml_path)?;
    let keystore_path = doc
        .get(YamlValue::String("keystore".to_string()))
        .and_then(YamlValue::as_mapping)
        .and_then(|keystore| keystore.get(YamlValue::String("path".to_string())))
        .and_then(YamlValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidArgument("tn.yaml is missing keystore.path".into()))?;
    let private_path = resolve_yaml_relative_path(yaml_path, keystore_path).join("local.private");
    if !private_path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&private_path)?;
    Ok(Some((
        private_path,
        tn_core::DeviceKey::from_private_bytes(&bytes)?,
    )))
}

#[cfg(feature = "http")]
fn load_identity_json_device(path: &Path) -> Result<tn_core::DeviceKey> {
    let raw = fs::read_to_string(path)?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    let method = doc
        .get("device_priv_enc_method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none");
    if method != "none" {
        return Err(Error::InvalidArgument(format!(
            "identity.json uses unsupported device_priv_enc_method {method:?}"
        )));
    }
    let encoded = doc
        .get("device_priv_b64_enc")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::InvalidArgument("identity.json missing device_priv_b64_enc".into())
        })?;
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .map_err(|err| Error::InvalidArgument(format!("invalid device_priv_b64_enc: {err}")))?;
    let device = tn_core::DeviceKey::from_private_bytes(&seed)?;
    if let Some(did) = doc
        .get("did")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if did != device.did() {
            return Err(Error::InvalidArgument(format!(
                "identity.json DID mismatch: file has {did:?}, derived {:?}",
                device.did()
            )));
        }
    }
    Ok(device)
}

#[cfg(feature = "http")]
fn read_yaml_mapping(path: &Path) -> Result<YamlMapping> {
    let raw = fs::read_to_string(path)?;
    match serde_yml::from_str::<YamlValue>(&raw)? {
        YamlValue::Mapping(mapping) => Ok(mapping),
        _ => Err(Error::InvalidArgument(format!(
            "{} must contain a YAML mapping",
            path.display()
        ))),
    }
}

#[cfg(feature = "http")]
fn resolve_yaml_relative_path(yaml_path: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        yaml_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(path)
    }
}

fn normalize_required<'a>(name: &str, value: &'a str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidArgument(format!("{name} must not be empty")));
    }
    Ok(value)
}

fn normalize_vault_url(value: &str) -> Result<String> {
    Ok(normalize_required("vault", value)?
        .trim_end_matches('/')
        .to_string())
}

#[cfg(feature = "http")]
fn json_field_str<'a>(raw: &'a JsonValue, field: &str, context: &str) -> Result<&'a str> {
    raw.get(field)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::VaultHttp(format!("{context} missing {field}")))
}

#[cfg(feature = "http")]
fn optional_json_string(raw: &JsonValue, field: &str) -> Option<String> {
    raw.get(field)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(feature = "http")]
fn account_status_error(method: &str, path: &str, response: reqwest::blocking::Response) -> Error {
    let status = response.status();
    let body = response.text().unwrap_or_default();
    let body = body.trim();
    let body = if body.len() > 512 { &body[..512] } else { body };
    if body.is_empty() {
        Error::VaultHttp(format!("{method} {path} returned {}", status.as_u16()))
    } else {
        Error::VaultHttp(format!(
            "{method} {path} returned {}: {body}",
            status.as_u16()
        ))
    }
}
