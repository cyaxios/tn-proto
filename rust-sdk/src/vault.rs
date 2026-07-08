//! Vault helpers.
//!
//! This namespace mirrors the Python/TypeScript `tn.vault.*` surface for
//! recording local vault link/unlink audit events and updating local
//! ceremony/vault link-state in `tn.yaml`.

#[cfg(feature = "http")]
use std::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "http")]
use crate::credential_store::{
    cache_account_awk_with_client, load_cached_account_awk, CredentialStore,
};
use crate::tn::Tn;
use crate::{Error, Result};
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::Engine;
use hmac::Mac;
#[cfg(feature = "http")]
use rand_core::RngCore;
#[cfg(feature = "http")]
use serde_json::Value as JsonValue;
use serde_yml::{Mapping as YamlMapping, Value as YamlValue};
use sha2::Sha256;
#[cfg(feature = "http")]
use tn_core::signing::signature_b64;
use tn_core::DeviceKey;

type HmacSha256 = hmac::Hmac<Sha256>;

/// Runtime vault namespace for a [`Tn`] handle.
pub struct Vault<'a> {
    tn: &'a Tn,
}

/// Result from [`Vault::link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLinkResult {
    /// Vault identity recorded in the admin event.
    pub vault_identity: String,
    /// Vault-side project id recorded in the admin event.
    pub project_id: String,
}

/// Result from [`Vault::unlink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultUnlinkResult {
    /// Vault identity recorded in the admin event.
    pub vault_identity: String,
    /// Vault-side project id recorded in the admin event.
    pub project_id: String,
    /// Optional unlink reason recorded in the admin event.
    pub reason: Option<String>,
}

/// Link-state mode written into the local ceremony YAML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLinkState {
    /// The ceremony is local-only and not connected to a vault.
    Local,
    /// The ceremony is connected to a vault.
    Linked,
}

impl VaultLinkState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Linked => "linked",
        }
    }
}

/// Options for [`Vault::set_link_state`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetLinkStateOptions {
    /// Vault identity or URL to stamp into `ceremony.linked_vault` and
    /// `vault.url` when linking.
    pub linked_vault: Option<String>,
    /// Optional vault-side project id to stamp into the ceremony and vault
    /// blocks when linking.
    pub linked_project_id: Option<String>,
}

/// Result from [`Vault::set_link_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLinkStateResult {
    /// State written into `ceremony.mode`.
    pub state: VaultLinkState,
    /// YAML file that was updated. This may be an extended parent file rather
    /// than the active overlay passed to [`Tn::init`](crate::Tn::init).
    pub yaml_path: PathBuf,
    /// Linked vault value written when `state` is [`VaultLinkState::Linked`].
    pub linked_vault: Option<String>,
    /// Linked vault project id written when supplied.
    pub linked_project_id: Option<String>,
}

/// Current local link-state read from ceremony YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLinkStateInfo {
    /// Current ceremony mode.
    pub state: VaultLinkState,
    /// YAML file that was read. This may be an extended parent file rather
    /// than the active overlay passed to [`Tn::init`](crate::Tn::init).
    pub yaml_path: PathBuf,
    /// Linked vault value, resolved from `vault.url` with
    /// `ceremony.linked_vault` as a fallback.
    pub linked_vault: Option<String>,
    /// Linked vault project id, resolved from `vault.linked_project_id` with
    /// `ceremony.linked_project_id` as a fallback.
    pub linked_project_id: Option<String>,
    /// Whether the YAML vault block is enabled.
    pub vault_enabled: bool,
    /// Whether vault autosync is enabled for this local ceremony.
    pub autosync: bool,
    /// Configured autosync interval in seconds, when present.
    pub sync_interval_seconds: Option<i64>,
}

/// Options for [`Vault::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConnectOptions {
    /// Vault URL or identity to write into local YAML and audit events.
    pub vault: String,
    /// Vault-side project id to write into local YAML and audit events.
    pub project_id: String,
    /// Optional friendly project name returned in the connection result.
    ///
    /// The Rust SDK does not create the vault project yet. A future HTTP
    /// client layer can pass the name it used when creating or discovering the
    /// project.
    pub project_name: Option<String>,
    /// Whether to emit a local `tn.vault.linked` audit event after the YAML
    /// link-state is updated.
    pub record_audit_event: bool,
}

impl VaultConnectOptions {
    /// Create connection options that record a local audit event.
    pub fn new(vault: impl Into<String>, project_id: impl Into<String>) -> Self {
        Self {
            vault: vault.into(),
            project_id: project_id.into(),
            project_name: None,
            record_audit_event: true,
        }
    }
}

/// Result from [`Vault::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConnectResult {
    /// Vault URL or identity used for this local connection.
    pub vault: String,
    /// Vault-side project id used for this local connection.
    pub project_id: String,
    /// Optional friendly project name carried through from
    /// [`VaultConnectOptions`].
    pub project_name: Option<String>,
    /// True when this call changed local link-state from unlinked to linked.
    pub newly_linked: bool,
    /// True when this call emitted a local `tn.vault.linked` audit event.
    pub audit_event_recorded: bool,
    /// Normalized YAML link-state after the call.
    pub state: VaultLinkStateInfo,
}

/// Result from the unauthenticated vault pending-claim onboarding flow.
///
/// The claim URL has the shape `{vault}/claim/{vault_id}#k=<password_b64>`.
/// The `#k=` fragment carries the BEK and is never sent to the vault server
/// by browsers.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInitUploadResult {
    /// Server-assigned pending-claim id.
    pub vault_id: String,
    /// ISO-8601 expiry returned by the vault.
    pub expires_at: String,
    /// Browser claim URL to show to the user.
    pub claim_url: String,
    /// Base64url-encoded BEK carried in the claim URL fragment.
    pub password_b64: String,
}

/// Options for [`Vault::init_upload_http`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultInitUploadOptions {
    /// Optional group subset to include in the encrypted full-keystore package.
    ///
    /// The default is all groups, matching Python/TypeScript init-upload.
    pub groups: Option<Vec<String>>,
}

/// Vault project metadata returned by a client implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultProject {
    /// Vault-side project id.
    pub id: String,
    /// Vault-side display name.
    pub name: String,
    /// Ceremony id associated with the vault project, when the vault returns
    /// one.
    pub ceremony_id: Option<String>,
}

/// Vault file metadata returned by file-list and upload routes.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    /// File key inside the vault project.
    pub name: String,
    /// Size in bytes when reported by the vault.
    pub size: Option<u64>,
    /// Hex SHA-256 digest when reported by the vault.
    pub sha256: Option<String>,
    /// Upload timestamp when reported by the vault.
    pub uploaded_at: Option<String>,
}

/// Account inbox metadata returned by the authenticated vault account inbox.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAccountInboxItem {
    /// Publisher DID that produced the package.
    pub publisher_identity: String,
    /// Ceremony id associated with the package.
    pub ceremony_id: String,
    /// Package timestamp path segment.
    pub ts: String,
    /// Timestamp set by the vault when this inbox item has already been
    /// consumed.
    pub consumed_at: Option<String>,
}

/// Response returned after publishing an inbox snapshot.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInboxSnapshot {
    /// Vault download path for the stored snapshot.
    pub stored_path: String,
    /// Stored package byte length.
    pub byte_size: u64,
    /// Package manifest signature.
    pub manifest_signature_b64: String,
    /// Optional package head row hash.
    pub head_row_hash: Option<String>,
}

/// Plaintext body member map used by the supported whole-body vault backup
/// model.
///
/// Keys must be `body/...` package member paths and values are raw member
/// bytes. This is the Rust-facing counterpart of Python/TS body encryption
/// maps.
pub type VaultBodyPlaintext = tn_core::body_encryption::BodyPlaintext;

/// Options for installing a decrypted vault body into a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInstallBodyOptions {
    /// Directory that will receive `tn.yaml` and a `keys/` subdirectory.
    pub target_dir: PathBuf,
    /// Whether different existing files may be overwritten.
    ///
    /// The default is `false` so restore is explicit and non-destructive.
    pub overwrite: bool,
}

impl VaultInstallBodyOptions {
    /// Install into `target_dir` without overwriting different existing files.
    pub fn new(target_dir: impl Into<PathBuf>) -> Self {
        Self {
            target_dir: target_dir.into(),
            overwrite: false,
        }
    }
}

/// Result from [`install_vault_body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInstallBodyResult {
    /// Directory that received restored files.
    pub target_dir: PathBuf,
    /// Restored `tn.yaml` path.
    pub yaml_path: PathBuf,
    /// Restored key directory.
    pub keys_dir: PathBuf,
    /// Paths written or overwritten by this call.
    pub written_paths: Vec<PathBuf>,
    /// Paths already present with identical bytes.
    pub deduped_paths: Vec<PathBuf>,
    /// Body members ignored because this helper only installs `tn.yaml` and
    /// flat `body/keys/*` project material.
    pub skipped_members: Vec<String>,
}

/// Install a decrypted vault body into a caller-supplied project directory.
///
/// This writes `body/tn.yaml` to `<target_dir>/tn.yaml` and flat
/// `body/keys/<name>` members to `<target_dir>/keys/<name>`. It refuses path
/// traversal, nested key paths, missing required identity files, mismatched
/// identity material, and different existing files unless `overwrite` is true.
///
/// # Errors
///
/// Returns [`crate::Error`] when the body is missing required project members,
/// identity material fails validation, the target is unsafe, or filesystem
/// writes fail.
pub fn install_vault_body(
    body: &VaultBodyPlaintext,
    options: VaultInstallBodyOptions,
) -> Result<VaultInstallBodyResult> {
    install_vault_body_impl(body, options)
}

/// Cipher-suite identifier recorded for vault body-encryption manifests.
pub const VAULT_BODY_CIPHER_SUITE: &str = tn_core::body_encryption::BODY_CIPHER_SUITE;

/// Frame identifier recorded for vault body-encryption manifests.
pub const VAULT_BODY_FRAME: &str = tn_core::body_encryption::BODY_FRAME;

/// AAD used when wrapping a project BEK under an account AWK.
pub const VAULT_BEK_WRAP_AAD: &[u8] = b"tn-vault-bek-wrap-v1";

/// AAD used by Python/TypeScript when wrapping an account AWK under a
/// credential key.
pub const VAULT_AWK_WRAP_AAD: &[u8] = b"tn-vault-awk-wrap-v1";

/// Minimum PBKDF2 iteration count accepted by the headless passphrase flow.
///
/// Python and TypeScript also reject lower counts so weak test fixtures cannot
/// accidentally become accepted credentials.
pub const VAULT_MIN_PBKDF2_ITERATIONS: u32 = 10_000;

/// Vault body encryption key.
///
/// A BEK encrypts the whole ceremony body frame before that frame is uploaded
/// to vault storage. It is distinct from the account wrap key that protects
/// the BEK in the vault's wrapped-key row.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultBek([u8; 32]);

impl VaultBek {
    /// Create a BEK from exactly 32 raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random BEK.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a BEK from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the slice is not exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::InvalidArgument(format!("vault BEK must be 32 bytes; got {}", bytes.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Borrow the raw BEK bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the wrapper and return the raw BEK bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for VaultBek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultBek(..)")
    }
}

/// Vault account wrap key.
///
/// An AWK wraps a project BEK for storage in the vault's wrapped-key row. Rust
/// does not derive or cache AWKs yet, but this wrapper gives the public API a
/// clear type boundary before those flows are added.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultAwk([u8; 32]);

impl VaultAwk {
    /// Create an AWK from exactly 32 raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create an AWK from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the slice is not exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::InvalidArgument(format!("vault AWK must be 32 bytes; got {}", bytes.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Borrow the raw AWK bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the wrapper and return the raw AWK bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for VaultAwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultAwk(..)")
    }
}

/// KDF parameters from a vault account credential wrap row.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct VaultCredentialKdfParams {
    /// Base64 or base64url salt used for PBKDF2-SHA256.
    pub salt_b64: Option<String>,
    /// Preferred iteration field used by Python/TypeScript.
    pub iterations: Option<u32>,
    /// Legacy alias accepted by Python/TypeScript.
    pub iter: Option<u32>,
}

impl VaultCredentialKdfParams {
    fn iteration_count(&self) -> u32 {
        self.iterations.or(self.iter).unwrap_or(300_000)
    }
}

/// Vault account credential row containing AWK wrapping material.
///
/// This mirrors Python `CredentialWrap` and TypeScript `CredentialWrap`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultCredentialWrap {
    /// KDF name. Rust currently supports `pbkdf2-sha256`, matching the
    /// Python/TypeScript headless fallback.
    pub kdf: String,
    /// KDF parameters.
    #[serde(default)]
    pub kdf_params: VaultCredentialKdfParams,
    /// Wrapped account key ciphertext plus tag, base64-encoded.
    pub wrapped_account_key_b64: String,
    /// AES-GCM 12-byte nonce, base64-encoded.
    pub wrap_nonce_b64: String,
}

impl VaultCredentialWrap {
    /// Parse a credential wrap row from vault JSON.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when required fields are missing or have
    /// incompatible types.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone())
            .map_err(|err| Error::InvalidArgument(format!("invalid vault credential wrap: {err}")))
    }
}

/// Derive the 32-byte credential key from a passphrase using PBKDF2-SHA256.
///
/// This mirrors Python `_derive_credential_key_pbkdf2` and TypeScript
/// `deriveCredentialKeyPbkdf2`.
///
/// # Errors
///
/// Returns [`crate::Error`] when `iterations` is below
/// [`VAULT_MIN_PBKDF2_ITERATIONS`].
pub fn derive_credential_key_pbkdf2(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32]> {
    if iterations < VAULT_MIN_PBKDF2_ITERATIONS {
        return Err(Error::InvalidArgument(format!(
            "refusing PBKDF2 with iterations={iterations} (<{VAULT_MIN_PBKDF2_ITERATIONS})"
        )));
    }

    let mut previous = hmac_sha256(passphrase.as_bytes(), &[salt, &[0, 0, 0, 1]].concat())?;
    let mut output = previous;
    for _ in 1..iterations {
        previous = hmac_sha256(passphrase.as_bytes(), &previous)?;
        for (out, byte) in output.iter_mut().zip(previous) {
            *out ^= byte;
        }
    }
    Ok(output)
}

/// Derive an account AWK from passphrase and already-fetched credential
/// material.
///
/// This pure helper mirrors TypeScript `deriveAwkFromMaterial` and Python
/// `derive_account_awk` minus the network fetch.
///
/// # Errors
///
/// Returns [`crate::Error`] when the credential uses an unsupported KDF, lacks
/// salt material, has invalid base64/nonce fields, or the passphrase cannot
/// authenticate the wrapped AWK.
pub fn derive_awk_from_material(
    passphrase: &str,
    credential: &VaultCredentialWrap,
) -> Result<VaultAwk> {
    if credential.kdf != "pbkdf2-sha256" {
        return Err(Error::InvalidArgument(format!(
            "credential KDF {:?} not supported in CLI; use the browser flow",
            credential.kdf
        )));
    }
    let salt_b64 = credential
        .kdf_params
        .salt_b64
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Error::InvalidArgument("credential row missing kdf_params.salt_b64".into())
        })?;
    let salt = decode_base64_loose(salt_b64, "kdf_params.salt_b64")?;
    let credential_key =
        derive_credential_key_pbkdf2(passphrase, &salt, credential.kdf_params.iteration_count())?;
    let awk = aes_gcm_unwrap_raw(
        &credential_key,
        &credential.wrapped_account_key_b64,
        &credential.wrap_nonce_b64,
        VAULT_AWK_WRAP_AAD,
        "AWK",
    )?;
    VaultAwk::from_slice(&awk)
}

/// Derive a project BEK from passphrase, account credential material, and a
/// project wrapped-key row.
///
/// This mirrors TypeScript `deriveBekFromMaterial`.
///
/// # Errors
///
/// Returns [`crate::Error`] when AWK derivation or BEK unwrap fails.
pub fn derive_bek_from_material(
    passphrase: &str,
    credential: &VaultCredentialWrap,
    wrapped: &VaultWrappedBek,
) -> Result<VaultBek> {
    let awk = derive_awk_from_material(passphrase, credential)?;
    unwrap_bek_from_awk(&awk, wrapped)
}

/// Wire fields for a vault wrapped-key row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultWrappedBek {
    /// AES-GCM ciphertext plus tag, base64-encoded.
    pub wrapped_bek_b64: String,
    /// AES-GCM 12-byte nonce, base64-encoded.
    pub wrap_nonce_b64: String,
}

impl VaultWrappedBek {
    /// Parse a wrapped-key row from a vault JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the JSON is not an object or the required
    /// base64 string fields are missing.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            wrapped_bek_b64: json_value_field_str(value, "wrapped_bek_b64", "wrapped-key row")?
                .to_string(),
            wrap_nonce_b64: json_value_field_str(value, "wrap_nonce_b64", "wrapped-key row")?
                .to_string(),
        })
    }

    /// Convert this wrapped-key row to the JSON body accepted by the vault
    /// `PUT /wrapped-key` route.
    pub fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "wrapped_bek_b64": self.wrapped_bek_b64,
            "wrap_nonce_b64": self.wrap_nonce_b64,
            "cipher_suite": VAULT_BODY_CIPHER_SUITE,
        })
    }
}

/// Wrap a BEK under an AWK with a fresh random AES-GCM nonce.
///
/// The wire fields match Python `wallet_push._wrap_bek_under_awk` and
/// TypeScript `wrapBekUnderAwk`.
///
/// # Errors
///
/// Returns [`crate::Error`] when AES-GCM rejects the key or encryption fails.
pub fn wrap_bek_under_awk(awk: &VaultAwk, bek: &VaultBek) -> Result<VaultWrappedBek> {
    use rand_core::{OsRng, RngCore};

    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    wrap_bek_under_awk_with_nonce(awk, bek, &nonce)
}

/// Wrap a BEK under an AWK with a caller-supplied nonce.
///
/// This deterministic helper is intended for tests and parity fixtures.
///
/// # Errors
///
/// Returns [`crate::Error`] when AES-GCM rejects the key or encryption fails.
pub fn wrap_bek_under_awk_with_nonce(
    awk: &VaultAwk,
    bek: &VaultBek,
    nonce: &[u8; 12],
) -> Result<VaultWrappedBek> {
    let cipher = Aes256Gcm::new_from_slice(awk.as_bytes())
        .map_err(|err| Error::InvalidArgument(format!("invalid AWK: {err}")))?;
    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: bek.as_bytes(),
                aad: VAULT_BEK_WRAP_AAD,
            },
        )
        .map_err(|_| Error::InvalidArgument("wrap BEK under AWK failed".into()))?;
    Ok(VaultWrappedBek {
        wrapped_bek_b64: base64::engine::general_purpose::STANDARD.encode(wrapped),
        wrap_nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
    })
}

/// Unwrap a BEK from vault wrapped-key wire fields using an AWK.
///
/// # Errors
///
/// Returns [`crate::Error`] when the base64 fields are invalid, the nonce is
/// not 12 bytes, authentication fails, or the unwrapped key is not 32 bytes.
pub fn unwrap_bek_from_awk(awk: &VaultAwk, wrapped: &VaultWrappedBek) -> Result<VaultBek> {
    let bek = aes_gcm_unwrap_raw(
        awk.as_bytes(),
        &wrapped.wrapped_bek_b64,
        &wrapped.wrap_nonce_b64,
        VAULT_BEK_WRAP_AAD,
        "BEK",
    )?;
    VaultBek::from_slice(&bek)
}

/// Encrypt body members under a caller-supplied BEK and nonce.
///
/// This is the deterministic test helper for the supported AWK/BEK whole-body
/// model. The wire output is `nonce || ciphertext+tag`, with a STORED zip
/// plaintext inside AES-256-GCM and no AAD.
///
/// # Errors
///
/// Returns [`crate::Error`] when a body member path is invalid or encryption
/// fails.
pub fn encrypt_vault_body_with_nonce(
    body: &VaultBodyPlaintext,
    bek: &VaultBek,
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    Ok(tn_core::body_encryption::encrypt_body_blob_with_nonce(
        body,
        bek.as_bytes(),
        nonce,
    )?)
}

/// Encrypt body members under a caller-supplied BEK with a fresh random nonce.
///
/// This mirrors Python/TS `encryptBodyBlob` for the supported whole-body vault
/// backup model.
///
/// # Errors
///
/// Returns [`crate::Error`] when a body member path is invalid or encryption
/// fails.
pub fn encrypt_vault_body(body: &VaultBodyPlaintext, bek: &VaultBek) -> Result<Vec<u8>> {
    use rand_core::{OsRng, RngCore};

    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    encrypt_vault_body_with_nonce(body, bek, &nonce)
}

/// Decrypt a supported whole-body vault backup blob under a BEK.
///
/// # Errors
///
/// Returns [`crate::Error`] when the blob is truncated, the key is wrong, the
/// ciphertext was tampered with, or the decrypted body is not a valid STORED
/// zip of `body/...` members.
pub fn decrypt_vault_body(blob: &[u8], bek: &VaultBek) -> Result<VaultBodyPlaintext> {
    Ok(tn_core::body_encryption::decrypt_body_blob(
        blob,
        bek.as_bytes(),
    )?)
}

/// Options for [`Vault::push_body_with_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct VaultPushBodyOptions {
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Body encryption key used for this upload.
    pub bek: VaultBek,
    /// Already-wrapped-key JSON body to store before uploading the encrypted
    /// body frame.
    ///
    /// This is intentionally explicit until Rust grows the AWK derivation and
    /// BEK wrapping flow. [`VaultHttpProjectClient::put_wrapped_key`] inserts
    /// `cipher_suite` when this object omits it.
    pub wrapped_key: JsonValue,
    /// Whether to store `wrapped_key` before uploading the encrypted body.
    ///
    /// Direct callers default to `true`. AWK-backed push sets this to `false`
    /// when it reuses an existing wrapped-key row.
    pub store_wrapped_key: bool,
    /// `If-Match` value for the encrypted-blob PUT. Use `"*"` for a first
    /// upload.
    pub if_match: String,
}

#[cfg(feature = "http")]
impl VaultPushBodyOptions {
    /// Create push options for a caller-supplied BEK and wrapped-key row.
    pub fn new(bek: VaultBek, wrapped_key: JsonValue) -> Self {
        Self {
            project_id: None,
            bek,
            wrapped_key,
            store_wrapped_key: true,
            if_match: "*".to_string(),
        }
    }

    /// Create push options by wrapping `bek` under `awk`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when BEK wrapping fails.
    pub fn wrap_with_awk(bek: VaultBek, awk: &VaultAwk) -> Result<Self> {
        let wrapped_key = wrap_bek_under_awk(awk, &bek)?.into_json();
        Ok(Self::new(bek, wrapped_key))
    }
}

/// Result from [`Vault::push_body_with_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq)]
pub struct VaultPushBodyResult {
    /// Vault project id that received the body.
    pub project_id: String,
    /// Number of body members collected and encrypted.
    pub body_member_count: usize,
    /// Length in bytes of the encrypted `nonce || ciphertext+tag` frame.
    pub encrypted_len: usize,
    /// Parsed wrapped-key response. This is the PUT response when
    /// `store_wrapped_key` was true, or the reused wrapped-key row when the
    /// caller intentionally skipped the PUT.
    pub wrapped_key_response: JsonValue,
    /// Parsed response from the encrypted-blob PUT.
    pub encrypted_blob_response: JsonValue,
}

/// Options for [`Vault::push_body_with_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct VaultPushWithAwkOptions {
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Account wrap key used to unwrap an existing project BEK or wrap a newly
    /// minted one.
    pub awk: VaultAwk,
}

#[cfg(feature = "http")]
impl VaultPushWithAwkOptions {
    /// Create AWK-backed push options.
    pub fn new(awk: VaultAwk) -> Self {
        Self {
            project_id: None,
            awk,
        }
    }
}

/// Result from [`Vault::push_body_with_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq)]
pub struct VaultPushWithAwkResult {
    /// Lower-level push result.
    pub push: VaultPushBodyResult,
    /// True when no wrapped-key row existed and Rust minted/wrapped a fresh
    /// BEK.
    pub wrapped_key_created: bool,
    /// `If-Match` value used for the encrypted body upload.
    pub if_match: String,
}

/// Options for [`Vault::push_body_with_passphrase_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPushWithPassphraseOptions {
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Optional credential id to fetch from the vault account. When omitted,
    /// Rust selects the unique primary credential row, or the sole row.
    pub credential_id: Option<String>,
}

#[cfg(feature = "http")]
impl VaultPushWithPassphraseOptions {
    /// Create passphrase-backed push options.
    pub fn new() -> Self {
        Self {
            project_id: None,
            credential_id: None,
        }
    }
}

#[cfg(feature = "http")]
impl Default for VaultPushWithPassphraseOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Options for [`Vault::push_body_with_cached_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPushWithCachedAwkOptions {
    /// Vault account id whose AWK is stored under `awk:{account_id}`.
    pub account_id: String,
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Optional passphrase fallback used only when no valid cached AWK exists.
    pub passphrase: Option<String>,
    /// Optional credential id to fetch when deriving an AWK from `passphrase`.
    pub credential_id: Option<String>,
}

#[cfg(feature = "http")]
impl VaultPushWithCachedAwkOptions {
    /// Create cached-AWK push options for `account_id`.
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            project_id: None,
            passphrase: None,
            credential_id: None,
        }
    }
}

/// Options for [`Vault::restore_body_with_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct VaultRestoreWithAwkOptions {
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Account wrap key used to unwrap the project BEK.
    pub awk: VaultAwk,
}

#[cfg(feature = "http")]
impl VaultRestoreWithAwkOptions {
    /// Create AWK-backed restore options.
    pub fn new(awk: VaultAwk) -> Self {
        Self {
            project_id: None,
            awk,
        }
    }
}

/// Options for [`Vault::restore_body_with_passphrase_http_client`] and
/// [`Vault::restore_and_install_body_with_passphrase_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRestoreWithPassphraseOptions {
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Optional credential id to fetch from the vault account. When omitted,
    /// Rust selects the unique primary credential row, or the sole row.
    pub credential_id: Option<String>,
}

/// Options for [`Vault::restore_body_with_cached_awk_http_client`] and
/// [`Vault::restore_and_install_body_with_cached_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRestoreWithCachedAwkOptions {
    /// Vault account id whose AWK is stored under `awk:{account_id}`.
    pub account_id: String,
    /// Vault project id. When omitted, Rust uses the linked project id from
    /// local YAML.
    pub project_id: Option<String>,
    /// Optional passphrase fallback used only when no valid cached AWK exists.
    pub passphrase: Option<String>,
    /// Optional credential id to fetch when deriving an AWK from `passphrase`.
    pub credential_id: Option<String>,
}

#[cfg(feature = "http")]
impl VaultRestoreWithCachedAwkOptions {
    /// Create cached-AWK restore options for `account_id`.
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            project_id: None,
            passphrase: None,
            credential_id: None,
        }
    }
}

#[cfg(feature = "http")]
impl VaultRestoreWithPassphraseOptions {
    /// Create passphrase-backed restore options.
    pub fn new() -> Self {
        Self {
            project_id: None,
            credential_id: None,
        }
    }
}

#[cfg(feature = "http")]
impl Default for VaultRestoreWithPassphraseOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from [`Vault::restore_body_with_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq)]
pub struct VaultRestoreWithAwkResult {
    /// Vault project id that was restored.
    pub project_id: String,
    /// Decrypted body members.
    pub body: VaultBodyPlaintext,
    /// Wrapped-key row used to recover the BEK.
    pub wrapped_key: VaultWrappedBek,
    /// Parsed encrypted-blob response.
    pub encrypted_blob_response: JsonValue,
}

/// Result from [`Vault::restore_and_install_body_with_awk_http_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq)]
pub struct VaultRestoreAndInstallWithAwkResult {
    /// Read-only restore result.
    pub restore: VaultRestoreWithAwkResult,
    /// Filesystem install result.
    pub install: VaultInstallBodyResult,
}

/// Options for [`Vault::connect_with_client`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultClientConnectOptions {
    /// Project name to create or discover on the vault.
    ///
    /// When omitted, Rust falls back to `ceremony.project_name`, then
    /// `ceremony.id`, matching Python/TypeScript wallet-link behavior.
    pub project_name: Option<String>,
    /// Whether to emit a local `tn.vault.linked` audit event after the YAML
    /// link-state is updated.
    pub record_audit_event: bool,
}

impl Default for VaultClientConnectOptions {
    fn default() -> Self {
        Self {
            project_name: None,
            record_audit_event: true,
        }
    }
}

/// Options for [`Vault::connect_http`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHttpConnectOptions {
    /// HTTP client options, including vault base URL and optional bearer token.
    pub client: VaultHttpProjectClientOptions,
    /// Project name to create or discover on the vault.
    ///
    /// When omitted, Rust falls back to `ceremony.project_name`, then
    /// `ceremony.id`.
    pub project_name: Option<String>,
    /// Whether to emit a local `tn.vault.linked` audit event after the YAML
    /// link-state is updated.
    pub record_audit_event: bool,
}

#[cfg(feature = "http")]
impl VaultHttpConnectOptions {
    /// Create HTTP connection options with default client settings.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: VaultHttpProjectClientOptions::new(base_url),
            project_name: None,
            record_audit_event: true,
        }
    }
}

/// Minimal project-management surface needed for vault connection.
///
/// A real HTTP client should implement `ensure_project` by creating the
/// project and, on a vault conflict, listing projects and reusing the matching
/// name. That mirrors Python/TypeScript while keeping this SDK layer testable
/// without network calls.
pub trait VaultProjectClient {
    /// Vault base URL or identity to stamp into local YAML.
    fn base_url(&self) -> &str;

    /// Create or discover a project under the authenticated vault identity.
    ///
    /// `ceremony_id` is forwarded when known so the vault can associate the
    /// remote project with this local ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the vault request fails, the project cannot
    /// be reused, or the response is malformed.
    fn ensure_project(&mut self, name: &str, ceremony_id: Option<&str>) -> Result<VaultProject>;
}

/// Device identity used by the vault DID challenge/verify flow.
#[cfg(feature = "http")]
pub trait VaultIdentity {
    /// Public DID sent to the vault challenge and verify endpoints.
    fn did(&self) -> &str;

    /// Sign the vault nonce bytes exactly as supplied.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the identity cannot sign the nonce.
    fn sign_nonce(&self, message: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(feature = "http")]
impl VaultIdentity for DeviceKey {
    fn did(&self) -> &str {
        self.did()
    }

    fn sign_nonce(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sign(message).to_vec())
    }
}

/// Ed25519 vault identity backed by the same device seed format TN stores in
/// `keys/local.private`.
#[cfg(feature = "http")]
pub struct VaultDeviceIdentity {
    device: DeviceKey,
}

#[cfg(feature = "http")]
impl VaultDeviceIdentity {
    /// Create a vault identity from a 32-byte Ed25519 device seed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `seed` is not exactly 32 bytes.
    pub fn from_private_bytes(seed: &[u8]) -> Result<Self> {
        Ok(Self {
            device: DeviceKey::from_private_bytes(seed)?,
        })
    }

    /// Wrap an existing TN device key.
    pub fn from_device_key(device: DeviceKey) -> Self {
        Self { device }
    }

    /// Borrow the public DID for this identity.
    pub fn did(&self) -> &str {
        self.device.did()
    }

    /// Borrow the underlying TN device key.
    pub fn device_key(&self) -> &DeviceKey {
        &self.device
    }
}

#[cfg(feature = "http")]
impl VaultIdentity for VaultDeviceIdentity {
    fn did(&self) -> &str {
        self.did()
    }

    fn sign_nonce(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.device.sign_nonce(message)
    }
}

/// Options for [`VaultHttpProjectClient`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHttpProjectClientOptions {
    /// Vault base URL, for example `https://vault.tn-proto.org`.
    pub base_url: String,
    /// Optional bearer token. When omitted, the client also checks
    /// `TN_VAULT_SESSION_TOKEN` and then `TN_VAULT_JWT`.
    pub bearer_token: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Optional User-Agent header.
    pub user_agent: Option<String>,
}

#[cfg(feature = "http")]
impl VaultHttpProjectClientOptions {
    /// Create options with the default timeout and no bearer token.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: None,
            timeout: Duration::from_secs(30),
            user_agent: Some(format!("tn-proto-rust/{}", env!("CARGO_PKG_VERSION"))),
        }
    }
}

/// Blocking HTTP vault client for authentication and project creation/discovery.
///
/// This concrete client mirrors the Python/TypeScript DID challenge/verify
/// auth flow, then implements the project-management surface needed by
/// [`Vault::connect_with_client`].
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct VaultHttpProjectClient {
    base_url: String,
    bearer_token: Option<String>,
    http: reqwest::blocking::Client,
}

#[cfg(feature = "http")]
impl VaultHttpProjectClient {
    /// Create a client with default options.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the base URL is empty or the HTTP client
    /// cannot be constructed.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_options(VaultHttpProjectClientOptions::new(base_url))
    }

    /// Create a client with explicit options.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the base URL is empty or the HTTP client
    /// cannot be constructed.
    pub fn with_options(options: VaultHttpProjectClientOptions) -> Result<Self> {
        let base_url = normalize_required("vault base_url", &options.base_url)?
            .trim_end_matches('/')
            .to_string();
        let mut builder = reqwest::blocking::Client::builder().timeout(options.timeout);
        if let Some(user_agent) = options
            .user_agent
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            builder = builder.user_agent(user_agent);
        }
        Ok(Self {
            base_url,
            bearer_token: options
                .bearer_token
                .or_else(|| std::env::var("TN_VAULT_SESSION_TOKEN").ok())
                .or_else(|| std::env::var("TN_VAULT_JWT").ok())
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            http: builder.build()?,
        })
    }

    /// Create a client and authenticate it with a TN device identity unless a
    /// bearer token is already configured in `options` or the vault token
    /// environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when client construction fails or the vault
    /// challenge/verify exchange fails.
    pub fn for_identity<I: VaultIdentity>(
        identity: &I,
        options: VaultHttpProjectClientOptions,
    ) -> Result<Self> {
        let mut client = Self::with_options(options)?;
        client.ensure_authenticated(identity)?;
        Ok(client)
    }

    /// Return the active bearer token, if the client has one.
    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }

    /// Replace the active bearer token.
    pub fn set_bearer_token(&mut self, token: impl Into<String>) {
        let token = token.into();
        self.bearer_token = normalize_optional_string(&token);
    }

    /// Run the vault DID challenge/verify flow and cache the returned bearer
    /// token on this client.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the identity DID is empty, either HTTP
    /// request fails, the vault rejects the exchange, or the JSON responses are
    /// missing `nonce`/`token`.
    pub fn authenticate<I: VaultIdentity>(&mut self, identity: &I) -> Result<String> {
        let did = normalize_required("vault identity did", identity.did())?;
        let challenge_body = JsonValue::Object(serde_json::Map::from_iter([(
            "did".to_string(),
            JsonValue::String(did.to_string()),
        )]));
        let challenge_response = self
            .request_without_auth(reqwest::Method::POST, "/api/v1/auth/challenge")?
            .json(&challenge_body)
            .send()?;
        if !challenge_response.status().is_success() {
            return Err(vault_status_error(
                "POST",
                "/api/v1/auth/challenge",
                challenge_response,
            ));
        }
        let challenge: JsonValue = challenge_response.json()?;
        let nonce = json_field_str(&challenge, "nonce", "vault challenge response")?;
        let signature = identity.sign_nonce(nonce.as_bytes())?;
        let verify_body = JsonValue::Object(serde_json::Map::from_iter([
            ("did".to_string(), JsonValue::String(did.to_string())),
            ("nonce".to_string(), JsonValue::String(nonce.to_string())),
            (
                "signature".to_string(),
                JsonValue::String(signature_b64(&signature)),
            ),
        ]));
        let verify_response = self
            .request_without_auth(reqwest::Method::POST, "/api/v1/auth/verify")?
            .json(&verify_body)
            .send()?;
        if !verify_response.status().is_success() {
            return Err(vault_status_error(
                "POST",
                "/api/v1/auth/verify",
                verify_response,
            ));
        }
        let verify: JsonValue = verify_response.json()?;
        let token = json_field_str(&verify, "token", "vault verify response")?.to_string();
        self.bearer_token = Some(token.clone());
        Ok(token)
    }

    /// Ensure the client has an active bearer token.
    ///
    /// If a token was supplied in options or environment variables, this
    /// returns it without a network request. Otherwise it runs
    /// [`authenticate`](Self::authenticate).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the challenge/verify exchange fails.
    pub fn ensure_authenticated<I: VaultIdentity>(&mut self, identity: &I) -> Result<&str> {
        if self.bearer_token.is_none() {
            self.authenticate(identity)?;
        }
        Ok(self
            .bearer_token
            .as_deref()
            .expect("authenticate or options populated bearer_token"))
    }

    /// Post an encrypted full-keystore package to the unauthenticated
    /// pending-claims endpoint.
    ///
    /// This is the HTTP leg used by Python `init_upload` and TypeScript
    /// `Tn.initUpload`: `POST /api/v1/pending-claims` with
    /// `application/octet-stream` bytes plus optional publisher/project
    /// headers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the request fails, the vault rejects the
    /// upload, or the response is missing `vault_id`/`expires_at`.
    pub fn post_pending_claim(
        &self,
        body: impl AsRef<[u8]>,
        project_name: Option<&str>,
        publisher_did: Option<&str>,
    ) -> Result<(String, String)> {
        let mut request = self
            .request_without_auth(reqwest::Method::POST, "/api/v1/pending-claims")?
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body.as_ref().to_vec());
        if let Some(project_name) = project_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            request = request.header("X-Project-Name", project_name);
        }
        if let Some(publisher_did) = publisher_did
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            request = request.header("X-Publisher-Did", publisher_did);
        }

        let response = request.send()?;
        let raw = parse_json_object_response(
            "POST",
            "/api/v1/pending-claims",
            response,
            "pending-claim response",
        )?;
        let vault_id = json_field_str(&raw, "vault_id", "pending-claim response")?.to_string();
        let expires_at = json_field_str(&raw, "expires_at", "pending-claim response")?.to_string();
        Ok((vault_id, expires_at))
    }

    /// Create a new project under the authenticated vault identity.
    ///
    /// Mirrors Python `create_project` and TypeScript `createProject`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the request fails or the vault returns a
    /// malformed project response.
    pub fn create_project(&self, name: &str, ceremony_id: Option<&str>) -> Result<VaultProject> {
        let mut body = serde_json::Map::new();
        body.insert("name".to_string(), JsonValue::String(name.to_string()));
        if let Some(ceremony_id) = ceremony_id {
            body.insert(
                "ceremony_id".to_string(),
                JsonValue::String(ceremony_id.to_string()),
            );
        }
        let response = self
            .request(reqwest::Method::POST, "/api/v1/projects")?
            .json(&JsonValue::Object(body))
            .send()?;
        if response.status().is_success() {
            return parse_project_response(response, Some(name));
        }
        Err(vault_status_error("POST", "/api/v1/projects", response))
    }

    /// List projects visible to the authenticated vault identity.
    ///
    /// Mirrors Python `list_projects` and TypeScript `listProjects`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the request fails or the vault response is
    /// not an array of project objects.
    pub fn list_projects(&self) -> Result<Vec<VaultProject>> {
        let response = self
            .request(reqwest::Method::GET, "/api/v1/projects")?
            .send()?;
        if !response.status().is_success() {
            return Err(vault_status_error("GET", "/api/v1/projects", response));
        }
        let raw: JsonValue = response.json()?;
        let JsonValue::Array(items) = raw else {
            return Err(Error::VaultHttp(
                "GET /api/v1/projects returned non-array JSON".into(),
            ));
        };
        items
            .into_iter()
            .map(|item| parse_project_json(item, None))
            .collect()
    }

    /// Fetch a single vault project by id.
    ///
    /// Mirrors Python `get_project` and TypeScript `getProject`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails,
    /// or the response is malformed.
    pub fn get_project(&self, project_id: &str) -> Result<VaultProject> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!("/api/v1/projects/{}", encode_path_segment(project_id));
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if response.status().is_success() {
            return parse_project_response(response, None);
        }
        Err(vault_status_error("GET", &path, response))
    }

    /// Delete a vault project by id.
    ///
    /// Mirrors Python `delete_project` and TypeScript `deleteProject`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty or the request
    /// fails.
    pub fn delete_project(&self, project_id: &str) -> Result<()> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!("/api/v1/projects/{}", encode_path_segment(project_id));
        let response = self.request(reqwest::Method::DELETE, &path)?.send()?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(vault_status_error("DELETE", &path, response))
    }

    /// Fetch the restore manifest for a vault project.
    ///
    /// Mirrors Python `restore_manifest` and TypeScript `restoreManifest`.
    /// The returned JSON object is intentionally left flexible because the
    /// vault manifest can grow fields without requiring an SDK release.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails,
    /// or the vault returns a non-object JSON response.
    pub fn restore_manifest(&self, project_id: &str) -> Result<JsonValue> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!(
            "/api/v1/projects/{}/restore",
            encode_path_segment(project_id)
        );
        let response = self.request(reqwest::Method::POST, &path)?.send()?;
        if !response.status().is_success() {
            return Err(vault_status_error("POST", &path, response));
        }
        let raw: JsonValue = response.json()?;
        if raw.is_object() {
            Ok(raw)
        } else {
            Err(Error::VaultHttp(
                "vault restore manifest response must be a JSON object".into(),
            ))
        }
    }

    /// List file metadata under a vault project.
    ///
    /// Mirrors Python `list_files`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails,
    /// or the vault response is not an array of file objects.
    pub fn list_files(&self, project_id: &str) -> Result<Vec<VaultFile>> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!("/api/v1/projects/{}/files", encode_path_segment(project_id));
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if !response.status().is_success() {
            return Err(vault_status_error("GET", &path, response));
        }
        let raw: JsonValue = response.json()?;
        let JsonValue::Array(items) = raw else {
            return Err(Error::VaultHttp(
                "GET project files returned non-array JSON".into(),
            ));
        };
        items.into_iter().map(parse_file_json).collect()
    }

    /// Upload a pre-sealed file blob to a vault project.
    ///
    /// Mirrors Python `upload_sealed`. This method does not perform sealing;
    /// callers pass the exact sealed bytes to store.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when ids are empty, the request fails, or the
    /// vault returns malformed file metadata.
    pub fn upload_sealed(
        &self,
        project_id: &str,
        file_name: &str,
        sealed: impl AsRef<[u8]>,
    ) -> Result<VaultFile> {
        let project_id = normalize_required("vault project id", project_id)?;
        let file_name = normalize_required("vault file name", file_name)?;
        let path = file_path(project_id, file_name);
        let response = self
            .request(reqwest::Method::PUT, &path)?
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(sealed.as_ref().to_vec())
            .send()?;
        if response.status().is_success() {
            let raw: JsonValue = response.json()?;
            return parse_file_json(raw);
        }
        Err(vault_status_error("PUT", &path, response))
    }

    /// Download a pre-sealed file blob from a vault project.
    ///
    /// Mirrors Python `download_sealed` and TypeScript `downloadSealed`.
    /// This method returns raw sealed bytes; unsealing is a later layer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when ids are empty or the request fails.
    pub fn download_sealed(&self, project_id: &str, file_name: &str) -> Result<Vec<u8>> {
        let project_id = normalize_required("vault project id", project_id)?;
        let file_name = normalize_required("vault file name", file_name)?;
        let path = file_path(project_id, file_name);
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if response.status().is_success() {
            return Ok(response.bytes()?.to_vec());
        }
        Err(vault_status_error("GET", &path, response))
    }

    /// List authenticated account inbox package metadata.
    ///
    /// Mirrors the vault `GET /api/v1/account/inbox` route used by
    /// Python/TypeScript wallet sync.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the request fails or the vault returns a
    /// malformed list response.
    pub fn list_account_inbox(&self) -> Result<Vec<VaultAccountInboxItem>> {
        let path = "/api/v1/account/inbox";
        let response = self.request(reqwest::Method::GET, path)?.send()?;
        if !response.status().is_success() {
            return Err(vault_status_error("GET", path, response));
        }
        let raw: JsonValue = response.json()?;
        let items = match raw {
            JsonValue::Array(items) => items,
            JsonValue::Object(mut object) => match object.remove("items") {
                Some(JsonValue::Array(items)) => items,
                Some(_) => {
                    return Err(Error::VaultHttp(
                        "GET /api/v1/account/inbox returned non-array items".into(),
                    ));
                }
                None => {
                    return Err(Error::VaultHttp(
                        "GET /api/v1/account/inbox response missing items".into(),
                    ));
                }
            },
            _ => {
                return Err(Error::VaultHttp(
                    "GET /api/v1/account/inbox returned non-array JSON".into(),
                ));
            }
        };
        items.into_iter().map(parse_account_inbox_item).collect()
    }

    /// Download a package from the authenticated account inbox.
    ///
    /// Returns `Ok(None)` for stale `404` / `410` references so callers can
    /// skip them during wallet staging.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when required path pieces are empty or the
    /// vault returns an unexpected error.
    pub fn download_account_inbox_package(
        &self,
        from_did: &str,
        ceremony_id: &str,
        ts: &str,
    ) -> Result<Option<Vec<u8>>> {
        let from_did = normalize_required("account inbox from_did", from_did)?;
        let ceremony_id = normalize_required("account inbox ceremony_id", ceremony_id)?;
        let ts = normalize_required("account inbox ts", ts)?;
        let path = format!(
            "/api/v1/account/inbox/{}/{}/{}.tnpkg",
            encode_path_segment(from_did),
            encode_path_segment(ceremony_id),
            encode_path_segment(ts),
        );
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND
            || response.status() == reqwest::StatusCode::GONE
        {
            return Ok(None);
        }
        if response.status().is_success() {
            return Ok(Some(response.bytes()?.to_vec()));
        }
        Err(vault_status_error("GET", &path, response))
    }

    /// Publish a signed `.tnpkg` snapshot to the vault inbox.
    ///
    /// Mirrors `POST /api/v1/inbox/{from_did}/snapshots/{ceremony_id}/{ts}.tnpkg`.
    /// The authenticated DID must match `from_did`, and the package manifest
    /// must also declare the same publisher.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when path pieces are empty, the vault rejects
    /// the package, or the response is malformed.
    pub fn post_inbox_snapshot(
        &self,
        from_did: &str,
        ceremony_id: &str,
        ts: &str,
        package: impl AsRef<[u8]>,
    ) -> Result<VaultInboxSnapshot> {
        let from_did = normalize_required("inbox snapshot from_did", from_did)?;
        let ceremony_id = normalize_required("inbox snapshot ceremony_id", ceremony_id)?;
        let ts = normalize_required("inbox snapshot ts", ts)?;
        let path = format!(
            "/api/v1/inbox/{}/snapshots/{}/{}.tnpkg",
            encode_path_segment(from_did),
            encode_path_segment(ceremony_id),
            encode_path_segment(ts),
        );
        let response = self
            .request(reqwest::Method::POST, &path)?
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(package.as_ref().to_vec())
            .send()?;
        let raw = parse_json_object_response("POST", &path, response, "inbox snapshot response")?;
        parse_inbox_snapshot_response(raw)
    }

    /// Delete a file from a vault project.
    ///
    /// Mirrors Python `delete_file`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when ids are empty or the request fails.
    pub fn delete_file(&self, project_id: &str, file_name: &str) -> Result<()> {
        let project_id = normalize_required("vault project id", project_id)?;
        let file_name = normalize_required("vault file name", file_name)?;
        let path = file_path(project_id, file_name);
        let response = self.request(reqwest::Method::DELETE, &path)?.send()?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(vault_status_error("DELETE", &path, response))
    }

    /// Fetch an account credential row including AWK wrapping material.
    ///
    /// Mirrors Python `_fetch_credential_with_wrap` and TypeScript
    /// `getCredentialWrap`. When `credential_id` is `None`, Rust fetches the
    /// account credential list, selects the unique primary row when present,
    /// otherwise the sole row, and errors on zero or multiple candidates.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the request fails, the credential list is
    /// malformed, no credential can be selected, or the selected credential
    /// row is missing required wrapping fields.
    pub fn get_credential_wrap(&self, credential_id: Option<&str>) -> Result<VaultCredentialWrap> {
        let raw = if let Some(credential_id) = credential_id {
            let credential_id = normalize_required("vault credential id", credential_id)?;
            let path = format!(
                "/api/v1/account/credentials/{}/wrap",
                encode_path_segment(credential_id)
            );
            let response = self.request(reqwest::Method::GET, &path)?.send()?;
            parse_json_object_response("GET", &path, response, "credential wrap response")?
        } else {
            let path = "/api/v1/account/credentials?include=wrap";
            let response = self.request(reqwest::Method::GET, path)?.send()?;
            if !response.status().is_success() {
                return Err(vault_status_error("GET", path, response));
            }
            select_credential_wrap_row(response.json()?)?
        };
        VaultCredentialWrap::from_json(&raw)
    }

    /// Fetch credential wrapping material and derive the account AWK from a
    /// passphrase.
    ///
    /// This is the network-backed counterpart of [`derive_awk_from_material`]
    /// and matches the Python/TypeScript headless passphrase fallback.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential fetch fails or the passphrase
    /// cannot unwrap the account AWK.
    pub fn derive_awk_from_passphrase(
        &self,
        passphrase: &str,
        credential_id: Option<&str>,
    ) -> Result<VaultAwk> {
        let credential = self.get_credential_wrap(credential_id)?;
        derive_awk_from_material(passphrase, &credential)
    }

    /// Fetch a project's wrapped-key row.
    ///
    /// Mirrors TypeScript `getWrappedKey` and the Python passphrase restore
    /// helper. The JSON object is left flexible because vault deployments may
    /// add fields.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails,
    /// or the vault returns a non-object JSON response.
    pub fn get_wrapped_key(&self, project_id: &str) -> Result<JsonValue> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!(
            "/api/v1/projects/{}/wrapped-key",
            encode_path_segment(project_id)
        );
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        parse_json_object_response("GET", &path, response, "wrapped-key response")
    }

    /// Fetch a project's wrapped-key row, returning `None` when the vault
    /// reports 404.
    ///
    /// This is the helper used by AWK-backed push: a missing row means Rust
    /// should mint a fresh BEK and store its wrapped-key row before uploading
    /// the encrypted body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails
    /// for any status other than 404, or the vault returns non-object JSON.
    pub fn try_get_wrapped_key(&self, project_id: &str) -> Result<Option<JsonValue>> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!(
            "/api/v1/projects/{}/wrapped-key",
            encode_path_segment(project_id)
        );
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        parse_json_object_response("GET", &path, response, "wrapped-key response").map(Some)
    }

    /// Store a project's BEK wrapped under the account AWK.
    ///
    /// Mirrors TypeScript `putWrappedKey`. If `body` omits `cipher_suite`, this
    /// method inserts `aes-256-gcm` to match the TS client.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, `body` is not an
    /// object, the request fails, or the vault returns a non-object JSON
    /// response.
    pub fn put_wrapped_key(&self, project_id: &str, body: JsonValue) -> Result<JsonValue> {
        let project_id = normalize_required("vault project id", project_id)?;
        let mut body = json_object(body, "wrapped-key request body")?;
        body.entry("cipher_suite".to_string())
            .or_insert_with(|| JsonValue::String(VAULT_BODY_CIPHER_SUITE.to_string()));
        let path = format!(
            "/api/v1/projects/{}/wrapped-key",
            encode_path_segment(project_id)
        );
        let response = self
            .request(reqwest::Method::PUT, &path)?
            .json(&JsonValue::Object(body))
            .send()?;
        parse_json_object_response("PUT", &path, response, "wrapped-key response")
    }

    /// Fetch a project's BEK-encrypted body blob descriptor.
    ///
    /// Mirrors TypeScript `getEncryptedBlob`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails,
    /// or the vault returns a non-object JSON response.
    pub fn get_encrypted_blob(&self, project_id: &str) -> Result<JsonValue> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!(
            "/api/v1/projects/{}/encrypted-blob",
            encode_path_segment(project_id)
        );
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        parse_json_object_response("GET", &path, response, "encrypted-blob response")
    }

    /// Return the `If-Match` value to use for the next encrypted body upload.
    ///
    /// A missing encrypted-blob row returns `"*"`. Otherwise Rust uses the
    /// returned `generation` field when present, matching Python/TypeScript
    /// wallet sync behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` is empty, the request fails
    /// for any status other than 404, or the vault returns non-object JSON.
    pub fn encrypted_blob_if_match(&self, project_id: &str) -> Result<String> {
        let project_id = normalize_required("vault project id", project_id)?;
        let path = format!(
            "/api/v1/projects/{}/encrypted-blob",
            encode_path_segment(project_id)
        );
        let response = self.request(reqwest::Method::GET, &path)?.send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok("*".to_string());
        }
        let blob = parse_json_object_response("GET", &path, response, "encrypted-blob response")?;
        let if_match = blob
            .get("generation")
            .and_then(|value| match value {
                JsonValue::Number(number) => Some(number.to_string()),
                JsonValue::String(value) if !value.trim().is_empty() => {
                    Some(value.trim().to_string())
                }
                _ => None,
            })
            .unwrap_or_else(|| "*".to_string());
        Ok(if_match)
    }

    /// Store a BEK-encrypted body blob for an account-owned project.
    ///
    /// Mirrors TypeScript `putEncryptedBlobAccount`. `if_match` becomes the
    /// required `If-Match` header; use `"*"` for first write.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `project_id` or `if_match` is empty,
    /// `body` is not an object, the request fails, or the vault returns a
    /// non-object JSON response.
    pub fn put_encrypted_blob_account(
        &self,
        project_id: &str,
        body: JsonValue,
        if_match: impl AsRef<str>,
    ) -> Result<JsonValue> {
        let project_id = normalize_required("vault project id", project_id)?;
        let if_match = normalize_required("If-Match", if_match.as_ref())?;
        let body = JsonValue::Object(json_object(body, "encrypted-blob request body")?);
        let path = format!(
            "/api/v1/projects/{}/encrypted-blob-account",
            encode_path_segment(project_id)
        );
        let response = self
            .request(reqwest::Method::PUT, &path)?
            .header(reqwest::header::IF_MATCH, if_match)
            .json(&body)
            .send()?;
        parse_json_object_response("PUT", &path, response, "encrypted-blob response")
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        let mut request = self.request_without_auth(method, path)?;
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }

    fn request_without_auth(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        Ok(self
            .http
            .request(method, format!("{}{}", self.base_url, path)))
    }
}

#[cfg(feature = "http")]
impl VaultProjectClient for VaultHttpProjectClient {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn ensure_project(&mut self, name: &str, ceremony_id: Option<&str>) -> Result<VaultProject> {
        match self.create_project(name, ceremony_id) {
            Ok(project) => Ok(project),
            Err(Error::VaultHttp(message)) if message.contains(" returned 409") => {
                let projects = self.list_projects()?;
                projects
                    .into_iter()
                    .find(|project| project.name == name)
                    .ok_or_else(|| {
                        Error::VaultHttp(format!(
                            "vault returned 409 for project {name:?} but list returned no match"
                        ))
                    })
            }
            Err(error) => Err(error),
        }
    }
}

impl<'a> Vault<'a> {
    pub(crate) fn new(tn: &'a Tn) -> Self {
        Self { tn }
    }

    /// Emit a `tn.vault.linked` admin event.
    ///
    /// This records that the local ceremony is paired with `vault_identity`'s
    /// `project_id`. It is idempotent for an already-active link to the same
    /// vault/project, matching tn-core and the Python/TypeScript behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the underlying runtime cannot emit the admin
    /// event.
    pub fn link(
        &self,
        vault_identity: impl AsRef<str>,
        project_id: impl AsRef<str>,
    ) -> Result<VaultLinkResult> {
        let vault_identity = vault_identity.as_ref();
        let project_id = project_id.as_ref();
        self.tn.runtime().vault_link(vault_identity, project_id)?;
        Ok(VaultLinkResult {
            vault_identity: vault_identity.to_string(),
            project_id: project_id.to_string(),
        })
    }

    /// Emit a `tn.vault.unlinked` admin event.
    ///
    /// The optional `reason` is written as `null` when absent, matching
    /// Python/TypeScript canonical event shape.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the underlying runtime cannot emit the admin
    /// event.
    pub fn unlink(
        &self,
        vault_identity: impl AsRef<str>,
        project_id: impl AsRef<str>,
        reason: Option<impl AsRef<str>>,
    ) -> Result<VaultUnlinkResult> {
        let vault_identity = vault_identity.as_ref();
        let project_id = project_id.as_ref();
        let reason = reason.map(|r| r.as_ref().to_string());
        self.tn
            .runtime()
            .vault_unlink(vault_identity, project_id, reason.as_deref())?;
        Ok(VaultUnlinkResult {
            vault_identity: vault_identity.to_string(),
            project_id: project_id.to_string(),
            reason,
        })
    }

    /// Update local YAML link-state for this ceremony.
    ///
    /// This mirrors Python/TypeScript link-state mutation: `Linked` stamps
    /// `ceremony.mode`, `ceremony.linked_vault`, optional
    /// `ceremony.linked_project_id`, and enables the `vault` block; `Local`
    /// clears the linked fields and disables autosync.
    ///
    /// When the active YAML is an overlay with `extends:`, this updates the
    /// nearest parent YAML that owns the `vault` block, matching the shared
    /// SDK convention that vault state belongs to the project ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the YAML cannot be read or written, when
    /// linked mode is requested without a vault value, or when the ceremony is
    /// already linked to a different vault.
    pub fn set_link_state(
        &self,
        state: VaultLinkState,
        options: SetLinkStateOptions,
    ) -> Result<VaultLinkStateResult> {
        let linked_vault = match state {
            VaultLinkState::Linked => {
                let value = options
                    .linked_vault
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        Error::InvalidArgument(
                            "linked mode requires SetLinkStateOptions::linked_vault".into(),
                        )
                    })?;
                Some(value.to_string())
            }
            VaultLinkState::Local => None,
        };
        let linked_project_id = options
            .linked_project_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let yaml_path = authoritative_yaml_for_key(self.tn.yaml_path(), "vault")?;
        let mut doc = read_yaml_mapping(&yaml_path)?;
        mutate_link_state(
            &mut doc,
            state,
            linked_vault.as_deref(),
            linked_project_id.as_deref(),
        )?;
        let rendered = serde_yml::to_string(&YamlValue::Mapping(doc))?;
        tn_core::keystore_backend::atomic_write_bytes(&yaml_path, rendered.as_bytes())?;

        Ok(VaultLinkStateResult {
            state,
            yaml_path,
            linked_vault,
            linked_project_id,
        })
    }

    /// Read local YAML link-state for this ceremony.
    ///
    /// This reads the same authoritative YAML target that
    /// [`Vault::set_link_state`] mutates. For an overlay with `extends:`, the
    /// returned [`VaultLinkStateInfo::yaml_path`] points at the parent YAML
    /// that owns the `vault` block.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the YAML cannot be read or when
    /// `ceremony.mode` is neither `local` nor `linked`.
    pub fn link_state(&self) -> Result<VaultLinkStateInfo> {
        let yaml_path = authoritative_yaml_for_key(self.tn.yaml_path(), "vault")?;
        let doc = read_yaml_mapping(&yaml_path)?;
        read_link_state(&doc, yaml_path)
    }

    /// Collect the local ceremony body for the supported vault push model.
    ///
    /// The body mirrors Python/TypeScript wallet sync: flat keystore files are
    /// added under `body/keys/<name>` and the ceremony YAML is added as
    /// `body/tn.yaml`. Application logs are not included.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the YAML or keystore cannot be read, or
    /// when the keystore contains no files.
    pub fn collect_body(&self) -> Result<VaultBodyPlaintext> {
        collect_vault_body(self.tn.yaml_path())
    }

    /// Upload this local ceremony as an encrypted pending claim and return a
    /// browser claim URL.
    ///
    /// This mirrors Python `tn.handlers.vault_push.init_upload` and
    /// TypeScript `Tn.initUpload`: Rust mints a fresh BEK, exports an
    /// encrypted `full_keystore` `.tnpkg`, posts it unauthenticated to
    /// `/api/v1/pending-claims`, then returns `{vault}/claim/{id}#k=<BEK>`.
    ///
    /// The claim URL is also written to `.tn/sync/claim_url.txt`, a
    /// `pending_claim` record is written to `.tn/sync/state.json`, and a
    /// redacted audit record is written to the admin outbox on a best-effort
    /// basis.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when package export, HTTP upload, or required
    /// response parsing fails. Best-effort local surfacing failures are not
    /// fatal once the vault has accepted the claim.
    #[cfg(feature = "http")]
    pub fn init_upload_http(
        &self,
        client: &VaultHttpProjectClient,
        options: VaultInitUploadOptions,
    ) -> Result<VaultInitUploadResult> {
        let bek = VaultBek::generate();
        let password_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bek.as_bytes());
        let package_bytes = self.export_encrypted_full_keystore_for_claim(&bek, options.groups)?;
        let identity = self.project_identity()?;
        let (vault_id, expires_at) = client.post_pending_claim(
            package_bytes,
            identity.project_name.as_deref(),
            Some(self.tn.did()),
        )?;
        let claim_url = format!(
            "{}/claim/{}#k={}",
            client.base_url.trim_end_matches('/'),
            vault_id,
            password_b64
        );

        let result = VaultInitUploadResult {
            vault_id,
            expires_at,
            claim_url,
            password_b64,
        };
        persist_pending_claim_surfaces(self.tn.yaml_path(), self.tn.did(), &result);
        Ok(result)
    }

    /// Install a decrypted vault body into a caller-supplied directory.
    ///
    /// This is a convenience wrapper around [`install_vault_body`]. It does
    /// not install into the active runtime automatically.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when body validation or filesystem writes fail.
    pub fn install_body(
        &self,
        body: &VaultBodyPlaintext,
        options: VaultInstallBodyOptions,
    ) -> Result<VaultInstallBodyResult> {
        install_vault_body(body, options)
    }

    /// Connect this local ceremony to an already-known vault project.
    ///
    /// This is the local half of the Python/TypeScript wallet-link flow. It
    /// does not create a project on the vault or perform network sync yet;
    /// callers supply the vault URL/identity and project id they received from
    /// a vault client. The method validates relink safety, updates YAML
    /// link-state, and optionally records a local `tn.vault.linked` audit
    /// event.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for empty vault/project values, attempts to
    /// connect a ceremony already linked to a different vault project, YAML
    /// mutation failures, or audit-event emit failures.
    pub fn connect(&self, options: VaultConnectOptions) -> Result<VaultConnectResult> {
        let vault = normalize_required("vault", &options.vault)?;
        let project_id = normalize_required("project_id", &options.project_id)?;
        let project_name = options
            .project_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let before = self.link_state()?;
        if let Some(existing_project_id) = before.linked_project_id.as_deref() {
            let existing_vault = before.linked_vault.as_deref().unwrap_or("");
            if existing_vault == vault && existing_project_id == project_id {
                return Ok(VaultConnectResult {
                    vault: vault.to_string(),
                    project_id: project_id.to_string(),
                    project_name,
                    newly_linked: false,
                    audit_event_recorded: false,
                    state: before,
                });
            }
            if !existing_vault.is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "ceremony is already linked to {existing_vault} project \
                     {existing_project_id}; unlink first"
                )));
            }
        }

        self.set_link_state(
            VaultLinkState::Linked,
            SetLinkStateOptions {
                linked_vault: Some(vault.to_string()),
                linked_project_id: Some(project_id.to_string()),
            },
        )?;
        let mut audit_event_recorded = false;
        if options.record_audit_event {
            self.link(vault, project_id)?;
            audit_event_recorded = true;
        }
        let state = self.link_state()?;

        Ok(VaultConnectResult {
            vault: vault.to_string(),
            project_id: project_id.to_string(),
            project_name,
            newly_linked: true,
            audit_event_recorded,
            state,
        })
    }

    /// Create or discover a vault project through `client`, then connect this
    /// local ceremony to that project.
    ///
    /// This is the first Rust equivalent of the Python/TypeScript wallet-link
    /// orchestration. It does not implement HTTP itself; instead, callers pass
    /// a client that can ensure a project exists. The method handles local
    /// idempotency, project-name fallback, YAML mutation, and optional local
    /// audit emission.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for empty client base URLs, missing project
    /// names, relink attempts to a different active project, vault-client
    /// failures, YAML mutation failures, or audit-event emit failures.
    pub fn connect_with_client<C: VaultProjectClient>(
        &self,
        client: &mut C,
        options: VaultClientConnectOptions,
    ) -> Result<VaultConnectResult> {
        let vault = normalize_required("vault base_url", client.base_url())?.to_string();
        let explicit_project_name = options
            .project_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if let Some(result) =
            self.existing_connection_for_vault(&vault, explicit_project_name.clone())?
        {
            return Ok(result);
        }

        let identity = self.project_identity()?;
        let project_name = options
            .project_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or(identity.project_name)
            .or_else(|| identity.ceremony_id.clone())
            .ok_or_else(|| {
                Error::InvalidArgument(
                    "vault connect requires project_name or ceremony.project_name/id".into(),
                )
            })?;
        let project = client.ensure_project(&project_name, identity.ceremony_id.as_deref())?;
        let project_id = normalize_required("vault project id", &project.id)?;

        self.connect(VaultConnectOptions {
            vault: vault.clone(),
            project_id: project_id.to_string(),
            project_name: Some(project.name),
            record_audit_event: options.record_audit_event,
        })
    }

    /// Push the local ceremony body to a vault through the blocking HTTP
    /// client.
    ///
    /// This is the first higher-level Rust sync primitive. It collects the
    /// local body, encrypts it under `options.bek`, stores the caller-supplied
    /// wrapped-key row, then uploads the encrypted body frame to
    /// `encrypted-blob-account`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the ceremony is not linked and no project
    /// id was supplied, local body collection or encryption fails, or either
    /// vault HTTP request fails.
    #[cfg(feature = "http")]
    pub fn push_body_with_http_client(
        &self,
        client: &VaultHttpProjectClient,
        options: VaultPushBodyOptions,
    ) -> Result<VaultPushBodyResult> {
        let project_id = match options
            .project_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(project_id) => project_id.to_string(),
            None => self.link_state()?.linked_project_id.ok_or_else(|| {
                Error::InvalidArgument(
                    "vault body push requires project_id or linked_project_id".into(),
                )
            })?,
        };
        let if_match = normalize_required("If-Match", &options.if_match)?.to_string();
        let body = self.collect_body()?;
        let body_member_count = body.len();
        let encrypted = encrypt_vault_body(&body, &options.bek)?;
        let encrypted_len = encrypted.len();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted[..12]);
        let mut salt = [0_u8; 16];
        rand_core::OsRng.fill_bytes(&mut salt);

        let wrapped_key_response = if options.store_wrapped_key {
            client.put_wrapped_key(&project_id, options.wrapped_key)?
        } else {
            options.wrapped_key
        };
        let encrypted_blob_response = client.put_encrypted_blob_account(
            &project_id,
            serde_json::json!({
                "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(&encrypted),
                "nonce_b64": nonce_b64,
                "salt_b64": base64::engine::general_purpose::STANDARD.encode(salt),
            }),
            if_match,
        )?;

        Ok(VaultPushBodyResult {
            project_id,
            body_member_count,
            encrypted_len,
            wrapped_key_response,
            encrypted_blob_response,
        })
    }

    /// Push the local ceremony body using an account wrap key.
    ///
    /// This mirrors the Python/TypeScript “mint or reuse BEK” push leg:
    /// fetch the wrapped-key row; if present, unwrap the existing project BEK
    /// with `options.awk`; if missing, mint a fresh BEK, wrap it under the AWK,
    /// and store the wrapped-key row. Then resolve the encrypted-blob
    /// generation and upload the encrypted ceremony body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when project id resolution fails, vault HTTP
    /// calls fail, the wrapped-key row cannot be unwrapped, or body collection
    /// and encryption fail.
    #[cfg(feature = "http")]
    pub fn push_body_with_awk_http_client(
        &self,
        client: &VaultHttpProjectClient,
        options: VaultPushWithAwkOptions,
    ) -> Result<VaultPushWithAwkResult> {
        let project_id = match options
            .project_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(project_id) => project_id.to_string(),
            None => self.link_state()?.linked_project_id.ok_or_else(|| {
                Error::InvalidArgument(
                    "vault AWK body push requires project_id or linked_project_id".into(),
                )
            })?,
        };

        let (bek, wrapped_key, wrapped_key_created) =
            match client.try_get_wrapped_key(&project_id)? {
                Some(row) => {
                    let wrapped = VaultWrappedBek::from_json(&row)?;
                    (unwrap_bek_from_awk(&options.awk, &wrapped)?, row, false)
                }
                None => {
                    let bek = VaultBek::generate();
                    let wrapped = wrap_bek_under_awk(&options.awk, &bek)?.into_json();
                    (bek, wrapped, true)
                }
            };
        let if_match = client.encrypted_blob_if_match(&project_id)?;
        let mut push_options = VaultPushBodyOptions::new(bek, wrapped_key);
        push_options.project_id = Some(project_id);
        push_options.if_match = if_match.clone();
        push_options.store_wrapped_key = wrapped_key_created;
        let push = self.push_body_with_http_client(client, push_options)?;

        Ok(VaultPushWithAwkResult {
            push,
            wrapped_key_created,
            if_match,
        })
    }

    /// Push the local ceremony body using a passphrase-derived account AWK.
    ///
    /// This mirrors the Python/TypeScript headless wallet sync path: fetch a
    /// vault account credential wrap, derive the AWK from `passphrase`, then
    /// run the same mint-or-reuse BEK body push as
    /// [`Vault::push_body_with_awk_http_client`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential fetch or AWK derivation fails,
    /// project id resolution fails, vault HTTP calls fail, or local body
    /// collection/encryption fails.
    #[cfg(feature = "http")]
    pub fn push_body_with_passphrase_http_client(
        &self,
        client: &VaultHttpProjectClient,
        passphrase: &str,
        options: VaultPushWithPassphraseOptions,
    ) -> Result<VaultPushWithAwkResult> {
        let awk =
            client.derive_awk_from_passphrase(passphrase, options.credential_id.as_deref())?;
        self.push_body_with_awk_http_client(
            client,
            VaultPushWithAwkOptions {
                project_id: options.project_id,
                awk,
            },
        )
    }

    /// Push the local ceremony body using a cached account AWK.
    ///
    /// This is the v0 convenience wrapper for unattended body backup: Rust
    /// first reads `awk:{account_id}` from `store`; when no valid cached AWK
    /// exists and `options.passphrase` is supplied, it derives the AWK through
    /// the vault HTTP client, caches it, then runs
    /// [`Vault::push_body_with_awk_http_client`].
    ///
    /// This is intentionally narrower than Python/TypeScript `wallet sync`:
    /// it performs the body push only and does not pull/absorb account inbox
    /// packages or publish group keys.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `account_id` is empty, no cached AWK is
    /// available and no passphrase fallback is supplied, credential fetch or
    /// derivation fails, project id resolution fails, vault HTTP calls fail,
    /// or local body collection/encryption fails.
    #[cfg(feature = "http")]
    pub fn push_body_with_cached_awk_http_client<S: CredentialStore + ?Sized>(
        &self,
        client: &VaultHttpProjectClient,
        store: &S,
        options: VaultPushWithCachedAwkOptions,
    ) -> Result<VaultPushWithAwkResult> {
        let awk = cached_or_derived_awk(
            store,
            client,
            &options.account_id,
            options.passphrase.as_deref(),
            options.credential_id.as_deref(),
        )?;
        self.push_body_with_awk_http_client(
            client,
            VaultPushWithAwkOptions {
                project_id: options.project_id,
                awk,
            },
        )
    }

    /// Restore a vault body using an account wrap key.
    ///
    /// This is the read-only mirror of
    /// [`Vault::push_body_with_awk_http_client`]: fetch the wrapped-key row,
    /// unwrap the project BEK with `options.awk`, fetch the encrypted body
    /// frame, and decrypt it into body members. It does not write files.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when project id resolution fails, either vault
    /// response is missing or malformed, the BEK cannot be unwrapped, or the
    /// encrypted body cannot be decrypted.
    #[cfg(feature = "http")]
    pub fn restore_body_with_awk_http_client(
        &self,
        client: &VaultHttpProjectClient,
        options: VaultRestoreWithAwkOptions,
    ) -> Result<VaultRestoreWithAwkResult> {
        let project_id = match options
            .project_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(project_id) => project_id.to_string(),
            None => self.link_state()?.linked_project_id.ok_or_else(|| {
                Error::InvalidArgument(
                    "vault AWK body restore requires project_id or linked_project_id".into(),
                )
            })?,
        };

        let wrapped_key_json = client.get_wrapped_key(&project_id)?;
        let wrapped_key = VaultWrappedBek::from_json(&wrapped_key_json)?;
        let bek = unwrap_bek_from_awk(&options.awk, &wrapped_key)?;
        let encrypted_blob_response = client.get_encrypted_blob(&project_id)?;
        let encrypted = encrypted_blob_bytes(&encrypted_blob_response)?;
        let body = decrypt_vault_body(&encrypted, &bek)?;

        Ok(VaultRestoreWithAwkResult {
            project_id,
            body,
            wrapped_key,
            encrypted_blob_response,
        })
    }

    /// Restore a vault body using a passphrase-derived account AWK.
    ///
    /// This is the passphrase-backed counterpart of
    /// [`Vault::restore_body_with_awk_http_client`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential fetch or AWK derivation fails,
    /// project id resolution fails, either vault response is missing or
    /// malformed, the BEK cannot be unwrapped, or the encrypted body cannot be
    /// decrypted.
    #[cfg(feature = "http")]
    pub fn restore_body_with_passphrase_http_client(
        &self,
        client: &VaultHttpProjectClient,
        passphrase: &str,
        options: VaultRestoreWithPassphraseOptions,
    ) -> Result<VaultRestoreWithAwkResult> {
        let awk =
            client.derive_awk_from_passphrase(passphrase, options.credential_id.as_deref())?;
        self.restore_body_with_awk_http_client(
            client,
            VaultRestoreWithAwkOptions {
                project_id: options.project_id,
                awk,
            },
        )
    }

    /// Restore a vault body using a cached account AWK.
    ///
    /// Rust first reads `awk:{account_id}` from `store`; when no valid cached
    /// AWK exists and `options.passphrase` is supplied, it derives the AWK
    /// through the vault HTTP client, caches it, then runs
    /// [`Vault::restore_body_with_awk_http_client`]. This method returns the
    /// decrypted body and does not write files.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `account_id` is empty, no cached AWK is
    /// available and no passphrase fallback is supplied, credential fetch or
    /// derivation fails, project id resolution fails, either vault response is
    /// missing or malformed, the BEK cannot be unwrapped, or the encrypted
    /// body cannot be decrypted.
    #[cfg(feature = "http")]
    pub fn restore_body_with_cached_awk_http_client<S: CredentialStore + ?Sized>(
        &self,
        client: &VaultHttpProjectClient,
        store: &S,
        options: VaultRestoreWithCachedAwkOptions,
    ) -> Result<VaultRestoreWithAwkResult> {
        let awk = cached_or_derived_awk(
            store,
            client,
            &options.account_id,
            options.passphrase.as_deref(),
            options.credential_id.as_deref(),
        )?;
        self.restore_body_with_awk_http_client(
            client,
            VaultRestoreWithAwkOptions {
                project_id: options.project_id,
                awk,
            },
        )
    }

    /// Restore a vault body with an AWK and install it into a target
    /// directory.
    ///
    /// This composes [`Vault::restore_body_with_awk_http_client`] with
    /// [`Vault::install_body`]. The install target is explicit and this method
    /// does not overwrite different existing files unless
    /// [`VaultInstallBodyOptions::overwrite`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when restore, body validation, or filesystem
    /// installation fails.
    #[cfg(feature = "http")]
    pub fn restore_and_install_body_with_awk_http_client(
        &self,
        client: &VaultHttpProjectClient,
        restore_options: VaultRestoreWithAwkOptions,
        install_options: VaultInstallBodyOptions,
    ) -> Result<VaultRestoreAndInstallWithAwkResult> {
        let restore = self.restore_body_with_awk_http_client(client, restore_options)?;
        let install = self.install_body(&restore.body, install_options)?;
        Ok(VaultRestoreAndInstallWithAwkResult { restore, install })
    }

    /// Restore a vault body with a passphrase-derived account AWK and install
    /// it into a target directory.
    ///
    /// This composes [`Vault::restore_body_with_passphrase_http_client`] with
    /// [`Vault::install_body`]. The install target is explicit and this method
    /// does not overwrite different existing files unless
    /// [`VaultInstallBodyOptions::overwrite`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential fetch, restore, body
    /// validation, or filesystem installation fails.
    #[cfg(feature = "http")]
    pub fn restore_and_install_body_with_passphrase_http_client(
        &self,
        client: &VaultHttpProjectClient,
        passphrase: &str,
        restore_options: VaultRestoreWithPassphraseOptions,
        install_options: VaultInstallBodyOptions,
    ) -> Result<VaultRestoreAndInstallWithAwkResult> {
        let restore =
            self.restore_body_with_passphrase_http_client(client, passphrase, restore_options)?;
        let install = self.install_body(&restore.body, install_options)?;
        Ok(VaultRestoreAndInstallWithAwkResult { restore, install })
    }

    /// Restore a vault body with a cached account AWK and install it into a
    /// target directory.
    ///
    /// This composes [`Vault::restore_body_with_cached_awk_http_client`] with
    /// [`Vault::install_body`]. The install target is explicit and this method
    /// does not overwrite different existing files unless
    /// [`VaultInstallBodyOptions::overwrite`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential resolution, restore, body
    /// validation, or filesystem installation fails.
    #[cfg(feature = "http")]
    pub fn restore_and_install_body_with_cached_awk_http_client<S: CredentialStore + ?Sized>(
        &self,
        client: &VaultHttpProjectClient,
        store: &S,
        restore_options: VaultRestoreWithCachedAwkOptions,
        install_options: VaultInstallBodyOptions,
    ) -> Result<VaultRestoreAndInstallWithAwkResult> {
        let restore =
            self.restore_body_with_cached_awk_http_client(client, store, restore_options)?;
        let install = self.install_body(&restore.body, install_options)?;
        Ok(VaultRestoreAndInstallWithAwkResult { restore, install })
    }

    /// Authenticate with a vault over HTTP, create or discover the vault
    /// project, then connect the local ceremony to it.
    ///
    /// This is the highest-level blocking Rust vault connection helper. It
    /// composes the DID challenge/verify auth flow, project create-or-reuse,
    /// local YAML mutation, and optional local audit event emission. If the
    /// local ceremony is already linked to the same vault, it returns the
    /// existing local result without authenticating or touching the network.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for invalid options, auth failure, project
    /// create/discovery failure, relink attempts to a different active project,
    /// YAML mutation failures, or audit-event emit failures.
    #[cfg(feature = "http")]
    pub fn connect_http<I: VaultIdentity>(
        &self,
        identity: &I,
        options: VaultHttpConnectOptions,
    ) -> Result<VaultConnectResult> {
        let mut client = VaultHttpProjectClient::with_options(options.client)?;
        let vault = normalize_required("vault base_url", client.base_url())?.to_string();
        let project_name = options
            .project_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if let Some(result) = self.existing_connection_for_vault(&vault, project_name.clone())? {
            return Ok(result);
        }

        client.ensure_authenticated(identity)?;
        self.connect_with_client(
            &mut client,
            VaultClientConnectOptions {
                project_name,
                record_audit_event: options.record_audit_event,
            },
        )
    }

    fn existing_connection_for_vault(
        &self,
        vault: &str,
        project_name: Option<String>,
    ) -> Result<Option<VaultConnectResult>> {
        let before = self.link_state()?;
        if let Some(existing_project_id) = before.linked_project_id.as_deref() {
            let existing_vault = before.linked_vault.as_deref().unwrap_or("");
            if existing_vault == vault {
                return Ok(Some(VaultConnectResult {
                    vault: vault.to_string(),
                    project_id: existing_project_id.to_string(),
                    project_name,
                    newly_linked: false,
                    audit_event_recorded: false,
                    state: before,
                }));
            }
            if !existing_vault.is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "ceremony is already linked to {existing_vault} project \
                     {existing_project_id}; unlink first"
                )));
            }
        }
        Ok(None)
    }

    fn project_identity(&self) -> Result<VaultProjectIdentity> {
        let yaml_path = authoritative_yaml_for_key(self.tn.yaml_path(), "vault")?;
        let doc = read_yaml_mapping(&yaml_path)?;
        let ceremony = mapping_get_mapping(&doc, "ceremony");
        Ok(VaultProjectIdentity {
            project_name: ceremony
                .and_then(|ceremony| mapping_get_non_empty_str(ceremony, "project_name"))
                .map(ToOwned::to_owned),
            ceremony_id: ceremony
                .and_then(|ceremony| mapping_get_non_empty_str(ceremony, "id"))
                .map(ToOwned::to_owned),
        })
    }

    #[cfg(feature = "http")]
    fn export_encrypted_full_keystore_for_claim(
        &self,
        bek: &VaultBek,
        groups: Option<Vec<String>>,
    ) -> Result<Vec<u8>> {
        let tmp_path = init_upload_temp_path();
        let export_result = self.tn.runtime().export(
            &tmp_path,
            tn_core::ExportOptions {
                kind: Some(tn_core::ManifestKind::FullKeystore),
                confirm_includes_secrets: true,
                groups,
                encrypt_body_with: Some(*bek.as_bytes()),
                ..Default::default()
            },
        );
        let bytes_result = match export_result {
            Ok(_) => fs::read(&tmp_path).map_err(Error::from),
            Err(error) => Err(Error::from(error)),
        };
        let _ = fs::remove_file(&tmp_path);
        bytes_result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VaultProjectIdentity {
    project_name: Option<String>,
    ceremony_id: Option<String>,
}

fn normalize_required<'a>(name: &str, value: &'a str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidArgument(format!("{name} must not be empty")));
    }
    Ok(value)
}

#[cfg(feature = "http")]
fn init_upload_temp_path() -> PathBuf {
    let mut random = [0_u8; 8];
    rand_core::OsRng.fill_bytes(&mut random);
    let stamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    std::env::temp_dir().join(format!(
        "tn-init-upload-{stamp}-{}.tnpkg",
        hex_lower(&random)
    ))
}

#[cfg(feature = "http")]
fn persist_pending_claim_surfaces(yaml_path: &Path, did: &str, result: &VaultInitUploadResult) {
    persist_pending_claim_state(yaml_path, result);
    persist_claim_url_file(yaml_path, &result.claim_url);
    persist_claim_url_admin_event(yaml_path, did, result);
}

#[cfg(feature = "http")]
fn persist_pending_claim_state(yaml_path: &Path, result: &VaultInitUploadResult) {
    let state_path = sync_state_path(yaml_path);
    let mut state = fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| match value {
            serde_json::Value::Object(object) => Some(object),
            _ => None,
        })
        .unwrap_or_default();
    state.insert(
        "pending_claim".into(),
        serde_json::json!({
            "vault_id": result.vault_id,
            "expires_at": result.expires_at,
            "claim_url": result.claim_url,
            "password_b64": result.password_b64,
        }),
    );
    if let Ok(bytes) = serde_json::to_vec_pretty(&serde_json::Value::Object(state)) {
        if let Some(parent) = state_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = tn_core::keystore_backend::atomic_write_bytes(&state_path, &bytes);
    }
}

#[cfg(feature = "http")]
fn persist_claim_url_file(yaml_path: &Path, claim_url: &str) {
    let path = sync_state_path(yaml_path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("claim_url.txt");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ =
        tn_core::keystore_backend::atomic_write_bytes(&path, format!("{claim_url}\n").as_bytes());
}

#[cfg(feature = "http")]
fn persist_claim_url_admin_event(yaml_path: &Path, did: &str, result: &VaultInitUploadResult) {
    let outbox = admin_outbox_dir(yaml_path);
    if fs::create_dir_all(&outbox).is_err() {
        return;
    }
    let ts = compact_utc_timestamp();
    let path = outbox.join(format!("claim_url_issued_{}_{}.json", ts, result.vault_id));
    let emitted_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let mut envelope = std::collections::BTreeMap::new();
    envelope.insert("claim_url_redacted", redact_claim_url(&result.claim_url));
    envelope.insert("did", did.to_string());
    envelope.insert("emitted_at", emitted_at);
    envelope.insert("event_type", "tn.vault.claim_url_issued".to_string());
    envelope.insert("expires_at", result.expires_at.clone());
    envelope.insert("vault_id", result.vault_id.clone());
    if let Ok(bytes) = serde_json::to_vec_pretty(&envelope) {
        let _ = tn_core::keystore_backend::atomic_write_bytes(&path, &bytes);
    }
}

#[cfg(feature = "http")]
fn sync_state_path(yaml_path: &Path) -> PathBuf {
    yaml_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(".tn")
        .join("sync")
        .join("state.json")
}

#[cfg(feature = "http")]
fn admin_outbox_dir(yaml_path: &Path) -> PathBuf {
    let parent = yaml_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = yaml_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("tn");
    parent.join(".tn").join(stem).join("admin").join("outbox")
}

#[cfg(feature = "http")]
fn redact_claim_url(claim_url: &str) -> String {
    claim_url.split_once('#').map_or_else(
        || claim_url.to_string(),
        |(base, _)| format!("{base}#k=<redacted>"),
    )
}

#[cfg(feature = "http")]
fn compact_utc_timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}{:03}000Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}

#[cfg(feature = "http")]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn json_value_field_str<'a>(
    raw: &'a serde_json::Value,
    field: &str,
    context: &str,
) -> Result<&'a str> {
    raw.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidArgument(format!("{context} missing {field}")))
}

#[cfg(feature = "http")]
fn encrypted_blob_bytes(raw: &JsonValue) -> Result<Vec<u8>> {
    let b64 = raw
        .get("ciphertext_b64")
        .or_else(|| raw.get("ciphertext"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::VaultHttp("encrypted-blob response missing ciphertext".into()))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|err| Error::VaultHttp(format!("invalid encrypted-blob ciphertext: {err}")))
}

#[cfg(feature = "http")]
fn cached_or_derived_awk<S: CredentialStore + ?Sized>(
    store: &S,
    client: &VaultHttpProjectClient,
    account_id: &str,
    passphrase: Option<&str>,
    credential_id: Option<&str>,
) -> Result<VaultAwk> {
    let account_id = normalize_required("vault account id", account_id)?;
    if let Some(awk) = load_cached_account_awk(store, account_id) {
        return Ok(awk);
    }
    let Some(passphrase) = passphrase else {
        return Err(Error::InvalidArgument(
            "cached AWK not found; provide passphrase or cache account AWK first".into(),
        ));
    };
    cache_account_awk_with_client(store, client, account_id, passphrase, credential_id)
}

fn install_vault_body_impl(
    body: &VaultBodyPlaintext,
    options: VaultInstallBodyOptions,
) -> Result<VaultInstallBodyResult> {
    let yaml_bytes = required_body_member(body, "body/tn.yaml")?;
    let private_bytes = required_body_member(body, "body/keys/local.private")?;
    let public_bytes = required_body_member(body, "body/keys/local.public")?;
    validate_vault_body_identity(private_bytes, public_bytes)?;

    let target_dir = options.target_dir;
    if target_dir.as_os_str().is_empty() {
        return Err(Error::InvalidArgument(
            "vault body install target_dir must not be empty".into(),
        ));
    }
    if target_dir.is_file() {
        return Err(Error::InvalidArgument(format!(
            "vault body install target {} is a file",
            target_dir.display()
        )));
    }
    fs::create_dir_all(&target_dir)?;
    let keys_dir = target_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let mut written_paths = Vec::new();
    let mut deduped_paths = Vec::new();
    let mut skipped_members = Vec::new();
    let yaml_path = target_dir.join("tn.yaml");
    write_restore_member(
        &yaml_path,
        yaml_bytes,
        options.overwrite,
        &mut written_paths,
        &mut deduped_paths,
    )?;

    let mut key_members: Vec<_> = body
        .iter()
        .filter_map(|(name, data)| name.strip_prefix("body/keys/").map(|rel| (name, rel, data)))
        .collect();
    key_members.sort_by(|a, b| a.1.cmp(b.1));
    for (name, rel, data) in key_members {
        validate_flat_key_member(rel)?;
        let dest = keys_dir.join(rel);
        write_restore_member(
            &dest,
            data,
            options.overwrite,
            &mut written_paths,
            &mut deduped_paths,
        )
        .map_err(|err| {
            Error::InvalidArgument(format!(
                "cannot install vault body member {name:?} to {}: {err}",
                dest.display()
            ))
        })?;
    }

    for name in body.keys() {
        if name != "body/tn.yaml" && !name.starts_with("body/keys/") {
            skipped_members.push(name.clone());
        }
    }
    skipped_members.sort();

    Ok(VaultInstallBodyResult {
        target_dir,
        yaml_path,
        keys_dir,
        written_paths,
        deduped_paths,
        skipped_members,
    })
}

fn required_body_member<'a>(body: &'a VaultBodyPlaintext, name: &str) -> Result<&'a [u8]> {
    body.get(name).map(Vec::as_slice).ok_or_else(|| {
        Error::InvalidArgument(format!("vault body is missing required member {name:?}"))
    })
}

fn validate_vault_body_identity(private_bytes: &[u8], public_bytes: &[u8]) -> Result<()> {
    if private_bytes.len() != 32 {
        return Err(Error::InvalidArgument(format!(
            "body/keys/local.private must be 32 bytes; got {}",
            private_bytes.len()
        )));
    }
    let public = std::str::from_utf8(public_bytes)
        .map_err(|err| {
            Error::InvalidArgument(format!("body/keys/local.public is not utf-8: {err}"))
        })?
        .trim();
    let device = DeviceKey::from_private_bytes(private_bytes)?;
    if device.did() != public {
        return Err(Error::InvalidArgument(format!(
            "vault body identity mismatch: body/keys/local.public={public:?}, \
             derived-from-private={:?}",
            device.did()
        )));
    }
    Ok(())
}

fn validate_flat_key_member(rel: &str) -> Result<()> {
    if rel.is_empty()
        || rel == "."
        || rel == ".."
        || rel.contains('/')
        || rel.contains('\\')
        || rel.contains(':')
    {
        return Err(Error::InvalidArgument(format!(
            "invalid vault body key member {rel:?}; expected flat body/keys/<name>"
        )));
    }
    Ok(())
}

fn write_restore_member(
    dest: &Path,
    data: &[u8],
    overwrite: bool,
    written_paths: &mut Vec<PathBuf>,
    deduped_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    if dest.exists() {
        let existing = fs::read(dest)?;
        if existing == data {
            deduped_paths.push(dest.to_path_buf());
            return Ok(());
        }
        if !overwrite {
            return Err(Error::InvalidArgument(format!(
                "{} already exists with different contents",
                dest.display()
            )));
        }
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    tn_core::keystore_backend::atomic_write_bytes(dest, data)?;
    written_paths.push(dest.to_path_buf());
    Ok(())
}

fn collect_vault_body(active_yaml_path: &Path) -> Result<VaultBodyPlaintext> {
    let yaml_path = authoritative_yaml_for_key(active_yaml_path, "keystore")?;
    let doc = read_yaml_mapping(&yaml_path)?;
    let keystore = mapping_get_mapping(&doc, "keystore")
        .and_then(|keystore| mapping_get_non_empty_str(keystore, "path"))
        .ok_or_else(|| Error::InvalidArgument("tn.yaml is missing keystore.path".into()))?;
    let keys_dir = resolve_yaml_relative_path(&yaml_path, keystore);
    let mut body = VaultBodyPlaintext::new();

    for entry in fs::read_dir(&keys_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Error::InvalidArgument(format!(
                "invalid keystore file name {name:?}"
            )));
        }
        body.insert(format!("body/keys/{name}"), fs::read(entry.path())?);
    }

    if body.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "keystore {} contains no files to push",
            keys_dir.display()
        )));
    }

    body.insert("body/tn.yaml".to_string(), fs::read(&yaml_path)?);
    Ok(body)
}

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

#[cfg(feature = "http")]
fn parse_project_response(
    response: reqwest::blocking::Response,
    fallback_name: Option<&str>,
) -> Result<VaultProject> {
    let raw: JsonValue = response.json()?;
    parse_project_json(raw, fallback_name)
}

#[cfg(feature = "http")]
fn parse_project_json(raw: JsonValue, fallback_name: Option<&str>) -> Result<VaultProject> {
    let JsonValue::Object(object) = raw else {
        return Err(Error::VaultHttp(
            "vault project response must be a JSON object".into(),
        ));
    };
    let id = object
        .get("id")
        .or_else(|| object.get("_id"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::VaultHttp("vault project response missing id".into()))?
        .to_string();
    let name = object
        .get("name")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(fallback_name)
        .unwrap_or(&id)
        .to_string();
    let ceremony_id = object
        .get("ceremony_id")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(VaultProject {
        id,
        name,
        ceremony_id,
    })
}

#[cfg(feature = "http")]
fn parse_file_json(raw: JsonValue) -> Result<VaultFile> {
    let JsonValue::Object(object) = raw else {
        return Err(Error::VaultHttp(
            "vault file response must be a JSON object".into(),
        ));
    };
    let name = object
        .get("name")
        .or_else(|| object.get("file_name"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::VaultHttp("vault file response missing name".into()))?
        .to_string();
    let size = object.get("size").and_then(JsonValue::as_u64);
    let sha256 = object
        .get("sha256")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let uploaded_at = object
        .get("uploaded_at")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(VaultFile {
        name,
        size,
        sha256,
        uploaded_at,
    })
}

#[cfg(feature = "http")]
fn parse_account_inbox_item(raw: JsonValue) -> Result<VaultAccountInboxItem> {
    let object = json_object(raw, "account inbox item")?;
    let raw = JsonValue::Object(object);
    let publisher_identity = raw
        .get("publisher_identity")
        .or_else(|| raw.get("from_did"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::VaultHttp("account inbox item missing publisher_identity".into()))?
        .to_string();
    let ceremony_id = json_field_str(&raw, "ceremony_id", "account inbox item")?.to_string();
    let ts = json_field_str(&raw, "ts", "account inbox item")?.to_string();
    let consumed_at = raw
        .get("consumed_at")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(VaultAccountInboxItem {
        publisher_identity,
        ceremony_id,
        ts,
        consumed_at,
    })
}

#[cfg(feature = "http")]
fn parse_inbox_snapshot_response(raw: JsonValue) -> Result<VaultInboxSnapshot> {
    let stored_path = json_field_str(&raw, "stored_path", "inbox snapshot response")?.to_string();
    let byte_size = raw
        .get("byte_size")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| Error::VaultHttp("inbox snapshot response missing byte_size".into()))?;
    let manifest_signature_b64 =
        json_field_str(&raw, "manifest_signature_b64", "inbox snapshot response")?.to_string();
    let head_row_hash = raw
        .get("head_row_hash")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(VaultInboxSnapshot {
        stored_path,
        byte_size,
        manifest_signature_b64,
        head_row_hash,
    })
}

#[cfg(feature = "http")]
fn json_object(value: JsonValue, context: &str) -> Result<serde_json::Map<String, JsonValue>> {
    match value {
        JsonValue::Object(object) => Ok(object),
        _ => Err(Error::VaultHttp(format!("{context} must be a JSON object"))),
    }
}

#[cfg(feature = "http")]
fn select_credential_wrap_row(raw: JsonValue) -> Result<JsonValue> {
    let JsonValue::Array(rows) = raw else {
        return Err(Error::VaultHttp("credentials list: expected array".into()));
    };
    let candidates: Vec<JsonValue> = {
        let primary: Vec<JsonValue> = rows
            .iter()
            .filter(|row| row.get("is_primary").and_then(JsonValue::as_bool) == Some(true))
            .cloned()
            .collect();
        if primary.is_empty() {
            rows
        } else {
            primary
        }
    };
    match candidates.len() {
        0 => Err(Error::VaultHttp(
            "no credentials registered for this account; register one via the browser flow first"
                .into(),
        )),
        1 => {
            let row = candidates.into_iter().next().expect("len checked");
            if row.is_object() {
                Ok(row)
            } else {
                Err(Error::VaultHttp(
                    "credential row must be a JSON object".into(),
                ))
            }
        }
        count => Err(Error::VaultHttp(format!(
            "{count} primary credentials found; pass credential_id to choose one"
        ))),
    }
}

#[cfg(feature = "http")]
fn parse_json_object_response(
    method: &str,
    path: &str,
    response: reqwest::blocking::Response,
    context: &str,
) -> Result<JsonValue> {
    if !response.status().is_success() {
        return Err(vault_status_error(method, path, response));
    }
    let raw: JsonValue = response.json()?;
    if raw.is_object() {
        Ok(raw)
    } else {
        Err(Error::VaultHttp(format!("{context} must be a JSON object")))
    }
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
fn normalize_optional_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(feature = "http")]
fn file_path(project_id: &str, file_name: &str) -> String {
    format!(
        "/api/v1/projects/{}/files/{}",
        encode_path_segment(project_id),
        encode_path_segment(file_name)
    )
}

#[cfg(feature = "http")]
fn encode_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                write!(&mut out, "%{byte:02X}").expect("writing to String cannot fail");
            }
        }
    }
    out
}

#[cfg(feature = "http")]
fn vault_status_error(method: &str, path: &str, response: reqwest::blocking::Response) -> Error {
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

fn read_link_state(doc: &YamlMapping, yaml_path: PathBuf) -> Result<VaultLinkStateInfo> {
    let ceremony = mapping_get_mapping(doc, "ceremony");
    let vault = mapping_get_mapping(doc, "vault");

    let mode = ceremony
        .and_then(|ceremony| mapping_get_str(ceremony, "mode"))
        .unwrap_or("local");
    let state = match mode {
        "local" => VaultLinkState::Local,
        "linked" => VaultLinkState::Linked,
        other => {
            return Err(Error::InvalidArgument(format!(
                "ceremony.mode must be local or linked, got {other:?}"
            )));
        }
    };

    let linked_vault = vault
        .and_then(|vault| mapping_get_non_empty_str(vault, "url"))
        .or_else(|| {
            ceremony.and_then(|ceremony| mapping_get_non_empty_str(ceremony, "linked_vault"))
        })
        .map(ToOwned::to_owned);
    let linked_project_id = vault
        .and_then(|vault| mapping_get_non_empty_str(vault, "linked_project_id"))
        .or_else(|| {
            ceremony.and_then(|ceremony| mapping_get_non_empty_str(ceremony, "linked_project_id"))
        })
        .map(ToOwned::to_owned);
    let vault_enabled = vault
        .and_then(|vault| mapping_get_bool(vault, "enabled"))
        .unwrap_or(false);
    let autosync = if vault_enabled {
        vault
            .and_then(|vault| mapping_get_bool(vault, "autosync"))
            .unwrap_or(vault_enabled)
    } else {
        false
    };
    let sync_interval_seconds =
        vault.and_then(|vault| mapping_get_i64(vault, "sync_interval_seconds"));

    Ok(VaultLinkStateInfo {
        state,
        yaml_path,
        linked_vault,
        linked_project_id,
        vault_enabled,
        autosync,
        sync_interval_seconds,
    })
}

fn mutate_link_state(
    doc: &mut YamlMapping,
    state: VaultLinkState,
    linked_vault: Option<&str>,
    linked_project_id: Option<&str>,
) -> Result<()> {
    let current_mode = mapping_get_mapping(doc, "ceremony")
        .and_then(|ceremony| mapping_get_str(ceremony, "mode"))
        .unwrap_or("local");
    let current_vault = mapping_get_mapping(doc, "vault")
        .and_then(|vault| mapping_get_str(vault, "url"))
        .filter(|value| !value.is_empty())
        .or_else(|| {
            mapping_get_mapping(doc, "ceremony")
                .and_then(|ceremony| mapping_get_str(ceremony, "linked_vault"))
                .filter(|value| !value.is_empty())
        });

    if let (VaultLinkState::Linked, Some(next_vault)) = (state, linked_vault) {
        if current_mode == "linked" && current_vault.is_some_and(|value| value != next_vault) {
            return Err(Error::InvalidArgument(
                "ceremony is already linked to a different vault; unlink first".into(),
            ));
        }
    }

    match state {
        VaultLinkState::Linked => {
            let linked_vault = linked_vault.expect("validated by Vault::set_link_state");
            {
                let ceremony = ensure_mapping(doc, "ceremony")?;
                mapping_set_str(ceremony, "mode", state.as_str());
                mapping_set_str(ceremony, "linked_vault", linked_vault);
                if let Some(project_id) = linked_project_id {
                    mapping_set_str(ceremony, "linked_project_id", project_id);
                }
            }

            let vault = ensure_mapping(doc, "vault")?;
            mapping_set_bool(vault, "enabled", true);
            mapping_set_str(vault, "url", linked_vault);
            if let Some(project_id) = linked_project_id {
                let current_project_id = mapping_get_str(vault, "linked_project_id").unwrap_or("");
                if current_project_id.is_empty() {
                    mapping_set_str(vault, "linked_project_id", project_id);
                }
            }
            let autosync = mapping_get_bool(vault, "autosync").unwrap_or(true);
            mapping_set_bool(vault, "autosync", autosync);
            mapping_set_default_i64(vault, "sync_interval_seconds", 600);
        }
        VaultLinkState::Local => {
            let ceremony = ensure_mapping(doc, "ceremony")?;
            mapping_set_str(ceremony, "mode", state.as_str());
            mapping_remove(ceremony, "linked_vault");
            mapping_remove(ceremony, "linked_project_id");

            let vault = ensure_mapping(doc, "vault")?;
            mapping_set_bool(vault, "enabled", false);
            mapping_set_str(vault, "url", "");
            mapping_set_str(vault, "linked_project_id", "");
            mapping_set_bool(vault, "autosync", false);
            mapping_set_default_i64(vault, "sync_interval_seconds", 600);
        }
    }

    Ok(())
}

fn authoritative_yaml_for_key(active_path: &Path, key: &str) -> Result<PathBuf> {
    let mut path = active_path.to_path_buf();

    for _ in 0..32 {
        let doc = read_yaml_mapping(&path)?;
        if doc.contains_key(&YamlValue::String(key.to_string())) {
            return normalize_existing_path(&path);
        }

        let Some(extends) = mapping_get_str(&doc, "extends") else {
            return normalize_existing_path(&path);
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("")).join(extends);
        path = parent;
    }

    Err(Error::InvalidArgument(
        "extends chain exceeds maximum depth while locating vault YAML".into(),
    ))
}

fn normalize_existing_path(path: &Path) -> Result<PathBuf> {
    Ok(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
}

fn read_yaml_mapping(path: &Path) -> Result<YamlMapping> {
    let raw = std::fs::read_to_string(path)?;
    match serde_yml::from_str::<YamlValue>(&raw)? {
        YamlValue::Mapping(mapping) => Ok(mapping),
        _ => Err(Error::InvalidArgument(format!(
            "{} must contain a YAML mapping",
            path.display()
        ))),
    }
}

fn ensure_mapping<'a>(doc: &'a mut YamlMapping, key: &str) -> Result<&'a mut YamlMapping> {
    let key_value = YamlValue::String(key.to_string());
    if !doc.contains_key(&key_value) {
        doc.insert(key_value.clone(), YamlValue::Mapping(YamlMapping::new()));
    }

    match doc.get_mut(&key_value) {
        Some(YamlValue::Mapping(mapping)) => Ok(mapping),
        _ => Err(Error::InvalidArgument(format!(
            "{key} must be a YAML mapping"
        ))),
    }
}

fn mapping_get_mapping<'a>(doc: &'a YamlMapping, key: &str) -> Option<&'a YamlMapping> {
    doc.get(YamlValue::String(key.to_string()))?.as_mapping()
}

fn mapping_get_str<'a>(doc: &'a YamlMapping, key: &str) -> Option<&'a str> {
    doc.get(YamlValue::String(key.to_string()))?.as_str()
}

fn mapping_get_non_empty_str<'a>(doc: &'a YamlMapping, key: &str) -> Option<&'a str> {
    mapping_get_str(doc, key).filter(|value| !value.is_empty())
}

fn mapping_get_bool(doc: &YamlMapping, key: &str) -> Option<bool> {
    doc.get(YamlValue::String(key.to_string()))?.as_bool()
}

fn mapping_get_i64(doc: &YamlMapping, key: &str) -> Option<i64> {
    doc.get(YamlValue::String(key.to_string()))?.as_i64()
}

fn mapping_set_str(doc: &mut YamlMapping, key: &str, value: &str) {
    doc.insert(
        YamlValue::String(key.to_string()),
        YamlValue::String(value.to_string()),
    );
}

fn mapping_set_bool(doc: &mut YamlMapping, key: &str, value: bool) {
    doc.insert(YamlValue::String(key.to_string()), YamlValue::Bool(value));
}

fn mapping_set_default_i64(doc: &mut YamlMapping, key: &str, value: i64) {
    let key_value = YamlValue::String(key.to_string());
    doc.entry(key_value)
        .or_insert_with(|| YamlValue::Number(value.into()));
}

fn mapping_remove(doc: &mut YamlMapping, key: &str) {
    doc.remove(YamlValue::String(key.to_string()));
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|err| Error::InvalidArgument(format!("invalid HMAC key: {err}")))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

fn aes_gcm_unwrap_raw(
    key: &[u8; 32],
    wrapped_b64: &str,
    nonce_b64: &str,
    aad: &[u8],
    what: &str,
) -> Result<Vec<u8>> {
    let nonce = decode_base64_loose(nonce_b64, "wrap_nonce_b64")?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|nonce: Vec<u8>| {
        Error::InvalidArgument(format!(
            "wrap_nonce_b64 decoded to {} bytes; expected 12",
            nonce.len()
        ))
    })?;
    let ciphertext = decode_base64_loose(wrapped_b64, "wrapped ciphertext")?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| Error::InvalidArgument(format!("invalid unwrap key: {err}")))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::InvalidArgument(format!("unwrap {what} failed")))
}

fn decode_base64_loose(value: &str, field: &str) -> Result<Vec<u8>> {
    let normalized = value.trim().replace('-', "+").replace('_', "/");
    let padding = (4 - normalized.len() % 4) % 4;
    let mut padded = normalized;
    padded.extend(std::iter::repeat_n('=', padding));
    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|err| Error::InvalidArgument(format!("invalid {field}: {err}")))
}
