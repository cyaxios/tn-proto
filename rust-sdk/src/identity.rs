//! Machine-global TN identity helpers.
//!
//! This mirrors the Python/TypeScript `identity.json` schema and BIP-39/HKDF
//! derivation path so Rust can create or restore the same account/device
//! identity those SDKs use.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::Sha256;

use crate::credential_store::default_identity_path;
use crate::{Error, Result};

const IDENTITY_SCHEMA_VERSION: u64 = 1;
const HKDF_SALT: &[u8] = b"tn:v1";
const HKDF_INFO_ROOT: &[u8] = b"tn:root:v1";
const HKDF_INFO_DEVICE: &[u8] = b"tn:device:v1";
const HKDF_INFO_VAULT_WRAP: &[u8] = b"tn:vault:wrap:v1";

/// Machine-global identity preferences persisted in `identity.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPrefs {
    /// Default mode for newly created ceremonies.
    pub default_new_ceremony_mode: String,
}

impl Default for IdentityPrefs {
    fn default() -> Self {
        Self {
            default_new_ceremony_mode: "local".to_string(),
        }
    }
}

/// Machine-global TN identity.
#[derive(Debug, Clone)]
pub struct Identity {
    /// DID for the device identity.
    pub did: String,
    /// URL-safe no-padding Ed25519 public key bytes.
    pub device_pub_b64: String,
    /// URL-safe no-padding Ed25519 private seed bytes.
    pub device_priv_b64_enc: String,
    /// Private key wrapping method. Rust currently writes and reads `none`.
    pub device_priv_enc_method: String,
    /// URL-safe no-padding 64-byte BIP-39 seed, when mnemonic-derived.
    pub seed_b64: Option<String>,
    /// Persisted mnemonic phrase, only when explicitly requested.
    pub mnemonic_stored: Option<String>,
    /// Remembered vault URL.
    pub linked_vault: Option<String>,
    /// Remembered vault account id.
    pub linked_account_id: Option<String>,
    /// Account preferences version pulled from the vault.
    pub prefs_version: u64,
    /// Local identity preferences.
    pub prefs: IdentityPrefs,
    /// Schema version.
    pub version: u64,
    mnemonic: Option<String>,
    source_path: Option<PathBuf>,
    raw: JsonMap<String, JsonValue>,
}

/// Options for persisting an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IdentitySaveOptions {
    /// Persist the recovery mnemonic in `mnemonic_stored`.
    ///
    /// Off by default because storing recovery words on disk increases the
    /// blast radius of a filesystem compromise.
    pub keep_mnemonic: bool,
}

impl Identity {
    /// Generate a new BIP-39-backed identity.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when `word_count` is not one of the BIP-39
    /// sizes used by Python/TypeScript: 12, 15, 18, 21, or 24.
    pub fn create_new(word_count: usize) -> Result<Self> {
        validate_word_count(word_count)?;
        let mnemonic = Mnemonic::generate_in(Language::English, word_count)
            .map_err(|err| Error::InvalidArgument(format!("mnemonic generation failed: {err}")))?;
        Self::from_mnemonic(mnemonic.to_string(), "")
    }

    /// Restore an identity from a BIP-39 mnemonic and optional passphrase.
    ///
    /// This follows Python/TypeScript exactly:
    /// BIP-39 seed -> HKDF `tn:root:v1` -> HKDF `tn:device:v1`.
    pub fn from_mnemonic(words: impl AsRef<str>, passphrase: impl AsRef<str>) -> Result<Self> {
        let words = words.as_ref().trim();
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)
            .map_err(|_| Error::InvalidArgument("invalid BIP-39 mnemonic (bad checksum)".into()))?;
        let seed = mnemonic.to_seed_normalized(passphrase.as_ref());
        let root = hkdf_expand(&seed, HKDF_INFO_ROOT)?;
        let device_seed = hkdf_expand(&root, HKDF_INFO_DEVICE)?;
        let device = tn_core::DeviceKey::from_private_bytes(&device_seed)?;
        let mut identity = Self {
            did: device.did().to_string(),
            device_pub_b64: b64url(&device.public_bytes()),
            device_priv_b64_enc: b64url(&device_seed),
            device_priv_enc_method: "none".to_string(),
            seed_b64: Some(b64url(&seed)),
            mnemonic_stored: None,
            linked_vault: None,
            linked_account_id: None,
            prefs_version: 0,
            prefs: IdentityPrefs::default(),
            version: IDENTITY_SCHEMA_VERSION,
            mnemonic: Some(mnemonic.to_string()),
            source_path: None,
            raw: JsonMap::new(),
        };
        identity
            .raw
            .insert("seed_b64".to_string(), json_string(b64url(&seed)));
        Ok(identity)
    }

    /// Load the default machine-global identity.
    pub fn load_default() -> Result<Self> {
        Self::load(default_identity_path())
    }

    /// Load an identity from `identity.json`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw_text = fs::read_to_string(path)?;
        let raw_value: JsonValue = serde_json::from_str(&raw_text)?;
        let raw = match raw_value {
            JsonValue::Object(object) => object,
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "identity.json at {} must contain a JSON object",
                    path.display()
                )));
            }
        };
        let version = raw
            .get("version")
            .and_then(JsonValue::as_u64)
            .unwrap_or(IDENTITY_SCHEMA_VERSION);
        if version != IDENTITY_SCHEMA_VERSION {
            return Err(Error::InvalidArgument(format!(
                "identity schema version {version} != {IDENTITY_SCHEMA_VERSION}"
            )));
        }
        let device_priv_enc_method = json_opt_str(&raw, "device_priv_enc_method")
            .unwrap_or("none")
            .to_string();
        if device_priv_enc_method != "none" {
            return Err(Error::InvalidArgument(format!(
                "identity.json device key is stored with encryption {device_priv_enc_method:?}; Rust cannot unwrap it yet"
            )));
        }
        let device_priv_b64_enc = json_required_str(&raw, "device_priv_b64_enc")?.to_string();
        let seed = decode_b64url(&device_priv_b64_enc)
            .map_err(|err| Error::InvalidArgument(format!("invalid device_priv_b64_enc: {err}")))?;
        let device = tn_core::DeviceKey::from_private_bytes(&seed)?;
        let did = json_opt_str(&raw, "did")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| device.did().to_string());
        if did != device.did() {
            return Err(Error::InvalidArgument(format!(
                "identity.json DID mismatch: file has {did:?}, derived {:?}",
                device.did()
            )));
        }
        let prefs = raw
            .get("prefs")
            .cloned()
            .and_then(|value| serde_json::from_value::<IdentityPrefs>(value).ok())
            .unwrap_or_default();
        let mnemonic_stored = json_opt_string(&raw, "mnemonic_stored");
        Ok(Self {
            did,
            device_pub_b64: json_opt_str(&raw, "device_pub_b64")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| b64url(&device.public_bytes())),
            device_priv_b64_enc,
            device_priv_enc_method,
            seed_b64: json_opt_string(&raw, "seed_b64"),
            mnemonic: mnemonic_stored.clone(),
            mnemonic_stored,
            linked_vault: json_opt_string(&raw, "linked_vault"),
            linked_account_id: json_opt_string(&raw, "linked_account_id"),
            prefs_version: raw
                .get("prefs_version")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0),
            prefs,
            version,
            source_path: Some(path.to_path_buf()),
            raw,
        })
    }

    /// Load an existing identity or mint and save a new one.
    pub fn load_or_mint_default() -> Result<Self> {
        Self::load_or_mint(default_identity_path())
    }

    /// Load an existing identity at `path` or mint and save a new one.
    pub fn load_or_mint(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.is_file() {
            return Self::load(path);
        }
        let mut identity = Self::create_new(12)?;
        identity.save_with_options(path, IdentitySaveOptions::default())?;
        Ok(identity)
    }

    /// Persist to the path the identity was loaded from, or the default path.
    pub fn save(&mut self) -> Result<PathBuf> {
        let path = self
            .source_path
            .clone()
            .unwrap_or_else(default_identity_path);
        self.save_with_options(path, IdentitySaveOptions::default())
    }

    /// Persist to `path` with explicit options.
    pub fn save_with_options(
        &mut self,
        path: impl AsRef<Path>,
        options: IdentitySaveOptions,
    ) -> Result<PathBuf> {
        if options.keep_mnemonic {
            self.mnemonic_stored = self.mnemonic.clone();
        }
        let path = path.as_ref();
        let doc = self.to_json_map();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&JsonValue::Object(sort_json_map(doc)))?;
        tn_core::keystore_backend::atomic_write_bytes(path, &bytes)?;
        self.source_path = Some(path.to_path_buf());
        Ok(path.to_path_buf())
    }

    /// Return the in-memory recovery phrase, if available.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Return the 32-byte Ed25519 device seed.
    pub fn device_private_bytes(&self) -> Result<[u8; 32]> {
        if self.device_priv_enc_method != "none" {
            return Err(Error::InvalidArgument(format!(
                "device_priv stored with encryption {:?}; unwrap before use",
                self.device_priv_enc_method
            )));
        }
        let bytes = decode_b64url(&self.device_priv_b64_enc)
            .map_err(|err| Error::InvalidArgument(format!("invalid device_priv_b64_enc: {err}")))?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::InvalidArgument(format!(
                "identity device seed must be 32 bytes; got {}",
                bytes.len()
            ))
        })
    }

    /// Build a [`tn_core::DeviceKey`] from the identity's device seed.
    pub fn device_key(&self) -> Result<tn_core::DeviceKey> {
        Ok(tn_core::DeviceKey::from_private_bytes(
            &self.device_private_bytes()?,
        )?)
    }

    /// Derive the 32-byte vault wrap key from the persisted BIP-39 seed.
    pub fn vault_wrap_key(&self) -> Result<[u8; 32]> {
        let seed_b64 = self.seed_b64.as_deref().ok_or_else(|| {
            Error::InvalidArgument(
                "vault_wrap_key requires seed_b64; restore from mnemonic first".into(),
            )
        })?;
        let seed = decode_b64url(seed_b64)
            .map_err(|err| Error::InvalidArgument(format!("invalid seed_b64: {err}")))?;
        let root = hkdf_expand(&seed, HKDF_INFO_ROOT)?;
        hkdf_expand(&root, HKDF_INFO_VAULT_WRAP)
    }

    fn to_json_map(&self) -> JsonMap<String, JsonValue> {
        let mut doc = self.raw.clone();
        doc.insert(
            "version".to_string(),
            JsonValue::Number(self.version.into()),
        );
        doc.insert("did".to_string(), json_string(&self.did));
        doc.insert(
            "device_pub_b64".to_string(),
            json_string(&self.device_pub_b64),
        );
        doc.insert(
            "device_priv_b64_enc".to_string(),
            json_string(&self.device_priv_b64_enc),
        );
        doc.insert(
            "device_priv_enc_method".to_string(),
            json_string(&self.device_priv_enc_method),
        );
        set_optional_string(&mut doc, "seed_b64", self.seed_b64.as_deref());
        set_optional_string(&mut doc, "mnemonic_stored", self.mnemonic_stored.as_deref());
        set_optional_string(&mut doc, "linked_vault", self.linked_vault.as_deref());
        set_optional_string(
            &mut doc,
            "linked_account_id",
            self.linked_account_id.as_deref(),
        );
        doc.insert(
            "prefs_version".to_string(),
            JsonValue::Number(self.prefs_version.into()),
        );
        doc.insert(
            "prefs".to_string(),
            serde_json::to_value(&self.prefs).expect("IdentityPrefs serializes"),
        );
        doc
    }
}

fn validate_word_count(word_count: usize) -> Result<()> {
    match word_count {
        12 | 15 | 18 | 21 | 24 => Ok(()),
        _ => Err(Error::InvalidArgument(
            "word_count must be one of [12, 15, 18, 21, 24]".into(),
        )),
    }
}

fn hkdf_expand(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut out = [0_u8; 32];
    hk.expand(info, &mut out)
        .map_err(|err| Error::InvalidArgument(format!("HKDF expand failed: {err}")))?;
    Ok(out)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64url(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
}

fn json_required_str<'a>(raw: &'a JsonMap<String, JsonValue>, key: &str) -> Result<&'a str> {
    json_opt_str(raw, key)
        .ok_or_else(|| Error::InvalidArgument(format!("identity.json missing {key}")))
}

fn json_opt_str<'a>(raw: &'a JsonMap<String, JsonValue>, key: &str) -> Option<&'a str> {
    raw.get(key)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn json_opt_string(raw: &JsonMap<String, JsonValue>, key: &str) -> Option<String> {
    json_opt_str(raw, key).map(ToOwned::to_owned)
}

fn json_string(value: impl AsRef<str>) -> JsonValue {
    JsonValue::String(value.as_ref().to_string())
}

fn set_optional_string(doc: &mut JsonMap<String, JsonValue>, key: &str, value: Option<&str>) {
    doc.insert(
        key.to_string(),
        value.map(json_string).unwrap_or(JsonValue::Null),
    );
}

fn sort_json_map(doc: JsonMap<String, JsonValue>) -> JsonMap<String, JsonValue> {
    let sorted: BTreeMap<_, _> = doc.into_iter().collect();
    sorted.into_iter().collect()
}
