//! C ABI bridge for tn-proto language bindings.
//!
//! The bridge deliberately keeps the ABI narrow: callers pass UTF-8 strings
//! and receive opaque handles or owned strings that must be freed by
//! [`tn_string_free`]. Higher-level typed APIs live in the language SDKs.

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine as _;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tn_core::DeviceKey;
use tn_core::{
    chain::{compute_row_hash, RowHashInput},
    envelope::{build_envelope, EnvelopeInput},
};
use tn_proto::{
    AbsorbReceiptExt, Identity, ManifestKind, PkgExportOptions, Tn, TnProfile, TnProjectOptions,
    VaultAwk, VaultHttpProjectClient, VaultHttpProjectClientOptions, VaultInstallBodyOptions,
    VaultPushWithPassphraseOptions, VaultRestoreWithAwkOptions, VaultRestoreWithPassphraseOptions,
};

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Opaque TN runtime handle for FFI consumers.
pub struct TnHandle {
    tn: Option<Tn>,
}

impl TnHandle {
    fn new(tn: Tn) -> Self {
        Self { tn: Some(tn) }
    }

    fn tn(&self) -> Result<&Tn, String> {
        self.tn
            .as_ref()
            .ok_or_else(|| "runtime handle is closed".to_string())
    }

    fn tn_mut(&mut self) -> Result<&mut Tn, String> {
        self.tn
            .as_mut()
            .ok_or_else(|| "runtime handle is closed".to_string())
    }
}

fn clear_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn set_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(message.into());
    });
}

fn take_result<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err("tn-core-ffi: native panic crossed FFI boundary".to_string()),
    }
}

unsafe fn string_from_ptr(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{name} must not be null"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(str::to_owned)
        .map_err(|err| format!("{name} must be valid UTF-8: {err}"))
}

fn required_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing field {key}"))
}

unsafe fn optional_string_from_ptr(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<String>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|value| {
            if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            }
        })
        .map_err(|err| format!("{name} must be valid UTF-8: {err}"))
}

fn optional_json_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!(
            "options_json field {key:?} must be a string or null"
        )),
    }
}

unsafe fn parse_optional_string_array(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    match optional_string_from_ptr(ptr, name)? {
        Some(json) => Some(
            serde_json::from_str::<Vec<String>>(&json)
                .map_err(|err| format!("{name} must be a JSON string array: {err}")),
        )
        .transpose(),
        None => Ok(None),
    }
}

fn into_c_string_ptr(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => {
            set_error("string contained an interior NUL byte");
            ptr::null_mut()
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn package_category_name(category: tn_proto::PackageCategory) -> &'static str {
    match category {
        tn_proto::PackageCategory::AdminSnapshot => "admin_snapshot",
        tn_proto::PackageCategory::Offer => "offer",
        tn_proto::PackageCategory::Enrolment => "enrolment",
        tn_proto::PackageCategory::RecipientInvite => "recipient_invite",
        tn_proto::PackageCategory::KitBundle => "kit_bundle",
        tn_proto::PackageCategory::FullKeystore => "full_keystore",
        tn_proto::PackageCategory::ContactUpdate => "contact_update",
        tn_proto::PackageCategory::IdentitySeed => "identity_seed",
        tn_proto::PackageCategory::ProjectSeed => "project_seed",
        tn_proto::PackageCategory::GroupKeys => "group_keys",
    }
}

fn device_identity_json(key: &DeviceKey) -> Value {
    json!({
        "seed_b64": B64_STANDARD.encode(key.private_bytes()),
        "public_key_b64": B64_STANDARD.encode(key.public_bytes()),
        "did": key.did(),
    })
}

fn package_signature_json(signature: &tn_proto::PackageSignatureStatus) -> Value {
    match signature {
        tn_proto::PackageSignatureStatus::Verified => json!({
            "status": "verified",
            "verified": true,
            "reason": null,
        }),
        tn_proto::PackageSignatureStatus::Invalid(reason) => json!({
            "status": "invalid",
            "verified": false,
            "reason": reason,
        }),
    }
}

fn package_info_json(info: tn_proto::PackageInfo) -> Value {
    let state = info.manifest.state.as_ref();
    let sealed = state
        .and_then(|value| value.get("body_encryption"))
        .is_some()
        || info.has_body_entry("body/encrypted.bin");
    json!({
        "kind": info.manifest.kind.as_str(),
        "category": package_category_name(info.category()),
        "scope": info.manifest.scope.clone(),
        "publisher_identity": info.manifest.publisher_identity.clone(),
        "recipient_identity": info.manifest.recipient_identity.clone(),
        "ceremony_id": info.manifest.ceremony_id.clone(),
        "event_count": info.manifest.event_count,
        "head_row_hash": info.manifest.head_row_hash.clone(),
        "signature": package_signature_json(&info.signature),
        "body_entry_count": info.body_entry_count,
        "body_entry_names": info.body_entry_names.clone(),
        "contains_secret_material": info.contains_secret_material(),
        "contains_reader_keys": info.contains_reader_keys(),
        "has_package_json": info.has_package_json(),
        "sealed": sealed,
    })
}

fn invitation_kit_hash_json(hash: &tn_proto::InvitationKitHash) -> Value {
    match hash {
        tn_proto::InvitationKitHash::NotPresent => json!({
            "status": "not_present",
            "verified": false,
            "expected": null,
        }),
        tn_proto::InvitationKitHash::Verified { expected } => json!({
            "status": "verified",
            "verified": true,
            "expected": expected,
        }),
    }
}

fn invitation_info_json(info: tn_proto::InvitationInfo) -> Result<Value, String> {
    let group_name = info.group_name();
    let kit_hash_verified = info.kit_hash_verified();
    let manifest = serde_json::to_value(&info.manifest).map_err(|err| err.to_string())?;
    Ok(json!({
        "manifest": manifest,
        "group_name": group_name,
        "kit_entry_name": info.kit_entry_name,
        "kit_len": info.kit_len,
        "kit_sha256_actual": info.kit_sha256_actual,
        "kit_hash": invitation_kit_hash_json(&info.kit_hash),
        "kit_hash_verified": kit_hash_verified,
    }))
}

fn invitation_accept_result_json(
    result: tn_proto::InvitationAcceptResult,
) -> Result<Value, String> {
    let group_name = result.group_name();
    let from_email = result.from_email().to_string();
    let leaf_index = result.leaf_index().cloned();
    Ok(json!({
        "info": invitation_info_json(result.info)?,
        "kit_path": result.kit_path.to_string_lossy(),
        "backup_path": result.backup_path.map(|path| path.to_string_lossy().into_owned()),
        "absorbed_at": result.absorbed_at,
        "group_name": group_name,
        "from_email": from_email,
        "leaf_index": leaf_index,
    }))
}

fn mint_invitation_result_json(result: tn_proto::MintInvitationResult) -> Result<Value, String> {
    let manifest = serde_json::to_value(&result.manifest).map_err(|err| err.to_string())?;
    Ok(json!({
        "path": result.path.to_string_lossy(),
        "recipient_did": result.recipient_did,
        "manifest": manifest,
        "kit_entry_name": result.kit_entry_name,
        "zip_len": result.zip_len,
    }))
}

unsafe fn handle_ref<'a>(handle: *const TnHandle) -> Result<&'a TnHandle, String> {
    if handle.is_null() {
        return Err("handle must not be null".to_string());
    }
    Ok(&*handle)
}

unsafe fn handle_mut<'a>(handle: *mut TnHandle) -> Result<&'a mut TnHandle, String> {
    if handle.is_null() {
        return Err("handle must not be null".to_string());
    }
    Ok(&mut *handle)
}

unsafe fn profile_from_ptr(ptr: *const c_char) -> Result<TnProfile, String> {
    match optional_string_from_ptr(ptr, "profile")? {
        Some(profile) => TnProfile::from_name(&profile).map_err(|err| err.to_string()),
        None => Ok(TnProfile::Transaction),
    }
}

/// Return the native bridge version.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`].
#[no_mangle]
pub extern "C" fn tn_ffi_version() -> *mut c_char {
    clear_error();
    into_c_string_ptr(env!("CARGO_PKG_VERSION").to_string())
}

/// Return and retain the last error for the current thread.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null when no error is recorded.
#[no_mangle]
pub extern "C" fn tn_last_error() -> *mut c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(message) => into_c_string_ptr(message.clone()),
        None => ptr::null_mut(),
    })
}

/// Free a string returned by this library.
#[no_mangle]
pub unsafe extern "C" fn tn_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Return canonical JSON for a JSON value.
///
/// `value_json` must be valid JSON. The returned string is owned by the caller
/// and must be released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_canonical_json(value_json: *const c_char) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let value_json = string_from_ptr(value_json, "value_json")?;
        let value: Value = serde_json::from_str(&value_json)
            .map_err(|err| format!("value_json must be valid JSON: {err}"))?;
        let bytes = tn_core::canonical::canonical_bytes(&value).map_err(|err| err.to_string())?;
        String::from_utf8(bytes).map_err(|err| format!("canonical bytes were not UTF-8: {err}"))
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return canonical JSON bytes as lowercase hex for a JSON value.
///
/// `value_json` must be valid JSON. The returned string is owned by the caller
/// and must be released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_canonical_bytes_hex(value_json: *const c_char) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let value_json = string_from_ptr(value_json, "value_json")?;
        let value: Value = serde_json::from_str(&value_json)
            .map_err(|err| format!("value_json must be valid JSON: {err}"))?;
        let bytes = tn_core::canonical::canonical_bytes(&value).map_err(|err| err.to_string())?;
        Ok(hex_encode(&bytes))
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Verify an envelope signature against `device_identity` over `row_hash`.
///
/// This verifies the same signature binding used by the runtime reader. It
/// does not verify row-hash recomputation or chain continuity. The returned
/// string is owned by the caller and must be released with [`tn_string_free`].
/// Returns null on malformed JSON or FFI errors. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_crypto_verify_envelope(envelope_json: *const c_char) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let envelope_json = string_from_ptr(envelope_json, "envelope_json")?;
        let value: Value = serde_json::from_str(&envelope_json)
            .map_err(|err| format!("envelope_json must be valid JSON: {err}"))?;
        let Some(obj) = value.as_object() else {
            return Ok(json!({
                "valid": false,
                "signature": false,
                "reason": "envelope must be a JSON object",
            })
            .to_string());
        };
        let Some(did) = obj.get("device_identity").and_then(Value::as_str) else {
            return Ok(json!({
                "valid": false,
                "signature": false,
                "reason": "missing device_identity",
            })
            .to_string());
        };
        let Some(row_hash) = obj.get("row_hash").and_then(Value::as_str) else {
            return Ok(json!({
                "valid": false,
                "signature": false,
                "reason": "missing row_hash",
            })
            .to_string());
        };
        let Some(signature_b64) = obj.get("signature").and_then(Value::as_str) else {
            return Ok(json!({
                "valid": false,
                "signature": false,
                "reason": "missing signature",
            })
            .to_string());
        };
        let signature = match tn_core::signing::signature_from_b64(signature_b64) {
            Ok(signature) => signature,
            Err(err) => {
                return Ok(json!({
                    "valid": false,
                    "signature": false,
                    "reason": err.to_string(),
                })
                .to_string());
            }
        };
        let valid = tn_core::DeviceKey::verify_did(did, row_hash.as_bytes(), &signature)
            .map_err(|err| err.to_string())?;
        Ok(json!({
            "valid": valid,
            "signature": valid,
            "reason": if valid { Value::Null } else { Value::String("signature verification failed".into()) },
        })
        .to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Seal one public-only envelope from the Python/TypeScript `tn seal` input shape.
///
/// `input_json` must be a JSON object containing `seed_b64`, `event_type`,
/// `level`, `sequence`, `prev_hash`, `timestamp`, and `event_id`.
/// `public_fields` is optional and defaults to `{}`. The returned string is the
/// compact envelope JSON line with a trailing newline.
#[no_mangle]
pub unsafe extern "C" fn tn_crypto_seal_public(input_json: *const c_char) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let input_json = string_from_ptr(input_json, "input_json")?;
        let value: Value = serde_json::from_str(&input_json)
            .map_err(|err| format!("input_json must be valid JSON: {err}"))?;
        let Some(obj) = value.as_object() else {
            return Err("seal input must be a JSON object".to_string());
        };

        let seed_b64 = required_str(obj, "seed_b64")?;
        let event_type = required_str(obj, "event_type")?;
        let level = required_str(obj, "level")?;
        let sequence = obj
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| "missing field sequence".to_string())?;
        let prev_hash = required_str(obj, "prev_hash")?;
        let timestamp = required_str(obj, "timestamp")?;
        let event_id = required_str(obj, "event_id")?;
        let public_fields = match obj.get("public_fields") {
            None | Some(Value::Null) => serde_json::Map::new(),
            Some(Value::Object(fields)) => fields.clone(),
            Some(_) => return Err("public_fields must be a JSON object".to_string()),
        };

        let seed = B64_STANDARD
            .decode(seed_b64)
            .map_err(|err| format!("invalid seed_b64: {err}"))?;
        let key = DeviceKey::from_private_bytes(&seed).map_err(|err| err.to_string())?;

        let hash_fields = public_fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>();
        let groups = BTreeMap::new();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: key.did(),
            timestamp,
            event_id,
            event_type,
            level,
            prev_hash,
            public_fields: &hash_fields,
            groups: &groups,
        });
        let signature = key.sign(row_hash.as_bytes());
        let signature_b64 = tn_core::signing::signature_b64(&signature);
        let line = build_envelope(EnvelopeInput {
            device_identity: key.did(),
            timestamp,
            event_id,
            event_type,
            level,
            sequence,
            prev_hash,
            row_hash: &row_hash,
            signature_b64: &signature_b64,
            public_fields,
            group_payloads: BTreeMap::new(),
        })
        .map_err(|err| err.to_string())?;
        Ok(line)
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Generate a fresh Ed25519 device identity.
///
/// The returned JSON contains `seed_b64`, `public_key_b64`, and `did`. The
/// seed is private key material and must be handled as a secret.
#[no_mangle]
pub unsafe extern "C" fn tn_identity_generate() -> *mut c_char {
    clear_error();
    match take_result(|| {
        let key = DeviceKey::generate();
        serde_json::to_string(&device_identity_json(&key)).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Derive an Ed25519 device identity from a base64-encoded 32-byte seed.
///
/// The returned JSON contains `seed_b64`, `public_key_b64`, and `did`. The
/// seed is private key material and must be handled as a secret.
#[no_mangle]
pub unsafe extern "C" fn tn_identity_from_seed_b64(seed_b64: *const c_char) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let seed_b64 = string_from_ptr(seed_b64, "seed_b64")?;
        let seed = B64_STANDARD
            .decode(seed_b64)
            .map_err(|err| format!("seed_b64 must be valid base64: {err}"))?;
        let key = DeviceKey::from_private_bytes(&seed).map_err(|err| err.to_string())?;
        serde_json::to_string(&device_identity_json(&key)).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Restore a TN machine identity from BIP-39 mnemonic words.
///
/// The returned JSON contains `seed_b64`, `public_key_b64`, `did`,
/// `identity_seed_b64url`, and `mnemonic`.
#[no_mangle]
pub unsafe extern "C" fn tn_identity_from_mnemonic(
    words: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let words = string_from_ptr(words, "words")?;
        let passphrase = optional_string_from_ptr(passphrase, "passphrase")?.unwrap_or_default();
        let identity = Identity::from_mnemonic(words, passphrase).map_err(|err| err.to_string())?;
        let device_seed = B64_URL
            .decode(&identity.device_priv_b64_enc)
            .map_err(|err| format!("derived identity device seed was not base64url: {err}"))?;
        let device = DeviceKey::from_private_bytes(&device_seed).map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "seed_b64": B64_STANDARD.encode(device.private_bytes()),
            "public_key_b64": B64_STANDARD.encode(device.public_bytes()),
            "did": device.did(),
            "identity_seed_b64url": identity.seed_b64,
            "mnemonic": identity.mnemonic(),
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Sign base64-encoded message bytes with a base64-encoded 32-byte seed.
///
/// Returns the TN wire signature encoding: URL-safe base64 without padding.
#[no_mangle]
pub unsafe extern "C" fn tn_identity_sign_b64(
    seed_b64: *const c_char,
    message_b64: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let seed_b64 = string_from_ptr(seed_b64, "seed_b64")?;
        let message_b64 = string_from_ptr(message_b64, "message_b64")?;
        let seed = B64_STANDARD
            .decode(seed_b64)
            .map_err(|err| format!("seed_b64 must be valid base64: {err}"))?;
        let message = B64_STANDARD
            .decode(message_b64)
            .map_err(|err| format!("message_b64 must be valid base64: {err}"))?;
        let key = DeviceKey::from_private_bytes(&seed).map_err(|err| err.to_string())?;
        Ok(tn_core::signing::signature_b64(&key.sign(&message)))
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Verify a TN wire signature against a DID and base64-encoded message bytes.
///
/// Returns JSON: `{ "valid": bool }`.
#[no_mangle]
pub unsafe extern "C" fn tn_identity_verify_did_b64(
    did: *const c_char,
    message_b64: *const c_char,
    signature_b64: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let did = string_from_ptr(did, "did")?;
        let message_b64 = string_from_ptr(message_b64, "message_b64")?;
        let signature_b64 = string_from_ptr(signature_b64, "signature_b64")?;
        let message = B64_STANDARD
            .decode(message_b64)
            .map_err(|err| format!("message_b64 must be valid base64: {err}"))?;
        let signature =
            tn_core::signing::signature_from_b64(&signature_b64).map_err(|err| err.to_string())?;
        let valid =
            DeviceKey::verify_did(&did, &message, &signature).map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({ "valid": valid })).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Open an existing `tn.yaml` and return an opaque runtime handle.
///
/// Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_open(yaml_path: *const c_char) -> *mut TnHandle {
    clear_error();
    match take_result(|| {
        let yaml_path = string_from_ptr(yaml_path, "yaml_path")?;
        Tn::init(yaml_path)
            .map(TnHandle::new)
            .map_err(|err| err.to_string())
    }) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Create or open a project and return an opaque runtime handle.
///
/// `project_dir` may be null or empty to use the process current directory.
/// Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_init_project(
    project: *const c_char,
    project_dir: *const c_char,
) -> *mut TnHandle {
    tn_runtime_init_project_with_options(project, project_dir, ptr::null())
}

/// Create or open a project with options and return an opaque runtime handle.
///
/// `project_dir` may be null or empty to use the process current directory.
/// `profile` may be null or empty to use `transaction`.
/// Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_init_project_with_options(
    project: *const c_char,
    project_dir: *const c_char,
    profile: *const c_char,
) -> *mut TnHandle {
    tn_runtime_init_project_with_seed(project, project_dir, profile, ptr::null())
}

/// Create or open a project with options and an explicit 32-byte device seed.
///
/// `device_seed_b64` may be null or empty to use the normal identity lookup.
/// Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_init_project_with_seed(
    project: *const c_char,
    project_dir: *const c_char,
    profile: *const c_char,
    device_seed_b64: *const c_char,
) -> *mut TnHandle {
    clear_error();
    match take_result(|| {
        let project = string_from_ptr(project, "project")?;
        let project_dir = optional_string_from_ptr(project_dir, "project_dir")?;
        let profile = profile_from_ptr(profile)?;
        let mut options = TnProjectOptions::default();
        options.project_dir = project_dir.map(PathBuf::from);
        options.profile = profile;
        if let Some(seed_b64) = optional_string_from_ptr(device_seed_b64, "device_seed_b64")? {
            let seed = B64_STANDARD
                .decode(seed_b64)
                .map_err(|err| format!("device_seed_b64 is not valid base64: {err}"))?;
            if seed.len() != 32 {
                return Err(format!(
                    "device_seed_b64 must decode to 32 bytes; got {}",
                    seed.len()
                ));
            }
            options.device_private_bytes = Some(seed);
        }
        Tn::init_project_with_options(&project, options)
            .map(TnHandle::new)
            .map_err(|err| err.to_string())
    }) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the active runtime device DID.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_did(handle: *const TnHandle) -> *mut c_char {
    clear_error();
    match take_result(|| Ok(handle_ref(handle)?.tn()?.did().to_owned())) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the active runtime YAML path.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_yaml_path(handle: *const TnHandle) -> *mut c_char {
    clear_error();
    match take_result(|| {
        Ok(handle_ref(handle)?
            .tn()?
            .yaml_path()
            .to_string_lossy()
            .into_owned())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the active runtime log path.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_log_path(handle: *const TnHandle) -> *mut c_char {
    clear_error();
    match take_result(|| {
        Ok(handle_ref(handle)?
            .tn()?
            .log_path()
            .to_string_lossy()
            .into_owned())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the loaded `.tn/config/agents.md` policy document as JSON.
///
/// Returns the JSON literal `null` when the active ceremony has no policy
/// file loaded; otherwise a JSON object with `version`, `schema`, `path`,
/// `body`, `content_hash`, and per-event `templates`. The document is the
/// one loaded at runtime open — re-open the handle after changing the file.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_agent_policy_doc(handle: *const TnHandle) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let value = match handle_ref(handle)?.tn()?.agent_policy_doc() {
            Some(doc) => policy_doc_to_json(doc),
            None => Value::Null,
        };
        serde_json::to_string(&value).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Render a parsed agents policy document into the stable JSON shape the
/// language SDKs consume from [`tn_runtime_agent_policy_doc`].
fn policy_doc_to_json(doc: &tn_core::agents_policy::PolicyDocument) -> Value {
    let templates: Map<String, Value> = doc
        .templates
        .iter()
        .map(|(event_type, t)| {
            (
                event_type.clone(),
                json!({
                    "event_type": t.event_type,
                    "instruction": t.instruction,
                    "use_for": t.use_for,
                    "do_not_use_for": t.do_not_use_for,
                    "consequences": t.consequences,
                    "on_violation_or_error": t.on_violation_or_error,
                    "content_hash": t.content_hash,
                    "version": t.version,
                    "path": t.path,
                }),
            )
        })
        .collect();
    json!({
        "version": doc.version,
        "schema": doc.schema,
        "path": doc.path,
        "body": doc.body,
        "content_hash": doc.content_hash,
        "templates": templates,
    })
}

/// Emit an event and return a JSON receipt.
///
/// `level` may be null or empty for the severity-less log path. `fields_json`
/// must be a JSON object. The returned string is owned by the caller and must
/// be released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_emit(
    handle: *const TnHandle,
    level: *const c_char,
    event_type: *const c_char,
    fields_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let level = optional_string_from_ptr(level, "level")?.unwrap_or_default();
        let event_type = string_from_ptr(event_type, "event_type")?;
        let fields_json = string_from_ptr(fields_json, "fields_json")?;
        let fields_value: Value = serde_json::from_str(&fields_json)
            .map_err(|err| format!("fields_json must be valid JSON: {err}"))?;
        let fields = fields_value
            .as_object()
            .cloned()
            .ok_or_else(|| "fields_json must be a JSON object".to_string())?;
        let receipt = handle_ref(handle)?
            .tn()?
            .emit(&level, &event_type, fields)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "emitted": receipt.emitted,
            "envelope": receipt.envelope,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Emit an event with an AAD marker map and return a JSON receipt.
///
/// `level` may be null or empty for the severity-less log path. `fields_json`
/// and `aad_json` must be JSON objects. The markers in `aad_json` are merged
/// over each group's configured default marker, bound as additional
/// authenticated data into every sealed group body, and echoed under the
/// public `tn_aad` envelope field. An empty `aad_json` object behaves exactly
/// like [`tn_runtime_emit`] for ceremonies without per-group default markers.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_emit_with_aad(
    handle: *const TnHandle,
    level: *const c_char,
    event_type: *const c_char,
    fields_json: *const c_char,
    aad_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let level = optional_string_from_ptr(level, "level")?.unwrap_or_default();
        let event_type = string_from_ptr(event_type, "event_type")?;
        let fields_json = string_from_ptr(fields_json, "fields_json")?;
        let aad_json = string_from_ptr(aad_json, "aad_json")?;
        let fields_value: Value = serde_json::from_str(&fields_json)
            .map_err(|err| format!("fields_json must be valid JSON: {err}"))?;
        let fields = fields_value
            .as_object()
            .cloned()
            .ok_or_else(|| "fields_json must be a JSON object".to_string())?;
        let aad_value: Value = serde_json::from_str(&aad_json)
            .map_err(|err| format!("aad_json must be valid JSON: {err}"))?;
        let aad = aad_value
            .as_object()
            .cloned()
            .ok_or_else(|| "aad_json must be a JSON object".to_string())?;
        let receipt = handle_ref(handle)?
            .tn()?
            .emit_with_aad(&level, &event_type, fields, aad)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "emitted": receipt.emitted,
            "envelope": receipt.envelope,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Render a sealed-object verb error into the machine-parseable
/// `tn_last_error` channel:
///
/// - failed verification (the SDK's `Error::Verify`) becomes
///   `VerifyError:` + a JSON object `{"failed_checks": [...],
///   "sequence": n, "event_type": "..."}`;
/// - malformed unseal input (`tn_core::Error::Malformed` for a sealed
///   object) becomes `UnsealError: ` + the reason;
/// - everything else stays a plain message.
fn sealed_object_error_message(err: &tn_proto::Error) -> String {
    match err {
        tn_proto::Error::Verify {
            failed_checks,
            sequence,
            event_type,
        } => format!(
            "VerifyError:{}",
            json!({
                "failed_checks": failed_checks,
                "sequence": sequence,
                "event_type": event_type,
            })
        ),
        tn_proto::Error::Core(tn_core::Error::Malformed {
            kind: "sealed object",
            reason,
        }) => format!("UnsealError: {reason}"),
        other => other.to_string(),
    }
}

/// Parse [`tn_runtime_seal`]'s nullable `options_json`:
/// `{"receipt": bool (default true), "aad": object|null}`.
fn parse_seal_options(options_json: Option<String>) -> Result<tn_core::SealOptions, String> {
    let mut opts = tn_core::SealOptions::default();
    let Some(text) = options_json else {
        return Ok(opts);
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| format!("options_json must be valid JSON: {err}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "options_json must be a JSON object".to_string())?;
    match obj.get("receipt") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(receipt)) => opts.receipt = *receipt,
        Some(_) => {
            return Err("options_json field \"receipt\" must be a boolean or null".to_string())
        }
    }
    match obj.get("aad") {
        None | Some(Value::Null) => {}
        Some(Value::Object(aad)) => opts.aad = aad.clone(),
        Some(_) => {
            return Err("options_json field \"aad\" must be a JSON object or null".to_string())
        }
    }
    Ok(opts)
}

/// Parse [`tn_runtime_unseal`]'s nullable `options_json`:
/// `{"verify": bool (default true), "as_recipient": "path"|null,
/// "group": "default"}`.
fn parse_unseal_options(options_json: Option<String>) -> Result<tn_core::UnsealOptions, String> {
    let mut opts = tn_core::UnsealOptions::default();
    let Some(text) = options_json else {
        return Ok(opts);
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| format!("options_json must be valid JSON: {err}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "options_json must be a JSON object".to_string())?;
    match obj.get("verify") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(verify)) => opts.verify = *verify,
        Some(_) => {
            return Err("options_json field \"verify\" must be a boolean or null".to_string())
        }
    }
    if let Some(dir) = optional_json_string(obj, "as_recipient")? {
        opts.as_recipient = Some(PathBuf::from(dir));
    }
    if let Some(group) = optional_json_string(obj, "group")? {
        opts.group = group;
    }
    Ok(opts)
}

/// Serialize an [`tn_core::UnsealOutcome`] into the stable JSON shape the
/// language SDKs consume from [`tn_runtime_unseal`].
fn unseal_outcome_json(outcome: tn_core::UnsealOutcome) -> Result<String, String> {
    let plaintext: Map<String, Value> = outcome.plaintext.into_iter().collect();
    let sealed_blocks: Vec<Value> = outcome
        .sealed_blocks
        .into_iter()
        .map(|block| {
            json!({
                "name": block.name,
                "ciphertext_b64": block.ciphertext_b64,
                "field_hashes": block.field_hashes,
                "aad_b64": block.aad_b64,
                "keystore_candidates": block.keystore_candidates,
            })
        })
        .collect();
    serde_json::to_string(&json!({
        "envelope": outcome.envelope,
        "plaintext": plaintext,
        "valid": {
            "signature": outcome.valid.signature,
            "row_hash": outcome.valid.row_hash,
        },
        "hidden_groups": outcome.hidden_groups,
        "sealed_blocks": sealed_blocks,
        "fields": outcome.fields,
    }))
    .map_err(|err| err.to_string())
}

/// Seal fields into a portable attested object (standalone envelope) and
/// return its wire line.
///
/// `fields_json` must be a JSON object. `options_json` may be null;
/// `{"receipt": bool (default true), "aad": object|null}`. The returned
/// string is the sealed object's compact envelope JSON line with NO trailing
/// newline — the transport artifact. SDKs must hand it on verbatim, never a
/// re-serialization (foreign JSON round-trips are exactly what the
/// fragile-value guard protects against). The returned string is owned by
/// the caller and must be released with [`tn_string_free`]. Returns null on
/// error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_seal(
    handle: *const TnHandle,
    object_type: *const c_char,
    fields_json: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let object_type = string_from_ptr(object_type, "object_type")?;
        let fields_json = string_from_ptr(fields_json, "fields_json")?;
        let fields_value: Value = serde_json::from_str(&fields_json)
            .map_err(|err| format!("fields_json must be valid JSON: {err}"))?;
        let fields = fields_value
            .as_object()
            .cloned()
            .ok_or_else(|| "fields_json must be a JSON object".to_string())?;
        let opts = parse_seal_options(optional_string_from_ptr(options_json, "options_json")?)?;
        let sealed = handle_ref(handle)?
            .tn()?
            .seal(&object_type, Value::Object(fields), opts)
            .map_err(|err| sealed_object_error_message(&err))?;
        Ok(sealed.wire)
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Verify a sealed object and open every group block a held key fits.
///
/// `source` is the sealed object's wire JSON text (the original wire string
/// is the safe input). `options_json` may be null; `{"verify": bool (default
/// true), "as_recipient": "path"|null, "group": "default"}`. With
/// `as_recipient` set, only `group` is decrypted, with keys from that bare
/// directory (the handle's own groups and keystore are not consulted).
///
/// Returns the outcome JSON: `{"envelope": {...}, "plaintext":
/// {"<group>": {...}}, "valid": {"signature": bool, "row_hash": bool},
/// "hidden_groups": [...], "sealed_blocks": [{"name", "ciphertext_b64",
/// "field_hashes", "aad_b64", "keystore_candidates"}], "fields": {...}}`.
/// `sealed_blocks` + `aad_b64` are the managed-cipher seam: a host holding a
/// cipher this build lacks (jwe always; hibe when the feature is off — the
/// FFI build itself gets hibe via feature unification from its direct
/// tn-core dependency) can run a second-pass decrypt without reimplementing
/// the AAD reconstruction. Holding no fitting key is NOT an error — the
/// verified public frame comes back with the blocks left sealed.
///
/// Error channel (see [`tn_last_error`]): failed verification is
/// `VerifyError:` + JSON `{"failed_checks": [...], "sequence": n,
/// "event_type": "..."}`; malformed input is `UnsealError: ` + reason;
/// everything else is a plain message. The returned string is owned by the
/// caller and must be released with [`tn_string_free`]. Returns null on
/// error.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_unseal(
    handle: *const TnHandle,
    source: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let source = string_from_ptr(source, "source")?;
        let opts = parse_unseal_options(optional_string_from_ptr(options_json, "options_json")?)?;
        let outcome = handle_ref(handle)?
            .tn()?
            .unseal(&source, opts)
            .map_err(|err| sealed_object_error_message(&err))?;
        unseal_outcome_json(outcome)
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Read decrypted entries and return a JSON array.
///
/// `all_runs` and `verify` are treated as false when set to 0 and true
/// otherwise. The returned string is owned by the caller and must be released
/// with [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_read(
    handle: *const TnHandle,
    all_runs: i32,
    verify: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let entries = handle_ref(handle)?
            .tn()?
            .read(tn_proto::ReadOptions {
                all_runs: all_runs != 0,
                verify: verify != 0,
            })
            .map_err(|err| err.to_string())?;
        let flat_entries: Vec<_> = entries.into_iter().map(|entry| entry.into_map()).collect();
        serde_json::to_string(&flat_entries).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Ensure an admin group exists and route fields into it.
///
/// `fields_json` must be a JSON array of strings. The returned string is
/// owned by the caller and must be released with [`tn_string_free`]. Returns
/// null on error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_ensure_group(
    handle: *mut TnHandle,
    group: *const c_char,
    fields_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let fields_json = string_from_ptr(fields_json, "fields_json")?;
        let fields: Vec<String> = serde_json::from_str(&fields_json)
            .map_err(|err| format!("fields_json must be a JSON string array: {err}"))?;
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .ensure_group(&group, fields.iter().map(String::as_str))
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "fields": result.fields,
            "created": result.created,
            "changed": result.changed,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Mint a reader kit for a recipient and return a JSON receipt.
///
/// `recipient_did` may be null or empty. `out_kit_path` must end with
/// `.btn.mykit`. The returned string is owned by the caller and must be
/// released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_add_recipient(
    handle: *mut TnHandle,
    group: *const c_char,
    recipient_did: *const c_char,
    out_kit_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let recipient_did = optional_string_from_ptr(recipient_did, "recipient_did")?;
        let kit_path = PathBuf::from(string_from_ptr(out_kit_path, "out_kit_path")?);
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .add_recipient(&group, recipient_did.clone(), &kit_path)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "recipient_did": result.recipient_did,
            "leaf_index": result.leaf_index,
            "kit_path": result.kit_path.to_string_lossy(),
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Revoke a recipient reader by leaf index and return a JSON receipt.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_revoke_recipient(
    handle: *mut TnHandle,
    group: *const c_char,
    leaf_index: u64,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .revoke_recipient(&group, leaf_index)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "leaf_index": result.leaf_index,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Rotate a btn admin group and return a JSON receipt.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_rotate_group(
    handle: *mut TnHandle,
    group: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .rotate(&group)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "generation": result.generation,
            "previous_kit_sha256": result.previous_kit_sha256,
            "new_kit_sha256": result.new_kit_sha256,
            "rotated_at": result.rotated_at,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Grant a hibe reader: mint a delegated identity key for `reader_did` and
/// export it as an absorbable `.tnpkg` kit, returning a JSON receipt
/// (`{"group", "reader_did", "id_path", "path"}`).
///
/// `reader_did` may be null or empty (no grant recorded, plaintext kit).
/// `id_path` may be null or empty to key the reader to the group's current
/// sealing path; pass an ancestor path to hand out a delegatable key.
/// hibe groups only — btn/jwe groups use `tn_runtime_admin_add_recipient`.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_grant_reader(
    handle: *mut TnHandle,
    group: *const c_char,
    reader_did: *const c_char,
    out_path: *const c_char,
    id_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let reader_did = optional_string_from_ptr(reader_did, "reader_did")?;
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let id_path = optional_string_from_ptr(id_path, "id_path")?;
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .grant_reader(&group, reader_did, &out_path, id_path)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "reader_did": result.reader_did,
            "id_path": result.id_path,
            "path": result.path.to_string_lossy(),
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Rotate a hibe group's identity path so future seals use `new_path`,
/// returning a JSON receipt (`{"group", "previous_path", "new_path"}`).
///
/// `allow_root_path` is treated as false when set to 0 and true otherwise;
/// the root path is the empty string and requires the flag. The live group
/// cipher is refreshed in place, so the next emit/seal through this handle
/// lands on the new path. hibe groups only — btn groups rotate via
/// `tn_runtime_admin_rotate_group`. The returned string is owned by the
/// caller and must be released with [`tn_string_free`]. Returns null on
/// error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_rotate_id_path(
    handle: *mut TnHandle,
    group: *const c_char,
    new_path: *const c_char,
    allow_root_path: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        // The empty string is meaningful here (the root path), so this is
        // a required pointer, not an optional-and-empty-collapsing one.
        let new_path = string_from_ptr(new_path, "new_path")?;
        let result = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .rotate_id_path(&group, &new_path, allow_root_path != 0)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "group": result.group,
            "previous_path": result.previous_path,
            "new_path": result.new_path,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the recipient roster for an admin group as JSON.
///
/// `include_revoked` is treated as false when set to 0 and true otherwise.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_recipients(
    handle: *mut TnHandle,
    group: *const c_char,
    include_revoked: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let recipients = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .recipients(&group, include_revoked != 0)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&recipients).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Return the revoked recipient count for an admin group.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_admin_revoked_count(
    handle: *mut TnHandle,
    group: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let revoked_count = handle_mut(handle)?
            .tn_mut()?
            .admin()
            .revoked_count(&group)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({ "revoked_count": revoked_count }))
            .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Export an admin-log snapshot package.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_export_admin_snapshot(
    handle: *const TnHandle,
    out_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let written = handle_ref(handle)?
            .tn()?
            .pkg()
            .export_admin_snapshot(&out_path)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({ "path": written.to_string_lossy() }))
            .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Export an existing reader-kit bundle package.
///
/// `groups_json` may be null/empty for all locally available kits or a JSON
/// string array. `to_did` may be null/empty. The returned string is owned by
/// the caller and must be released with [`tn_string_free`]. Returns null on
/// error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_export_kit_bundle(
    handle: *const TnHandle,
    out_path: *const c_char,
    groups_json: *const c_char,
    to_did: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let groups = match optional_string_from_ptr(groups_json, "groups_json")? {
            Some(groups_json) => Some(
                serde_json::from_str::<Vec<String>>(&groups_json)
                    .map_err(|err| format!("groups_json must be a JSON string array: {err}"))?,
            ),
            None => None,
        };
        let to_did = optional_string_from_ptr(to_did, "to_did")?;
        let written = handle_ref(handle)?
            .tn()?
            .pkg()
            .export_kit_bundle(&out_path, groups, to_did)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({ "path": written.to_string_lossy() }))
            .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Export a project-seed bootstrap package.
///
/// The package contains secret key material and therefore always confirms
/// secret export explicitly. The returned string is owned by the caller and
/// must be released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_export_project_seed(
    handle: *const TnHandle,
    out_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let written = handle_ref(handle)?.tn()?.pkg().export_with(
            &out_path,
            PkgExportOptions {
                kind: ManifestKind::ProjectSeed,
                confirm_includes_secrets: true,
                ..PkgExportOptions::default()
            },
        );
        let written = written.map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({ "path": written.to_string_lossy() }))
            .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Export an encrypted `full_keystore` package for vault pending-claim upload.
///
/// `bek_b64` must decode to 32 bytes. The package contains secret key
/// material, encrypted in the package body with the supplied BEK.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_export_encrypted_full_keystore(
    handle: *const TnHandle,
    out_path: *const c_char,
    groups_json: *const c_char,
    bek_b64: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let out_path = string_from_ptr(out_path, "out_path")?;
        let groups = parse_optional_string_array(groups_json, "groups_json")?;
        let bek_b64 = string_from_ptr(bek_b64, "bek_b64")?;
        let bek = B64_STANDARD
            .decode(bek_b64)
            .map_err(|err| format!("bek_b64 must be valid base64: {err}"))?;
        let bek: [u8; 32] = bek
            .try_into()
            .map_err(|_| "bek_b64 must decode to exactly 32 bytes".to_string())?;
        let path = PathBuf::from(out_path);
        let exported = handle_ref(handle)?.tn()?.pkg().export_with(
            &path,
            PkgExportOptions {
                kind: ManifestKind::FullKeystore,
                confirm_includes_secrets: true,
                groups,
                encrypt_body_with: Some(bek),
                ..PkgExportOptions::default()
            },
        );
        let exported = exported.map_err(|err| err.to_string())?;
        let len = std::fs::metadata(&exported)
            .map_err(|err| err.to_string())?
            .len();
        serde_json::to_string(&json!({
            "path": exported.to_string_lossy(),
            "length": len,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Export a `full_keystore`/`group_keys` package for vault account-inbox sync.
///
/// `groups_json` may be null/empty for all publishable BTN groups or a JSON
/// string array. The returned string is owned by the caller and must be
/// released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_export_group_keys(
    handle: *const TnHandle,
    out_path: *const c_char,
    groups_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let out_path = string_from_ptr(out_path, "out_path")?;
        let groups = parse_optional_string_array(groups_json, "groups_json")?;
        let path = PathBuf::from(out_path);
        let exported = handle_ref(handle)?
            .tn()?
            .pkg()
            .export_group_keys(&path, groups)
            .map_err(|err| err.to_string())?;
        let len = std::fs::metadata(&exported)
            .map_err(|err| err.to_string())?
            .len();
        serde_json::to_string(&json!({
            "path": exported.to_string_lossy(),
            "length": len,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Push the local ceremony body to the vault using a passphrase-derived AWK.
///
/// This runs the Rust SDK's supported passphrase push flow: fetch account
/// credential wrapping material, derive the account AWK from `passphrase`,
/// mint or reuse the project BEK, then upload the encrypted body with the
/// vault generation/If-Match guard.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_vault_push_body_with_passphrase(
    handle: *const TnHandle,
    vault_base_url: *const c_char,
    bearer_token: *const c_char,
    project_id: *const c_char,
    passphrase: *const c_char,
    credential_id: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let vault_base_url = string_from_ptr(vault_base_url, "vault_base_url")?;
        let bearer_token = optional_string_from_ptr(bearer_token, "bearer_token")?;
        let project_id = optional_string_from_ptr(project_id, "project_id")?;
        let passphrase = string_from_ptr(passphrase, "passphrase")?;
        let credential_id = optional_string_from_ptr(credential_id, "credential_id")?;

        let mut client_options = VaultHttpProjectClientOptions::new(vault_base_url);
        client_options.bearer_token = bearer_token;
        let client =
            VaultHttpProjectClient::with_options(client_options).map_err(|err| err.to_string())?;
        let mut push_options = VaultPushWithPassphraseOptions::new();
        push_options.project_id = project_id;
        push_options.credential_id = credential_id;
        let result = handle_ref(handle)?
            .tn()?
            .vault()
            .push_body_with_passphrase_http_client(&client, &passphrase, push_options)
            .map_err(|err| err.to_string())?;

        serde_json::to_string(&json!({
            "project_id": result.push.project_id,
            "body_member_count": result.push.body_member_count,
            "encrypted_len": result.push.encrypted_len,
            "wrapped_key_created": result.wrapped_key_created,
            "if_match": result.if_match,
            "wrapped_key_response": result.push.wrapped_key_response,
            "encrypted_blob_response": result.push.encrypted_blob_response,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Restore the vault body using a passphrase-derived AWK without installing files.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_vault_restore_body_with_passphrase(
    handle: *const TnHandle,
    vault_base_url: *const c_char,
    bearer_token: *const c_char,
    project_id: *const c_char,
    passphrase: *const c_char,
    credential_id: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let vault_base_url = string_from_ptr(vault_base_url, "vault_base_url")?;
        let bearer_token = optional_string_from_ptr(bearer_token, "bearer_token")?;
        let project_id = optional_string_from_ptr(project_id, "project_id")?;
        let passphrase = string_from_ptr(passphrase, "passphrase")?;
        let credential_id = optional_string_from_ptr(credential_id, "credential_id")?;

        let mut client_options = VaultHttpProjectClientOptions::new(vault_base_url);
        client_options.bearer_token = bearer_token;
        let client =
            VaultHttpProjectClient::with_options(client_options).map_err(|err| err.to_string())?;
        let mut restore_options = VaultRestoreWithPassphraseOptions::new();
        restore_options.project_id = project_id;
        restore_options.credential_id = credential_id;
        let result = handle_ref(handle)?
            .tn()?
            .vault()
            .restore_body_with_passphrase_http_client(&client, &passphrase, restore_options)
            .map_err(|err| err.to_string())?;

        let mut body_member_names = result.body.keys().cloned().collect::<Vec<_>>();
        body_member_names.sort();
        let total_body_bytes: usize = result.body.values().map(Vec::len).sum();
        serde_json::to_string(&json!({
            "project_id": result.project_id,
            "body_member_count": body_member_names.len(),
            "total_body_bytes": total_body_bytes,
            "body_member_names": body_member_names,
            "wrapped_key": {
                "wrapped_bek_b64": result.wrapped_key.wrapped_bek_b64,
                "wrap_nonce_b64": result.wrapped_key.wrap_nonce_b64,
            },
            "encrypted_blob_response": result.encrypted_blob_response,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Restore the vault body using a passphrase-derived AWK and install it to a directory.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_vault_restore_install_body_with_passphrase(
    handle: *const TnHandle,
    vault_base_url: *const c_char,
    bearer_token: *const c_char,
    project_id: *const c_char,
    passphrase: *const c_char,
    credential_id: *const c_char,
    target_dir: *const c_char,
    overwrite: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let vault_base_url = string_from_ptr(vault_base_url, "vault_base_url")?;
        let bearer_token = optional_string_from_ptr(bearer_token, "bearer_token")?;
        let project_id = optional_string_from_ptr(project_id, "project_id")?;
        let passphrase = string_from_ptr(passphrase, "passphrase")?;
        let credential_id = optional_string_from_ptr(credential_id, "credential_id")?;
        let target_dir = PathBuf::from(string_from_ptr(target_dir, "target_dir")?);

        let mut client_options = VaultHttpProjectClientOptions::new(vault_base_url);
        client_options.bearer_token = bearer_token;
        let client =
            VaultHttpProjectClient::with_options(client_options).map_err(|err| err.to_string())?;
        let mut restore_options = VaultRestoreWithPassphraseOptions::new();
        restore_options.project_id = project_id;
        restore_options.credential_id = credential_id;
        let mut install_options = VaultInstallBodyOptions::new(target_dir);
        install_options.overwrite = overwrite != 0;
        let result = handle_ref(handle)?
            .tn()?
            .vault()
            .restore_and_install_body_with_passphrase_http_client(
                &client,
                &passphrase,
                restore_options,
                install_options,
            )
            .map_err(|err| err.to_string())?;

        let mut body_member_names = result.restore.body.keys().cloned().collect::<Vec<_>>();
        body_member_names.sort();
        let total_body_bytes: usize = result.restore.body.values().map(Vec::len).sum();
        let written_paths: Vec<_> = result
            .install
            .written_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let deduped_paths: Vec<_> = result
            .install
            .deduped_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        serde_json::to_string(&json!({
            "project_id": result.restore.project_id,
            "body_member_count": body_member_names.len(),
            "total_body_bytes": total_body_bytes,
            "body_member_names": body_member_names,
            "target_dir": result.install.target_dir.to_string_lossy(),
            "yaml_path": result.install.yaml_path.to_string_lossy(),
            "keys_dir": result.install.keys_dir.to_string_lossy(),
            "written_paths": written_paths,
            "deduped_paths": deduped_paths,
            "skipped_members": result.install.skipped_members,
            "wrapped_key": {
                "wrapped_bek_b64": result.restore.wrapped_key.wrapped_bek_b64,
                "wrap_nonce_b64": result.restore.wrapped_key.wrap_nonce_b64,
            },
            "encrypted_blob_response": result.restore.encrypted_blob_response,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Restore the vault body using a raw 32-byte AWK and install it to a directory.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_vault_restore_install_body_with_awk(
    handle: *const TnHandle,
    vault_base_url: *const c_char,
    bearer_token: *const c_char,
    project_id: *const c_char,
    awk_b64: *const c_char,
    target_dir: *const c_char,
    overwrite: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let vault_base_url = string_from_ptr(vault_base_url, "vault_base_url")?;
        let bearer_token = optional_string_from_ptr(bearer_token, "bearer_token")?;
        let project_id = optional_string_from_ptr(project_id, "project_id")?;
        let awk_b64 = string_from_ptr(awk_b64, "awk_b64")?;
        let awk_bytes = B64_STANDARD
            .decode(awk_b64)
            .map_err(|err| format!("invalid AWK base64: {err}"))?;
        let awk = VaultAwk::from_slice(&awk_bytes).map_err(|err| err.to_string())?;
        let target_dir = PathBuf::from(string_from_ptr(target_dir, "target_dir")?);

        let mut client_options = VaultHttpProjectClientOptions::new(vault_base_url);
        client_options.bearer_token = bearer_token;
        let client =
            VaultHttpProjectClient::with_options(client_options).map_err(|err| err.to_string())?;
        let mut restore_options = VaultRestoreWithAwkOptions::new(awk);
        restore_options.project_id = project_id;
        let mut install_options = VaultInstallBodyOptions::new(target_dir);
        install_options.overwrite = overwrite != 0;
        let result = handle_ref(handle)?
            .tn()?
            .vault()
            .restore_and_install_body_with_awk_http_client(
                &client,
                restore_options,
                install_options,
            )
            .map_err(|err| err.to_string())?;

        let mut body_member_names = result.restore.body.keys().cloned().collect::<Vec<_>>();
        body_member_names.sort();
        let total_body_bytes: usize = result.restore.body.values().map(Vec::len).sum();
        let written_paths: Vec<_> = result
            .install
            .written_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let deduped_paths: Vec<_> = result
            .install
            .deduped_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        serde_json::to_string(&json!({
            "project_id": result.restore.project_id,
            "body_member_count": body_member_names.len(),
            "total_body_bytes": total_body_bytes,
            "body_member_names": body_member_names,
            "target_dir": result.install.target_dir.to_string_lossy(),
            "yaml_path": result.install.yaml_path.to_string_lossy(),
            "keys_dir": result.install.keys_dir.to_string_lossy(),
            "written_paths": written_paths,
            "deduped_paths": deduped_paths,
            "skipped_members": result.install.skipped_members,
            "wrapped_key": {
                "wrapped_bek_b64": result.restore.wrapped_key.wrapped_bek_b64,
                "wrap_nonce_b64": result.restore.wrapped_key.wrap_nonce_b64,
            },
            "encrypted_blob_response": result.restore.encrypted_blob_response,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Mint fresh reader kits for one recipient and export them as a kit bundle.
///
/// `groups_json` may be null/empty for all non-internal groups or a JSON
/// string array. `seal_for_recipient` is treated as false when set to 0 and
/// true otherwise. The returned string is owned by the caller and must be
/// released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_bundle_for_recipient(
    handle: *const TnHandle,
    recipient_did: *const c_char,
    out_path: *const c_char,
    groups_json: *const c_char,
    seal_for_recipient: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let recipient_did = string_from_ptr(recipient_did, "recipient_did")?;
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let groups = match optional_string_from_ptr(groups_json, "groups_json")? {
            Some(groups_json) => Some(
                serde_json::from_str::<Vec<String>>(&groups_json)
                    .map_err(|err| format!("groups_json must be a JSON string array: {err}"))?,
            ),
            None => None,
        };
        let result = handle_ref(handle)?
            .tn()?
            .pkg()
            .bundle_for_recipient(
                recipient_did,
                &out_path,
                tn_proto::BundleForRecipientOptions {
                    groups,
                    seal_for_recipient: seal_for_recipient != 0,
                },
            )
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "path": result.path.to_string_lossy(),
            "recipient_did": result.recipient_did,
            "groups": result.groups,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Compile a recipient enrolment handoff package.
///
/// `seal_for_recipient` is treated as false when set to 0 and true otherwise.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_compile_enrolment(
    handle: *const TnHandle,
    group: *const c_char,
    recipient_did: *const c_char,
    out_path: *const c_char,
    seal_for_recipient: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let recipient_did = string_from_ptr(recipient_did, "recipient_did")?;
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let result = handle_ref(handle)?
            .tn()?
            .pkg()
            .compile_enrolment(tn_proto::CompileEnrolmentOptions {
                group,
                recipient_did,
                out_path,
                seal_for_recipient: seal_for_recipient != 0,
            })
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "path": result.path.to_string_lossy(),
            "recipient_did": result.recipient_did,
            "groups": result.groups,
            "manifest_sha256": result.manifest_sha256,
            "package_sha256": result.package_sha256,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Compile an offer package and emit a local offer attestation.
///
/// `seal_for_recipient` is treated as false when set to 0 and true otherwise.
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_offer(
    handle: *const TnHandle,
    group: *const c_char,
    peer_did: *const c_char,
    out_path: *const c_char,
    seal_for_recipient: i32,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let group = string_from_ptr(group, "group")?;
        let peer_did = string_from_ptr(peer_did, "peer_did")?;
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let result = handle_ref(handle)?
            .tn()?
            .pkg()
            .offer(tn_proto::OfferOptions {
                group,
                peer_did,
                out_path,
                seal_for_recipient: seal_for_recipient != 0,
            })
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&json!({
            "path": result.path.to_string_lossy(),
            "group": result.group,
            "peer_did": result.peer_did,
            "package_sha256": result.package_sha256,
            "status": result.status,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Inspect a package from disk without absorbing it.
///
/// Invalid manifest signatures are reported in the JSON payload rather than as
/// FFI errors. Parse errors still return null; use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_inspect_path(
    handle: *const TnHandle,
    source_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let source_path = PathBuf::from(string_from_ptr(source_path, "source_path")?);
        let info = handle_ref(handle)?
            .tn()?
            .pkg()
            .inspect_path(&source_path)
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&package_info_json(info)).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Absorb a package from disk.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_pkg_absorb_path(
    handle: *const TnHandle,
    source_path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let source_path = PathBuf::from(string_from_ptr(source_path, "source_path")?);
        let receipt = handle_ref(handle)?
            .tn()?
            .pkg()
            .absorb_path(&source_path)
            .map_err(|err| err.to_string())?;
        let replaced_kit_paths: Vec<_> = receipt
            .replaced_kit_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        serde_json::to_string(&json!({
            "kind": receipt.kind,
            "status": format!("{:?}", receipt.status()).to_ascii_lowercase(),
            "accepted_count": receipt.accepted_count,
            "deduped_count": receipt.deduped_count,
            "noop": receipt.noop,
            "conflict_count": receipt.conflicts.len(),
            "legacy_status": receipt.legacy_status,
            "legacy_reason": receipt.legacy_reason,
            "replaced_kit_paths": replaced_kit_paths,
        }))
        .map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// List local `tn-invite-*.zip` files in a directory.
///
/// Missing directories return an empty list. The returned string is owned by
/// the caller and must be released with [`tn_string_free`]. Returns null on
/// error. Use [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_inbox_list_local(
    handle: *const TnHandle,
    dir: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let dir = PathBuf::from(string_from_ptr(dir, "dir")?);
        let paths = handle_ref(handle)?
            .tn()?
            .inbox()
            .list_local(&dir)
            .map_err(|err| err.to_string())?;
        let paths: Vec<_> = paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        serde_json::to_string(&paths).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Inspect a local invitation zip without accepting it.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_inbox_inspect_path(
    handle: *const TnHandle,
    path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let path = PathBuf::from(string_from_ptr(path, "path")?);
        let info = handle_ref(handle)?
            .tn()?
            .inbox()
            .inspect_path(&path)
            .map_err(|err| err.to_string())?;
        let value = invitation_info_json(info)?;
        serde_json::to_string(&value).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Accept a local invitation zip into the active ceremony.
///
/// The returned string is owned by the caller and must be released with
/// [`tn_string_free`]. Returns null on error. Use [`tn_last_error`] for
/// details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_inbox_accept_path(
    handle: *const TnHandle,
    path: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let path = PathBuf::from(string_from_ptr(path, "path")?);
        let result = handle_ref(handle)?
            .tn()?
            .inbox()
            .accept_path(&path)
            .map_err(|err| err.to_string())?;
        let value = invitation_accept_result_json(result)?;
        serde_json::to_string(&value).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Mint a local invitation zip.
///
/// `options_json` may be null/empty or a JSON object containing `group`,
/// `from_email`, `project_id`, `project_name`, `note`, `invitation_id`, and
/// `provenance` string fields. The returned string is owned by the caller and
/// must be released with [`tn_string_free`]. Returns null on error. Use
/// [`tn_last_error`] for details.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_inbox_mint_invite_path(
    handle: *const TnHandle,
    recipient: *const c_char,
    out_path: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    clear_error();
    match take_result(|| {
        let recipient = string_from_ptr(recipient, "recipient")?;
        let out_path = PathBuf::from(string_from_ptr(out_path, "out_path")?);
        let options = match optional_string_from_ptr(options_json, "options_json")? {
            Some(options_json) => {
                let value: Value = serde_json::from_str(&options_json)
                    .map_err(|err| format!("options_json must be valid JSON: {err}"))?;
                let object = value
                    .as_object()
                    .ok_or_else(|| "options_json must be a JSON object".to_string())?;
                tn_proto::MintInvitationOptions {
                    group: optional_json_string(object, "group")?,
                    from_email: optional_json_string(object, "from_email")?,
                    project_id: optional_json_string(object, "project_id")?,
                    project_name: optional_json_string(object, "project_name")?,
                    note: optional_json_string(object, "note")?,
                    invitation_id: optional_json_string(object, "invitation_id")?,
                    provenance: optional_json_string(object, "provenance")?,
                }
            }
            None => tn_proto::MintInvitationOptions::default(),
        };
        let result = handle_ref(handle)?
            .tn()?
            .inbox()
            .mint_invite_path(&recipient, &out_path, options)
            .map_err(|err| err.to_string())?;
        let value = mint_invitation_result_json(result)?;
        serde_json::to_string(&value).map_err(|err| err.to_string())
    }) {
        Ok(value) => into_c_string_ptr(value),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

/// Close and free a runtime handle.
///
/// Returns 0 on success and -1 on error.
#[no_mangle]
pub unsafe extern "C" fn tn_runtime_close(handle: *mut TnHandle) -> i32 {
    clear_error();
    if handle.is_null() {
        set_error("handle must not be null");
        return -1;
    }

    match take_result(|| {
        let mut boxed = Box::from_raw(handle);
        if let Some(tn) = boxed.tn.take() {
            tn.close().map_err(|err| err.to_string())?;
        }
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).expect("test string contains an interior NUL")
    }

    fn last_error_message() -> Option<String> {
        LAST_ERROR.with(|slot| slot.borrow().clone())
    }

    /// Take ownership of a returned C string, assert the call succeeded,
    /// and free it through the public ABI like a real consumer would.
    unsafe fn consume(ptr: *mut c_char) -> String {
        assert!(
            !ptr.is_null(),
            "ffi call failed: {:?}",
            last_error_message()
        );
        let s = CStr::from_ptr(ptr)
            .to_str()
            .expect("ffi returned non-UTF-8")
            .to_owned();
        tn_string_free(ptr);
        s
    }

    /// Create a hermetic project ceremony inside `dir` and return its handle.
    unsafe fn open_project(dir: &std::path::Path, project: &str) -> *mut TnHandle {
        let project = c(project);
        let project_dir = c(dir.to_str().expect("tempdir path is not UTF-8"));
        let handle = tn_runtime_init_project(project.as_ptr(), project_dir.as_ptr());
        assert!(
            !handle.is_null(),
            "init_project failed: {:?}",
            last_error_message()
        );
        handle
    }

    unsafe fn emit_json(handle: *mut TnHandle, event_type: &str, fields: &str) -> Value {
        let level = c("info");
        let event_type = c(event_type);
        let fields = c(fields);
        let receipt = consume(tn_runtime_emit(
            handle,
            level.as_ptr(),
            event_type.as_ptr(),
            fields.as_ptr(),
        ));
        serde_json::from_str(&receipt).expect("emit receipt is not JSON")
    }

    unsafe fn emit_with_aad_json(
        handle: *mut TnHandle,
        event_type: &str,
        fields: &str,
        aad: &str,
    ) -> Value {
        let level = c("info");
        let event_type = c(event_type);
        let fields = c(fields);
        let aad = c(aad);
        let receipt = consume(tn_runtime_emit_with_aad(
            handle,
            level.as_ptr(),
            event_type.as_ptr(),
            fields.as_ptr(),
            aad.as_ptr(),
        ));
        serde_json::from_str(&receipt).expect("emit receipt is not JSON")
    }

    unsafe fn read_entries(handle: *mut TnHandle) -> Vec<Value> {
        let json = consume(tn_runtime_read(handle, 0, 0));
        serde_json::from_str::<Value>(&json)
            .expect("read result is not JSON")
            .as_array()
            .expect("read result is not an array")
            .clone()
    }

    unsafe fn seal_wire(
        handle: *mut TnHandle,
        object_type: &str,
        fields: &str,
        options: Option<&str>,
    ) -> String {
        let object_type = c(object_type);
        let fields = c(fields);
        let options_c = options.map(c);
        consume(tn_runtime_seal(
            handle,
            object_type.as_ptr(),
            fields.as_ptr(),
            options_c.as_ref().map_or(ptr::null(), |o| o.as_ptr()),
        ))
    }

    unsafe fn unseal_raw(
        handle: *mut TnHandle,
        source: &str,
        options: Option<&str>,
    ) -> *mut c_char {
        let source = c(source);
        let options_c = options.map(c);
        tn_runtime_unseal(
            handle,
            source.as_ptr(),
            options_c.as_ref().map_or(ptr::null(), |o| o.as_ptr()),
        )
    }

    #[test]
    fn emit_with_aad_binds_markers_and_reads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_aad");

            let receipt = emit_with_aad_json(
                handle,
                "payment.flagged",
                r#"{"secret_note":"escalate"}"#,
                r#"{"purpose":"audit"}"#,
            );
            assert_eq!(receipt["emitted"], Value::Bool(true));
            let echoed = receipt["envelope"]["tn_aad"]
                .as_str()
                .expect("envelope missing tn_aad echo");
            let echoed: Value = serde_json::from_str(echoed).expect("tn_aad echo is not JSON");
            assert_eq!(echoed["default"]["purpose"], Value::String("audit".into()));

            // The group still opens on read: the reader reconstructs the
            // bound AAD from the public tn_aad echo.
            let entries = read_entries(handle);
            let entry = entries
                .iter()
                .find(|e| e["event_type"] == "payment.flagged")
                .expect("emitted entry not visible to read");
            assert_eq!(entry["secret_note"], Value::String("escalate".into()));
            let read_echo = entry["tn_aad"].as_str().expect("read entry missing tn_aad");
            let read_echo: Value =
                serde_json::from_str(read_echo).expect("read tn_aad echo is not JSON");
            assert_eq!(
                read_echo["default"]["purpose"],
                Value::String("audit".into())
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    #[test]
    fn emit_with_aad_empty_map_matches_plain_emit_wire_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_aad_empty");

            let with_empty =
                emit_with_aad_json(handle, "payment.plain", r#"{"secret_note":"quiet"}"#, "{}");
            let plain = emit_json(handle, "payment.plain", r#"{"secret_note":"quiet"}"#);

            for receipt in [&with_empty, &plain] {
                assert_eq!(receipt["emitted"], Value::Bool(true));
                let envelope = receipt["envelope"]
                    .as_object()
                    .expect("receipt envelope is not an object");
                assert!(
                    !envelope.contains_key("tn_aad"),
                    "empty aad must not add a tn_aad field"
                );
            }

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    #[test]
    fn emit_with_aad_rejects_non_object_aad() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_aad_reject");

            let level = c("info");
            let event_type = c("payment.bad_aad");
            let fields = c(r#"{"ok":true}"#);
            let aad = c(r#"["not","an","object"]"#);
            let result = tn_runtime_emit_with_aad(
                handle,
                level.as_ptr(),
                event_type.as_ptr(),
                fields.as_ptr(),
                aad.as_ptr(),
            );
            assert!(result.is_null(), "array aad must be rejected");
            let message = last_error_message().expect("rejection must set tn_last_error");
            assert!(
                message.contains("aad_json must be a JSON object"),
                "unexpected error: {message}"
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    const POLICY_MD: &str = "# TN Agents Policy\n\
        version: 1\n\
        schema: tn-agents-policy@v1\n\
        \n\
        ## deal.approved\n\
        \n\
        ### instruction\n\
        Record one approved deal.\n\
        \n\
        ### use_for\n\
        Deal reporting.\n\
        \n\
        ### do_not_use_for\n\
        Compensation decisions.\n\
        \n\
        ### consequences\n\
        Exposure violates the deal desk policy.\n\
        \n\
        ### on_violation_or_error\n\
        Escalate to compliance.\n";

    #[test]
    fn agent_policy_doc_loads_after_file_write_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_agents");

            // No policy file yet: the accessor returns the JSON literal null.
            assert_eq!(consume(tn_runtime_agent_policy_doc(handle)), "null");

            // Drop the policy under the ceremony yaml dir, then reopen so
            // the core reloads it and auto-publishes on the hash change.
            let yaml_path = consume(tn_runtime_yaml_path(handle));
            let yaml_dir = std::path::Path::new(&yaml_path)
                .parent()
                .expect("yaml path has a parent")
                .to_path_buf();
            let config_dir = yaml_dir.join(".tn").join("config");
            std::fs::create_dir_all(&config_dir).expect("create policy dir");
            std::fs::write(config_dir.join("agents.md"), POLICY_MD).expect("write policy");
            assert_eq!(tn_runtime_close(handle), 0);

            let yaml_c = c(&yaml_path);
            let handle = tn_runtime_open(yaml_c.as_ptr());
            assert!(
                !handle.is_null(),
                "reopen failed: {:?}",
                last_error_message()
            );

            let doc: Value = serde_json::from_str(&consume(tn_runtime_agent_policy_doc(handle)))
                .expect("policy doc is not JSON");
            assert_eq!(doc["version"], Value::String("1".into()));
            assert!(doc["content_hash"]
                .as_str()
                .expect("policy doc missing content_hash")
                .starts_with("sha256:"));
            assert_eq!(
                doc["templates"]["deal.approved"]["instruction"],
                Value::String("Record one approved deal.".into())
            );

            // The reopen emitted tn.agents.policy_published onto the
            // ceremony's admin/protocol surface.
            let admin_log = yaml_dir.join("admin").join("default.ndjson");
            let admin_text = std::fs::read_to_string(&admin_log).expect("admin log missing");
            assert!(
                admin_text.contains("tn.agents.policy_published"),
                "policy_published event not on the admin surface"
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    #[test]
    fn ffi_seal_unseal_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_seal");

            let wire = seal_wire(
                handle,
                "obj.invoice.v1",
                r#"{"amount":9800,"customer":"acme"}"#,
                Some(r#"{"receipt":false}"#),
            );
            assert!(
                !wire.ends_with('\n'),
                "wire line must carry no trailing newline"
            );
            let sealed: Value = serde_json::from_str(&wire).expect("wire is not JSON");
            assert_eq!(sealed["sequence"], json!(0));
            assert_eq!(sealed["prev_hash"], json!(""));
            assert_eq!(sealed["tn_sealed"], json!(1));
            assert!(
                sealed.get("amount").is_none(),
                "fields must not ride in the clear"
            );
            assert!(sealed["default"]["ciphertext"].is_string());
            // receipt:false wrote nothing onto the admin surface.
            let yaml_path = consume(tn_runtime_yaml_path(handle));
            let admin_log = std::path::Path::new(&yaml_path)
                .parent()
                .expect("yaml path has a parent")
                .join("admin")
                .join("default.ndjson");
            let admin_text = std::fs::read_to_string(&admin_log).unwrap_or_default();
            assert!(
                !admin_text.contains("tn.object.sealed"),
                "receipt:false must not write a receipt row"
            );

            let outcome: Value =
                serde_json::from_str(&consume(unseal_raw(handle, &wire, None)))
                    .expect("unseal outcome is not JSON");
            assert_eq!(outcome["valid"]["signature"], json!(true));
            assert_eq!(outcome["valid"]["row_hash"], json!(true));
            assert_eq!(
                outcome["fields"],
                json!({"amount": 9800, "customer": "acme"})
            );
            assert_eq!(outcome["plaintext"]["default"]["amount"], json!(9800));
            assert_eq!(outcome["hidden_groups"], json!([]));
            assert_eq!(outcome["sealed_blocks"], json!([]));
            assert_eq!(outcome["envelope"]["row_hash"], sealed["row_hash"]);
            assert_eq!(outcome["envelope"]["tn_sealed"], json!(1));
            assert!(
                outcome["fields"].get("tn_sealed").is_none(),
                "the wire marker must not leak into user fields"
            );

            // Default options chain a tn.object.sealed receipt row onto
            // the ceremony's admin surface.
            let _ = seal_wire(handle, "obj.invoice.v1", r#"{"amount":1}"#, None);
            let admin_text = std::fs::read_to_string(&admin_log).expect("admin log missing");
            assert!(
                admin_text.contains("tn.object.sealed"),
                "default seal must write the receipt row onto the admin surface"
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    #[test]
    fn ffi_unseal_verifyerror_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_seal_verify");

            let wire = seal_wire(
                handle,
                "obj.invoice.v1",
                r#"{"amount":1}"#,
                Some(r#"{"receipt":false}"#),
            );
            let tampered = wire.replace("\"tn_sealed\":1", "\"tn_sealed\":2");
            assert_ne!(wire, tampered, "wire must carry the compact marker to tamper");

            // Tampering a public value flips the recomputed row hash but
            // leaves the signature (over the untouched row_hash string)
            // valid, so failed_checks names row_hash alone.
            let result = unseal_raw(handle, &tampered, None);
            assert!(result.is_null(), "tampered object must fail verification");
            let message = last_error_message().expect("verify failure must set tn_last_error");
            let payload = message
                .strip_prefix("VerifyError:")
                .unwrap_or_else(|| panic!("expected VerifyError: prefix, got: {message}"));
            let parsed: Value =
                serde_json::from_str(payload).expect("VerifyError payload is not JSON");
            assert_eq!(parsed["failed_checks"], json!(["row_hash"]));
            assert_eq!(parsed["sequence"], json!(0));
            assert_eq!(parsed["event_type"], json!("obj.invoice.v1"));

            // verify:false returns the outcome despite the tamper, with
            // both valid flags reported false.
            let outcome: Value = serde_json::from_str(&consume(unseal_raw(
                handle,
                &tampered,
                Some(r#"{"verify":false}"#),
            )))
            .expect("unseal outcome is not JSON");
            assert_eq!(outcome["valid"], json!({"signature": false, "row_hash": false}));

            // Malformed input is the UnsealError: prefix, not a verify
            // failure and not a plain message.
            let malformed = unseal_raw(handle, "not a sealed object at all", None);
            assert!(malformed.is_null(), "malformed input must be rejected");
            let message = last_error_message().expect("malformed input must set tn_last_error");
            assert!(
                message.starts_with("UnsealError: "),
                "unexpected error: {message}"
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }

    /// The hibe admin exports marshal their guards through the error
    /// channel: a btn project rejects both verbs with the hibe-only
    /// messages. (The happy path needs a hibe ceremony's key material and
    /// is covered end-to-end by the tn-core suite and the C# SDK tests.)
    #[test]
    fn ffi_hibe_admin_verbs_are_hibe_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        unsafe {
            let handle = open_project(dir.path(), "ffi_hibe_admin");

            let group = c("default");
            let reader = c("did:key:z6Mk-reader");
            let out = c(dir
                .path()
                .join("reader.tnpkg")
                .to_str()
                .expect("tempdir path is not UTF-8"));
            let granted = tn_runtime_admin_grant_reader(
                handle,
                group.as_ptr(),
                reader.as_ptr(),
                out.as_ptr(),
                ptr::null(),
            );
            assert!(granted.is_null(), "btn group must reject grant_reader");
            let message = last_error_message().expect("guard must set tn_last_error");
            assert!(
                message.contains("grant_reader is hibe-only. Use add_recipient for btn/jwe groups."),
                "unexpected error: {message}"
            );

            let new_path = c("team/policy-b");
            let rotated = tn_runtime_admin_rotate_id_path(
                handle,
                group.as_ptr(),
                new_path.as_ptr(),
                0,
            );
            assert!(rotated.is_null(), "btn group must reject rotate_id_path");
            let message = last_error_message().expect("guard must set tn_last_error");
            assert!(
                message.contains("this rotation is hibe-only (btn groups rotate via tn rotate)."),
                "unexpected error: {message}"
            );

            assert_eq!(tn_runtime_close(handle), 0);
        }
    }
}
