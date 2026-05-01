//! WebAssembly bindings for tn-core.
//!
//! Phase B surface: canonical, chain, signing, indexing, envelope, plus
//! the admin catalog from Phase A. btn encrypt/decrypt and JWE land in
//! Phase C so the Node CLI can round-trip real logs with Python.
//!
//! Invariants:
//! - JSON outputs must match what tn_core (via PyO3) produces in Python,
//!   byte for byte. The Rust reducer is the source of truth.
//! - No filesystem access. tn-core pulled in with default-features off.
//! - JS values round-trip through `JSON.stringify` / `JSON.parse` so
//!   `null` keys survive intact. See Phase A README for rationale.
//!
//! Naming: every exported function uses a camelCase `js_name` so the
//! `.d.ts` reads like idiomatic TypeScript. Internal Rust names stay
//! snake_case.

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

use tn_core::admin_catalog;
use tn_core::admin_reduce;
use tn_core::canonical;
use tn_core::chain;
use tn_core::envelope;
use tn_core::indexing;
use tn_core::signing::{self, DeviceKey};

use tn_btn::{
    Ciphertext as BtnCiphertext, Config as BtnConfig, LeafIndex,
    PublisherState as BtnPublisherState, ReaderKit as BtnReaderKit,
};

// ---------------------------------------------------------------------------
// JSON <-> JS bridge helpers
// ---------------------------------------------------------------------------

/// Parse a JS value (object, string, number, array, null) into a
/// `serde_json::Value`. Uses `JSON.stringify` on the JS side so we get a
/// plain string path and then parse with serde_json. This avoids the
/// `serde-wasm-bindgen` default of mapping `Option::None` to
/// `undefined`, which would drop keys like `recipient_did: null` on the
/// way out.
fn js_to_json(v: JsValue) -> Result<Value, JsError> {
    let s = js_sys::JSON::stringify(&v)
        .map_err(|e| JsError::new(&format!("JSON.stringify failed: {e:?}")))?
        .as_string()
        .ok_or_else(|| JsError::new("JSON.stringify did not return a string"))?;
    serde_json::from_str(&s).map_err(|e| JsError::new(&format!("serde_json::from_str: {e}")))
}

/// Inverse of `js_to_json`: render through `serde_json::to_string` and
/// `JSON.parse`. Keeps null keys intact.
fn json_to_js(v: &Value) -> Result<JsValue, JsError> {
    let s = serde_json::to_string(v)
        .map_err(|e| JsError::new(&format!("serde_json::to_string: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| JsError::new(&format!("JSON.parse failed: {e:?}")))
}

fn expect_object(v: Value, what: &str) -> Result<Map<String, Value>, JsError> {
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(JsError::new(&format!("{what} must be a JSON object"))),
    }
}

// ---------------------------------------------------------------------------
// Admin catalog / reduce (Phase A)
// ---------------------------------------------------------------------------

/// Reduce an envelope to a typed state delta.
///
/// `envelope` is a JS object matching the flat ndjson envelope shape
/// (top-level `event_type`, `did`, plus the catalog's admin fields).
///
/// Returns the JSON serialization of `StateDelta`, tagged with `kind`.
///
/// Errors propagate as JS exceptions (`Error`) with the reducer's message.
#[wasm_bindgen(js_name = "adminReduce")]
pub fn admin_reduce_js(envelope: JsValue) -> Result<JsValue, JsError> {
    let value = js_to_json(envelope)?;
    let delta = admin_reduce::reduce(&value).map_err(|e| JsError::new(&format!("{e}")))?;
    let delta_value =
        serde_json::to_value(&delta).map_err(|e| JsError::new(&format!("delta -> json: {e}")))?;
    json_to_js(&delta_value)
}

/// List the catalogued admin event kinds.
///
/// Returns `[{event_type, sign, sync, schema: [[name, type], ...]}, ...]`.
/// Schema types are strings: `string`, `optional_string`, `int`,
/// `optional_int`, `iso8601`.
#[wasm_bindgen(js_name = "adminCatalogKinds")]
pub fn admin_catalog_kinds_js() -> Result<JsValue, JsError> {
    let mut out = Vec::with_capacity(admin_catalog::CATALOG.len());
    for k in admin_catalog::CATALOG {
        let mut schema = Vec::with_capacity(k.schema.len());
        for (name, ftype) in k.schema {
            schema.push((*name, field_type_str(*ftype)));
        }
        out.push(serde_json::json!({
            "event_type": k.event_type,
            "sign": k.sign,
            "sync": k.sync,
            "schema": schema,
        }));
    }
    let out_value = Value::Array(out);
    json_to_js(&out_value)
}

/// Validate that `fields` match the catalog schema for `eventType`.
///
/// Throws on schema violation; returns `undefined` on success.
#[wasm_bindgen(js_name = "adminValidateEmit")]
pub fn admin_validate_emit_js(event_type: &str, fields: JsValue) -> Result<(), JsError> {
    let value = js_to_json(fields)?;
    let obj = value
        .as_object()
        .ok_or_else(|| JsError::new("fields must be an object"))?;
    admin_catalog::validate_emit(event_type, obj).map_err(|e| JsError::new(&format!("{e}")))
}

fn field_type_str(t: admin_catalog::FieldType) -> &'static str {
    use admin_catalog::FieldType;
    match t {
        FieldType::String => "string",
        FieldType::OptionalString => "optional_string",
        FieldType::Int => "int",
        FieldType::OptionalInt => "optional_int",
        FieldType::Iso8601 => "iso8601",
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/// Serialize a JSON value to canonical bytes (sorted keys, no whitespace).
///
/// Returns a `Uint8Array`. Byte-identical to
/// `tn.canonical.canonical_bytes` in Python.
#[wasm_bindgen(js_name = "canonicalBytes")]
pub fn canonical_bytes_js(value: JsValue) -> Result<Vec<u8>, JsError> {
    let v = js_to_json(value)?;
    canonical::canonical_bytes(&v).map_err(|e| JsError::new(&format!("{e}")))
}

/// Convenience: canonical bytes as a UTF-8 string. Callers who want the
/// raw bytes should use `canonicalBytes`. This variant is for `row_hash`
/// debugging in TS, which often wants a readable string.
#[wasm_bindgen(js_name = "canonicalJson")]
pub fn canonical_json_js(value: JsValue) -> Result<String, JsError> {
    let bytes = canonical_bytes_js(value)?;
    String::from_utf8(bytes).map_err(|e| JsError::new(&format!("canonical bytes not utf-8: {e}")))
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 device key.
///
/// Returns `{ seed: Uint8Array(32), publicKey: Uint8Array(32), did: string }`.
#[wasm_bindgen(js_name = "generateDeviceKey")]
pub fn generate_device_key_js() -> Result<JsValue, JsError> {
    let dk = DeviceKey::generate();
    device_key_to_js(&dk)
}

/// Load a device key from its 32-byte Ed25519 seed.
///
/// Returns `{ seed, publicKey, did }` matching `generateDeviceKey`.
#[wasm_bindgen(js_name = "deviceKeyFromSeed")]
pub fn device_key_from_seed_js(seed: &[u8]) -> Result<JsValue, JsError> {
    let dk = DeviceKey::from_private_bytes(seed).map_err(|e| JsError::new(&format!("{e}")))?;
    device_key_to_js(&dk)
}

/// Encode a 32-byte Ed25519 public key as `did:key:z…`.
#[wasm_bindgen(js_name = "deriveDidKey")]
pub fn derive_did_key_js(public_key: &[u8]) -> Result<String, JsError> {
    if public_key.len() != 32 {
        return Err(JsError::new("public key must be 32 bytes"));
    }
    // DeviceKey needs the private seed, but did:key derivation only
    // needs the public key. Implement the same bs58 multicodec path
    // directly rather than round-tripping through a DeviceKey.
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xed, 0x01]);
    buf.extend_from_slice(public_key);
    Ok(format!("did:key:z{}", bs58::encode(buf).into_string()))
}

/// Sign `message` with the 32-byte Ed25519 seed. Returns a 64-byte
/// signature.
#[wasm_bindgen(js_name = "signMessage")]
pub fn sign_message_js(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    let dk = DeviceKey::from_private_bytes(seed).map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(dk.sign(message).to_vec())
}

/// Verify a signature against an Ed25519 `did:key:z…` identity.
///
/// Returns `false` for non-Ed25519 DIDs (secp256k1 verify deferred to
/// match the Rust core policy), `true` only if the signature is valid.
#[wasm_bindgen(js_name = "verifyDid")]
pub fn verify_did_js(did: &str, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    DeviceKey::verify_did(did, message, signature).map_err(|e| JsError::new(&format!("{e}")))
}

/// URL-safe base64 (no padding) encoding of a signature. Mirror of
/// `tn.signing.signature_b64`.
#[wasm_bindgen(js_name = "signatureB64")]
pub fn signature_b64_js(sig: &[u8]) -> String {
    signing::signature_b64(sig)
}

/// Decode a URL-safe-no-padding base64 signature.
#[wasm_bindgen(js_name = "signatureFromB64")]
pub fn signature_from_b64_js(s: &str) -> Result<Vec<u8>, JsError> {
    signing::signature_from_b64(s).map_err(|e| JsError::new(&format!("{e}")))
}

fn device_key_to_js(dk: &DeviceKey) -> Result<JsValue, JsError> {
    use base64::Engine as _;
    // Round-trip through JSON.parse so the shape is a plain object, not
    // a Map (which happens with serde-wasm-bindgen default).
    let seed = base64::engine::general_purpose::STANDARD.encode(dk.private_bytes());
    let pk = base64::engine::general_purpose::STANDARD.encode(dk.public_bytes());
    let did = dk.did().to_string();
    let v = serde_json::json!({
        "seed_b64": seed,
        "public_key_b64": pk,
        "did": did,
    });
    json_to_js(&v)
}

// ---------------------------------------------------------------------------
// Indexing
// ---------------------------------------------------------------------------

/// Derive the per-group HKDF index key from a 32-byte master.
///
/// Info string: `b"tn-index:v1:" + ceremony + b":" + group + b":" + decimal(epoch)`.
/// Returns 32 bytes.
#[wasm_bindgen(js_name = "deriveGroupIndexKey")]
pub fn derive_group_index_key_js(
    master: &[u8],
    ceremony_id: &str,
    group_name: &str,
    epoch: u64,
) -> Result<Vec<u8>, JsError> {
    indexing::derive_group_index_key(master, ceremony_id, group_name, epoch)
        .map(|k| k.to_vec())
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Compute the keyed equality token `"hmac-sha256:v1:<hex>"` for a
/// (field_name, value) pair under a 32-byte group index key.
#[wasm_bindgen(js_name = "indexToken")]
pub fn index_token_js(
    group_index_key: &[u8],
    field_name: &str,
    value: JsValue,
) -> Result<String, JsError> {
    let v = js_to_json(value)?;
    indexing::index_token(group_index_key, field_name, &v)
        .map_err(|e| JsError::new(&format!("{e}")))
}

// ---------------------------------------------------------------------------
// Chain / row hash
// ---------------------------------------------------------------------------

/// Zero-initialized prev_hash used for the first row in a new
/// event_type chain.
#[wasm_bindgen(js_name = "zeroHash")]
pub fn zero_hash_js() -> String {
    chain::ZERO_HASH.to_string()
}

/// Compute a row_hash.
///
/// `input` is a JSON object with:
/// ```json
/// {
///   "did": string,
///   "timestamp": string,
///   "event_id": string,
///   "event_type": string,
///   "level": string,
///   "prev_hash": string,
///   "public_fields": { [key]: value },
///   "groups": {
///     [group_name]: {
///       "ciphertext_b64": string,   // standard base64
///       "field_hashes": { [field_name]: token_string }
///     }
///   }
/// }
/// ```
///
/// Returns `"sha256:<64-hex>"`.
#[wasm_bindgen(js_name = "computeRowHash")]
pub fn compute_row_hash_js(input: JsValue) -> Result<String, JsError> {
    use base64::Engine as _;
    let v = js_to_json(input)?;
    let obj = expect_object(v, "rowHash input")?;

    let did = str_field(&obj, "did")?;
    let timestamp = str_field(&obj, "timestamp")?;
    let event_id = str_field(&obj, "event_id")?;
    let event_type = str_field(&obj, "event_type")?;
    let level = str_field(&obj, "level")?;
    let prev_hash = str_field(&obj, "prev_hash")?;

    let public_fields_raw = obj
        .get("public_fields")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let public_fields_map = expect_object(public_fields_raw, "public_fields")?;
    let public_fields: BTreeMap<String, Value> = public_fields_map.into_iter().collect();

    let groups_raw = obj
        .get("groups")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let groups_map = expect_object(groups_raw, "groups")?;

    let mut groups = BTreeMap::<String, chain::GroupInput>::new();
    for (gname, gval) in groups_map {
        let gobj = expect_object(gval, "group entry")?;
        let ct_b64 = gobj
            .get("ciphertext_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new("group.ciphertext_b64 missing or not a string"))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|e| JsError::new(&format!("ciphertext_b64: {e}")))?;
        let fh_raw = gobj
            .get("field_hashes")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let fh_map = expect_object(fh_raw, "group.field_hashes")?;
        let mut fh = BTreeMap::<String, String>::new();
        for (fname, fval) in fh_map {
            let tok = fval
                .as_str()
                .ok_or_else(|| JsError::new("field_hashes values must be strings"))?;
            fh.insert(fname, tok.to_string());
        }
        groups.insert(
            gname,
            chain::GroupInput {
                ciphertext,
                field_hashes: fh,
            },
        );
    }

    let input_ref = chain::RowHashInput {
        did: &did,
        timestamp: &timestamp,
        event_id: &event_id,
        event_type: &event_type,
        level: &level,
        prev_hash: &prev_hash,
        public_fields: &public_fields,
        groups: &groups,
    };
    Ok(chain::compute_row_hash(&input_ref))
}

fn str_field(obj: &Map<String, Value>, k: &str) -> Result<String, JsError> {
    obj.get(k)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| JsError::new(&format!("field {k:?} missing or not a string")))
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// Build an envelope ndjson line (9 mandatory fields, then public, then
/// group payloads), followed by a trailing `\n`.
///
/// `input` shape:
/// ```json
/// {
///   "did": string, "timestamp": string, "event_id": string,
///   "event_type": string, "level": string, "sequence": number,
///   "prev_hash": string, "row_hash": string, "signature_b64": string,
///   "public_fields": { [key]: value },
///   "group_payloads": { [group]: { "ciphertext": "<b64>", "field_hashes": {...} } }
/// }
/// ```
///
/// Public fields + group payloads preserve insertion order.
#[wasm_bindgen(js_name = "buildEnvelope")]
pub fn build_envelope_js(input: JsValue) -> Result<String, JsError> {
    let v = js_to_json(input)?;
    let obj = expect_object(v, "envelope input")?;

    let did = str_field(&obj, "did")?;
    let timestamp = str_field(&obj, "timestamp")?;
    let event_id = str_field(&obj, "event_id")?;
    let event_type = str_field(&obj, "event_type")?;
    let level = str_field(&obj, "level")?;
    let sequence = obj
        .get("sequence")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| JsError::new("sequence missing or not a non-negative integer"))?;
    let prev_hash = str_field(&obj, "prev_hash")?;
    let row_hash = str_field(&obj, "row_hash")?;
    let signature_b64 = str_field(&obj, "signature_b64")?;

    let public_fields = obj
        .get("public_fields")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let public_fields = expect_object(public_fields, "public_fields")?;

    let group_payloads = obj
        .get("group_payloads")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let group_payloads = expect_object(group_payloads, "group_payloads")?;

    let ein = envelope::EnvelopeInput {
        did: &did,
        timestamp: &timestamp,
        event_id: &event_id,
        event_type: &event_type,
        level: &level,
        sequence,
        prev_hash: &prev_hash,
        row_hash: &row_hash,
        signature_b64: &signature_b64,
        public_fields,
        group_payloads,
    };
    envelope::build_envelope(ein).map_err(|e| JsError::new(&format!("{e}")))
}

// ---------------------------------------------------------------------------
// btn cipher
// ---------------------------------------------------------------------------

/// Publisher-side btn state.
///
/// Wraps `tn_btn::PublisherState`. The constructor is equivalent to
/// `BtnPublisher.new(seed)` in Python: if `seed` is 32 bytes, the
/// publisher is deterministic; otherwise a random seed is generated.
///
/// All mutating operations (`mint`, `revokeByLeaf`, `revokeKit`) change
/// internal state. Persist via `toBytes()` / restore via
/// `BtnPublisher.fromBytes()`.
#[wasm_bindgen]
pub struct BtnPublisher {
    inner: BtnPublisherState,
}

#[wasm_bindgen]
impl BtnPublisher {
    /// Create a publisher. Pass `null` for a random seed, or a 32-byte
    /// `Uint8Array` for a deterministic one.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: Option<Vec<u8>>) -> Result<BtnPublisher, JsError> {
        let inner = match seed {
            None => {
                BtnPublisherState::setup(BtnConfig).map_err(|e| JsError::new(&format!("{e}")))?
            }
            Some(s) => {
                if s.len() != 32 {
                    return Err(JsError::new(&format!(
                        "seed must be 32 bytes, got {}",
                        s.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s);
                BtnPublisherState::setup_with_seed(BtnConfig, arr)
                    .map_err(|e| JsError::new(&format!("{e}")))?
            }
        };
        Ok(Self { inner })
    }

    /// Restore a publisher state from bytes previously produced by
    /// [`Self::to_bytes`].
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<BtnPublisher, JsError> {
        let inner =
            BtnPublisherState::from_bytes(bytes).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(Self { inner })
    }

    /// 32-byte publisher identifier. Stable for the lifetime of this state.
    #[wasm_bindgen(js_name = "publisherId")]
    pub fn publisher_id(&self) -> Vec<u8> {
        self.inner.publisher_id().to_vec()
    }

    /// Current epoch counter.
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    /// Number of currently-active reader kits.
    #[wasm_bindgen(js_name = "issuedCount")]
    pub fn issued_count(&self) -> usize {
        self.inner.issued_count()
    }

    /// Number of revoked reader kits.
    #[wasm_bindgen(js_name = "revokedCount")]
    pub fn revoked_count(&self) -> usize {
        self.inner.revoked_count()
    }

    /// Tree height for this build.
    #[wasm_bindgen(js_name = "treeHeight")]
    pub fn tree_height(&self) -> u8 {
        tn_btn::config::TREE_HEIGHT
    }

    /// Maximum readers this publisher can ever mint.
    #[wasm_bindgen(js_name = "maxLeaves")]
    pub fn max_leaves(&self) -> u64 {
        tn_btn::config::MAX_LEAVES
    }

    /// Mint a fresh reader kit. Returns its wire bytes (tnpkg-equivalent).
    pub fn mint(&mut self) -> Result<Vec<u8>, JsError> {
        let kit = self
            .inner
            .mint()
            .map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(kit.to_bytes())
    }

    /// Revoke a reader by its kit bytes. Idempotent.
    #[wasm_bindgen(js_name = "revokeKit")]
    pub fn revoke_kit(&mut self, kit_bytes: &[u8]) -> Result<(), JsError> {
        let kit = BtnReaderKit::from_bytes(kit_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
        self.inner
            .revoke(&kit)
            .map_err(|e| JsError::new(&format!("{e}")))
    }

    /// Revoke a reader by leaf index. Idempotent.
    #[wasm_bindgen(js_name = "revokeByLeaf")]
    pub fn revoke_by_leaf(&mut self, leaf: u64) -> Result<(), JsError> {
        self.inner
            .revoke_by_leaf(LeafIndex(leaf))
            .map_err(|e| JsError::new(&format!("{e}")))
    }

    /// Encrypt `plaintext` for all currently-active readers. Returns
    /// serialized ciphertext bytes.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let ct = self
            .inner
            .encrypt(plaintext)
            .map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(ct.to_bytes())
    }

    /// Serialize this publisher state for persistence. Treat as secret.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// Decrypt `ctBytes` with `kitBytes`. Returns plaintext bytes. Throws
/// on NotEntitled or malformed input.
#[wasm_bindgen(js_name = "btnDecrypt")]
pub fn btn_decrypt_js(kit_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let kit = BtnReaderKit::from_bytes(kit_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
    let ct = BtnCiphertext::from_bytes(ct_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
    kit.decrypt(&ct).map_err(|e| JsError::new(&format!("{e}")))
}

/// Extract the 32-byte publisher_id from a ciphertext.
#[wasm_bindgen(js_name = "btnCiphertextPublisherId")]
pub fn btn_ciphertext_publisher_id_js(ct_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let ct = BtnCiphertext::from_bytes(ct_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(ct.publisher_id.to_vec())
}

/// Extract the 32-byte publisher_id from a reader kit.
#[wasm_bindgen(js_name = "btnKitPublisherId")]
pub fn btn_kit_publisher_id_js(kit_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let kit = BtnReaderKit::from_bytes(kit_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(kit.publisher_id().to_vec())
}

/// Extract the leaf index (u64) from a reader kit.
#[wasm_bindgen(js_name = "btnKitLeaf")]
pub fn btn_kit_leaf_js(kit_bytes: &[u8]) -> Result<u64, JsError> {
    let kit = BtnReaderKit::from_bytes(kit_bytes).map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(kit.leaf().0)
}

/// Tree height constant.
#[wasm_bindgen(js_name = "btnTreeHeight")]
pub fn btn_tree_height_js() -> u8 {
    tn_btn::config::TREE_HEIGHT
}

/// Max leaves constant.
#[wasm_bindgen(js_name = "btnMaxLeaves")]
pub fn btn_max_leaves_js() -> u64 {
    tn_btn::config::MAX_LEAVES
}
