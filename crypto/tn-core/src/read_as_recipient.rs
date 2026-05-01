//! Decrypt a foreign publisher's ndjson log with a kit dropped into a
//! local keystore directory by `Runtime::absorb`.
//!
//! Mirrors Python `tn.read_as_recipient(log_path, keystore_dir, group=)`
//! and TS `readAsRecipient(logPath, keystorePath, opts?)`. Closes the
//! cross-binding gap surfaced by the cash-register Stage 6 + AVL J7
//! audits — Rust now has the same direct-decrypt verb its sibling
//! bindings ship.
//!
//! Dispatches on the kit file present in `keystore_path`:
//!
//! - `<group>.btn.mykit` → btn (subset-difference broadcast)
//! - `<group>.jwe.mykey` → JWE (NOT IMPLEMENTED in this port; we're
//!   btn-only for the current shipping default)
//!
//! Use this verb when the calling Rust app holds a kit handed to it via
//! a `kit_bundle` `.tnpkg` and needs to read another publisher's log.
//! It deliberately bypasses the full `Runtime` setup so cross-publisher
//! reads don't require a ceremony of your own.

use std::path::Path;

use serde_json::{Map, Value};

use crate::cipher::btn::BtnReaderCipher;
use crate::cipher::GroupCipher as _;
use crate::error::{Error, Result};
use crate::signing::{signature_from_b64, DeviceKey};

/// One decrypted entry from a foreign publisher's log. Mirrors the
/// shape that Python's `tn.read_as_recipient` and TS's
/// `readAsRecipient` yield.
#[derive(Debug, Clone)]
pub struct ForeignReadEntry {
    /// Raw envelope JSON (public fields, signatures, hashes, group
    /// ciphertext blocks). Same shape as anything `Runtime::read`
    /// would produce.
    pub envelope: Map<String, Value>,
    /// Decrypted group plaintext, keyed by group name. Only the group
    /// we have a kit for is present. A group whose ciphertext we
    /// couldn't decrypt is recorded with the marker key
    /// `"$no_read_key"` mapping to `true`.
    pub plaintext: Map<String, Value>,
    /// Per-row validity. `signature` is the public-key check against
    /// the envelope's `did`; `chain` is per-event-type prev_hash
    /// continuity. `row_hash` recomputation isn't run here — match
    /// Python/TS behavior, where signature verification is the
    /// cryptographic source of truth and a bad row_hash would
    /// invalidate the signature anyway.
    pub valid: ForeignValid,
}

/// Per-row validity flags for a foreign-read entry.
#[derive(Debug, Clone, Copy)]
pub struct ForeignValid {
    /// True iff the envelope's signature verifies under the publisher's `did`.
    pub signature: bool,
    /// True iff the envelope's `prev_hash` matches the previous
    /// envelope's `row_hash` for the same `event_type`.
    pub chain: bool,
}

/// Options controlling the foreign-read iteration.
#[derive(Debug, Clone)]
pub struct ReadAsRecipientOptions {
    /// Group name to decrypt. Default `"default"`.
    pub group: String,
    /// Verify per-row signatures (slower but catches forgery).
    /// Default `true`. Off for debug-only fast-paths where you only
    /// care about plaintext.
    pub verify_signatures: bool,
}

impl Default for ReadAsRecipientOptions {
    fn default() -> Self {
        Self {
            group: "default".into(),
            verify_signatures: true,
        }
    }
}

/// Iterate decrypted entries from `log_path` using a kit found in
/// `keystore_path`. Mirrors Python's `tn.read_as_recipient` and TS's
/// `readAsRecipient`. (AVL J7 / cash-register S6.2 cross-binding port.)
///
/// # Errors
///
/// - `Error::InvalidConfig` if no kit for `opts.group` exists in
///   `keystore_path` (looks for `<group>.btn.mykit` for btn; JWE keys
///   are not yet supported in Rust).
/// - `Error::Io` for file read failures.
/// - `Error::Json` for malformed JSON lines.
pub fn read_as_recipient(
    log_path: &Path,
    keystore_path: &Path,
    opts: ReadAsRecipientOptions,
) -> Result<Vec<ForeignReadEntry>> {
    let group = opts.group;
    let btn_kit_path = keystore_path.join(format!("{group}.btn.mykit"));
    let jwe_key_path = keystore_path.join(format!("{group}.jwe.mykey"));

    if !btn_kit_path.exists() {
        if jwe_key_path.exists() {
            return Err(Error::InvalidConfig(format!(
                "read_as_recipient: cipher=jwe is not implemented in tn-core. \
                 For JWE foreign reads, use the Python tn-protocol package or \
                 wait for the upcoming Rust JWE port. (group={group:?})"
            )));
        }
        return Err(Error::InvalidConfig(format!(
            "read_as_recipient: no recipient kit for group {group:?} in {}. \
             Looked for {} (btn) and {} (jwe). If you absorbed a kit_bundle, \
             the kit lands in your ceremony's keystore — point keystore_path there.",
            keystore_path.display(),
            btn_kit_path.display(),
            jwe_key_path.display(),
        )));
    }

    let kit_bytes = std::fs::read(&btn_kit_path).map_err(Error::Io)?;
    let cipher = BtnReaderCipher::from_kit_bytes(&kit_bytes)?;

    let text = std::fs::read_to_string(log_path).map_err(Error::Io)?;
    let mut entries: Vec<ForeignReadEntry> = Vec::new();
    let mut prev_hash_by_type: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();

    for raw_line in text.split('\n') {
        let s = raw_line.trim();
        if s.is_empty() {
            continue;
        }
        let env: Value = serde_json::from_str(s).map_err(Error::Json)?;
        let env_map = env
            .as_object()
            .ok_or_else(|| Error::Malformed {
                kind: "envelope",
                reason: "expected JSON object".into(),
            })?
            .clone();

        let event_type = env_map
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        if event_type.is_empty() {
            continue;
        }

        // Per-event-type chain check.
        let env_prev = env_map.get("prev_hash").and_then(Value::as_str);
        let env_row = env_map.get("row_hash").and_then(Value::as_str);
        let last = prev_hash_by_type.get(event_type);
        let chain_ok = match (last, env_prev) {
            (None, _) => true,
            (Some(prev), Some(env)) => prev == env,
            _ => false,
        };
        if let Some(rh) = env_row {
            prev_hash_by_type.insert(event_type.to_string(), rh.to_string());
        }

        // Decrypt the requested group when its ciphertext is present.
        // Three failure layers, each with its own sentinel:
        //   - base64 decode fails  → $decrypt_error (malformed wire bytes)
        //   - btn decrypt fails    → $no_read_key   (kit not entitled)
        //   - JSON parse fails     → $decrypt_error (decrypted to non-JSON)
        // Mirrors Python's tn.reader.read_as_recipient sentinels.
        let mut plaintext: Map<String, Value> = Map::new();
        if let Some(g_block) = env_map.get(&group).and_then(Value::as_object) {
            if let Some(ct) = g_block.get("ciphertext").and_then(Value::as_str) {
                let pt_value = decrypt_group_ciphertext(&cipher, ct);
                plaintext.insert(group.clone(), pt_value);
            }
        }

        // Signature verification.
        let mut sig_ok = true;
        if opts.verify_signatures {
            let did = env_map.get("did").and_then(Value::as_str);
            let sig_str = env_map.get("signature").and_then(Value::as_str);
            match (did, sig_str, env_row) {
                (Some(did), Some(sig_b64), Some(row)) => {
                    sig_ok = match signature_from_b64(sig_b64) {
                        Ok(sig_bytes) => {
                            DeviceKey::verify_did(did, row.as_bytes(), &sig_bytes).unwrap_or(false)
                        }
                        Err(_) => false,
                    };
                }
                _ => sig_ok = false,
            }
        }

        entries.push(ForeignReadEntry {
            envelope: env_map,
            plaintext,
            valid: ForeignValid {
                signature: sig_ok,
                chain: chain_ok,
            },
        });
    }

    Ok(entries)
}

/// Try to decrypt a base64-encoded ciphertext with the given reader
/// kit, returning a JSON value. Three failure layers, each with its
/// own sentinel matching Python's `tn.reader.read_as_recipient`:
///
/// - base64 decode fails  → `{"$decrypt_error": true}`
/// - btn decrypt fails    → `{"$no_read_key":  true}` (kit not entitled)
/// - JSON parse fails     → `{"$decrypt_error": true}` (decrypted to non-JSON)
fn decrypt_group_ciphertext(cipher: &BtnReaderCipher, ct_b64: &str) -> Value {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let sentinel = |key: &str| -> Value {
        let mut m = Map::new();
        m.insert(key.to_string(), Value::Bool(true));
        Value::Object(m)
    };

    let Ok(ct_bytes) = STANDARD.decode(ct_b64) else {
        return sentinel("$decrypt_error");
    };
    let Ok(pt_bytes) = cipher.decrypt(&ct_bytes) else {
        return sentinel("$no_read_key");
    };
    let Ok(pt) = serde_json::from_slice::<Value>(&pt_bytes) else {
        return sentinel("$decrypt_error");
    };
    pt
}
