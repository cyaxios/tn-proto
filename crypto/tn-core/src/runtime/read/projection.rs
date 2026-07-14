use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::super::{FlatEntry, Instructions, ReadEntry, SecureEntry, ValidFlags};

const FLAT_ENVELOPE_KEYS: [&str; 6] = [
    "timestamp",
    "event_type",
    "level",
    "did",
    "sequence",
    "event_id",
];
const CRYPTO_KEYS: [&str; 3] = ["prev_hash", "row_hash", "signature"];

pub(super) fn insert_validity_metadata(flat: &mut FlatEntry, validity: &ValidFlags) {
    flat.insert(
        "_valid".into(),
        serde_json::json!({
            "signature": validity.signature,
            "row_hash": validity.row_hash,
            "chain": validity.chain,
            "writer_authenticated": validity.writer_authenticated,
            "writer_authorized": validity.writer_authorized,
            "reasons": validity.reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
        }),
    );
}

pub(super) fn secure_entry_from_flat(mut flat: FlatEntry, forensic: bool) -> SecureEntry {
    retain_forensic_validity(&mut flat, forensic);
    let hidden_groups = take_string_array(&mut flat, "_hidden_groups");
    let decrypt_errors = take_string_array(&mut flat, "_decrypt_errors");
    let instructions = take_instructions(&mut flat);
    SecureEntry {
        fields: flat,
        instructions,
        hidden_groups,
        decrypt_errors,
    }
}

fn retain_forensic_validity(flat: &mut FlatEntry, forensic: bool) {
    let validity = flat.remove("_valid");
    if !forensic {
        return;
    }
    let Some(validity) = validity else {
        return;
    };
    let reasons = validity
        .get("reasons")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    flat.insert("_valid".into(), validity);
    if reasons.as_array().is_some_and(|items| !items.is_empty()) {
        flat.insert("_invalid_reasons".into(), reasons);
    }
}

fn take_instructions(flat: &mut FlatEntry) -> Option<Instructions> {
    let instructions = Instructions {
        instruction: take_string(flat, "instruction"),
        use_for: take_string(flat, "use_for"),
        do_not_use_for: take_string(flat, "do_not_use_for"),
        consequences: take_string(flat, "consequences"),
        on_violation_or_error: take_string(flat, "on_violation_or_error"),
        policy: take_string(flat, "policy"),
    };
    let empty = instructions.instruction.is_empty()
        && instructions.use_for.is_empty()
        && instructions.do_not_use_for.is_empty()
        && instructions.consequences.is_empty()
        && instructions.on_violation_or_error.is_empty()
        && instructions.policy.is_empty();
    (!empty).then_some(instructions)
}

fn take_string(flat: &mut FlatEntry, name: &str) -> String {
    flat.remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn take_string_array(flat: &mut FlatEntry, name: &str) -> Vec<String> {
    flat.remove(name)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// Project an audit-shaped entry into the flat shape returned by `Runtime::read`.
pub fn flatten_raw_entry(entry: &ReadEntry, _include_valid: bool) -> FlatEntry {
    let Value::Object(envelope) = &entry.envelope else {
        return Map::new();
    };
    let reserved = reserved_flat_keys();
    let mut flat = Map::new();
    copy_envelope_fields(envelope, &mut flat);
    copy_public_fields(envelope, &reserved, &mut flat);
    let decrypt_errors = merge_group_plaintext(entry, &mut flat);
    let hidden_groups = collect_hidden_groups(entry, envelope, &reserved);
    insert_group_markers(&mut flat, hidden_groups, decrypt_errors);
    flat
}

fn reserved_flat_keys() -> BTreeSet<&'static str> {
    FLAT_ENVELOPE_KEYS.into_iter().chain(CRYPTO_KEYS).collect()
}

fn copy_envelope_fields(envelope: &Map<String, Value>, flat: &mut FlatEntry) {
    for key in FLAT_ENVELOPE_KEYS {
        if let Some(value) = envelope.get(key) {
            flat.insert(key.into(), value.clone());
        }
    }
}

fn copy_public_fields(
    envelope: &Map<String, Value>,
    reserved: &BTreeSet<&str>,
    flat: &mut FlatEntry,
) {
    for (key, value) in envelope {
        let encrypted_group = value
            .as_object()
            .is_some_and(|object| object.contains_key("ciphertext"));
        if !reserved.contains(key.as_str()) && !encrypted_group {
            flat.insert(key.clone(), value.clone());
        }
    }
}

fn merge_group_plaintext(entry: &ReadEntry, flat: &mut FlatEntry) -> Vec<String> {
    let mut errors = Vec::new();
    for (group, body) in &entry.plaintext_per_group {
        let Some(fields) = body.as_object() else {
            continue;
        };
        if fields.get("$decrypt_error") == Some(&Value::Bool(true)) {
            errors.push(group.clone());
            continue;
        }
        if fields.get("$no_read_key") == Some(&Value::Bool(true)) {
            continue;
        }
        for (key, value) in fields {
            flat.insert(key.clone(), value.clone());
        }
    }
    errors
}

fn collect_hidden_groups(
    entry: &ReadEntry,
    envelope: &Map<String, Value>,
    reserved: &BTreeSet<&str>,
) -> Vec<String> {
    envelope
        .iter()
        .filter(|(key, value)| {
            !reserved.contains(key.as_str())
                && value
                    .as_object()
                    .is_some_and(|object| object.contains_key("ciphertext"))
        })
        .filter(|(key, _)| {
            entry.plaintext_per_group.get(*key).is_none_or(|body| {
                body.as_object()
                    .is_some_and(|object| object.get("$no_read_key") == Some(&Value::Bool(true)))
            })
        })
        .map(|(key, _)| key.clone())
        .collect()
}

fn insert_group_markers(
    flat: &mut FlatEntry,
    mut hidden_groups: Vec<String>,
    mut decrypt_errors: Vec<String>,
) {
    insert_sorted_marker(flat, "_hidden_groups", &mut hidden_groups);
    insert_sorted_marker(flat, "_decrypt_errors", &mut decrypt_errors);
}

fn insert_sorted_marker(flat: &mut FlatEntry, name: &str, groups: &mut Vec<String>) {
    if groups.is_empty() {
        return;
    }
    groups.sort();
    flat.insert(
        name.into(),
        Value::Array(groups.drain(..).map(Value::String).collect()),
    );
}

pub(crate) fn merge_envelope(entry: &ReadEntry) -> Map<String, Value> {
    let mut merged = entry.envelope.as_object().cloned().unwrap_or_default();
    for value in entry.plaintext_per_group.values() {
        let Some(fields) = value.as_object() else {
            continue;
        };
        for (key, value) in fields {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

pub(crate) fn apply_schema_defaults(event_type: &str, mut merged: Map<String, Value>) -> Value {
    if event_type == "tn.recipient.added" && !merged.contains_key("cipher") {
        merged.insert("cipher".into(), Value::String("btn".into()));
    }
    if event_type == "tn.recipient.revoked" && !merged.contains_key("recipient_identity") {
        merged.insert("recipient_identity".into(), Value::Null);
    }
    Value::Object(merged)
}

pub(super) fn flat_in_current_run(flat: &FlatEntry, current_run_id: &str) -> bool {
    matches!(flat.get("run_id"), Some(Value::String(value)) if value == current_run_id)
}
