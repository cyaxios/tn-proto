use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};

use crate::chain::{compute_row_hash, GroupInput, RowHashInput};
use crate::signing::{signature_from_b64, DeviceKey};

use super::super::{ReadEntry, ReadRecordState};

pub(super) struct PreparedRecord {
    pub(super) entry: ReadEntry,
    pub(super) record: ReadRecordState,
    pub(super) group_inputs: BTreeMap<String, GroupInput>,
}

pub(super) fn invalid_record(envelope: Value) -> PreparedRecord {
    PreparedRecord {
        entry: ReadEntry {
            envelope,
            plaintext_per_group: BTreeMap::new(),
        },
        record: ReadRecordState {
            record_valid: false,
            row_hash_present: false,
            row_hash_valid: false,
            chain_valid: false,
            signature_present: false,
            signature_valid: false,
            writer_did: None,
            aad_valid: true,
            recipient_groups: BTreeSet::new(),
        },
        group_inputs: BTreeMap::new(),
    }
}

pub(super) fn prepare_record(
    line: &str,
    prev_hash_by_event: &mut HashMap<String, String>,
) -> PreparedRecord {
    let Ok(envelope) = serde_json::from_str::<Value>(line) else {
        return invalid_record(serde_json::json!({"event_type": "<parse-error>"}));
    };
    prepare_envelope(envelope, prev_hash_by_event)
}

pub(super) fn prepare_envelope(
    envelope: Value,
    prev_hash_by_event: &mut HashMap<String, String>,
) -> PreparedRecord {
    let Some(object) = envelope.as_object() else {
        return invalid_record(envelope);
    };
    let fields = EnvelopeFields::from_object(object);
    let (groups, recipient_groups, groups_valid) = extract_group_inputs(object);
    let record_valid = fields.required_shape_valid() && groups_valid;
    let chain_valid = advance_chain(&fields, prev_hash_by_event);
    let row_hash_present = fields.row_hash.is_some_and(|hash| !hash.is_empty());
    let row_hash_valid =
        record_valid && row_hash_present && row_hash_matches(&envelope, &fields, &groups);
    let signature_present = fields.signature.is_some_and(|value| !value.is_empty());
    let signature_valid =
        record_valid && signature_present && row_hash_present && signature_matches(&fields);
    let writer_did = fields.writer_did.map(str::to_owned);
    prepared_record(
        envelope,
        writer_did,
        groups,
        RecordChecks {
            record_valid,
            row_hash_present,
            row_hash_valid,
            chain_valid,
            signature_present,
            signature_valid,
            recipient_groups,
        },
    )
}

struct EnvelopeFields<'a> {
    writer_did: Option<&'a str>,
    timestamp: Option<&'a str>,
    event_id: Option<&'a str>,
    event_type: Option<&'a str>,
    level: Option<&'a str>,
    prev_hash: Option<&'a str>,
    row_hash: Option<&'a str>,
    signature: Option<&'a str>,
    sequence_present: bool,
}

impl<'a> EnvelopeFields<'a> {
    fn from_object(object: &'a Map<String, Value>) -> Self {
        let string = |name: &str| object.get(name).and_then(Value::as_str);
        Self {
            writer_did: string("device_identity"),
            timestamp: string("timestamp"),
            event_id: string("event_id"),
            event_type: string("event_type"),
            level: string("level"),
            prev_hash: string("prev_hash"),
            row_hash: string("row_hash"),
            signature: string("signature"),
            sequence_present: object.get("sequence").and_then(Value::as_u64).is_some(),
        }
    }

    fn required_shape_valid(&self) -> bool {
        self.writer_did.is_some_and(|did| !did.is_empty())
            && self.timestamp.is_some()
            && self.event_id.is_some_and(|id| !id.is_empty())
            && self.event_type.is_some_and(|kind| !kind.is_empty())
            && self.level.is_some()
            && self.sequence_present
    }
}

// These are independent cryptographic facts, not one multi-state flag.
#[allow(clippy::struct_excessive_bools)]
struct RecordChecks {
    record_valid: bool,
    row_hash_present: bool,
    row_hash_valid: bool,
    chain_valid: bool,
    signature_present: bool,
    signature_valid: bool,
    recipient_groups: BTreeSet<String>,
}

fn prepared_record(
    envelope: Value,
    writer_did: Option<String>,
    group_inputs: BTreeMap<String, GroupInput>,
    checks: RecordChecks,
) -> PreparedRecord {
    PreparedRecord {
        entry: ReadEntry {
            envelope,
            plaintext_per_group: BTreeMap::new(),
        },
        record: ReadRecordState {
            record_valid: checks.record_valid,
            row_hash_present: checks.row_hash_present,
            row_hash_valid: checks.row_hash_valid,
            chain_valid: checks.chain_valid,
            signature_present: checks.signature_present,
            signature_valid: checks.signature_valid,
            writer_did,
            aad_valid: true,
            recipient_groups: checks.recipient_groups,
        },
        group_inputs,
    }
}

fn advance_chain(
    fields: &EnvelopeFields<'_>,
    prev_hash_by_event: &mut HashMap<String, String>,
) -> bool {
    let valid = match (fields.event_type, fields.prev_hash) {
        (Some(kind), Some(previous)) => prev_hash_by_event
            .get(kind)
            .map_or(previous == crate::chain::ZERO_HASH, |last| last == previous),
        _ => false,
    };
    if let (Some(kind), Some(hash)) = (fields.event_type, fields.row_hash) {
        prev_hash_by_event.insert(kind.to_owned(), hash.to_owned());
    }
    valid
}

fn row_hash_matches(
    envelope: &Value,
    fields: &EnvelopeFields<'_>,
    groups: &BTreeMap<String, GroupInput>,
) -> bool {
    let public_fields = recompute_public_fields(envelope);
    let expected = compute_row_hash(&RowHashInput {
        device_identity: fields.writer_did.unwrap_or(""),
        timestamp: fields.timestamp.unwrap_or(""),
        event_id: fields.event_id.unwrap_or(""),
        event_type: fields.event_type.unwrap_or(""),
        level: fields.level.unwrap_or(""),
        prev_hash: fields.prev_hash.unwrap_or(""),
        public_fields: &public_fields,
        groups,
    });
    fields.row_hash == Some(expected.as_str())
}

fn signature_matches(fields: &EnvelopeFields<'_>) -> bool {
    fields
        .signature
        .and_then(|value| signature_from_b64(value).ok())
        .and_then(|bytes| {
            fields.writer_did.map(|did| {
                DeviceKey::verify_did(did, fields.row_hash.unwrap_or("").as_bytes(), &bytes)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn extract_group_inputs(
    object: &Map<String, Value>,
) -> (BTreeMap<String, GroupInput>, BTreeSet<String>, bool) {
    let mut groups = BTreeMap::new();
    let mut recipients = BTreeSet::new();
    let mut valid = true;
    for (name, value) in object {
        let Some(group) = encrypted_group(value) else {
            continue;
        };
        recipients.insert(name.clone());
        match group_input(group) {
            Some(input) => {
                groups.insert(name.clone(), input);
            }
            None => valid = false,
        }
    }
    (groups, recipients, valid)
}

pub(super) fn decode_group_inputs(envelope: &Value) -> Option<BTreeMap<String, GroupInput>> {
    let object = envelope.as_object()?;
    let (groups, _, valid) = extract_group_inputs(object);
    valid.then_some(groups)
}

fn encrypted_group(value: &Value) -> Option<&Map<String, Value>> {
    value
        .as_object()
        .filter(|group| group.contains_key("ciphertext"))
}

fn group_input(group: &Map<String, Value>) -> Option<GroupInput> {
    let ciphertext = STANDARD.decode(group.get("ciphertext")?.as_str()?).ok()?;
    let values = group.get("field_hashes")?.as_object()?;
    let mut field_hashes = BTreeMap::new();
    for (field, value) in values {
        field_hashes.insert(field.clone(), value.as_str()?.to_owned());
    }
    Some(GroupInput {
        ciphertext,
        field_hashes,
    })
}

pub(super) fn seed_chain_from_line(line: &str, prev_hash_by_event: &mut HashMap<String, String>) {
    let Ok(envelope) = serde_json::from_str::<Value>(line) else {
        return;
    };
    let Some(object) = envelope.as_object() else {
        return;
    };
    if let (Some(event_type), Some(row_hash)) = (
        object.get("event_type").and_then(Value::as_str),
        object.get("row_hash").and_then(Value::as_str),
    ) {
        prev_hash_by_event.insert(event_type.to_owned(), row_hash.to_owned());
    }
}

fn recompute_public_fields(env: &Value) -> BTreeMap<String, Value> {
    const RESERVED: [&str; 9] = [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "prev_hash",
        "row_hash",
        "signature",
        "sequence",
    ];
    let mut public_out = BTreeMap::new();
    let Value::Object(env_map) = env else {
        return public_out;
    };
    for (key, value) in env_map {
        if RESERVED.contains(&key.as_str()) {
            continue;
        }
        if value
            .as_object()
            .is_some_and(|item| item.contains_key("ciphertext"))
        {
            continue;
        }
        public_out.insert(key.clone(), value.clone());
    }
    public_out
}
