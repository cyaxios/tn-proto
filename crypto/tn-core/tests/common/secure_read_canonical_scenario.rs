//! Canonical-scenario helpers for the cross-language byte-compare tests
//! covering `tn.secure_read()` flat output and `tn.agents` pre-encryption
//! canonical bytes.
//!
//! Spec: `docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md`
//! section 5.4.
//!
//! `#[path]`-included by:
//!   - `secure_read_fixture_builder.rs` (regenerate the committed fixture)
//!   - `secure_read_interop.rs`         (consume the Python + TS fixtures)
//!
//! Holding the helpers in a single source file keeps the canonical
//! scenario inputs in one place and prevents drift between the regenerate
//! script and the byte-compare tests.

#![cfg(feature = "fs")]
#![allow(dead_code)] // builder uses ALL helpers; interop uses a subset

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use tn_core::agents_policy::parse_policy_text;
use tn_core::canonical::canonical_bytes;
use tn_core::runtime::{flatten_raw_entry, ReadEntry};

pub const CANONICAL_DID: &str =
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
pub const CANONICAL_POLICY_PATH: &str = ".tn/config/agents.md";
pub const CANONICAL_POLICY_TEXT: &str = "# TN Agents Policy\n\
version: 1\n\
schema: tn-agents-policy@v1\n\
\n\
## payment.completed\n\
\n\
### instruction\n\
This row records a completed payment.\n\
\n\
### use_for\n\
Aggregate reporting on amount and currency.\n\
\n\
### do_not_use_for\n\
Credit decisions, loan underwriting, risk scoring.\n\
\n\
### consequences\n\
customer_id is PII; exposure violates GDPR.\n\
\n\
### on_violation_or_error\n\
POST https://merchant.example.com/controls/escalate\n";

/// Build the canonical-scenario raw `ReadEntry` for `order.created`.
///
/// Two group payloads in the envelope (`default`, `pii`); caller holds
/// only the `default` kit so `pii` lands in `_hidden_groups`.
pub fn order_created_raw() -> ReadEntry {
    let envelope = json!({
        "did": CANONICAL_DID,
        "timestamp": "2026-04-25T18:32:18.000000Z",
        "event_id": "01HXYZ0000000000000000ORD1",
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": format!("sha256:{}", "0".repeat(64)),
        "row_hash": format!("sha256:{}", "1".repeat(64)),
        "signature": "AAAA",
        "request_id": "req_abc",
        "default": {"ciphertext": "ZGVmYXVsdA==", "field_hashes": {}},
        "pii": {"ciphertext": "cGlp", "field_hashes": {}},
    });

    let mut plaintext: BTreeMap<String, Value> = BTreeMap::new();
    plaintext.insert(
        "default".into(),
        json!({
            "order_id": "ord_2026_q2_a47b9",
            "amount": 4999,
            "currency": "USD",
        }),
    );

    ReadEntry {
        envelope,
        plaintext_per_group: plaintext,
    }
}

/// Build the canonical-scenario raw `ReadEntry` for `payment.completed`.
///
/// Caller holds both the `default` kit and the `tn.agents` kit; the
/// `tn.agents` plaintext carries the six policy fields exactly as the
/// splice payload would have populated them at emit time.
pub fn payment_completed_raw() -> ReadEntry {
    let envelope = json!({
        "did": CANONICAL_DID,
        "timestamp": "2026-04-25T18:33:42.000000Z",
        "event_id": "01HXYZ0000000000000000PAY1",
        "event_type": "payment.completed",
        "level": "info",
        "sequence": 2,
        "prev_hash": format!("sha256:{}", "1".repeat(64)),
        "row_hash": format!("sha256:{}", "2".repeat(64)),
        "signature": "BBBB",
        "default": {"ciphertext": "ZGVmYXVsdA==", "field_hashes": {}},
        "tn.agents": {"ciphertext": "YWdlbnRz", "field_hashes": {}},
    });

    let mut plaintext: BTreeMap<String, Value> = BTreeMap::new();
    plaintext.insert(
        "default".into(),
        json!({
            "order_id": "ord_2026_q2_a47b9",
            "amount": 4999,
            "currency": "USD",
        }),
    );
    plaintext.insert(
        "tn.agents".into(),
        json!({
            "instruction": "This row records a completed payment.",
            "use_for": "Aggregate reporting on amount and currency.",
            "do_not_use_for": "Credit decisions, loan underwriting, risk scoring.",
            "consequences": "customer_id is PII; exposure violates GDPR.",
            "on_violation_or_error": "POST https://merchant.example.com/controls/escalate",
            "policy": ".tn/config/agents.md#payment.completed@1#sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
        }),
    );

    ReadEntry {
        envelope,
        plaintext_per_group: plaintext,
    }
}

/// Lift the six tn.agents fields out of `flat` into a typed `instructions`
/// block, removing the same field names from the flat top level. Mirrors
/// Python `tn._attach_instructions` and TS `attachInstructions`.
fn attach_instructions(flat: &mut Map<String, Value>, raw: &ReadEntry) {
    let body = raw.plaintext_per_group.get("tn.agents");
    let Some(obj) = body.and_then(Value::as_object) else {
        return;
    };
    if obj.get("$no_read_key") == Some(&Value::Bool(true))
        || obj.get("$decrypt_error") == Some(&Value::Bool(true))
    {
        return;
    }

    let fields = [
        "instruction",
        "use_for",
        "do_not_use_for",
        "consequences",
        "on_violation_or_error",
        "policy",
    ];
    let mut instructions = Map::new();
    for f in fields {
        if let Some(v) = obj.get(f) {
            instructions.insert(f.into(), v.clone());
        }
        flat.shift_remove(f);
    }
    if !instructions.is_empty() {
        flat.insert("instructions".into(), Value::Object(instructions));
    }
}

/// Build the `secure_read_canonical.json` payload — the dict
/// `Runtime::secure_read()` would hand to the LLM for the canonical
/// scenario.
pub fn build_secure_read_canonical() -> Value {
    let order = order_created_raw();
    let mut order_flat = flatten_raw_entry(&order, false);
    attach_instructions(&mut order_flat, &order);

    let payment = payment_completed_raw();
    let mut payment_flat = flatten_raw_entry(&payment, false);
    attach_instructions(&mut payment_flat, &payment);

    let mut top = Map::new();
    top.insert("order_created".into(), Value::Object(order_flat));
    top.insert("payment_completed".into(), Value::Object(payment_flat));
    Value::Object(top)
}

/// Build the `tn_agents_pre_encryption.json` payload — the canonical
/// pre-encryption bytes of the splice payload for the canonical
/// `payment.completed` event.
pub fn build_tn_agents_pre_encryption() -> Value {
    let doc = parse_policy_text(CANONICAL_POLICY_TEXT, CANONICAL_POLICY_PATH)
        .expect("parse canonical policy text");
    let template = doc
        .templates
        .get("payment.completed")
        .expect("policy must declare payment.completed");

    let mut splice = Map::new();
    splice.insert(
        "instruction".into(),
        Value::String(template.instruction.clone()),
    );
    splice.insert("use_for".into(), Value::String(template.use_for.clone()));
    splice.insert(
        "do_not_use_for".into(),
        Value::String(template.do_not_use_for.clone()),
    );
    splice.insert(
        "consequences".into(),
        Value::String(template.consequences.clone()),
    );
    splice.insert(
        "on_violation_or_error".into(),
        Value::String(template.on_violation_or_error.clone()),
    );
    splice.insert(
        "policy".into(),
        Value::String(format!(
            "{}#{}@{}#{}",
            template.path, template.event_type, template.version, template.content_hash
        )),
    );
    let splice_value = Value::Object(splice);

    let cb = canonical_bytes(&splice_value).expect("canonical encode");
    let mut top = Map::new();
    top.insert("splice_dict".into(), splice_value);
    top.insert(
        "canonical_bytes_hex".into(),
        Value::String(hex_encode(&cb)),
    );
    top.insert(
        "canonical_bytes_len".into(),
        Value::Number(serde_json::Number::from(cb.len() as u64)),
    );
    top.insert(
        "policy_content_hash".into(),
        Value::String(doc.content_hash.clone()),
    );
    Value::Object(top)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Encode `obj` as canonical JSON (sorted keys, compact separators, UTF-8)
/// — the same wire form Python writes via
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
/// and TS writes via its `stableStringify`.
pub fn canonical_json_bytes(obj: &Value) -> Vec<u8> {
    canonical_bytes(obj).expect("canonical encode")
}

// --------------------------------------------------------------------------
// Per-admin-event canonical scenarios. Each pair `(event_type, fields)` is
// the exact emit-time payload `canonical_bytes(...)` runs over for the
// row_hash. Mirrored byte-for-byte by the Python + TS builders. Adding an
// event_type here pins the canonical shape across all three SDKs and would
// have caught the 2026-04-25 e2e canonicalization-drift report on the
// protocol-spec side.
// --------------------------------------------------------------------------

/// Returns `(event_type, fields)` pairs in stable insertion order. The
/// pin order does not affect the canonical bytes (each event's fields
/// canonicalize independently); we use `Vec` rather than `BTreeMap` so
/// the human-edit ordering matches the Python source.
pub fn admin_event_scenarios() -> Vec<(&'static str, Value)> {
    vec![
        (
            "tn.ceremony.init",
            json!({
                "ceremony_id": "cer_byte_compare_canonical_2026",
                "cipher": "btn",
                "device_did": CANONICAL_DID,
                "created_at": "2026-04-25T18:00:00.000000Z",
            }),
        ),
        (
            "tn.group.added",
            json!({
                "group": "default",
                "cipher": "btn",
                "publisher_did": CANONICAL_DID,
                "added_at": "2026-04-25T18:00:01.000000Z",
            }),
        ),
        (
            "tn.recipient.added",
            json!({
                "group": "default",
                "leaf_index": 7,
                "recipient_did": "did:key:zRecipientCanonical",
                "kit_sha256": format!("sha256:{}", "a".repeat(64)),
                "cipher": "btn",
            }),
        ),
        (
            "tn.recipient.revoked",
            json!({
                "group": "default",
                "leaf_index": 7,
                "recipient_did": "did:key:zRecipientCanonical",
            }),
        ),
        (
            "tn.coupon.issued",
            json!({
                "group": "default",
                "slot": 3,
                "to_did": "did:key:zCouponHolder",
                "issued_to": "did:key:zCouponHolder",
            }),
        ),
        (
            "tn.rotation.completed",
            json!({
                "group": "default",
                "cipher": "btn",
                "generation": 2,
                "previous_kit_sha256": format!("sha256:{}", "b".repeat(64)),
                "old_pool_size": 12,
                "new_pool_size": 24,
                "rotated_at": "2026-04-25T18:00:02.000000Z",
            }),
        ),
        (
            "tn.enrolment.compiled",
            json!({
                "group": "default",
                "peer_did": "did:key:zPeerEnrolment",
                "package_sha256": format!("sha256:{}", "c".repeat(64)),
                "compiled_at": "2026-04-25T18:00:03.000000Z",
            }),
        ),
        (
            "tn.enrolment.absorbed",
            json!({
                "group": "default",
                "from_did": "did:key:zSenderEnrolment",
                "package_sha256": format!("sha256:{}", "c".repeat(64)),
                "absorbed_at": "2026-04-25T18:00:04.000000Z",
            }),
        ),
        (
            "tn.vault.linked",
            json!({
                "vault_did": "did:web:vault.example",
                "project_id": "proj_byte_compare",
                "linked_at": "2026-04-25T18:00:05.000000Z",
            }),
        ),
        (
            "tn.vault.unlinked",
            json!({
                "vault_did": "did:web:vault.example",
                "project_id": "proj_byte_compare",
                "reason": "operator_initiated",
                "unlinked_at": "2026-04-25T18:00:06.000000Z",
            }),
        ),
        (
            "tn.agents.policy_published",
            json!({
                "policy_uri": CANONICAL_POLICY_PATH,
                "version": "1",
                "content_hash": "sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
                "event_types_covered": [
                    "order.created",
                    "payment.completed",
                    "tn.recipient.added",
                ],
                "policy_text": CANONICAL_POLICY_TEXT,
            }),
        ),
        (
            "tn.read.tampered_row_skipped",
            json!({
                "envelope_event_id": "01HXYZ0000000000000000PAY1",
                "envelope_did": CANONICAL_DID,
                "envelope_event_type": "payment.completed",
                "envelope_sequence": 2,
            }),
        ),
    ]
}

/// Build the `admin_events_canonical.json` payload — per-event canonical
/// bytes for every admin event_type in the catalog.
pub fn build_admin_events_canonical() -> Value {
    let mut top = Map::new();
    for (event_type, fields) in admin_event_scenarios() {
        let cb = canonical_bytes(&fields).expect("canonical encode");
        let mut entry = Map::new();
        entry.insert("fields".into(), fields);
        entry.insert(
            "canonical_bytes_hex".into(),
            Value::String(hex_encode(&cb)),
        );
        entry.insert(
            "canonical_bytes_len".into(),
            Value::Number(serde_json::Number::from(cb.len() as u64)),
        );
        top.insert(event_type.into(), Value::Object(entry));
    }
    Value::Object(top)
}
