//! Read-entry shaping: flatten/merge envelopes, attach tn.agents
//! instructions, apply schema defaults, run-scope predicate.
//!
//! Split out of `runtime.rs` (file-size refactor). Behavior unchanged;
//! `use super::*` re-imports everything these helpers need from the parent.

use super::*;

/// Map a [`ValidFlags`] to the public ``invalid_reasons`` shape.
pub(crate) fn invalid_reasons(valid: ValidFlags) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if !valid.signature {
        out.push("signature");
    }
    if !valid.row_hash {
        out.push("row_hash");
    }
    if !valid.chain {
        out.push("chain");
    }
    out
}

/// Lift the six tn.agents fields out of `flat` into a typed
/// `Instructions` block. Returns the instructions plus the
/// `(hidden_groups, decrypt_errors)` lists already computed by
/// [`flatten_raw_entry`].
pub(crate) fn attach_instructions(
    flat: &mut FlatEntry,
    raw: &ReadEntry,
) -> (Option<Instructions>, Vec<String>, Vec<String>) {
    // Pull hidden_groups / decrypt_errors out so we can return them as
    // typed Vec<String>. They were inserted by flatten_raw_entry.
    let hidden = match flat.remove("_hidden_groups") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let errs = match flat.remove("_decrypt_errors") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };

    let body = raw.plaintext_per_group.get("tn.agents");
    let Some(obj) = body.and_then(Value::as_object) else {
        return (None, hidden, errs);
    };
    if obj.get("$no_read_key") == Some(&Value::Bool(true))
        || obj.get("$decrypt_error") == Some(&Value::Bool(true))
    {
        return (None, hidden, errs);
    }

    // Both fetch the field for the Instructions block AND remove it
    // from the flat top level. flat already had these (flatten_raw_entry
    // merges every readable group's fields).
    let take = |flat: &mut FlatEntry, k: &str| -> String {
        flat.remove(k);
        obj.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    };
    let instr = Instructions {
        instruction: take(flat, "instruction"),
        use_for: take(flat, "use_for"),
        do_not_use_for: take(flat, "do_not_use_for"),
        consequences: take(flat, "consequences"),
        on_violation_or_error: take(flat, "on_violation_or_error"),
        policy: take(flat, "policy"),
    };
    if instr.instruction.is_empty()
        && instr.use_for.is_empty()
        && instr.do_not_use_for.is_empty()
        && instr.consequences.is_empty()
        && instr.on_violation_or_error.is_empty()
        && instr.policy.is_empty()
    {
        return (None, hidden, errs);
    }
    (Some(instr), hidden, errs)
}

/// Project a `ReadEntry` to the flat shape used by `Runtime::read()` per
/// the 2026-04-25 read-ergonomics spec.
///
/// - Six envelope basics (`timestamp`, `event_type`, `level`, `did`,
///   `sequence`, `event_id`) surface as top-level keys.
/// - Public fields beyond envelope basics surface flat.
/// - Decrypted fields from every readable group are merged in
///   alphabetical group order so last-write-wins on collision is
///   deterministic across runs.
/// - Crypto plumbing (`prev_hash`, `row_hash`, `signature`, ciphertext,
///   `field_hashes`) is excluded.
/// - `_hidden_groups` lists groups present in the envelope with no
///   readable plaintext. Omitted when empty.
/// - `_decrypt_errors` lists groups whose decrypt threw. Omitted when
///   empty.
///
/// `_include_valid` is wired through from the spec but the actual
/// `_valid` block is added by the caller (`read_with_verify`) since
/// validity flags don't live on `ReadEntry` itself.
//
// cognitive_complexity: this is a deliberate flat dispatch over the
// six envelope shapes (public fields / groups / decrypt errors /
// reserved fields / …). Each branch is a few-line projection. The
// alternative — a per-shape helper — buys no clarity and forces an
// allocation per shape that's currently elided inline.
#[allow(clippy::cognitive_complexity)]
pub fn flatten_raw_entry(entry: &ReadEntry, _include_valid: bool) -> FlatEntry {
    const FLAT_ENVELOPE_KEYS: [&str; 6] = [
        "timestamp",
        "event_type",
        "level",
        "did",
        "sequence",
        "event_id",
    ];
    const CRYPTO_KEYS: [&str; 3] = ["prev_hash", "row_hash", "signature"];

    let env_obj: &Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m,
        _ => return Map::new(),
    };

    let mut out: FlatEntry = Map::new();

    // 1. Envelope basics.
    for k in FLAT_ENVELOPE_KEYS {
        if let Some(v) = env_obj.get(k) {
            out.insert(k.into(), v.clone());
        }
    }

    let mut reserved: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for k in FLAT_ENVELOPE_KEYS {
        reserved.insert(k);
    }
    for k in CRYPTO_KEYS {
        reserved.insert(k);
    }

    // 2. Public fields beyond envelope basics: anything in env that
    //    isn't an envelope basic, isn't crypto plumbing, and isn't a
    //    group payload (dict with "ciphertext").
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }

    // 3. Decrypted group fields, merged in alphabetical group order.
    let mut decrypt_errors: Vec<String> = Vec::new();
    // BTreeMap iteration is alphabetical.
    for (gname, body) in &entry.plaintext_per_group {
        if let Some(obj) = body.as_object() {
            if obj.get("$decrypt_error") == Some(&Value::Bool(true)) {
                decrypt_errors.push(gname.clone());
                continue;
            }
            if obj.get("$no_read_key") == Some(&Value::Bool(true)) {
                continue;
            }
            for (k, v) in obj {
                out.insert(k.clone(), v.clone());
            }
        }
    }

    // 4. _hidden_groups: groups in envelope with ciphertext but no
    //    readable plaintext.
    let mut hidden: Vec<String> = Vec::new();
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if !v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        let body = entry.plaintext_per_group.get(k);
        let no_read = body.is_none()
            || body.is_some_and(|b| {
                b.as_object()
                    .is_some_and(|o| o.get("$no_read_key") == Some(&Value::Bool(true)))
            });
        if no_read {
            hidden.push(k.clone());
        }
    }
    if !hidden.is_empty() {
        hidden.sort();
        out.insert(
            "_hidden_groups".into(),
            Value::Array(hidden.into_iter().map(Value::String).collect()),
        );
    }
    if !decrypt_errors.is_empty() {
        decrypt_errors.sort();
        out.insert(
            "_decrypt_errors".into(),
            Value::Array(decrypt_errors.into_iter().map(Value::String).collect()),
        );
    }

    out
}

/// Flatten a `ReadEntry` into a single JSON object: envelope fields plus
/// every per-group plaintext dict merged on top. Mirrors Python's
/// `recipients()` / `admin_state()` and TS `_mergeEnvelope` exactly.
pub(crate) fn merge_envelope(entry: &ReadEntry) -> Map<String, Value> {
    let mut merged: Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    for v in entry.plaintext_per_group.values() {
        if let Value::Object(group_fields) = v {
            for (k, vv) in group_fields {
                merged.insert(k.clone(), vv.clone());
            }
        }
    }
    merged
}

/// Apply schema defaults the Rust emitter omits but the catalog requires
/// at reduce time. Mirrors Python and TS `_applySchemaDefaults`.
pub(crate) fn apply_schema_defaults(event_type: &str, mut merged: Map<String, Value>) -> Value {
    if event_type == "tn.recipient.added" && !merged.contains_key("cipher") {
        merged.insert("cipher".into(), Value::String("btn".into()));
    }
    if event_type == "tn.recipient.revoked" && !merged.contains_key("recipient_identity") {
        merged.insert("recipient_identity".into(), Value::Null);
    }
    Value::Object(merged)
}

pub(crate) fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Predicate for `Runtime::read`: does this flat entry belong to the
/// current process's run? True iff the entry's `run_id` is a string
/// matching the runtime's. Entries with no `run_id` (or a non-string
/// value) are EXCLUDED — for cross-session safety, the default is
/// "this run only." Use [`Runtime::read_all_runs`] for the full
/// history. (FINDINGS.md #12.)
pub(crate) fn flat_in_current_run(flat: &FlatEntry, current_run_id: &str) -> bool {
    matches!(flat.get("run_id"), Some(Value::String(s)) if s == current_run_id)
}

