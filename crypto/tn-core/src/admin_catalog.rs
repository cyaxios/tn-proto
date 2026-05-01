//! Static registry of admin event kinds.
//!
//! Each `AdminEventKind` describes one `tn.*` event: its event_type string,
//! its field schema, and its sync/sign policy. The catalog is a compile-
//! time constant slice. Adding a kind is one record.
//!
//! Callers: the publisher runtime uses `validate_emit` before sealing an
//! admin envelope; the reducer (`admin_reduce::reduce`) reads the catalog
//! to know how to parse each kind.

use serde_json::{Map, Value};

/// Accepted JSON-value shape for an admin event field. Drives `validate_emit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Non-empty UTF-8 string.
    String,
    /// String or JSON null.
    OptionalString,
    /// u64 fits; negative values rejected.
    Int,
    /// u64 fits, nullable.
    OptionalInt,
    /// ISO-8601 timestamp string (any parseable format).
    Iso8601,
}

/// One entry in the admin event catalog: the event type, its required field
/// schema, and whether emissions of this kind must be signed / synced.
#[derive(Debug, Clone, Copy)]
pub struct AdminEventKind {
    /// Canonical event type string (e.g. `tn.ceremony.init`).
    pub event_type: &'static str,
    /// Required fields, in declaration order, each paired with its expected type.
    pub schema: &'static [(&'static str, FieldType)],
    /// If true, the publisher must sign envelopes of this kind.
    pub sign: bool,
    /// If true, the envelope is synced to peers (vs. kept publisher-local).
    pub sync: bool,
}

/// Reason `validate_emit` rejected an envelope.
#[derive(Debug)]
pub enum ValidateError {
    /// The `event_type` string is not in the catalog.
    UnknownEventType(String),
    /// A field declared in the catalog schema was not present in the emit.
    MissingField(&'static str),
    /// A field was present but its JSON value did not match the declared type.
    WrongType {
        /// Name of the offending field.
        field: &'static str,
        /// Type the catalog required.
        expected: FieldType,
        /// Stringified form of the value actually received.
        got: String,
    },
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEventType(s) => write!(f, "unknown admin event_type {s:?}"),
            Self::MissingField(n) => write!(f, "missing required field {n:?}"),
            Self::WrongType {
                field,
                expected,
                got,
            } => {
                write!(f, "field {field:?}: expected {expected:?}, got {got}")
            }
        }
    }
}

impl std::error::Error for ValidateError {}

/// Catalog of all admin event kinds. See spec §2.1.
pub const CATALOG: &[AdminEventKind] = &[
    AdminEventKind {
        event_type: "tn.ceremony.init",
        schema: &[
            ("ceremony_id", FieldType::String),
            ("cipher", FieldType::String),
            ("device_did", FieldType::String),
            ("created_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.group.added",
        schema: &[
            ("group", FieldType::String),
            ("cipher", FieldType::String),
            ("publisher_did", FieldType::String),
            ("added_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.recipient.added",
        schema: &[
            ("group", FieldType::String),
            ("leaf_index", FieldType::OptionalInt),
            ("recipient_did", FieldType::OptionalString),
            ("kit_sha256", FieldType::String),
            ("cipher", FieldType::String),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.recipient.revoked",
        schema: &[
            ("group", FieldType::String),
            ("leaf_index", FieldType::OptionalInt),
            ("recipient_did", FieldType::OptionalString),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.coupon.issued",
        schema: &[
            ("group", FieldType::String),
            ("slot", FieldType::Int),
            ("to_did", FieldType::String),
            ("issued_to", FieldType::String),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.rotation.completed",
        schema: &[
            ("group", FieldType::String),
            ("cipher", FieldType::String),
            ("generation", FieldType::Int),
            ("previous_kit_sha256", FieldType::String),
            ("old_pool_size", FieldType::OptionalInt),
            ("new_pool_size", FieldType::OptionalInt),
            ("rotated_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.enrolment.compiled",
        schema: &[
            ("group", FieldType::String),
            ("peer_did", FieldType::String),
            ("package_sha256", FieldType::String),
            ("compiled_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.enrolment.absorbed",
        schema: &[
            ("group", FieldType::String),
            ("from_did", FieldType::String),
            ("package_sha256", FieldType::String),
            ("absorbed_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.vault.linked",
        schema: &[
            ("vault_did", FieldType::String),
            ("project_id", FieldType::String),
            ("linked_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.vault.unlinked",
        schema: &[
            ("vault_did", FieldType::String),
            ("project_id", FieldType::String),
            ("reason", FieldType::OptionalString),
            ("unlinked_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    // --- 2026-04-25 read-ergonomics + agents-group spec ----------------
    //
    // `tn.agents.policy_published` records the active `.tn/config/agents.md`
    // policy text + content_hash so an auditor replaying the log knows
    // which policy was active at any timestamp. Reducer doesn't act on
    // it — replayable provenance only (per spec §2.7).
    AdminEventKind {
        event_type: "tn.agents.policy_published",
        schema: &[
            ("policy_uri", FieldType::String),
            ("version", FieldType::String),
            ("content_hash", FieldType::String),
            // event_types_covered is a JSON array of strings; the catalog
            // doesn't validate array shape today, so we don't list it
            // here. Same call as the existing `signature`-of-array fields
            // already in the catalog.
            ("policy_text", FieldType::String),
        ],
        sign: true,
        sync: true,
    },
    // `tn.read.tampered_row_skipped` is emitted by `secure_read()` under
    // `on_invalid="skip"` when an envelope fails (sig|row_hash|chain).
    // Public fields only — the bad row's payload is NOT exposed. Per spec §3.3.
    AdminEventKind {
        event_type: "tn.read.tampered_row_skipped",
        schema: &[
            ("envelope_event_id", FieldType::String),
            ("envelope_did", FieldType::String),
            ("envelope_event_type", FieldType::String),
            ("envelope_sequence", FieldType::OptionalInt),
        ],
        sign: true,
        sync: false,
    },
];

/// Look up a kind by event_type.
pub fn kind_for(event_type: &str) -> Option<&'static AdminEventKind> {
    CATALOG.iter().find(|k| k.event_type == event_type)
}

/// Validate an emit's fields against the catalog kind's schema.
///
/// Called by runtime::emit_inner before signing any `tn.*` envelope, so a
/// publisher cannot accidentally sign an envelope with a shape the reducer
/// would later reject.
pub fn validate_emit(event_type: &str, fields: &Map<String, Value>) -> Result<(), ValidateError> {
    let kind = kind_for(event_type)
        .ok_or_else(|| ValidateError::UnknownEventType(event_type.to_string()))?;
    for (name, ftype) in kind.schema {
        let v = fields.get(*name).ok_or(ValidateError::MissingField(name))?;
        check_field(name, *ftype, v)?;
    }
    Ok(())
}

fn check_field(name: &'static str, ftype: FieldType, v: &Value) -> Result<(), ValidateError> {
    // Arms share Ok(()) bodies deliberately — one per (type, shape) combo,
    // merging them would obscure which field types accept which values.
    #[allow(clippy::match_same_arms)]
    match (ftype, v) {
        (FieldType::String, Value::String(s)) if !s.is_empty() => Ok(()),
        (FieldType::OptionalString, Value::String(_) | Value::Null) => Ok(()),
        (FieldType::Int, Value::Number(n)) if n.as_u64().is_some() => Ok(()),
        (FieldType::OptionalInt, Value::Number(n)) if n.as_u64().is_some() => Ok(()),
        (FieldType::OptionalInt, Value::Null) => Ok(()),
        (FieldType::Iso8601, Value::String(s)) if !s.is_empty() => Ok(()),
        _ => Err(ValidateError::WrongType {
            field: name,
            expected: ftype,
            got: format!("{v}"),
        }),
    }
}
