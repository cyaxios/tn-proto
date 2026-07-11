//! Internal admin-log machinery behind [`crate::Runtime`]'s admin verbs
//! (`tn.admin.*` / `tn rotate`); see [`crate::AdminState`]. Holds the static
//! registry of admin event kinds. Reach here directly only to inspect or
//! validate a single admin event schema.
//!
//! Each `AdminEventKind` describes one `tn.*` event: its event_type string,
//! its field schema, and its sync/sign policy. The catalog is a compile-
//! time constant slice. Adding a kind is one record.
//!
//! Callers: the publisher runtime uses `validate_emit` before sealing an
//! admin envelope; the reducer (`admin_reduce::reduce`) reads the catalog
//! to know how to parse each kind.

use serde_json::{Map, Value};

use crate::sealed_object::ENVELOPE_RESERVED;
use crate::unsafe_operation::UnsafeOperationNotice;

const UNSAFE_OPERATION_EVENT: &str = "tn.security.unsafe_operation";
const UNSAFE_OPERATION_RUNTIME_METADATA: [&str; 1] = ["run_id"];

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
    /// JSON array containing only non-empty strings.
    StringArray,
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
    /// A strict catalog kind received a field outside its declared schema.
    UnexpectedField {
        /// Name of the field absent from the strict schema.
        field: String,
    },
    /// A field has the correct broad JSON shape but violates the event's
    /// typed value contract.
    InvalidPayload {
        /// Typed deserialization failure explaining the invalid value.
        reason: String,
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
            Self::UnexpectedField { field } => write!(f, "unexpected field {field:?}"),
            Self::InvalidPayload { reason } => write!(f, "invalid payload: {reason}"),
        }
    }
}

impl std::error::Error for ValidateError {}

/// Catalog of all admin event kinds. See spec §2.1.
pub const CATALOG: &[AdminEventKind] = &[
    AdminEventKind {
        event_type: "tn.ceremony.init",
        // NOTE: `device_identity` is intentionally NOT a schema field
        // here. It is the mandatory reserved envelope scalar (hashed
        // first in the row_hash preimage and always written at envelope
        // root by `build_envelope`), exactly like every other admin
        // event identifies its publisher. Listing it as a public field
        // *and* having it as the scalar made the writer hash it twice
        // (scalar + public) on any ceremony whose yaml carries
        // `device_identity` in public_fields (every Python/TS-written
        // ceremony via DEFAULT_PUBLIC_FIELDS), while spec-correct readers
        // exclude the reserved scalar — so `tn.ceremony.init` failed
        // row_hash verification cross-SDK. The reducer reads
        // `device_identity` from the envelope scalar, so it needs no
        // catalog field. See `on_ceremony_init`.
        schema: &[
            ("ceremony_id", FieldType::String),
            ("cipher", FieldType::String),
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
            ("publisher_identity", FieldType::String),
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
            ("recipient_identity", FieldType::OptionalString),
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
            ("recipient_identity", FieldType::OptionalString),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.coupon.issued",
        schema: &[
            ("group", FieldType::String),
            ("slot", FieldType::Int),
            ("recipient_identity", FieldType::String),
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
            ("peer_identity", FieldType::String),
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
            ("publisher_identity", FieldType::String),
            ("package_sha256", FieldType::String),
            ("absorbed_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.vault.linked",
        schema: &[
            ("vault_identity", FieldType::String),
            ("project_id", FieldType::String),
            ("linked_at", FieldType::Iso8601),
        ],
        sign: true,
        sync: true,
    },
    AdminEventKind {
        event_type: "tn.vault.unlinked",
        schema: &[
            ("vault_identity", FieldType::String),
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
            ("envelope_device_identity", FieldType::String),
            ("envelope_event_type", FieldType::String),
            ("envelope_sequence", FieldType::OptionalInt),
        ],
        sign: true,
        sync: false,
    },
    // Explicit security weakening uses one strict, non-secret five-field
    // statement across every SDK.
    AdminEventKind {
        event_type: "tn.security.unsafe_operation",
        schema: &[
            ("artifact_digest", FieldType::OptionalString),
            ("group", FieldType::OptionalString),
            ("operation", FieldType::String),
            ("relaxations", FieldType::StringArray),
            ("subject_did", FieldType::OptionalString),
        ],
        sign: true,
        sync: true,
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
    if kind.event_type == UNSAFE_OPERATION_EVENT {
        validate_unsafe_operation(fields, kind)?;
    }
    Ok(())
}

fn validate_unsafe_operation(
    fields: &Map<String, Value>,
    kind: &AdminEventKind,
) -> Result<(), ValidateError> {
    if let Some(field) = fields.keys().find(|field| {
        !kind.schema.iter().any(|(name, _)| name == field)
            && !ENVELOPE_RESERVED.contains(&field.as_str())
            && !UNSAFE_OPERATION_RUNTIME_METADATA.contains(&field.as_str())
    }) {
        return Err(ValidateError::UnexpectedField {
            field: field.clone(),
        });
    }

    if let Some(run_id) = fields.get("run_id") {
        check_field("run_id", FieldType::String, run_id)?;
    }

    let mut payload = Map::new();
    for (name, _) in kind.schema {
        payload.insert(
            (*name).to_string(),
            fields
                .get(*name)
                .expect("schema fields were checked before typed validation")
                .clone(),
        );
    }
    serde_json::from_value::<UnsafeOperationNotice>(Value::Object(payload))
        .map(|_| ())
        .map_err(|error| ValidateError::InvalidPayload {
            reason: error.to_string(),
        })
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
        (FieldType::StringArray, Value::Array(values))
            if values
                .iter()
                .all(|value| matches!(value, Value::String(s) if !s.is_empty())) =>
        {
            Ok(())
        }
        _ => Err(ValidateError::WrongType {
            field: name,
            expected: ftype,
            got: format!("{v}"),
        }),
    }
}
