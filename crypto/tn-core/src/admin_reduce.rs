//! Pure reducer: given an attested TN envelope, produce a typed
//! `StateDelta` describing the administrative state change. No I/O.
//!
//! Used on the publisher side to drive `tn.recipients()` / `tn.admin_state()`
//! and on the vault side to dispatch to Mongo writes (`routes_sync.py`).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::admin_catalog::{kind_for, validate_emit, ValidateError};

/// Typed state change derived from an admin envelope.
///
/// Variant names and fields mirror the schema declared in [`crate::admin_catalog::CATALOG`]
/// — see that module for the authoritative field definitions and semantics.
/// Fields are left undocumented here to avoid maintaining two copies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(missing_docs)] // Fields mirror admin_catalog::CATALOG; see that module.
pub enum StateDelta {
    /// `tn.ceremony.init` — a device joined the protocol under a new ceremony.
    CeremonyInit {
        ceremony_id: String,
        cipher: String,
        device_identity: String,
        created_at: String,
    },
    /// `tn.group.added` — a publisher declared a new group.
    GroupAdded {
        group: String,
        cipher: String,
        publisher_identity: String,
        added_at: String,
    },
    /// `tn.recipient.added` — a reader kit was minted into a group.
    RecipientAdded {
        group: String,
        leaf_index: Option<u64>,
        recipient_identity: Option<String>,
        kit_sha256: String,
        cipher: String,
    },
    /// `tn.recipient.revoked` — a previously-added recipient was revoked.
    RecipientRevoked {
        group: String,
        leaf_index: Option<u64>,
        recipient_identity: Option<String>,
    },
    /// `tn.coupon.issued` — a single-use coupon was handed to a DID.
    CouponIssued {
        group: String,
        slot: u64,
        recipient_identity: String,
        issued_to: String,
    },
    /// `tn.rotation.completed` — the group's kit was rotated to a new generation.
    RotationCompleted {
        group: String,
        cipher: String,
        generation: u64,
        previous_kit_sha256: String,
        old_pool_size: Option<u64>,
        new_pool_size: Option<u64>,
        rotated_at: String,
    },
    /// `tn.enrolment.compiled` — a peer enrolment package was built and signed.
    EnrolmentCompiled {
        group: String,
        peer_identity: String,
        package_sha256: String,
        compiled_at: String,
    },
    /// `tn.enrolment.absorbed` — a peer's enrolment package was applied locally.
    EnrolmentAbsorbed {
        group: String,
        publisher_identity: String,
        package_sha256: String,
        absorbed_at: String,
    },
    /// `tn.vault.linked` — a vault was associated with a project.
    VaultLinked {
        vault_identity: String,
        project_id: String,
        linked_at: String,
    },
    /// `tn.vault.unlinked` — a vault association was severed.
    VaultUnlinked {
        vault_identity: String,
        project_id: String,
        reason: Option<String>,
        unlinked_at: String,
    },
    /// Catch-all for non-admin or non-catalogued events. Vault stores the
    /// envelope but produces no side-effect.
    Unknown { event_type: String },
}

/// Reason `reduce` rejected an envelope.
#[derive(Debug)]
pub enum ReduceError {
    /// Envelope carries a catalogued event_type but its fields fail schema
    /// validation. Indicates forgery or a publisher bug. Vault should
    /// reject.
    SchemaViolation(ValidateError),
    /// Envelope is missing top-level `event_type`.
    MissingEventType,
}

impl std::fmt::Display for ReduceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaViolation(e) => write!(f, "schema violation: {e}"),
            Self::MissingEventType => write!(f, "envelope missing event_type"),
        }
    }
}
impl std::error::Error for ReduceError {}

/// Reduce an envelope to a typed state delta.
///
/// Envelope is the flat JSON object as written to ndjson (top-level keys
/// include `event_type`, `did`, `timestamp`, plus the admin fields).
pub fn reduce(envelope: &Value) -> Result<StateDelta, ReduceError> {
    let obj = envelope.as_object().ok_or(ReduceError::MissingEventType)?;
    let event_type = obj
        .get("event_type")
        .and_then(|v| v.as_str())
        .ok_or(ReduceError::MissingEventType)?;

    // Non-catalogued event: treat as Unknown.
    let Some(_kind) = kind_for(event_type) else {
        return Ok(StateDelta::Unknown {
            event_type: event_type.to_string(),
        });
    };

    // Validate shape. Forged/mismatched envelopes return SchemaViolation.
    validate_emit(event_type, obj).map_err(ReduceError::SchemaViolation)?;

    Ok(build_delta(event_type, obj))
}

/// Build the typed delta once schema validation has passed. Never panics: an
/// `event_type` that `kind_for` recognizes but no arm here handles (catalog/
/// reducer drift) falls through to [`StateDelta::Unknown`].
fn build_delta(event_type: &str, obj: &Map<String, Value>) -> StateDelta {
    match event_type {
        "tn.ceremony.init" => StateDelta::CeremonyInit {
            ceremony_id: s(obj, "ceremony_id"),
            cipher: s(obj, "cipher"),
            device_identity: s(obj, "device_identity"),
            created_at: s(obj, "created_at"),
        },
        "tn.group.added" => StateDelta::GroupAdded {
            group: s(obj, "group"),
            cipher: s(obj, "cipher"),
            publisher_identity: s(obj, "publisher_identity"),
            added_at: s(obj, "added_at"),
        },
        "tn.recipient.added" => StateDelta::RecipientAdded {
            group: s(obj, "group"),
            leaf_index: opt_u(obj, "leaf_index"),
            recipient_identity: opt_s(obj, "recipient_identity"),
            kit_sha256: s(obj, "kit_sha256"),
            cipher: s(obj, "cipher"),
        },
        "tn.recipient.revoked" => StateDelta::RecipientRevoked {
            group: s(obj, "group"),
            leaf_index: opt_u(obj, "leaf_index"),
            recipient_identity: opt_s(obj, "recipient_identity"),
        },
        "tn.coupon.issued" => StateDelta::CouponIssued {
            group: s(obj, "group"),
            slot: u(obj, "slot"),
            recipient_identity: s(obj, "recipient_identity"),
            issued_to: s(obj, "issued_to"),
        },
        "tn.rotation.completed" => StateDelta::RotationCompleted {
            group: s(obj, "group"),
            cipher: s(obj, "cipher"),
            generation: u(obj, "generation"),
            previous_kit_sha256: s(obj, "previous_kit_sha256"),
            old_pool_size: opt_u(obj, "old_pool_size"),
            new_pool_size: opt_u(obj, "new_pool_size"),
            rotated_at: s(obj, "rotated_at"),
        },
        "tn.enrolment.compiled" => StateDelta::EnrolmentCompiled {
            group: s(obj, "group"),
            peer_identity: s(obj, "peer_identity"),
            package_sha256: s(obj, "package_sha256"),
            compiled_at: s(obj, "compiled_at"),
        },
        "tn.enrolment.absorbed" => StateDelta::EnrolmentAbsorbed {
            group: s(obj, "group"),
            publisher_identity: s(obj, "publisher_identity"),
            package_sha256: s(obj, "package_sha256"),
            absorbed_at: s(obj, "absorbed_at"),
        },
        "tn.vault.linked" => StateDelta::VaultLinked {
            vault_identity: s(obj, "vault_identity"),
            project_id: s(obj, "project_id"),
            linked_at: s(obj, "linked_at"),
        },
        "tn.vault.unlinked" => StateDelta::VaultUnlinked {
            vault_identity: s(obj, "vault_identity"),
            project_id: s(obj, "project_id"),
            reason: opt_s(obj, "reason"),
            unlinked_at: s(obj, "unlinked_at"),
        },
        // Everything else recognized by `kind_for` maps to `Unknown`:
        //  - `tn.agents.policy_published` / `tn.read.tampered_row_skipped` are
        //    catalog-valid (the publisher can sign, the reducer validates
        //    shape) but carry no admin-state mutation per the 2026-04-25
        //    read-ergonomics spec; existing reducers ignore them and the
        //    dedicated policy / tampered-row consumers walk the log directly.
        //  - any future `kind_for` entry without a matching arm above
        //    (catalog/reducer drift) also lands here rather than panicking.
        //    `build_delta` is reached from the wasm `adminReduce` export and
        //    the Python admin path, so a panic would trap the wasm instance /
        //    raise a pyo3 PanicException in user space — which the SDK must
        //    never do.
        _ => StateDelta::Unknown {
            event_type: event_type.to_string(),
        },
    }
}

fn s(obj: &Map<String, Value>, k: &str) -> String {
    obj.get(k)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}
fn opt_s(obj: &Map<String, Value>, k: &str) -> Option<String> {
    obj.get(k).and_then(|v| v.as_str().map(String::from))
}
fn u(obj: &Map<String, Value>, k: &str) -> u64 {
    obj.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0)
}
fn opt_u(obj: &Map<String, Value>, k: &str) -> Option<u64> {
    obj.get(k).and_then(serde_json::Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_delta_falls_through_to_unknown_on_catalog_drift() {
        // `build_delta` is reached from `reduce` only after `kind_for`
        // recognizes the event_type. If a future catalog entry is added
        // without a matching `build_delta` arm, this path must yield
        // `Unknown`, never panic: it is FFI-reachable via the wasm
        // `adminReduce` export and the Python admin path, where a panic
        // becomes a wasm trap / pyo3 PanicException in user space.
        let obj = json!({ "event_type": "tn.future.uncatalogued" })
            .as_object()
            .unwrap()
            .clone();
        match build_delta("tn.future.uncatalogued", &obj) {
            StateDelta::Unknown { event_type } => {
                assert_eq!(event_type, "tn.future.uncatalogued");
            }
            other => panic!("expected Unknown fallthrough, got {other:?}"),
        }
    }
}
