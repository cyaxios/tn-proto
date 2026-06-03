//! Pre-filled [`AbsorbReceipt`] constructors for the snapshot-absorb
//! short-circuits.
//!
//! [`noop_receipt`] is returned when the receiver's clock already dominates the
//! manifest; [`rejected_receipt`] when the snapshot body is missing or
//! malformed. Both keep the receipt-shaping out of the orchestrator on
//! [`Runtime`](crate::Runtime). The [`AbsorbReceipt`] type itself is part of the
//! public API and lives in [`super`].

use super::AbsorbReceipt;
use crate::tnpkg::Manifest;

/// Receipt for the "manifest is already dominated" short-circuit.
pub(super) fn noop_receipt(manifest: &Manifest) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: manifest.kind.as_str().into(),
        accepted_count: 0,
        deduped_count: 0,
        noop: true,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: String::new(),
        legacy_reason: String::new(),
        replaced_kit_paths: Vec::new(),
    }
}

/// Receipt for the "body missing/malformed" rejection paths.
pub(super) fn rejected_receipt(manifest: &Manifest, reason: &str) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: manifest.kind.as_str().into(),
        accepted_count: 0,
        deduped_count: 0,
        noop: false,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: "rejected".into(),
        legacy_reason: reason.into(),
        replaced_kit_paths: Vec::new(),
    }
}
