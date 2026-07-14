//! Structured warning and audit delivery for explicit read-policy weakening.

use tn_core::{UnsafeOperation, UnsafeOperationNotice, UnsafeRelaxation};

use crate::{ReadPolicyOptions, Tn};

pub(crate) fn warn_and_audit_read_weakening(
    tn: &Tn,
    options: &ReadPolicyOptions,
    operation: UnsafeOperation,
) {
    let mut relaxations = Vec::new();
    if options.verify == tn_core::runtime::VerifyMode::Disabled {
        relaxations.push(UnsafeRelaxation::VerificationDisabled);
    }
    if options.require_signature == Some(false) {
        relaxations.push(UnsafeRelaxation::SignatureNotRequired);
    }
    if options.allow_unauthenticated == Some(true) {
        relaxations.push(UnsafeRelaxation::UnauthenticatedAllowed);
    }
    if options.allow_unknown_writers {
        relaxations.push(UnsafeRelaxation::UnknownWriterAllowed);
    }
    if relaxations.is_empty() {
        return;
    }

    let notice = UnsafeOperationNotice::new(operation, relaxations);
    tn_core::trusted_enrollment::emit_unsafe_warning(&notice);
    tn.emit_unsafe_operation_audit(&notice);
}
