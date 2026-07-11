from __future__ import annotations

import warnings

from tn.security_audit import (
    UnsafeOperation,
    UnsafeOperationNotice,
    UnsafeRelaxation,
    TnSecurityWarning,
    record_unsafe_operation,
)


def _read_notice() -> UnsafeOperationNotice:
    return UnsafeOperationNotice(
        operation=UnsafeOperation.READ,
        relaxations=(UnsafeRelaxation.VERIFICATION_DISABLED,),
        group=None,
        subject_did=None,
        artifact_digest=None,
    )


class _AuditContext:
    def __init__(self, *, writable: bool = True, fail: bool = False) -> None:
        self.writable = writable
        self.fail = fail
        self.events: list[tuple[str, dict[str, object]]] = []

    def emit_admin(self, event_type: str, fields: dict[str, object]) -> None:
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.events.append((event_type, fields))


def test_notice_freezes_exact_enums_and_canonical_payload() -> None:
    assert [operation.value for operation in UnsafeOperation] == [
        "read",
        "watch",
        "jwe_add_recipient",
        "hibe_grant",
        "legacy_package_import",
    ]
    assert [relaxation.value for relaxation in UnsafeRelaxation] == [
        "verification_disabled",
        "signature_not_required",
        "unauthenticated_allowed",
        "unknown_writer_allowed",
        "unverified_key_binding",
        "plaintext_bearer_delivery",
        "legacy_signer_mismatch",
    ]
    assert _read_notice().to_fields() == {
        "artifact_digest": None,
        "group": None,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": None,
    }
    assert _read_notice().to_canonical_json() == (
        '{"artifact_digest":null,"group":null,"operation":"read",'
        '"relaxations":["verification_disabled"],"subject_did":null}'
    )


def test_notice_sorts_and_deduplicates_relaxations() -> None:
    notice = UnsafeOperationNotice(
        operation="jwe_add_recipient",
        relaxations=(
            "unverified_key_binding",
            UnsafeRelaxation.SIGNATURE_NOT_REQUIRED,
            UnsafeRelaxation.UNVERIFIED_KEY_BINDING,
        ),
        group="default",
        subject_did="did:key:zExample",
        artifact_digest="sha256:abc",
    )
    assert notice.relaxations == (
        UnsafeRelaxation.SIGNATURE_NOT_REQUIRED,
        UnsafeRelaxation.UNVERIFIED_KEY_BINDING,
    )


def test_record_warns_and_emits_exact_best_effort_admin_event() -> None:
    context = _AuditContext()
    notice = _read_notice()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        record_unsafe_operation(notice, context)

    warning = caught[0].message
    assert len(caught) == 1
    assert isinstance(warning, TnSecurityWarning)
    assert warning.notice is notice
    assert context.events == [
        ("tn.security.unsafe_operation", notice.to_fields()),
    ]


def test_warning_always_fires_when_audit_is_unwritable_or_fails() -> None:
    for context in (_AuditContext(writable=False), _AuditContext(fail=True)):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            record_unsafe_operation(_read_notice(), context)
        assert len(caught) == 1
        assert isinstance(caught[0].message, TnSecurityWarning)
        assert context.events == []


def test_recursion_guard_suppresses_nested_warning_and_audit() -> None:
    notice = _read_notice()

    class RecursiveContext(_AuditContext):
        def emit_admin(self, event_type: str, fields: dict[str, object]) -> None:
            super().emit_admin(event_type, fields)
            record_unsafe_operation(notice, self)

    context = RecursiveContext()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        record_unsafe_operation(notice, context)

    assert len(caught) == 1
    assert context.events == [
        ("tn.security.unsafe_operation", notice.to_fields()),
    ]
