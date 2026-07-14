"""Shared warning and audit payload for explicitly unsafe operations."""

from __future__ import annotations

import json
import warnings
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

UNSAFE_OPERATION_EVENT_TYPE = "tn.security.unsafe_operation"


class UnsafeOperation(str, Enum):
    """Operations whose compatibility switches can weaken TN guarantees."""

    READ = "read"
    WATCH = "watch"
    JWE_ADD_RECIPIENT = "jwe_add_recipient"
    HIBE_GRANT = "hibe_grant"
    LEGACY_PACKAGE_IMPORT = "legacy_package_import"


class UnsafeRelaxation(str, Enum):
    """Stable wire names for every explicit security relaxation."""

    VERIFICATION_DISABLED = "verification_disabled"
    SIGNATURE_NOT_REQUIRED = "signature_not_required"
    UNAUTHENTICATED_ALLOWED = "unauthenticated_allowed"
    UNKNOWN_WRITER_ALLOWED = "unknown_writer_allowed"
    UNVERIFIED_KEY_BINDING = "unverified_key_binding"
    PLAINTEXT_BEARER_DELIVERY = "plaintext_bearer_delivery"
    LEGACY_SIGNER_MISMATCH = "legacy_signer_mismatch"


@dataclass(frozen=True)
class UnsafeOperationNotice:
    """Non-secret, cross-SDK description of one explicitly unsafe request."""

    operation: UnsafeOperation
    relaxations: tuple[UnsafeRelaxation, ...]
    group: str | None = None
    subject_did: str | None = None
    artifact_digest: str | None = None

    def __post_init__(self) -> None:
        operation = UnsafeOperation(self.operation)
        relaxations = tuple(
            sorted(
                {UnsafeRelaxation(value) for value in self.relaxations},
                key=lambda value: value.value,
            ),
        )
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "relaxations", relaxations)

    def to_fields(self) -> dict[str, object]:
        """Return the exact five-field administrative event payload."""

        return {
            "artifact_digest": self.artifact_digest,
            "group": self.group,
            "operation": self.operation.value,
            "relaxations": [value.value for value in self.relaxations],
            "subject_did": self.subject_did,
        }

    def to_canonical_json(self) -> str:
        """Serialize the notice as ``tn-canonical-json-v1`` JSON."""

        return json.dumps(
            self.to_fields(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


class TnSecurityWarning(UserWarning):
    """Language warning carrying a structured unsafe-operation notice."""

    def __init__(self, notice: UnsafeOperationNotice) -> None:
        self.notice = notice
        super().__init__(
            f"explicit TN security weakening requested: {notice.to_canonical_json()}",
        )


class UnsafeOperationContext(Protocol):
    """Minimum context needed for best-effort administrative emission."""

    writable: bool

    def emit_admin(self, event_type: str, fields: dict[str, object]) -> Any: ...


_AUDIT_RECURSION: ContextVar[bool] = ContextVar(
    "tn_security_audit_recursion",
    default=False,
)


def record_unsafe_operation(
    notice: UnsafeOperationNotice,
    context: UnsafeOperationContext,
) -> None:
    """Warn once and best-effort emit the common event when context is writable."""

    if _AUDIT_RECURSION.get():
        return

    token = _AUDIT_RECURSION.set(True)
    try:
        warnings.warn(TnSecurityWarning(notice), stacklevel=2)
        if context.writable:
            try:
                context.emit_admin(UNSAFE_OPERATION_EVENT_TYPE, notice.to_fields())
            except Exception:  # noqa: BLE001 - audit emission is deliberately best effort.
                # Audit observability must never alter the requested operation.
                pass
    finally:
        _AUDIT_RECURSION.reset(token)


__all__ = [
    "UNSAFE_OPERATION_EVENT_TYPE",
    "TnSecurityWarning",
    "UnsafeOperation",
    "UnsafeOperationContext",
    "UnsafeOperationNotice",
    "UnsafeRelaxation",
    "record_unsafe_operation",
]
