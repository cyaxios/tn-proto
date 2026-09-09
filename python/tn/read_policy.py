"""Read-policy compatibility types backed by the canonical Rust evaluator."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum
from typing import Literal, TypeAlias, cast

from .read_trust import ReadTrustProvider, validate_ed25519_did

VerifyMode: TypeAlias = Literal["auto", "raise", "skip"] | bool
ResolvedVerifyMode: TypeAlias = Literal["raise", "skip", "disabled"]


class ReadRejectReason(str, Enum):
    RECORD_INVALID = "record_invalid"
    ROW_HASH_INVALID = "row_hash_invalid"
    CHAIN_INVALID = "chain_invalid"
    SIGNATURE_REQUIRED = "signature_required"
    SIGNATURE_INVALID = "signature_invalid"
    WRITER_UNTRUSTED = "writer_untrusted"
    AAD_INVALID = "aad_invalid"
    NOT_A_RECIPIENT = "not_a_recipient"


@dataclass(frozen=True)
class ReadContext:
    active: bool
    local_log: bool
    detached: bool
    writable: bool
    profile_sign: bool | None
    profile_chain: bool | None
    local_device_did: str | None
    required_group: str | None
    trust_provider: ReadTrustProvider


@dataclass(frozen=True)
class ReadRecordState:
    record_valid: bool
    row_hash_present: bool
    row_hash_valid: bool
    chain_valid: bool
    signature_present: bool
    signature_valid: bool
    writer_did: str | None
    aad_valid: bool
    recipient_groups: frozenset[str]


@dataclass(frozen=True)
class ReadDecision:
    accepted: bool
    reasons: list[ReadRejectReason]
    writer_authenticated: bool
    writer_authorized: bool

    @property
    def first_reason(self) -> ReadRejectReason | None:
        """The stable reason used by raise/callback adapters."""

        return self.reasons[0] if self.reasons else None


@dataclass(frozen=True)
class ReadTrustPolicy:
    mode: ResolvedVerifyMode
    require_signature: bool
    allow_unauthenticated: bool
    trusted_writers: frozenset[str]
    allow_unknown_writers: bool

    @classmethod
    def resolve(
        cls,
        verify: VerifyMode,
        require_signature: bool | None,
        allow_unauthenticated: bool | None,
        trusted_writers: Collection[str] | None,
        allow_unknown_writers: bool,
        context: ReadContext,
    ) -> ReadTrustPolicy:
        """Freeze public options and receiver-local context into one policy."""

        mode = _resolve_verify_mode(verify)
        _require_optional_bool("require_signature", require_signature)
        _require_optional_bool("allow_unauthenticated", allow_unauthenticated)
        _require_bool("allow_unknown_writers", allow_unknown_writers)

        if mode == "disabled" and trusted_writers is not None:
            raise ValueError("verify=False cannot be combined with trusted_writers")

        inferred_unsigned_profile = (
            context.active
            and context.local_log
            and not context.detached
            and context.profile_sign is False
        )
        if require_signature is None:
            resolved_require_signature = (
                not allow_unauthenticated
                if allow_unauthenticated is not None
                else not inferred_unsigned_profile
            )
        else:
            resolved_require_signature = require_signature
        if allow_unauthenticated is None:
            resolved_allow_unauthenticated = not resolved_require_signature
        else:
            resolved_allow_unauthenticated = allow_unauthenticated
        if resolved_require_signature == resolved_allow_unauthenticated:
            raise ValueError(
                "require_signature and allow_unauthenticated must express one consistent policy",
            )

        if trusted_writers is None:
            resolved_trusted_writers = context.trust_provider.trusted_writer_dids(context)
        else:
            if isinstance(trusted_writers, (str, bytes)):
                raise ValueError("trusted_writers must be a collection of Ed25519 DIDs")
            resolved_trusted_writers = frozenset(
                validate_ed25519_did(did) for did in trusted_writers
            )

        return cls(
            mode=mode,
            require_signature=resolved_require_signature,
            allow_unauthenticated=resolved_allow_unauthenticated,
            trusted_writers=frozenset(resolved_trusted_writers),
            allow_unknown_writers=allow_unknown_writers,
        )

    def evaluate(self, record: ReadRecordState, context: ReadContext) -> ReadDecision:
        """Delegate already-scanned facts to Rust without reading mutable trust state."""

        from ._native.core import read_policy_evaluate

        decision = read_policy_evaluate(
            {
                "verify": self.mode,
                "require_signature": self.require_signature,
                "allow_unauthenticated": self.allow_unauthenticated,
                "trusted_writers": sorted(self.trusted_writers),
                # This is the already-resolved trust snapshot, not a new override.
                "trusted_writers_supplied": False,
                "allow_unknown_writers": self.allow_unknown_writers,
            },
            {
                "record_valid": record.record_valid,
                "row_hash_present": record.row_hash_present,
                "row_hash_valid": record.row_hash_valid,
                "chain_valid": record.chain_valid,
                "signature_present": record.signature_present,
                "signature_valid": record.signature_valid,
                "writer_did": record.writer_did,
                "aad_valid": record.aad_valid,
                "recipient_groups": sorted(record.recipient_groups),
            },
            {
                "active": context.active,
                "local_log": context.local_log,
                "detached": context.detached,
                "writable": context.writable,
                "profile_sign": context.profile_sign,
                "profile_chain": context.profile_chain,
                "local_device_did": context.local_device_did,
                "required_group": context.required_group,
            },
        )
        return ReadDecision(
            accepted=decision["accepted"],
            reasons=[ReadRejectReason(reason) for reason in decision["reasons"]],
            writer_authenticated=decision["writer_authenticated"],
            writer_authorized=decision["writer_authorized"],
        )


def _resolve_verify_mode(verify: VerifyMode) -> ResolvedVerifyMode:
    if verify is True:
        return "raise"
    if verify is False:
        return "disabled"
    if isinstance(verify, str) and verify in {"auto", "raise", "skip"}:
        return cast(ResolvedVerifyMode, "raise" if verify == "auto" else verify)
    raise ValueError("verify must be one of 'auto', 'raise', 'skip', True, or False")


def _require_optional_bool(name: str, value: bool | None) -> None:
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{name} must be bool or None")


def _require_bool(name: str, value: bool) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be bool")


__all__ = [
    "ReadContext",
    "ReadDecision",
    "ReadRecordState",
    "ReadRejectReason",
    "ReadTrustPolicy",
    "ResolvedVerifyMode",
    "VerifyMode",
]
