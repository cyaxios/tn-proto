"""Pure secure-default policy resolution and per-record read decisions."""

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
        """Evaluate one already-scanned record without reading mutable state."""

        reasons: list[ReadRejectReason] = []

        def reject(reason: ReadRejectReason) -> None:
            if reason not in reasons:
                reasons.append(reason)

        if not record.record_valid:
            reject(ReadRejectReason.RECORD_INVALID)
            return ReadDecision(
                accepted=False,
                reasons=reasons,
                writer_authenticated=False,
                writer_authorized=False,
            )

        chain_required = not (
            context.active
            and context.local_log
            and not context.detached
            and context.profile_chain is False
        )
        # A signature authenticates the row hash, so a signed record still
        # requires that hash even when the local profile disables chaining.
        row_hash_required = chain_required or record.signature_present
        row_hash_valid = not row_hash_required or (
            record.row_hash_present and record.row_hash_valid
        )
        if not row_hash_valid:
            reject(ReadRejectReason.ROW_HASH_INVALID)
        chain_valid = not chain_required or record.chain_valid
        if not chain_valid:
            reject(ReadRejectReason.CHAIN_INVALID)

        writer_authenticated = record.signature_present and record.signature_valid
        if not record.signature_present:
            if self.require_signature:
                reject(ReadRejectReason.SIGNATURE_REQUIRED)
        elif not record.signature_valid:
            reject(ReadRejectReason.SIGNATURE_INVALID)

        writer_trusted = record.writer_did in self.trusted_writers
        if not writer_trusted and not self.allow_unknown_writers:
            reject(ReadRejectReason.WRITER_UNTRUSTED)

        if not record.aad_valid:
            reject(ReadRejectReason.AAD_INVALID)
        if (
            context.required_group is not None
            and context.required_group not in record.recipient_groups
        ):
            reject(ReadRejectReason.NOT_A_RECIPIENT)

        integrity_valid = row_hash_valid and chain_valid
        writer_authorized = writer_authenticated and writer_trusted and integrity_valid

        ignored: frozenset[ReadRejectReason]
        if self.mode == "disabled":
            ignored = frozenset(
                {
                    ReadRejectReason.ROW_HASH_INVALID,
                    ReadRejectReason.CHAIN_INVALID,
                    ReadRejectReason.SIGNATURE_REQUIRED,
                    ReadRejectReason.SIGNATURE_INVALID,
                    ReadRejectReason.WRITER_UNTRUSTED,
                },
            )
            writer_authenticated = False
            writer_authorized = False
        elif self.allow_unauthenticated:
            ignored = frozenset(
                {
                    ReadRejectReason.SIGNATURE_REQUIRED,
                },
            )
        else:
            ignored = frozenset()

        accepted = all(reason in ignored for reason in reasons)
        return ReadDecision(
            accepted=accepted,
            reasons=reasons,
            writer_authenticated=writer_authenticated,
            writer_authorized=writer_authorized,
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
