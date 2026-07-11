"""Strict signed statements for TN trusted-principal enrollment."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from .canonical import _canonical_bytes
from .trust import (
    TrustError,
    TrustReason,
    VerifiedJweBinding,
    VerifiedPrincipal,
    parse_ed25519_did_key,
    verify_ed25519_did_signature,
)

if TYPE_CHECKING:
    from .signing import DeviceKey


Purpose = Literal["jwe-reader", "hibe-reader", "hibe-authority"]

_PURPOSES = frozenset(("jwe-reader", "hibe-reader", "hibe-authority"))
_CHALLENGE_FIELDS = frozenset(
    (
        "version",
        "kind",
        "publisher_did",
        "expected_reader_did",
        "ceremony_id",
        "group",
        "nonce_b64",
        "issued_at",
        "expires_at",
        "challenge_id",
        "signature_b64",
    )
)
_PROOF_FIELDS = frozenset(
    (
        "version",
        "purpose",
        "subject_did",
        "audience_did",
        "ceremony_id",
        "group",
        "issued_at",
        "expires_at",
        "nonce_b64",
        "binding",
        "signature_b64",
    )
)
_RESPONSE_FIELDS = frozenset(
    (
        "version",
        "kind",
        "publisher_did",
        "reader_did",
        "ceremony_id",
        "group",
        "accepted_offer_digest",
        "x25519_public_key_sha256",
        "group_epoch",
        "issued_at",
        "expires_at",
        "signature_b64",
    )
)
_BINDING_FIELDS = {
    "jwe-reader": frozenset(("algorithm", "public_key_b64", "challenge_digest")),
    "hibe-reader": frozenset(("algorithm", "delivery", "challenge_digest")),
    "hibe-authority": frozenset(("algorithm", "mpk_sha256", "path_epoch", "max_depth", "id_path")),
}
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _error(reason: TrustReason, detail: str) -> TrustError:
    return TrustError(reason, detail)


def _exact_fields(
    value: object,
    expected: frozenset[str],
    label: str,
    *,
    reason: TrustReason = TrustReason.STATEMENT_INVALID,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _error(reason, f"{label} must be an object")
    keys = set(value.keys())
    if not all(isinstance(key, str) for key in keys):
        raise _error(reason, f"{label} field names must be strings")
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(keys - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing!r}")
        if unknown:
            details.append(f"unknown fields {unknown!r}")
        raise _error(reason, f"{label} has " + " and ".join(details))
    return value


def _string(
    value: object,
    field: str,
    *,
    reason: TrustReason = TrustReason.STATEMENT_INVALID,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        suffix = "a string" if allow_empty else "a non-empty string"
        raise _error(reason, f"{field} must be {suffix}")
    return value


def _integer(
    value: object,
    field: str,
    *,
    minimum: int,
    reason: TrustReason = TrustReason.STATEMENT_INVALID,
) -> int:
    if type(value) is not int or value < minimum:
        raise _error(reason, f"{field} must be an integer greater than or equal to {minimum}")
    return value


def _parse_datetime(value: object, field: str) -> datetime:
    text = _string(value, field)
    if not text.endswith("Z"):
        raise _error(TrustReason.STATEMENT_INVALID, f"{field} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise _error(
            TrustReason.STATEMENT_INVALID, f"{field} is not a valid UTC timestamp"
        ) from exc
    parsed = _utc_datetime(parsed, field)
    if _format_datetime(parsed) != text:
        raise _error(TrustReason.STATEMENT_INVALID, f"{field} is not in canonical UTC form")
    return parsed


def _utc_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _error(
            TrustReason.STATEMENT_INVALID, f"{field} must be a timezone-aware UTC datetime"
        )
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise _error(TrustReason.STATEMENT_INVALID, f"{field} is not a valid datetime") from exc
    if offset != timedelta(0):
        raise _error(TrustReason.STATEMENT_INVALID, f"{field} must use UTC")
    return value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    utc = _utc_datetime(value, "timestamp")
    return utc.isoformat().replace("+00:00", "Z")


def _validate_time_order(issued_at: datetime, expires_at: datetime) -> None:
    issued_at = _utc_datetime(issued_at, "issued_at")
    expires_at = _utc_datetime(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise _error(TrustReason.STATEMENT_INVALID, "expires_at must be later than issued_at")


def _validate_freshness(issued_at: datetime, expires_at: datetime, now: datetime) -> None:
    _validate_time_order(issued_at, expires_at)
    now = _utc_datetime(now, "now")
    if now < issued_at:
        raise _error(TrustReason.STATEMENT_INVALID, "statement was issued in the future")
    if now >= expires_at:
        raise _error(TrustReason.STATEMENT_EXPIRED, "statement has expired")


def _decode_b64(
    value: object,
    field: str,
    *,
    length: int,
    reason: TrustReason,
) -> bytes:
    text = _string(value, field, reason=reason)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise _error(reason, f"{field} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != text:
        raise _error(reason, f"{field} must be canonical padded base64")
    if len(decoded) != length:
        raise _error(reason, f"{field} must decode to exactly {length} bytes")
    return decoded


def _validate_nonce(value: object) -> None:
    _decode_b64(
        value,
        "nonce_b64",
        length=32,
        reason=TrustReason.STATEMENT_INVALID,
    )


def _signature_bytes(value: object, *, allow_unsigned: bool = False) -> bytes | None:
    if allow_unsigned and value == "":
        return None
    return _decode_b64(
        value,
        "signature_b64",
        length=64,
        reason=TrustReason.SIGNATURE_INVALID,
    )


def _validate_digest(
    value: object,
    field: str,
    *,
    reason: TrustReason = TrustReason.STATEMENT_INVALID,
) -> str:
    text = _string(value, field, reason=reason)
    if _SHA256_RE.fullmatch(text) is None:
        raise _error(reason, f"{field} must be a lowercase sha256 digest")
    return text


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _validate_did(value: object, field: str) -> str:
    did = _string(value, field)
    parse_ed25519_did_key(did)
    return did


def _validate_nonempty(value: object, field: str) -> str:
    return _string(value, field)


def _ensure_signing_key(key: DeviceKey, expected_did: str) -> None:
    actual_did = getattr(key, "device_identity", None)
    if not isinstance(actual_did, str):
        actual_did = getattr(key, "did", None)
    if actual_did != expected_did:
        raise _error(
            TrustReason.DID_SIGNER_MISMATCH,
            "signing key identity does not match the statement signer",
        )


def _sign(key: DeviceKey, signing_bytes: bytes) -> str:
    signature = key.sign(signing_bytes)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise _error(TrustReason.SIGNATURE_INVALID, "signing key returned an invalid signature")
    return base64.b64encode(signature).decode("ascii")


def _proof_binding(binding: object, purpose: Purpose) -> dict[str, object]:
    expected = _BINDING_FIELDS[purpose]
    value = _exact_fields(
        binding,
        expected,
        f"{purpose} binding",
        reason=TrustReason.BINDING_INVALID,
    )
    result = dict(value)

    if purpose == "jwe-reader":
        if (
            _string(
                value["algorithm"],
                "binding.algorithm",
                reason=TrustReason.BINDING_INVALID,
            )
            != "X25519"
        ):
            raise _error(TrustReason.BINDING_INVALID, "jwe-reader binding algorithm must be X25519")
        _decode_b64(
            value["public_key_b64"],
            "binding.public_key_b64",
            length=32,
            reason=TrustReason.BINDING_INVALID,
        )
        _validate_digest(
            value["challenge_digest"],
            "binding.challenge_digest",
            reason=TrustReason.BINDING_INVALID,
        )
        return result

    if purpose == "hibe-reader":
        if (
            _string(
                value["algorithm"],
                "binding.algorithm",
                reason=TrustReason.BINDING_INVALID,
            )
            != "Ed25519-did-key"
        ):
            raise _error(
                TrustReason.BINDING_INVALID,
                "hibe-reader binding algorithm must be Ed25519-did-key",
            )
        if (
            _string(
                value["delivery"],
                "binding.delivery",
                reason=TrustReason.BINDING_INVALID,
            )
            != "recipient-seal-v1"
        ):
            raise _error(
                TrustReason.BINDING_INVALID,
                "hibe-reader delivery must be recipient-seal-v1",
            )
        _validate_digest(
            value["challenge_digest"],
            "binding.challenge_digest",
            reason=TrustReason.BINDING_INVALID,
        )
        return result

    if (
        _string(
            value["algorithm"],
            "binding.algorithm",
            reason=TrustReason.BINDING_INVALID,
        )
        != "TN-BBG-HIBE-BLS12-381"
    ):
        raise _error(
            TrustReason.BINDING_INVALID,
            "hibe-authority binding algorithm must be TN-BBG-HIBE-BLS12-381",
        )
    _validate_digest(
        value["mpk_sha256"],
        "binding.mpk_sha256",
        reason=TrustReason.BINDING_INVALID,
    )
    _integer(
        value["path_epoch"],
        "binding.path_epoch",
        minimum=0,
        reason=TrustReason.BINDING_INVALID,
    )
    max_depth = _integer(
        value["max_depth"],
        "binding.max_depth",
        minimum=1,
        reason=TrustReason.BINDING_INVALID,
    )
    id_path = _string(
        value["id_path"],
        "binding.id_path",
        reason=TrustReason.BINDING_INVALID,
    )
    parts = id_path.split("/")
    if any(not part for part in parts) or len(parts) > max_depth:
        raise _error(
            TrustReason.BINDING_INVALID,
            "binding.id_path must contain one to max_depth non-empty components",
        )
    return result


@dataclass(frozen=True, slots=True)
class EnrollmentChallengeV1:
    version: Literal[1]
    kind: Literal["tn-enrollment-challenge"]
    publisher_did: str
    expected_reader_did: str
    ceremony_id: str
    group: str
    nonce_b64: str
    issued_at: datetime
    expires_at: datetime
    challenge_id: str
    signature_b64: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EnrollmentChallengeV1:
        value = _exact_fields(value, _CHALLENGE_FIELDS, "enrollment challenge")
        version = _integer(value["version"], "version", minimum=1)
        if version != 1:
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment challenge version")
        kind = _string(value["kind"], "kind")
        if kind != "tn-enrollment-challenge":
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment challenge kind")
        result = cls(
            version=1,
            kind="tn-enrollment-challenge",
            publisher_did=_string(value["publisher_did"], "publisher_did"),
            expected_reader_did=_string(value["expected_reader_did"], "expected_reader_did"),
            ceremony_id=_string(value["ceremony_id"], "ceremony_id"),
            group=_string(value["group"], "group"),
            nonce_b64=_string(value["nonce_b64"], "nonce_b64"),
            issued_at=_parse_datetime(value["issued_at"], "issued_at"),
            expires_at=_parse_datetime(value["expires_at"], "expires_at"),
            challenge_id=_string(value["challenge_id"], "challenge_id"),
            signature_b64=_string(
                value["signature_b64"],
                "signature_b64",
                allow_empty=True,
            ),
        )
        result._validate(allow_unsigned=False)
        return result

    def _validate(self, *, allow_unsigned: bool) -> None:
        if (
            type(self.version) is not int
            or self.version != 1
            or self.kind != "tn-enrollment-challenge"
        ):
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment challenge")
        _validate_did(self.publisher_did, "publisher_did")
        _validate_did(self.expected_reader_did, "expected_reader_did")
        _validate_nonempty(self.ceremony_id, "ceremony_id")
        _validate_nonempty(self.group, "group")
        _validate_nonempty(self.challenge_id, "challenge_id")
        _validate_nonce(self.nonce_b64)
        _validate_time_order(self.issued_at, self.expires_at)
        _signature_bytes(self.signature_b64, allow_unsigned=allow_unsigned)

    def _wire_value(self, *, include_signature: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "version": self.version,
            "kind": self.kind,
            "publisher_did": self.publisher_did,
            "expected_reader_did": self.expected_reader_did,
            "ceremony_id": self.ceremony_id,
            "group": self.group,
            "nonce_b64": self.nonce_b64,
            "issued_at": _format_datetime(self.issued_at),
            "expires_at": _format_datetime(self.expires_at),
            "challenge_id": self.challenge_id,
        }
        if include_signature:
            value["signature_b64"] = self.signature_b64
        return value

    def signing_bytes(self) -> bytes:
        self._validate(allow_unsigned=True)
        return _canonical_bytes(self._wire_value(include_signature=False))

    def sign(self, key: DeviceKey) -> EnrollmentChallengeV1:
        self._validate(allow_unsigned=True)
        _ensure_signing_key(key, self.publisher_did)
        return replace(self, signature_b64=_sign(key, self.signing_bytes()))


def verify_enrollment_challenge(
    challenge: EnrollmentChallengeV1,
    expected_publisher_did: str,
    expected_reader_did: str,
    expected_ceremony_id: str,
    expected_group: str,
    now: datetime,
) -> None:
    challenge._validate(allow_unsigned=False)
    _validate_did(expected_publisher_did, "expected_publisher_did")
    _validate_did(expected_reader_did, "expected_reader_did")
    if challenge.publisher_did != expected_publisher_did:
        raise _error(
            TrustReason.DID_SIGNER_MISMATCH,
            "challenge publisher does not match the expected publisher",
        )
    if challenge.expected_reader_did != expected_reader_did:
        raise _error(TrustReason.WRONG_RECIPIENT, "challenge names a different reader")
    if challenge.ceremony_id != expected_ceremony_id or challenge.group != expected_group:
        raise _error(TrustReason.SCOPE_MISMATCH, "challenge ceremony or group does not match")
    _validate_freshness(challenge.issued_at, challenge.expires_at, now)
    signature = cast(bytes, _signature_bytes(challenge.signature_b64))
    verify_ed25519_did_signature(
        challenge.publisher_did,
        challenge.signing_bytes(),
        signature,
    )


@dataclass(frozen=True, slots=True)
class KeyBindingProofV1:
    version: Literal[1]
    purpose: Purpose
    subject_did: str
    audience_did: str
    ceremony_id: str
    group: str
    issued_at: datetime
    expires_at: datetime
    nonce_b64: str
    binding: Mapping[str, object]
    signature_b64: str

    def __post_init__(self) -> None:
        if not isinstance(self.binding, Mapping):
            raise _error(TrustReason.BINDING_INVALID, "key-binding proof binding must be an object")
        # A proof is a value object. Snapshot and freeze nested input so a
        # stateful Mapping cannot change between signature verification and
        # purpose-specific key extraction.
        object.__setattr__(self, "binding", MappingProxyType(dict(self.binding)))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> KeyBindingProofV1:
        value = _exact_fields(value, _PROOF_FIELDS, "key-binding proof")
        version = _integer(value["version"], "version", minimum=1)
        if version != 1:
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported key-binding proof version")
        purpose_text = _string(value["purpose"], "purpose")
        if purpose_text not in _PURPOSES:
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported key-binding proof purpose")
        purpose = cast(Purpose, purpose_text)
        result = cls(
            version=1,
            purpose=purpose,
            subject_did=_string(value["subject_did"], "subject_did"),
            audience_did=_string(value["audience_did"], "audience_did"),
            ceremony_id=_string(value["ceremony_id"], "ceremony_id"),
            group=_string(value["group"], "group"),
            issued_at=_parse_datetime(value["issued_at"], "issued_at"),
            expires_at=_parse_datetime(value["expires_at"], "expires_at"),
            nonce_b64=_string(value["nonce_b64"], "nonce_b64"),
            binding=_proof_binding(value["binding"], purpose),
            signature_b64=_string(
                value["signature_b64"],
                "signature_b64",
                allow_empty=True,
            ),
        )
        result._validate(allow_unsigned=False)
        return result

    def _validate(self, *, allow_unsigned: bool) -> None:
        if type(self.version) is not int or self.version != 1 or self.purpose not in _PURPOSES:
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported key-binding proof")
        _validate_did(self.subject_did, "subject_did")
        _validate_did(self.audience_did, "audience_did")
        _validate_nonempty(self.ceremony_id, "ceremony_id")
        _validate_nonempty(self.group, "group")
        _validate_nonce(self.nonce_b64)
        _validate_time_order(self.issued_at, self.expires_at)
        _proof_binding(self.binding, cast(Purpose, self.purpose))
        _signature_bytes(self.signature_b64, allow_unsigned=allow_unsigned)

    def _wire_value(self, *, include_signature: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "version": self.version,
            "purpose": self.purpose,
            "subject_did": self.subject_did,
            "audience_did": self.audience_did,
            "ceremony_id": self.ceremony_id,
            "group": self.group,
            "issued_at": _format_datetime(self.issued_at),
            "expires_at": _format_datetime(self.expires_at),
            "nonce_b64": self.nonce_b64,
            "binding": dict(self.binding),
        }
        if include_signature:
            value["signature_b64"] = self.signature_b64
        return value

    def signing_bytes(self) -> bytes:
        self._validate(allow_unsigned=True)
        return _canonical_bytes(self._wire_value(include_signature=False))

    def sign(self, key: DeviceKey) -> KeyBindingProofV1:
        self._validate(allow_unsigned=True)
        _ensure_signing_key(key, self.subject_did)
        return replace(self, signature_b64=_sign(key, self.signing_bytes()))


def verify_key_binding_proof(
    proof: KeyBindingProofV1,
    expected_purpose: str,
    expected_audience_did: str,
    expected_ceremony_id: str,
    expected_group: str,
    now: datetime,
    challenge: EnrollmentChallengeV1 | None,
) -> VerifiedPrincipal:
    proof._validate(allow_unsigned=False)
    if expected_purpose not in _PURPOSES or proof.purpose != expected_purpose:
        raise _error(TrustReason.BINDING_INVALID, "key-binding proof purpose does not match")
    _validate_did(expected_audience_did, "expected_audience_did")
    if proof.audience_did != expected_audience_did:
        raise _error(TrustReason.WRONG_RECIPIENT, "key-binding proof names a different audience")
    if proof.ceremony_id != expected_ceremony_id or proof.group != expected_group:
        raise _error(
            TrustReason.SCOPE_MISMATCH, "key-binding proof ceremony or group does not match"
        )
    _validate_freshness(proof.issued_at, proof.expires_at, now)

    if proof.purpose in {"jwe-reader", "hibe-reader"}:
        if challenge is None:
            raise _error(TrustReason.CHALLENGE_MISSING, "reader proof requires a challenge")
        try:
            verify_enrollment_challenge(
                challenge,
                expected_publisher_did=expected_audience_did,
                expected_reader_did=proof.subject_did,
                expected_ceremony_id=expected_ceremony_id,
                expected_group=expected_group,
                now=now,
            )
        except TrustError as exc:
            if exc.reason is TrustReason.STATEMENT_EXPIRED:
                raise _error(TrustReason.CHALLENGE_EXPIRED, exc.detail) from exc
            raise
        if not (challenge.issued_at <= proof.issued_at < challenge.expires_at):
            raise _error(
                TrustReason.BINDING_INVALID,
                "proof issuance time is outside the challenge validity interval",
            )
        challenge_digest = _sha256(_canonical_bytes(challenge._wire_value(include_signature=True)))
        if proof.binding["challenge_digest"] != challenge_digest:
            raise _error(TrustReason.BINDING_INVALID, "proof is bound to a different challenge")

    signature = cast(bytes, _signature_bytes(proof.signature_b64))
    verify_ed25519_did_signature(proof.subject_did, proof.signing_bytes(), signature)
    proof_digest = _sha256(_canonical_bytes(proof._wire_value(include_signature=True)))
    return VerifiedPrincipal(
        did=proof.subject_did,
        purpose=proof.purpose,
        audience_did=proof.audience_did,
        ceremony_id=proof.ceremony_id,
        group=proof.group,
        proof_digest=proof_digest,
        issued_at=proof.issued_at,
        expires_at=proof.expires_at,
    )


def verify_jwe_key_binding(
    proof: KeyBindingProofV1,
    expected_audience_did: str,
    expected_ceremony_id: str,
    expected_group: str,
    now: datetime,
    challenge: EnrollmentChallengeV1 | None,
) -> VerifiedJweBinding:
    principal = verify_key_binding_proof(
        proof,
        expected_purpose="jwe-reader",
        expected_audience_did=expected_audience_did,
        expected_ceremony_id=expected_ceremony_id,
        expected_group=expected_group,
        now=now,
        challenge=challenge,
    )
    public_key = _decode_b64(
        proof.binding["public_key_b64"],
        "binding.public_key_b64",
        length=32,
        reason=TrustReason.BINDING_INVALID,
    )
    challenge_digest = cast(str, proof.binding.get("challenge_digest"))
    return VerifiedJweBinding(
        principal=principal,
        public_key=public_key,
        public_key_sha256=_sha256(public_key),
        proof_digest=principal.proof_digest,
        challenge_digest=challenge_digest,
    )


@dataclass(frozen=True, slots=True)
class EnrollmentResponseV1:
    version: Literal[1]
    kind: Literal["tn-enrollment-response"]
    publisher_did: str
    reader_did: str
    ceremony_id: str
    group: str
    accepted_offer_digest: str
    x25519_public_key_sha256: str
    group_epoch: int
    issued_at: datetime
    expires_at: datetime
    signature_b64: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EnrollmentResponseV1:
        value = _exact_fields(value, _RESPONSE_FIELDS, "enrollment response")
        version = _integer(value["version"], "version", minimum=1)
        if version != 1:
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment response version")
        kind = _string(value["kind"], "kind")
        if kind != "tn-enrollment-response":
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment response kind")
        result = cls(
            version=1,
            kind="tn-enrollment-response",
            publisher_did=_string(value["publisher_did"], "publisher_did"),
            reader_did=_string(value["reader_did"], "reader_did"),
            ceremony_id=_string(value["ceremony_id"], "ceremony_id"),
            group=_string(value["group"], "group"),
            accepted_offer_digest=_string(
                value["accepted_offer_digest"],
                "accepted_offer_digest",
            ),
            x25519_public_key_sha256=_string(
                value["x25519_public_key_sha256"],
                "x25519_public_key_sha256",
            ),
            group_epoch=_integer(value["group_epoch"], "group_epoch", minimum=0),
            issued_at=_parse_datetime(value["issued_at"], "issued_at"),
            expires_at=_parse_datetime(value["expires_at"], "expires_at"),
            signature_b64=_string(
                value["signature_b64"],
                "signature_b64",
                allow_empty=True,
            ),
        )
        result._validate(allow_unsigned=False)
        return result

    def _validate(self, *, allow_unsigned: bool) -> None:
        if (
            type(self.version) is not int
            or self.version != 1
            or self.kind != "tn-enrollment-response"
        ):
            raise _error(TrustReason.STATEMENT_INVALID, "unsupported enrollment response")
        _validate_did(self.publisher_did, "publisher_did")
        _validate_did(self.reader_did, "reader_did")
        _validate_nonempty(self.ceremony_id, "ceremony_id")
        _validate_nonempty(self.group, "group")
        _validate_digest(self.accepted_offer_digest, "accepted_offer_digest")
        _validate_digest(self.x25519_public_key_sha256, "x25519_public_key_sha256")
        _integer(self.group_epoch, "group_epoch", minimum=0)
        _validate_time_order(self.issued_at, self.expires_at)
        _signature_bytes(self.signature_b64, allow_unsigned=allow_unsigned)

    def _wire_value(self, *, include_signature: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "version": self.version,
            "kind": self.kind,
            "publisher_did": self.publisher_did,
            "reader_did": self.reader_did,
            "ceremony_id": self.ceremony_id,
            "group": self.group,
            "accepted_offer_digest": self.accepted_offer_digest,
            "x25519_public_key_sha256": self.x25519_public_key_sha256,
            "group_epoch": self.group_epoch,
            "issued_at": _format_datetime(self.issued_at),
            "expires_at": _format_datetime(self.expires_at),
        }
        if include_signature:
            value["signature_b64"] = self.signature_b64
        return value

    def signing_bytes(self) -> bytes:
        self._validate(allow_unsigned=True)
        return _canonical_bytes(self._wire_value(include_signature=False))

    def sign(self, key: DeviceKey) -> EnrollmentResponseV1:
        self._validate(allow_unsigned=True)
        _ensure_signing_key(key, self.publisher_did)
        return replace(self, signature_b64=_sign(key, self.signing_bytes()))


def verify_enrollment_response(
    response: EnrollmentResponseV1,
    expected_publisher_did: str,
    expected_reader_did: str,
    expected_ceremony_id: str,
    expected_group: str,
    expected_offer_digest: str,
    expected_public_key_sha256: str,
    now: datetime,
) -> None:
    response._validate(allow_unsigned=False)
    _validate_did(expected_publisher_did, "expected_publisher_did")
    _validate_did(expected_reader_did, "expected_reader_did")
    if response.publisher_did != expected_publisher_did:
        raise _error(
            TrustReason.DID_SIGNER_MISMATCH,
            "response publisher does not match the expected publisher",
        )
    if response.reader_did != expected_reader_did:
        raise _error(TrustReason.WRONG_RECIPIENT, "response names a different reader")
    if response.ceremony_id != expected_ceremony_id or response.group != expected_group:
        raise _error(TrustReason.SCOPE_MISMATCH, "response ceremony or group does not match")
    _validate_digest(
        expected_offer_digest,
        "expected_offer_digest",
        reason=TrustReason.BINDING_INVALID,
    )
    _validate_digest(
        expected_public_key_sha256,
        "expected_public_key_sha256",
        reason=TrustReason.BINDING_INVALID,
    )
    if response.accepted_offer_digest != expected_offer_digest:
        raise _error(TrustReason.BINDING_INVALID, "response names a different accepted offer")
    if response.x25519_public_key_sha256 != expected_public_key_sha256:
        raise _error(TrustReason.BINDING_INVALID, "response names a different X25519 key")
    _validate_freshness(response.issued_at, response.expires_at, now)
    signature = cast(bytes, _signature_bytes(response.signature_b64))
    verify_ed25519_did_signature(response.publisher_did, response.signing_bytes(), signature)


__all__ = [
    "EnrollmentChallengeV1",
    "EnrollmentResponseV1",
    "KeyBindingProofV1",
    "verify_enrollment_challenge",
    "verify_enrollment_response",
    "verify_jwe_key_binding",
    "verify_key_binding_proof",
]
