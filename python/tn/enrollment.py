"""Receiver-local trusted enrollment challenge and pending-offer state."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ._keystore_backend import AdvisoryFileLock, atomic_write_bytes
from .canonical import _canonical_bytes
from .config import LoadedConfig
from .conventions import enrollment_dir, outbox_dir, tnpkg_filename
from .key_binding import (
    EnrollmentChallengeV1,
    EnrollmentResponseV1,
    KeyBindingProofV1,
    verify_enrollment_challenge,
    verify_enrollment_response,
    verify_jwe_key_binding,
)
from .packaging import Package
from .packaging import _canonical_bytes as _package_signing_bytes
from .packaging import verify as verify_package
from .signing import DeviceKey
from .tnpkg import (
    ManifestSignatureError,
    PackageError,
    _inspect_tnpkg_archive,
    _open_zip,
    _read_manifest,
)
from .trust import (
    AcceptedOffer,
    TrustError,
    TrustReason,
    VerifiedJweBinding,
    parse_ed25519_did_key,
    verify_ed25519_did_signature,
)

_SHA256_PREFIX = "sha256:"
_SHA256_LENGTH = len(_SHA256_PREFIX) + 64
_UTC = timezone.utc
# Enrollment offers contain one compact proof/package body. One MiB leaves
# generous extension room while bounding self-extracting ZIP prefixes and
# accidental/malicious raw artifact retention far below the generic package
# payload ceiling.
MAX_ENROLLMENT_ARTIFACT_BYTES = 1024 * 1024
# Unsolicited offers consume receiver-local disk before authorization. Keep a
# bounded review queue while reserving challenged enrollment capacity.
MAX_UNSOLICITED_OFFER_BYTES = 256 * 1024
MAX_UNSOLICITED_PENDING_COUNT = 128
MAX_UNSOLICITED_PENDING_BYTES = 8 * 1024 * 1024
# Publisher-issued challenges have capacity reserved independently of the
# unsolicited review queue, but are still bounded: a reader can otherwise
# mint unlimited distinct signed proof/container variants for one challenge
# before any one variant consumes it.
MAX_CHALLENGED_VARIANTS_PER_CHALLENGE = 4
MAX_CHALLENGED_PENDING_COUNT = 256
MAX_CHALLENGED_PENDING_BYTES = 32 * 1024 * 1024
MAX_ENROLLMENT_ZIP_ENTRIES = 8
MAX_ENROLLMENT_MEMBER_BYTES = 256 * 1024
MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024
MAX_ENROLLMENT_COMPRESSION_RATIO = 20
_SAFE_CHALLENGE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_SAFE_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_WINDOWS_RESERVED_COMPONENT = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class PendingOffer:
    """A verified binding backed by the complete retained signed artifact."""

    ceremony_id: str
    group: str
    reader_did: str
    offer_digest: str
    artifact_digest: str
    artifact_path: Path
    verified: VerifiedJweBinding


@dataclass(frozen=True, slots=True)
class OutboundOfferState:
    """Reader-held metadata required to authenticate an enrollment response."""

    version: int
    publisher_did: str
    reader_did: str
    ceremony_id: str
    group: str
    offer_digest: str
    artifact_digest: str
    proof_digest: str
    public_key_sha256: str
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "publisher_did": self.publisher_did,
            "reader_did": self.reader_did,
            "ceremony_id": self.ceremony_id,
            "group": self.group,
            "offer_digest": self.offer_digest,
            "artifact_digest": self.artifact_digest,
            "proof_digest": self.proof_digest,
            "public_key_sha256": self.public_key_sha256,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class EnrollmentResponseInstall:
    """Result of one authenticated reader-side response installation."""

    applied: bool
    response_digest: str
    publisher_did: str
    offer_digest: str


@dataclass(frozen=True, slots=True)
class _VerifiedArtifact:
    pending: PendingOffer
    artifact_digest: str
    challenge_id: str | None


@dataclass(slots=True)
class _PendingUsage:
    unsolicited_count: int
    unsolicited_bytes: int
    challenged_count: int
    challenged_bytes: int
    challenge_variants: dict[str, int]


@dataclass(frozen=True, slots=True)
class _PendingScanConflict:
    path: Path
    error: TrustError


@dataclass(frozen=True, slots=True)
class _PendingScan:
    offers: tuple[PendingOffer, ...]
    conflicts: tuple[_PendingScanConflict, ...]


def _sha256(value: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(value).hexdigest()


def _require_digest(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or not value.startswith(_SHA256_PREFIX)
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            f"{field} must be a lowercase sha256 digest",
        )
    return value


def _require_utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} must be timezone-aware")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} is invalid") from exc
    if offset != timedelta(0):
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} must use UTC")
    return value.astimezone(_UTC)


def _timestamp(value: datetime) -> str:
    return _require_utc(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} is invalid") from exc
    parsed = _require_utc(parsed, field)
    if _timestamp(parsed) != value:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field} is not canonical")
    return parsed


def _scope_component(value: str) -> str:
    """Map signed ceremony/group text to one portable collision-safe name."""
    return "sha256-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_enrollment_group(value: str) -> str:
    """Require one portable filename-safe JWE enrollment group component."""
    if (
        not isinstance(value, str)
        or _SAFE_GROUP.fullmatch(value) is None
        or value.endswith(".")
        or _WINDOWS_RESERVED_COMPONENT.fullmatch(value.split(".", 1)[0]) is not None
    ):
        raise TrustError(
            TrustReason.SCOPE_MISMATCH,
            "enrollment group must be a portable component using 1-128 "
            "ASCII letters, digits, dot, underscore, or hyphen",
        )
    return value


def _digest_component(value: str) -> str:
    return _require_digest(value, "digest")[len(_SHA256_PREFIX) :]


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return _canonical_bytes(value) + b"\n"


_OUTBOUND_OFFER_FIELDS = {
    "version",
    "publisher_did",
    "reader_did",
    "ceremony_id",
    "group",
    "offer_digest",
    "artifact_digest",
    "proof_digest",
    "public_key_sha256",
    "created_at",
}


def _outbound_offer_path(cfg: LoadedConfig, offer_digest: str) -> Path:
    return enrollment_dir(cfg.yaml_path) / "outbound" / "offers" / (
        f"{_digest_component(offer_digest)}.json"
    )


def _outbound_artifact_path(cfg: LoadedConfig, offer_digest: str) -> Path:
    return enrollment_dir(cfg.yaml_path) / "outbound" / "artifacts" / (
        f"{_digest_component(offer_digest)}.tnpkg"
    )


def _outbound_published_path(cfg: LoadedConfig, offer_digest: str) -> Path:
    return enrollment_dir(cfg.yaml_path) / "outbound" / "published" / (
        f"{_digest_component(offer_digest)}.json"
    )


def _outbound_state_from_record(record: Mapping[str, object]) -> OutboundOfferState:
    _exact_fields(record, _OUTBOUND_OFFER_FIELDS, "outbound offer state")
    if record["version"] != 1:
        raise TrustError(TrustReason.STATEMENT_INVALID, "unsupported outbound offer state")
    for field in (
        "publisher_did",
        "reader_did",
        "ceremony_id",
        "group",
        "offer_digest",
        "artifact_digest",
        "proof_digest",
        "public_key_sha256",
        "created_at",
    ):
        if not isinstance(record[field], str) or not record[field]:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                f"outbound offer state field {field!r} is invalid",
            )
    parse_ed25519_did_key(str(record["publisher_did"]))
    parse_ed25519_did_key(str(record["reader_did"]))
    validate_enrollment_group(str(record["group"]))
    for field in (
        "offer_digest",
        "artifact_digest",
        "proof_digest",
        "public_key_sha256",
    ):
        _require_digest(str(record[field]), f"outbound offer {field}")
    return OutboundOfferState(**record)  # type: ignore[arg-type]


def record_outbound_offer(
    cfg: LoadedConfig,
    binding: VerifiedJweBinding,
    artifact: bytes,
    *,
    created_at: datetime,
) -> OutboundOfferState:
    """Durably retain response-verification metadata, never reader secrets."""
    if binding.principal.did != cfg.device.device_identity:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "outbound offer reader does not match the loaded device",
        )
    validate_enrollment_group(binding.principal.group)
    state = OutboundOfferState(
        version=1,
        publisher_did=binding.principal.audience_did,
        reader_did=binding.principal.did,
        ceremony_id=binding.principal.ceremony_id,
        group=binding.principal.group,
        offer_digest=binding.proof_digest,
        artifact_digest=_sha256(artifact),
        proof_digest=binding.proof_digest,
        public_key_sha256=binding.public_key_sha256,
        created_at=_timestamp(created_at),
    )
    data = _canonical_json_bytes(state.to_dict())
    path = _outbound_offer_path(cfg, state.offer_digest)
    artifact_path = _outbound_artifact_path(cfg, state.offer_digest)
    lock_path = enrollment_dir(cfg.yaml_path) / "enrollment.lock"
    with AdvisoryFileLock(lock_path):
        if artifact_path.exists():
            if read_enrollment_artifact(artifact_path) != artifact:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "outbound offer digest conflicts with retained artifact bytes",
                )
        else:
            atomic_write_bytes(artifact_path, artifact)
        if path.exists():
            if path.read_bytes() != data:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "outbound offer digest conflicts with retained state",
                )
        else:
            atomic_write_bytes(path, data)
    return state


def load_outbound_offer(cfg: LoadedConfig, offer_digest: str) -> OutboundOfferState:
    """Load exact reader-held state for one previously emitted offer."""
    path = _outbound_offer_path(cfg, offer_digest)
    if not path.exists():
        raise TrustError(
            TrustReason.UNTRUSTED_PRINCIPAL,
            "outbound offer state was not found",
        )
    state = _outbound_state_from_record(_read_json_object(path, "outbound offer state"))
    artifact_path = _outbound_artifact_path(cfg, offer_digest)
    try:
        artifact = read_enrollment_artifact(artifact_path)
    except OSError as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "retained outbound offer artifact is unreadable",
        ) from exc
    if _sha256(artifact) != state.artifact_digest:
        raise TrustError(
            TrustReason.REPLAY_CONFLICT,
            "retained outbound offer artifact digest does not match state",
        )
    return state


def _publish_outbound_offer_locked(
    cfg: LoadedConfig,
    state: OutboundOfferState,
    artifact: bytes,
) -> Path:
    destination = outbox_dir(cfg.yaml_path) / tnpkg_filename(
        state.publisher_did,
        "offer",
        1,
    )
    atomic_write_bytes(destination, artifact)
    marker_path = _outbound_published_path(cfg, state.offer_digest)
    marker: dict[str, object] = {
        "version": 1,
        "offer_digest": state.offer_digest,
        "artifact_digest": state.artifact_digest,
        "published_at": _timestamp(datetime.now(_UTC)),
    }
    if marker_path.exists():
        retained = _read_json_object(marker_path, "outbound publication marker")
        _exact_fields(
            retained,
            {"version", "offer_digest", "artifact_digest", "published_at"},
            "outbound publication marker",
        )
        if (
            retained.get("version") != 1
            or retained.get("offer_digest") != state.offer_digest
            or retained.get("artifact_digest") != state.artifact_digest
            or not isinstance(retained.get("published_at"), str)
        ):
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "outbound publication marker conflicts with prepared offer",
            )
        _parse_timestamp(retained["published_at"], "outbound published_at")
    else:
        atomic_write_bytes(marker_path, _canonical_json_bytes(marker))
    return destination


def publish_outbound_offer(cfg: LoadedConfig, offer_digest: str) -> Path:
    """Recoverably publish one prepared offer after its state is durable."""
    lock_path = enrollment_dir(cfg.yaml_path) / "enrollment.lock"
    with AdvisoryFileLock(lock_path):
        state_path = _outbound_offer_path(cfg, offer_digest)
        if not state_path.exists():
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                "outbound offer state was not found",
            )
        state = _outbound_state_from_record(
            _read_json_object(state_path, "outbound offer state")
        )
        artifact_path = _outbound_artifact_path(cfg, offer_digest)
        try:
            artifact = read_enrollment_artifact(artifact_path)
        except OSError as exc:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "retained outbound offer artifact is unreadable",
            ) from exc
        if _sha256(artifact) != state.artifact_digest:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "retained outbound offer artifact digest does not match state",
            )
        return _publish_outbound_offer_locked(cfg, state, artifact)


def resume_outbound_offer(
    cfg: LoadedConfig,
    *,
    publisher_did: str,
    ceremony_id: str,
    group: str,
    public_key: bytes,
    challenge: EnrollmentChallengeV1 | None,
) -> Package | None:
    """Publish and return one exact matching prepared-but-unpublished offer."""
    parse_ed25519_did_key(publisher_did)
    validate_enrollment_group(group)
    if not isinstance(ceremony_id, str) or not ceremony_id:
        raise TrustError(TrustReason.SCOPE_MISMATCH, "offer ceremony must be non-empty")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise TrustError(TrustReason.BINDING_INVALID, "offer public key must be 32 bytes")
    public_key_sha256 = _sha256(public_key)
    offers_root = enrollment_dir(cfg.yaml_path) / "outbound" / "offers"
    if not offers_root.exists():
        return None
    lock_path = enrollment_dir(cfg.yaml_path) / "enrollment.lock"
    with AdvisoryFileLock(lock_path):
        candidates: list[tuple[str, str, OutboundOfferState, bytes, Package]] = []
        for state_path in sorted(offers_root.glob("*.json")):
            state = _outbound_state_from_record(
                _read_json_object(state_path, "outbound offer state")
            )
            if (
                state.publisher_did != publisher_did
                or state.reader_did != cfg.device.device_identity
                or state.ceremony_id != ceremony_id
                or state.group != group
                or state.public_key_sha256 != public_key_sha256
                or _outbound_published_path(cfg, state.offer_digest).exists()
            ):
                continue
            artifact = read_enrollment_artifact(
                _outbound_artifact_path(cfg, state.offer_digest)
            )
            if _sha256(artifact) != state.artifact_digest:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "prepared outbound offer artifact digest does not match state",
                )
            try:
                manifest, body = _read_manifest(artifact, verify_signature=True)
                package_value = json.loads(body["body/package.json"].decode("utf-8"))
                package = Package(**package_value)
            except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    "prepared outbound offer artifact is malformed",
                ) from exc
            if (
                manifest.kind != "offer"
                or manifest.publisher_identity != cfg.device.device_identity
                or manifest.recipient_identity != publisher_did
                or manifest.ceremony_id != ceremony_id
                or manifest.scope != group
                or package.package_kind != "offer"
                or package.device_identity != cfg.device.device_identity
                or package.recipient_identity != publisher_did
                or package.ceremony_id != ceremony_id
                or package.group != group
                or not verify_package(package)
            ):
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "prepared outbound offer scope or signer conflicts with state",
                )
            proof_value = package.payload.get("key_binding_proof")
            if not isinstance(proof_value, Mapping):
                raise TrustError(
                    TrustReason.BINDING_INVALID,
                    "prepared outbound offer lacks a key-binding proof",
                )
            proof = KeyBindingProofV1.from_dict(proof_value)
            binding = verify_jwe_key_binding(
                proof,
                expected_audience_did=publisher_did,
                expected_ceremony_id=ceremony_id,
                expected_group=group,
                now=proof.issued_at,
                challenge=challenge,
            )
            if (
                binding.public_key != public_key
                or binding.proof_digest != state.offer_digest
                or binding.proof_digest != state.proof_digest
            ):
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "prepared outbound offer binding conflicts with state",
                )
            candidates.append(
                (state.created_at, state.offer_digest, state, artifact, package)
            )
        if not candidates:
            return None
        _created_at, _digest, state, artifact, package = min(candidates)
        _publish_outbound_offer_locked(cfg, state, artifact)
        return package


_RESPONSE_STATE_FIELDS = {
    "version",
    "response_digest",
    "publisher_did",
    "reader_did",
    "ceremony_id",
    "group",
    "group_epoch",
    "accepted_offer_digest",
    "artifact_digest",
    "proof_digest",
    "x25519_public_key_sha256",
    "sender_pub_b64",
    "verified_at",
}


def _response_state_path(cfg: LoadedConfig, offer_digest: str) -> Path:
    return enrollment_dir(cfg.yaml_path) / "outbound" / "responses" / (
        f"{_digest_component(offer_digest)}.json"
    )


def _response_prepare_path(cfg: LoadedConfig, offer_digest: str) -> Path:
    return enrollment_dir(cfg.yaml_path) / "outbound" / "response-prepared" / (
        f"{_digest_component(offer_digest)}.json"
    )


def _response_digest(response: EnrollmentResponseV1) -> str:
    return _sha256(_canonical_bytes(response._wire_value(include_signature=True)))


def _validated_response_state(record: Mapping[str, object]) -> dict[str, object]:
    _exact_fields(record, _RESPONSE_STATE_FIELDS, "enrollment response state")
    if record["version"] != 1:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "unsupported enrollment response state",
        )
    for field in (
        "response_digest",
        "publisher_did",
        "reader_did",
        "ceremony_id",
        "group",
        "accepted_offer_digest",
        "artifact_digest",
        "proof_digest",
        "x25519_public_key_sha256",
        "sender_pub_b64",
        "verified_at",
    ):
        if not isinstance(record[field], str) or not record[field]:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                f"enrollment response state field {field!r} is invalid",
            )
    if type(record["group_epoch"]) is not int or int(record["group_epoch"]) < 0:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "enrollment response state group_epoch is invalid",
        )
    parse_ed25519_did_key(str(record["publisher_did"]))
    parse_ed25519_did_key(str(record["reader_did"]))
    validate_enrollment_group(str(record["group"]))
    for field in (
        "response_digest",
        "accepted_offer_digest",
        "artifact_digest",
        "proof_digest",
        "x25519_public_key_sha256",
    ):
        _require_digest(str(record[field]), f"enrollment response {field}")
    _parse_timestamp(record["verified_at"], "enrollment response verified_at")
    try:
        sender_pub = base64.b64decode(str(record["sender_pub_b64"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "enrollment response sender public key is not canonical base64",
        ) from exc
    if len(sender_pub) != 32:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "enrollment response sender public key must be 32 bytes",
        )
    return dict(record)


def _load_verified_publishers(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"version": 1, "publishers": {}}
    record = _read_json_object(path, "verified publisher record")
    if set(record) != {"version", "publishers"} or record.get("version") != 1:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "verified publisher record has an unsupported shape",
        )
    publishers = record.get("publishers")
    if not isinstance(publishers, dict):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "verified publisher record publishers must be an object",
        )
    for did, metadata in publishers.items():
        parse_ed25519_did_key(did)
        if not isinstance(metadata, dict):
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "verified publisher metadata must be an object",
            )
    return {"version": 1, "publishers": dict(publishers)}


def _response_yaml_bytes(
    cfg: LoadedConfig,
    state: Mapping[str, object],
    reader_public_key: bytes,
) -> bytes:
    import yaml

    try:
        document = yaml.safe_load(cfg.yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader configuration is not valid YAML",
        ) from exc
    if not isinstance(document, dict):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader configuration root must be an object",
        )
    ceremony = document.setdefault("ceremony", {})
    groups = document.setdefault("groups", {})
    if not isinstance(ceremony, dict) or not isinstance(groups, dict):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader ceremony and groups configuration must be objects",
        )
    target_ceremony = str(state["ceremony_id"])
    local_ceremony = ceremony.get("id")
    already_enrolled = any(
        isinstance(spec, dict) and spec.get("publisher_identity")
        for spec in groups.values()
    )
    if local_ceremony and local_ceremony != target_ceremony and already_enrolled:
        raise TrustError(
            TrustReason.SCOPE_MISMATCH,
            "reader is already enrolled in a different ceremony",
        )
    ceremony["id"] = target_ceremony
    group_name = validate_enrollment_group(str(state["group"]))
    group = groups.setdefault(group_name, {})
    if not isinstance(group, dict):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader group configuration must be an object",
        )
    current_epoch = group.get("group_epoch", 0)
    if type(current_epoch) is not int or current_epoch < 0:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader group epoch is invalid",
        )
    target_epoch = int(state["group_epoch"])
    if current_epoch > target_epoch:
        raise TrustError(
            TrustReason.REPLAY_CONFLICT,
            "enrollment response would roll back the reader group epoch",
        )
    current_publisher = group.get("publisher_identity")
    if current_publisher not in (None, "", state["publisher_did"]):
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "reader group already names a different publisher",
        )
    group["cipher"] = "jwe"
    group["group_epoch"] = target_epoch
    group["publisher_identity"] = state["publisher_did"]
    group["sender_pub_b64"] = state["sender_pub_b64"]
    recipients = group.setdefault("recipients", [])
    if not isinstance(recipients, list):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "reader group recipients must be a list",
        )
    reader_did = str(state["reader_did"])
    reader_entry = {
        "recipient_identity": reader_did,
        "pub_b64": base64.b64encode(reader_public_key).decode("ascii"),
    }
    filtered = [
        value
        for value in recipients
        if not (isinstance(value, dict) and value.get("recipient_identity") == reader_did)
    ]
    filtered.append(reader_entry)
    group["recipients"] = filtered
    return yaml.safe_dump(document, sort_keys=False).encode("utf-8")


def install_enrollment_response(
    cfg: LoadedConfig,
    response: EnrollmentResponseV1,
    *,
    sender_pub_b64: str,
    now: datetime,
) -> EnrollmentResponseInstall:
    """Authenticate and crash-recoverably install a publisher response.

    All cryptographic and receiver-local state checks complete before the
    durable prepare record is written.  Exact retries replay the prepared
    mutation and converge on one accepted response; conflicting responses for
    the same offer digest fail closed.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if not isinstance(response, EnrollmentResponseV1):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "a strict EnrollmentResponseV1 is required",
        )
    validate_enrollment_group(response.group)
    now = _require_utc(now, "now")
    try:
        sender_pub = base64.b64decode(sender_pub_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "enrollment sender_pub_b64 is not canonical base64",
        ) from exc
    if len(sender_pub) != 32:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "enrollment sender public key must be 32 bytes",
        )
    canonical_sender_pub_b64 = base64.b64encode(sender_pub).decode("ascii")
    mykey_path = cfg.keystore / f"{response.group}.jwe.mykey"
    try:
        private_bytes = mykey_path.read_bytes()
        reader_private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    except (OSError, ValueError) as exc:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            f"reader has no valid {response.group}.jwe.mykey",
        ) from exc
    reader_public_key = reader_private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    reader_public_key_sha256 = _sha256(reader_public_key)
    lock_path = enrollment_dir(cfg.yaml_path) / "enrollment.lock"
    with AdvisoryFileLock(lock_path):
        outbound = load_outbound_offer(cfg, response.accepted_offer_digest)
        if outbound.reader_did != cfg.device.device_identity:
            raise TrustError(
                TrustReason.WRONG_RECIPIENT,
                "outbound offer belongs to a different local reader",
            )
        if reader_public_key_sha256 != outbound.public_key_sha256:
            raise TrustError(
                TrustReason.BINDING_INVALID,
                "local reader key no longer matches the accepted offer",
            )
        digest = _response_digest(response)
        state: dict[str, object] = {
            "version": 1,
            "response_digest": digest,
            "publisher_did": response.publisher_did,
            "reader_did": response.reader_did,
            "ceremony_id": response.ceremony_id,
            "group": response.group,
            "group_epoch": response.group_epoch,
            "accepted_offer_digest": response.accepted_offer_digest,
            "artifact_digest": outbound.artifact_digest,
            "proof_digest": outbound.proof_digest,
            "x25519_public_key_sha256": response.x25519_public_key_sha256,
            "sender_pub_b64": canonical_sender_pub_b64,
            "verified_at": _timestamp(now),
        }
        prepare_path = _response_prepare_path(cfg, response.accepted_offer_digest)
        accepted_path = _response_state_path(cfg, response.accepted_offer_digest)
        prepared: dict[str, object]
        verification_now = now
        if prepare_path.exists():
            prepared = _validated_response_state(
                _read_json_object(prepare_path, "prepared enrollment response")
            )
            expected = dict(state)
            expected.pop("verified_at")
            retained = dict(prepared)
            retained.pop("verified_at")
            if retained != expected:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "prepared response state conflicts with the authenticated response",
                )
            # Preserve the original verification time across crash recovery.
            state = prepared
            verification_now = _parse_timestamp(
                prepared["verified_at"],
                "prepared enrollment response verified_at",
            )

        # A new response must be fresh now. An exact prepared retry is instead
        # re-authenticated at the original, durably retained verification
        # instant; the prepare comparison above prevents this historical check
        # from authorizing any different response or sender key.
        verify_enrollment_response(
            response,
            expected_publisher_did=outbound.publisher_did,
            expected_reader_did=cfg.device.device_identity,
            expected_ceremony_id=outbound.ceremony_id,
            expected_group=outbound.group,
            expected_offer_digest=outbound.offer_digest,
            expected_public_key_sha256=outbound.public_key_sha256,
            now=verification_now,
        )
        if not prepare_path.exists():
            atomic_write_bytes(prepare_path, _canonical_json_bytes(state))

        already_applied = False
        if accepted_path.exists():
            accepted = _validated_response_state(
                _read_json_object(accepted_path, "accepted enrollment response")
            )
            if accepted != state:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "accepted offer already has a conflicting response",
                )
            already_applied = True

        yaml_bytes = _response_yaml_bytes(cfg, state, reader_public_key)
        trust_path = cfg.keystore / "trust" / "verified_publishers.v1.json"
        trust = _load_verified_publishers(trust_path)
        publishers = trust["publishers"]
        if not isinstance(publishers, dict):  # guarded by _load_verified_publishers
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "verified publisher record publishers must be an object",
            )
        prior = publishers.get(response.publisher_did)
        if isinstance(prior, dict):
            prior_epoch = prior.get("group_epoch", -1)
            if type(prior_epoch) is not int:
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    "verified publisher group epoch is invalid",
                )
            if prior_epoch > response.group_epoch:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "enrollment response would roll back verified publisher state",
                )
        publishers[response.publisher_did] = {
            "accepted_offer_digest": state["accepted_offer_digest"],
            "artifact_digest": state["artifact_digest"],
            "ceremony_id": state["ceremony_id"],
            "group": state["group"],
            "group_epoch": state["group_epoch"],
            "proof_digest": state["proof_digest"],
            "proof_source": "enrollment-response",
            "response_digest": state["response_digest"],
            "verified": True,
            "verified_at": state["verified_at"],
            "x25519_public_key_sha256": state["x25519_public_key_sha256"],
        }

        # The prepare record above makes this sequence recoverable. Every
        # target write is atomic and idempotent; the accepted marker is last.
        atomic_write_bytes(cfg.yaml_path, yaml_bytes)
        atomic_write_bytes(
            cfg.keystore / f"{response.group}.jwe.sender_pub",
            sender_pub,
        )
        atomic_write_bytes(trust_path, _canonical_json_bytes(trust))
        if not already_applied:
            atomic_write_bytes(accepted_path, _canonical_json_bytes(state))
        return EnrollmentResponseInstall(
            applied=not already_applied,
            response_digest=digest,
            publisher_did=response.publisher_did,
            offer_digest=response.accepted_offer_digest,
        )


def _raise_oversized_artifact(size: int) -> None:
    raise TrustError(
        TrustReason.STATEMENT_INVALID,
        f"enrollment artifact size {size} exceeds the maximum enrollment "
        f"artifact size of {MAX_ENROLLMENT_ARTIFACT_BYTES} bytes",
    )


def read_enrollment_artifact(path: Path) -> bytes:
    """Read one path with a pre-stat and a TOCTOU-safe bounded read."""
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_ENROLLMENT_ARTIFACT_BYTES:
        _raise_oversized_artifact(size)
    with path.open("rb") as handle:
        artifact = handle.read(MAX_ENROLLMENT_ARTIFACT_BYTES + 1)
    if len(artifact) > MAX_ENROLLMENT_ARTIFACT_BYTES:
        _raise_oversized_artifact(len(artifact))
    return artifact


def validate_enrollment_archive(source: Path | str | bytes | bytearray) -> None:
    """Metadata-only compact-offer limits; reads no archive member bytes."""
    with _open_zip(source) as archive:
        names = _inspect_tnpkg_archive(archive)
        if len(names) > MAX_ENROLLMENT_ZIP_ENTRIES:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                f"enrollment package entry count {len(names)} exceeds limit "
                f"{MAX_ENROLLMENT_ZIP_ENTRIES}",
            )
        total = 0
        for info in archive.infolist():
            size = info.file_size
            if size > MAX_ENROLLMENT_MEMBER_BYTES:
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    f"enrollment package member {info.filename!r} size {size} "
                    f"exceeds limit {MAX_ENROLLMENT_MEMBER_BYTES}",
                )
            total += size
            if total > MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES:
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    f"enrollment package total uncompressed size {total} exceeds "
                    f"limit {MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES}",
                )
            ratio = size / max(info.compress_size, 1)
            if ratio > MAX_ENROLLMENT_COMPRESSION_RATIO:
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    f"enrollment package member {info.filename!r} compression "
                    f"ratio {ratio:.1f} exceeds limit "
                    f"{MAX_ENROLLMENT_COMPRESSION_RATIO}",
                )


def _read_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{label} is unreadable") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{label} must be an object")
    return value


def _exact_fields(value: Mapping[str, object], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{label} has an invalid shape")


class EnrollmentStore:
    """Durable version-1 enrollment state for one publisher ceremony."""

    def __init__(
        self,
        cfg: LoadedConfig,
        publisher_key: DeviceKey,
        state_root: Path | None = None,
    ) -> None:
        if publisher_key.device_identity != cfg.device.device_identity:
            raise TrustError(
                TrustReason.DID_SIGNER_MISMATCH,
                "publisher key does not match the loaded ceremony identity",
            )
        parse_ed25519_did_key(publisher_key.device_identity)
        self.cfg = cfg
        self.publisher_key = publisher_key
        self.state_root = Path(state_root or enrollment_dir(cfg.yaml_path)).resolve()
        self.lock_path = self.state_root / "enrollment.lock"
        self.challenges_dir = self.state_root / "challenges"
        self.offers_dir = self.state_root / "offers"
        self.approvals_dir = self.state_root / "approvals"
        self.consumed_dir = self.state_root / "consumed"
        self.accepted_dir = self.state_root / "accepted"
        self.preauthorized_dir = self.state_root / "preauthorized"

    def _lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self.lock_path)

    def _validate_scope(self, reader_did: str, group: str) -> None:
        parse_ed25519_did_key(reader_did)
        validate_enrollment_group(group)
        if group not in self.cfg.groups:
            raise TrustError(
                TrustReason.SCOPE_MISMATCH,
                f"group {group!r} is not present in this ceremony",
            )

    def _preauthorization_path(self, reader_did: str, group: str) -> Path:
        did_hash = hashlib.sha256(reader_did.encode("utf-8")).hexdigest()
        return (
            self.preauthorized_dir
            / _scope_component(self.cfg.ceremony_id)
            / _scope_component(group)
            / f"{did_hash}.json"
        )

    def preauthorize(self, reader_did: str, group: str) -> None:
        """Persist exact DID/ceremony/group authorization for challenged offers."""
        self._validate_scope(reader_did, group)
        record: dict[str, object] = {
            "version": 1,
            "ceremony_id": self.cfg.ceremony_id,
            "group": group,
            "reader_did": reader_did,
        }
        data = _canonical_json_bytes(record)
        path = self._preauthorization_path(reader_did, group)
        with self._lock():
            if path.exists():
                if path.read_bytes() != data:
                    raise TrustError(
                        TrustReason.REPLAY_CONFLICT,
                        "preauthorization scope conflicts with existing state",
                    )
                return
            atomic_write_bytes(path, data)

    def _is_preauthorized(self, reader_did: str, group: str) -> bool:
        path = self._preauthorization_path(reader_did, group)
        if not path.exists():
            return False
        record = _read_json_object(path, "preauthorization record")
        _exact_fields(
            record,
            {"version", "ceremony_id", "group", "reader_did"},
            "preauthorization record",
        )
        if record != {
            "version": 1,
            "ceremony_id": self.cfg.ceremony_id,
            "group": group,
            "reader_did": reader_did,
        }:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "preauthorization record does not match the requested scope",
            )
        return True

    def issue_challenge(
        self,
        reader_did: str,
        group: str,
        ttl: timedelta,
    ) -> EnrollmentChallengeV1:
        """Issue and durably retain a one-time publisher-signed challenge."""
        self._validate_scope(reader_did, group)
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise TrustError(TrustReason.STATEMENT_INVALID, "challenge ttl must be positive")
        issued_at = datetime.now(_UTC)
        expires_at = issued_at + ttl
        with self._lock():
            while True:
                challenge_id = str(uuid.uuid4())
                path = self.challenges_dir / f"{challenge_id}.json"
                if not path.exists():
                    break
            challenge = EnrollmentChallengeV1(
                version=1,
                kind="tn-enrollment-challenge",
                publisher_did=self.publisher_key.device_identity,
                expected_reader_did=reader_did,
                ceremony_id=self.cfg.ceremony_id,
                group=group,
                nonce_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                issued_at=issued_at,
                expires_at=expires_at,
                challenge_id=challenge_id,
                signature_b64="",
            ).sign(self.publisher_key)
            challenge_doc = challenge._wire_value(include_signature=True)
            record: dict[str, object] = {
                "version": 1,
                "challenge_digest": _sha256(_canonical_bytes(challenge_doc)),
                "challenge": challenge_doc,
            }
            atomic_write_bytes(path, _canonical_json_bytes(record))
        return challenge

    def _load_challenge_for_digest(
        self,
        challenge_digest: str,
    ) -> EnrollmentChallengeV1:
        _require_digest(challenge_digest, "challenge digest")
        if not self.challenges_dir.exists():
            raise TrustError(TrustReason.CHALLENGE_MISSING, "challenge is not retained")
        for path in sorted(self.challenges_dir.glob("*.json")):
            record = _read_json_object(path, "challenge record")
            _exact_fields(
                record,
                {"version", "challenge_digest", "challenge"},
                "challenge record",
            )
            if record["version"] != 1:
                raise TrustError(TrustReason.STATEMENT_INVALID, "unsupported challenge record")
            if record["challenge_digest"] != challenge_digest:
                continue
            challenge_value = record["challenge"]
            if not isinstance(challenge_value, Mapping):
                raise TrustError(TrustReason.STATEMENT_INVALID, "challenge record is malformed")
            challenge = EnrollmentChallengeV1.from_dict(challenge_value)
            actual = _sha256(_canonical_bytes(challenge._wire_value(include_signature=True)))
            if actual != challenge_digest or path.stem != challenge.challenge_id:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "retained challenge digest or identifier conflicts with its bytes",
                )
            return challenge
        raise TrustError(TrustReason.CHALLENGE_MISSING, "challenge digest is not retained")

    def _offer_path(
        self,
        ceremony_id: str,
        group: str,
        reader_did: str,
        offer_digest: str,
    ) -> Path:
        validate_enrollment_group(group)
        did_hash = hashlib.sha256(reader_did.encode("utf-8")).hexdigest()
        return (
            self.offers_dir
            / _scope_component(ceremony_id)
            / _scope_component(group)
            / did_hash
            / f"{_digest_component(offer_digest)}.tnpkg"
        )

    def _approval_path(self, offer_digest: str) -> Path:
        return self.approvals_dir / f"{_digest_component(offer_digest)}.json"

    def _accepted_path(self, offer_digest: str) -> Path:
        return self.accepted_dir / f"{_digest_component(offer_digest)}.json"

    def _consumed_path(self, challenge_id: str) -> Path:
        if not isinstance(challenge_id, str) or _SAFE_CHALLENGE_ID.fullmatch(challenge_id) is None:
            raise TrustError(TrustReason.STATEMENT_INVALID, "challenge id is invalid")
        return self.consumed_dir / f"{challenge_id}.json"

    def _parse_inner_package(self, body: Mapping[str, bytes]) -> Package:
        raw = body.get("body/package.json")
        if raw is None:
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer body is missing package.json")
        try:
            value = json.loads(raw.decode("utf-8"))
        except RecursionError as exc:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "offer package JSON nesting exceeds the parser limit",
            ) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrustError(
                TrustReason.STATEMENT_INVALID, "offer package is invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer package must be an object")
        try:
            package = Package(**value)
        except TypeError as exc:
            raise TrustError(
                TrustReason.STATEMENT_INVALID, "offer package shape is invalid"
            ) from exc
        if type(package.package_version) is not int or package.package_version != 1:
            raise TrustError(TrustReason.STATEMENT_INVALID, "unsupported offer package version")
        if package.package_kind != "offer":
            raise TrustError(TrustReason.STATEMENT_INVALID, "package is not an offer")
        if not isinstance(package.payload, dict):
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer payload must be an object")
        return package

    def _verify_inner_signature(self, package: Package) -> None:
        if not isinstance(package.sig_b64, str) or not isinstance(
            package.signer_verify_pub_b64, str
        ):
            raise TrustError(TrustReason.SIGNATURE_INVALID, "offer signature is missing")
        try:
            signature = base64.b64decode(package.sig_b64, validate=True)
            declared_public_key = base64.b64decode(
                package.signer_verify_pub_b64,
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise TrustError(TrustReason.SIGNATURE_INVALID, "offer signature is malformed") from exc
        did_public_key = parse_ed25519_did_key(package.device_identity)
        if declared_public_key != did_public_key:
            raise TrustError(
                TrustReason.DID_SIGNER_MISMATCH,
                "offer verification key does not match its asserted DID",
            )
        verify_ed25519_did_signature(
            package.device_identity,
            _package_signing_bytes(package),
            signature,
        )

    def _is_committed_replay(
        self,
        *,
        proof: KeyBindingProofV1,
        offer_digest: str,
        artifact_digest: str,
        challenge_id: str | None,
    ) -> bool:
        public_key_value = proof.binding.get("public_key_b64")
        if not isinstance(public_key_value, str):
            return False
        try:
            public_key = base64.b64decode(public_key_value, validate=True)
        except (ValueError, binascii.Error):
            return False
        candidate: dict[str, object] = {
            "version": 1,
            "ceremony_id": proof.ceremony_id,
            "group": proof.group,
            "reader_did": proof.subject_did,
            "offer_digest": offer_digest,
            "artifact_digest": artifact_digest,
            "challenge_id": challenge_id,
            "proof_digest": offer_digest,
            "public_key_sha256": _sha256(public_key),
        }
        accepted_path = self._accepted_path(offer_digest)
        if (
            accepted_path.exists()
            and _read_json_object(
                accepted_path,
                "accepted offer record",
            )
            == candidate
        ):
            return True
        if challenge_id is None:
            return False
        consumed = self._load_consumed(challenge_id)
        return consumed is not None and consumed == {
            "version": 1,
            "challenge_id": challenge_id,
            "offer_digest": offer_digest,
            "artifact_digest": artifact_digest,
        }

    def _classify_consumed_challenge(
        self,
        *,
        challenge_id: str,
        offer_digest: str,
        artifact_digest: str,
    ) -> bool:
        """Return true for an exact replay; reject every other consumed use."""
        record = self._load_consumed(challenge_id)
        if record is None:
            return False
        prior_artifact = record.get("artifact_digest")
        prior_offer = record.get("offer_digest")
        if prior_artifact is None or prior_offer is None:
            raise TrustError(
                TrustReason.CHALLENGE_REPLAYED,
                "challenge has already been consumed",
            )
        if prior_artifact == artifact_digest and prior_offer == offer_digest:
            return True
        raise TrustError(
            TrustReason.REPLAY_CONFLICT,
            "challenge was consumed by a different signed artifact",
        )

    def _classify_approval(self, offer_digest: str, artifact_digest: str) -> bool:
        """Return true only for a durable approval of these exact bytes."""
        path = self._approval_path(offer_digest)
        if not path.exists():
            return False
        record = _read_json_object(path, "offer approval")
        _exact_fields(
            record,
            {"version", "offer_digest", "artifact_digest", "approved_at"},
            "offer approval",
        )
        if record["version"] != 1 or record["offer_digest"] != offer_digest:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "approval does not match the exact offer digest",
            )
        if record["artifact_digest"] != artifact_digest:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "approval does not match the exact retained offer artifact",
            )
        if not isinstance(record["approved_at"], str):
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer approval is malformed")
        return True

    def _verify_artifact(
        self,
        artifact: bytes,
        expected_publisher_did: str,
        now: datetime,
    ) -> _VerifiedArtifact:
        if not isinstance(artifact, bytes):
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer artifact must be bytes")
        if len(artifact) > MAX_ENROLLMENT_ARTIFACT_BYTES:
            _raise_oversized_artifact(len(artifact))
        try:
            validate_enrollment_archive(artifact)
        except TrustError:
            raise
        except (PackageError, ValueError) as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, str(exc)) from exc
        now = _require_utc(now, "now")
        parse_ed25519_did_key(expected_publisher_did)
        if expected_publisher_did != self.publisher_key.device_identity:
            raise TrustError(
                TrustReason.WRONG_RECIPIENT,
                "expected publisher does not match this enrollment store",
            )
        try:
            manifest, body = _read_manifest(artifact, verify_signature=True)
        except ManifestSignatureError as exc:
            raise TrustError(TrustReason.SIGNATURE_INVALID, str(exc)) from exc
        except PackageError as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, str(exc)) from exc
        except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer artifact is malformed") from exc
        if manifest.kind != "offer":
            raise TrustError(TrustReason.STATEMENT_INVALID, "artifact is not an offer")
        package = self._parse_inner_package(body)
        validate_enrollment_group(package.group)
        if manifest.publisher_identity != package.device_identity:
            raise TrustError(
                TrustReason.OUTER_INNER_SIGNER_MISMATCH,
                "outer manifest and inner offer name different signers",
            )
        if (
            manifest.recipient_identity != expected_publisher_did
            or package.recipient_identity != expected_publisher_did
        ):
            raise TrustError(TrustReason.WRONG_RECIPIENT, "offer names a different publisher")
        if (
            manifest.ceremony_id != self.cfg.ceremony_id
            or package.ceremony_id != self.cfg.ceremony_id
            or manifest.scope != package.group
            or package.group not in self.cfg.groups
        ):
            raise TrustError(TrustReason.SCOPE_MISMATCH, "offer ceremony or group does not match")
        self._verify_inner_signature(package)
        proof_value = package.payload.get("key_binding_proof")
        if not isinstance(proof_value, Mapping):
            raise TrustError(TrustReason.BINDING_INVALID, "offer lacks a key-binding proof")
        proof = KeyBindingProofV1.from_dict(proof_value)
        if proof.subject_did != manifest.publisher_identity:
            raise TrustError(
                TrustReason.OUTER_INNER_SIGNER_MISMATCH,
                "outer manifest signer and proof subject differ",
            )
        proof_signature = base64.b64decode(proof.signature_b64, validate=True)
        verify_ed25519_did_signature(
            proof.subject_did,
            proof.signing_bytes(),
            proof_signature,
        )
        challenge_digest = proof.binding.get("challenge_digest")
        challenge: EnrollmentChallengeV1 | None
        if challenge_digest is None:
            challenge = None
        elif isinstance(challenge_digest, str):
            challenge = self._load_challenge_for_digest(challenge_digest)
        else:
            raise TrustError(TrustReason.BINDING_INVALID, "challenge digest has invalid type")
        offer_digest = _sha256(_canonical_bytes(proof._wire_value(include_signature=True)))
        artifact_digest = _sha256(artifact)
        verification_now = now
        challenge_id = challenge.challenge_id if challenge is not None else None
        if challenge is not None:
            # Authenticate receiver-local challenge state independently of
            # current freshness. This lets the lifecycle classify an expired
            # challenge before the proof verifier reports its own expiry.
            verify_enrollment_challenge(
                challenge,
                expected_publisher_did=expected_publisher_did,
                expected_reader_did=proof.subject_did,
                expected_ceremony_id=self.cfg.ceremony_id,
                expected_group=package.group,
                now=challenge.issued_at,
            )
        consumed_exact = (
            self._classify_consumed_challenge(
                challenge_id=challenge_id,
                offer_digest=offer_digest,
                artifact_digest=artifact_digest,
            )
            if challenge_id is not None
            else False
        )
        approval_exact = self._classify_approval(offer_digest, artifact_digest)
        if consumed_exact or approval_exact or self._is_committed_replay(
            proof=proof,
            offer_digest=offer_digest,
            artifact_digest=artifact_digest,
            challenge_id=challenge_id,
        ):
            # Freshness authorized the original promotion. Exact retained-byte
            # replay remains an idempotent no-op, but signatures/scope are
            # still reverified at the proof's original valid instant.
            verification_now = proof.issued_at
        elif challenge is not None and now >= challenge.expires_at:
            raise TrustError(
                TrustReason.CHALLENGE_EXPIRED,
                "challenge has expired",
            )
        binding = verify_jwe_key_binding(
            proof,
            expected_audience_did=expected_publisher_did,
            expected_ceremony_id=self.cfg.ceremony_id,
            expected_group=package.group,
            now=verification_now,
            challenge=challenge,
        )
        public_key_b64 = package.payload.get("x25519_pub_b64")
        if public_key_b64 is not None:
            if not isinstance(public_key_b64, str):
                raise TrustError(TrustReason.BINDING_INVALID, "offer public key is invalid")
            try:
                public_key = base64.b64decode(public_key_b64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise TrustError(
                    TrustReason.BINDING_INVALID, "offer public key is invalid"
                ) from exc
            if public_key != binding.public_key:
                raise TrustError(
                    TrustReason.BINDING_INVALID,
                    "offer public key differs from the signed binding",
                )
        if binding.proof_digest != offer_digest:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT, "proof digest changed during verification"
            )
        artifact_path = self._offer_path(
            proof.ceremony_id,
            proof.group,
            proof.subject_did,
            offer_digest,
        )
        return _VerifiedArtifact(
            pending=PendingOffer(
                ceremony_id=proof.ceremony_id,
                group=proof.group,
                reader_did=proof.subject_did,
                offer_digest=offer_digest,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                verified=binding,
            ),
            artifact_digest=artifact_digest,
            challenge_id=challenge_id,
        )

    def _load_consumed(self, challenge_id: str) -> dict[str, object] | None:
        path = self._consumed_path(challenge_id)
        if not path.exists():
            return None
        return _read_json_object(path, "consumed challenge record")

    def _assert_challenge_available(self, verified: _VerifiedArtifact) -> bool:
        if verified.challenge_id is None:
            return False
        return self._classify_consumed_challenge(
            challenge_id=verified.challenge_id,
            offer_digest=verified.pending.offer_digest,
            artifact_digest=verified.artifact_digest,
        )

    def _pending_usage(self) -> _PendingUsage:
        usage = _PendingUsage(
            unsolicited_count=0,
            unsolicited_bytes=0,
            challenged_count=0,
            challenged_bytes=0,
            challenge_variants={},
        )
        if not self.offers_dir.exists():
            return usage
        for path in sorted(self.offers_dir.rglob("*.tnpkg")):
            artifact = read_enrollment_artifact(path)
            validate_enrollment_archive(artifact)
            try:
                manifest, body = _read_manifest(artifact, verify_signature=True)
            except ManifestSignatureError as exc:
                raise TrustError(TrustReason.SIGNATURE_INVALID, str(exc)) from exc
            package = self._parse_inner_package(body)
            if manifest.publisher_identity != package.device_identity:
                raise TrustError(
                    TrustReason.OUTER_INNER_SIGNER_MISMATCH,
                    "retained offer outer and inner signers differ",
                )
            self._verify_inner_signature(package)
            proof_value = package.payload.get("key_binding_proof")
            if not isinstance(proof_value, Mapping):
                raise TrustError(TrustReason.BINDING_INVALID, "retained offer lacks a proof")
            proof = KeyBindingProofV1.from_dict(proof_value)
            if proof.subject_did != package.device_identity:
                raise TrustError(
                    TrustReason.OUTER_INNER_SIGNER_MISMATCH,
                    "retained offer package and proof signers differ",
                )
            try:
                proof_signature = base64.b64decode(proof.signature_b64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise TrustError(
                    TrustReason.SIGNATURE_INVALID,
                    "retained offer proof signature is malformed",
                ) from exc
            verify_ed25519_did_signature(
                proof.subject_did,
                proof.signing_bytes(),
                proof_signature,
            )
            offer_digest = _sha256(
                _canonical_bytes(proof._wire_value(include_signature=True))
            )
            artifact_digest = _sha256(artifact)
            challenge_digest = proof.binding.get("challenge_digest")
            challenge_id: str | None
            if challenge_digest is None:
                challenge_id = None
            elif isinstance(challenge_digest, str):
                _require_digest(challenge_digest, "retained challenge digest")
                challenge_id = self._load_challenge_for_digest(
                    challenge_digest
                ).challenge_id
            else:
                raise TrustError(
                    TrustReason.BINDING_INVALID,
                    "retained challenge digest has invalid type",
                )
            accepted_path = self._accepted_path(offer_digest)
            if accepted_path.exists():
                accepted = _read_json_object(accepted_path, "accepted offer record")
                public_key_value = proof.binding.get("public_key_b64")
                try:
                    public_key = (
                        base64.b64decode(public_key_value, validate=True)
                        if isinstance(public_key_value, str)
                        else b""
                    )
                except (ValueError, binascii.Error):
                    public_key = b""
                expected_accepted: dict[str, object] = {
                    "version": 1,
                    "ceremony_id": proof.ceremony_id,
                    "group": proof.group,
                    "reader_did": proof.subject_did,
                    "offer_digest": offer_digest,
                    "artifact_digest": artifact_digest,
                    "challenge_id": challenge_id,
                    "proof_digest": offer_digest,
                    "public_key_sha256": _sha256(public_key),
                }
                if not public_key or accepted != expected_accepted:
                    raise TrustError(
                        TrustReason.REPLAY_CONFLICT,
                        "accepted offer record conflicts with retained artifact bytes",
                    )
                continue
            if challenge_digest is None:
                usage.unsolicited_count += 1
                usage.unsolicited_bytes += len(artifact)
            else:
                usage.challenged_count += 1
                usage.challenged_bytes += len(artifact)
                usage.challenge_variants[challenge_digest] = (
                    usage.challenge_variants.get(challenge_digest, 0) + 1
                )
        return usage

    def _assert_pending_quota(
        self,
        verified: _VerifiedArtifact,
        artifact_size: int,
    ) -> None:
        if verified.challenge_id is None:
            if artifact_size > MAX_UNSOLICITED_OFFER_BYTES:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    f"unsolicited offer size {artifact_size} exceeds limit "
                    f"{MAX_UNSOLICITED_OFFER_BYTES}",
                )
            usage = self._pending_usage()
            if usage.unsolicited_count >= MAX_UNSOLICITED_PENDING_COUNT:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    f"unsolicited pending offer count reached limit "
                    f"{MAX_UNSOLICITED_PENDING_COUNT}",
                )
            if (
                usage.unsolicited_bytes + artifact_size
                > MAX_UNSOLICITED_PENDING_BYTES
            ):
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    f"unsolicited pending offer bytes would exceed limit "
                    f"{MAX_UNSOLICITED_PENDING_BYTES}",
                )
            return

        challenge_digest = verified.pending.verified.challenge_digest
        if challenge_digest is None:
            raise TrustError(
                TrustReason.BINDING_INVALID,
                "challenged offer is missing its verified challenge digest",
            )
        usage = self._pending_usage()
        if (
            usage.challenge_variants.get(challenge_digest, 0)
            >= MAX_CHALLENGED_VARIANTS_PER_CHALLENGE
        ):
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                "challenged offer variants for challenge reached limit "
                f"{MAX_CHALLENGED_VARIANTS_PER_CHALLENGE}",
            )
        if usage.challenged_count >= MAX_CHALLENGED_PENDING_COUNT:
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                f"challenged pending offer count reached limit "
                f"{MAX_CHALLENGED_PENDING_COUNT}",
            )
        if usage.challenged_bytes + artifact_size > MAX_CHALLENGED_PENDING_BYTES:
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                f"challenged pending offer bytes would exceed limit "
                f"{MAX_CHALLENGED_PENDING_BYTES}",
            )

    def stage_offer(
        self,
        artifact: bytes,
        expected_publisher_did: str,
        now: datetime,
    ) -> PendingOffer:
        """Verify and retain exact `.tnpkg` bytes without authorizing them."""
        # Reject malformed/unscoped input before creating even the lock file.
        # The authoritative verification is repeated under the lock below.
        preverified = self._verify_artifact(artifact, expected_publisher_did, now)
        preexisting_path = preverified.pending.artifact_path
        if preexisting_path.exists():
            if read_enrollment_artifact(preexisting_path) == artifact:
                return preverified.pending
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "offer digest already names different retained artifact bytes",
            )
        if preverified.challenge_id is None:
            if len(artifact) > MAX_UNSOLICITED_OFFER_BYTES:
                self._assert_pending_quota(preverified, len(artifact))
            elif not self.state_root.exists():
                self._assert_pending_quota(preverified, len(artifact))
        with self._lock():
            verified = self._verify_artifact(artifact, expected_publisher_did, now)
            self._assert_challenge_available(verified)
            path = verified.pending.artifact_path
            if path.exists():
                if read_enrollment_artifact(path) != artifact:
                    raise TrustError(
                        TrustReason.REPLAY_CONFLICT,
                        "offer digest already names different retained artifact bytes",
                    )
            else:
                self._assert_pending_quota(verified, len(artifact))
                atomic_write_bytes(path, artifact)
        return verified.pending

    def _reverify_pending(self, pending: PendingOffer, now: datetime) -> _VerifiedArtifact:
        if not isinstance(pending, PendingOffer):
            raise TrustError(TrustReason.STATEMENT_INVALID, "pending offer has invalid type")
        expected_path = self._offer_path(
            pending.ceremony_id,
            pending.group,
            pending.reader_did,
            pending.offer_digest,
        )
        if pending.artifact_path != expected_path:
            raise TrustError(TrustReason.REPLAY_CONFLICT, "pending offer path is not canonical")
        try:
            artifact = read_enrollment_artifact(pending.artifact_path)
        except OSError as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, "retained offer is unreadable") from exc
        verified = self._verify_artifact(
            artifact,
            self.publisher_key.device_identity,
            now,
        )
        if verified.pending != pending:
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "retained artifact no longer matches the pending verified value",
            )
        return verified

    def _load_approval(self, verified: _VerifiedArtifact) -> bool:
        return self._classify_approval(
            verified.pending.offer_digest,
            verified.artifact_digest,
        )

    def _accepted_record(self, verified: _VerifiedArtifact) -> dict[str, object]:
        return {
            "version": 1,
            "ceremony_id": verified.pending.ceremony_id,
            "group": verified.pending.group,
            "reader_did": verified.pending.reader_did,
            "offer_digest": verified.pending.offer_digest,
            "artifact_digest": verified.artifact_digest,
            "challenge_id": verified.challenge_id,
            "proof_digest": verified.pending.verified.proof_digest,
            "public_key_sha256": verified.pending.verified.public_key_sha256,
        }

    def _is_accepted_exact(self, verified: _VerifiedArtifact) -> bool:
        path = self._accepted_path(verified.pending.offer_digest)
        if not path.exists():
            return False
        record = _read_json_object(path, "accepted offer record")
        if record != self._accepted_record(verified):
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "accepted offer record conflicts with retained artifact bytes",
            )
        return True

    def _accepted(self, verified: _VerifiedArtifact) -> AcceptedOffer:
        return AcceptedOffer(
            binding=verified.pending.verified,
            offer_digest=verified.pending.offer_digest,
            artifact_digest=verified.artifact_digest,
        )

    def _promote_locked(self, verified: _VerifiedArtifact) -> AcceptedOffer:
        consumed_exact = self._assert_challenge_available(verified)
        accepted_exact = self._is_accepted_exact(verified)
        if consumed_exact and accepted_exact:
            return self._accepted(verified)
        if verified.challenge_id is not None and not consumed_exact:
            consumed_record: dict[str, object] = {
                "version": 1,
                "challenge_id": verified.challenge_id,
                "offer_digest": verified.pending.offer_digest,
                "artifact_digest": verified.artifact_digest,
            }
            atomic_write_bytes(
                self._consumed_path(verified.challenge_id),
                _canonical_json_bytes(consumed_record),
            )
        if not accepted_exact:
            atomic_write_bytes(
                self._accepted_path(verified.pending.offer_digest),
                _canonical_json_bytes(self._accepted_record(verified)),
            )
        return self._accepted(verified)

    def reconcile(self, pending: PendingOffer, *, now: datetime) -> AcceptedOffer:
        """Reverify and promote a preauthorized or exact-approved offer."""
        # As with staging, reject an invalid caller-supplied value before the
        # lock file can become the first persistent mutation.
        self._reverify_pending(pending, now)
        with self._lock():
            verified = self._reverify_pending(pending, now)
            consumed_exact = self._assert_challenge_available(verified)
            if consumed_exact and self._is_accepted_exact(verified):
                return self._accepted(verified)
            authorized = self._load_approval(verified)
            if verified.challenge_id is not None:
                authorized = authorized or self._is_preauthorized(
                    verified.pending.reader_did,
                    verified.pending.group,
                )
            if not authorized:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    "offer requires exact-digest administrator approval",
                )
            return self._promote_locked(verified)

    def _find_pending_path(self, offer_digest: str) -> Path:
        component = _digest_component(offer_digest)
        matches = (
            sorted(self.offers_dir.rglob(f"{component}.tnpkg")) if self.offers_dir.exists() else []
        )
        if not matches:
            raise TrustError(TrustReason.UNTRUSTED_PRINCIPAL, "pending offer digest was not found")
        if len(matches) != 1:
            raise TrustError(TrustReason.REPLAY_CONFLICT, "pending offer digest is ambiguous")
        return matches[0]

    def _pending_from_path(self, path: Path, now: datetime) -> _VerifiedArtifact:
        try:
            artifact = read_enrollment_artifact(path)
        except OSError as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, "pending offer is unreadable") from exc
        verified = self._verify_artifact(
            artifact,
            self.publisher_key.device_identity,
            now,
        )
        if verified.pending.artifact_path != path:
            raise TrustError(TrustReason.REPLAY_CONFLICT, "pending offer is stored at a wrong path")
        return verified

    def approve_and_reconcile(
        self,
        offer_digest: str,
        *,
        now: datetime,
    ) -> AcceptedOffer:
        """Approve an exact digest, reverify, consume, and promote under one lock."""
        _require_digest(offer_digest, "offer digest")
        now = _require_utc(now, "now")
        if not self.offers_dir.exists():
            raise TrustError(TrustReason.UNTRUSTED_PRINCIPAL, "pending offer digest was not found")
        with self._lock():
            path = self._find_pending_path(offer_digest)
            verified = self._pending_from_path(path, now)
            if verified.pending.offer_digest != offer_digest:
                raise TrustError(TrustReason.REPLAY_CONFLICT, "offer digest does not match bytes")
            consumed_exact = self._assert_challenge_available(verified)
            if consumed_exact and self._is_accepted_exact(verified):
                return self._accepted(verified)
            approval_path = self._approval_path(offer_digest)
            approval_record: dict[str, object] = {
                "version": 1,
                "offer_digest": offer_digest,
                "artifact_digest": verified.artifact_digest,
                "approved_at": _timestamp(now),
            }
            approval_bytes = _canonical_json_bytes(approval_record)
            if approval_path.exists():
                existing = _read_json_object(approval_path, "offer approval")
                if (
                    existing.get("offer_digest") != offer_digest
                    or existing.get("artifact_digest") != verified.artifact_digest
                ):
                    raise TrustError(
                        TrustReason.REPLAY_CONFLICT,
                        "offer approval conflicts with retained bytes",
                    )
            else:
                atomic_write_bytes(approval_path, approval_bytes)
            return self._promote_locked(verified)

    def pending_offer(self, offer_digest: str, *, now: datetime) -> PendingOffer:
        """Load and reverify one retained offer by its exact digest."""
        _require_digest(offer_digest, "offer digest")
        if not self.offers_dir.exists():
            raise TrustError(TrustReason.UNTRUSTED_PRINCIPAL, "pending offer digest was not found")
        with self._lock():
            verified = self._pending_from_path(self._find_pending_path(offer_digest), now)
            if verified.pending.offer_digest != offer_digest:
                raise TrustError(TrustReason.REPLAY_CONFLICT, "offer digest does not match bytes")
            return verified.pending

    def require_accepted_offer(
        self,
        accepted_offer: AcceptedOffer,
        *,
        now: datetime,
    ) -> AcceptedOffer:
        """Reverify that a typed value is backed by this store's durable state."""
        if not isinstance(accepted_offer, AcceptedOffer):
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                "an AcceptedOffer returned by enrollment reconciliation is required",
            )
        _require_digest(accepted_offer.offer_digest, "accepted offer digest")
        now = _require_utc(now, "now")
        if not self.offers_dir.exists():
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                "accepted offer has no retained enrollment artifact",
            )
        with self._lock():
            try:
                path = self._find_pending_path(accepted_offer.offer_digest)
            except TrustError as exc:
                if exc.reason is TrustReason.UNTRUSTED_PRINCIPAL:
                    raise TrustError(
                        TrustReason.UNTRUSTED_PRINCIPAL,
                        "accepted offer has no retained enrollment artifact",
                    ) from exc
                raise
            verified = self._pending_from_path(path, now)
            if not self._is_accepted_exact(verified):
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    "offer has not been durably accepted",
                )
            retained = self._accepted(verified)
            if retained != accepted_offer:
                raise TrustError(
                    TrustReason.REPLAY_CONFLICT,
                    "AcceptedOffer value does not match durable accepted state",
                )
            return retained

    def _scan_pending_offers(self, *, now: datetime) -> _PendingScan:
        """Isolate retained-artifact failures while preserving explicit reports."""
        now = _require_utc(now, "now")
        if not self.offers_dir.exists():
            return _PendingScan(offers=(), conflicts=())
        with self._lock():
            result: list[PendingOffer] = []
            conflicts: list[_PendingScanConflict] = []
            for path in sorted(self.offers_dir.rglob("*.tnpkg")):
                try:
                    verified = self._pending_from_path(path, now)
                    if not self._is_accepted_exact(verified):
                        result.append(verified.pending)
                except TrustError as exc:
                    conflicts.append(_PendingScanConflict(path=path, error=exc))
            return _PendingScan(offers=tuple(result), conflicts=tuple(conflicts))

    def pending_offers(self, *, now: datetime) -> tuple[PendingOffer, ...]:
        """Return all verified pending offers, failing closed on corrupt state."""
        scan = self._scan_pending_offers(now=now)
        if scan.conflicts:
            raise scan.conflicts[0].error
        return scan.offers


__all__ = [
    "MAX_CHALLENGED_PENDING_BYTES",
    "MAX_CHALLENGED_PENDING_COUNT",
    "MAX_CHALLENGED_VARIANTS_PER_CHALLENGE",
    "MAX_ENROLLMENT_ARTIFACT_BYTES",
    "MAX_ENROLLMENT_COMPRESSION_RATIO",
    "MAX_ENROLLMENT_MEMBER_BYTES",
    "MAX_ENROLLMENT_TOTAL_UNCOMPRESSED_BYTES",
    "MAX_ENROLLMENT_ZIP_ENTRIES",
    "MAX_UNSOLICITED_OFFER_BYTES",
    "MAX_UNSOLICITED_PENDING_BYTES",
    "MAX_UNSOLICITED_PENDING_COUNT",
    "EnrollmentStore",
    "PendingOffer",
    "read_enrollment_artifact",
    "resume_outbound_offer",
    "validate_enrollment_archive",
    "validate_enrollment_group",
]
