"""Receiver-local trusted enrollment challenge and pending-offer state."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ._bounded_json import JsonNestingError, loads_bounded
from ._keystore_backend import AdvisoryFileLock, atomic_write_bytes
from .canonical import _canonical_bytes
from .config import LoadedConfig
from .conventions import enrollment_dir
from .key_binding import (
    EnrollmentChallengeV1,
    KeyBindingProofV1,
    verify_jwe_key_binding,
)
from .packaging import Package
from .packaging import _canonical_bytes as _package_signing_bytes
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


@dataclass(frozen=True, slots=True)
class PendingOffer:
    """A verified binding backed by the complete retained signed artifact."""

    ceremony_id: str
    group: str
    reader_did: str
    offer_digest: str
    artifact_path: Path
    verified: VerifiedJweBinding


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


def _scope_component(value: str) -> str:
    """Map signed ceremony/group text to one portable collision-safe name."""
    return "sha256-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_component(value: str) -> str:
    return _require_digest(value, "digest")[len(_SHA256_PREFIX) :]


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return _canonical_bytes(value) + b"\n"


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
        if not isinstance(group, str) or not group:
            raise TrustError(TrustReason.SCOPE_MISMATCH, "group must be non-empty")
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
        if not isinstance(challenge_id, str) or not challenge_id:
            raise TrustError(TrustReason.STATEMENT_INVALID, "challenge id is invalid")
        try:
            canonical_id = str(uuid.UUID(challenge_id))
        except (ValueError, AttributeError) as exc:
            raise TrustError(TrustReason.STATEMENT_INVALID, "challenge id is invalid") from exc
        if challenge_id != canonical_id:
            raise TrustError(TrustReason.STATEMENT_INVALID, "challenge id is not canonical")
        return self.consumed_dir / f"{canonical_id}.json"

    def _parse_inner_package(self, body: Mapping[str, bytes]) -> Package:
        raw = body.get("body/package.json")
        if raw is None:
            raise TrustError(TrustReason.STATEMENT_INVALID, "offer body is missing package.json")
        try:
            value = loads_bounded(raw)
        except JsonNestingError as exc:
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
        if (
            consumed_exact
            or approval_exact
            or self._is_committed_replay(
                proof=proof,
                offer_digest=offer_digest,
                artifact_digest=artifact_digest,
                challenge_id=challenge_id,
            )
        ):
            # Freshness authorized the original promotion. Exact retained-byte
            # replay remains an idempotent no-op, but signatures/scope are
            # still reverified at the proof's original valid instant.
            verification_now = proof.issued_at
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
            offer_digest = _sha256(_canonical_bytes(proof._wire_value(include_signature=True)))
            artifact_digest = _sha256(artifact)
            challenge_digest = proof.binding.get("challenge_digest")
            challenge_id: str | None
            if challenge_digest is None:
                challenge_id = None
            elif isinstance(challenge_digest, str):
                _require_digest(challenge_digest, "retained challenge digest")
                challenge_id = self._load_challenge_for_digest(challenge_digest).challenge_id
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
            if usage.unsolicited_bytes + artifact_size > MAX_UNSOLICITED_PENDING_BYTES:
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
                f"challenged pending offer count reached limit {MAX_CHALLENGED_PENDING_COUNT}",
            )
        if usage.challenged_bytes + artifact_size > MAX_CHALLENGED_PENDING_BYTES:
            raise TrustError(
                TrustReason.UNTRUSTED_PRINCIPAL,
                f"challenged pending offer bytes would exceed limit {MAX_CHALLENGED_PENDING_BYTES}",
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
    "validate_enrollment_archive",
]
