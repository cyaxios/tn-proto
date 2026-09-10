"""tn.offer — JWE recipient bootstrap verb.

Generates an X25519 keypair for this party (if absent), emits a signed
offer package addressed to a publisher_did. The publisher absorbs the
package and wires the recipient's pub into their JWE group's
recipients JSON, enabling the recipient to decrypt future entries.

The package signature is self-consistent transport integrity. A publisher
must separately authenticate that the asserted recipient DID owns the signing
key and that the signed offer binds this X25519 enrollment before admitting it.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._keystore_backend import AdvisoryFileLock, atomic_write_bytes
from .canonical import _canonical_bytes
from .compile import _build_outbox_artifact, _now_iso, _signing_key
from .config import LoadedConfig
from .enrollment import (
    publish_outbound_offer,
    record_outbound_offer,
    resume_outbound_offer,
    validate_enrollment_group,
)
from .key_binding import (
    EnrollmentChallengeV1,
    KeyBindingProofV1,
    verify_enrollment_challenge,
    verify_jwe_key_binding,
)
from .packaging import Package, sign
from .trust import TrustError, TrustReason, parse_ed25519_did_key


def _ensure_mykey(
    cfg: LoadedConfig,
    group: str,
    *,
    rotate_reader_key: bool = False,
) -> bytes:
    """Return one concurrency-safe reader key, rotating only when explicit."""
    validate_enrollment_group(group)
    mykey_path = cfg.keystore / f"{group}.jwe.mykey"
    lock_path = cfg.keystore / f"{group}.jwe.mykey.lock"
    with AdvisoryFileLock(lock_path):
        prior = mykey_path.read_bytes() if mykey_path.exists() else None
        if prior is not None:
            try:
                sk = X25519PrivateKey.from_private_bytes(prior)
            except ValueError as exc:
                raise TrustError(
                    TrustReason.BINDING_INVALID,
                    f"{group}.jwe.mykey is not a valid 32-byte X25519 private key",
                ) from exc
        if prior is None or rotate_reader_key:
            if prior is not None:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                archive = mykey_path.with_name(
                    f"{mykey_path.name}.previous.{stamp}.{secrets.token_hex(4)}"
                )
                atomic_write_bytes(archive, prior)
            sk = X25519PrivateKey.generate()
            atomic_write_bytes(mykey_path, sk.private_bytes_raw())
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _existing_mykey_public(cfg: LoadedConfig, group: str) -> bytes | None:
    """Return the current reader public key without creating or rotating it."""
    validate_enrollment_group(group)
    mykey_path = cfg.keystore / f"{group}.jwe.mykey"
    lock_path = cfg.keystore / f"{group}.jwe.mykey.lock"
    with AdvisoryFileLock(lock_path):
        if not mykey_path.exists():
            return None
        try:
            private_key = X25519PrivateKey.from_private_bytes(mykey_path.read_bytes())
        except ValueError as exc:
            raise TrustError(
                TrustReason.BINDING_INVALID,
                f"{group}.jwe.mykey is not a valid 32-byte X25519 private key",
            ) from exc
        return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def offer(
    cfg: LoadedConfig,
    publisher_did: str,
    *,
    challenge: EnrollmentChallengeV1 | None = None,
    group: str = "default",
    ceremony_id: str | None = None,
    rotate_reader_key: bool = False,
) -> Package:
    """Emit an `offer` package addressed to publisher_did.

    Generates an X25519 keypair for this recipient if none exists for
    `group`. Writes the package to <yaml_dir>/outbox/. Returns the Package.

    If the publisher_did doesn't look like a DID, raises ValueError with
    a pointed message.
    """
    parse_ed25519_did_key(publisher_did)
    validate_enrollment_group(group)
    now = datetime.now(timezone.utc)
    if challenge is not None:
        if not isinstance(challenge, EnrollmentChallengeV1):
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "offer challenge has an invalid type",
            )
        target_ceremony = challenge.ceremony_id
        if ceremony_id is not None and ceremony_id != target_ceremony:
            raise TrustError(
                TrustReason.SCOPE_MISMATCH,
                "ceremony_id override conflicts with the publisher challenge",
            )
        verify_enrollment_challenge(
            challenge,
            expected_publisher_did=publisher_did,
            expected_reader_did=cfg.device.device_identity,
            expected_ceremony_id=target_ceremony,
            expected_group=group,
            # Authenticate the signed scope before even creating a lock file.
            # Current freshness is enforced below if no exact prepared offer
            # can be resumed.
            now=challenge.issued_at,
        )
        challenge_digest: str | None = "sha256:" + hashlib.sha256(
            _canonical_bytes(challenge._wire_value(include_signature=True))
        ).hexdigest()
    else:
        if ceremony_id is None or not isinstance(ceremony_id, str) or not ceremony_id:
            raise ValueError(
                "offer: ceremony_id is required for an unsolicited foreign offer"
            )
        target_ceremony = ceremony_id
        challenge_digest = None

    existing_pub = _existing_mykey_public(cfg, group)
    if existing_pub is not None:
        resumed = resume_outbound_offer(
            cfg,
            publisher_did=publisher_did,
            ceremony_id=target_ceremony,
            group=group,
            public_key=existing_pub,
            challenge=challenge,
        )
        if resumed is not None:
            return resumed

    if challenge is not None:
        verify_enrollment_challenge(
            challenge,
            expected_publisher_did=publisher_did,
            expected_reader_did=cfg.device.device_identity,
            expected_ceremony_id=target_ceremony,
            expected_group=group,
            now=now,
        )
        proof_expires_at = min(now + timedelta(minutes=10), challenge.expires_at)
    else:
        proof_expires_at = now + timedelta(minutes=10)

    pub = _ensure_mykey(cfg, group, rotate_reader_key=rotate_reader_key)
    proof = KeyBindingProofV1(
        version=1,
        purpose="jwe-reader",
        subject_did=cfg.device.device_identity,
        audience_did=publisher_did,
        ceremony_id=target_ceremony,
        group=group,
        issued_at=now,
        expires_at=proof_expires_at,
        nonce_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        binding={
            "algorithm": "X25519",
            "public_key_b64": base64.b64encode(pub).decode("ascii"),
            "challenge_digest": challenge_digest,
        },
        signature_b64="",
    ).sign(cfg.device)
    pkg = Package(
        package_version=1,
        package_kind="offer",
        ceremony_id=target_ceremony,
        group=group,
        group_epoch=0,
        device_identity=cfg.device.device_identity,
        signer_verify_pub_b64="",
        recipient_identity=publisher_did,
        payload={
            "x25519_pub_b64": base64.b64encode(pub).decode("ascii"),
            "key_binding_proof": proof._wire_value(include_signature=True),
        },
        compiled_at=_now_iso(),
    )
    signed = sign(pkg, _signing_key(cfg))
    _outbox_path, artifact = _build_outbox_artifact(cfg, signed)
    binding = verify_jwe_key_binding(
        proof,
        expected_audience_did=publisher_did,
        expected_ceremony_id=target_ceremony,
        expected_group=group,
        now=now,
        challenge=challenge,
    )
    record_outbound_offer(
        cfg,
        binding,
        artifact,
        created_at=now,
    )
    publish_outbound_offer(cfg, binding.proof_digest)
    return signed
