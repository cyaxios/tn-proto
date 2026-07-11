#!/usr/bin/env python3
"""Build the deterministic cross-SDK trust contract fixtures."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import ntpath
import posixpath
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = ROOT / "tests/fixtures/trust/v1"
SCHEMA = "tn.trust-fixtures/v1"
CANONICALIZATION = "tn-canonical-json-v1"

ISSUED_AT = "2026-07-11T14:00:00Z"
VALIDATION_TIME = "2026-07-11T14:05:00Z"
EXPIRES_AT = "2026-07-11T14:10:00Z"
AFTER_EXPIRY = "2026-07-11T14:10:01Z"
CEREMONY_ID = "trust-fixture-ceremony-2026-07-11"
GROUP = "default"
CHALLENGE_ID = "challenge-00000000-0000-4000-8000-000000000001"

OPERATIONS = (
    "read",
    "watch",
    "jwe_add_recipient",
    "hibe_grant",
    "legacy_package_import",
)
RELAXATIONS = (
    "verification_disabled",
    "signature_not_required",
    "unauthenticated_allowed",
    "unknown_writer_allowed",
    "unverified_key_binding",
    "plaintext_bearer_delivery",
    "legacy_signer_mismatch",
)


JsonObject = dict[str, Any]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _fixed_bytes(label: str, length: int = 32) -> bytes:
    blocks = bytearray()
    counter = 0
    while len(blocks) < length:
        blocks.extend(
            hashlib.sha256(f"tn-trust-v1:{label}:{counter}".encode()).digest()
        )
        counter += 1
    return bytes(blocks[:length])


def _base58btc(value: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    zeroes = len(value) - len(value.lstrip(b"\0"))
    return "1" * zeroes + (encoded or "1")


def _did_key(public_key: bytes, prefix: bytes = b"\xed\x01") -> str:
    return "did:key:z" + _base58btc(prefix + public_key)


def _raw_public(private_key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _ed25519_material(label: str) -> JsonObject:
    seed = _fixed_bytes(f"ed25519:{label}")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = _raw_public(private_key)
    return {
        "did": _did_key(public_key),
        "private": private_key,
        "public": public_key,
        "seed": seed,
    }


def _x25519_material(label: str) -> JsonObject:
    seed = _fixed_bytes(f"x25519:{label}")
    private_key = X25519PrivateKey.from_private_bytes(seed)
    return {
        "private": private_key,
        "public": _raw_public(private_key),
        "seed": seed,
    }


def _sign_statement(body: JsonObject, signer: Ed25519PrivateKey) -> JsonObject:
    statement = copy.deepcopy(body)
    statement["signature_b64"] = _b64(signer.sign(_canonical_bytes(statement)))
    return statement


def _statement_signing_bytes(statement: JsonObject) -> bytes:
    value = copy.deepcopy(statement)
    value.pop("signature_b64", None)
    return _canonical_bytes(value)


def _manifest_signing_bytes(manifest: JsonObject) -> bytes:
    value = copy.deepcopy(manifest)
    value.pop("manifest_signature_b64", None)
    return _canonical_bytes(value)


def _resign_manifest(manifest: JsonObject, signer: Ed25519PrivateKey) -> JsonObject:
    value = copy.deepcopy(manifest)
    value.pop("manifest_signature_b64", None)
    value["manifest_signature_b64"] = _b64(signer.sign(_manifest_signing_bytes(value)))
    return value


def _tnpkg_bytes(manifest: JsonObject, body_members: dict[str, bytes]) -> bytes:
    entries = {"manifest.json": _canonical_bytes(manifest), **body_members}
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 7, 11, 14, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            archive.writestr(info, content)
    return output.getvalue()


def _offer_package(
    materials: JsonObject,
    *,
    proof: JsonObject | None = None,
    outer_signer: JsonObject | None = None,
) -> JsonObject:
    inner_proof = proof or materials["jwe_proof"]
    signer = outer_signer or materials["reader"]
    package_body = {
        "ceremony_id": CEREMONY_ID,
        "compiled_at": ISSUED_AT,
        "device_identity": materials["reader"]["did"],
        "group": GROUP,
        "group_epoch": 0,
        "package_kind": "offer",
        "package_version": 1,
        "payload": {
            "key_binding_proof": inner_proof,
            "x25519_pub_b64": _b64(materials["reader_x25519"]["public"]),
        },
        "recipient_identity": materials["publisher"]["did"],
        "signer_verify_pub_b64": _b64(materials["reader"]["public"]),
    }
    package_body["sig_b64"] = _b64(
        materials["reader"]["private"].sign(_canonical_bytes(package_body)),
    )
    body_members = {
        "body/metadata.json": _canonical_bytes(
            {"ceremony_id": CEREMONY_ID, "group": GROUP, "purpose": "jwe-reader"},
        ),
        "body/package.json": _canonical_bytes(package_body),
    }
    manifest = _resign_manifest(
        {
            "as_of": ISSUED_AT,
            "body_sha256": {
                path: _sha256(content) for path, content in body_members.items()
            },
            "ceremony_id": CEREMONY_ID,
            "clock": {},
            "event_count": 1,
            "kind": "offer",
            "publisher_identity": signer["did"],
            "recipient_identity": materials["publisher"]["did"],
            "scope": GROUP,
            "version": 1,
        },
        signer["private"],
    )
    package = _tnpkg_bytes(manifest, body_members)
    return {
        "artifact_digest": _sha256(package),
        "body_members": body_members,
        "manifest": manifest,
        "tnpkg": package,
    }


def _document(name: str, cases: list[JsonObject]) -> JsonObject:
    return {
        "canonicalization": CANONICALIZATION,
        "cases": cases,
        "fixture": name,
        "schema": SCHEMA,
    }


def _reject(
    baseline: JsonObject,
    case_id: str,
    reason: str,
    mutate: Callable[[JsonObject], None],
    *,
    validity_key: str = "accepted",
) -> JsonObject:
    case = copy.deepcopy(baseline)
    case["id"] = case_id
    case["baseline"] = baseline["id"]
    mutate(case["input"])
    case["expected"] = {validity_key: False, "reason": reason}
    return case


def _materials() -> JsonObject:
    publisher = _ed25519_material("publisher")
    reader = _ed25519_material("reader")
    authority = _ed25519_material("authority")
    reader_x25519 = _x25519_material("reader-static")
    sender_x25519 = _x25519_material("publisher-ephemeral")

    challenge = _sign_statement(
        {
            "ceremony_id": CEREMONY_ID,
            "challenge_id": CHALLENGE_ID,
            "expected_reader_did": reader["did"],
            "expires_at": EXPIRES_AT,
            "group": GROUP,
            "issued_at": ISSUED_AT,
            "kind": "tn-enrollment-challenge",
            "nonce_b64": _b64(_fixed_bytes("challenge-nonce")),
            "publisher_did": publisher["did"],
            "version": 1,
        },
        publisher["private"],
    )
    challenge_digest = _sha256(_canonical_bytes(challenge))
    hibe_challenge = _sign_statement(
        {
            "ceremony_id": CEREMONY_ID,
            "challenge_id": "challenge-00000000-0000-4000-8000-000000000002",
            "expected_reader_did": reader["did"],
            "expires_at": EXPIRES_AT,
            "group": GROUP,
            "issued_at": ISSUED_AT,
            "kind": "tn-enrollment-challenge",
            "nonce_b64": _b64(_fixed_bytes("hibe-challenge-nonce")),
            "publisher_did": authority["did"],
            "version": 1,
        },
        authority["private"],
    )
    hibe_challenge_digest = _sha256(_canonical_bytes(hibe_challenge))

    jwe_proof = _sign_statement(
        {
            "audience_did": publisher["did"],
            "binding": {
                "algorithm": "X25519",
                "challenge_digest": challenge_digest,
                "public_key_b64": _b64(reader_x25519["public"]),
            },
            "ceremony_id": CEREMONY_ID,
            "expires_at": EXPIRES_AT,
            "group": GROUP,
            "issued_at": ISSUED_AT,
            "nonce_b64": _b64(_fixed_bytes("jwe-proof-nonce")),
            "purpose": "jwe-reader",
            "subject_did": reader["did"],
            "version": 1,
        },
        reader["private"],
    )
    hibe_reader_proof = _sign_statement(
        {
            "audience_did": authority["did"],
            "binding": {
                "algorithm": "Ed25519-did-key",
                "challenge_digest": hibe_challenge_digest,
                "delivery": "recipient-seal-v1",
            },
            "ceremony_id": CEREMONY_ID,
            "expires_at": EXPIRES_AT,
            "group": GROUP,
            "issued_at": ISSUED_AT,
            "nonce_b64": _b64(_fixed_bytes("hibe-reader-proof-nonce")),
            "purpose": "hibe-reader",
            "subject_did": reader["did"],
            "version": 1,
        },
        reader["private"],
    )
    mpk = _fixed_bytes("hibe-mpk", 96)
    hibe_authority_proof = _sign_statement(
        {
            "audience_did": publisher["did"],
            "binding": {
                "algorithm": "TN-BBG-HIBE-BLS12-381",
                "id_path": "org/fraud/case-17",
                "max_depth": 3,
                "mpk_sha256": _sha256(mpk),
                "path_epoch": 4,
            },
            "ceremony_id": CEREMONY_ID,
            "expires_at": EXPIRES_AT,
            "group": GROUP,
            "issued_at": ISSUED_AT,
            "nonce_b64": _b64(_fixed_bytes("hibe-authority-proof-nonce")),
            "purpose": "hibe-authority",
            "subject_did": authority["did"],
            "version": 1,
        },
        authority["private"],
    )
    offer_digest = _sha256(_canonical_bytes(jwe_proof))
    response = _sign_statement(
        {
            "accepted_offer_digest": offer_digest,
            "ceremony_id": CEREMONY_ID,
            "expires_at": "2026-07-11T14:11:00Z",
            "group": GROUP,
            "group_epoch": 1,
            "issued_at": "2026-07-11T14:01:00Z",
            "kind": "tn-enrollment-response",
            "publisher_did": publisher["did"],
            "reader_did": reader["did"],
            "version": 1,
            "x25519_public_key_sha256": _sha256(reader_x25519["public"]),
        },
        publisher["private"],
    )
    return {
        "authority": authority,
        "challenge": challenge,
        "challenge_digest": challenge_digest,
        "hibe_challenge": hibe_challenge,
        "hibe_challenge_digest": hibe_challenge_digest,
        "hibe_authority_proof": hibe_authority_proof,
        "hibe_mpk": mpk,
        "hibe_reader_proof": hibe_reader_proof,
        "jwe_proof": jwe_proof,
        "offer_digest": offer_digest,
        "publisher": publisher,
        "reader": reader,
        "reader_x25519": reader_x25519,
        "response": response,
        "sender_x25519": sender_x25519,
    }


def _did_key_vectors(materials: JsonObject) -> JsonObject:
    cases: list[JsonObject] = []
    for role in ("publisher", "reader", "authority"):
        material = materials[role]
        cases.append(
            {
                "expected": {"public_key_b64": _b64(material["public"]), "valid": True},
                "id": f"{role}_ed25519_did_key",
                "input": {
                    "did": material["did"],
                    "public_key_b64": _b64(material["public"]),
                    "seed_b64": _b64(material["seed"]),
                },
                "kind": "ed25519-did-key",
            },
        )

    publisher_case = cases[0]
    cases.append(
        _reject(
            publisher_case,
            "did_key_wrong_multicodec",
            "did_invalid",
            lambda value: value.__setitem__(
                "did",
                _did_key(materials["publisher"]["public"], b"\xec\x01"),
            ),
            validity_key="valid",
        ),
    )
    cases.append(
        _reject(
            publisher_case,
            "did_key_truncated",
            "did_invalid",
            lambda value: value.__setitem__("did", value["did"][:-1]),
            validity_key="valid",
        ),
    )

    x25519 = materials["reader_x25519"]
    x_case = {
        "expected": {"public_key_b64": _b64(x25519["public"]), "valid": True},
        "id": "reader_x25519_static_key",
        "input": {
            "algorithm": "X25519",
            "private_seed_b64": _b64(x25519["seed"]),
            "public_key_b64": _b64(x25519["public"]),
        },
        "kind": "x25519-key",
    }
    cases.append(x_case)
    cases.append(
        _reject(
            x_case,
            "reader_x25519_wrong_length",
            "binding_invalid",
            lambda value: value.__setitem__(
                "public_key_b64",
                _b64(base64.b64decode(value["public_key_b64"])[:-1]),
            ),
            validity_key="valid",
        ),
    )
    return _document("did_key_vectors", cases)


def _signed_case(
    case_id: str,
    kind: str,
    statement: JsonObject,
    signer: JsonObject,
    validation: JsonObject,
) -> JsonObject:
    return {
        "canonical_b64": _b64(_statement_signing_bytes(statement)),
        "expected": {"accepted": True},
        "id": case_id,
        "input": {"statement": copy.deepcopy(statement), "validation": validation},
        "kind": kind,
        "signer_public_key_b64": _b64(signer["public"]),
    }


def _signed_statements(materials: JsonObject) -> JsonObject:
    publisher = materials["publisher"]
    reader = materials["reader"]
    authority = materials["authority"]
    cases = [
        _signed_case(
            "valid_enrollment_challenge",
            "EnrollmentChallengeV1",
            materials["challenge"],
            publisher,
            {
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_publisher_did": publisher["did"],
                "expected_reader_did": reader["did"],
                "now": VALIDATION_TIME,
            },
        ),
        _signed_case(
            "valid_hibe_reader_challenge",
            "EnrollmentChallengeV1",
            materials["hibe_challenge"],
            authority,
            {
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_publisher_did": authority["did"],
                "expected_reader_did": reader["did"],
                "now": VALIDATION_TIME,
            },
        ),
        _signed_case(
            "valid_jwe_reader_proof",
            "KeyBindingProofV1/jwe-reader",
            materials["jwe_proof"],
            reader,
            {
                "challenge_digest": materials["challenge_digest"],
                "expected_audience_did": publisher["did"],
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_public_key_sha256": _sha256(
                    materials["reader_x25519"]["public"]
                ),
                "expected_purpose": "jwe-reader",
                "expected_signer_did": reader["did"],
                "now": VALIDATION_TIME,
            },
        ),
        _signed_case(
            "valid_hibe_reader_proof",
            "KeyBindingProofV1/hibe-reader",
            materials["hibe_reader_proof"],
            reader,
            {
                "challenge_digest": materials["hibe_challenge_digest"],
                "expected_audience_did": authority["did"],
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_purpose": "hibe-reader",
                "expected_signer_did": reader["did"],
                "now": VALIDATION_TIME,
            },
        ),
        _signed_case(
            "valid_hibe_authority_proof",
            "KeyBindingProofV1/hibe-authority",
            materials["hibe_authority_proof"],
            authority,
            {
                "expected_audience_did": publisher["did"],
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_mpk_b64": _b64(materials["hibe_mpk"]),
                "expected_purpose": "hibe-authority",
                "expected_signer_did": authority["did"],
                "now": VALIDATION_TIME,
            },
        ),
        _signed_case(
            "valid_enrollment_response",
            "EnrollmentResponseV1",
            materials["response"],
            publisher,
            {
                "expected_ceremony_id": CEREMONY_ID,
                "expected_group": GROUP,
                "expected_offer_digest": materials["offer_digest"],
                "expected_public_key_sha256": _sha256(
                    materials["reader_x25519"]["public"]
                ),
                "expected_publisher_did": publisher["did"],
                "expected_reader_did": reader["did"],
                "now": VALIDATION_TIME,
            },
        ),
    ]

    challenge = cases[0]
    cases.append(
        _reject(
            challenge,
            "challenge_unknown_field",
            "statement_invalid",
            lambda value: value["statement"].__setitem__("unexpected", True),
        ),
    )
    cases.append(
        _reject(
            challenge,
            "challenge_unsupported_version",
            "statement_invalid",
            lambda value: value["statement"].__setitem__("version", 2),
        ),
    )
    cases.append(
        _reject(
            challenge,
            "challenge_expired_statement",
            "statement_expired",
            lambda value: value["validation"].__setitem__("now", AFTER_EXPIRY),
        ),
    )
    cases.append(
        _reject(
            challenge,
            "challenge_signature_mutated",
            "signature_invalid",
            lambda value: value["statement"].__setitem__(
                "signature_b64", _b64(bytes(64))
            ),
        ),
    )
    jwe = next(case for case in cases if case["id"] == "valid_jwe_reader_proof")
    cases.append(
        _reject(
            jwe,
            "jwe_proof_signer_did_mismatch",
            "did_signer_mismatch",
            lambda value: value["validation"].__setitem__(
                "expected_signer_did",
                authority["did"],
            ),
        ),
    )
    cases.append(
        _reject(
            jwe,
            "jwe_proof_wrong_recipient",
            "wrong_recipient",
            lambda value: value["validation"].__setitem__(
                "expected_audience_did",
                authority["did"],
            ),
        ),
    )
    cases.append(
        _reject(
            jwe,
            "jwe_proof_scope_mismatch",
            "scope_mismatch",
            lambda value: value["validation"].__setitem__("expected_group", "fraud"),
        ),
    )
    cases.append(
        _reject(
            jwe,
            "jwe_proof_binding_mismatch",
            "binding_invalid",
            lambda value: value["validation"].__setitem__(
                "expected_public_key_sha256",
                _sha256(_fixed_bytes("other-x25519-public")),
            ),
        ),
    )
    for case in cases:
        case["canonical_b64"] = _b64(
            _statement_signing_bytes(case["input"]["statement"]),
        )
    return _document("signed_statements", cases)


def _package_body_index(materials: JsonObject) -> JsonObject:
    package = _offer_package(materials)
    manifest = package["manifest"]
    body_raw = package["body_members"]
    valid = {
        "canonical_b64": _b64(_manifest_signing_bytes(manifest)),
        "expected": {"accepted": True},
        "id": "valid_offer_body_index",
        "input": {
            "body_members_b64": {
                path: _b64(content) for path, content in body_raw.items()
            },
            "manifest_b64": _b64(_canonical_bytes(manifest)),
        },
        "signer_public_key_b64": _b64(materials["reader"]["public"]),
    }
    cases = [valid]
    cases.append(
        _reject(
            valid,
            "substituted_offer_body",
            "body_digest_mismatch",
            lambda value: value["body_members_b64"].__setitem__(
                "body/package.json",
                _b64(body_raw["body/package.json"] + b"\n"),
            ),
        ),
    )
    cases.append(
        _reject(
            valid,
            "missing_indexed_body",
            "body_digest_mismatch",
            lambda value: value["body_members_b64"].pop("body/package.json"),
        ),
    )
    cases.append(
        _reject(
            valid,
            "extra_unindexed_body",
            "body_digest_mismatch",
            lambda value: value["body_members_b64"].__setitem__(
                "body/extra.json",
                _b64(b"{}"),
            ),
        ),
    )
    malformed_manifest = copy.deepcopy(manifest)
    malformed_manifest["body_sha256"]["body/package.json"] = "sha256:NOT-LOWERCASE-HEX"
    malformed_manifest = _resign_manifest(
        malformed_manifest, materials["reader"]["private"]
    )
    cases.append(
        _reject(
            valid,
            "malformed_body_digest",
            "body_digest_mismatch",
            lambda value: value.__setitem__(
                "manifest_b64",
                _b64(_canonical_bytes(malformed_manifest)),
            ),
        ),
    )
    missing_index_manifest = copy.deepcopy(manifest)
    missing_index_manifest.pop("body_sha256")
    missing_index_manifest = _resign_manifest(
        missing_index_manifest,
        materials["reader"]["private"],
    )
    cases.append(
        _reject(
            valid,
            "missing_body_index",
            "body_digest_mismatch",
            lambda value: value.__setitem__(
                "manifest_b64",
                _b64(_canonical_bytes(missing_index_manifest)),
            ),
        ),
    )
    invalid_signature_manifest = copy.deepcopy(manifest)
    invalid_signature_manifest["manifest_signature_b64"] = _b64(bytes(64))
    cases.append(
        _reject(
            valid,
            "manifest_signature_mutated",
            "signature_invalid",
            lambda value: value.__setitem__(
                "manifest_b64",
                _b64(_canonical_bytes(invalid_signature_manifest)),
            ),
        ),
    )
    for case in cases:
        case_manifest = json.loads(
            base64.b64decode(case["input"]["manifest_b64"], validate=True),
        )
        case["canonical_b64"] = _b64(
            _manifest_signing_bytes(case_manifest),
        )
    return _document("package_body_index", cases)


def _offer_lifecycle_input(materials: JsonObject, package: JsonObject) -> JsonObject:
    return {
        "operation": "absorb_offer",
        "tnpkg_b64": _b64(package["tnpkg"]),
        "validation": {
            "challenge_state": "issued",
            "expected_ceremony_id": CEREMONY_ID,
            "expected_challenge_digest": materials["challenge_digest"],
            "expected_group": GROUP,
            "expected_public_key_sha256": _sha256(
                materials["reader_x25519"]["public"],
            ),
            "local_recipient_did": materials["publisher"]["did"],
            "now": VALIDATION_TIME,
            "trusted_reader_dids": [materials["reader"]["did"]],
        },
    }


def _jwe_lifecycle_artifact(materials: JsonObject) -> JsonObject:
    sender = materials["sender_x25519"]
    reader = materials["reader_x25519"]
    shared_secret = sender["private"].exchange(
        X25519PublicKey.from_public_bytes(reader["public"]),
    )
    algorithm = b"ECDH-ES+A256KW"
    concat_kdf = b"".join(
        (
            (1).to_bytes(4, "big"),
            shared_secret,
            len(algorithm).to_bytes(4, "big"),
            algorithm,
            (0).to_bytes(4, "big"),
            (0).to_bytes(4, "big"),
            (256).to_bytes(4, "big"),
        ),
    )
    key_encryption_key = hashlib.sha256(concat_kdf).digest()
    content_encryption_key = _fixed_bytes("jwe-content-encryption-key")
    wrapped_key = aes_key_wrap(key_encryption_key, content_encryption_key)

    protected = _b64u(_canonical_bytes({"enc": "A256GCM"}))
    aad = _canonical_bytes(
        {
            "ceremony_id": CEREMONY_ID,
            "group": GROUP,
            "recipient": materials["reader"]["did"],
        },
    )
    aad_b64u = _b64u(aad)
    aead_aad = f"{protected}.{aad_b64u}".encode("ascii")
    iv = _fixed_bytes("jwe-content-iv", 12)
    plaintext = _canonical_bytes(
        {"event_type": "fixture.first_decrypt", "secret": "accepted"},
    )
    sealed = AESGCM(content_encryption_key).encrypt(iv, plaintext, aead_aad)
    jwe = {
        "aad": aad_b64u,
        "ciphertext": _b64u(sealed[:-16]),
        "iv": _b64u(iv),
        "protected": protected,
        "recipients": [
            {
                "encrypted_key": _b64u(wrapped_key),
                "header": {
                    "alg": "ECDH-ES+A256KW",
                    "epk": {
                        "crv": "X25519",
                        "kty": "OKP",
                        "x": _b64u(sender["public"]),
                    },
                },
            },
        ],
        "tag": _b64u(sealed[-16:]),
    }
    return {
        "aad": aad,
        "jwe": _canonical_bytes(jwe),
        "plaintext": plaintext,
        "shared_secret": shared_secret,
    }


def _enrollment_lifecycle(materials: JsonObject) -> JsonObject:
    challenge_case = {
        "expected": {
            "accepted": True,
            "challenge_digest": materials["challenge_digest"],
            "next_state": "challenge_issued",
        },
        "id": "issue_signed_challenge",
        "input": {
            "challenge": materials["challenge"],
            "operation": "issue_challenge",
            "publisher_did": materials["publisher"]["did"],
            "reader_did": materials["reader"]["did"],
        },
        "phase": "challenge",
    }
    offer_package = _offer_package(materials)
    offer_case = {
        "expected": {
            "accepted": True,
            "artifact_digest": offer_package["artifact_digest"],
            "next_state": "offer_pending",
            "offer_digest": materials["offer_digest"],
        },
        "id": "absorb_authenticated_offer",
        "input": _offer_lifecycle_input(materials, offer_package),
        "phase": "offer",
    }
    approval_case = {
        "expected": {"accepted": True, "next_state": "offer_accepted"},
        "id": "approve_exact_offer_digest",
        "input": {
            "approved_offer_digest": materials["offer_digest"],
            "operation": "approve_offer",
            "pending_offer_digest": materials["offer_digest"],
            "reader_did": materials["reader"]["did"],
            "tnpkg_b64": _b64(offer_package["tnpkg"]),
        },
        "phase": "approval",
    }
    response_case = {
        "expected": {"accepted": True, "next_state": "publisher_installed"},
        "id": "verify_accepted_enrollment_response",
        "input": {
            "expected_offer_digest": materials["offer_digest"],
            "expected_public_key_sha256": _sha256(materials["reader_x25519"]["public"]),
            "operation": "verify_response",
            "response": materials["response"],
        },
        "phase": "response",
    }

    reader = materials["reader_x25519"]
    jwe_artifact = _jwe_lifecycle_artifact(materials)
    decrypt_case = {
        "expected": {
            "accepted": True,
            "plaintext_b64": _b64(jwe_artifact["plaintext"]),
            "shared_secret_sha256": _sha256(jwe_artifact["shared_secret"]),
        },
        "id": "first_decrypt_with_retained_reader_key",
        "input": {
            "aad_b64": _b64(jwe_artifact["aad"]),
            "jwe_b64": _b64(jwe_artifact["jwe"]),
            "operation": "first_decrypt",
            "reader_private_seed_b64": _b64(reader["seed"]),
        },
        "phase": "first_decrypt",
    }
    cases = [challenge_case, offer_case, approval_case, response_case, decrypt_case]

    outer_mismatch_package = _offer_package(
        materials,
        outer_signer=materials["authority"],
    )
    mismatched_body_members = copy.deepcopy(offer_package["body_members"])
    mismatched_body_members["body/package.json"] += b"\n"
    body_mismatch_tnpkg = _tnpkg_bytes(
        offer_package["manifest"],
        mismatched_body_members,
    )
    offer_mutations: tuple[tuple[str, str, Callable[[JsonObject], None]], ...] = (
        (
            "offer_outer_inner_signer_mismatch",
            "outer_inner_signer_mismatch",
            lambda value: value.__setitem__(
                "tnpkg_b64",
                _b64(outer_mismatch_package["tnpkg"]),
            ),
        ),
        (
            "offer_wrong_recipient",
            "wrong_recipient",
            lambda value: value["validation"].__setitem__(
                "local_recipient_did",
                materials["authority"]["did"],
            ),
        ),
        (
            "offer_scope_mismatch",
            "scope_mismatch",
            lambda value: value["validation"].__setitem__("expected_group", "fraud"),
        ),
        (
            "offer_body_digest_mismatch",
            "body_digest_mismatch",
            lambda value: value.__setitem__("tnpkg_b64", _b64(body_mismatch_tnpkg)),
        ),
        (
            "offer_challenge_missing",
            "challenge_missing",
            lambda value: value["validation"].__setitem__("challenge_state", "missing"),
        ),
        (
            "offer_challenge_expired",
            "challenge_expired",
            lambda value: value["validation"].__setitem__("challenge_state", "expired"),
        ),
        (
            "offer_challenge_replayed",
            "challenge_replayed",
            lambda value: value["validation"].__setitem__(
                "challenge_state", "consumed"
            ),
        ),
        (
            "offer_binding_invalid",
            "binding_invalid",
            lambda value: value["validation"].__setitem__(
                "expected_public_key_sha256",
                _sha256(_fixed_bytes("other-x25519-public")),
            ),
        ),
        (
            "offer_untrusted_principal",
            "untrusted_principal",
            lambda value: value["validation"].__setitem__("trusted_reader_dids", []),
        ),
    )
    for case_id, reason, mutate in offer_mutations:
        rejected = _reject(offer_case, case_id, reason, mutate)
        rejected["phase"] = "offer"
        cases.append(rejected)

    cases.append(
        _reject(
            approval_case,
            "approval_digest_not_exact",
            "untrusted_principal",
            lambda value: value.__setitem__(
                "approved_offer_digest",
                _sha256(b"another-offer"),
            ),
        ),
    )
    cases[-1]["phase"] = "approval"
    cases.append(
        _reject(
            response_case,
            "response_offer_scope_mismatch",
            "scope_mismatch",
            lambda value: value.__setitem__(
                "expected_offer_digest",
                _sha256(b"another-offer"),
            ),
        ),
    )
    cases[-1]["phase"] = "response"
    cases.append(
        _reject(
            decrypt_case,
            "first_decrypt_wrong_private_key",
            "binding_invalid",
            lambda value: value.__setitem__(
                "reader_private_seed_b64",
                _b64(_fixed_bytes("wrong-reader-x25519")),
            ),
        ),
    )
    cases[-1]["phase"] = "first_decrypt"
    return _document("enrollment_lifecycle", cases)


def _state_transitions(materials: JsonObject) -> JsonObject:
    consume = {
        "expected": {"accepted": True, "next_state": "consumed"},
        "id": "consume_fresh_challenge",
        "input": {
            "artifact_digest": _sha256(b"offer-artifact-a"),
            "challenge_id": CHALLENGE_ID,
            "consumed": False,
            "operation": "consume_challenge",
            "prior_artifact_digest": None,
        },
    }
    repeated = {
        "expected": {"accepted": True, "idempotent": True, "next_state": "consumed"},
        "id": "repeat_same_consumed_artifact",
        "input": {
            "artifact_digest": _sha256(b"offer-artifact-a"),
            "challenge_id": CHALLENGE_ID,
            "consumed": True,
            "operation": "consume_challenge",
            "prior_artifact_digest": _sha256(b"offer-artifact-a"),
        },
    }
    epoch_update = {
        "expected": {"accepted": True, "next_epoch": 4},
        "id": "advance_hibe_epoch",
        "input": {
            "authority_did": materials["authority"]["did"],
            "current_epoch": 3,
            "current_mpk_sha256": _sha256(materials["hibe_mpk"]),
            "incoming_epoch": 4,
            "incoming_mpk_sha256": _sha256(materials["hibe_mpk"]),
            "operation": "install_hibe_assertion",
        },
    }
    same_epoch = {
        "expected": {"accepted": True, "idempotent": True, "next_epoch": 4},
        "id": "repeat_same_hibe_epoch",
        "input": {
            "authority_did": materials["authority"]["did"],
            "current_epoch": 4,
            "current_mpk_sha256": _sha256(materials["hibe_mpk"]),
            "incoming_epoch": 4,
            "incoming_mpk_sha256": _sha256(materials["hibe_mpk"]),
            "operation": "install_hibe_assertion",
        },
    }
    cases = [consume, repeated, epoch_update, same_epoch]
    cases.append(
        _reject(
            consume,
            "consume_already_used_challenge",
            "challenge_replayed",
            lambda value: value.__setitem__("consumed", True),
        ),
    )
    cases.append(
        _reject(
            repeated,
            "consumed_challenge_conflicting_artifact",
            "replay_conflict",
            lambda value: value.__setitem__(
                "artifact_digest", _sha256(b"offer-artifact-b")
            ),
        ),
    )
    cases.append(
        _reject(
            epoch_update,
            "hibe_epoch_rollback",
            "epoch_rollback",
            lambda value: value.__setitem__("incoming_epoch", 2),
        ),
    )
    cases.append(
        _reject(
            same_epoch,
            "hibe_same_epoch_mpk_conflict",
            "epoch_conflict",
            lambda value: value.__setitem__(
                "incoming_mpk_sha256",
                _sha256(_fixed_bytes("conflicting-hibe-mpk", 96)),
            ),
        ),
    )
    return _document("state_transitions", cases)


def _read_input(materials: JsonObject, verify: str | bool = "auto") -> JsonObject:
    publisher_did = materials["publisher"]["did"]
    return {
        "context": {
            "active": True,
            "detached": False,
            "local_device_did": publisher_did,
            "local_log": True,
            "profile_chain": True,
            "profile_sign": True,
            "required_group": None,
            "trusted_writer_dids": [publisher_did],
            "writable": True,
        },
        "policy": {
            "allow_unauthenticated": None,
            "allow_unknown_writers": False,
            "require_signature": None,
            "trusted_writers": None,
            "verify": verify,
        },
        "record": {
            "aad_valid": True,
            "chain_valid": True,
            "record_valid": True,
            "recipient_groups": [GROUP],
            "row_hash_present": True,
            "row_hash_valid": True,
            "signature_present": True,
            "signature_valid": True,
            "writer_did": publisher_did,
        },
    }


def _read_case(
    case_id: str,
    value: JsonObject,
    *,
    accepted: bool = True,
    reasons: list[str] | None = None,
    writer_authenticated: bool = True,
    writer_authorized: bool = True,
) -> JsonObject:
    verify = value["policy"]["verify"]
    return {
        "expected": {
            "accepted": accepted,
            "reasons": reasons or [],
            "resolved_mode": "raise"
            if verify == "auto"
            else ("disabled" if verify is False else verify),
            "writer_authenticated": writer_authenticated,
            "writer_authorized": writer_authorized,
        },
        "id": case_id,
        "input": value,
    }


def _read_reject(
    baseline: JsonObject,
    case_id: str,
    reasons: list[str],
    mutate: Callable[[JsonObject], None],
    *,
    writer_authenticated: bool,
    writer_authorized: bool,
) -> JsonObject:
    case = copy.deepcopy(baseline)
    case["id"] = case_id
    case["baseline"] = baseline["id"]
    mutate(case["input"])
    case["expected"] = {
        "accepted": False,
        "reasons": reasons,
        "resolved_mode": (
            "raise"
            if case["input"]["policy"]["verify"] == "auto"
            else (
                "disabled"
                if case["input"]["policy"]["verify"] is False
                else case["input"]["policy"]["verify"]
            )
        ),
        "writer_authenticated": writer_authenticated,
        "writer_authorized": writer_authorized,
    }
    return case


def _read_policy_matrix(materials: JsonObject) -> JsonObject:
    auto = _read_case("auto_local_signed", _read_input(materials, "auto"))
    raise_mode = _read_case("raise_local_signed", _read_input(materials, "raise"))
    skip_mode = _read_case("skip_local_signed", _read_input(materials, "skip"))
    disabled = _read_case(
        "false_local_signed",
        _read_input(materials, False),
        writer_authenticated=False,
        writer_authorized=False,
    )

    local_unsigned_input = _read_input(materials, "auto")
    local_unsigned_input["context"]["profile_sign"] = False
    local_unsigned_input["record"]["signature_present"] = False
    local_unsigned = _read_case(
        "auto_local_profile_unsigned",
        local_unsigned_input,
        writer_authenticated=False,
        writer_authorized=False,
    )

    foreign_input = _read_input(materials, "auto")
    foreign_input["context"]["local_log"] = False
    foreign_input["context"]["trusted_writer_dids"] = [materials["reader"]["did"]]
    foreign_input["record"]["writer_did"] = materials["reader"]["did"]
    foreign = _read_case("auto_foreign_trusted_signed", foreign_input)

    explicit_unsigned_input = copy.deepcopy(foreign_input)
    explicit_unsigned_input["policy"]["allow_unauthenticated"] = True
    explicit_unsigned_input["policy"]["require_signature"] = False
    explicit_unsigned_input["record"]["signature_present"] = False
    explicit_unsigned = _read_case(
        "explicit_foreign_unsigned",
        explicit_unsigned_input,
        writer_authenticated=False,
        writer_authorized=False,
    )

    allow_unknown_input = copy.deepcopy(foreign_input)
    allow_unknown_input["policy"]["allow_unknown_writers"] = True
    allow_unknown_input["record"]["writer_did"] = materials["authority"]["did"]
    allow_unknown = _read_case(
        "explicit_allow_unknown_writer",
        allow_unknown_input,
        writer_authenticated=True,
        writer_authorized=False,
    )

    row_hash_absent_input = _read_input(materials, "auto")
    row_hash_absent_input["context"]["profile_chain"] = False
    row_hash_absent_input["record"]["row_hash_present"] = False
    row_hash_absent = _read_case(
        "row_hash_absent_not_required",
        row_hash_absent_input,
    )

    chain_disabled_input = _read_input(materials, "auto")
    chain_disabled_input["context"]["profile_chain"] = False
    chain_disabled_input["record"]["chain_valid"] = False
    chain_disabled = _read_case("chain_disabled", chain_disabled_input)

    trusted_override_input = copy.deepcopy(foreign_input)
    trusted_override_input["context"]["trusted_writer_dids"] = [
        materials["publisher"]["did"],
    ]
    trusted_override_input["policy"]["trusted_writers"] = [materials["reader"]["did"]]
    trusted_override = _read_case(
        "explicit_trusted_writers_override",
        trusted_override_input,
    )

    disabled_unknown_input = copy.deepcopy(disabled["input"])
    disabled_unknown_input["record"]["writer_did"] = materials["authority"]["did"]
    disabled_unknown = _read_case(
        "disabled_ignores_unknown_writer",
        disabled_unknown_input,
        reasons=["writer_untrusted"],
        writer_authenticated=False,
        writer_authorized=False,
    )
    disabled_unknown["baseline"] = disabled["id"]

    cases = [
        auto,
        raise_mode,
        skip_mode,
        disabled,
        local_unsigned,
        foreign,
        explicit_unsigned,
        allow_unknown,
        row_hash_absent,
        chain_disabled,
        trusted_override,
        disabled_unknown,
    ]
    cases.extend(
        [
            _read_reject(
                auto,
                "record_invalid",
                ["record_invalid"],
                lambda value: value["record"].__setitem__("record_valid", False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
            _read_reject(
                auto,
                "row_hash_invalid",
                ["row_hash_invalid"],
                lambda value: value["record"].__setitem__("row_hash_valid", False),
                writer_authenticated=True,
                writer_authorized=False,
            ),
            _read_reject(
                auto,
                "chain_invalid",
                ["chain_invalid"],
                lambda value: value["record"].__setitem__("chain_valid", False),
                writer_authenticated=True,
                writer_authorized=False,
            ),
            _read_reject(
                auto,
                "signature_required",
                ["signature_required"],
                lambda value: value["record"].__setitem__("signature_present", False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
            _read_reject(
                auto,
                "signature_invalid",
                ["signature_invalid"],
                lambda value: value["record"].__setitem__("signature_valid", False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
            _read_reject(
                foreign,
                "writer_untrusted",
                ["writer_untrusted"],
                lambda value: value["record"].__setitem__(
                    "writer_did",
                    materials["authority"]["did"],
                ),
                writer_authenticated=True,
                writer_authorized=False,
            ),
            _read_reject(
                auto,
                "aad_invalid",
                ["aad_invalid"],
                lambda value: value["record"].__setitem__("aad_valid", False),
                writer_authenticated=True,
                writer_authorized=True,
            ),
            _read_reject(
                auto,
                "not_a_recipient",
                ["not_a_recipient"],
                lambda value: value["context"].__setitem__("required_group", "fraud"),
                writer_authenticated=True,
                writer_authorized=True,
            ),
            _read_reject(
                foreign,
                "foreign_unsigned",
                ["signature_required"],
                lambda value: value["record"].__setitem__("signature_present", False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
            _read_reject(
                local_unsigned,
                "context_free_unsigned",
                ["signature_required"],
                lambda value: value["context"].__setitem__("active", False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
            _read_reject(
                skip_mode,
                "skip_row_hash_invalid",
                ["row_hash_invalid"],
                lambda value: value["record"].__setitem__("row_hash_valid", False),
                writer_authenticated=True,
                writer_authorized=False,
            ),
        ],
    )

    row_case = next(case for case in cases if case["id"] == "row_hash_invalid")
    cases.append(
        _read_reject(
            row_case,
            "row_then_chain_invalid",
            ["row_hash_invalid", "chain_invalid"],
            lambda value: value["record"].__setitem__("chain_valid", False),
            writer_authenticated=True,
            writer_authorized=False,
        ),
    )

    for case_id, field, reason in (
        ("disabled_record_invalid", "record_valid", "record_invalid"),
        ("disabled_aad_invalid", "aad_valid", "aad_invalid"),
    ):
        cases.append(
            _read_reject(
                disabled,
                case_id,
                [reason],
                lambda value, field=field: value["record"].__setitem__(field, False),
                writer_authenticated=False,
                writer_authorized=False,
            ),
        )
    cases.append(
        _read_reject(
            disabled,
            "disabled_not_a_recipient",
            ["not_a_recipient"],
            lambda value: value["context"].__setitem__("required_group", "fraud"),
            writer_authenticated=False,
            writer_authorized=False,
        ),
    )

    for case_id, field, reason in (
        ("disabled_ignores_row_hash", "row_hash_valid", "row_hash_invalid"),
        ("disabled_ignores_chain", "chain_valid", "chain_invalid"),
        (
            "disabled_ignores_signature",
            "signature_valid",
            "signature_invalid",
        ),
    ):
        value = copy.deepcopy(disabled["input"])
        value["record"][field] = False
        case = _read_case(
            case_id,
            value,
            reasons=[reason],
            writer_authenticated=False,
            writer_authorized=False,
        )
        case["baseline"] = disabled["id"]
        cases.append(case)

    parameter_error = _read_reject(
        disabled,
        "false_with_trusted_writers_parameter_error",
        [],
        lambda value: value["policy"].__setitem__(
            "trusted_writers",
            [materials["publisher"]["did"]],
        ),
        writer_authenticated=False,
        writer_authorized=False,
    )
    parameter_error["expected"]["parameter_error"] = True
    parameter_error["expected"].pop("resolved_mode")
    cases.append(parameter_error)
    return _document("read_policy_matrix", cases)


def _source_id(descriptor: bytes) -> str:
    return "source:sha256:" + hashlib.sha256(descriptor).hexdigest()


def _cursor_case(
    case_id: str,
    source_kind: str,
    descriptor: bytes,
    cursor_kind: str,
    cursor_value: str,
    source_input: JsonObject,
) -> JsonObject:
    source_id = _source_id(descriptor)
    return {
        "expected": {
            "cursor": {
                "sources": {source_id: {"kind": cursor_kind, "value": cursor_value}},
                "version": 1,
            },
            "descriptor_b64": _b64(descriptor),
            "source_id": source_id,
        },
        "id": case_id,
        "input": source_input,
        "source_kind": source_kind,
    }


def _read_cursor_vectors() -> JsonObject:
    posix_absolute = posixpath.normpath(
        posixpath.join("/srv/tn/ceremonies/acme", "./logs/../logs/run.tnlog"),
    )
    posix_descriptor = b"file\0" + posix_absolute.encode("utf-8")
    posix_case = _cursor_case(
        "posix_file_byte_offset",
        "file-posix",
        posix_descriptor,
        "byte_offset",
        "18446744073709551615",
        {
            "base_directory": "/srv/tn/ceremonies/acme",
            "cursor_kind": "byte_offset",
            "cursor_value": "18446744073709551615",
            "path": "./logs/../logs/run.tnlog",
            "platform": "posix",
        },
    )

    windows_native = ntpath.normpath(
        ntpath.join(r"C:\TN\ceremonies\acme", r"..\logs\.\run.tnlog"),
    )
    drive, tail = ntpath.splitdrive(windows_native)
    windows_absolute = drive.lower() + tail.replace("\\", "/")
    windows_descriptor = b"file\0" + windows_absolute.encode("utf-8")
    windows_case = _cursor_case(
        "windows_file_byte_offset",
        "file-windows",
        windows_descriptor,
        "byte_offset",
        "9007199254740993",
        {
            "base_directory": r"C:\TN\ceremonies\acme",
            "cursor_kind": "byte_offset",
            "cursor_value": "9007199254740993",
            "path": r"..\logs\.\run.tnlog",
            "platform": "windows",
        },
    )

    handler_descriptor = b"handler\0s3\0audit-primary"
    handler_case = _cursor_case(
        "configured_handler_sequence",
        "handler",
        handler_descriptor,
        "sequence",
        "9223372036854775808",
        {
            "configured_id": "audit-primary",
            "cursor_kind": "sequence",
            "cursor_value": "9223372036854775808",
            "handler_kind": "s3",
        },
    )

    detached_content = _canonical_bytes({"fixture": "detached", "rows": 2})
    detached_digest = _sha256(detached_content)
    detached_descriptor = b"detached\0" + detached_digest.encode("ascii")
    detached_case = _cursor_case(
        "detached_bytes_opaque",
        "detached",
        detached_descriptor,
        "opaque",
        "opaque:page/7?token=A%2FB",
        {
            "content_b64": _b64(detached_content),
            "cursor_kind": "opaque",
            "cursor_value": "opaque:page/7?token=A%2FB",
        },
    )

    sources: dict[str, JsonObject] = {}
    for case in (posix_case, windows_case, handler_case, detached_case):
        source_id = case["expected"]["source_id"]
        sources[source_id] = next(iter(case["expected"]["cursor"]["sources"].values()))
    multi_case = {
        "expected": {
            "cursor": {"sources": dict(sorted(sources.items())), "version": 1}
        },
        "id": "multi_source_sorted_cursor",
        "input": {
            "source_ids_unsorted": list(reversed(sorted(sources))),
            "sources": copy.deepcopy(sources),
        },
        "source_kind": "multi-source",
    }
    return _document(
        "read_cursor_vectors",
        [posix_case, windows_case, handler_case, detached_case, multi_case],
    )


def _unsafe_operation_event(materials: JsonObject) -> JsonObject:
    read_payload = {
        "artifact_digest": None,
        "group": None,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": None,
    }
    read_case = {
        "expected": {
            "accepted": True,
            "canonical_json": _canonical_bytes(read_payload).decode(),
        },
        "id": "read_verification_disabled",
        "input": read_payload,
    }
    operation_cases = [read_case]
    for operation, relaxations in (
        (
            "watch",
            [
                "signature_not_required",
                "unauthenticated_allowed",
                "unknown_writer_allowed",
            ],
        ),
        ("jwe_add_recipient", ["unverified_key_binding"]),
        ("hibe_grant", ["plaintext_bearer_delivery"]),
        ("legacy_package_import", ["legacy_signer_mismatch"]),
    ):
        payload = {
            "artifact_digest": None,
            "group": GROUP,
            "operation": operation,
            "relaxations": relaxations,
            "subject_did": materials["reader"]["did"],
        }
        operation_cases.append(
            {
                "expected": {
                    "accepted": True,
                    "canonical_json": _canonical_bytes(payload).decode(),
                },
                "id": f"{operation}_notice",
                "input": payload,
            },
        )
    all_payload = {
        "artifact_digest": _sha256(b"legacy-package"),
        "group": GROUP,
        "operation": "legacy_package_import",
        "relaxations": [
            "unverified_key_binding",
            "legacy_signer_mismatch",
            "unverified_key_binding",
        ],
        "subject_did": materials["reader"]["did"],
    }
    normalized = copy.deepcopy(all_payload)
    normalized["relaxations"] = sorted(set(normalized["relaxations"]))
    normalization_case = {
        "expected": {
            "accepted": True,
            "canonical_json": _canonical_bytes(normalized).decode(),
            "normalized": normalized,
        },
        "id": "relaxations_sort_and_deduplicate",
        "input": all_payload,
    }
    cases = [*operation_cases, normalization_case]
    cases.append(
        _reject(
            read_case,
            "unknown_notice_field",
            "statement_invalid",
            lambda value: value.__setitem__("unexpected", True),
        ),
    )
    cases.append(
        _reject(
            read_case,
            "unknown_operation",
            "statement_invalid",
            lambda value: value.__setitem__("operation", "export_secrets"),
        ),
    )
    cases.append(
        _reject(
            read_case,
            "unknown_relaxation",
            "statement_invalid",
            lambda value: value["relaxations"].__setitem__(0, "everything_allowed"),
        ),
    )
    return _document("unsafe_operation_event", cases)


def build_documents() -> dict[str, JsonObject]:
    materials = _materials()
    return {
        "did_key_vectors.json": _did_key_vectors(materials),
        "enrollment_lifecycle.json": _enrollment_lifecycle(materials),
        "package_body_index.json": _package_body_index(materials),
        "read_cursor_vectors.json": _read_cursor_vectors(),
        "read_policy_matrix.json": _read_policy_matrix(materials),
        "signed_statements.json": _signed_statements(materials),
        "state_transitions.json": _state_transitions(materials),
        "unsafe_operation_event.json": _unsafe_operation_event(materials),
    }


def render_documents() -> dict[Path, bytes]:
    return {
        OUTPUT_ROOT / name: _canonical_bytes(document) + b"\n"
        for name, document in build_documents().items()
    }


def _check(rendered: dict[Path, bytes]) -> int:
    differing_paths = {
        path
        for path, expected in rendered.items()
        if not path.is_file() or path.read_bytes() != expected
    }
    if OUTPUT_ROOT.is_dir():
        differing_paths.update(set(OUTPUT_ROOT.glob("*.json")) - set(rendered))
    differing = [path.relative_to(ROOT).as_posix() for path in sorted(differing_paths)]
    if differing:
        print("trust fixture drift:", file=sys.stderr)
        for path in differing:
            print(f"  {path}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare generated bytes with the checked-in fixtures without writing",
    )
    args = parser.parse_args(argv)
    rendered = render_documents()
    if args.check:
        return _check(rendered)

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    for path, content in sorted(rendered.items()):
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
