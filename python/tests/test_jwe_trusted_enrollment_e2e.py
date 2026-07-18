from __future__ import annotations

import base64
import hashlib
import importlib
import json
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import tn
import tn.enrollment as enrollment

from tn.absorb import absorb
from tn.canonical import _canonical_bytes
from tn.config import LoadedConfig, load_or_create
from tn.compile import compile_enrolment, emit_to_outbox
from tn.conventions import enrollment_dir, outbox_dir
from tn.enrollment import EnrollmentStore
from tn.key_binding import EnrollmentResponseV1, KeyBindingProofV1, verify_jwe_key_binding
from tn.offer import offer
from tn.packaging import Package, sign
from tn.security_audit import TnSecurityWarning
from tn.tnpkg import _read_manifest
from tn.trust import AcceptedOffer, TrustError, TrustReason


def _homes(tmp_path: Path) -> tuple[LoadedConfig, LoadedConfig]:
    publisher = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    reader = load_or_create(tmp_path / "reader" / "tn.yaml", cipher="jwe")
    assert publisher.device.did != reader.device.did
    assert publisher.keystore != reader.keystore
    return publisher, reader


def _challenge(publisher: LoadedConfig, reader: LoadedConfig):
    store = EnrollmentStore(publisher, publisher.device)
    store.preauthorize(reader.device.did, "default")
    return store.issue_challenge(reader.device.did, "default", timedelta(minutes=10))


def _only_outbox_artifact(cfg: LoadedConfig) -> Path:
    artifacts = list(outbox_dir(cfg.yaml_path).glob("*.tnpkg"))
    assert len(artifacts) == 1
    return artifacts[0]


def _proof_digest(proof: KeyBindingProofV1) -> str:
    wire = proof._wire_value(include_signature=True)
    return "sha256:" + hashlib.sha256(_canonical_bytes(wire)).hexdigest()


def _accepted_flow(
    publisher: LoadedConfig,
    reader: LoadedConfig,
) -> AcceptedOffer:
    challenge = _challenge(publisher, reader)
    offer(reader, publisher.device.did, challenge=challenge)
    receipt = absorb(publisher, _only_outbox_artifact(reader))
    assert receipt.offer_digest is not None
    store = EnrollmentStore(publisher, publisher.device)
    now = datetime.now(timezone.utc)
    pending = store.pending_offer(receipt.offer_digest, now=now)
    return store.reconcile(pending, now=now)


def test_reader_offer_uses_authenticated_target_scope_and_durable_state(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)

    package = offer(
        reader,
        publisher.device.did,
        challenge=challenge,
        group="default",
    )

    assert package.ceremony_id == publisher.ceremony_id
    assert package.group == "default"
    assert package.device_identity == reader.device.did
    assert package.recipient_identity == publisher.device.did

    proof = KeyBindingProofV1.from_dict(package.payload["key_binding_proof"])
    binding = verify_jwe_key_binding(
        proof,
        expected_audience_did=publisher.device.did,
        expected_ceremony_id=publisher.ceremony_id,
        expected_group="default",
        now=proof.issued_at,
        challenge=challenge,
    )
    assert binding.principal.did == reader.device.did
    assert base64.b64decode(package.payload["x25519_pub_b64"], validate=True) == (
        binding.public_key
    )

    artifact = _only_outbox_artifact(reader)
    manifest, body = _read_manifest(artifact, verify_signature=True)
    assert manifest.publisher_identity == reader.device.did
    assert manifest.recipient_identity == publisher.device.did
    assert manifest.ceremony_id == publisher.ceremony_id
    assert manifest.scope == "default"
    assert set(body) == {"body/package.json"}

    outbound = enrollment.load_outbound_offer(reader, binding.proof_digest)
    assert outbound.offer_digest == binding.proof_digest
    assert outbound.proof_digest == binding.proof_digest
    assert outbound.reader_did == reader.device.did
    assert outbound.publisher_did == publisher.device.did
    assert outbound.ceremony_id == publisher.ceremony_id
    assert outbound.group == "default"
    assert outbound.public_key_sha256 == binding.public_key_sha256
    assert "private" not in outbound.to_dict()
    assert "mykey" not in outbound.to_dict()


def test_reader_verifies_challenge_before_creating_key_or_state(tmp_path: Path) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)
    unrelated_publisher = load_or_create(
        tmp_path / "unrelated-publisher" / "tn.yaml",
        cipher="jwe",
    )
    key_path = reader.keystore / "default.jwe.mykey"
    original_key = key_path.read_bytes()

    with pytest.raises(TrustError) as caught:
        offer(reader, unrelated_publisher.device.did, challenge=challenge)

    assert caught.value.reason is TrustReason.DID_SIGNER_MISMATCH
    assert key_path.read_bytes() == original_key
    assert not enrollment_dir(reader.yaml_path).exists()
    assert not outbox_dir(reader.yaml_path).exists()


def test_challenge_selects_target_ceremony_and_rejects_conflicting_override(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)
    key_path = reader.keystore / "default.jwe.mykey"
    original_key = key_path.read_bytes()

    with pytest.raises(TrustError) as caught:
        offer(
            reader,
            publisher.device.did,
            challenge=challenge,
            ceremony_id="different-ceremony",
        )

    assert caught.value.reason is TrustReason.SCOPE_MISMATCH
    assert key_path.read_bytes() == original_key


def test_unsolicited_offer_requires_explicit_foreign_ceremony(tmp_path: Path) -> None:
    publisher, reader = _homes(tmp_path)
    key_path = reader.keystore / "default.jwe.mykey"
    original_key = key_path.read_bytes()

    with pytest.raises(ValueError, match="ceremony_id"):
        offer(reader, publisher.device.did)

    assert key_path.read_bytes() == original_key

    package = offer(
        reader,
        publisher.device.did,
        ceremony_id=publisher.ceremony_id,
    )
    proof = KeyBindingProofV1.from_dict(package.payload["key_binding_proof"])
    assert proof.binding["challenge_digest"] is None


def test_reader_key_reuse_rotation_and_concurrent_first_creation(tmp_path: Path) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)

    first = offer(reader, publisher.device.did, challenge=challenge)
    key_path = reader.keystore / "default.jwe.mykey"
    first_secret = key_path.read_bytes()
    second = offer(reader, publisher.device.did, challenge=challenge)
    assert key_path.read_bytes() == first_secret
    assert first.payload["x25519_pub_b64"] == second.payload["x25519_pub_b64"]

    rotated = offer(
        reader,
        publisher.device.did,
        challenge=challenge,
        rotate_reader_key=True,
    )
    assert key_path.read_bytes() != first_secret
    assert rotated.payload["x25519_pub_b64"] != first.payload["x25519_pub_b64"]
    archives = list(reader.keystore.glob("default.jwe.mykey.previous.*"))
    assert len(archives) == 1
    assert archives[0].read_bytes() == first_secret

    concurrent_reader = load_or_create(
        tmp_path / "concurrent-reader" / "tn.yaml",
        cipher="jwe",
    )
    (concurrent_reader.keystore / "default.jwe.mykey").unlink()
    concurrent_challenge = EnrollmentStore(publisher, publisher.device).issue_challenge(
        concurrent_reader.device.did,
        "default",
        timedelta(minutes=10),
    )

    def create_offer(_: int):
        return offer(
            concurrent_reader,
            publisher.device.did,
            challenge=concurrent_challenge,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        packages = list(pool.map(create_offer, range(16)))
    public_keys = {package.payload["x25519_pub_b64"] for package in packages}
    assert len(public_keys) == 1


def test_publisher_absorb_receipt_exposes_exact_offer_digests(tmp_path: Path) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)
    package = offer(reader, publisher.device.did, challenge=challenge)
    proof = KeyBindingProofV1.from_dict(package.payload["key_binding_proof"])
    outbound = enrollment.load_outbound_offer(reader, _proof_digest(proof))

    receipt = absorb(publisher, _only_outbox_artifact(reader))

    assert receipt.status == "offer_stashed"
    assert receipt.offer_digest == outbound.offer_digest
    assert receipt.artifact_digest == outbound.artifact_digest
    assert receipt.reader_did == reader.device.did


def test_outbound_state_is_durable_before_offer_becomes_sendable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offer_module = importlib.import_module("tn.offer")

    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)

    def fail_publish(*_args, **_kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(offer_module, "publish_outbound_offer", fail_publish, raising=False)
    with pytest.raises(OSError, match="injected publication failure"):
        offer_module.offer(reader, publisher.device.did, challenge=challenge)

    assert not outbox_dir(reader.yaml_path).exists()
    state_files = list(
        (enrollment_dir(reader.yaml_path) / "outbound" / "offers").glob("*.json")
    )
    artifacts = list(
        (enrollment_dir(reader.yaml_path) / "outbound" / "artifacts").glob("*.tnpkg")
    )
    assert len(state_files) == 1
    assert len(artifacts) == 1
    retained = json.loads(state_files[0].read_text(encoding="utf-8"))
    digest = retained["offer_digest"]
    assert retained["artifact_digest"] == (
        "sha256:" + hashlib.sha256(artifacts[0].read_bytes()).hexdigest()
    )

    monkeypatch.setattr(
        offer_module,
        "publish_outbound_offer",
        enrollment.publish_outbound_offer,
        raising=False,
    )
    recovered_package = offer_module.offer(
        reader,
        publisher.device.did,
        challenge=challenge,
    )
    published = _only_outbox_artifact(reader)
    published_bytes = published.read_bytes()
    assert published_bytes == artifacts[0].read_bytes()
    _manifest, recovered_body = _read_manifest(published, verify_signature=True)
    assert json.loads(recovered_body["body/package.json"]) == recovered_package.__dict__
    assert len(
        list((enrollment_dir(reader.yaml_path) / "outbound" / "offers").glob("*.json"))
    ) == 1
    assert enrollment.publish_outbound_offer(reader, digest).read_bytes() == published_bytes


def test_failed_explicit_reader_key_rotation_resumes_without_rotating_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offer_module = importlib.import_module("tn.offer")
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)
    original_key = (reader.keystore / "default.jwe.mykey").read_bytes()

    def fail_publish(*_args, **_kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(offer_module, "publish_outbound_offer", fail_publish, raising=False)
    with pytest.raises(OSError, match="injected publication failure"):
        offer_module.offer(
            reader,
            publisher.device.did,
            challenge=challenge,
            rotate_reader_key=True,
        )
    rotated_key = (reader.keystore / "default.jwe.mykey").read_bytes()
    assert rotated_key != original_key

    monkeypatch.setattr(
        offer_module,
        "publish_outbound_offer",
        enrollment.publish_outbound_offer,
        raising=False,
    )
    recovered = offer_module.offer(
        reader,
        publisher.device.did,
        challenge=challenge,
        rotate_reader_key=True,
    )

    assert (reader.keystore / "default.jwe.mykey").read_bytes() == rotated_key
    assert len(
        list((enrollment_dir(reader.yaml_path) / "outbound" / "offers").glob("*.json"))
    ) == 1
    _manifest, body = _read_manifest(_only_outbox_artifact(reader), verify_signature=True)
    assert json.loads(body["body/package.json"]) == recovered.__dict__


def test_prepared_offer_recovery_survives_challenge_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offer_module = importlib.import_module("tn.offer")
    publisher, reader = _homes(tmp_path)
    base = datetime.now(timezone.utc)
    challenge = enrollment.EnrollmentChallengeV1(
        version=1,
        kind="tn-enrollment-challenge",
        publisher_did=publisher.device.did,
        expected_reader_did=reader.device.did,
        ceremony_id=publisher.ceremony_id,
        group="default",
        nonce_b64=base64.b64encode(b"e" * 32).decode("ascii"),
        issued_at=base,
        expires_at=base + timedelta(minutes=2),
        challenge_id="expiry-recovery",
        signature_b64="",
    ).sign(publisher.device)

    class Clock(datetime):
        current = base + timedelta(seconds=1)

        @classmethod
        def now(cls, tz=None):
            return cls.current

    monkeypatch.setattr(offer_module, "datetime", Clock)

    def fail_publish(*_args, **_kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(offer_module, "publish_outbound_offer", fail_publish)
    with pytest.raises(OSError, match="injected publication failure"):
        offer_module.offer(reader, publisher.device.did, challenge=challenge)
    retained_artifact = next(
        (enrollment_dir(reader.yaml_path) / "outbound" / "artifacts").glob("*.tnpkg")
    ).read_bytes()

    Clock.current = challenge.expires_at + timedelta(seconds=1)
    monkeypatch.setattr(offer_module, "publish_outbound_offer", enrollment.publish_outbound_offer)
    recovered = offer_module.offer(reader, publisher.device.did, challenge=challenge)

    assert _only_outbox_artifact(reader).read_bytes() == retained_artifact
    _manifest, body = _read_manifest(retained_artifact, verify_signature=True)
    assert json.loads(body["body/package.json"]) == recovered.__dict__


def test_compile_enrolment_requires_durably_reverified_accepted_offer(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    challenge = _challenge(publisher, reader)
    package = offer(reader, publisher.device.did, challenge=challenge)
    proof = KeyBindingProofV1.from_dict(package.payload["key_binding_proof"])
    binding = verify_jwe_key_binding(
        proof,
        expected_audience_did=publisher.device.did,
        expected_ceremony_id=publisher.ceremony_id,
        expected_group="default",
        now=proof.issued_at,
        challenge=challenge,
    )
    outbound = enrollment.load_outbound_offer(reader, binding.proof_digest)
    constructed_only = AcceptedOffer(
        binding=binding,
        offer_digest=binding.proof_digest,
        artifact_digest=outbound.artifact_digest,
    )

    with pytest.raises(TrustError) as caught:
        compile_enrolment(
            publisher,
            "default",
            reader.device.did,
            accepted_offer=constructed_only,
        )
    assert caught.value.reason is TrustReason.UNTRUSTED_PRINCIPAL

    receipt = absorb(publisher, _only_outbox_artifact(reader))
    assert receipt.offer_digest is not None
    store = EnrollmentStore(publisher, publisher.device)
    now = datetime.now(timezone.utc)
    accepted = store.reconcile(
        store.pending_offer(receipt.offer_digest, now=now),
        now=now,
    )
    response_package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    response = EnrollmentResponseV1.from_dict(
        response_package.payload["enrollment_response"]
    )
    assert response.accepted_offer_digest == accepted.offer_digest
    assert response.x25519_public_key_sha256 == accepted.binding.public_key_sha256
    assert response.reader_did == reader.device.did


def test_reader_verifies_response_against_outbound_state_before_trusting_publisher(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    original_reader_key = (reader.keystore / "default.jwe.mykey").read_bytes()
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    artifact = emit_to_outbox(publisher, package)

    receipt = absorb(reader, artifact)

    assert receipt.status == "enrolment_applied", receipt.reason
    assert (reader.keystore / "default.jwe.mykey").read_bytes() == original_reader_key
    trust_path = reader.keystore / "trust" / "verified_publishers.v1.json"
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    metadata = trust["publishers"][publisher.device.did]
    assert metadata["proof_source"] == "enrollment-response"
    assert metadata["accepted_offer_digest"] == accepted.offer_digest
    assert metadata["x25519_public_key_sha256"] == accepted.binding.public_key_sha256


def _resign_response_package(
    package,
    publisher: LoadedConfig,
    **response_changes,
):
    response = EnrollmentResponseV1.from_dict(package.payload["enrollment_response"])
    changed = replace(
        response,
        **response_changes,
        signature_b64="",
    ).sign(publisher.device)
    changed_package = replace(
        package,
        payload={
            **package.payload,
            "enrollment_response": changed._wire_value(include_signature=True),
        },
        signer_verify_pub_b64="",
        sig_b64="",
    )
    return sign(changed_package, publisher.device.signing_key())


def test_response_key_mismatch_is_rejected_before_any_reader_mutation(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    package = _resign_response_package(
        package,
        publisher,
        x25519_public_key_sha256="sha256:" + "00" * 32,
    )
    artifact = emit_to_outbox(publisher, package)

    yaml_before = reader.yaml_path.read_bytes()
    mykey_before = (reader.keystore / "default.jwe.mykey").read_bytes()
    sender_pub_path = reader.keystore / "default.jwe.sender_pub"
    trust_path = reader.keystore / "trust" / "verified_publishers.v1.json"

    receipt = absorb(reader, artifact)

    assert receipt.status == "rejected"
    assert "different X25519 key" in receipt.reason
    assert reader.yaml_path.read_bytes() == yaml_before
    assert (reader.keystore / "default.jwe.mykey").read_bytes() == mykey_before
    assert not sender_pub_path.exists()
    assert not trust_path.exists()


def test_response_outer_and_inner_signers_must_match_before_state_change(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    unrelated = load_or_create(tmp_path / "unrelated" / "tn.yaml", cipher="jwe")
    package = replace(
        package,
        device_identity=unrelated.device.did,
        signer_verify_pub_b64="",
        sig_b64="",
    )
    package = sign(package, unrelated.device.signing_key())
    artifact = emit_to_outbox(publisher, package)
    yaml_before = reader.yaml_path.read_bytes()

    receipt = absorb(reader, artifact)

    assert receipt.status == "rejected"
    assert "signer" in receipt.reason.lower()
    assert reader.yaml_path.read_bytes() == yaml_before
    assert not (reader.keystore / "trust" / "verified_publishers.v1.json").exists()


def test_response_exact_replay_is_idempotent_and_retains_no_reader_secret(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    artifact = emit_to_outbox(publisher, package)
    mykey_before = (reader.keystore / "default.jwe.mykey").read_bytes()

    first = absorb(reader, artifact)
    second = absorb(reader, artifact)

    assert first.status == "enrolment_applied"
    assert second.status == "no_op"
    assert (reader.keystore / "default.jwe.mykey").read_bytes() == mykey_before
    response_states = list(
        (enrollment_dir(reader.yaml_path) / "outbound" / "responses").glob("*.json")
    )
    assert len(response_states) == 1
    state_bytes = response_states[0].read_bytes()
    assert mykey_before not in state_bytes
    assert b"private" not in state_bytes.lower()


def test_response_install_recovers_from_a_durable_prepare_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    artifact = emit_to_outbox(publisher, package)
    trust_path = reader.keystore / "trust" / "verified_publishers.v1.json"
    original_atomic_write = enrollment.atomic_write_bytes
    failed = False

    def fail_first_trust_write(path, data):
        nonlocal failed
        if Path(path) == trust_path and not failed:
            failed = True
            raise OSError("injected trust-state write failure")
        return original_atomic_write(path, data)

    monkeypatch.setattr(enrollment, "atomic_write_bytes", fail_first_trust_write)
    interrupted = absorb(reader, artifact)
    assert interrupted.status == "rejected"
    assert "injected trust-state write failure" in interrupted.reason
    assert len(
        list(
            (
                enrollment_dir(reader.yaml_path)
                / "outbound"
                / "response-prepared"
            ).glob("*.json")
        )
    ) == 1
    assert not list(
        (enrollment_dir(reader.yaml_path) / "outbound" / "responses").glob("*.json")
    )

    monkeypatch.setattr(enrollment, "atomic_write_bytes", original_atomic_write)
    recovered = absorb(reader, artifact)

    assert recovered.status == "enrolment_applied"
    assert trust_path.exists()
    assert len(
        list(
            (enrollment_dir(reader.yaml_path) / "outbound" / "responses").glob("*.json")
        )
    ) == 1


def test_exact_prepared_response_recovers_after_statement_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
        ttl=timedelta(seconds=30),
    )
    response = EnrollmentResponseV1.from_dict(package.payload["enrollment_response"])
    sender_pub_b64 = package.payload["sender_pub_b64"]
    trust_path = reader.keystore / "trust" / "verified_publishers.v1.json"
    original_atomic_write = enrollment.atomic_write_bytes

    def fail_first_trust_write(path, data):
        if Path(path) == trust_path:
            raise OSError("injected trust-state write failure")
        return original_atomic_write(path, data)

    monkeypatch.setattr(enrollment, "atomic_write_bytes", fail_first_trust_write)
    with pytest.raises(OSError, match="injected trust-state write failure"):
        enrollment.install_enrollment_response(
            reader,
            response,
            sender_pub_b64=sender_pub_b64,
            now=response.issued_at + timedelta(seconds=1),
        )

    monkeypatch.setattr(enrollment, "atomic_write_bytes", original_atomic_write)
    recovered = enrollment.install_enrollment_response(
        reader,
        response,
        sender_pub_b64=sender_pub_b64,
        now=response.expires_at + timedelta(seconds=1),
    )

    assert recovered.applied is True
    assert trust_path.exists()


def test_expired_response_without_exact_prepare_is_still_rejected(tmp_path: Path) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
        ttl=timedelta(seconds=30),
    )
    response = EnrollmentResponseV1.from_dict(package.payload["enrollment_response"])

    with pytest.raises(TrustError) as raised:
        enrollment.install_enrollment_response(
            reader,
            response,
            sender_pub_b64=package.payload["sender_pub_b64"],
            now=response.expires_at + timedelta(seconds=1),
        )

    assert raised.value.reason is TrustReason.STATEMENT_EXPIRED
    assert not (
        enrollment_dir(reader.yaml_path) / "outbound" / "response-prepared"
    ).exists()


@pytest.mark.parametrize(
    "unsafe_group",
    [
        "../escape",
        r"..\escape",
        "/absolute",
        r"C:\absolute",
        " leading",
        "trailing ",
        ".",
        "..",
        "a/b",
        "a:b",
        "CON",
        "com1",
    ],
)
def test_offer_rejects_nonportable_group_before_key_or_state_mutation(
    tmp_path: Path,
    unsafe_group: str,
) -> None:
    publisher, reader = _homes(tmp_path)
    now = datetime.now(timezone.utc)
    challenge = enrollment.EnrollmentChallengeV1(
        version=1,
        kind="tn-enrollment-challenge",
        publisher_did=publisher.device.did,
        expected_reader_did=reader.device.did,
        ceremony_id=publisher.ceremony_id,
        group=unsafe_group,
        nonce_b64=base64.b64encode(b"n" * 32).decode("ascii"),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        challenge_id="safe-challenge-id",
        signature_b64="",
    ).sign(publisher.device)
    key_files_before = {
        path.relative_to(reader.keystore): path.read_bytes()
        for path in reader.keystore.rglob("*")
        if path.is_file()
    }

    with pytest.raises(TrustError) as raised:
        offer(
            reader,
            publisher.device.did,
            challenge=challenge,
            group=unsafe_group,
        )

    assert raised.value.reason is TrustReason.SCOPE_MISMATCH
    assert key_files_before == {
        path.relative_to(reader.keystore): path.read_bytes()
        for path in reader.keystore.rglob("*")
        if path.is_file()
    }
    assert not enrollment_dir(reader.yaml_path).exists()
    assert not outbox_dir(reader.yaml_path).exists()


def test_response_install_rejects_nonportable_group_before_filesystem_use(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    response = EnrollmentResponseV1.from_dict(package.payload["enrollment_response"])
    unsafe_response = replace(
        response,
        group="../escaped-response",
        signature_b64="",
    ).sign(publisher.device)
    yaml_before = reader.yaml_path.read_bytes()

    with pytest.raises(TrustError) as raised:
        enrollment.install_enrollment_response(
            reader,
            unsafe_response,
            sender_pub_b64=package.payload["sender_pub_b64"],
            now=response.issued_at + timedelta(seconds=1),
        )

    assert raised.value.reason is TrustReason.SCOPE_MISMATCH
    assert reader.yaml_path.read_bytes() == yaml_before
    assert not (reader.keystore.parent / "escaped-response.jwe.mykey").exists()
    assert not (reader.keystore.parent / "escaped-response.jwe.sender_pub").exists()


def _legacy_enrollment_package(
    publisher: LoadedConfig,
    *,
    recipient_did: str,
    sender_byte: bytes = b"s",
) -> Package:
    package = Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id=publisher.ceremony_id,
        group="default",
        group_epoch=publisher.groups["default"].index_epoch,
        device_identity=publisher.device.did,
        signer_verify_pub_b64="",
        recipient_identity=recipient_did,
        payload={
            "publisher_identity": publisher.device.did,
            "sender_pub_b64": base64.b64encode(sender_byte * 32).decode("ascii"),
        },
        compiled_at=datetime.now(timezone.utc).isoformat(),
    )
    return sign(package, publisher.device.signing_key())


def test_response_less_legacy_enrollment_is_rejected_by_default_without_mutation(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    artifact = emit_to_outbox(
        publisher,
        _legacy_enrollment_package(publisher, recipient_did=reader.device.did),
    )
    yaml_before = reader.yaml_path.read_bytes()

    result = absorb(reader, artifact)

    assert result.status == "rejected"
    assert "unsafe_legacy_enrollment" in result.reason
    assert reader.yaml_path.read_bytes() == yaml_before
    assert not (reader.keystore / "default.jwe.sender_pub").exists()


def test_explicit_legacy_enrollment_is_audited_and_marked_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaml

    publisher, reader = _homes(tmp_path)
    artifact = emit_to_outbox(
        publisher,
        _legacy_enrollment_package(publisher, recipient_did=reader.device.did),
    )
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        tn,
        "info",
        lambda event_type, **fields: events.append((event_type, fields)),
    )

    with pytest.warns(TnSecurityWarning) as caught:
        result = absorb(reader, artifact, unsafe_legacy_enrollment=True)

    assert result.status == "enrolment_applied"
    document = yaml.safe_load(reader.yaml_path.read_text(encoding="utf-8"))
    assert document["groups"]["default"]["verified"] is False
    notice = caught[0].message.notice
    assert [value.value for value in notice.relaxations] == ["unverified_key_binding"]
    assert events[0][0] == "tn.security.unsafe_operation"
    assert events[0][1]["relaxations"] == ["unverified_key_binding"]


def test_unsafe_legacy_enrollment_never_accepts_a_foreign_recipient(
    tmp_path: Path,
) -> None:
    publisher, reader = _homes(tmp_path)
    unrelated = load_or_create(tmp_path / "unrelated" / "tn.yaml", cipher="jwe")
    artifact = emit_to_outbox(
        publisher,
        _legacy_enrollment_package(publisher, recipient_did=unrelated.device.did),
    )
    yaml_before = reader.yaml_path.read_bytes()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = absorb(reader, artifact, unsafe_legacy_enrollment=True)

    assert result.status == "rejected"
    assert "recipient" in result.reason.lower()
    assert reader.yaml_path.read_bytes() == yaml_before
    assert caught == []


def test_legacy_enrollment_uses_one_exact_bounded_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, reader = _homes(tmp_path)
    source = emit_to_outbox(
        publisher,
        _legacy_enrollment_package(
            publisher,
            recipient_did=reader.device.did,
            sender_byte=b"a",
        ),
    )
    first_bytes = source.read_bytes()
    second_bytes = emit_to_outbox(
        publisher,
        _legacy_enrollment_package(
            publisher,
            recipient_did=reader.device.did,
            sender_byte=b"b",
        ),
    ).read_bytes()
    source.write_bytes(first_bytes)
    original_read = enrollment.read_enrollment_artifact

    def swap_after_bounded_read(path):
        retained = original_read(path)
        Path(path).write_bytes(second_bytes)
        return retained

    monkeypatch.setattr(enrollment, "read_enrollment_artifact", swap_after_bounded_read)
    monkeypatch.setattr(tn, "info", lambda *_args, **_kwargs: None)
    with pytest.warns(TnSecurityWarning) as caught:
        result = absorb(reader, source, unsafe_legacy_enrollment=True)

    assert result.status == "enrolment_applied"
    assert (reader.keystore / "default.jwe.sender_pub").read_bytes() == b"a" * 32
    assert caught[0].message.notice.artifact_digest == (
        "sha256:" + hashlib.sha256(first_bytes).hexdigest()
    )


def test_corrupted_prepared_response_cannot_redirect_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    package = compile_enrolment(
        publisher,
        "default",
        reader.device.did,
        accepted_offer=accepted,
    )
    artifact = emit_to_outbox(publisher, package)
    trust_path = reader.keystore / "trust" / "verified_publishers.v1.json"
    original_atomic_write = enrollment.atomic_write_bytes

    def fail_trust_write(path, data):
        if Path(path) == trust_path:
            raise OSError("injected trust-state write failure")
        return original_atomic_write(path, data)

    monkeypatch.setattr(enrollment, "atomic_write_bytes", fail_trust_write)
    assert absorb(reader, artifact).status == "rejected"
    prepared_path = next(
        (
            enrollment_dir(reader.yaml_path) / "outbound" / "response-prepared"
        ).glob("*.json")
    )
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    prepared["sender_pub_b64"] = base64.b64encode(b"\x99" * 32).decode("ascii")
    prepared_path.write_text(json.dumps(prepared), encoding="utf-8")
    yaml_before = reader.yaml_path.read_bytes()

    monkeypatch.setattr(enrollment, "atomic_write_bytes", original_atomic_write)
    rejected = absorb(reader, artifact)

    assert rejected.status == "rejected"
    assert "prepared response" in rejected.reason
    assert reader.yaml_path.read_bytes() == yaml_before
    assert not trust_path.exists()
