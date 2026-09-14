
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import base64
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tn import admin
from tn.absorb import absorb
from tn.compile import compile_enrolment, compile_kit_bundle, emit_to_outbox
from tn.config import LoadedConfig, load_or_create
from tn.conventions import outbox_dir
from tn.enrollment import EnrollmentStore
from tn.offer import offer
from tn.packaging import verify
from tn.trust import AcceptedOffer


# Enrolment packages require a durably reconciled AcceptedOffer obtained through
# the real trusted-offer ceremony (a hand-built one is rejected with
# TrustReason.UNTRUSTED_PRINCIPAL). These helpers drive that ceremony end to
# end, mirroring tests/test_jwe_trusted_enrollment_e2e.py: the publisher issues
# a preauthorized challenge, the reader offers under it, the publisher absorbs
# the reader's outbox artifact and reconciles the retained offer into an
# AcceptedOffer the publisher can compile against.
def _homes(tmp_path: Path) -> tuple[LoadedConfig, LoadedConfig]:
    publisher = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    reader = load_or_create(tmp_path / "reader" / "tn.yaml", cipher="jwe")
    assert publisher.device.did != reader.device.did
    return publisher, reader


def _only_outbox_artifact(cfg: LoadedConfig) -> Path:
    artifacts = list(outbox_dir(cfg.yaml_path).glob("*.tnpkg"))
    assert len(artifacts) == 1
    return artifacts[0]


def _accepted_flow(publisher: LoadedConfig, reader: LoadedConfig) -> AcceptedOffer:
    store = EnrollmentStore(publisher, publisher.device)
    store.preauthorize(reader.device.did, "default")
    challenge = store.issue_challenge(reader.device.did, "default", timedelta(minutes=10))
    offer(reader, publisher.device.did, challenge=challenge)
    receipt = absorb(publisher, _only_outbox_artifact(reader))
    assert receipt.offer_digest is not None
    now = datetime.now(timezone.utc)
    return store.reconcile(store.pending_offer(receipt.offer_digest, now=now), now=now)


def test_compile_enrolment_produces_signed_package(tmp_path: Path):
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    pkg = compile_enrolment(
        publisher, "default", reader.device.did, accepted_offer=accepted
    )
    assert pkg.package_kind == "enrolment"
    assert pkg.recipient_identity == reader.device.did
    assert pkg.ceremony_id == publisher.ceremony_id
    assert "sender_pub_b64" in pkg.payload
    assert len(base64.b64decode(pkg.payload["sender_pub_b64"])) == 32
    assert verify(pkg) is True


def test_emit_to_outbox_writes_file(tmp_path: Path):
    publisher, reader = _homes(tmp_path)
    accepted = _accepted_flow(publisher, reader)
    pkg = compile_enrolment(
        publisher, "default", reader.device.did, accepted_offer=accepted
    )
    path = emit_to_outbox(publisher, pkg)
    assert path.exists()
    assert path.parent == outbox_dir(publisher.yaml_path)
    assert path.suffix == ".tnpkg"


def test_compile_enrolment_rejects_btn_group(tmp_path: Path):
    publisher, reader = _homes(tmp_path)
    admin.ensure_group(publisher, "press", cipher=_workflow_cipher("btn"))
    # A valid AcceptedOffer for the default JWE group is still required to
    # satisfy the keyword-only argument, but the btn/JWE-only guard fires
    # first — before the offer is reverified — so compiling against the btn
    # group raises the pointed RuntimeError.
    accepted = _accepted_flow(publisher, reader)
    with pytest.raises(RuntimeError) as e:
        compile_enrolment(
            publisher, "press", reader.device.did, accepted_offer=accepted
        )
    msg = str(e.value)
    assert "press" in msg
    assert "jwe" in msg.lower()


def _bootstrap_btn_keystore(tmp_path: Path) -> Path:
    """Init a btn ceremony so the keystore has a `*.btn.mykit` for
    compile_kit_bundle to bundle. Returns the keystore directory.
    """
    import tn

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.flush_and_close()
    cfg = load_or_create(yaml)
    return cfg.keystore


def test_compile_kit_bundle_full_requires_secret_acknowledgment(tmp_path: Path):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    with pytest.raises(ValueError) as exc:
        compile_kit_bundle(keystore, out_path=out, full=True)
    msg = str(exc.value)
    assert "private keys" in msg.lower()
    # Without confirm the archive must NOT have been written.
    assert not out.exists()


def test_compile_kit_bundle_full_with_ack_writes_warning_marker(tmp_path: Path):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    # The keystore now lives under .tn/<stem>/keys/, so pass yaml_path so
    # compile_kit_bundle can sign the manifest using the ceremony's device key.
    path = compile_kit_bundle(
        keystore,
        out_path=out,
        full=True,
        confirm_includes_secrets=True,
        yaml_path=tmp_path / "tn.yaml",
    )
    assert path.exists()
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        # The new universal `.tnpkg` wrapper places body files under body/.
        assert "body/WARNING_CONTAINS_PRIVATE_KEYS" in names
        # Marker is zero-byte by contract.
        assert zf.read("body/WARNING_CONTAINS_PRIVATE_KEYS") == b""


def test_compile_kit_bundle_readers_only_skips_secret_marker(tmp_path: Path):
    """full=False is the safe path; no marker, no acknowledgment needed."""
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    # See sibling test for why yaml_path is now required.
    path = compile_kit_bundle(
        keystore, out_path=out, full=False, yaml_path=tmp_path / "tn.yaml",
    )
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert "WARNING_CONTAINS_PRIVATE_KEYS" not in names
        assert "body/WARNING_CONTAINS_PRIVATE_KEYS" not in names


@pytest.mark.parametrize("option", ["label", "note"])
def test_compile_rejects_unused_metadata_before_writing(tmp_path: Path, option: str):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        compile_kit_bundle(
            keystore, out_path=out, yaml_path=tmp_path / "tn.yaml",
            **{option: "metadata"},
        )
    assert not out.exists()
