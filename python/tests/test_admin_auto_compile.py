
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import os
from pathlib import Path

from tn import admin
from tn.config import load_or_create
from tn.conventions import outbox_dir


def test_add_recipient_with_pub_wires_recipient_but_emits_no_enrolment(tmp_path: Path):
    """Publisher-direct add wires the recipient's key but emits NO enrolment
    package. Post trusted-enrollment refactor an enrolment package is a
    publisher-signed response to a reader's *proven* offer (offer -> absorb ->
    reconcile); a caller-supplied bare pubkey carries no such proof, so nothing
    is compiled here. The recipient is still registered and can be encrypted to;
    a proof-backed enrolment is produced later, from the reader-driven flow."""
    import yaml as _yaml

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob", os.urandom(32))

    # The recipient is wired into the group (the publisher can encrypt to it)...
    doc = _yaml.safe_load((tmp_path / "tn.yaml").read_text(encoding="utf-8"))
    recips = [r["recipient_identity"] for r in doc["groups"]["default"]["recipients"]]
    assert "did:key:z6MkBob" in recips

    # ...but no enrolment package is auto-emitted (it comes from the offer flow).
    pkgs = list(outbox_dir(tmp_path).glob("*.tnpkg"))
    assert not any("enrolment" in p.name for p in pkgs), (
        f"publisher-direct add must not emit an enrolment package; outbox={pkgs}"
    )


def test_add_recipient_without_pub_does_not_emit(tmp_path: Path):
    """Pending state doesn't have enough info to compile — no package yet."""
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")  # pending
    pkgs = list(outbox_dir(tmp_path).glob("*.tnpkg"))
    assert not any("enrolment" in p.name for p in pkgs), (
        f"pending add_recipient must not emit enrolment; outbox={pkgs}"
    )
