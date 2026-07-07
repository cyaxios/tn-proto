
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


def test_add_recipient_with_pub_auto_emits_enrolment(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob", os.urandom(32))
    pkgs = list(outbox_dir(tmp_path).glob("*.tnpkg"))
    assert any("enrolment" in p.name for p in pkgs), (
        f"add_recipient with pub should auto-emit enrolment; outbox={pkgs}"
    )


def test_add_recipient_without_pub_does_not_emit(tmp_path: Path):
    """Pending state doesn't have enough info to compile — no package yet."""
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")  # pending
    pkgs = list(outbox_dir(tmp_path).glob("*.tnpkg"))
    assert not any("enrolment" in p.name for p in pkgs), (
        f"pending add_recipient must not emit enrolment; outbox={pkgs}"
    )
