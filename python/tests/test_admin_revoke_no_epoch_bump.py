
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import os
from pathlib import Path

from tn import admin
from tn.config import load_or_create


def test_revoke_does_not_bump_index_epoch(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob", os.urandom(32))
    epoch_before = cfg.groups["default"].index_epoch
    admin._revoke_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")
    assert cfg.groups["default"].index_epoch == epoch_before


def test_revoke_on_btn_group_raises(tmp_path: Path):
    """Per-group cipher dispatch: admin.revoke_recipient is JWE-only;
    btn groups must use tn.admin_revoke_recipient instead."""
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher=_workflow_cipher("jwe"))
    admin.ensure_group(cfg, "press", cipher=_workflow_cipher("btn"))
    import pytest

    with pytest.raises(RuntimeError) as e:
        admin._revoke_recipient_jwe_impl(cfg, "press", "did:key:z6MkBob")
    msg = str(e.value)
    assert "press" in msg
    assert "btn" in msg.lower()
