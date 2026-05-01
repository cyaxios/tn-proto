"""Verify btn ceremonies route through Rust; JWE/BGW fall back to Python."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


def test_btn_ceremony_uses_rust(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("x.test", k=1)
    assert tn.using_rust() is True
    tn.flush_and_close()


def test_jwe_ceremony_uses_python(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")
    tn.info("x.test", k=1)
    assert tn.using_rust() is False
    tn.flush_and_close()


def test_tn_force_python_env_var_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("x.test", k=1)
    assert tn.using_rust() is False
    tn.flush_and_close()


def test_btn_ceremony_with_explicit_log_path_keeps_rust(tmp_path):
    """Regression: ``tn.init(yaml, log_path=...)`` used to synthesize a
    handler that wasn't flagged ``_tn_default``, and DispatchRuntime then
    treated it as a "user handler" and disabled the Rust runtime —
    breaking ``admin_add_recipient`` on btn ceremonies. The fix flags
    every handler in the back-compat synthesized list as default so the
    Rust path stays live.
    """
    yaml = tmp_path / "tn.yaml"
    log_path = tmp_path / "logs" / "tn.ndjson"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tn.init(yaml, log_path=str(log_path), cipher="btn")
    tn.flush_and_close()
    # Re-init now that yaml exists, with the same explicit log_path. This
    # is the call shape tnproto-org/src/allocate_worker.py uses against a
    # publisher's pre-minted ceremony.
    tn.init(yaml, log_path=str(log_path), cipher="btn")
    try:
        assert tn.using_rust() is True
        # admin_add_recipient requires Rust dispatch — minting it under
        # this init shape proves the runtime is fully functional, not just
        # that ``using_rust`` returns True.
        kit_path = tmp_path / "out.btn.mykit"
        leaf = tn.admin.add_recipient("default", recipient_did=tn.current_config().device.did, out_path=str(kit_path)).leaf_index
        assert isinstance(leaf, int)
        assert kit_path.exists() and kit_path.stat().st_size > 0
    finally:
        tn.flush_and_close()
