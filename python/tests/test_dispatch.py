"""Verify whole-runtime BTN routing and Python-managed JWE dispatch."""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
from tn import _dispatch


def test_btn_ceremony_uses_rust(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("x.test", k=1)
    assert tn.using_rust() is True
    tn.flush_and_close()


def test_jwe_ceremony_uses_python(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("jwe"))
    tn.info("x.test", k=1)
    assert tn.using_rust() is False
    tn.flush_and_close()


def test_tn_force_python_env_var_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("x.test", k=1)
    assert tn.using_rust() is False
    tn.flush_and_close()


def test_python_fallback_emits_deprecation_warning(tmp_path, monkeypatch):
    """When tn_core is unavailable, should_use_rust() must emit a
    DeprecationWarning to nudge users off the soon-to-be-removed
    pure-Python fallback.
    """
    monkeypatch.setattr(_dispatch, "_RUST_OK", False)
    yaml = tmp_path / "tn.yaml"
    yaml.write_text("groups: {default: {cipher: btn}}\n", encoding="utf-8")
    with pytest.warns(DeprecationWarning, match="pure-Python runtime"):
        assert _dispatch.should_use_rust(yaml) is False


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
    tn.init(yaml, log_path=str(log_path), cipher=_workflow_cipher("btn"))
    tn.flush_and_close()
    # Re-init now that yaml exists, with the same explicit log_path. This
    # is the call shape tnproto-org/src/allocate_worker.py uses against a
    # publisher's pre-minted ceremony.
    tn.init(yaml, log_path=str(log_path), cipher=_workflow_cipher("btn"))
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


def test_close_drains_python_handlers_on_rust_path():
    """On the btn+rust path, close() must flush+close the PYTHON runtime too.

    The Rust runtime owns the log, but the user's Python handlers (S3, Delta,
    kafka, firehose) live on self._py_rt and receive entries via the fan-out.
    Closing only the Rust runtime left those handlers un-drained, silently
    dropping their buffered batches despite the documented flush_and_close
    drain contract.
    """
    from tn._dispatch import DispatchRuntime

    class _SpyPy:
        def __init__(self) -> None:
            self.closed = False

        def flush_and_close(self, *, timeout: float = 30.0) -> None:
            self.closed = True

    class _SpyRust:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    rt = DispatchRuntime.__new__(DispatchRuntime)
    rt._use_rust = True
    rt._rt = _SpyRust()
    rt._py_rt = _SpyPy()

    rt.close()

    assert rt._py_rt.closed, "Python handlers were not drained on the rust path"
    assert rt._rt.closed, "Rust runtime was not closed"
