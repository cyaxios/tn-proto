"""A failed Rust-runtime rebuild after a key/path rotation must not be
swallowed: the runtime would keep sealing under the PRE-rotation identity
path, so a grantee the rotation was meant to cut off could still open
post-rotation entries.

Posture: the explicit admin rotation verbs (``rotate_reader_path``,
``revoke_reader``, btn ``rotate``) and the explicit rebind helper
``tn.logger.reload_from_yaml`` raise when the native reload fails.
Ambient paths (``ensure_group``'s internal reload) still contain the
error — the SDK never throws an exception the user didn't ask for.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
import tn.reader


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


class _FailingReloadNative:
    """Proxy over the real native runtime whose group-cipher reload always
    fails, standing in for any future on-disk/keystore parse error (the
    original incident: ValueError "idpath history line 1 contains CR")."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        if name == "reload_group_cipher":
            def _boom(group):
                raise ValueError("simulated: idpath history unreadable")

            return _boom
        return getattr(self._real, name)


def test_rotate_reader_path_raises_when_native_reload_fails(
    tmp_path: Path,
) -> None:
    """The rotation call itself must surface a failed native rebuild —
    the caller must never walk away believing the rotation is live while
    the runtime keeps sealing under the old path."""
    a_yaml = tmp_path / "authority" / "tn.yaml"
    a_log = tmp_path / "authority" / "log.ndjson"

    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("epoch.a", body="sealed before rotation")
    kit = tmp_path / "reader.tnpkg"
    tn.admin.grant_reader("default", reader_did="did:key:z6Mk-r", out_path=kit)

    rt = tn._dispatch_rt
    assert rt is not None and rt.using_rust
    real_native = rt._rt
    rt._rt = _FailingReloadNative(real_native)
    try:
        with pytest.raises(RuntimeError, match="rotat"):
            tn.admin.rotate_reader_path("default", "policy-b")
    finally:
        rt._rt = real_native

    # Documented recovery: re-init from disk (which holds the rotated
    # path). Post-recovery seals must land on the NEW path.
    tn.flush_and_close()
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("epoch.b", body="sealed after rotation")
    tn.flush_and_close()

    # A reader holding only the PRE-rotation grant must not open the
    # post-rotation entry. Before the fix, the swallowed reload failure
    # let the stale runtime seal epoch.b under the old path — readable
    # by exactly the grantee the rotation was meant to cut off.
    r_yaml = tmp_path / "reader" / "tn.yaml"
    tn.init(r_yaml, log_path=tmp_path / "reader" / "log.ndjson")
    r_cfg = tn.current_config()
    tn.absorb(kit)
    entries = {
        e["envelope"]["event_type"]: e
        for e in tn.reader.read_as_recipient(a_log, r_cfg.keystore, group="default")
    }
    assert entries["epoch.a"]["plaintext"]["default"]["body"] == (
        "sealed before rotation"
    )
    assert entries["epoch.b"]["plaintext"]["default"] == {"$no_read_key": True}, (
        entries["epoch.b"]["plaintext"]["default"]
    )


def test_reload_from_yaml_raises_when_rust_reload_fails(tmp_path: Path) -> None:
    """tn.logger.reload_from_yaml is an explicit rebind call: a failed
    Rust reload must raise, not warn-and-continue on the stale runtime."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, log_path=tmp_path / "log.ndjson")
    rt = tn._dispatch_rt
    assert rt is not None

    def _boom():
        raise ValueError("simulated reload failure")

    rt.reload = _boom
    with pytest.raises(RuntimeError, match="stale"):
        tn.logger.reload_from_yaml()


def test_ensure_group_contains_reload_failure(tmp_path: Path) -> None:
    """Ambient containment law: ensure_group's internal reload failure
    must NOT propagate into the caller — the group is on disk and the
    next init recovers."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, log_path=tmp_path / "log.ndjson")
    cfg = tn.current_config()
    rt = tn._dispatch_rt
    assert rt is not None

    def _boom():
        raise ValueError("simulated reload failure")

    rt.reload = _boom
    tn.ensure_group(cfg, "finance", fields=["amount"])  # must not raise
