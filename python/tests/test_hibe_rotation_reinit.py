"""Regression: re-init a hibe ceremony after an identity-path rotation.

The rotation writer persists ``<group>.hibe.idpath.history`` as text; on
Windows a newline-translating write turns each "\n" into "\r\n" and the
Rust runtime (the default loader for hibe ceremonies) rejects the file
with "idpath history line 1 contains CR". The pure-Python loader tolerates
CR, so only the re-init through the Rust runtime catches it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_reinit_after_rotation_survives_rust_runtime(tmp_path: Path) -> None:
    yaml = tmp_path / "tn.yaml"
    log = tmp_path / "log.ndjson"

    tn.init(yaml, log_path=log, cipher="hibe")
    tn.info("epoch.a", body="sealed before rotation")
    tn.admin.rotate_reader_path("default", "self/epoch2")
    keystore = Path(tn.current_config().keystore)
    tn.flush_and_close()

    # The history file must be byte-identical across platforms: the Rust
    # loader rejects any line ending in CR.
    history = (keystore / "default.hibe.idpath.history").read_bytes()
    assert b"\r" not in history, f"CR leaked into idpath history: {history!r}"

    # Re-init routes the ceremony through the Rust runtime by default;
    # before the fix this raised ValueError("... contains CR") on Windows.
    tn.init(yaml, log_path=log, cipher="hibe")
    tn.info("epoch.b", body="sealed after rotation")
    tn.flush_and_close()
