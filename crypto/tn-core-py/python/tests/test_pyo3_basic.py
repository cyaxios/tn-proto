"""PyO3 basic smoke test — init, emit, read via tn_core._core.Runtime."""
from __future__ import annotations

import pathlib
import sys

import pytest  # type: ignore[import-not-found]  # test-only dep, available via venv

# Make the repo's Python tn package available (for ceremony setup).
# File: tn-protocol/crypto/tn-core-py/python/tests/test_pyo3_basic.py
#   parents[0] = .../python/tests
#   parents[1] = .../python
#   parents[2] = .../tn-core-py
#   parents[3] = .../crypto
#   parents[4] = .../tn-protocol
#   parents[5] = content_platform (repo root)
REPO = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / "tn-protocol" / "python"))

from tn_core import Runtime  # type: ignore[import-not-found]  # PyO3 extension, maturin-built


@pytest.fixture
def btn_ceremony(tmp_path):
    import tn  # type: ignore[import-not-found]  # added to sys.path above
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    return yaml


def test_init_emit_read(btn_ceremony):
    rt = Runtime.init(str(btn_ceremony))
    assert rt.did().startswith("did:key:z")

    receipt = rt.emit("info", "order.created", {"amount": 100, "note": "hello"})
    assert receipt["sequence"] == 1
    assert receipt["row_hash"].startswith("sha256:")

    entries = rt.read()
    assert len(entries) == 1
    env = entries[0]["envelope"]
    assert env["event_type"] == "order.created"
    assert entries[0]["plaintext"]["default"]["amount"] == 100
    assert entries[0]["plaintext"]["default"]["note"] == "hello"
