"""tn.watch produces Entry-shaped JSON, not crypto internals."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_watch_once_emits_entry_shape(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=100, order_id="A100")
    tn.flush_and_close()

    # Run `python -m tn.watch --once` and parse each line.
    result = subprocess.run(
        [sys.executable, "-m", "tn.watch", str(yaml), "--once"],
        cwd=str(_HERE.parent),  # run from tn-protocol/python
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    assert lines, f"no output from tn.watch: stderr={result.stderr}"

    # Find the order.created line (ceremony.init may also appear; that's OK).
    order_lines = [l for l in lines if '"order.created"' in l]
    assert order_lines, f"no order.created in output: {lines!r}"

    parsed = json.loads(order_lines[0])
    # Shape: Entry keys present.
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "event_type" in parsed
    assert "fields" in parsed
    assert "valid" in parsed
    assert parsed["event_type"] == "order.created"
    assert parsed["fields"]["amount"] == 100
    assert parsed["fields"]["order_id"] == "A100"
    # No crypto internals.
    line_blob = json.dumps(parsed)
    assert "ciphertext" not in line_blob
    assert "signature" not in parsed
    assert "row_hash" not in parsed
    assert "prev_hash" not in parsed
