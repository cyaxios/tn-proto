"""Tests for tn.watch — the async-iterable library verb and CLI.

Note: pytest-asyncio is not currently installed in this project.
The async tests below wrap asyncio.run() in sync test functions so they
run without any asyncio pytest plugin. If pytest-asyncio is added in the
future, the functions can be converted to `async def` with
`@pytest.mark.asyncio`.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

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


# ---------------------------------------------------------------------------
# Library verb: tn.watch()
# ---------------------------------------------------------------------------


def test_watch_yields_new_appends(tmp_path):
    """tn.watch() yields entries appended after the watcher starts."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)

    seen: list[str] = []

    async def reader():
        async for entry in tn.watch(poll_interval=0.05):
            seen.append(entry["event_type"])
            if len(seen) >= 2:
                break

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.info("a")
        tn.info("b")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    assert "a" in seen
    assert "b" in seen


def test_watch_since_start_replays_existing(tmp_path):
    """tn.watch(since='start') replays entries written before the watcher started."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)
    tn.info("pre.1")
    tn.info("pre.2")

    seen: list[str] = []

    async def reader():
        async for entry in tn.watch(since="start", poll_interval=0.05):
            seen.append(entry["event_type"])
            if len(seen) >= 3:
                break

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.info("post.1")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    # pre.1 and pre.2 must be replayed; post.1 may or may not be included
    # depending on timing, but the watcher breaks at 3 entries so at least
    # the pre-existing ones are present.
    assert "pre.1" in seen
    assert "pre.2" in seen


# ---------------------------------------------------------------------------
# CLI compatibility: existing --once test preserved
# ---------------------------------------------------------------------------


def test_watch_once_emits_entry_shape(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=100, order_id="A100")
    tn.flush_and_close()

    # Run `python -m tn.watch --once --since start` and parse each line.
    result = subprocess.run(
        [sys.executable, "-m", "tn.watch", str(yaml), "--once", "--since", "start"],
        cwd=str(_HERE.parent),
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
