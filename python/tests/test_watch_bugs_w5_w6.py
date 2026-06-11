"""Regression tests for the W5 + W6 follow-up bugs filed against
0.4.2a4. Ship in 0.4.2a5.

- W5: ``tn.watch()`` from a no-ceremony directory was silent (or
  raised a less-helpful "no active runtime") while ``tn.read()``
  raised the friendly "no ceremony found. Looked at $TN_YAML..."
  message. Now both verbs share the same autoinit path.

- W6: ``tn.watch(log='admin', since='start')`` yielded only the
  subset of admin entries whose envelopes carried a ``run_id``.
  Admin events emitted by runtime verbs (``ensure_group``, etc.)
  legitimately lack ``run_id``, and ``Entry.from_raw`` (the
  read-path constructor) already handled that by defaulting to
  ``""``. ``Entry.from_flat`` (the watch-path constructor) was
  stricter and rejected those rows. Now both constructors share
  the same leniency.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# --------------------------------------------------------------------
# W5 — tn.watch from no-ceremony dir surfaces the same error as
# tn.read.
# --------------------------------------------------------------------


def _run(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    script = tmp_path / "case.py"
    script.write_text(body, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )


def test_watch_no_ceremony_raises_helpful_error(tmp_path: Path):
    body = textwrap.dedent('''
        import os, asyncio
        os.environ["TN_NO_STDOUT"] = "1"
        import tn

        async def main():
            async for _ in tn.watch(poll_interval=0.05):
                pass
        try:
            asyncio.run(asyncio.wait_for(main(), timeout=0.5))
            print("YIELDED_OR_TIMEOUT")
        except RuntimeError as exc:
            print("RUNTIMEERROR: " + str(exc))
        except Exception as exc:
            print("OTHER: " + type(exc).__name__ + ": " + str(exc))
    ''').strip()
    rc = _run(tmp_path, body)
    assert rc.returncode == 0, rc.stderr
    out = rc.stdout.decode().strip()
    assert "RUNTIMEERROR:" in out, out
    assert "no ceremony found" in out
    assert "tn.init()" in out


def test_read_no_ceremony_raises_helpful_error(tmp_path: Path):
    """Companion: ``tn.read`` raises the same error. Pinned so the
    two surfaces don't drift."""
    body = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn

        try:
            list(tn.read())
            print("YIELDED")
        except RuntimeError as exc:
            print("RUNTIMEERROR: " + str(exc))
    ''').strip()
    rc = _run(tmp_path, body)
    assert rc.returncode == 0, rc.stderr
    out = rc.stdout.decode().strip()
    assert "RUNTIMEERROR:" in out, out
    assert "no ceremony found" in out


# --------------------------------------------------------------------
# W6 — tn.watch(log='admin') yields all admin entries, including the
# ones emitted by runtime verbs that lack a run_id.
# --------------------------------------------------------------------


def test_watch_admin_yields_all_entries_including_runid_less(tmp_path: Path):
    """Reproduces the exact W6 scenario:
      - first ``tn.init()`` writes 3 admin events with ``run_id``
      - three ``ensure_group`` calls write 3 admin events WITHOUT
        ``run_id`` (they're emitted by the runtime verb, not in a
        run context)
      - ``tn.watch(log='admin', since='start')`` must yield all 6,
        matching what ``tn.read(log='admin')`` yields.
    """
    body = textwrap.dedent('''
        import os, json, asyncio, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn

        tn.init()
        tn.flush_and_close()
        tn.init()
        cfg = tn.current_config()
        tn.ensure_group(cfg, "finance", fields=["amount"])
        tn.ensure_group(cfg, "audit", fields=["actor"])
        tn.ensure_group(cfg, "ops", fields=["operator"])
        tn.flush_and_close()

        project = pathlib.Path.cwd().name
        admin = pathlib.Path("./.tn") / project / "admin" / "default.ndjson"
        on_disk = len(admin.read_text().splitlines())

        tn.init()
        read_events = [e.event_type for e in tn.read(log="admin")]

        async def main():
            out = []
            async def run():
                async for e in tn.watch(log="admin", since="start", poll_interval=0.05):
                    out.append(e.event_type)
            try:
                await asyncio.wait_for(run(), timeout=1.5)
            except asyncio.TimeoutError:
                pass
            return out
        watch_events = asyncio.run(main())

        print(json.dumps({
            "on_disk": on_disk,
            "read_count": len(read_events),
            "watch_count": len(watch_events),
            "watch_events": watch_events,
        }))
    ''').strip()
    rc = _run(tmp_path, body)
    assert rc.returncode == 0, rc.stderr
    import json
    payload = json.loads(rc.stdout.decode().strip().splitlines()[-1])
    assert payload["on_disk"] == 6, payload
    assert payload["read_count"] == 6, payload
    assert payload["watch_count"] == 6, (
        f"W6 regression — watch yielded only {payload['watch_count']} of "
        f"{payload['on_disk']} admin entries: {payload!r}"
    )


def test_entry_from_flat_tolerates_missing_run_id():
    """Direct unit test on the constructor leniency. ``run_id`` is
    optional; the constructor defaults it to ``""`` (matching
    ``Entry.from_raw``)."""
    from tn._entry import Entry

    flat = {
        "event_type": "tn.group.added",
        # Wire-format key is `device_identity` post-0.4.3a1; `from_flat`
        # translates it to the `did` dataclass attribute for back-compat.
        "device_identity": "did:key:zTest",
        "event_id": "00000000-0000-0000-0000-000000000001",
        "sequence": 1,
        "timestamp": "2026-05-19T01:00:00.000Z",
        "level": "info",
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": "sha256:" + "a" * 64,
        "signature": "",
        # NOTE: deliberately no run_id
    }
    entry = Entry.from_flat(flat)
    assert entry.run_id == "", (
        f"expected run_id='' for runid-less envelope, got {entry.run_id!r}"
    )
    assert entry.event_type == "tn.group.added"


def test_entry_from_flat_still_requires_real_envelope_fields():
    """Don't loosen *everything* — make sure other required envelope
    fields still raise on absence. This pins the boundary of the
    leniency change so a future refactor doesn't accidentally drop
    the other required fields."""
    from tn._entry import Entry

    bare = {"event_type": "tn.group.added", "timestamp": "2026-05-19T01:00:00.000Z"}
    with pytest.raises(ValueError, match=r"required envelope field"):
        Entry.from_flat(bare)
