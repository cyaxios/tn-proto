"""tn.admin.ensure_group must rebind the live runtime so the new
group is visible to subsequent emits in the same process.

Covers DX review #8: prior to 0.4.2a2, ``ensure_group`` correctly
wrote the new group to disk and updated the in-memory ``cfg`` /
``field_to_groups``, but the Rust dispatch runtime kept its
init-time view. The next ``tn.info("e", new_field=...)`` routed
through ``default`` only; only a ``flush_and_close() + tn.init()``
round-trip surfaced the new group.

Fix: ``ensure_group`` calls ``tn.logger.reload_from_yaml()`` after
the on-disk write, which re-reads the yaml into the active
TNRuntime's ``cfg`` and re-inits the Rust dispatch runtime against
the updated yaml. Subsequent emits in the same process now route
through the new group.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path


def _run(tmp_path: Path, body: str, name: str = "case.py") -> str:
    script = tmp_path / name
    # Force UTF-8 so non-ASCII chars in test bodies survive the
    # Windows default cp1252 write encoding.
    script.write_text(body, encoding="utf-8")
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"subprocess failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    lines = rc.stdout.decode().strip().splitlines()
    return lines[-1] if lines else ""


def test_ensure_group_makes_new_routing_visible_same_process(tmp_path: Path):
    """In one process: init, ensure_group("finance", fields=["amount"]),
    info(..., amount=...). The on-disk entry MUST contain the
    finance group's payload."""
    body = textwrap.dedent('''
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn

        tn.init()
        cfg = tn.current_config()
        tn.ensure_group(cfg, "finance", fields=["amount", "currency"])
        tn.info("order.created", amount=4999, currency="USD", notes="x")
        tn.flush_and_close()

        last = json.loads(
            pathlib.Path("./.tn/default/logs/tn.ndjson")
                .read_text().splitlines()[-1]
        )
        groups = [
            k for k in last
            if isinstance(last[k], dict) and "ciphertext" in last[k]
        ]
        print(json.dumps({"groups": sorted(groups)}))
    ''').strip()
    payload = json.loads(_run(tmp_path, body))
    assert "finance" in payload["groups"], (
        f"finance group missing from in-process emit after "
        f"ensure_group; got {payload['groups']!r}. The runtime did "
        f"not hot-reload."
    )
    assert "default" in payload["groups"], (
        f"default group missing — unrelated regression"
    )


def test_ensure_group_persists_across_process_boundary(tmp_path: Path):
    """Sanity: the previously-working cross-process case still works.
    Process A ensures the group; process B's tn.init picks it up
    from yaml; B's emit routes through finance."""
    proc_a = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.ensure_group(tn.current_config(), "finance", fields=["amount"])
        tn.flush_and_close()
    ''').strip()
    _run(tmp_path, proc_a, name="proc_a.py")

    proc_b = textwrap.dedent('''
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.info("order.created", amount=4999)
        tn.flush_and_close()
        last = json.loads(
            pathlib.Path("./.tn/default/logs/tn.ndjson")
                .read_text().splitlines()[-1]
        )
        groups = [
            k for k in last
            if isinstance(last[k], dict) and "ciphertext" in last[k]
        ]
        print(json.dumps({"groups": sorted(groups)}))
    ''').strip()
    payload = json.loads(_run(tmp_path, proc_b, name="proc_b.py"))
    assert "finance" in payload["groups"]


def test_ensure_group_idempotent_second_call(tmp_path: Path):
    """Calling ensure_group twice with the same args must be a no-op
    on the second call (the existing behaviour, pinned)."""
    body = textwrap.dedent('''
        import os, json
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        cfg = tn.current_config()
        tn.ensure_group(cfg, "ops", fields=["operator"])
        # Second call — must NOT raise, must NOT duplicate routing.
        tn.ensure_group(cfg, "ops", fields=["operator"])
        tn.info("e", operator="alice")
        tn.flush_and_close()
        print(json.dumps({
            "operator_groups": cfg.field_to_groups.get("operator", []),
        }))
    ''').strip()
    payload = json.loads(_run(tmp_path, body))
    assert payload["operator_groups"] == ["ops"], (
        f"operator field routing diverged: {payload!r}"
    )
