"""tn.init(link=False) produces an unlinked (offline) ceremony.

Covers DX review #5: previously the ``link=`` kwarg was accepted at
the function signature but only controlled the post-init auto-link
prompt. The freshly-minted yaml always had ``mode: linked`` and a
hard-coded ``linked_vault`` URL, with no init-time way to produce an
air-gapped offline ceremony.

Fix threads ``link`` from ``tn.init`` -> ``_ensure_ceremony_on_disk``
-> ``_create_default_ceremony`` -> ``config.create_fresh``. When
``link=False``, the yaml carries ``mode: local`` and an empty
``linked_vault``.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import yaml as pyyaml


SCRIPT_TEMPLATE = textwrap.dedent("""
    import os
    os.environ["TN_NO_STDOUT"] = "1"
    import tn
    tn.init({init_kwargs})
    tn.flush_and_close()
""").strip()


def _run_init(tmp_path: Path, init_kwargs: str) -> Path:
    """Subprocess-isolated init; returns the path to the resulting yaml."""
    script = tmp_path / "init.py"
    script.write_text(SCRIPT_TEMPLATE.format(init_kwargs=init_kwargs))
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"init({init_kwargs}) failed: stdout={rc.stdout!r} "
        f"stderr={rc.stderr!r}"
    )
    return tmp_path / ".tn" / tmp_path.name / "tn.yaml"


def test_link_false_produces_local_mode(tmp_path: Path):
    yaml_path = _run_init(tmp_path, "link=False")
    doc = pyyaml.safe_load(yaml_path.read_text())
    cer = doc["ceremony"]
    assert cer["mode"] == "local", (
        f"link=False should produce mode=local, got mode={cer['mode']!r}"
    )
    assert cer["linked_vault"] == "", (
        f"link=False should empty linked_vault, got "
        f"{cer['linked_vault']!r}"
    )
    assert doc["vault"]["enabled"] is False
    assert doc["vault"]["url"] == ""
    assert doc["vault"]["autosync"] is False
    assert doc["vault"]["sync_interval_seconds"] == 600


def test_link_true_keeps_linked_mode(tmp_path: Path):
    yaml_path = _run_init(tmp_path, "link=True")
    doc = pyyaml.safe_load(yaml_path.read_text())
    cer = doc["ceremony"]
    assert cer["mode"] == "linked"
    assert cer["linked_vault"]  # non-empty URL
    assert doc["vault"]["enabled"] is True
    assert doc["vault"]["url"] == cer["linked_vault"]
    assert doc["vault"]["autosync"] is True


def test_link_omitted_defaults_to_linked(tmp_path: Path):
    """Backwards-compat: bare tn.init() preserves linked default."""
    yaml_path = _run_init(tmp_path, "")
    doc = pyyaml.safe_load(yaml_path.read_text())
    cer = doc["ceremony"]
    assert cer["mode"] == "linked"
    assert cer["linked_vault"]


def test_link_false_then_load_works(tmp_path: Path):
    """Unlinked ceremonies must be loadable end-to-end — emit and read
    without ever hitting the vault."""
    _run_init(tmp_path, "link=False")
    script = tmp_path / "use.py"
    script.write_text(textwrap.dedent("""
        import os, json
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()  # picks up the existing unlinked yaml
        tn.info("offline.evt", marker="ok")
        tn.flush_and_close()
        evts = [e.event_type for e in tn.read()]
        print(json.dumps({"events": evts}))
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr
    payload = pyyaml.safe_load(rc.stdout.decode().strip().splitlines()[-1])
    assert "offline.evt" in payload["events"]
