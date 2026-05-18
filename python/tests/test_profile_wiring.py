"""Profile= kwarg drives ceremony behaviour, not just metadata.

Covers DX review #4 (partial fix): the profile catalog's ``signs``
boolean now lands in ``ceremony.sign`` on yaml, which the Rust
runtime honours by emitting empty signatures for ``telemetry`` /
``stdout`` profiles. ``chains`` / ``flush`` / ``default_sink`` are
not yet driven by profile in the default-ceremony path — that
requires Rust runtime work and is tracked separately.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml as pyyaml

from tn import _profiles


SCRIPT_TEMPLATE = textwrap.dedent("""
    import os, json, pathlib
    os.environ["TN_NO_STDOUT"] = "1"
    import tn
    tn.init(profile={profile!r})
    tn.info("evt.test", x=1)
    tn.flush_and_close()
    log = pathlib.Path("./.tn/default/logs/tn.ndjson")
    last_line = log.read_text().splitlines()[-1]
    last = json.loads(last_line)
    sig = last.get("signature")
    print(json.dumps({{
        "signature_value": sig,
        "signature_present": bool(sig),
    }}))
""").strip()


def _run_profile_init(tmp_path: Path, profile: str) -> dict:
    """Init a fresh ceremony with `profile` in a subprocess; emit one
    entry; return the on-disk signature info. Subprocess isolation
    matters because tn's module-level singleton binds at first init.
    """
    script = tmp_path / "init.py"
    script.write_text(SCRIPT_TEMPLATE.format(profile=profile))
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"init({profile!r}) subprocess failed: stdout={rc.stdout!r} "
        f"stderr={rc.stderr!r}"
    )
    payload = json.loads(rc.stdout.decode().strip().splitlines()[-1])
    return payload


def _yaml_sign_value(tmp_path: Path) -> bool:
    """Return ceremony.sign from the on-disk yaml."""
    doc = pyyaml.safe_load(
        (tmp_path / ".tn" / "default" / "tn.yaml").read_text()
    )
    return doc["ceremony"]["sign"]


@pytest.mark.parametrize("profile", list(_profiles.all_profile_names()))
def test_profile_drives_yaml_sign(tmp_path: Path, profile: str):
    """Yaml ceremony.sign mirrors the profile catalog's `signs` bit."""
    p = _profiles.get(profile)
    sub = tmp_path / profile
    sub.mkdir()
    _run_profile_init(sub, profile)
    assert _yaml_sign_value(sub) is p.signs, (
        f"profile={profile} expected ceremony.sign={p.signs} "
        f"but yaml has {_yaml_sign_value(sub)!r}"
    )


@pytest.mark.parametrize("profile", list(_profiles.all_profile_names()))
def test_profile_drives_emit_signature(tmp_path: Path, profile: str):
    """Profiles with signs=False produce entries with empty signature."""
    p = _profiles.get(profile)
    sub = tmp_path / profile
    sub.mkdir()
    payload = _run_profile_init(sub, profile)
    if p.signs:
        assert payload["signature_present"], (
            f"profile={profile} signs=True but on-disk signature is "
            f"empty: {payload!r}"
        )
    else:
        assert not payload["signature_present"], (
            f"profile={profile} signs=False but on-disk signature is "
            f"present: {payload!r}"
        )


def test_default_profile_signs(tmp_path: Path):
    """Sanity baseline: when no profile kwarg is passed, the default
    is `transaction`, which signs."""
    script = tmp_path / "init.py"
    script.write_text(textwrap.dedent("""
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()  # no profile kwarg
        tn.info("evt", x=1); tn.flush_and_close()
        log = pathlib.Path("./.tn/default/logs/tn.ndjson")
        last = json.loads(log.read_text().splitlines()[-1])
        print(json.dumps({"signature_present": bool(last.get("signature"))}))
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr
    payload = json.loads(rc.stdout.decode().strip().splitlines()[-1])
    assert payload["signature_present"]
