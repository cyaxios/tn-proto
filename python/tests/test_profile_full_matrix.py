"""Check each profile's signing, chaining, and output configuration."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tn import _profiles


# --------------------------------------------------------------------
# Catalog ground-truth — read directly from the source-of-truth
# module so any future catalog change ripples through the matrix.
# --------------------------------------------------------------------
PROFILE_NAMES = list(_profiles.all_profile_names())
CATALOG = {name: _profiles.get(name) for name in PROFILE_NAMES}


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def _run_subprocess(tmp_path: Path, body: str) -> dict:
    """Run a script with the given body in tmp_path; return the JSON
    payload printed on the last line."""
    script = tmp_path / "case.py"
    script.write_text(body, encoding="utf-8")
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"case.py failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    lines = rc.stdout.decode().strip().splitlines()
    assert lines, f"no stdout from case.py; stderr={rc.stderr!r}"
    return json.loads(lines[-1])


def _emit_and_inspect(tmp_path: Path, profile: str) -> dict:
    """Init a fresh ceremony with the chosen profile, emit one entry,
    inspect both the yaml and the resulting on-disk log line."""
    body = textwrap.dedent(f"""
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        os.environ["TN_NO_LINK"] = "1"
        import tn
        tn.init(profile={profile!r})
        cfg = tn.current_config()
        yaml_path = pathlib.Path(cfg.yaml_path)
        log = pathlib.Path(cfg.resolve_log_path())
        tn.info("matrix.evt", x=1, message="hello")
        tn.info("matrix.evt", x=2, message="again")
        tn.flush_and_close()
        import yaml
        cer = (yaml.safe_load(yaml_path.read_text()) or {{}}).get("ceremony", {{}})
        handlers = yaml.safe_load(yaml_path.read_text()).get("handlers") or []
        # Capture sink kinds from yaml so the matrix test can check
        # what handler-set this profile produced.
        sink_kinds = sorted({{h.get("kind") for h in handlers if isinstance(h, dict)}})
        if log.is_file() and log.read_text().strip():
            last = json.loads(log.read_text().splitlines()[-1])
        else:
            last = None
        print(json.dumps({{
            "yaml_ceremony": {{
                "profile": cer.get("profile"),
                "sign":    cer.get("sign"),
                "chain":   cer.get("chain"),
            }},
            "yaml_handlers_sink_kinds": sink_kinds,
            "yaml_handlers": handlers,
            "last_entry": last,
        }}))
    """).strip()
    return _run_subprocess(tmp_path, body)


# --------------------------------------------------------------------
# Signing settings and emitted signatures.
# --------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_signs_axis_wired_in_yaml(tmp_path: Path, profile: str):
    """yaml.ceremony.sign reflects the catalog's signs bit."""
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    assert result["yaml_ceremony"]["sign"] is CATALOG[profile].signs, (
        f"profile={profile}: expected ceremony.sign="
        f"{CATALOG[profile].signs}, got {result['yaml_ceremony']['sign']!r}"
    )


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_signs_axis_wired_in_emit(tmp_path: Path, profile: str):
    """On-disk entries have empty signature iff catalog says signs=False."""
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    last = result["last_entry"]
    if last is None:
        pytest.skip(
            f"profile={profile} produced no on-disk entry "
            "(stdout-only default_sink); signature check is moot"
        )
    sig = last.get("signature") or ""
    if CATALOG[profile].signs:
        assert sig, (
            f"profile={profile} signs=True but on-disk signature empty"
        )
    else:
        assert not sig, (
            f"profile={profile} signs=False but on-disk signature is set"
        )


# --------------------------------------------------------------------
# Chaining and output settings.
# --------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if not p.chains],
)
def test_unchained_profiles_keep_sequence_without_hash_link(tmp_path: Path, profile: str):
    """Independent entries retain a sequence counter and an empty prev_hash."""
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    last = result["last_entry"]
    if last is None:
        pytest.skip(
            f"profile={profile} produced no on-disk entry; "
            "chains check is moot"
        )
    assert result["yaml_ceremony"]["chain"] is False
    assert last["prev_hash"] == ""
    assert last["sequence"] == 2


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if p.default_sink == "stdout"],
)
def test_stdout_profile_selects_stdout_handler(tmp_path: Path, profile: str):
    """The stdout profile declares its console handler in the YAML."""
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    sinks = set(result["yaml_handlers_sink_kinds"])
    assert "file.rotating" not in sinks
    assert "stdout" in sinks


# --------------------------------------------------------------------
# Stream output configuration.
# --------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if p.default_sink == "stdout"],
)
def test_stream_yaml_honors_default_sink_stdout(tmp_path: Path, profile: str):
    """Named streams apply their profile's output setting."""
    body = textwrap.dedent(f"""
        import os, json, pathlib
        os.environ["TN_NO_STDOUT"] = "1"
        import tn, yaml
        # Default first so a stream can be minted on top of it.
        tn.init()
        # Then a named stream with the chosen profile.
        tn.init("telemetry_stream", profile={profile!r})
        tn.flush_and_close()
        stream_yaml = pathlib.Path("./.tn/telemetry_stream/tn.yaml")
        doc = yaml.safe_load(stream_yaml.read_text())
        handlers = doc.get("handlers") or []
        kinds = sorted({{h.get("kind") for h in handlers if isinstance(h, dict)}})
        print(json.dumps({{"kinds": kinds}}))
    """).strip()
    result = _run_subprocess(tmp_path, body)
    assert "file.rotating" not in result["kinds"], (
        f"stream yaml for profile={profile} should NOT carry "
        f"file.rotating (default_sink=stdout). Got {result['kinds']!r}"
    )
    assert "stdout" in result["kinds"]


# --------------------------------------------------------------------
# Documentation pin — profile catalog has the 5 known entries
# --------------------------------------------------------------------


def test_catalog_has_five_documented_profiles():
    """Pin the catalog shape so a new profile or a removed one fails
    here, prompting matching doc / test updates."""
    assert set(PROFILE_NAMES) == {
        "transaction", "audit", "secure_log", "telemetry", "stdout",
    }, f"catalog changed; update docs + matrix tests. got {PROFILE_NAMES}"
