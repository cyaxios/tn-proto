"""End-to-end audit of every profile in tn._profiles against every
catalog axis (signs / chains / flush / default_sink).

Pinned ground truth: what the catalog *claims* each profile does
(``tn._profiles._CATALOG``), and what the runtime *actually delivers*
today. Where the two diverge, the test pins the gap with a clear
xfail-style assertion so we can't lose track of it.

DX review #4 wired ``signs`` into ``ceremony.sign``. The other three
axes are still no-ops at the runtime level today. This file is the
single place to flip from "documented gap" to "actually wired" once
the Rust runtime grows the matching switches.
"""
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
        import tn
        tn.init(profile={profile!r})
        tn.info("matrix.evt", x=1, message="hello")
        tn.flush_and_close()
        yaml_path = pathlib.Path("./.tn/default/tn.yaml")
        import yaml
        cer = (yaml.safe_load(yaml_path.read_text()) or {{}}).get("ceremony", {{}})
        handlers = yaml.safe_load(yaml_path.read_text()).get("handlers") or []
        # Capture sink kinds from yaml so the matrix test can check
        # what handler-set this profile produced.
        sink_kinds = sorted({{h.get("kind") for h in handlers if isinstance(h, dict)}})
        log = pathlib.Path("./.tn/default/logs/tn.ndjson")
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
            "last_entry": last,
        }}))
    """).strip()
    return _run_subprocess(tmp_path, body)


# --------------------------------------------------------------------
# Wired axes (assertions that MUST pass — gaps if they fail)
# --------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_signs_axis_wired_in_yaml(tmp_path: Path, profile: str):
    """yaml.ceremony.sign reflects the catalog's signs bit.
    DX review #4 wired this axis."""
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
    if CATALOG[profile].default_sink == "stdout":
        # Profiles whose default sink is stdout currently STILL emit
        # to the file too (see test_default_sink_axis_GAP). When the
        # default_sink axis is wired, last may be None.
        pass
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
# Gap axes (currently NOT wired — the assertions document the gap)
# --------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if not p.chains],
)
def test_chains_axis_GAP(tmp_path: Path, profile: str):
    """Profiles with chains=False (secure_log, telemetry, stdout) should
    emit entries without ``prev_hash`` / ``sequence``. Today the Rust
    runtime always chains. This test pins the gap: it XFAILS until
    the chains axis is wired in ``crypto/tn-core/src/chain.rs``.
    """
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    last = result["last_entry"]
    if last is None:
        pytest.skip(
            f"profile={profile} produced no on-disk entry; "
            "chains check is moot"
        )
    has_chain_fields = (
        "prev_hash" in last
        or "sequence" in last
    )
    if has_chain_fields:
        pytest.xfail(
            f"GAP: profile={profile} catalog says chains=False but "
            f"runtime still emits prev_hash + sequence. Awaiting Rust "
            f"runtime support (crypto/tn-core/src/chain.rs)."
        )
    else:
        # Already fixed — assert the gap really is closed.
        assert "prev_hash" not in last
        assert "sequence" not in last


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if p.default_sink == "stdout"],
)
def test_default_sink_axis_GAP(tmp_path: Path, profile: str):
    """Profiles whose default_sink is 'stdout' (telemetry, stdout) should
    NOT have a file.rotating handler in the default-ceremony yaml.
    Today ``config.create_fresh`` always declares both. Stream yamls
    DO honour default_sink (verified separately in
    test_stream_yaml_honors_default_sink); only the default ceremony
    has the gap.
    """
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    sinks = set(result["yaml_handlers_sink_kinds"])
    if "file.rotating" in sinks:
        pytest.xfail(
            f"GAP: profile={profile} catalog says default_sink=stdout "
            f"but default-ceremony yaml still declares a file.rotating "
            f"handler. config.create_fresh's baseline yaml needs a "
            f"profile-aware handler list."
        )
    else:
        assert "file.rotating" not in sinks


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_flush_axis_GAP(tmp_path: Path, profile: str):
    """``profile.flush`` (fsync / buffered / async) should drive the
    handler's flush policy in yaml. Currently neither the default
    nor stream-yaml writers consult this field.
    """
    sub = tmp_path / profile
    sub.mkdir()
    result = _emit_and_inspect(sub, profile)
    handlers_text = json.dumps(result.get("yaml_handlers_sink_kinds", []))
    # The yaml handler dicts only carry kind/path/etc — no flush field.
    # This test pins the gap as a known-skip for now.
    pytest.xfail(
        f"GAP: profile.flush={CATALOG[profile].flush!r} is not "
        f"reflected in yaml handlers (no flush policy field on the "
        f"handler dict). handlers_text={handlers_text}"
    )


# --------------------------------------------------------------------
# Stream-yaml honouring of default_sink (the path that DOES work)
# --------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [name for name, p in CATALOG.items() if p.default_sink == "stdout"],
)
def test_stream_yaml_honors_default_sink_stdout(tmp_path: Path, profile: str):
    """Per-stream yamls written by ``_create_stream_yaml`` DO consult
    profile.default_sink today (line 414-426 in tn/_multi.py). Pin
    this so the default-ceremony fix later doesn't accidentally
    regress streams.
    """
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
