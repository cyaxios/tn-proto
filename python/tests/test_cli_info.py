"""Coverage for the ``tn info`` CLI verb (``tn.cli_info``).

Python parity test for the TS ``tn-js info`` verb. These run the verb
IN PROCESS (calling ``cmd_info`` directly) against an isolated, real
ceremony so coverage tracks every line of ``cli_info.py`` and so we can
assert the emitted entry actually lands in the log via ``tn.read``.

Each test gets a fresh TN_HOME / cwd and a fresh ceremony minted by
``tn.init`` at an explicit yaml path, then tears the runtime down so the
module-level singleton never bleeds between tests.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import tn
from tn.cli_info import cmd_info, parse_field_args


@pytest.fixture(autouse=True)
def _isolated_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate every test: empty TN_HOME, empty cwd, no auto vault link,
    and a guaranteed runtime teardown so the singleton doesn't leak."""
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tn-home"))
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.setenv("TN_NO_LINK", "1")  # no surprise vault contact
    monkeypatch.setenv("TN_NO_STDOUT", "1")  # keep emit off real stdout
    monkeypatch.chdir(tmp_path)
    try:
        yield
    finally:
        tn.flush_and_close()


def _ns(**kw) -> argparse.Namespace:
    """Build an argparse.Namespace with the fields cmd_info expects,
    filling sensible defaults so each test only states what it varies."""
    kw.setdefault("yaml", None)
    kw.setdefault("event", None)
    kw.setdefault("level", "info")
    kw.setdefault("field", None)
    return argparse.Namespace(**kw)


def _fresh_yaml(tmp_path: Path) -> str:
    """Mint a fresh ceremony and return its tn.yaml path as a string.

    We let ``tn.init()`` (no arg) discover/create under the isolated
    TN_HOME, read back the yaml path, then close so ``cmd_info`` does its
    own ``tn.init(yaml)`` from a clean slate — exercising the verb's bind
    path rather than relying on an already-bound singleton.
    """
    tn.init()
    yaml_path = str(tn.current_config().yaml_path)
    tn.flush_and_close()
    return yaml_path


# ---------------------------------------------------------------------------
# parse_field_args
# ---------------------------------------------------------------------------

def test_parse_field_args_none_and_empty() -> None:
    assert parse_field_args(None) == {}
    assert parse_field_args([]) == {}


def test_parse_field_args_basic_pairs() -> None:
    assert parse_field_args(["a=1", "who=alice"]) == {"a": "1", "who": "alice"}


def test_parse_field_args_value_may_contain_equals() -> None:
    # Split on the FIRST '=' only (mirrors the TS split/join behaviour).
    assert parse_field_args(["note=a=b=c"]) == {"note": "a=b=c"}


def test_parse_field_args_rejects_missing_separator() -> None:
    with pytest.raises(ValueError, match="no '=' separator"):
        parse_field_args(["bareword"])


def test_parse_field_args_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="empty key"):
        parse_field_args(["=value"])


# ---------------------------------------------------------------------------
# cmd_info — error paths (no emit)
# ---------------------------------------------------------------------------

def test_cmd_info_missing_yaml(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cmd_info(_ns(yaml=None, event="evt"))
    assert rc == 2
    assert "--yaml <path> is required" in capsys.readouterr().err


def test_cmd_info_missing_event(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cmd_info(_ns(yaml=str(tmp_path / "tn.yaml"), event=None))
    assert rc == 2
    assert "--event <type> is required" in capsys.readouterr().err


def test_cmd_info_bad_field_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cmd_info(_ns(yaml=str(tmp_path / "tn.yaml"), event="evt", field=["nope"]))
    assert rc == 2
    assert "no '=' separator" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# cmd_info — happy emit (entry actually lands in the log)
# ---------------------------------------------------------------------------

def _read_events(yaml_path: str) -> list:
    """Re-bind the ceremony and read back every entry for assertions."""
    tn.init(yaml_path)
    try:
        return list(tn.read())
    finally:
        tn.flush_and_close()


def test_cmd_info_emits_default_info_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    yaml_path = _fresh_yaml(tmp_path)
    rc = cmd_info(
        _ns(yaml=yaml_path, event="hello.world", level="info", field=["who=alice"])
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "event_type='hello.world'" in out
    assert "level='info'" in out
    assert "fields=1" in out

    events = _read_events(yaml_path)
    hits = [e for e in events if e.event_type == "hello.world"]
    assert hits, f"hello.world not found among {[e.event_type for e in events]}"
    entry = hits[0]
    assert entry.level == "info"
    assert entry.fields["who"] == "alice"


def test_cmd_info_level_defaults_when_falsy(tmp_path: Path) -> None:
    """A falsy/blank ``--level`` falls back to 'info' (the `or 'info'`)."""
    yaml_path = _fresh_yaml(tmp_path)
    rc = cmd_info(_ns(yaml=yaml_path, event="evt.blank", level="", field=None))
    assert rc == 0
    events = _read_events(yaml_path)
    hits = [e for e in events if e.event_type == "evt.blank"]
    assert hits and hits[0].level == "info"


def test_cmd_info_standard_warning_level(tmp_path: Path) -> None:
    yaml_path = _fresh_yaml(tmp_path)
    rc = cmd_info(_ns(yaml=yaml_path, event="evt.warn", level="warning"))
    assert rc == 0
    events = _read_events(yaml_path)
    hits = [e for e in events if e.event_type == "evt.warn"]
    assert hits and hits[0].level == "warning"


def test_cmd_info_nonstandard_level_routes_through_log(tmp_path: Path) -> None:
    """A non-standard ``--level`` (e.g. 'trace') goes through tn.log and
    lands verbatim — exercising the else branch."""
    yaml_path = _fresh_yaml(tmp_path)
    rc = cmd_info(
        _ns(yaml=yaml_path, event="evt.trace", level="trace", field=["k=v"])
    )
    assert rc == 0
    events = _read_events(yaml_path)
    hits = [e for e in events if e.event_type == "evt.trace"]
    assert hits, "trace event not found"
    assert hits[0].level == "trace"
    assert hits[0].fields["k"] == "v"
