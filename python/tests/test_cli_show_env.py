"""Tests for the reflective ``tn show env`` CLI verb.

Covers the three render formats (human, env, json), redaction of secret
variables in human/json output, and that the env format is paste-able
(no comments, well-formed KEY=VALUE lines).

The verb is reflective-only — these tests must not depend on a running
ceremony. We point ``TN_HOME`` at an empty tmp dir so the discovery
chain returns nothing and yaml-sourced rows simply render as ``(unset)``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tn.cli import (
    _ENV_SCHEMA,
    _redact,
    _render_env_format,
    _render_human,
    _render_json,
    cmd_show_env,
    build_parser,
)


@pytest.fixture(autouse=True)
def _isolated_tn_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin TN_HOME at an empty dir so yaml discovery is deterministic."""
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tn-home"))
    # Make sure no inherited yaml ref leaks in.
    monkeypatch.delenv("TN_YAML", raising=False)
    # Run from an empty cwd so ./tn.yaml never resolves.
    monkeypatch.chdir(tmp_path)


def test_schema_is_non_empty_and_well_shaped() -> None:
    """Catch a typo / accidental drop in ``_ENV_SCHEMA``."""
    assert len(_ENV_SCHEMA) >= 30, "expected a sizeable canonical inventory"
    seen: set[str] = set()
    for entry in _ENV_SCHEMA:
        # Required keys.
        for key in ("name", "category", "purpose", "default", "precedence"):
            assert key in entry, f"{entry.get('name')!r} missing {key}"
        assert entry["name"] not in seen, f"duplicate row: {entry['name']}"
        seen.add(entry["name"])
        # Canonical names start with TN_ unless they're vendor / OS fallbacks.
        if not entry["name"].startswith(("XDG_", "APPDATA")):
            assert entry["name"].startswith("TN_"), entry["name"]


def test_human_renders_all_categories(monkeypatch: pytest.MonkeyPatch) -> None:
    """Human output groups by category and includes every row's name."""
    monkeypatch.setenv("TN_VAULT_URL", "https://vault.example")
    text = _render_human(_ENV_SCHEMA, dict(__import__("os").environ), {})
    # Headers for each category we declared.
    for cat in ("identity", "vault", "ceremony", "runtime", "logging"):
        assert f"## {cat}" in text
    # Every schema row appears.
    for entry in _ENV_SCHEMA:
        assert entry["name"] in text
    # An env-set value renders with its actual value.
    assert "https://vault.example" in text


def test_human_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Secret rows must NEVER show their value in human form."""
    monkeypatch.setenv("TN_VAULT_JWT", "supersecretjwtvaluepleasehide")
    text = _render_human(_ENV_SCHEMA, dict(__import__("os").environ), {})
    assert "supersecretjwtvaluepleasehide" not in text
    # Should show the redacted form instead.
    assert "*** (length: 29)" in text


def test_env_format_is_paste_able_kv_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    """The --format=env block must be a clean ``KEY=VALUE`` listing."""
    monkeypatch.setenv("TN_VAULT_URL", "https://vault.example")
    monkeypatch.setenv("TN_VAULT_JWT", "live-secret-value")
    text = _render_env_format(_ENV_SCHEMA, dict(__import__("os").environ), {})
    # No headers, no comments — every non-empty line matches KEY=VALUE.
    line_re = re.compile(r"^[A-Z][A-Z0-9_]*=.*$")
    for line in text.splitlines():
        assert line.strip() != ""
        assert line_re.match(line), f"not a KV line: {line!r}"
    # The env-set values are present in full (env format is the deploy
    # paste form, so secrets are NOT redacted here — by design).
    assert "TN_VAULT_URL=https://vault.example" in text
    assert "TN_VAULT_JWT=live-secret-value" in text


def test_env_format_skips_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset rows are dropped from the deploy-paste form."""
    monkeypatch.delenv("TN_VAULT_JWT", raising=False)
    text = _render_env_format(_ENV_SCHEMA, dict(__import__("os").environ), {})
    assert "TN_VAULT_JWT=" not in text


def test_json_format_is_valid_and_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    """--format=json must produce parseable JSON with one row per schema entry."""
    monkeypatch.setenv("TN_VAULT_URL", "https://vault.example")
    text = _render_json(
        _ENV_SCHEMA, dict(__import__("os").environ), {}, redact_secrets=True
    )
    parsed = json.loads(text)
    assert "entries" in parsed
    assert len(parsed["entries"]) == len(_ENV_SCHEMA)
    by_name = {row["name"]: row for row in parsed["entries"]}
    # An env-set row carries source="env" and the value.
    assert by_name["TN_VAULT_URL"]["source"] == "env"
    assert by_name["TN_VAULT_URL"]["value"] == "https://vault.example"
    # Every row carries a category.
    for row in parsed["entries"]:
        assert row["category"]


def test_json_format_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default JSON form (used by `tn show env --format=json`) redacts."""
    monkeypatch.setenv("TN_VAULT_JWT", "shouldnotappear")
    text = _render_json(
        _ENV_SCHEMA, dict(__import__("os").environ), {}, redact_secrets=True
    )
    assert "shouldnotappear" not in text
    parsed = json.loads(text)
    by_name = {row["name"]: row for row in parsed["entries"]}
    jwt_row = by_name["TN_VAULT_JWT"]
    assert jwt_row["secret"] is True
    assert jwt_row["source"] == "env"
    assert jwt_row["value"] == _redact("shouldnotappear")


def test_redact_helper_format() -> None:
    assert _redact("abcd") == "*** (length: 4)"
    assert _redact("") == "*** (length: 0)"


def test_show_env_subcommand_wired_into_parser() -> None:
    """``tn show env`` must dispatch to ``cmd_show_env`` via argparse."""
    parser = build_parser()
    args = parser.parse_args(["show", "env"])
    assert args.func is cmd_show_env
    # Default format is human.
    assert getattr(args, "format", "human") == "human"


def test_show_env_format_choices_are_enforced() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["show", "env", "--format=bogus"])


def test_cmd_show_env_prints_to_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Smoke test: the verb writes to stdout and exits 0 in all three formats."""
    monkeypatch.setenv("TN_VAULT_URL", "https://vault.example")
    parser = build_parser()

    for fmt in ("human", "env", "json"):
        capsys.readouterr()  # flush
        args = parser.parse_args(["show", "env", f"--format={fmt}"])
        rc = cmd_show_env(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert out, f"--format={fmt} produced no output"
        if fmt == "json":
            json.loads(out)  # must parse
        elif fmt == "human":
            assert "## vault" in out
        elif fmt == "env":
            # No stray comments / headers in deploy-paste form.
            for line in out.splitlines():
                assert "=" in line
