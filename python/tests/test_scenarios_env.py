"""Unit tests for scenarios._harness.env."""

import os

from scenarios._harness.env import get_optional, load_repo_env


def test_load_repo_env_tolerates_missing(tmp_path, monkeypatch):
    # Point to nonexistent paths; should not raise.
    monkeypatch.setattr(
        "scenarios._harness.env.CANDIDATE_ENV_PATHS",
        [tmp_path / "nope.env"],
    )
    load_repo_env()  # silent no-op


def test_load_repo_env_reads_key_value_lines(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO_VAR=hello\nBAR_VAR=world\n# comment\n\n")
    monkeypatch.setattr(
        "scenarios._harness.env.CANDIDATE_ENV_PATHS",
        [env_file],
    )
    monkeypatch.delenv("FOO_VAR", raising=False)
    monkeypatch.delenv("BAR_VAR", raising=False)
    load_repo_env()
    assert os.environ["FOO_VAR"] == "hello"
    assert os.environ["BAR_VAR"] == "world"


def test_get_optional_returns_none_for_missing(monkeypatch):
    monkeypatch.delenv("ZZZ_NOT_SET", raising=False)
    assert get_optional("ZZZ_NOT_SET") is None
