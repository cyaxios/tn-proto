"""Tests for tn._autoinit — discovery chain, loud notice, strict mode.

Coverage:
  * Step 5 (auto-create) fires when no env var, no ./tn.yaml, no
    $TN_HOME yaml exist; loud notice prints once; subsequent emits
    reuse the same runtime.
  * Step 2 ($TN_YAML) loads an existing ceremony; no notice.
  * Step 3 (./tn.yaml) loads an existing ceremony; no notice.
  * Step 4 ($TN_HOME yaml) loads an existing ceremony; no notice.
  * Strict mode (TN_STRICT=1 env var or tn.set_strict(True)) raises the
    standard "tn.init must be called" error and skips auto-init.
  * The loud notice fires exactly once per process even across multiple
    auto-create paths (the cache via _notice_printed flag).

The tests intentionally swap in a fresh cwd via ``monkeypatch.chdir``
and a private ``$TN_HOME`` per test so we never write to the user's
real home directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import _autoinit


@pytest.fixture(autouse=True)
def _reset_runtime_and_autoinit_state(monkeypatch):
    """Every test starts with no runtime and a clean autoinit state.

    Also clears env vars that would leak from a parent shell, and points
    ``$TN_HOME`` somewhere harmless until the test sets it explicitly.
    """
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_STRICT", raising=False)
    monkeypatch.delenv("TN_AUTOINIT_QUIET", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()


def test_autoinit_creates_fresh_ceremony_when_nothing_found(tmp_path, monkeypatch, capsys):
    """No env var, no cwd yaml, no $TN_HOME yaml → step 5 auto-creates."""
    cwd = tmp_path / "project"
    cwd.mkdir()
    home = tmp_path / "tnhome"
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(home))

    # Pre-condition: nothing on disk.
    assert not (cwd / "tn.yaml").exists()
    assert not (home / "tn.yaml").exists()

    tn.info("evt.first", k=1)
    # tn.info returns None (REPL-friendly); verify init worked via state.
    assert tn._dispatch_rt is not None

    # The yaml should now exist at $TN_HOME/tn.yaml.
    assert (home / "tn.yaml").exists()

    # Loud banner went to stderr.
    captured = capsys.readouterr()
    assert "TN: A NEW CEREMONY HAS BEEN CREATED" in captured.err
    assert str(home / "tn.yaml") in captured.err


def test_autoinit_notice_prints_once_per_process(tmp_path, monkeypatch, capsys):
    """A second emit shouldn't reprint the banner."""
    cwd = tmp_path / "p2"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhome2"))

    tn.info("evt.a", k=1)
    first = capsys.readouterr().err
    tn.info("evt.b", k=2)
    second = capsys.readouterr().err

    assert "NEW CEREMONY" in first
    assert "NEW CEREMONY" not in second


def test_autoinit_quiet_silences_notice(tmp_path, monkeypatch, capsys):
    cwd = tmp_path / "quiet"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhome3"))
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    tn.info("evt.q", k=1)
    captured = capsys.readouterr()
    assert "NEW CEREMONY" not in captured.err
    assert "NEW CEREMONY" not in captured.out


def test_autoinit_loads_existing_cwd_yaml_silently(tmp_path, monkeypatch, capsys):
    """Step 3: ./tn.yaml exists → load, no notice."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhome4"))

    # Bootstrap the cwd ceremony with an explicit init, then close.
    tn.init(cwd / "tn.yaml", cipher="btn")
    tn.flush_and_close()
    _autoinit.reset_state_for_tests()
    capsys.readouterr()  # discard any output from explicit init

    assert (cwd / "tn.yaml").exists()

    # Now an emit with no init should pick up the cwd yaml.
    tn.info("evt.reuse", k=1)
    captured = capsys.readouterr()
    assert "NEW CEREMONY" not in captured.err


def test_autoinit_loads_tn_yaml_env_var(tmp_path, monkeypatch, capsys):
    """Step 2: $TN_YAML wins over cwd."""
    other = tmp_path / "other"
    other.mkdir()
    yaml = other / "tn.yaml"

    # Bootstrap the env-var ceremony.
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    _autoinit.reset_state_for_tests()
    capsys.readouterr()

    cwd = tmp_path / "cwd2"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_YAML", str(yaml))
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhome5"))

    tn.info("evt.envar", k=1)
    captured = capsys.readouterr()
    assert "NEW CEREMONY" not in captured.err
    # The active config's yaml should be the env-var one.
    assert tn.current_config().yaml_path.resolve() == yaml.resolve()


def test_strict_mode_env_var_disables_autoinit(tmp_path, monkeypatch):
    cwd = tmp_path / "strict-env"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhomeS"))
    monkeypatch.setenv("TN_STRICT", "1")

    with pytest.raises(RuntimeError, match="tn.init"):
        tn.info("evt.x", k=1)


def test_strict_mode_python_call_disables_autoinit(tmp_path, monkeypatch):
    cwd = tmp_path / "strict-py"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhomeP"))

    tn.set_strict(True)
    try:
        with pytest.raises(RuntimeError, match="tn.init"):
            tn.info("evt.x", k=1)
    finally:
        tn.set_strict(False)


def test_set_strict_false_reenables_after_env(tmp_path, monkeypatch, capsys):
    """``tn.set_strict(False)`` overrides ``TN_STRICT=1``."""
    cwd = tmp_path / "strict-flip"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhomeF"))
    monkeypatch.setenv("TN_STRICT", "1")

    tn.set_strict(False)
    try:
        tn.info("evt.flip", k=1)  # should NOT raise.
        assert tn._dispatch_rt is not None
    finally:
        tn.set_strict(False)
        # Reset to env-driven default for the next test.
        _autoinit._strict_override = None  # type: ignore[attr-defined]


def test_autoinit_tn_yaml_pointing_at_missing_file_creates(tmp_path, monkeypatch, capsys):
    """If $TN_YAML points to a path that doesn't exist, we create
    there — and the notice fires (the absence is surprising)."""
    target = tmp_path / "named" / "tn.yaml"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_YAML", str(target))
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhomeM"))

    tn.info("evt.named", k=1)
    captured = capsys.readouterr()
    assert target.exists()
    assert "NEW CEREMONY" in captured.err


def test_explicit_init_skips_autoinit(tmp_path, monkeypatch, capsys):
    """If the caller has already called ``tn.init(...)``, the autoinit
    helper short-circuits — no notice, even if the yaml was just minted."""
    cwd = tmp_path / "explicit"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhomeE"))

    yaml = cwd / "tn.yaml"
    tn.init(yaml, cipher="btn")
    capsys.readouterr()  # drop any output from explicit init

    tn.info("evt.explicit", k=1)
    captured = capsys.readouterr()
    assert "NEW CEREMONY" not in captured.err
