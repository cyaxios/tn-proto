"""tn.read returns a stats-bearing iterator + supports on_skip callback.

Covers DX review #10 + #11:

- ``tn.read(verify="skip")`` was silent: callers had no count of
  skipped rows. Now the returned iterator exposes ``.stats``
  (``ReadStats``) tracking yielded + skipped_parse + skipped_verify.
- ``tn.read(verify=True)`` raised on first failure with no chance to
  observe before the exception. Now an optional ``on_skip(env, reason)``
  callback fires once before the raise so callers can log / alert.
- ``tn.read(verify="skip", on_skip=...)`` also fires the callback per
  skipped row.
- ``verify=False`` is UNCHANGED — parse errors still raise.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _default_log(tmp_path: Path) -> Path:
    return tmp_path / ".tn" / tmp_path.name / "logs" / "default.ndjson"


@pytest.fixture()
def ceremony(tmp_path: Path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    os.environ["TN_NO_STDOUT"] = "1"
    import tn

    # Kill any leaked runtime from prior tests so this fixture binds
    # to the fresh tmp_path .tn/ directory. Without this, certain
    # test orderings cause tn.init to short-circuit on a stale
    # global runtime and the new ceremony is never written to disk.
    try:
        tn.flush_and_close()
    except Exception:
        pass

    tn.init()
    tn.info("alpha", x=1)
    tn.info("beta", x=2)
    tn.info("gamma", x=3)
    tn.flush_and_close()
    # Re-init so subsequent tn.read uses the live runtime.
    tn.init()
    try:
        yield tn, tmp_path
    finally:
        tn.flush_and_close()
        os.chdir(cwd)


def _tamper_event_type(log_path: Path, line_idx: int) -> None:
    """Tamper one entry's plaintext event_type so verify catches it.

    Forces a runtime flush+reinit so the live runtime re-reads the
    mutated file from disk (some test orderings caused the Rust
    runtime to cache log content from before the mutation).
    """
    import tn

    tn.flush_and_close()
    lines = log_path.read_text().splitlines()
    doc = json.loads(lines[line_idx])
    doc["event_type"] = "<TAMPERED>"
    lines[line_idx] = json.dumps(doc)
    log_path.write_text("\n".join(lines) + "\n")
    tn.init()


def test_skip_mode_returns_stats(ceremony):
    tn, tmp_path = ceremony
    log = _default_log(tmp_path)
    _tamper_event_type(log, 1)

    result = tn.read(verify="skip")
    out = list(result)

    assert [e.event_type for e in out] == ["alpha", "gamma"]
    assert result.stats.yielded == 2
    assert result.stats.skipped_verify == 1
    assert result.stats.skipped_parse == 0
    assert len(result.stats.skipped_reasons) == 1


def test_skip_mode_fires_on_skip_callback(ceremony):
    tn, tmp_path = ceremony
    log = _default_log(tmp_path)
    _tamper_event_type(log, 1)

    seen: list[tuple[str, str]] = []
    result = tn.read(
        verify="skip",
        on_skip=lambda env, reason: seen.append((env.get("event_type"), reason)),
    )
    out = list(result)

    assert [e.event_type for e in out] == ["alpha", "gamma"]
    assert len(seen) == 1
    et, reason = seen[0]
    # Tampered event_type — the stored event_type is "<TAMPERED>" so
    # the callback receives that.
    assert et == "<TAMPERED>"
    # Reason should mention the failed integrity axis.
    assert reason  # non-empty


def test_verify_true_fires_callback_before_raise(ceremony):
    tn, tmp_path = ceremony
    log = _default_log(tmp_path)
    _tamper_event_type(log, 1)

    seen: list[tuple[str, str]] = []
    result = tn.read(
        verify=True,
        on_skip=lambda env, reason: seen.append((env.get("event_type"), reason)),
    )
    with pytest.raises(Exception, match=r"failed:"):
        list(result)
    # Callback must have fired exactly once before the raise.
    assert len(seen) == 1
    assert seen[0][1]  # reason non-empty
    # Stats also reflect the failure even though the iterator died.
    assert result.stats.skipped_verify == 1
    assert result.stats.yielded == 1  # alpha was yielded before beta failed


def test_default_verify_false_unchanged(ceremony):
    tn, _ = ceremony
    result = tn.read()
    out = list(result)
    # Three entries written, all yield cleanly when nothing's wrong.
    assert [e.event_type for e in out] == ["alpha", "beta", "gamma"]
    assert result.stats.yielded == 3
    assert result.stats.skipped_verify == 0
    assert result.stats.skipped_parse == 0


def test_verify_false_yields_around_parse_error(ceremony):
    """#10 (0.4.2a4): under default ``verify=False``, a single corrupt
    row no longer kills iteration. Clean entries before and after the
    bad one both surface; ``stats.skipped_parse`` ticks so callers
    that want a count can read it. ``verify=True`` still raises
    (covered separately in ``test_verify_true_fires_callback_before_raise``)
    and ``verify='skip'`` still emits the admin event +
    fires the callback.
    """
    tn, tmp_path = ceremony
    log = _default_log(tmp_path)
    import base64
    lines = log.read_text().splitlines()
    doc = json.loads(lines[1])
    raw = bytearray(base64.urlsafe_b64decode(doc["default"]["ciphertext"] + "=="))
    raw[20] ^= 0x01
    doc["default"]["ciphertext"] = base64.urlsafe_b64encode(
        bytes(raw)
    ).rstrip(b"=").decode()
    lines[1] = json.dumps(doc)
    log.write_text("\n".join(lines) + "\n")

    # The runtime was bound BEFORE the on-disk tampering; rebind so
    # tn.read() picks up the mutated file.
    tn.flush_and_close()
    tn.init()
    result = tn.read()  # default verify=False
    events = [e.event_type for e in result]
    assert "alpha" in events and "gamma" in events, (
        f"clean entries on either side of the corrupt one must both "
        f"yield; got {events!r}"
    )
    assert result.stats.skipped_parse == 1
    assert result.stats.yielded >= 2


def test_on_skip_callback_exceptions_dont_break_iteration(ceremony):
    """A buggy observer must not tank the read loop."""
    tn, tmp_path = ceremony
    log = _default_log(tmp_path)
    _tamper_event_type(log, 1)

    def boom(env, reason):
        raise RuntimeError("observer is buggy")

    result = tn.read(verify="skip", on_skip=boom)
    # Iteration should complete despite the buggy callback.
    out = list(result)
    assert [e.event_type for e in out] == ["alpha", "gamma"]
    assert result.stats.skipped_verify == 1


def test_stats_partial_consumption(ceremony):
    """Stats tick incrementally; if the caller breaks out early,
    stats reflect partial progress (not the full file)."""
    tn, _ = ceremony
    result = tn.read()
    next(result)  # consume one
    next(result)  # consume two
    # don't consume the rest
    assert result.stats.yielded == 2
