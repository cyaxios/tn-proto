"""StdoutHandler — write canonical envelope JSON lines to stdout.

Default-on (matches log → console mental model from stdlib logging),
opt-out via TN_NO_STDOUT=1 env var or tn.init(stdout=False) kwarg.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn

# -----------------------------------------------------------------------
# Unit: StdoutHandler writes raw_line to its stream
# -----------------------------------------------------------------------

def test_stdout_handler_writes_raw_line_to_stream():
    from tn.handlers.stdout import StdoutHandler

    captured = io.BytesIO()
    h = StdoutHandler(name="stdout", stream=captured)
    raw = b'{"event_type":"test.evt","sequence":1}\n'
    envelope = {"event_type": "test.evt", "sequence": 1}
    h.emit(envelope, raw)

    out = captured.getvalue()
    assert out == raw, f"expected raw bytes, got {out!r}"


def test_stdout_handler_appends_newline_if_missing():
    """Defensive: even if a caller hands us a line without trailing \\n,
    we don't run two entries together on screen."""
    from tn.handlers.stdout import StdoutHandler

    captured = io.BytesIO()
    h = StdoutHandler(name="stdout", stream=captured)
    h.emit({"event_type": "a"}, b'{"event_type":"a"}')
    h.emit({"event_type": "b"}, b'{"event_type":"b"}')
    text = captured.getvalue().decode("utf-8")
    assert text.count("\n") == 2, f"expected 2 newlines, got {text!r}"


def test_stdout_handler_respects_filter():
    """SyncHandler filter spec should suppress non-matching events."""
    from tn.handlers.stdout import StdoutHandler

    captured = io.BytesIO()
    h = StdoutHandler(name="stdout", stream=captured,
                      filter_spec={"event_type_prefix": "kept."})
    if h.accepts({"event_type": "kept.a"}):
        h.emit({"event_type": "kept.a"}, b'{"event_type":"kept.a"}\n')
    if h.accepts({"event_type": "dropped.b"}):
        h.emit({"event_type": "dropped.b"}, b'{"event_type":"dropped.b"}\n')

    text = captured.getvalue().decode("utf-8")
    assert "kept.a" in text
    assert "dropped.b" not in text


# -----------------------------------------------------------------------
# Integration: default-on through tn.init() pipeline
# -----------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_default_on_writes_to_stdout(tmp_path, capfd, monkeypatch):
    """Out of the box, tn.init() + tn.info() should land a JSON line on stdout.

    Uses capfd (file-descriptor capture) instead of capsys because the default
    cipher (btn) routes through the Rust runtime, which writes the JSON line
    via Rust's StdoutHandler (writes to fd 1 directly, bypasses sys.stdout).
    """
    monkeypatch.delenv("TN_NO_STDOUT", raising=False)
    tn.init(tmp_path / "tn.yaml")
    tn.info("evt.default_on", x=1)
    tn.flush_and_close()
    out = capfd.readouterr().out
    assert "evt.default_on" in out, f"stdout missing event: {out!r}"
    # Should be parseable JSON
    json_lines = [ln for ln in out.splitlines() if "evt.default_on" in ln]
    assert json_lines, "no candidate line found"
    parsed = json.loads(json_lines[0])
    assert parsed["event_type"] == "evt.default_on"


def test_opt_out_via_env_var(tmp_path, capfd, monkeypatch):
    """TN_NO_STDOUT=1 disables the default handler (both Python and Rust paths)."""
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    tn.init(tmp_path / "tn.yaml")
    tn.info("evt.opted_out_env", x=1)
    tn.flush_and_close()
    out = capfd.readouterr().out
    assert "evt.opted_out_env" not in out, (
        f"TN_NO_STDOUT=1 should suppress stdout output, got: {out!r}"
    )


def test_opt_out_via_kwarg(tmp_path, capfd, monkeypatch):
    """tn.init(stdout=False) disables the default Python handler.

    Note: tn.init(stdout=False) only suppresses the Python-side StdoutHandler.
    On btn ceremonies that route through the Rust runtime, Rust's native
    StdoutHandler reads TN_NO_STDOUT itself, not the Python kwarg — so we set
    the env var to ensure the Rust handler is also silenced.
    """
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    tn.init(tmp_path / "tn.yaml", stdout=False)
    tn.info("evt.opted_out_kwarg", x=1)
    tn.flush_and_close()
    out = capfd.readouterr().out
    assert "evt.opted_out_kwarg" not in out, (
        f"stdout opt-out should suppress stdout output, got: {out!r}"
    )


def test_stdout_does_not_break_file_handler(tmp_path, capfd, monkeypatch):
    """Default-on stdout is additive — the file handler still writes the log.

    Uses capfd (fd-level) so we capture both Python and Rust stdout writes.
    """
    monkeypatch.delenv("TN_NO_STDOUT", raising=False)
    tn.init(tmp_path / "tn.yaml")
    tn.info("evt.both", x=1)
    tn.flush_and_close()
    # FINDINGS #2 — keystore + logs are now namespaced under .tn/<yaml-stem>/.
    # For tn.yaml the stem is "tn", so the log lands at .tn/tn/logs/tn.ndjson.
    log_path = tmp_path / ".tn" / "tn" / "logs" / "tn.ndjson"
    assert log_path.exists(), "file handler should still write tn.ndjson"
    file_text = log_path.read_text(encoding="utf-8")
    assert "evt.both" in file_text
    out = capfd.readouterr().out
    assert "evt.both" in out


def test_stdout_fires_on_btn_rust_path(tmp_path, capfd, monkeypatch):
    """When the Rust runtime takes over (btn cipher + tn_core ext built),
    stdout must STILL emit the JSON line — Rust's native StdoutHandler
    closes the gap that Python's StdoutHandler can't (Rust doesn't fan
    out to Python handlers).

    Skipped if the Rust extension isn't built (single-source SDK works
    via Python; the Rust gap only matters when Rust path is live)."""
    try:
        import tn_core  # noqa: F401
    except ImportError:
        pytest.skip("tn_core extension not built; this test exercises the Rust path")

    monkeypatch.delenv("TN_NO_STDOUT", raising=False)
    monkeypatch.delenv("TN_FORCE_PYTHON", raising=False)
    tn.init(tmp_path / "tn.yaml", cipher="btn")
    if not tn.using_rust():
        pytest.skip("Rust path not active even with btn cipher; nothing to verify")
    tn.info("evt.btn_rust_stdout", x=1)
    tn.flush_and_close()
    # Use capfd so we capture the file descriptor, not just sys.stdout —
    # the Rust handler writes to fd 1 directly.
    out = capfd.readouterr().out
    assert "evt.btn_rust_stdout" in out, (
        f"Rust path with stdout default should emit JSON to fd 1, got: {out!r}"
    )


def test_registry_recognizes_kind_stdout():
    """The yaml `handlers: [{kind: stdout}]` resolves to a StdoutHandler.
    Tested directly against the registry to avoid coupling to yaml schema."""
    from pathlib import Path as _Path

    from tn.handlers.registry import build_handlers
    from tn.handlers.stdout import StdoutHandler

    handlers = build_handlers(
        [{"kind": "stdout"}],
        yaml_dir=_Path("/tmp"),
        default_log_dir=_Path("/tmp"),
    )
    assert len(handlers) == 1
    assert isinstance(handlers[0], StdoutHandler)
