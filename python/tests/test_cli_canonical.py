"""Tests for ``tn.cli_canonical.cmd_canonical``.

Exercises every line of the verb: valid scalar/nested JSON, blank-line
skipping, the bad-JSON ``SystemExit(2)`` path, and the stdout-without-
``.buffer`` fallback. Also asserts byte-for-byte equality with the
canonical form the TS ``tn-js canonical`` verb emits (key-sorted,
whitespace-free, newline-terminated) so the two implementations stay in
row_hash parity.
"""

from __future__ import annotations

import argparse
import io

import pytest

from tn.cli_canonical import cmd_canonical


class _FakeStdout:
    """Text-ish stdout exposing a ``.buffer`` BytesIO, like ``sys.stdout``."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()


def _run(monkeypatch, stdin_text: str) -> bytes:
    """Drive ``cmd_canonical`` with ``stdin_text`` and capture stdout bytes."""
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    fake_stdout = _FakeStdout()
    monkeypatch.setattr("sys.stdout", fake_stdout)
    rc = cmd_canonical(argparse.Namespace())
    assert rc == 0
    return fake_stdout.buffer.getvalue()


def test_valid_scalar_json(monkeypatch):
    assert _run(monkeypatch, '{"b": 2, "a": 1}\n') == b'{"a":1,"b":2}\n'


def test_nested_json_sorts_recursively(monkeypatch):
    out = _run(monkeypatch, '{"z": {"y": 1, "x": [3, 2]}, "a": "hi"}\n')
    assert out == b'{"a":"hi","z":{"x":[3,2],"y":1}}\n'


def test_blank_lines_skipped(monkeypatch):
    # Leading blank, whitespace-only, and trailing blank lines produce no
    # output; only the real line is canonicalized.
    out = _run(monkeypatch, '\n   \n{"a": 1}\n\n')
    assert out == b'{"a":1}\n'


def test_multiple_lines_each_emitted(monkeypatch):
    out = _run(monkeypatch, '{"a": 1}\n{"b": 2}\n')
    assert out == b'{"a":1}\n{"b":2}\n'


def test_invalid_json_exits_2(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json\n"))
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(io.BytesIO()))
    with pytest.raises(SystemExit) as exc:
        cmd_canonical(argparse.Namespace())
    assert exc.value.code == 2
    assert "invalid JSON on stdin" in capsys.readouterr().err


def test_stdout_without_buffer_fallback(monkeypatch):
    # When sys.stdout has no ``.buffer`` (e.g. a plain BytesIO), the verb
    # falls back to writing bytes directly to the object.
    monkeypatch.setattr("sys.stdin", io.StringIO('{"a": 1}\n'))
    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", raw)
    assert cmd_canonical(argparse.Namespace()) == 0
    assert raw.getvalue() == b'{"a":1}\n'


def test_matches_ts_canonical_sample(monkeypatch):
    # The canonical form the TS ``tn-js canonical`` verb emits for this
    # sample: sorted keys, no whitespace, UTF-8, newline-terminated.
    sample = '{"sequence": 7, "event_type": "log", "device": "did:key:abc"}\n'
    expected = b'{"device":"did:key:abc","event_type":"log","sequence":7}\n'
    assert _run(monkeypatch, sample) == expected
