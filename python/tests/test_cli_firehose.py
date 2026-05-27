"""Tests for the gated ``tn firehose`` CLI verbs.

Covers the gate (env unset -> verb invisible; env set -> verb present)
and a happy-path dispatch with a mocked ``httpx`` transport so no real
network call leaves the test process.

The verbs proxy a Cloudflare Worker — operational only, gated by
``TN_FIREHOSE_ENABLED=1`` so the surface stays hidden from the default
CLI install.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import sys

import httpx
import pytest


def _reload_cli():
    """Re-import tn.cli so the gate sees the current env var state."""
    if "tn.cli" in sys.modules:
        return importlib.reload(sys.modules["tn.cli"])
    import tn.cli as cli_mod  # noqa: F401
    return importlib.import_module("tn.cli")


# ── Gate visibility ──────────────────────────────────────────────────


def test_firehose_absent_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TN_FIREHOSE_ENABLED", raising=False)
    cli = _reload_cli()
    parser = cli.build_parser()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            parser.parse_args(["--help"])
        except SystemExit:
            pass
    help_text = buf.getvalue()
    assert "firehose" not in help_text, (
        "firehose verb leaked into --help with TN_FIREHOSE_ENABLED unset"
    )


def test_firehose_present_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TN_FIREHOSE_ENABLED", "1")
    cli = _reload_cli()
    parser = cli.build_parser()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            parser.parse_args(["--help"])
        except SystemExit:
            pass
    help_text = buf.getvalue()
    assert "firehose" in help_text, "firehose verb missing with gate on"


def test_firehose_dispatch_unknown_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TN_FIREHOSE_ENABLED", raising=False)
    cli = _reload_cli()
    parser = cli.build_parser()
    # argparse raises SystemExit with code 2 on unknown verb.
    with pytest.raises(SystemExit):
        parser.parse_args(["firehose", "stats", "t1"])


# ── Stats happy path ─────────────────────────────────────────────────


def test_firehose_stats_dispatches_via_httpx(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("TN_FIREHOSE_ENABLED", "1")
    monkeypatch.setenv("TN_FIREHOSE_URL", "http://worker.invalid")
    cli = _reload_cli()

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        return httpx.Response(200, json={"tenant": "t1", "frames": 7})

    transport = httpx.MockTransport(handler)

    real_get = httpx.get

    def fake_get(url, *args, **kwargs):
        kwargs.setdefault("timeout", 5.0)
        with httpx.Client(transport=transport) as c:
            return c.get(url, *args, **kwargs)

    monkeypatch.setattr(cli.httpx, "get", fake_get)
    try:
        parser = cli.build_parser()
        args = parser.parse_args(["firehose", "stats", "t1"])
        rc = args.func(args)
    finally:
        monkeypatch.setattr(cli.httpx, "get", real_get)

    assert rc == 0
    assert captured["url"].endswith("/stats/t1")
    out = capsys.readouterr().out
    body = json.loads(out)
    assert body == {"tenant": "t1", "frames": 7}


def test_firehose_stats_missing_url_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TN_FIREHOSE_ENABLED", "1")
    monkeypatch.delenv("TN_FIREHOSE_URL", raising=False)
    cli = _reload_cli()
    parser = cli.build_parser()
    args = parser.parse_args(["firehose", "stats", "t1"])
    with pytest.raises(SystemExit) as excinfo:
        args.func(args)
    assert excinfo.value.code == 1


def test_firehose_list_requires_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TN_FIREHOSE_ENABLED", "1")
    monkeypatch.setenv("TN_FIREHOSE_URL", "http://worker.invalid")
    monkeypatch.delenv("TN_FIREHOSE_TOKEN", raising=False)
    cli = _reload_cli()
    parser = cli.build_parser()
    args = parser.parse_args(["firehose", "list", "did:key:zSomething"])
    with pytest.raises(SystemExit) as excinfo:
        args.func(args)
    assert excinfo.value.code == 1
