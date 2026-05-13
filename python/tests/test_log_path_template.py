"""Main-log path templating: per-envelope fan-out + glob read.

Closes the write-side half of the path-templating story. Issue #47
left the admin log able to fan across files but the main log stuck
on a single literal path. This module proves:

1. `logs.path` with `{event_type}` (etc.) tokens routes each emit
   to its rendered file
2. `tn.read(log=template)` glob-merges the per-event files back
   into a single timestamp-ordered stream
3. Schema validation rejects unknown tokens

The Rust runtime doesn't yet support templated `logs.path`. The
dispatch layer auto-routes templated ceremonies through Python
(see `_dispatch._logs_path_is_templated`) so this feature works
without breaking Rust acceleration for non-templated ceremonies.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml as _yaml

import tn


def _swap_logs_path(yaml_path: Path, new_path: str) -> None:
    """Edit both `logs.path` and the matching `handlers[].path` so
    write side (the handler) and read-side metadata (`logs.path`)
    stay aligned. `logs.path` is the source of truth for where the
    main log lives; the synthesized `file.rotating` handler is what
    actually writes — keep both in sync when templating.
    """
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("logs", {})["path"] = new_path
    for h in doc.get("handlers") or []:
        if isinstance(h, dict) and h.get("kind", "").startswith("file"):
            h["path"] = new_path
            break
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_emit_routes_per_event_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`logs.path` with `{event_class}` writes order.* to one file,
    payment.* to another, audit.* to a third."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    # logs.path is resolved relative to the yaml directory, so the
    # template below renders to <yaml_dir>/logs/<class>.ndjson.
    _swap_logs_path(yaml_path, "./logs/{event_class}.ndjson")

    tn.init(yaml_path)
    tn.info("order.created", id="A100")
    tn.info("payment.captured", amount=4999)
    tn.info("audit.review", reviewer="alice")
    tn.info("order.shipped", id="A100")
    tn.flush_and_close()

    log_dir = yaml_path.parent / "logs"
    order_lines = (log_dir / "order.ndjson").read_text(encoding="utf-8").splitlines()
    payment_lines = (log_dir / "payment.ndjson").read_text(encoding="utf-8").splitlines()
    audit_lines = (log_dir / "audit.ndjson").read_text(encoding="utf-8").splitlines()

    # Each rendered file holds only its own class's envelopes.
    for line in order_lines:
        env = json.loads(line)
        assert env["event_type"].startswith("order."), env["event_type"]
    for line in payment_lines:
        assert json.loads(line)["event_type"].startswith("payment.")
    for line in audit_lines:
        assert json.loads(line)["event_type"].startswith("audit.")

    assert len(order_lines) == 2
    assert len(payment_lines) == 1
    assert len(audit_lines) == 1


def test_read_globs_template_back_into_one_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`tn.read(log=template_string, all_runs=True)` glob-merges the
    per-event-class files back into one stream."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    template = "./logs/{event_class}.ndjson"
    _swap_logs_path(yaml_path, template)

    tn.init(yaml_path)
    tn.info("order.created", id="A100", marker="A")
    tn.info("payment.captured", amount=4999, marker="B")
    tn.info("audit.review", marker="C")
    tn.flush_and_close()

    # Re-init and read back via the same template; expect all three
    # markers in the merged stream.
    tn.init(yaml_path)
    seen = {
        e.fields.get("marker")
        for e in tn.read(log=template, all_runs=True)
        if e.fields.get("marker") is not None
    }
    assert seen == {"A", "B", "C"}, f"missing markers; saw {seen}"


def test_schema_rejects_unknown_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`logs.path` with an unknown `{foo}` token raises at load time,
    not at first emit."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    _swap_logs_path(yaml_path, "./.tn/logs/{not_a_real_token}.ndjson")

    with pytest.raises(ValueError, match="logs.path"):
        tn.init(yaml_path)
