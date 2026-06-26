"""Main-log path templating with ``{event_id}``: one file per event.

A ceremony declaring ``logs: {path: ./logs/{event_id}.ndjson}`` writes
each emit to a file named after that event's unique ``event_id``, with
exactly one row per file. The read side globs the template back into a
single merged stream. The ``init(log_path=...)`` knob must agree with
the yaml form rather than silently collapsing.

Companion to ``test_log_path_template.py`` (which covers the
low-cardinality ``{event_class}`` / ``{event_type}`` / ``{date}``
tokens). ``{event_id}`` is the high-cardinality case the writer layer
handles with an open-write-close path (no handle pooling).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml as _yaml

import tn


def _swap_logs_path(yaml_path: Path, new_path: str) -> None:
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("logs", {})["path"] = new_path
    for h in doc.get("handlers") or []:
        if isinstance(h, dict) and h.get("kind", "").startswith("file"):
            h["path"] = new_path
            break
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _ndjson_files(log_dir: Path) -> list[Path]:
    return sorted(p for p in log_dir.glob("*.ndjson"))


def test_emit_routes_one_file_per_event_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`logs.path` with `{event_id}` writes each emit to its own file,
    one row apiece."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    _swap_logs_path(yaml_path, "./logs/{event_id}.ndjson")

    tn.init(yaml_path)
    n = 5
    for i in range(n):
        tn.info("order.created", seq=i)
    tn.flush_and_close()

    log_dir = yaml_path.parent / "logs"
    files = _ndjson_files(log_dir)

    # Every business emit produced a distinct file with exactly one row,
    # whose filename stem equals the row's event_id. (Admin events like
    # tn.ceremony.init also land in their own files; we assert about the
    # business rows specifically and that NO file holds >1 row.)
    business_ids = set()
    for f in files:
        lines = [ln for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 1, f"{f.name} should hold exactly one row, got {len(lines)}"
        env = json.loads(lines[0])
        assert env["event_id"] == f.stem, f"{f.name}: stem != event_id"
        if env["event_type"] == "order.created":
            business_ids.add(env["event_id"])

    assert len(business_ids) == n, f"expected {n} distinct business files, saw {len(business_ids)}"


def test_read_globs_event_id_back_into_one_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`tn.read(log=template, all_runs=True)` glob-merges the per-event
    files back into one stream."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    template = "./logs/{event_id}.ndjson"
    _swap_logs_path(yaml_path, template)

    tn.init(yaml_path)
    tn.info("order.created", marker="A")
    tn.info("order.created", marker="B")
    tn.info("order.created", marker="C")
    tn.flush_and_close()

    tn.init(yaml_path)
    seen = {
        e.fields.get("marker")
        for e in tn.read(log=template, all_runs=True)
        if e.fields.get("marker") is not None
    }
    assert seen == {"A", "B", "C"}, f"missing markers; saw {seen}"


def test_init_log_path_agrees_with_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`tn.init(yaml, log_path="./logs/{event_id}.ndjson")` on a fresh
    ceremony must template (one file per event), matching what the same
    `logs.path` set in yaml would do — not silently collapse to one
    file or raise."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    yaml_path = tmp_path / "tn.yaml"
    tn.init(str(yaml_path), log_path="./logs/{event_id}.ndjson")
    cfg = tn.current_config()
    assert "{event_id}" in cfg.log_path, f"log_path did not template: {cfg.log_path!r}"

    tn.info("order.created", seq=0)
    tn.info("order.created", seq=1)
    tn.flush_and_close()

    log_dir = Path(cfg.yaml_path).parent / "logs"
    files = _ndjson_files(log_dir)
    business = [
        f
        for f in files
        if json.loads(f.read_text(encoding="utf-8").splitlines()[0])["event_type"]
        == "order.created"
    ]
    assert len(business) == 2, f"expected 2 per-event files, saw {len(business)}"


def test_pure_python_fallback_no_handle_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On the pure-Python emit path (TN_FORCE_PYTHON), the templated
    handler must open-write-close per `{event_id}` row rather than
    caching a writer per rendered path. Caching would accumulate one
    open file handle per event — the leak this token is designed to
    avoid. We assert the handler's writer cache stays empty while still
    producing one file per event."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn-home"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")

    tn.init()
    yaml_path = tn.current_config().yaml_path
    tn.flush_and_close()

    _swap_logs_path(yaml_path, "./logs/{event_id}.ndjson")

    tn.init(yaml_path)
    from tn import logger as _lg
    from tn.handlers.file import FileTemplatedRotatingHandler

    templated = [
        h
        for h in _lg._runtime.handlers
        if isinstance(h, FileTemplatedRotatingHandler)
    ]
    assert templated, "expected a FileTemplatedRotatingHandler on the pure-Python path"
    handler = templated[0]

    n = 6
    for i in range(n):
        tn.info("order.created", seq=i)

    # Write-once-close: no per-path writers retained for an {event_id}
    # template (would be `n` open handles otherwise). Checked BEFORE
    # flush_and_close, which clears the cache unconditionally.
    cached_after_emits = len(handler._handlers)
    tn.flush_and_close()
    assert cached_after_emits == 0, (
        f"event_id template must not pool writers; cached {cached_after_emits}"
    )

    log_dir = yaml_path.parent / "logs"
    business = [
        f
        for f in _ndjson_files(log_dir)
        if json.loads(f.read_text(encoding="utf-8").splitlines()[0])["event_type"]
        == "order.created"
    ]
    assert len(business) == n, f"expected {n} per-event files, saw {len(business)}"
    for f in business:
        lines = [ln for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 1
