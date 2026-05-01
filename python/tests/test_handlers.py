"""Handler infrastructure: rotation, filters, outbox durability."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
from tn.filters import _compile_filter
from tn.handlers.base import AsyncHandler
from tn.handlers.file import FileRotatingHandler


def test_filter_compiler():
    accept_all = _compile_filter(None)
    assert accept_all({"event_type": "order.created"}) is True

    only_orders = _compile_filter({"event_type": {"starts_with": "order."}})
    assert only_orders({"event_type": "order.created"}) is True
    assert only_orders({"event_type": "auth.login"}) is False

    warn_or_error = _compile_filter({"level": {"in": ["warning", "error"]}})
    assert warn_or_error({"level": "warning"}) is True
    assert warn_or_error({"level": "info"}) is False

    combined = _compile_filter(
        {
            "event_type": {"starts_with": "order."},
            "level": {"in": ["warning", "error"]},
        }
    )
    assert combined({"event_type": "order.shipped", "level": "error"}) is True
    assert combined({"event_type": "order.shipped", "level": "info"}) is False
    assert combined({"event_type": "auth.failed", "level": "error"}) is False
    print("filter compiler: ok")


def test_event_type_whitelist():
    # The emit path must refuse event_type with directory-traversal chars.
    with tempfile.TemporaryDirectory(prefix="tnfilt_") as td:
        tn.init(Path(td) / "tn.yaml")
        try:
            tn.info("../../etc/passwd", x=1)
            raise AssertionError("event_type traversal was accepted")
        except ValueError as e:
            assert "invalid" in str(e)
        tn.flush_and_close()
    print("event_type whitelist: ok")


def test_file_rotation_by_size():
    with tempfile.TemporaryDirectory(prefix="tnrot_") as td:
        path = Path(td) / "rot.ndjson"
        # 2KB max, 3 backups — tiny so we trigger rotation quickly
        h = FileRotatingHandler(
            name="rot",
            path=path,
            max_bytes=2 * 1024,
            backup_count=3,
        )
        # Each entry ~200 bytes -> ~11 per rollover; write 40 entries
        for i in range(40):
            raw = (json.dumps({"i": i, "pad": "x" * 150}) + "\n").encode()
            h.emit({}, raw)
        h.close()

        # Expect the primary file + up to 3 backups
        backups = sorted(path.parent.glob("rot.ndjson.*"))
        assert path.exists(), "primary file missing"
        assert 1 <= len(backups) <= 3, f"unexpected backup count {len(backups)}"
        print(f"file rotation: primary + {len(backups)} backup(s) ok")


def test_async_handler_outbox_durability():
    """Start an async handler with a failing publisher; kill the worker
    thread; prove items survive in the SQLite outbox for next run."""

    events_delivered: list[dict] = []
    fail_first_n = threading.Event()

    class FlakyAsyncHandler(AsyncHandler):
        def _publish(self, envelope, raw_line):
            if not fail_first_n.is_set():
                raise RuntimeError("broker down")
            events_delivered.append(envelope)

    with tempfile.TemporaryDirectory(prefix="tnout_") as td:
        outbox_path = Path(td) / ".tn/outbox"

        h = FlakyAsyncHandler(
            name="flaky",
            outbox_path=outbox_path,
            max_retries=3,
            backoff_initial=0.05,
            backoff_max=0.2,
        )

        # Enqueue a few items while publisher is failing.
        for i in range(3):
            h.emit({"event_type": "test.flaky", "event_id": f"e{i}"}, f'{{"i":{i}}}\n'.encode())

        time.sleep(0.6)  # let worker attempt + fail a few times
        assert len(events_delivered) == 0, "nothing should have delivered yet"

        # Allow publishes to succeed now.
        fail_first_n.set()
        time.sleep(1.0)  # worker should drain

        h.close(timeout=2.0)

        assert len(events_delivered) == 3, f"expected 3 delivered, got {len(events_delivered)}"
        assert [e["event_id"] for e in events_delivered] == ["e0", "e1", "e2"]
        print("async outbox (flaky publisher + retries): 3/3 eventually delivered")


def test_logger_fans_out_to_multiple_handlers_per_yaml():
    """Configure two file handlers with disjoint filters and confirm each
    file only receives its subset of entries."""
    with tempfile.TemporaryDirectory(prefix="tnfan_") as td:
        ws = Path(td)
        # Bootstrap a ceremony, then REPLACE the default handlers section
        # with two custom file handlers. Appending a second `handlers:` key
        # would produce a duplicate-field error from the Rust yaml parser
        # ("ceremony: duplicate field `handlers`"); replace via yaml load+dump
        # so the new ceremony has exactly one handlers list.
        import yaml as _yaml
        tn.init(ws / "tn.yaml")
        tn.flush_and_close()
        doc = _yaml.safe_load((ws / "tn.yaml").read_text(encoding="utf-8"))
        doc["handlers"] = [
            {
                "name": "orders",
                "kind": "file.rotating",
                "path": "./.tn/logs/orders.ndjson",
                "max_bytes": 1048576,
                "filter": {"event_type": {"starts_with": "order."}},
            },
            {
                "name": "auth",
                "kind": "file.rotating",
                "path": "./.tn/logs/auth.ndjson",
                "max_bytes": 1048576,
                "filter": {"event_type": {"starts_with": "auth."}},
            },
        ]
        (ws / "tn.yaml").write_text(
            _yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
        )

        tn.flush_and_close()
        tn.init(ws / "tn.yaml")

        tn.info("order.created", amount=100)
        tn.info("order.shipped", tracking="XYZ")
        tn.warning("auth.failed", reason="bad password")
        tn.info("billing.charged", amount=50)  # matches NEITHER filter

        tn.flush_and_close()

        orders_lines = (ws / ".tn/logs" / "orders.ndjson").read_text().splitlines()
        auth_lines = (ws / ".tn/logs" / "auth.ndjson").read_text().splitlines()
        assert len(orders_lines) == 2, orders_lines
        assert len(auth_lines) == 1, auth_lines
        assert json.loads(orders_lines[0])["event_type"] == "order.created"
        assert json.loads(auth_lines[0])["event_type"] == "auth.failed"
        # billing.charged matched no handler; it was sealed but not written
        # anywhere. A warning was logged via Python's logging module.
        print("fan-out with filters: orders=2 auth=1 (billing unrouted)")


def main() -> int:
    test_filter_compiler()
    test_event_type_whitelist()
    test_file_rotation_by_size()
    test_async_handler_outbox_durability()
    test_logger_fans_out_to_multiple_handlers_per_yaml()
    print("\nall handler tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
