"""Example 6: route events to three files with independent filters.

The handlers list writes every event to a size-rotated file, auth events
also to a daily file, and page events also to their own size-rotated file.
The example runs in a temporary directory and checks the record counts.

Run from the repository root:
    python python/examples/ex06_multi_handler.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jamie6_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        tn.init(yaml_path)
        tn.flush_and_close()

        # Replace the auto-generated handlers list with three handlers
        # of our own. We parse + edit + re-dump the YAML so there's
        # exactly one top-level `handlers:` key — Rust's strict YAML
        # parser (and the spec) reject duplicate top-level keys.
        import yaml as _yaml

        doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        doc["handlers"] = [
            {
                "name": "everything",
                "kind": "file.rotating",
                "path": "./.tn/logs/tn.ndjson",
                "max_bytes": 524288,
                "backup_count": 7,
            },
            {
                "name": "auth_stream",
                "kind": "file.timed_rotating",
                "path": "./.tn/logs/auth.ndjson",
                "when": "midnight",
                "backup_count": 30,
                "filter": {"event_type": {"starts_with": "auth."}},
            },
            {
                "name": "pages_only",
                "kind": "file.rotating",
                "path": "./.tn/logs/pages.ndjson",
                "max_bytes": 524288,
                "filter": {"event_type": {"starts_with": "page."}},
            },
        ]
        yaml_path.write_text(
            _yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
        )
        tn.init(yaml_path)

        events = [
            ("app.booted", {"pid": 42}),
            ("auth.login", {"user": "alice"}),
            ("page.view", {"path": "/", "user": "alice"}),
            ("auth.failed", {"user": "eve", "reason": "bad_password"}),
            ("page.view", {"path": "/about", "user": "alice"}),
            ("app.metric", {"memory_mb": 512}),
        ]
        for et, fields in events:
            tn.info(et, **fields)

        tn.flush_and_close()

        # Counts below exclude bootstrap attestations (tn.ceremony.init,
        # tn.group.added) that the protocol emits at init — we only care
        # about the user-facing events we logged above.
        def _user_lines(path):
            return [
                ln
                for ln in path.read_text().splitlines()
                if ln.strip() and '"event_type":"tn.' not in ln
            ]

        # Every event went to ./.tn/logs/tn.ndjson.
        # auth.* also went to ./.tn/logs/auth.ndjson.
        # page.* also went to ./.tn/logs/pages.ndjson.
        for name in ("tn.ndjson", "auth.ndjson", "pages.ndjson"):
            p = ws / ".tn" / "logs" /name
            n = len(_user_lines(p))
            print(f"  {name:14}  {n} line(s)")

        # Counts: 6 / 2 / 2 user events.
        assert len(_user_lines(ws / ".tn" / "logs" /"tn.ndjson")) == 6
        assert len(_user_lines(ws / ".tn" / "logs" /"auth.ndjson")) == 2
        assert len(_user_lines(ws / ".tn" / "logs" /"pages.ndjson")) == 2
        print("\nfan-out works as configured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
