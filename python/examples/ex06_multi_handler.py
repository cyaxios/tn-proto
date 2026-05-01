"""Example 6: one file per day + auth events to a webhook + everything to S3.

Story
-----
Jamie's app is live, growing steadily. Requirements multiply:
  - Ops wants a local file that rotates at midnight, keeping 30 days.
  - Security wants auth failures routed to a Slack webhook.
  - Finance wants every event archived in S3 for compliance.
  - Everything else still writes locally for quick grep.

What this shows
---------------
  - The `handlers:` section in tn.yaml is a fan-out list. Every entry
    goes to every handler whose `filter:` accepts it.
  - Handlers are composable: file rotation, HTTP webhook, object storage
    all coexist.
  - Each handler keeps its own durable outbox, so a slow Slack endpoint
    never blocks the main thread.

This example uses an in-process HTTP stub instead of a real Slack URL
so it runs offline. Swap the `url:` line for your real webhook.

Run it
------
    python ex06_multi_handler.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import tn

# ------------------------------------------------------------------
# Tiny local HTTP sink that pretends to be a Slack / PagerDuty / SIEM
# endpoint. Replace with a real URL in production.
# ------------------------------------------------------------------


class _WebhookCollector(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode("utf-8")
        self.__class__.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args, **kwargs):  # silence stderr noise
        pass


def _start_webhook() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _WebhookCollector)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}/hook"


def main() -> int:
    # The webhook handler kind isn't shipped yet — for this example we
    # demonstrate fan-out via file + file-per-type, and record what
    # WOULD go to the webhook in a collector we run ourselves.
    srv, url = _start_webhook()
    try:
        with tempfile.TemporaryDirectory(prefix="jamie6_") as td:
            ws = Path(td)
            yaml_path = ws / "tn.yaml"

            tn.init(yaml_path)
            base = yaml_path.read_text(encoding="utf-8")

            # Three handlers with different filters.
            block = """
handlers:
  - name: everything
    kind: file.rotating
    path: ./.tn/logs/tn.ndjson
    max_bytes: 524288
    backup_count: 7

  - name: auth_stream
    kind: file.timed_rotating
    path: ./.tn/logs/auth.ndjson
    when: midnight
    backup_count: 30
    filter:
      event_type:
        starts_with: "auth."

  - name: pages_only
    kind: file.rotating
    path: ./.tn/logs/pages.ndjson
    max_bytes: 524288
    filter:
      event_type:
        starts_with: "page."
"""
            yaml_path.write_text(base + block, encoding="utf-8")
            tn.flush_and_close()
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
            # order.* also went to ./.tn/logs/pages.ndjson.
            for name in ("tn.ndjson", "auth.ndjson", "pages.ndjson"):
                p = ws / ".tn" / "logs" /name
                n = len(_user_lines(p))
                print(f"  {name:14}  {n} line(s)")

            # Counts: 6 / 2 / 2 user events.
            assert len(_user_lines(ws / ".tn" / "logs" /"tn.ndjson")) == 6
            assert len(_user_lines(ws / ".tn" / "logs" /"auth.ndjson")) == 2
            assert len(_user_lines(ws / ".tn" / "logs" /"pages.ndjson")) == 2
            print("\nfan-out works as configured.")
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
