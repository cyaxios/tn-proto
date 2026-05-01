"""Example 7: request-scoped context for FastAPI / async apps.

Story
-----
Jamie migrates from a sync Flask app to FastAPI. Now the process
handles many requests concurrently. Every log line should carry the
`user_id`, `request_id`, `method`, and `path` so a debugger can follow
a failing trace — but passing those to every `tn.info()` call is
miserable. The answer is `contextvars`: set once per request, picked up
automatically everywhere downstream.

What this shows
---------------
  - `tn.set_context(**kwargs)` is async-task-isolated. Concurrent
    handlers do not bleed context into each other.
  - After set_context, every tn.log call in the same task / await
    chain automatically includes those fields — public ones go into
    the envelope, group-routed ones go into the right ciphertext.

Run it
------
    python ex07_context.py
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import tn


async def handle_request(req_id: str, user: str, action: str) -> dict:
    """Simulates a FastAPI request handler that does some work."""
    # In FastAPI you would put this inside your auth dependency,
    # so every downstream function/service sees the context automatically.
    tn.set_context(
        request_id=req_id,
        user_did=f"did:plc:{user}",
        method="POST",
        path=f"/{action}",
    )

    # Some downstream service function — no context passed.
    await do_work(action)

    return {"ok": True}


async def do_work(action: str) -> None:
    # Nothing here says anything about user_id or request_id. They come
    # from the contextvar, set in handle_request above.
    tn.info("work.started", action=action)
    await asyncio.sleep(0.01)
    tn.info("work.done", action=action, ms=10)


async def run(n_requests: int) -> None:
    # Fire N requests concurrently to prove context isolation.
    await asyncio.gather(
        *[handle_request(f"req-{i}", f"user-{i}", "checkout") for i in range(n_requests)]
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jamie7_") as td:
        yaml_path = Path(td) / "tn.yaml"
        tn.init(yaml_path)

        asyncio.run(run(4))

        # FINDINGS #2 — logs are namespaced under .tn/<yaml-stem>/.
        log_path = Path(td) / ".tn" / "tn" / "logs" / "tn.ndjson"
        tn.flush_and_close()
        tn.init(yaml_path)
        cfg = tn.current_config()

        # Group entries by request_id to prove each request's context
        # stayed with IT, not bleeding into other concurrent requests.
        # tn.read_raw yields {envelope, plaintext, valid} dicts so we can
        # pull request_id straight off the envelope. The four requests
        # were emitted in the prior run before flush_and_close, so we need
        # all_runs=True to surface them after re-init (default-strict
        # run_id filter would otherwise drop them — FINDINGS #4 / #12).
        by_req: dict[str, list[dict]] = {}
        for e in tn.read_raw(log_path, cfg, all_runs=True):
            env = e["envelope"]
            if env.get("event_type", "").startswith("tn."):
                continue  # skip bootstrap attestations
            rid = env.get("request_id", "?")
            by_req.setdefault(rid, []).append(env)

        for rid, entries in sorted(by_req.items()):
            types = [e["event_type"] for e in entries]
            users = {e.get("user_did") for e in entries}
            assert len(users) == 1, f"context leak! saw users {users} in {rid}"
            print(f"  {rid}  user={users.pop()}  events={types}")

        print("\ncontext isolation works across concurrent tasks.")
        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
