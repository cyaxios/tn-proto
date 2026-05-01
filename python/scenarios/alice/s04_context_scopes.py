"""Alice s04 — set_context under asyncio + threads, no bleed."""

from __future__ import annotations

import asyncio
import threading

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceContextScopes(Scenario):
    persona = "alice"
    name = "s04_context_scopes"
    tags = {"baseline", "jwe", "local", "context"}

    ASYNC_TASKS = 20
    THREAD_TASKS = 10

    def run(self, ctx: ScenarioContext) -> None:
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")

        async def _async_worker(rid: int):
            tn.set_context(request_id=f"async-{rid}", worker="async")
            tn.info("work.async", i=rid)
            tn.clear_context()

        async def _run_async():
            await asyncio.gather(*[_async_worker(i) for i in range(self.ASYNC_TASKS)])

        asyncio.run(_run_async())

        def _thread_worker(rid: int):
            tn.set_context(request_id=f"thread-{rid}", worker="thread")
            tn.info("work.thread", i=rid)
            tn.clear_context()

        threads = [
            threading.Thread(target=_thread_worker, args=(i,)) for i in range(self.THREAD_TASKS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        # No context bleed: every async entry's request_id starts with "async-"
        # Note: request_id is a public context field that lands in the envelope
        # top-level rather than plaintext["default"]. worker IS in plaintext["default"].
        # We check both locations for request_id to handle either placement.
        no_bleed = True
        workers_observed: set[str] = set()
        decryption_ok = True
        decrypted_count = 0
        for e in entries:
            env = e["envelope"]
            pt = e["plaintext"].get("default", {})
            worker = pt.get("worker")
            rid = pt.get("request_id") or env.get("request_id", "")
            if worker is not None:
                workers_observed.add(worker)
            if worker == "async" and not rid.startswith("async-"):
                no_bleed = False
            if worker == "thread" and not rid.startswith("thread-"):
                no_bleed = False

            # Round-trip: 'i' was passed as a field. Check it made it back
            # into plaintext['default']['i'].
            if "i" in pt and isinstance(pt["i"], int):
                decrypted_count += 1
            else:
                decryption_ok = False

        ctx.record("log_count", len(entries))
        ctx.record("async_tasks", self.ASYNC_TASKS)
        ctx.record("thread_tasks", self.THREAD_TASKS)
        ctx.record("workers_observed", sorted(workers_observed))
        ctx.record("decrypted_count", decrypted_count)
        ctx.assert_invariant("context_no_bleed", no_bleed)
        ctx.assert_invariant(
            "chain_verified",
            all(e["valid"]["chain"] for e in entries),
        )
        ctx.assert_invariant(
            "decryption_verified",
            decryption_ok and decrypted_count == len(entries),
        )
        tn.flush_and_close()
