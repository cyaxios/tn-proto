"""Example 1: your first attested log.

Story
-----
Jamie runs a small SaaS. Last Tuesday at 3 a.m. it went down; customers
complained by 8 a.m. and Jamie had no idea what had happened. Jamie
installs `tn-protocol` and adds three lines to the order handler.
Next time something breaks, there are signed logs.

What this shows
---------------
  - `tn.init()` (no args) creates or loads a ceremony in the standard
    location: a device key (Ed25519), a did:key identity, a default
    btn group, and the .tn/ directory under cwd or $TN_HOME.
  - `tn.info(event, **fields)` emits an attested log line.
  - `tn.read()` (no args) reads them back as flat dicts — the same
    shape you'd write yourself: ``{event_type, timestamp, ...your fields}``.
    Each entry has been decrypted; crypto plumbing is invisible.

For the audit-grade view (signatures, chain hashes, ciphertext bytes),
see ``ex02_reading.py`` which uses ``tn.read_raw()`` to demo the
envelope shape under the friendly surface.

Run it
------
    python ex01_hello.py
"""

from __future__ import annotations

import os
import tempfile

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jamie_", ignore_cleanup_errors=True) as td:
        # Use the tempdir as our project root so the ceremony lands in
        # an isolated .tn/ directory we own. Real apps just call
        # `tn.init()` from the project root.
        os.chdir(td)
        tn.init()

        print(f"I am: {tn.current_config().device.did}")

        # log three things that happened
        tn.info("app.booted", pid=1234)
        tn.info("page.view", path="/checkout", user="u_42")
        tn.warning("auth.retry", attempts=3)

        # Read them back. tn.read() returns flat dicts — the same shape
        # you'd hand-write. Defaults to the current run's events only,
        # so naive filters don't pick up entries from prior test runs.
        print("\n--- log entries (flat shape) ---")
        for e in tn.read():
            if e["event_type"].startswith("tn."):
                continue  # skip bootstrap attestations for demo clarity
            # Pull out everything that isn't envelope plumbing
            crypto_fields = {"did", "timestamp", "event_id", "sequence", "level",
                             "event_type", "run_id", "_hidden_groups"}
            payload = {k: v for k, v in e.items() if k not in crypto_fields}
            print(f"[{e['level']:7}] {e['event_type']:16} seq={e['sequence']} "
                  f"fields={payload}")

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
