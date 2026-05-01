"""Example 2: who said this, and can I trust it?

Story
-----
Jamie's logs now exist (see ``ex01_hello.py``), but someone asks: "how
do I know these are really from your production server and not something
you wrote yesterday to cover your tracks?" Jamie opens the audit-grade
view of the log and walks through what each entry carries.

What this shows
---------------
  - ``tn.read()`` (the friendly form, ex01) hides the envelope and shows
    flat decrypted fields. ``tn.read_raw()`` exposes the audit-grade
    shape: ``{envelope, plaintext, valid}`` per entry.
  - The envelope holds public fields anyone can read + encrypted
    per-group payloads only holders of the right kit can decrypt.
  - The signature is over ``row_hash``, which covers the public fields,
    the ciphertexts, and the prev_hash. Tampering with any of them
    breaks verification.
  - Chains are per-event_type. Each event_type is an independent log.
  - Anyone can verify a signature using only the ``did`` in the entry.
    No network lookup, no central authority.

Run it
------
    python ex02_reading.py
"""

from __future__ import annotations

import json
import os
import tempfile

import tn
from tn.signing import DeviceKey, _signature_from_b64


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jamie2_", ignore_cleanup_errors=True) as td:
        os.chdir(td)
        tn.init()

        # emit a few entries across two event types
        tn.info("page.view", path="/", user="alice")
        tn.info("page.view", path="/about", user="alice")
        tn.info("auth.login", user="alice")
        tn.info("page.view", path="/checkout", user="alice")

        # ``cfg.log_path`` is the canonical pointer to the on-disk log;
        # never hardcode `.tn/logs/tn.ndjson` in your own code.
        cfg = tn.current_config()
        log_path = cfg.resolve_log_path()
        # NOTE: the example used to do `flush_and_close()` + `init()`
        # here purely for narrative effect — "show what an auditor
        # sees when they pick up the log later." Now that session-start
        # rotation rolls the prior log to `<name>.1`, that flush+init
        # would move the just-written entries into the backup file and
        # leave the current file empty. Read in the same session
        # instead; the demo is just as clear.

        # -------- anatomy of one entry ------------------------------------
        print("--- envelope shape (raw line as written to disk) ---")
        with open(log_path, encoding="utf-8") as f:
            first_line = f.readline()
        raw = json.loads(first_line)
        for k, v in raw.items():
            shown = v if not isinstance(v, dict) else "{...group payload...}"
            print(f"  {k:12} = {shown}")

        # -------- every signature verifies, every chain is intact --------
        print("\n--- walking all entries (audit shape via tn.read_raw) ---")
        chains: dict[str, list[int]] = {}
        for e in tn.read_raw():
            env = e["envelope"]
            if env.get("event_type", "").startswith("tn."):
                continue  # skip bootstrap attestations for demo clarity
            valid = e["valid"]
            chains.setdefault(env["event_type"], []).append(env["sequence"])
            print(
                f"  event_type={env['event_type']:14}  "
                f"seq={env['sequence']} "
                f"sig={'ok' if valid['signature'] else 'BAD'} "
                f"chain={'ok' if valid['chain'] else 'BROKEN'} "
                f"row_hash_recomputes={'ok' if valid['row_hash'] else 'BAD'}"
            )

        print("\n--- per-event_type chain sequences ---")
        for et, seqs in chains.items():
            print(f"  {et:14}  {seqs}")

        # -------- independent verification: just did + sig + row_hash ----
        print("\n--- verifying one entry with ONLY public material ---")
        sig = _signature_from_b64(raw["signature"])
        ok = DeviceKey.verify(raw["did"], raw["row_hash"].encode("ascii"), sig)
        print(f"  DID      = {raw['did']}")
        print(f"  row_hash = {raw['row_hash']}")
        print(f"  verify   = {ok}")
        print("  (no keystore, no network, no central authority needed.)")

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
