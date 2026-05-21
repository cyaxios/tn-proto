"""Example 2: who said this, and can I trust it?

Story
-----
Jamie's logs now exist (see ``ex01_hello.py``), but someone asks: "how
do I know these are really from your production server and not something
you wrote yesterday to cover your tracks?" Jamie opens the audit-grade
view of the log and walks through what each entry carries.

What this shows
---------------
  - ``tn.read()`` (the friendly form, ex01) yields :class:`tn.Entry`
    instances with typed attribute access — ``e.event_type``,
    ``e.fields``, ``e.row_hash``. ``tn.read(raw=True)`` exposes the
    audit-grade shape: the on-disk envelope dict per line, with the
    group-keyed ciphertext blocks intact.
  - The envelope holds public fields anyone can read + encrypted
    per-group payloads only holders of the right kit can decrypt.
  - The signature is over ``row_hash``, which covers the public fields,
    the ciphertexts, and the prev_hash. Tampering with any of them
    breaks verification. ``tn.read(verify=True)`` walks every row,
    re-checks signature/row_hash/chain, and raises
    :class:`tn.VerifyError` on the first failure.
  - Chains are per-event_type. Each event_type is an independent log.
  - Anyone can verify a signature using only the ``did`` in the entry.
    No network lookup, no central authority.

Run it
------
    python ex02_reading.py
"""

from __future__ import annotations

import os
import tempfile

import tn
from tn import VerifyError
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

        # -------- anatomy of one entry (raw envelope on disk) -------------
        # tn.read(raw=True) yields the on-disk envelope dict for each
        # row — exactly what an auditor sees if they cat the .ndjson
        # file. Group-keyed ciphertext blocks are present as nested
        # dicts; everything else is public envelope plumbing.
        print("--- envelope shape (raw=True; the dict written to disk) ---")
        first_env = next(
            env for env in tn.read(raw=True)
            if not str(env.get("event_type", "")).startswith("tn.")
        )
        for k, v in first_env.items():
            if isinstance(v, dict) and "ciphertext" in v:
                ct_len = len(v["ciphertext"])
                shown = f"{{ciphertext: <{ct_len}-byte b64 blob>, ...}}"
            else:
                shown = v
            print(f"  {k:12} = {shown}")

        # -------- typed walk: who, what, and the per-event_type chain ----
        # Default tn.read() yields Entry instances. The chain plumbing
        # (sequence, prev_hash, row_hash, signature) is right there as
        # typed attributes — no dict spelunking, IDE autocompletes.
        print("\n--- walking all entries (typed Entry attributes) ---")
        chains: dict[str, list[int]] = {}
        for e in tn.read():
            if e.event_type.startswith("tn."):
                continue  # skip bootstrap attestations for demo clarity
            chains.setdefault(e.event_type, []).append(e.sequence)
            print(
                f"  event_type={e.event_type:14}  "
                f"seq={e.sequence}  "
                f"did={e.did[:18]}...{e.did[-6:]}  "
                f"row_hash={e.row_hash[:18]}...  "
                f"prev_hash={e.prev_hash[:18]}..."
            )

        print("\n--- per-event_type chain sequences ---")
        for et, seqs in chains.items():
            print(f"  {et:14}  {seqs}")

        # -------- integrity sweep: verify every row in one call -----------
        # tn.read(verify=True) re-checks signature + row_hash + chain
        # for every row. Clean log → iterates silently. Tampered row →
        # raises tn.VerifyError carrying the offending row's sequence,
        # event_type, and which checks failed. We wrap in try/except
        # so the demo prints a sensible result either way.
        print("\n--- integrity sweep (tn.read(verify=True)) ---")
        try:
            checked = sum(1 for _ in tn.read(verify=True))
            print(f"  all {checked} rows pass: signature, row_hash, chain")
        except VerifyError as exc:
            print(
                f"  TAMPER DETECTED at seq={exc.sequence} "
                f"event={exc.event_type!r} failed_checks={exc.failed_checks}"
            )

        # -------- independent verification: just did + sig + row_hash ----
        # The strong claim: anyone, anywhere, with no keystore and no
        # network, can verify a signature using only the public material
        # written into the row. Pull one envelope out of raw=True and
        # let DeviceKey.verify do the math.
        print("\n--- verifying one entry with ONLY public material ---")
        sig = _signature_from_b64(first_env["signature"])
        ok = DeviceKey.verify(
            first_env["device_identity"], first_env["row_hash"].encode("ascii"), sig,
        )
        # 0.4.3a1: the envelope's signer-identity key is `device_identity`.
        print(f"  DID      = {first_env['device_identity']}")
        print(f"  row_hash = {first_env['row_hash']}")
        print(f"  verify   = {ok}")
        print("  (no keystore, no network, no central authority needed.)")

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
