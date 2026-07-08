"""Python half of the ts-sdk hibe cross-impl proof (see hibe_cross_impl.sh).

Stage --emit:   Python mints a hibe ceremony, seals two entries, and grants
                a reader kit (.tnpkg) for the TS side to absorb.
Stage --verify: Python absorbs the kit the TS authority granted and reads
                the TS-written hibe log through tn.reader.read_as_recipient,
                asserting plaintext, signature, and chain.

Run inside the tn-proto venv (e.g. ~/venv-tnhibe). The workspace directory
is passed as argv so the shell driver owns creation/cleanup.
"""

from __future__ import annotations

import sys
from pathlib import Path

import tn
import tn.reader


def emit(ws: Path) -> int:
    yaml = ws / "py_auth" / "tn.yaml"
    log = ws / "py_auth" / "log.ndjson"
    kit = ws / "py_to_ts.tnpkg"
    tn.init(yaml, log_path=log, cipher="hibe")
    assert tn.current_config().cipher_name == "hibe"
    tn.info("py.first", note="python sealed 1")
    tn.info("py.second", note="python sealed 2")
    tn.admin.grant_reader("default", reader_did="did:key:z6Mk-ts-reader", out_path=kit)
    tn.flush_and_close()
    print(f"py-emit: sealed 2 entries at {log}; granted kit {kit}")
    return 0


def verify(ws: Path) -> int:
    ts_log = ws / "ts_auth_log.ndjson"
    ts_kit = ws / "ts_to_py.tnpkg"
    yaml = ws / "py_reader" / "tn.yaml"
    tn.init(yaml, log_path=ws / "py_reader" / "log.ndjson")
    keystore = tn.current_config().keystore
    res = tn.absorb(ts_kit)
    assert res.legacy_status != "rejected", f"absorb rejected: {res.legacy_reason}"
    assert res.accepted_count >= 3, f"expected hibe mpk+idpath+sk installed: {res}"
    tn.flush_and_close()

    got = {}
    for e in tn.reader.read_as_recipient(ts_log, keystore, group="default"):
        et = e["envelope"]["event_type"]
        got[et] = e["plaintext"]["default"]
        assert e["valid"]["signature"], f"bad signature on TS entry {et}"
        assert e["valid"]["chain"], f"broken chain on TS entry {et}"
    assert got["ts.first"]["note"] == "typescript sealed 1", got
    assert got["ts.second"]["note"] == "typescript sealed 2", got
    print("py-verify: python opened both TS-sealed hibe entries; sig+chain ok")
    return 0


def main() -> int:
    stage = sys.argv[1]
    ws = Path(sys.argv[2])
    if stage == "--emit":
        return emit(ws)
    if stage == "--verify":
        return verify(ws)
    raise SystemExit(f"unknown stage {stage!r}")


if __name__ == "__main__":
    sys.exit(main())
