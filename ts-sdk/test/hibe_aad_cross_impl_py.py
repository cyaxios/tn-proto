"""Python half of the ts-sdk hibe AAD cross-impl proof (see
hibe_aad_cross_impl.sh).

Stage --emit:   Python mints a hibe ceremony, seals an entry bound to an aad
                dict, and grants a reader kit (.tnpkg) for the TS side to
                absorb. The public tn_aad echo carries the binding data.
Stage --verify: Python absorbs the kit the TS authority granted, reconstructs
                the aad from the TS-written record's public tn_aad, opens the
                body, and verifies signature + chain. Also proves a tampered
                tn_aad fails to decrypt (never yields plaintext).

Run inside the tn-proto venv (e.g. ~/venv-tnhibe). The workspace directory is
passed as argv so the shell driver owns creation/cleanup.
"""

from __future__ import annotations

import json
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
    tn.info("py.aad", note="python sealed with aad", aad={"policy": "finra-oba", "v": "1"})
    tn.admin.grant_reader("default", reader_did="did:key:z6Mk-ts-reader", out_path=kit)
    tn.flush_and_close()

    # Confirm the echo landed in the public section for the TS side to use.
    line = [l for l in log.read_text(encoding="utf-8").splitlines() if l][0]
    env = json.loads(line)
    assert json.loads(env["tn_aad"]) == {"default": {"policy": "finra-oba", "v": "1"}}, env.get("tn_aad")
    print(f"py-emit: sealed aad-bound entry at {log}; granted kit {kit}")
    return 0


def verify(ws: Path) -> int:
    ts_log = ws / "ts_auth_log.ndjson"
    ts_kit = ws / "ts_to_py.tnpkg"
    yaml = ws / "py_reader" / "tn.yaml"
    tn.init(yaml, log_path=ws / "py_reader" / "log.ndjson")
    keystore = tn.current_config().keystore
    res = tn.absorb(ts_kit)
    assert res.legacy_status != "rejected", f"absorb rejected: {res.legacy_reason}"
    tn.flush_and_close()

    got = {}
    for e in tn.reader.read_as_recipient(ts_log, keystore, group="default"):
        et = e["envelope"]["event_type"]
        got[et] = e["plaintext"]["default"]
        assert e["valid"]["signature"], f"bad signature on TS entry {et}"
        assert e["valid"]["chain"], f"broken chain on TS entry {et}"
        # The TS writer echoed the aad it bound; Python reconstructed it to open.
        assert json.loads(e["envelope"]["tn_aad"]) == {"default": {"policy": "sox-404", "v": "2"}}, e[
            "envelope"
        ].get("tn_aad")
    assert got["ts.aad"]["note"] == "typescript sealed with aad", got
    print("py-verify: python reconstructed TS aad, opened body; sig+chain ok")

    # Tamper the TS record's tn_aad on disk -> python must fail to decrypt.
    lines = ts_log.read_text(encoding="utf-8").splitlines()
    tampered = []
    for line in lines:
        obj = json.loads(line)
        if obj.get("event_type") == "ts.aad":
            obj["tn_aad"] = obj["tn_aad"].replace("sox-404", "tampered")
        tampered.append(json.dumps(obj, separators=(",", ":")))
    ts_log.write_text("\n".join(tampered) + "\n", encoding="utf-8")

    for e in tn.reader.read_as_recipient(ts_log, keystore, group="default"):
        if e["envelope"]["event_type"] == "ts.aad":
            pt = e["plaintext"]["default"]
            assert pt != {"note": "typescript sealed with aad"}, "tamper leaked plaintext"
            assert "$decrypt_error" in pt or "$no_read_key" in pt, pt
    print("py-verify: tampered TS tn_aad did NOT decrypt (marker, not plaintext)")
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
