"""HIBE Python↔wasm interop, Python side.

--emit:   write hibe_fixture.json (setup, keys, python-sealed blobs).
--verify: open the wasm-sealed reply from hibe_js_out.json and check the
          mpk fingerprint matches.
Run via run_hibe_interop.sh.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from tn import _hibe

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "hibe_fixture.json"
JS_OUT = HERE / "hibe_js_out.json"

ID_PATH = "reader-did/policy-1"
CHILD_PATH = "reader-did/policy-1/epoch-0"


def emit() -> None:
    mpk, msk = _hibe.setup(3)
    sk = _hibe.keygen(mpk, msk, ID_PATH)
    parent_sk = _hibe.keygen(mpk, msk, ID_PATH)
    body = "sealed by python for wasm"
    child_body = "sealed by python to the child path"
    doc = {
        "mpk": base64.b64encode(mpk).decode(),
        "sk": base64.b64encode(sk).decode(),
        "id_path": ID_PATH,
        "sealed": base64.b64encode(
            _hibe.seal(mpk, ID_PATH, body.encode())
        ).decode(),
        "body": body,
        "parent_sk": base64.b64encode(parent_sk).decode(),
        "child_label": "epoch-0",
        "child_sealed": base64.b64encode(
            _hibe.seal(mpk, CHILD_PATH, child_body.encode())
        ).decode(),
        "child_body": child_body,
        "reply_body": "sealed by wasm for python",
        "msk": base64.b64encode(msk).decode(),
    }
    FIXTURE.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"emitted {FIXTURE}")


def verify() -> None:
    fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
    js = json.loads(JS_OUT.read_text(encoding="utf-8"))
    mpk = base64.b64decode(fx["mpk"])
    sk = base64.b64decode(fx["sk"])
    opened = _hibe.open(mpk, sk, base64.b64decode(js["sealed"]))
    assert opened.decode() == js["body"], opened
    assert base64.b64decode(js["mpk_fp"]) == _hibe.mpk_fingerprint(mpk)
    print("python opened wasm-sealed blob: ok")


if __name__ == "__main__":
    if "--emit" in sys.argv:
        emit()
    elif "--verify" in sys.argv:
        verify()
    else:
        sys.exit("pass --emit or --verify")
