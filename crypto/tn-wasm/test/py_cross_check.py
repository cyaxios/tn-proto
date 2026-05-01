"""Cross-check: re-derive every value produced by node_smoke.mjs using
the Python reference (tn_core via PyO3 for the admin path, and the pure
Python `tn` module for canonical / chain / signing / indexing /
envelope). Compare byte for byte.

Run with the project venv:
    .venv/Scripts/python.exe tn-protocol/crypto/tn-wasm/test/py_cross_check.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Point sys.path at the tn-protocol SDK (not the `python/tn` module which
# belongs to the separate auth/relay package).
TN_SDK_PATH = HERE.parents[2] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def load_json(p: Path) -> object:
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def eq(self, name: str, actual: object, expected: object) -> None:
        if actual == expected:
            print(f"[ok]   {name}")
            self.passed += 1
        else:
            print(f"[fail] {name}")
            print(f"       expected: {expected!r}")
            print(f"       actual:   {actual!r}")
            self.failed += 1


def main() -> int:
    try:
        from tn_core.admin import reduce as admin_reduce
    except Exception as exc:
        print(f"[fail] could not import tn_core.admin: {exc}")
        print("       run  cd tn-protocol/crypto/tn-py && maturin develop  first")
        return 2
    try:
        from tn.canonical import canonical_bytes
        from tn.chain import compute_row_hash
        from tn.signing import DeviceKey, signature_b64
        from tn.indexing import derive_group_index_key, index_token
    except Exception as exc:
        print(f"[fail] could not import tn Python reference: {exc}")
        return 2

    # Inline envelope builder. Mirrors the construction in
    # `tn.logger.emit` (the envelope dict + json.dumps with compact
    # separators + trailing newline). No logger state is touched.
    def build_envelope(
        *,
        did: str,
        timestamp: str,
        event_id: str,
        event_type: str,
        level: str,
        sequence: int,
        prev_hash: str,
        row_hash: str,
        signature: str,
        public_fields: dict,
        group_payloads: dict,
    ) -> str:
        env: dict = {
            "did": did,
            "timestamp": timestamp,
            "event_id": event_id,
            "event_type": event_type,
            "level": level,
            "sequence": sequence,
            "prev_hash": prev_hash,
            "row_hash": row_hash,
            "signature": signature,
        }
        for k, v in public_fields.items():
            env.setdefault(k, v)
        for gname, gval in group_payloads.items():
            env[gname] = gval
        return json.dumps(env, separators=(",", ":")) + "\n"

    fixtures = load_json(HERE / "fixtures.json")
    js_path = HERE / "js_out.json"
    if not js_path.exists():
        print(f"[fail] missing {js_path}. Run node test/node_smoke.mjs first.")
        return 2
    js = load_json(js_path)
    c = Checker()

    # ---- admin reduce ----
    admin_results = js.get("admin", [])
    for fixture, js_result in zip(fixtures, admin_results):
        name = fixture["name"]
        if not js_result.get("ok"):
            c.eq(f"admin.{name} ok", False, True)
            continue
        try:
            py_delta = admin_reduce(fixture["envelope"])
        except Exception as exc:
            py_delta = {"error": str(exc)}
        py_str = json.dumps(py_delta, sort_keys=True)
        js_str = json.dumps(js_result["delta"], sort_keys=True)
        c.eq(f"admin.{name}", js_str, py_str)

    # ---- canonical JSON ----
    for i, case in enumerate(js.get("crypto", {}).get("canonical", [])):
        py_bytes = canonical_bytes(case["input"])
        c.eq(f"canonicalJson[{i}]", case["output"], py_bytes.decode("utf-8"))

    # ---- signing ----
    for entry in js.get("crypto", {}).get("signing", []):
        seed = base64.b64decode(entry["seed_b64"])
        dk = DeviceKey.from_private_bytes(seed)
        c.eq(
            f"signing.public_key[{entry['name']}]",
            base64.b64encode(dk.public_bytes).decode("ascii"),
            entry["public_key_b64"],
        )
        c.eq(f"signing.did[{entry['name']}]", dk.did, entry["did"])

        message = base64.b64decode(entry["message_b64"])
        py_sig = dk.sign(message)
        c.eq(
            f"signing.signature_raw[{entry['name']}]",
            base64.b64encode(py_sig).decode("ascii"),
            entry["signature_b64_raw"],
        )
        c.eq(
            f"signing.signature_b64url[{entry['name']}]",
            signature_b64(py_sig),
            entry["signature_b64url"],
        )
        # Cross-verify: Python verifies the JS signature.
        js_sig = base64.b64decode(entry["signature_b64_raw"])
        ok = DeviceKey.verify(entry["did"], message, js_sig)
        c.eq(f"signing.cross_verify[{entry['name']}]", ok, True)

    # ---- indexing ----
    idx = js.get("crypto", {}).get("indexing")
    if idx is not None:
        master = base64.b64decode(idx["master_b64"])
        gk = derive_group_index_key(master, idx["ceremony_id"], idx["group_name"], idx["epoch"])
        c.eq("indexing.group_key_hex", idx["group_key_hex"], gk.hex())
        for tok in idx["tokens"]:
            py_tok = index_token(gk, tok["field"], tok["value"])
            c.eq(f"indexToken[{tok['field']}={tok['value']}]", tok["token"], py_tok)

    # ---- row hash ----
    rh = js.get("crypto", {}).get("rowHash")
    if rh is not None:
        inp = rh["input"]
        py_rh = compute_row_hash(
            did=inp["did"],
            timestamp=inp["timestamp"],
            event_id=inp["event_id"],
            event_type=inp["event_type"],
            level=inp["level"],
            prev_hash=inp["prev_hash"],
            public_fields=inp["public_fields"],
            groups={
                g: {
                    "ciphertext": base64.b64decode(v["ciphertext_b64"]),
                    "field_hashes": v.get("field_hashes", {}),
                }
                for g, v in inp.get("groups", {}).items()
            },
        )
        c.eq("computeRowHash", rh["output"], py_rh)

    # ---- envelope ----
    env = js.get("crypto", {}).get("envelope")
    if env is not None:
        inp = env["input"]
        # _build_envelope signature in Python's logger emits the same
        # 9-field header + public fields + group payloads.
        py_line = build_envelope(
            did=inp["did"],
            timestamp=inp["timestamp"],
            event_id=inp["event_id"],
            event_type=inp["event_type"],
            level=inp["level"],
            sequence=inp["sequence"],
            prev_hash=inp["prev_hash"],
            row_hash=inp["row_hash"],
            signature=inp["signature_b64"],
            public_fields=inp["public_fields"],
            group_payloads=inp.get("group_payloads", {}),
        )
        c.eq("buildEnvelope", env["output"], py_line)

    print(f"\n{c.passed} passed, {c.failed} failed")
    return 0 if c.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
