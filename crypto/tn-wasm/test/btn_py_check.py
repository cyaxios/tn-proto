"""btn interop cross-check (Python side).

Reads btn_fixture.json produced by btn_interop.mjs. Re-derives the
publisher from the shared seed, asserts publisher_id matches, decrypts
each JS-produced ciphertext with each kit, revokes, and writes its own
ciphertext batch back into the fixture so the Node side can decrypt
those with --verify-py.

Run with the project venv:
    .venv/Scripts/python.exe tn-protocol/crypto/tn-wasm/test/btn_py_check.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    try:
        from btn import PublisherState, decrypt as btn_decrypt, ciphertext_publisher_id, kit_publisher_id, kit_leaf
    except Exception as exc:
        print(f"[fail] could not import btn: {exc}")
        print("       run  cd tn-protocol/crypto/btn-py && maturin develop  first")
        return 2

    fx_path = HERE / "btn_fixture.json"
    if not fx_path.exists():
        print(f"[fail] missing {fx_path}. Run node test/btn_interop.mjs first.")
        return 2
    fx = json.loads(fx_path.read_text("utf-8"))
    passed = failed = 0

    def ok(name: str) -> None:
        nonlocal passed
        print(f"[ok]   {name}")
        passed += 1

    def fail(name: str, why: object = "") -> None:
        nonlocal failed
        print(f"[fail] {name}: {why}")
        failed += 1

    seed = base64.b64decode(fx["seed_b64"])
    pub = PublisherState(seed=seed)

    if pub.publisher_id.hex() == fx["publisher_id_hex"]:
        ok("publisher_id matches across JS and Python")
    else:
        fail(
            "publisher_id matches across JS and Python",
            f"js={fx['publisher_id_hex']} py={pub.publisher_id.hex()}",
        )

    # Kits from JS decode cleanly, and their publisher_id matches.
    for name, kit_b64 in fx["kits"].items():
        kit = base64.b64decode(kit_b64)
        if kit_publisher_id(kit).hex() == fx["publisher_id_hex"]:
            ok(f"kit {name} publisher_id matches")
        else:
            fail(f"kit {name} publisher_id matches")

    # Python decrypts every JS ciphertext with every JS kit.
    payloads = [base64.b64decode(p) for p in fx["payloads"]]
    cts = [base64.b64decode(c) for c in fx["ciphertexts"]]
    for i, ct in enumerate(cts):
        # Sanity: publisher_id on ct.
        if ciphertext_publisher_id(ct).hex() != fx["publisher_id_hex"]:
            fail(f"ct[{i}] publisher_id matches")
            continue
        for kname, kit_b64 in fx["kits"].items():
            kit = base64.b64decode(kit_b64)
            pt = btn_decrypt(kit, ct)
            if pt == payloads[i]:
                ok(f"py decrypt JS ct[{i}] with kit {kname}")
            else:
                fail(
                    f"py decrypt JS ct[{i}] with kit {kname}",
                    f"got {pt!r}, expected {payloads[i]!r}",
                )

    # Now have Python independently re-derive its own publisher from the
    # same seed, mint 3 kits (they must be byte-identical to the JS
    # kits because the seed + tree is deterministic), then encrypt the
    # same payloads. The JS side will decrypt in --verify-py mode.
    py_pub = PublisherState(seed=seed)
    py_kits = [py_pub.mint(), py_pub.mint(), py_pub.mint()]
    for (js_name, js_b64), py_kit in zip(fx["kits"].items(), py_kits):
        if py_kit == base64.b64decode(js_b64):
            ok(f"py mint kit {js_name} matches JS bytes")
        else:
            # Kits include internal path-key layout; bytes should match
            # for the same seed. If not, that's a serious interop bug.
            fail(
                f"py mint kit {js_name} matches JS bytes",
                f"py len={len(py_kit)}, js len={len(base64.b64decode(js_b64))}",
            )

    py_cts = [py_pub.encrypt(p) for p in payloads]
    fx["py_ciphertexts"] = [base64.b64encode(c).decode("ascii") for c in py_cts]

    # Python decrypt Python ciphertexts with JS kits (just to be sure).
    for i, pct in enumerate(py_cts):
        for kname, kit_b64 in fx["kits"].items():
            kit = base64.b64decode(kit_b64)
            pt = btn_decrypt(kit, pct)
            if pt == payloads[i]:
                ok(f"py decrypt py ct[{i}] with JS kit {kname}")
            else:
                fail(f"py decrypt py ct[{i}] with JS kit {kname}")

    # Write fixture back for the JS --verify-py pass.
    fx_path.write_text(json.dumps(fx, indent=2) + "\n", encoding="utf-8")

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
