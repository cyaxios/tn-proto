"""Generate (kit, ciphertext, plaintext) fixture triples for the
extension's Node-side interop test.

The extension's `wasm/tn_wasm.js` bundle is the production decrypt path
that runs in every user's browser. This script writes Python-produced
artifacts into a temp dir; `python_interop.mjs` then loads the EXACT
extension wasm bundle and asserts it can decrypt them.

That direction is the one users see: a service generating btn ciphertext
in Python, the user's browser extension reading it. The forward path
(JS -> Python) is already covered by tnproto-org/static/dashboard/test/
wasm_e2e.test.mjs + tn-protocol/python/tests/test_browser_wasm_interop.py.

Refs:
  - D-26 (atomic CAS — informs determinism: same plaintext always works)
  - D-22 (passphrase fallback — orthogonal, but this fixture path is a
    natural place to verify our fixture construction is independent of
    unlock state)

Usage:
  python python_fixture_gen.py <out_dir>

Writes:
  <out_dir>/kit.bin           raw .btn.mykit bytes
  <out_dir>/ciphertext.bin    raw btn ciphertext for plaintext below
  <out_dir>/plaintext.json    plaintext (UTF-8 JSON we expect back)
  <out_dir>/meta.json         publisher_id_hex + sizes for sanity checks
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python_fixture_gen.py <out_dir>", file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    try:
        import tn_btn  # type: ignore
    except ImportError as exc:
        print(f"tn_btn not importable from this Python: {exc}", file=sys.stderr)
        return 3

    # Mint a fresh publisher and self-kit. PublisherState seeds itself
    # internally (CSPRNG) — no need to pass a seed, just like the vault
    # does for first-time ceremonies.
    state = tn_btn.PublisherState()
    kit = state.mint()

    plaintext_obj = {
        "source": "python_fixture_gen",
        "customer_name": "Charlie",
        "amount": 42.5,
        "note": "Python -> extension wasm interop",
    }
    plaintext_bytes = json.dumps(plaintext_obj, sort_keys=True).encode("utf-8")
    ciphertext = state.encrypt(plaintext_bytes)

    # Sanity-check on the Python side that the fixture round-trips
    # before we hand it off to JS — saves a lot of debugging if
    # something is wrong on this side.
    rt = tn_btn.decrypt(kit, ciphertext)
    if rt != plaintext_bytes:
        print("python self-decrypt does not round-trip", file=sys.stderr)
        return 4

    pub_id = tn_btn.kit_publisher_id(kit) if hasattr(tn_btn, "kit_publisher_id") else b""

    (out / "kit.bin").write_bytes(kit)
    (out / "ciphertext.bin").write_bytes(ciphertext)
    (out / "plaintext.json").write_bytes(plaintext_bytes)
    meta = {
        "kit_len": len(kit),
        "ciphertext_len": len(ciphertext),
        "plaintext_len": len(plaintext_bytes),
        "publisher_id_hex": pub_id.hex() if pub_id else None,
        "plaintext_obj": plaintext_obj,
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"wrote fixture to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
