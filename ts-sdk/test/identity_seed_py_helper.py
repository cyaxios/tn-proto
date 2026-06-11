"""Python side of the cross-impl identity_seed interop test (GAP 2).

Driven by ts-sdk/test/identity_seed_interop.test.ts. Proves the
identity_seed `.tnpkg` round-trips between the TS SDK and the reference
Python implementation in BOTH directions:

  * `export`: build an identity_seed tnpkg from a known 32-byte seed via
    Python's `tn.export(kind="identity_seed", device=...)`. The TS side
    then absorbs it and must derive the SAME device DID.
  * `absorb`: absorb a TS-produced identity_seed tnpkg via Python's
    low-level `tn.absorb.absorb(source)` bootstrap path (which installs
    local.private / local.public / tn.yaml into <cwd>/.tn/tn/keys), then
    report the installed DID + the DID re-derived from the installed
    private seed. The TS side asserts both equal the seed's DID — i.e.
    Python installed an operable identity from the TS bundle.

Usage:
    python identity_seed_py_helper.py export <out_path> <seed_hex> [nickname]
    python identity_seed_py_helper.py absorb <tnpkg_path> <dest_dir>

Both subcommands print ONE json object to stdout.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def _do_export(out_path: str, seed_hex: str, nickname: str | None) -> int:
    from tn.signing import DeviceKey

    export = importlib.import_module("tn.export").export

    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        sys.stderr.write(f"seed must be 32 bytes; got {len(seed)}\n")
        return 1
    device = DeviceKey.from_private_bytes(seed)
    export(out_path, kind="identity_seed", device=device, nickname=nickname)
    _write(json.dumps({"did": device.did}, sort_keys=True) + "\n")
    return 0


def _do_absorb(tnpkg_path: str, dest_dir: str) -> int:
    from tn.signing import DeviceKey

    absorb = importlib.import_module("tn.absorb").absorb

    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    # The single-arg bootstrap absorb derives its keystore from cwd
    # (<cwd>/.tn/tn/keys). chdir so the install lands in dest, isolated
    # from any ambient ceremony.
    prev_cwd = os.getcwd()
    os.chdir(dest)
    try:
        receipt = absorb(tnpkg_path)
    finally:
        os.chdir(prev_cwd)

    keys = dest / ".tn" / "tn" / "keys"
    pub_path = keys / "local.public"
    priv_path = keys / "local.private"
    installed_did = pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else None
    derived_did = None
    if priv_path.exists():
        derived_did = DeviceKey.from_private_bytes(priv_path.read_bytes()).did

    payload = {
        "kind": getattr(receipt, "kind", None),
        "status": getattr(receipt, "legacy_status", None),
        "reason": getattr(receipt, "legacy_reason", None),
        "accepted_count": getattr(receipt, "accepted_count", None),
        "noop": getattr(receipt, "noop", None),
        "installed_did": installed_did,
        "derived_did": derived_did,
    }
    _write(json.dumps(payload, sort_keys=True, default=str) + "\n")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "usage: identity_seed_py_helper.py export|absorb ...\n"
        )
        return 1
    cmd = sys.argv[1]
    if cmd == "export":
        if len(sys.argv) < 4:
            sys.stderr.write("export requires <out_path> <seed_hex> [nickname]\n")
            return 1
        nickname = sys.argv[4] if len(sys.argv) > 4 else None
        return _do_export(sys.argv[2], sys.argv[3], nickname)
    if cmd == "absorb":
        if len(sys.argv) < 4:
            sys.stderr.write("absorb requires <tnpkg_path> <dest_dir>\n")
            return 1
        return _do_absorb(sys.argv[2], sys.argv[3])
    sys.stderr.write(f"unknown subcommand {cmd!r}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
