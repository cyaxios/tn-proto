"""Python side of the cross-impl project_seed interop test (GAP: project_seed).

Driven by ts-sdk/test/project_seed_interop.test.ts. Proves the
``project_seed`` ``.tnpkg`` (full-ceremony identity + config backup)
round-trips between the TS SDK and the reference Python implementation in
BOTH directions.

``project_seed`` carries KEYS + CONFIG, not the event log (see project
memory). So a successful restore is proven by: the restored ceremony has
the SAME device DID, the SAME group set, AND can OPERATE — emit a fresh
entry and read it back through the restored btn keystore. It is NOT
proven by replaying the producer's original log (there is none in the
bundle).

Subcommands (each prints exactly ONE json object to stdout):

  * ``export <out_path>``
        Build a fresh btn ceremony in a temp dir (``tn.init`` mints the
        complete keystore: local.private/public, index_master, and the
        ``default`` + ``tn.agents`` btn self-state/self-kit), then
        ``tn.export(kind="project_seed", confirm_includes_secrets=True)``.
        Prints ``{did, groups}`` — the identity + group set the TS side
        must see after it absorbs the bundle.

  * ``absorb <tnpkg_path> <dest_dir>``
        Absorb a TS-produced project_seed bundle into ``dest_dir`` via the
        cwd-bootstrap path (``tn.absorb`` with no prior ``tn.init`` —
        synthesizes a cfg from cwd + the bundle's ``body/tn.yaml`` and
        auto-binds the runtime to the freshly-written ``./tn.yaml``).
        Then PROVE OPERATE: ``tn.info`` a fresh entry and ``tn.read`` it
        back. Prints the installed DID, the DID re-derived from the
        installed private seed, the restored group set, and the read-back
        entry (event_type + fields).

stdout is routed through the raw buffer so Windows does not rewrite
``\n`` -> ``\r\n`` (the TS side reads stdout as utf8 + json-parses it).
``TN_AUTOINIT_QUIET=1`` is set before importing ``tn`` so the one-time
autoinit banner never lands on stdout and corrupts the json payload.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Keep stdout clean for the json payload the TS side parses:
#   * TN_AUTOINIT_QUIET=1 — suppress the one-time autoinit banner.
#   * TN_NO_STDOUT=1       — suppress the per-event stdout log handler so a
#                           `tn.info(...)` during the operate-proof does not
#                           echo a human log line onto stdout.
# Both must be set BEFORE `tn` is imported / any verb runs.
os.environ.setdefault("TN_AUTOINIT_QUIET", "1")
os.environ.setdefault("TN_NO_STDOUT", "1")

_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


# Import the in-tree `tn` package from this worktree's python/ dir, exactly
# like the sibling interop helpers. ts-sdk/test/ -> ts-sdk -> <root>;
# <root>/python is the package parent.
TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def _do_export(out_path: str) -> int:
    import tempfile

    import tn

    # Build a complete, fresh btn ceremony in an isolated temp dir. A fresh
    # `tn.init` mints the full keystore (both the `default` and the
    # implicit `tn.agents` group btn self-state/self-kit), which is exactly
    # what project_seed must back up for an operable restore.
    src = Path(tempfile.mkdtemp(prefix="tn-ps-py-export-"))
    prev_cwd = os.getcwd()
    os.chdir(src)
    try:
        tn.init(str(src / "tn.yaml"))
        cfg = tn.current_config()
        did = str(cfg.device.did)
        groups = sorted(cfg.groups.keys())
        tn.export(out_path, kind="project_seed", confirm_includes_secrets=True)
    finally:
        os.chdir(prev_cwd)

    _write(json.dumps({"did": did, "groups": groups}, sort_keys=True) + "\n")
    return 0


def _do_absorb(tnpkg_path: str, dest_dir: str) -> int:
    import tn
    from tn.signing import DeviceKey

    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    # The single-arg bootstrap absorb derives its keystore from cwd and the
    # bundle's body/tn.yaml; chdir so the install lands in dest, isolated
    # from any ambient ceremony. absorb() auto-binds the runtime to the
    # freshly-written ./tn.yaml, so the follow-up tn.info / tn.read operate
    # on the RESTORED ceremony.
    prev_cwd = os.getcwd()
    os.chdir(dest)
    try:
        receipt = tn.absorb(tnpkg_path)
        rejected = getattr(receipt, "legacy_status", None) == "rejected"

        installed_did = None
        derived_did = None
        restored_groups = None
        readback_event_type = None
        readback_fields = None
        operate_ok = False

        if not rejected:
            cfg = tn.current_config()
            keys = cfg.keystore
            pub_path = keys / "local.public"
            priv_path = keys / "local.private"
            if pub_path.exists():
                installed_did = pub_path.read_text(encoding="utf-8").strip()
            if priv_path.exists():
                derived_did = DeviceKey.from_private_bytes(priv_path.read_bytes()).did
            restored_groups = sorted(cfg.groups.keys())

            # Prove the restored keys/config OPERATE: emit a fresh entry and
            # read it back through the restored btn keystore.
            tn.info("order.created", amount=4242, marker="ps-interop-a")
            user_rows = [e for e in tn.read() if not e.event_type.startswith("tn.")]
            if user_rows:
                last = user_rows[-1]
                readback_event_type = last.event_type
                readback_fields = last.fields
                operate_ok = True
    finally:
        os.chdir(prev_cwd)

    payload = {
        "kind": getattr(receipt, "kind", None),
        "status": getattr(receipt, "legacy_status", None),
        "reason": getattr(receipt, "legacy_reason", None),
        "accepted_count": getattr(receipt, "accepted_count", None),
        "installed_did": installed_did,
        "derived_did": derived_did,
        "restored_groups": restored_groups,
        "operate_ok": operate_ok,
        "readback_event_type": readback_event_type,
        "readback_fields": readback_fields,
    }
    _write(json.dumps(payload, sort_keys=True, default=str) + "\n")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: project_seed_py_helper.py export|absorb ...\n")
        return 1
    cmd = sys.argv[1]
    if cmd == "export":
        if len(sys.argv) < 3:
            sys.stderr.write("export requires <out_path>\n")
            return 1
        return _do_export(sys.argv[2])
    if cmd == "absorb":
        if len(sys.argv) < 4:
            sys.stderr.write("absorb requires <tnpkg_path> <dest_dir>\n")
            return 1
        return _do_absorb(sys.argv[2], sys.argv[3])
    sys.stderr.write(f"unknown subcommand {cmd!r}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
