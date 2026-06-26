"""``tn admin <sub>`` — low-level ceremony admin sub-dispatcher.

Mirrors the TypeScript ``tn admin`` verb group (``ts-sdk/src/cli/admin.ts`` +
the ``case "admin"`` wrapper in ``ts-sdk/bin/tn-js.mjs``). It is the
machine-shaped, JSON-on-stdout counterpart to the friendlier top-level verbs
(``tn add_recipient`` / ``tn rotate``): each subcommand prints a single
``{"ok": true, ...}`` JSON line and reuses the SAME ``tn.admin.*`` SDK
functions the top-level verbs call, so e.g. ``tn admin rotate`` and ``tn
rotate`` drive an identical rotation.

    tn admin add-recipient    --yaml <p> --group <g> --out <kit> [--recipient-did <did>]
    tn admin revoke-recipient --yaml <p> --group <g> --leaf <i> [--recipient-did <did>]
    tn admin revoked-count    --yaml <p> --group <g>
    tn admin rotate           --yaml <p> [--group <g> | --groups a,b] [--out <dir|.tnpkg>]

``revoke-recipient`` is the genuinely new capability on the Python side —
there was previously no CLI path to revoke a btn recipient (the SDK exposed
``tn.admin.revoke_recipient`` but no verb wired to it).

The new file is thin over ``tn.admin`` (imported as ``_admin``, matching
``cli_pkg.py``) and reuses ``cli_pkg``'s rotate helpers so the rotation
output stays consistent with ``tn rotate``.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import tn

from . import admin as _admin
from .cli_common import _die, _resolve_yaml_or_discover
from .cli_pkg import (
    _rotate_emit_bundles,
    _rotate_resolve_output,
    _rotate_select_groups,
    _rotate_snapshot_recipients,
)
from .pkg import bundle_for_recipient


def _emit(obj: dict) -> None:
    """Print one JSON line to stdout — the TS ``process.stdout.write(JSON + "\n")``
    shape, so machine consumers parse a single object per subcommand."""
    print(json.dumps(obj))


# ---------------------------------------------------------------------
# tn admin add-recipient --group <g> --out <kit> [--recipient-did <did>]
# ---------------------------------------------------------------------


def cmd_admin_add_recipient(args: argparse.Namespace) -> int:
    """Register a recipient on a group and mint their reader kit.

    Reuses ``tn.admin.add_recipient`` (the same function the higher-level
    ``tn add_recipient`` / ``tn bundle`` path bottoms out in). ``--out`` is
    required, mirroring the TS subcommand. The kit path shape (raw
    ``<group>.btn.mykit`` vs an absorbable ``.tnpkg``) is decided by
    ``tn.admin.add_recipient`` from the ``--out`` suffix.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    if not args.out:
        _die("admin add-recipient: --out <kit-path> is required", code=2)

    tn.init(yaml_path)
    try:
        result = _admin.add_recipient(
            args.group,
            out_path=args.out,
            recipient_did=args.recipient_did,
        )
    finally:
        tn.flush_and_close()

    _emit(
        {
            "ok": True,
            "group": args.group,
            "leaf_index": result.leaf_index,
            "kit_path": str(result.kit_path) if result.kit_path is not None else args.out,
            "recipient_did": args.recipient_did,
        }
    )
    return 0


# ---------------------------------------------------------------------
# tn admin revoke-recipient --group <g> --leaf <i> [--recipient-did <did>]
# ---------------------------------------------------------------------


def cmd_admin_revoke_recipient(args: argparse.Namespace) -> int:
    """Revoke a recipient from a group. The genuinely new Python CLI
    capability — wires ``tn.admin.revoke_recipient`` to a verb.

    btn groups revoke by ``--leaf`` (the TS subcommand requires it) or, as
    a Python convenience that the SDK already supports, by
    ``--recipient-did`` (resolved to the active leaf via the admin log).
    JWE groups revoke by ``--recipient-did``.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    if args.leaf is None and args.recipient_did is None:
        _die(
            "admin revoke-recipient: --leaf <index> is required "
            "(or --recipient-did for did-based revocation)",
            code=2,
        )

    tn.init(yaml_path)
    try:
        _admin.revoke_recipient(
            args.group,
            leaf_index=args.leaf,
            recipient_did=args.recipient_did,
        )
    finally:
        tn.flush_and_close()

    _emit({"ok": True, "group": args.group, "leaf_index": args.leaf})
    return 0


# ---------------------------------------------------------------------
# tn admin revoked-count --group <g>
# ---------------------------------------------------------------------


def cmd_admin_revoked_count(args: argparse.Namespace) -> int:
    """Print the number of revoked recipients in a btn group's state.
    Thin over ``tn.admin.revoked_count``."""
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path)
    try:
        count = _admin.revoked_count(args.group)
    finally:
        tn.flush_and_close()

    _emit({"ok": True, "group": args.group, "count": count})
    return 0


# ---------------------------------------------------------------------
# tn admin rotate [--group <g> | --groups a,b] [--out <dir|.tnpkg>]
# ---------------------------------------------------------------------


def cmd_admin_rotate(args: argparse.Namespace) -> int:
    """Rotate group key material and emit per-recipient kit_bundle .tnpkg
    artifacts — JSON-shaped sibling of ``tn rotate``.

    Reuses ``cli_pkg``'s rotate helpers and ``tn.admin.rotate`` so the
    rotation itself is identical to ``tn rotate``; only the output is the
    TS ``{"ok": true, "rotated": [...], "artifacts": [...]}`` JSON line.

    Group selection mirrors the TS subcommand:

      * ``--group <g>``  — single group
      * ``--groups a,b`` — explicit subset
      * neither          — every non-internal group (excludes ``tn.agents``)
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path)
    try:
        cfg = tn.current_config()
        target_groups = _rotate_select_groups(args, cfg)

        # Snapshot surviving recipients PRE-rotation (shared helper).
        recipient_groups = _rotate_snapshot_recipients(target_groups)

        # Rotate each group via the SAME tn.admin.rotate the top-level
        # `tn rotate` verb calls.
        rotated: list[dict] = []
        for g in target_groups:
            res = _admin.rotate(g)
            rotated.append({"group": g, "generation": res.generation or 0})

        if not recipient_groups:
            _emit(
                {
                    "ok": True,
                    "rotated": rotated,
                    "artifacts": [],
                    "note": "no surviving recipients to bundle for; rotation recorded",
                }
            )
            return 0

        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out_dir, single_file = _rotate_resolve_output(
            args.out, len(recipient_groups), ts
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        artifacts = _rotate_emit_bundles(
            recipient_groups, out_dir, single_file, bundle_for_recipient
        )

        _emit(
            {
                "ok": True,
                "rotated": rotated,
                "artifacts": [str(Path(a)) for a in artifacts],
                "out_dir": str(out_dir),
            }
        )
        return 0
    finally:
        tn.flush_and_close()
