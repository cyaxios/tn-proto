"""CLI verbs: ``tn vault link`` / ``tn vault unlink``.

Thin wrappers over the ``tn.vault`` SDK namespace
(:func:`tn.vault.link` / :func:`tn.vault.unlink`). These verbs only
*emit* the attested ``tn.vault.linked`` / ``tn.vault.unlinked`` events to
the ceremony's admin log; they do not create the vault project (that is
``tn wallet link``).

Mirrors the TypeScript ``vaultCmd`` in ``ts-sdk/bin/tn-js.mjs``: same two
subcommands, same ``--yaml`` / ``--reason`` flags, and the same JSON
receipt shape on stdout::

    {"ok": true, "verb": "vault.link", "event_id": "...",
     "row_hash": "...", "vault_did": "...", "project_id": "..."}

Unlike the TS SDK, the Python ``tn.vault.link`` / ``tn.vault.unlink``
return ``None`` (no receipt object), so the CLI reads the just-emitted
entry back from the admin log to recover ``event_id`` / ``row_hash`` for
the receipt. This is NOT a re-emit — the event was written by the SDK.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _die(msg: str, code: int = 1) -> int:
    """Print a CLI error and return the exit code (caller returns it)."""
    print(f"tn: error: {msg}", file=sys.stderr)
    return code


def _emit_and_read_receipt(
    args: argparse.Namespace, event_type: str, do_emit: Any
) -> int:
    """Shared body for both verbs.

    Resolves the yaml, inits the ceremony, runs ``do_emit`` (the SDK
    call that writes the attested event), then reads the matching entry
    back from the admin log to assemble the JSON receipt. Always closes
    the runtime in ``finally``.
    """
    import tn
    from tn.admin.log import resolve_admin_log_path

    if not args.vault_did or not args.project_id:
        verb = event_type.rsplit(".", 1)[-1]
        return _die(
            f"vault {verb}: <vault-did> and <project-id> are required positionals",
            2,
        )

    yaml_arg = getattr(args, "yaml", None)
    if yaml_arg:
        yaml_path = Path(yaml_arg).resolve()
        if not yaml_path.exists():
            return _die(f"yaml not found: {yaml_path}")
        tn.init(yaml_path)
    else:
        # No --yaml: rely on tn.init()'s discovery chain
        # ($TN_YAML, ./tn.yaml, ~/.tn/tn.yaml).
        try:
            tn.init()
        except Exception as exc:  # noqa: BLE001 — surface as a clean CLI error
            return _die(f"could not load a ceremony: {exc}")

    try:
        do_emit()

        # The SDK wrote the event to the admin log; read it back to
        # recover event_id / row_hash for the receipt. The matching
        # entry for this (vault_did, project_id) is the last one.
        admin_log = resolve_admin_log_path(tn.current_config())
        match = None
        for entry in tn.read(log=admin_log):
            if (
                entry.event_type == event_type
                and entry.fields.get("vault_identity") == args.vault_did
                and entry.fields.get("project_id") == args.project_id
            ):
                match = entry

        verb = event_type.rsplit(".", 1)[-1]
        receipt = {
            "ok": True,
            "verb": f"vault.{verb}",
            "event_id": match.event_id if match is not None else None,
            "row_hash": match.row_hash if match is not None else None,
            "vault_did": args.vault_did,
            "project_id": args.project_id,
        }
        sys.stdout.write(json.dumps(receipt) + "\n")
    finally:
        tn.flush_and_close()
    return 0


def cmd_vault_link(args: argparse.Namespace) -> int:
    """``tn vault link <vault-did> <project-id> [--yaml <path>]``.

    Emits ``tn.vault.linked`` via :func:`tn.vault.link`.
    """
    import tn

    return _emit_and_read_receipt(
        args,
        "tn.vault.linked",
        lambda: tn.vault.link(args.vault_did, args.project_id),
    )


def cmd_vault_unlink(args: argparse.Namespace) -> int:
    """``tn vault unlink <vault-did> <project-id> [--reason <r>] [--yaml <path>]``.

    Emits ``tn.vault.unlinked`` via :func:`tn.vault.unlink`.
    """
    import tn

    reason = getattr(args, "reason", None)
    return _emit_and_read_receipt(
        args,
        "tn.vault.unlinked",
        lambda: tn.vault.unlink(args.vault_did, args.project_id, reason),
    )
