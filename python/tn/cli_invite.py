"""`tn invite` — mint a real `tn-invite-<id>.zip` from the CLI.

This is the secure successor to the server's invitation wrapper. Until
this verb existed, the outer wrapper was produced *only* server-side by
the web vault, so a faithful same-language round-trip
(``mint invite zip -> inbox accept``) was impossible inside ``tn_proto``.

The verb is a thin shim over primitives that already exist:

* the **inner package** is minted by ``tn.admin.add_recipient(group,
  recipient_did=..., out_path=<tmp>.tnpkg)``. That canonical path signs
  the package and recipient-seals its body to the reader's real DID key.
* the **outer wrapper** is built by :func:`make_invitation_zip`, which
  wraps ``{kit.tnpkg, manifest.json}``; the outer manifest binds the
  package hash, group, and sender metadata.

Usage::

    tn invite <recipient> <out.zip> [--group default] [--yaml ./tn.yaml]

``<recipient>`` must be a resolvable Ed25519 ``did:key``. Placeholder DIDs
cannot authenticate recipient delivery and are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _kit_entry_name(_group: str | None) -> str:
    """Return the canonical signed-package entry name for a secure invite."""
    return "kit.tnpkg"


def make_invitation_zip(kit_bytes: bytes, manifest: dict) -> bytes:
    """Build the wrapper invitation archive in memory and return its bytes.

    Mirror of ``tn_proto_web`` ``routes_invite._make_invitation_zip``. The
    wrapper holds exactly two entries:

    * ``kit.tnpkg`` — a signed package whose body is recipient-sealed.
    * ``manifest.json`` — invitation metadata (group, leaf index,
      kit_sha256, sender info), pretty-printed.
    """
    buf = BytesIO()
    kit_name = _kit_entry_name(manifest.get("group_name"))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(kit_name, kit_bytes)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buf.getvalue()


def cmd_invite(args: argparse.Namespace) -> int:
    """Mint a real recipient kit and wrap it as a ``tn-invite-<id>.zip``.

    Steps (all over existing machinery — nothing hand-built):

    1. Resolve + init the publisher's ceremony.
    2. Mint a signed, recipient-sealed package via
       ``tn.admin.add_recipient(...)`` (records the attested
       ``tn.recipient.added`` event and returns the ``leaf_index``).
    3. Compute ``kit_sha256`` over the package bytes.
    4. Assemble the ``manifest.json`` and zip it next to the kit via
       :func:`make_invitation_zip`.
    """
    from . import admin, current_config, flush_and_close
    from . import init as tn_init
    from .cli_common import _resolve_yaml_or_discover

    yaml_path = _resolve_yaml_or_discover(args.yaml)

    recipient_did = args.recipient
    from .recipient_seal import recipient_key_is_resolvable

    if not recipient_key_is_resolvable(recipient_did):
        raise ValueError(
            "tn invite requires the recipient's real Ed25519 did:key so "
            "the reader package can be recipient-sealed"
        )

    group = args.group
    out_path = Path(args.out).expanduser().resolve()

    tn_init(str(yaml_path))
    try:
        cfg = current_config()
        group_spec = cfg.groups.get(group)
        if group_spec is None:
            raise KeyError(f"unknown group: {group!r}")
        if group_spec.cipher.name != "btn":
            raise ValueError("tn invite currently supports BTN reader kits only")

        # 2. Mint the canonical signed package. With the resolvable DID gate
        # above, add_recipient seals the package body to this recipient.
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".tnpkg", dir=str(out_path.parent)
        ) as tf:
            kit_path = Path(tf.name)
        try:
            add_result = admin.add_recipient(
                group,
                recipient_did=recipient_did,
                out_path=str(kit_path),
            )
            leaf_index = add_result.leaf_index
            kit_bytes = kit_path.read_bytes()
        finally:
            if kit_path.exists():
                kit_path.unlink()

        # 3. Hash (sha256:<hex>, matching the server + accept verb).
        kit_sha256 = "sha256:" + hashlib.sha256(kit_bytes).hexdigest()

        # 4. Manifest + wrapper zip. Field set mirrors the server manifest
        #    (routes_invite.invite_reader): the keys inbox.accept reads are
        #    group_name, leaf_index, from_email, from_account_did, kit_sha256.
        # Opaque unique id; the server treats it as a plain string
        # (routes_invite declares `invitation_id: str`, no format check).
        invitation_id = str(uuid.uuid4())
        from_did = cfg.device.device_identity
        manifest = {
            "invitation_id": invitation_id,
            "from_account_did": from_did,
            "from_email": getattr(args, "from_email", None) or from_did,
            "project_id": getattr(cfg, "linked_project_id", None),
            "project_name": getattr(cfg, "project_name", None) or "",
            "group_name": group,
            "leaf_index": leaf_index,
            "kit_sha256": kit_sha256,
            "kit_format": "tnpkg",
            "delivery": "recipient-seal-v1",
            "event_id": None,
            "created_at": _now_iso(),
            "note": getattr(args, "note", None),
            "provenance": "cli-minted",
        }
        zip_bytes = make_invitation_zip(kit_bytes, manifest)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(zip_bytes)
    finally:
        flush_and_close()

    print(f"[tn invite] wrote {out_path}")
    print(f"[tn invite]   group:     {group}")
    print(f"[tn invite]   recipient: {recipient_did}")
    print(f"[tn invite]   leaf:      {leaf_index}")
    print(f"[tn invite]   kit_sha256:{kit_sha256}")
    print(f"[tn invite]   inner kit: {_kit_entry_name(group)}")
    return 0


def add_invite_parser(sub: argparse._SubParsersAction) -> None:
    """Register the ``tn invite`` subcommand on the top-level parser.

    Factored out so ``cli.py`` wires it with one call (keeping the dispatch
    registration close to the other verbs) without importing the handler
    body eagerly.
    """
    p_invite = sub.add_parser(
        "invite",
        help="Mint a real tn-invite-<id>.zip (kit + manifest) for one recipient.",
    )
    p_invite.add_argument(
        "recipient",
        help="Recipient's real Ed25519 device DID (did:key:z...).",
    )
    p_invite.add_argument("out", help="Destination tn-invite-<id>.zip path.")
    p_invite.add_argument(
        "--group",
        default="default",
        help="Group to mint the kit for (default: default).",
    )
    p_invite.add_argument(
        "--yaml",
        default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_invite.add_argument(
        "--from-email",
        dest="from_email",
        default=None,
        help="Sender email recorded in the manifest (default: your device DID).",
    )
    p_invite.add_argument(
        "--note",
        default=None,
        help="Free-form note the recipient sees alongside the invitation.",
    )
    p_invite.set_defaults(func=cmd_invite)
