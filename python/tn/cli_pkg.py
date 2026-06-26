"""``tn`` packaging verbs: bundle / add_recipient / group add / absorb /
import / export / rotate.

The recipient-flow + deploy primitives. `bundle` / `add_recipient` mint a
kit_bundle .tnpkg for a recipient; `group add` extends a ceremony; `absorb`
installs a .tnpkg into the active ceremony; `import` bootstraps a ceremony from
a project_seed; `export` mints one; `rotate` bumps group epochs and emits one
kit_bundle per surviving recipient. Thin over `tn.pkg` and `tn.admin`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import zipfile
from pathlib import Path

import tn

from . import admin as _admin
from .cli_common import _die, _resolve_yaml_or_discover
from .pkg import absorb, bundle_for_recipient
from .pkg import export as pkg_export

# ---------------------------------------------------------------------
# `tn bundle <yaml> <recipient_did> <out>`
# `tn absorb <yaml> <package>`
# `tn read   <yaml> [<log>]`
# Three small recipient-flow verbs that mirror the cookbook §7 path so
# the cash-_register Stage 6 workflow is one CLI call per step. Closes
# FINDINGS #9.
# ---------------------------------------------------------------------


def cmd_bundle(args: argparse.Namespace) -> int:
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path)
    try:
        groups = args.groups.split(",") if args.groups else None
        out = bundle_for_recipient(
            args.recipient,
            args.out,
            groups=groups,
            seal_for_recipient=getattr(args, "seal_for_recipient", False),
        )
        cfg = tn.current_config()
        # The bundle was just minted — every requested group has a fresh
        # tn.recipient.added event in the log. Print a one-line summary
        # the user can hand off alongside the .tnpkg.
        print(f"[tn bundle] wrote {out}")
        print(f"[tn bundle]   recipient: {args.recipient}")
        print(f"[tn bundle]   ceremony:  {cfg.ceremony_id}  (cipher={cfg.cipher_name})")
        print(f"[tn bundle]   groups:    {groups or sorted(g for g in cfg.groups if g != 'tn.agents')}")
    finally:
        tn.flush_and_close()
    return 0


def cmd_add_recipient(args: argparse.Namespace) -> int:
    """Friendlier shape that matches the cash-_register assignment's
    expected line (FINDINGS S6.4)::

        python -m tn add_recipient <group> <did-or-label> [--out path]

    A bare label like ``professor`` is allowed — when it doesn't look
    like a DID we synthesize a fake one (``did:key:zLabel-<label>``) so
    the attestation event still records *something* identifiable. For
    real workflows, pass the recipient's actual DID.

    Output filename defaults to ``./<safe-label>.tnpkg`` so the student's
    one-line workflow ``... add_recipient default professor`` works as
    written. The yaml is auto-discovered via the standard chain.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    label = args.recipient
    if label.startswith("did:"):
        recipient_did = label
        out_default_stem = re.sub(r"[^A-Za-z0-9._-]", "_", label.split(":")[-1])
    else:
        # Stable placeholder DID from the label — recorded on the
        # attestation event so the kit-recipient lookup works.
        recipient_did = f"did:key:zLabel-{label}"
        out_default_stem = re.sub(r"[^A-Za-z0-9._-]", "_", label) or "recipient"

    # --seal-for-recipient needs a real key-DID to wrap the body under
    # the recipient's actual public key. A friendly label like
    # `did:key:zLabel-foo` has no embedded base58 public key, so the
    # seal path would fail deep inside `_did_key_to_ed25519_pub`. Reject
    # the combination here with a clear message.
    if getattr(args, "seal_for_recipient", False) and (
        not label.startswith("did:") or recipient_did.startswith("did:key:zLabel-")
    ):
        print(
            "[tn add_recipient] error: --seal-for-recipient requires a real "
            "key-DID for the recipient (one with an embedded base58 public "
            "key). Friendly labels synthesize a placeholder DID that has no "
            f"public key, so the seal step has nothing to wrap under. Got "
            f"{label!r}. Pass the recipient's real did:key:z... instead, or "
            "drop --seal-for-recipient to ship an unsealed kit bundle.",
            file=sys.stderr,
        )
        return 2

    out_path = Path(args.out).resolve() if args.out else Path.cwd() / f"{out_default_stem}.tnpkg"

    tn.init(yaml_path)
    try:
        groups = [args.group]
        out = bundle_for_recipient(
            recipient_did,
            out_path,
            groups=groups,
            seal_for_recipient=getattr(args, "seal_for_recipient", False),
        )
        print(f"[tn add_recipient] wrote {out}")
        print(f"[tn add_recipient]   group:     {args.group}")
        print(f"[tn add_recipient]   recipient: {recipient_did}")
    finally:
        tn.flush_and_close()
    return 0


def cmd_group_add(args: argparse.Namespace) -> int:
    """Add a group to an existing ceremony post-init::

        python -m tn group add <name> [--fields a,b,c] [--cipher btn|jwe]

    Group-add was previously API-only (``tn.ensure_group``). Under the
    multi-ceremony layout the group is written to the authoritative
    project-root yaml (the head of a stream's ``extends:`` chain), so it
    persists for fresh-process readers and a later ``tn add_recipient``.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    fields = (
        [f.strip() for f in args.fields.split(",") if f.strip()]
        if args.fields
        else None
    )

    tn.init(yaml_path)
    try:
        cfg = tn.current_config()
        tn.ensure_group(cfg, args.name, fields=fields, cipher=args.cipher)
        print(f"[tn group add] added group {args.name!r}")
        if fields:
            print(f"[tn group add]   fields: {', '.join(fields)}")
        print(f"[tn group add]   cipher: {args.cipher or cfg.cipher_name}")
    finally:
        tn.flush_and_close()
    return 0


def cmd_absorb(args: argparse.Namespace) -> int:
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    package = Path(args.package).resolve()
    if not package.exists():
        _die(f"package not found: {package}")

    tn.init(yaml_path)
    # 0.4.2a9: reject self-absorb. A .tnpkg whose `from_did` matches the
    # active ceremony's DID means the publisher is trying to absorb a
    # bundle they just minted — that overwrites their OWN publisher
    # keystore with a reader-kit copy. The absorb path warns on the
    # collision but proceeds; that's a foot-cannon in a CLI. Block it
    # at the verb so the user has to use `--allow-self-absorb` (escape
    # hatch for tests).
    try:
        with zipfile.ZipFile(package) as zf:
            if "manifest.json" in zf.namelist():
                m = json.loads(zf.read("manifest.json").decode("utf-8"))
                from_did = m.get("publisher_identity")
                local_did = tn.current_config().device.did
                if from_did and from_did == local_did and not getattr(
                    args, "allow_self_absorb", False
                ):
                    tn.flush_and_close()
                    _die(
                        f"refusing to absorb a package this ceremony minted "
                        f"(from_did={from_did}). Absorbing it would overwrite "
                        f"the publisher's own keystore with a reader-kit "
                        f"copy. Pass --allow-self-absorb if you actually "
                        f"intend to do this (tests, recovery flows).",
                        code=2,
                    )
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError):
        # Not a zip / no manifest / bad JSON — let the real absorb path
        # produce its own error message about the corrupt package.
        pass

    try:
        receipt = absorb(package)
    finally:
        tn.flush_and_close()

    kind = getattr(receipt, "kind", "?")
    accepted = getattr(receipt, "accepted_count", 0)
    skipped = getattr(receipt, "deduped_count", 0)
    print(f"[tn absorb] kind={kind} accepted={accepted} skipped={skipped}")
    replaced = list(getattr(receipt, "replaced_kit_paths", []) or [])
    if replaced:
        print(f"[tn absorb] WARN: overwrote {len(replaced)} existing kit file(s):")
        for p in replaced:
            print(f"             {p}")
        print(
            "[tn absorb] prior bytes preserved at <name>.previous.<UTC_TS> "
            "in the same directory."
        )
    return 0 if accepted >= 0 else 1


def _rotate_select_groups(args: argparse.Namespace, cfg) -> list[str]:
    """Resolve the target group set (positional / --groups / all non-internal)
    and reject a mutually-exclusive selection or any unknown group."""
    if args.group is not None and args.groups is not None:
        _die("pass either a positional <group> or --groups, not both.", code=2)
    if args.group is not None:
        target_groups = [args.group]
    elif args.groups is not None:
        target_groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    else:
        target_groups = [g for g in cfg.groups if g != "tn.agents"]
    unknown = [g for g in target_groups if g not in cfg.groups]
    if unknown:
        _die(
            f"unknown group(s) {unknown!r}; ceremony declares "
            f"{sorted(cfg.groups)}.",
            code=2,
        )
    return target_groups


def _rotate_snapshot_recipients(target_groups: list[str]) -> dict[str, list[str]]:
    """Snapshot the surviving (non-revoked) recipients per group PRE-rotation,
    inverted to ``{recipient_did: [group, ...]}``."""
    recipient_groups: dict[str, list[str]] = {}
    for g in target_groups:
        for rec in _admin.recipients(g):
            if rec.get("revoked"):
                continue
            rdid = rec.get("recipient_identity")
            if not isinstance(rdid, str):
                continue
            recipient_groups.setdefault(rdid, []).append(g)
    return recipient_groups


def _rotate_resolve_output(out, recipient_count: int, ts: str) -> tuple[Path, Path | None]:
    """Resolve (out_dir, single_file) from --out: absent -> ./rotated_<ts>/;
    a .tnpkg path -> that single file (rejected for >1 recipient); else a
    directory."""
    out_arg = Path(out).resolve() if out else None
    if out_arg is None:
        return Path.cwd() / f"rotated_{ts}", None
    if out_arg.suffix == ".tnpkg":
        if recipient_count > 1:
            _die(
                f"--out {out_arg.name} is a single .tnpkg path but "
                f"this rotation has {recipient_count} surviving "
                "recipient(s). Pass a directory path (or omit --out) "
                "to write one .tnpkg per recipient.",
                code=2,
            )
        return out_arg.parent, out_arg
    return out_arg, None


def _rotate_emit_bundles(
    recipient_groups: dict[str, list[str]],
    out_dir: Path,
    single_file: Path | None,
    bundle_for_recipient,
) -> list[Path]:
    """Mint one kit_bundle .tnpkg per surviving recipient (post-rotation key
    material), returning the written artifact paths."""
    artifacts: list[Path] = []
    for rdid, groups in recipient_groups.items():
        if single_file is not None:
            pkg_path = single_file
        else:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", rdid)
            pkg_path = out_dir / f"{safe}.tnpkg"
        written = bundle_for_recipient(rdid, pkg_path, groups=groups)
        artifacts.append(Path(written))
    return artifacts


def cmd_import(args: argparse.Namespace) -> int:
    """Restore a project_seed backup (keys + config) into this directory.

    ``tn import`` is the user-facing restore verb. Unlike ``tn absorb``
    (which binds an existing ceremony first), import drives the
    bootstrap-aware absorb path so a ``project_seed`` lands into a FRESH
    directory with no prior ``tn init``. ``absorb`` remains for kit
    bundles / enrolments into an already-initialized ceremony.
    """
    package = Path(args.package).resolve()
    if not package.exists() or package.stat().st_size == 0:
        _die(f"package not found or empty: {package}")

    try:
        receipt = absorb(package)
    except Exception as exc:  # noqa: BLE001 — surface a clean CLI error
        _die(f"import failed: {exc}", code=1)
        return 1  # unreachable; _die raises

    if getattr(receipt, "legacy_status", None) == "rejected":
        _die(
            f"[tn import] rejected: {getattr(receipt, 'legacy_reason', 'unknown')}",
            code=1,
        )

    kind = getattr(receipt, "kind", "?")
    accepted = getattr(receipt, "accepted_count", 0)
    restored_did = ""
    try:
        restored_did = tn.current_config().device.device_identity
        tn.flush_and_close()
    except Exception:  # noqa: BLE001 — DID display is best-effort
        pass

    print(f"[tn import] restored kind={kind} files={accepted}")
    if restored_did:
        print(f"[tn import]   device:  {restored_did}")
    print("[tn import] ceremony is live here; run `tn read` or `tn info <event_type>`.")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Mint a .tnpkg backup from the active ceremony.

    Currently supports ``--kind project_seed`` — the complete
    identity+config backup (raw private keys + canonical ``tn.yaml``)
    that ``tn import`` restores on a fresh device. Requires
    ``--include-secrets`` because the bundle carries private keys.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tn.init(yaml_path)
    written = None
    did = ""
    try:
        cfg = tn.current_config()
        did = cfg.device.device_identity
        if args.kind == "project_seed":
            if not args.include_secrets:
                _die(
                    "tn export --kind project_seed writes the device's raw "
                    "private keys into the bundle. Pass --include-secrets to "
                    "acknowledge.",
                    code=2,
                )
            written = pkg_export(
                out_path,
                kind="project_seed",
                cfg=cfg,
                confirm_includes_secrets=True,
            )
        else:
            _die(f"unsupported export kind for the CLI: {args.kind!r}", code=2)
    finally:
        tn.flush_and_close()

    print(f"[tn export] wrote {written}")
    print(f"[tn export]   kind:    {args.kind}")
    print(f"[tn export]   device:  {did}")
    print(f"[tn export]   restore: tn import {Path(written).name}")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    """Rotate group key material and emit per-recipient kit_bundle .tnpkg
    artifacts so the publisher can hand new kits to surviving recipients.

    The rotation primitive is the deploy event for a TN ceremony: it
    bumps the per-group ``index_epoch``, regenerates the publisher's
    self-kit, renames the prior key material to ``.revoked.<ts>`` (the
    publisher keeps the file on disk for keywalk exercises across
    rotation boundaries), and appends a ``tn.rotation.completed``
    attestation to the admin log. Recipients receive the new kit but
    keep their old ones too — also kept on disk for keywalk.

    Rotation is *not* eviction. The same recipient set carries
    forward; both pre- and post-rotation kits successfully decrypt
    both pre- and post-rotation entries. The new kit exists so the
    publisher can hand it to new recipients added after this point,
    and so the keystore generation count moves forward for
    audit/key-hygiene purposes. To actually remove a recipient,
    revoke them via ``admin_revoke_recipient`` before rotating.

    Vault-linked ceremonies push the new state on autosync as a side
    effect of the underlying ``tn.admin.rotate`` call (see
    ``_maybe_autosync``); the vault then drives recipient notification.
    Vault-less ceremonies rely on this CLI's per-recipient .tnpkg
    artifacts as the distribution channel — upload the directory as a
    CI artifact (``actions/upload-artifact`` or equivalent) and hand the
    individual files to recipients out-of-band.

    Group selection (in priority order):

      * positional ``<group>`` — single group only
      * ``--groups a,b,c``    — explicit subset
      * neither              — every non-internal group in the ceremony
                               (excludes ``tn.agents``, same convention
                               as ``tn bundle``).

    Output (``--out``):

      * absent                       → ``./rotated_<UTC_TS>/`` directory,
                                       one ``<recipient_safe>.tnpkg`` per
                                       surviving recipient.
      * existing directory           → same shape, in that directory.
      * path ending in ``.tnpkg``    → that exact file. Single-recipient
                                       only; rejected if the rotation
                                       affected more than one recipient.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)
    tn.init(yaml_path)
    try:
        cfg = tn.current_config()
        if cfg.cipher_name != "btn":
            _die(
                f"tn rotate currently supports btn ceremonies only; "
                f"this ceremony uses {cfg.cipher_name!r}.",
                code=2,
            )

        target_groups = _rotate_select_groups(args, cfg)

        # Snapshot surviving recipients PRE-rotation so we know who to mint
        # new kits for (the btn recipient set carries forward unchanged, but
        # the explicit snapshot survives any future semantic change).
        recipient_groups = _rotate_snapshot_recipients(target_groups)

        # Rotate each group. Each call also fires _maybe_autosync, so
        # vault-linked ceremonies push state as a side effect.
        rotated: list[tuple[str, int]] = []
        for g in target_groups:
            res = _admin.rotate(g)
            rotated.append((g, res.generation or 0))

        # Resolve output destination.
        if not recipient_groups:
            print(
                "[tn rotate] rotated "
                f"{len(rotated)} group(s); no surviving recipients to "
                "bundle for. New kits will be minted on the next "
                "`tn add_recipient` / `tn bundle` call.",
            )
            for g, gen in rotated:
                print(f"             {g}: epoch={gen}")
            return 0

        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out_dir, single_file = _rotate_resolve_output(args.out, len(recipient_groups), ts)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Bundle per recipient. bundle_for_recipient internally loops
        # admin.add_recipient (which mints fresh kits using the
        # post-rotation key material), so the artifact contains kits
        # the recipient can absorb to read post-rotation entries.
        artifacts = _rotate_emit_bundles(
            recipient_groups, out_dir, single_file, bundle_for_recipient
        )

        print(
            f"[tn rotate] rotated {len(rotated)} group(s); "
            f"emitted {len(artifacts)} .tnpkg artifact(s) "
            f"into {out_dir}",
        )
        for g, gen in rotated:
            print(f"             {g}: epoch={gen}")
        for art in artifacts:
            print(f"             -> {art.name}")
        return 0
    finally:
        tn.flush_and_close()
