"""``tn streams`` / ``tn validate`` — multi-ceremony introspection verbs.

Read-only inspection of the project's ``.tn/`` tree: ``streams`` lists the
ceremonies declared on disk; ``validate`` runs the schema / catalog /
keystore-consistency checks suitable for a pre-commit hook or CI gate. Both
are thin over :mod:`tn._layout` / :mod:`tn._profiles`; no state is mutated.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import _layout, _profiles


def cmd_streams(args: argparse.Namespace) -> int:
    """List ceremonies declared under ``.tn/`` for the project.

    Reads ``.tn/<name>/tn.yaml`` for each subdirectory and surfaces
    name, stamped profile (if any), and yaml path. Cheap, read-only.
    """
    project_dir = Path(args.project_dir).resolve() if args.project_dir else Path.cwd()
    names = _layout.list_ceremonies_on_disk(project_dir)

    rows: list[dict] = []
    for name in names:
        yaml_path = _layout.ceremony_yaml_path(name, project_dir=project_dir)
        profile: str | None = None
        try:
            with yaml_path.open("r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            profile = (doc.get("ceremony") or {}).get("profile")
        except (OSError, yaml.YAMLError):
            pass
        rows.append(
            {
                "name": name,
                "profile": profile or "(unspecified)",
                "yaml_path": str(yaml_path),
            }
        )

    if args.format == "json":
        print(json.dumps(rows, indent=2))
        return 0

    # Human format: simple aligned table.
    if not rows:
        print(f"(no ceremonies found under {project_dir / '.tn'})")
        return 0
    name_w = max(len("NAME"), max(len(r["name"]) for r in rows))
    prof_w = max(len("PROFILE"), max(len(r["profile"]) for r in rows))
    print(f"{'NAME':<{name_w}}  {'PROFILE':<{prof_w}}  YAML")
    print(f"{'-' * name_w}  {'-' * prof_w}  {'-' * 4}")
    for r in rows:
        print(f"{r['name']:<{name_w}}  {r['profile']:<{prof_w}}  {r['yaml_path']}")
    return 0


def _validate_resolve_keystore_pub(
    *,
    yaml_path: Path,
    yaml_doc: dict,
    project_dir: Path,
) -> Path | None:
    """Resolve the path to ``local.public`` for the ceremony at
    ``yaml_path``. Used by ``cmd_validate`` to compare
    yaml.device.device_identity against the keystore's recorded did:key.

    Resolution order:

    1. ``yaml_doc['keystore']['path']`` if present (relative to the
       yaml's directory) — named streams point at default's keystore
       via this field.
    2. ``<yaml_dir>/keys/local.public`` fallback (the default
       ceremony layout).

    Returns ``None`` if neither resolves to a path that could
    plausibly hold a keystore (caller can ignore this ceremony's
    DID-consistency check).
    """
    yaml_dir = yaml_path.parent
    keystore_section = yaml_doc.get("keystore") or {}
    raw_path = keystore_section.get("path") if isinstance(
        keystore_section, dict
    ) else None
    if isinstance(raw_path, str) and raw_path:
        # Stream yaml relative paths are interpreted relative to the
        # stream's own yaml directory (matches what the runtime does).
        keystore_dir = (yaml_dir / raw_path).resolve()
    else:
        keystore_dir = yaml_dir / "keys"
    pub = keystore_dir / "local.public"
    return pub


def _validate_required_sections(
    doc: dict, yaml_path: Path, is_stream: bool
) -> list[str]:
    """Required top-level sections (narrower for `extends:` streams) + the
    legacy `me:` block rejection."""
    errors: list[str] = []
    required_top: list[str] = ["ceremony"]
    if not is_stream:
        required_top += ["logs", "keystore", "device", "groups"]
        if "me" in doc and "device" not in doc:
            errors.append(
                f"{yaml_path}: legacy `me:` top-level block is no longer "
                f"supported (0.4.3a1 renamed it to `device:`). Replace "
                f"`device: {{device_identity: ...}}` with `device: {{device_identity: ...}}`."
            )
    for key in required_top:
        if key not in doc:
            errors.append(
                f"{yaml_path}: missing required top-level key "
                f"{key!r}. A yaml that parses but lacks "
                f"required sections will fail at init time with "
                f"a confusing error; declare {key!r} or add an "
                f"`extends:` pointing at a yaml that does."
            )
    return errors


def _validate_subkeys(doc: dict, yaml_path: Path, is_stream: bool) -> list[str]:
    """Runtime-depended sub-keys: ceremony.id always; logs.path / keystore.path
    / device.device_identity for non-stream yamls."""
    errors: list[str] = []
    if isinstance(doc.get("ceremony"), dict):
        if "id" not in doc["ceremony"]:
            errors.append(f"{yaml_path}: ceremony.id is required")
    if not is_stream:
        if isinstance(doc.get("logs"), dict) and "path" not in doc["logs"]:
            errors.append(f"{yaml_path}: logs.path is required")
        if isinstance(doc.get("keystore"), dict) and "path" not in doc["keystore"]:
            errors.append(f"{yaml_path}: keystore.path is required")
        if isinstance(doc.get("device"), dict) and "device_identity" not in doc["device"]:
            errors.append(f"{yaml_path}: device.device_identity is required")
    return errors


def _validate_profile(doc: dict, yaml_path: Path) -> list[str]:
    """ceremony.profile must be in the SDK catalog when present."""
    profile = (doc.get("ceremony") or {}).get("profile")
    if profile is not None and not _profiles.is_known(profile):
        return [
            f"{yaml_path}: unknown profile {profile!r}; "
            f"catalog: {list(_profiles.all_profile_names())}"
        ]
    return []


def _validate_group_kits(doc: dict, yaml_path: Path) -> list[str]:
    """Each declared btn group must have a non-empty publisher self-kit on
    disk, else the publisher silently fails to decrypt its own emits."""
    errors: list[str] = []
    groups_dict = doc.get("groups") if isinstance(doc.get("groups"), dict) else None
    keystore_block = doc.get("keystore") if isinstance(doc.get("keystore"), dict) else None
    if not (groups_dict and keystore_block and "path" in keystore_block):
        return errors
    ks_path = Path(keystore_block["path"])
    if not ks_path.is_absolute():
        ks_path = (yaml_path.parent / ks_path).resolve()
    for gname, gspec in groups_dict.items():
        if not isinstance(gspec, dict):
            continue
        cipher = gspec.get("cipher") or doc.get("ceremony", {}).get("cipher") or "btn"
        if cipher != "btn":
            continue
        kit_file = ks_path / f"{gname}.btn.mykit"
        if not kit_file.is_file():
            errors.append(
                f"{yaml_path}: group {gname!r} kit missing: "
                f"{kit_file}. Without the publisher self-kit "
                f"the runtime will silently fail to decrypt "
                f"its own emits. Re-init the ceremony or "
                f"absorb a fresh kit bundle."
            )
        elif kit_file.stat().st_size == 0:
            errors.append(
                f"{yaml_path}: group {gname!r} kit is empty: "
                f"{kit_file}. Same effect as missing — "
                f"emits will be unreadable by the publisher."
            )
    return errors


def _validate_did_consistency(
    doc: dict, yaml_path: Path, project_dir: Path
) -> list[str]:
    """yaml device.device_identity must match the keystore's local.public
    did:key (the basic keystore/yaml consistency invariant, DX review #2)."""
    keystore_pub = _validate_resolve_keystore_pub(
        yaml_path=yaml_path,
        yaml_doc=doc,
        project_dir=project_dir,
    )
    if keystore_pub is None or not keystore_pub.is_file():
        return []
    try:
        derived_did = keystore_pub.read_text(encoding="ascii").strip()
    except OSError as exc:
        return [f"{yaml_path}: could not read keystore {keystore_pub}: {exc}"]
    yaml_did = (doc.get("device") or {}).get("device_identity")
    if yaml_did and derived_did and yaml_did != derived_did:
        return [
            f"{yaml_path}: yaml device.device_identity does not match keystore. "
            f"yaml device.device_identity = {yaml_did}; "
            f"keys/local.public = {derived_did}. "
            "Reseat one to match the other before any further "
            "writes — the runtime will refuse to load this "
            "ceremony otherwise."
        ]
    return []


def _validate_one_ceremony(name: str, project_dir: Path) -> list[str]:
    """Run every per-ceremony check for ``name``; return its accumulated
    errors (empty when valid). A read/parse failure or non-mapping top level
    short-circuits the remaining checks for that ceremony."""
    yaml_path = _layout.ceremony_yaml_path(name, project_dir=project_dir)
    try:
        with yaml_path.open("r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except OSError as exc:
        return [f"{yaml_path}: read failed: {exc}"]
    except yaml.YAMLError as exc:
        return [f"{yaml_path}: yaml parse failed: {exc}"]

    if not isinstance(doc, dict):
        return [f"{yaml_path}: top-level must be a mapping"]

    is_stream = "extends" in doc
    errors: list[str] = []
    errors += _validate_required_sections(doc, yaml_path, is_stream)
    errors += _validate_subkeys(doc, yaml_path, is_stream)
    errors += _validate_profile(doc, yaml_path)
    errors += _validate_group_kits(doc, yaml_path)
    errors += _validate_did_consistency(doc, yaml_path, project_dir)
    return errors


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate the project's ``.tn/`` configuration tree.

    Read-only checks:
      - every ``.tn/<name>/tn.yaml`` parses as a mapping
      - every stamped ceremony.profile is in the SDK catalog
      - the default ceremony exists if any others do (identity must
        live at the project root)
      - the on-disk ``me.did`` in each ``tn.yaml`` matches the
        ``keys/local.public`` did:key for that ceremony (the basic
        keystore-yaml consistency invariant — DX review #2)

    Returns 0 if everything is well-formed; 1 with errors printed
    to stderr otherwise. Suitable for use in a pre-commit hook or
    CI pipeline. Adds a non-zero exit on the *first* error so CI
    output stays compact.
    """
    project_dir = Path(args.project_dir).resolve() if args.project_dir else Path.cwd()
    root = project_dir / _layout.TN_ROOT_DIRNAME

    errors: list[str] = []
    warnings: list[str] = []

    if not root.is_dir():
        print(f"(no .tn/ directory at {project_dir} — nothing to validate)")
        return 0

    names = _layout.list_ceremonies_on_disk(project_dir)
    if not names:
        print(f"(no ceremonies under {root} — nothing to validate)")
        return 0

    if "default" not in names:
        warnings.append(
            "no 'default' ceremony at .tn/default/. The project's "
            "identity should live there; named streams normally "
            "extend from it."
        )

    for name in names:
        errors += _validate_one_ceremony(name, project_dir)

    if warnings:
        for w in warnings:
            print(f"WARNING: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(names)} ceremon{'y' if len(names) == 1 else 'ies'} valid.")
    return 0
