"""
tn.inbox -- local kit acceptance CLI.

Frank runs this on his laptop after downloading a zip from the vault.
No vault contact during acceptance. Entirely local operation.

Usage:
    python -m tn.inbox accept ./tn-invite-01KQ.zip [--yaml ./tn.yaml]
    python -m tn.inbox list-local [--dir ~/Downloads]

The vault is a one-way messaging channel: Alice allocates server-side and
deposits the zip. Frank downloads. Frank accepts locally. No write-back
to the vault from this CLI.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path

# ── Acceptance logic ─────────────────────────────────────────────────


class InboxError(Exception):
    """Raised when an inbox operation fails for a user-visible reason."""


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_kit_hash(kit_bytes: bytes, manifest: dict) -> None:
    """Verify kit_bytes matches the sha256 recorded in the manifest."""
    expected = manifest.get("kit_sha256", "")
    if not expected:
        return  # no hash in manifest; skip verification
    if expected.startswith("sha256:"):
        expected_hex = expected[len("sha256:") :]
    else:
        expected_hex = expected
    actual = _sha256_hex(kit_bytes)
    if actual != expected_hex:
        raise InboxError(
            f"Kit hash mismatch.\n"
            f"  Expected: {expected_hex}\n"
            f"  Got:      {actual}\n"
            "The zip may be corrupted. Re-download from the vault."
        )


def accept(zip_path: Path, yaml_path: Path | None = None) -> dict:
    """Unzip an invitation, verify the kit, install it, and emit an attested event.

    Parameters
    ----------
    zip_path:
        Path to the tn-invite-<id>.zip file downloaded from the vault.
    yaml_path:
        Path to Frank's tn.yaml. Defaults to ./tn.yaml in the current
        working directory.

    Returns
    -------
    dict with keys: group_name, leaf_index, from_email, kit_path, absorbed_at.
    """
    if not zip_path.exists():
        raise InboxError(f"Zip not found: {zip_path}")

    if yaml_path is None:
        yaml_path = Path.cwd() / "tn.yaml"

    if not yaml_path.exists():
        raise InboxError(
            f"tn.yaml not found at {yaml_path}. "
            "Run from a directory with a ceremony, or pass --yaml <path>."
        )

    # 1. Unzip to a temp directory.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        try:
            with zipfile.ZipFile(str(zip_path), "r") as zf:
                zf.extractall(str(tmp_dir))
        except zipfile.BadZipFile as exc:
            raise InboxError(f"Invalid zip file: {exc}") from exc

        # 2. Read manifest.
        manifest_path = tmp_dir / "manifest.json"
        if not manifest_path.exists():
            raise InboxError("Invalid invitation zip: missing manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        group_name = manifest.get("group_name", "default")
        leaf_index = manifest.get("leaf_index")
        from_email = manifest.get("from_email", "unknown")
        from_did = manifest.get("from_account_did", "")
        kit_sha256 = manifest.get("kit_sha256", "")

        # 3. Read and verify kit bytes.
        kit_source = tmp_dir / "kit.tnpkg"
        if not kit_source.exists():
            raise InboxError("Invalid invitation zip: missing kit.tnpkg")
        kit_bytes = kit_source.read_bytes()
        _verify_kit_hash(kit_bytes, manifest)

        # 4. Locate Frank's keystore dir from tn.yaml.
        # Honor the yaml's ``keystore.path``; the per-yaml-stem namespace
        # default lives there now (FINDINGS #2). Fall back to the legacy
        # ``./.tn/keys`` only when the yaml omits the field.
        try:
            import yaml as _yaml

            with open(yaml_path, encoding="utf-8") as f:
                yaml_doc = _yaml.safe_load(f) or {}
        except Exception as exc:
            raise InboxError(f"Could not read tn.yaml: {exc}") from exc

        yaml_dir = yaml_path.parent
        keystore_rel = (yaml_doc.get("keystore") or {}).get("path") or "./.tn/keys"
        keystore_dir = (yaml_dir / keystore_rel).resolve()
        keystore_dir.mkdir(parents=True, exist_ok=True)

        # 5. Install kit: rename existing to .previous.<timestamp>, then write.
        kit_dest = keystore_dir / f"{group_name}.btn.mykit"
        if kit_dest.exists():
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            previous = kit_dest.with_name(f"{group_name}.btn.mykit.previous.{ts}")
            kit_dest.rename(previous)
            print(f"  (Backed up existing kit to {previous.name})")
        kit_dest.write_bytes(kit_bytes)

    # 6. Emit tn.enrolment.absorbed to Frank's local log.
    absorbed_at = _now_iso()
    try:
        import tn

        # Honor the yaml's logs.path too (FINDINGS #2 namespacing).
        log_rel = (yaml_doc.get("logs") or {}).get("path") or "./.tn/logs/tn.ndjson"
        log_abs = (yaml_dir / log_rel).resolve()
        tn.init(str(yaml_path), log_path=str(log_abs))
        tn.info(
            "tn.enrolment.absorbed",
            group=group_name,
            from_did=from_did,
            package_sha256=kit_sha256,
            absorbed_at=absorbed_at,
        )
        tn.flush_and_close()
    except Exception as exc:  # noqa: BLE001 — preserve broad swallow; see body of handler
        # Non-fatal: kit is already installed. Warn and continue.
        print(
            f"  Warning: could not emit tn.enrolment.absorbed: {exc}\n"
            "  The kit is installed. You may emit the attestation manually."
        )

    return {
        "group_name": group_name,
        "leaf_index": leaf_index,
        "from_email": from_email,
        "kit_path": str(kit_dest),
        "absorbed_at": absorbed_at,
    }


def list_local(downloads_dir: Path | None = None) -> list[Path]:
    """List tn-invite-*.zip files in the given (or default Downloads) directory."""
    if downloads_dir is None:
        downloads_dir = Path.home() / "Downloads"
    if not downloads_dir.exists():
        return []
    return sorted(downloads_dir.glob("tn-invite-*.zip"))


# ── CLI entry point ──────────────────────────────────────────────────


def _cmd_accept(args: argparse.Namespace) -> None:
    zip_path = Path(args.zip).expanduser().resolve()
    yaml_path = Path(args.yaml).expanduser().resolve() if args.yaml else None

    print(f"Accepting invitation from {zip_path.name} ...")
    result = accept(zip_path, yaml_path=yaml_path)

    print(
        f"\nInstalled kit for group '{result['group_name']}' "
        f"(leaf {result['leaf_index']}) from {result['from_email']}."
    )
    print(f"Kit written to: {result['kit_path']}")
    print(f"Absorbed at:    {result['absorbed_at']}")
    print("\nReady to read. Try:")
    print(
        "  python -c \"import tn; tn.init('./tn.yaml'); [print(e) for e in tn.read('../alice/.tn/logs/tn.ndjson')]\""
    )


def _cmd_list_local(args: argparse.Namespace) -> None:
    dir_path = Path(args.dir).expanduser().resolve() if args.dir else None
    zips = list_local(dir_path)
    if not zips:
        d = dir_path or (Path.home() / "Downloads")
        print(f"No tn-invite-*.zip files found in {d}")
        return
    print(f"Found {len(zips)} invitation zip(s):")
    for z in zips:
        print(f"  {z}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tn.inbox",
        description="TN inbox: accept invitation zips locally.",
    )
    sub = parser.add_subparsers(dest="command")

    p_accept = sub.add_parser("accept", help="Unzip and install a kit locally.")
    p_accept.add_argument("zip", help="Path to the tn-invite-*.zip file.")
    p_accept.add_argument(
        "--yaml",
        default=None,
        help="Path to tn.yaml (defaults to ./tn.yaml).",
    )

    p_list = sub.add_parser("list-local", help="List invitation zips in Downloads.")
    p_list.add_argument(
        "--dir",
        default=None,
        help="Directory to scan (defaults to ~/Downloads).",
    )

    args = parser.parse_args()

    if args.command == "accept":
        try:
            _cmd_accept(args)
        except InboxError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "list-local":
        _cmd_list_local(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
