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
import sys
import zipfile
from io import BytesIO
from pathlib import Path

from ._bounded_json import loads_bounded
from .tnpkg import TnpkgManifest, _read_manifest

# ── Acceptance logic ─────────────────────────────────────────────────

_MAX_INVITE_ENTRIES = 16
_MAX_INVITE_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_INVITE_KIT_BYTES = 128 * 1024 * 1024
_MAX_INVITE_TOTAL_BYTES = _MAX_INVITE_MANIFEST_BYTES + _MAX_INVITE_KIT_BYTES
_MAX_INVITE_COMPRESSION_RATIO = 200


class InboxError(Exception):
    """Raised when an inbox operation fails for a user-visible reason."""


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_kit_entry(names: list[str], group_name: str) -> str | None:
    """Locate the inner kit entry name inside an unpacked invitation zip.

    The real server names a raw kit ``<group>.btn.mykit``; older wrappers and
    secure invitations use ``kit.tnpkg``. Exactly one kit-shaped member is
    required so unsigned outer metadata cannot select a raw downgrade beside
    a genuine signed package. Returns ``None`` when no kit entry exists.
    """
    del group_name
    members = [n for n in names if n != "manifest.json"]
    kit_shaped = [n for n in members if n.endswith(".tnpkg") or n.endswith(".btn.mykit")]
    if len(kit_shaped) > 1:
        raise InboxError("Invalid invitation zip: multiple kit entries are ambiguous")
    if len(kit_shaped) == 1:
        return kit_shaped[0]

    return None


def _inspect_invitation_archive(zf: zipfile.ZipFile) -> list[str]:
    """Reject outer archive bombs and duplicate/ambiguous members before read."""
    infos = zf.infolist()
    if len(infos) > _MAX_INVITE_ENTRIES:
        raise InboxError("Invalid invitation zip: too many archive entries")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise InboxError("Invalid invitation zip: duplicate archive member")
    if names.count("manifest.json") != 1:
        raise InboxError("Invalid invitation zip: expected exactly one manifest.json")

    total = 0
    for info in infos:
        if info.flag_bits & 0x1:
            raise InboxError("Invalid invitation zip: encrypted ZIP entries are unsupported")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise InboxError("Invalid invitation zip: unsupported ZIP compression method")
        limit = (
            _MAX_INVITE_MANIFEST_BYTES
            if info.filename == "manifest.json"
            else _MAX_INVITE_KIT_BYTES
        )
        if info.file_size > limit:
            raise InboxError("Invalid invitation zip: archive member exceeds its size limit")
        if info.file_size and (
            not info.compress_size
            or info.file_size > info.compress_size * _MAX_INVITE_COMPRESSION_RATIO
        ):
            raise InboxError("Invalid invitation zip: archive compression ratio is unsafe")
        total += info.file_size
        if total > _MAX_INVITE_TOTAL_BYTES:
            raise InboxError("Invalid invitation zip: total uncompressed size exceeds its limit")
    return names


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


def _read_inner_manifest(package_bytes: bytes) -> TnpkgManifest:
    """Bound and authenticate the package carried by a secure invite."""
    try:
        manifest, _body = _read_manifest(package_bytes, verify_signature=True)
    except (ValueError, zipfile.BadZipFile) as exc:
        raise InboxError(f"Invalid recipient package: {exc}") from exc
    return manifest


def _signed_btn_group(inner: TnpkgManifest) -> str:
    """Derive the one BTN group from authenticated package metadata."""
    state = inner.state
    if not isinstance(state, dict):
        raise InboxError("Recipient package is missing signed kit metadata")
    encryption = state.get("body_encryption")
    if not isinstance(encryption, dict) or not encryption.get("recipient_wraps"):
        raise InboxError("Recipient package body is not recipient-sealed")
    kits = state.get("kits")
    if not isinstance(kits, list):
        raise InboxError("Recipient package is missing signed kit metadata")
    names = [item.get("name") for item in kits if isinstance(item, dict)]
    btn_names = [name for name in names if isinstance(name, str) and name.endswith(".btn.mykit")]
    if len(names) != 1 or len(btn_names) != 1:
        raise InboxError("Secure invitation must carry exactly one BTN reader kit")
    group = btn_names[0][: -len(".btn.mykit")]
    if not group or "/" in group or "\\" in group:
        raise InboxError("Recipient package contains an invalid signed group name")
    return group


def _install_recipient_package(
    package_bytes: bytes,
    *,
    inner: TnpkgManifest,
    yaml_path: Path,
    yaml_doc: dict,
    kit_dest: Path,
) -> None:
    """Authenticate, unwrap, and absorb one recipient-sealed ``.tnpkg``."""
    import tn

    log_rel = (yaml_doc.get("logs") or {}).get("path") or "./.tn/logs/tn.ndjson"
    log_abs = (yaml_path.parent / log_rel).resolve()
    keep_runtime_for_attestation = False
    try:
        tn.init(str(yaml_path), log_path=str(log_abs))
        local_did = tn.current_config().device.device_identity
        if inner.recipient_identity != local_did:
            raise InboxError("Signed package is not addressed to this recipient DID")

        receipt = tn.pkg.absorb(package_bytes)
        if receipt.legacy_status not in ("enrolment_applied", "no_op"):
            raise InboxError(f"Recipient package rejected: {receipt.legacy_reason}")
        if not kit_dest.exists():
            raise InboxError("Recipient package did not install the expected group kit")
        keep_runtime_for_attestation = True
    finally:
        if not keep_runtime_for_attestation:
            try:
                tn.flush_and_close()
            except Exception:  # noqa: BLE001 - preserve the delivery failure
                pass


def _emit_absorb_attestation(
    *,
    yaml_path: Path,
    yaml_doc: dict,
    runtime_is_open: bool,
    group_name: str,
    publisher_did: str,
    package_sha256: str,
    absorbed_at: str,
) -> None:
    """Emit the local receipt and always close the active runtime."""
    import tn

    try:
        if not runtime_is_open:
            log_rel = (yaml_doc.get("logs") or {}).get("path") or "./.tn/logs/tn.ndjson"
            log_abs = (yaml_path.parent / log_rel).resolve()
            tn.init(str(yaml_path), log_path=str(log_abs))
        tn.info(
            "tn.enrolment.absorbed",
            group=group_name,
            publisher_identity=publisher_did,
            package_sha256=package_sha256,
            absorbed_at=absorbed_at,
        )
    finally:
        tn.flush_and_close()


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

    # 1. Open the outer invitation zip.
    try:
        zf = zipfile.ZipFile(str(zip_path), "r")
    except zipfile.BadZipFile as exc:
        raise InboxError(f"Invalid zip file: {exc}") from exc

    with zf:
        names = _inspect_invitation_archive(zf)

        # 2. Read manifest.
        try:
            manifest = loads_bounded(zf.read("manifest.json"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise InboxError(f"Invalid invitation manifest: {exc}") from exc
        if not isinstance(manifest, dict):
            raise InboxError("Invalid invitation manifest: expected an object")

        outer_group_name = manifest.get("group_name", "default")
        if not isinstance(outer_group_name, str) or not outer_group_name:
            raise InboxError("Invalid invitation manifest: group_name must be a string")
        leaf_index = manifest.get("leaf_index")
        from_email = manifest.get("from_email", "unknown")
        from_did = manifest.get("from_account_did", "")
        kit_sha256 = manifest.get("kit_sha256", "")

        # 3. Read and verify kit bytes. The real server names the inner
        #    kit ``<group>.btn.mykit``; the legacy name was ``kit.tnpkg``.
        #    Accept either (and any single kit-shaped entry).
        kit_entry = _find_kit_entry(names, outer_group_name)
        if kit_entry is None:
            raise InboxError("Invalid invitation zip: missing kit.tnpkg")
        kit_bytes = zf.read(kit_entry)
    _verify_kit_hash(kit_bytes, manifest)

    # Security is selected by the carried bytes, never by unsigned outer
    # metadata. Removing `kit_format` cannot downgrade a signed package into
    # the legacy raw-kit installer.
    secure_package = zipfile.is_zipfile(BytesIO(kit_bytes))
    declared_secure = (
        manifest.get("kit_format") == "tnpkg" or manifest.get("delivery") == "recipient-seal-v1"
    )
    if declared_secure and not secure_package:
        raise InboxError("Invitation declares a secure package but carries a raw kit")

    inner = None
    group_name = outer_group_name
    if secure_package:
        inner = _read_inner_manifest(kit_bytes)
        if inner.kind != "kit_bundle":
            raise InboxError("Secure invitation must carry a kit_bundle package")
        if inner.publisher_identity != from_did:
            raise InboxError("Invitation sender does not match the signed package publisher")
        group_name = _signed_btn_group(inner)
        from_did = inner.publisher_identity
        leaf_index = None  # Legacy outer metadata is not authenticated.
        kit_sha256 = "sha256:" + _sha256_hex(kit_bytes)

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

    # 5. Install legacy raw kits directly. Secure invites carry a signed
    # recipient-sealed tnpkg and go through the normal verified absorb path.
    kit_dest = keystore_dir / f"{group_name}.btn.mykit"
    runtime_is_open = False
    if secure_package:
        if inner is None:  # Defensive type narrowing; secure inspection set it above.
            raise InboxError("Secure invitation inspection did not produce a manifest")
        _install_recipient_package(
            kit_bytes,
            inner=inner,
            yaml_path=yaml_path,
            yaml_doc=yaml_doc,
            kit_dest=kit_dest,
        )
        runtime_is_open = True
    else:
        if kit_dest.exists():
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            previous = kit_dest.with_name(f"{group_name}.btn.mykit.previous.{ts}")
            kit_dest.rename(previous)
            print(f"  (Backed up existing kit to {previous.name})")
        kit_dest.write_bytes(kit_bytes)

    # 6. Emit tn.enrolment.absorbed to Frank's local log.
    absorbed_at = _now_iso()
    try:
        _emit_absorb_attestation(
            yaml_path=yaml_path,
            yaml_doc=yaml_doc,
            runtime_is_open=runtime_is_open,
            group_name=group_name,
            publisher_did=from_did,
            package_sha256=kit_sha256,
            absorbed_at=absorbed_at,
        )
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
