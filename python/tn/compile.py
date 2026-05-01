"""Package compilation verbs — publisher-side.

compile_enrolment(cfg, group, peer_did)  - JWE: tell peer how to decrypt
emit_to_outbox(cfg, pkg) - write to <yaml_dir>/outbox/

compile_bearer_coupon (BGW) is added in a later task (Task 13).
"""

from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from .cipher import JWEGroupCipher
from .config import LoadedConfig
from .conventions import outbox_dir, tnpkg_filename
from .packaging import Package, _canonical_bytes, sign


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _signing_key(cfg: LoadedConfig):
    """Return the device's Ed25519PrivateKey for signing packages."""
    return cfg.device.signing_key()


def compile_enrolment(cfg: LoadedConfig, group: str, peer_did: str) -> Package:
    """Build and sign an `enrolment` package addressed to peer_did.

    Raises RuntimeError with a pointed message if the group isn't JWE or
    this party isn't the publisher.
    """
    if group not in cfg.groups:
        raise RuntimeError(
            f"compile_enrolment: group {group!r} is not in this ceremony "
            f"(known groups: {list(cfg.groups)}). Add it with "
            f"admin.ensure_group(cfg, {group!r}, cipher='jwe') first."
        )
    gcfg = cfg.groups[group]
    if not isinstance(gcfg.cipher, JWEGroupCipher):
        raise RuntimeError(
            f"compile_enrolment: group {group!r} uses cipher "
            f"{gcfg.cipher.name!r}, but enrolment packages are JWE-only. "
            f"For btn groups use tn.admin_add_recipient + compile_kit_bundle."
        )
    sender_pub = gcfg.cipher.sender_pub()
    if not sender_pub:
        raise RuntimeError(
            f"compile_enrolment: group {group!r} has no sender_pub in the "
            f"JWE cipher — this party isn't the publisher. Only the "
            f"ceremony creator can compile enrolment packages."
        )
    pkg = Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id=cfg.ceremony_id,
        group=group,
        group_epoch=gcfg.index_epoch,
        signer_did=cfg.device.did,
        signer_verify_pub_b64="",
        peer_did=peer_did,
        payload={
            "publisher_did": cfg.device.did,
            "sender_pub_b64": base64.b64encode(sender_pub).decode("ascii"),
        },
        compiled_at=_now_iso(),
    )
    signed_pkg = sign(pkg, _signing_key(cfg))

    # Attested event: an enrolment package was successfully compiled.
    # Downstream observers (vault, dashboard) use this to track offer state.
    # Uses _canonical_bytes() — the deterministic serialization that covers
    # every field except sig_b64 — so the hash matches what the recipient
    # verifies against.
    from . import logger as _lg

    if _lg._runtime is not None:
        try:
            pkg_sha = "sha256:" + hashlib.sha256(_canonical_bytes(signed_pkg)).hexdigest()
            compiled_at = datetime.now(timezone.utc).isoformat()
            _lg._require_init().emit(
                "info",
                "tn.enrolment.compiled",
                {
                    "group": group,
                    "peer_did": peer_did,
                    "package_sha256": pkg_sha,
                    "compiled_at": compiled_at,
                },
            )
        except Exception as emit_err:  # noqa: BLE001 — preserve broad swallow; see body of handler
            logging.getLogger("tn.compile").warning(
                "enrolment.compiled attestation failed for group=%s peer_did=%s: %s",
                group,
                peer_did,
                emit_err,
            )

    return signed_pkg


def emit_to_outbox(cfg: LoadedConfig, pkg: Package) -> Path:
    """Write pkg to <yaml_dir>/.tn/outbox/ with the conventional filename.

    Now wraps the package in the universal `.tnpkg` manifest header by
    routing through ``tn.export``. The package_kind on the inner Package
    drives the manifest kind on the outer wrapper.
    """
    from .export import export as _export

    out = outbox_dir(cfg.yaml_path.parent) / tnpkg_filename(
        pkg.peer_did,
        pkg.package_kind,
        pkg.package_version,
    )
    return _export(
        out,
        kind=pkg.package_kind,  # "offer" or "enrolment"
        cfg=cfg,
        to_did=pkg.peer_did,
        package=pkg,
    )


# --------------------------------------------------------------------------
# compile_kit_bundle: package a keystore's btn reader kits into a .tnpkg
# (a zip archive) that the Chrome extension, the tn-js CLI, and Python's
# own inbox accepter can all consume. Cross-language parity with
# tn-protocol/ts-sdk/src/compile.ts::compileKitBundle.
# --------------------------------------------------------------------------


def compile_kit_bundle(
    keystore_dir: Path | str | None = None,
    *,
    out_path: Path | str,
    cfg: LoadedConfig | None = None,
    yaml_path: Path | str | None = None,
    groups: list[str] | None = None,
    label: str | None = None,
    note: str | None = None,
    full: bool = False,
    confirm_includes_secrets: bool = False,
) -> Path:
    """Build a `.tnpkg` archive containing the keystore's reader kits.

    This is now a thin wrapper around ``tn.export(kind="kit_bundle")`` /
    ``tn.export(kind="full_keystore")`` — every produced archive carries
    the universal signed manifest header. The kits themselves still live
    inside the zip body at ``body/<group>.btn.mykit`` so chrome-ext /
    tn-js consumers can scan them.

    Provide either ``keystore_dir`` or ``yaml_path`` (or an already
    loaded ``cfg``). The body shape is the same as before; the manifest
    header is new.
    """
    if full and not confirm_includes_secrets:
        raise ValueError(
            "compile_kit_bundle(full=True) writes the publisher's raw private keys "
            "(local.private + index_master.key) into the zip. This is intended for "
            "publisher-to-self backup only. Pass confirm_includes_secrets=True to "
            "acknowledge."
        )

    if cfg is None and yaml_path is not None:
        from .config import load

        cfg = load(Path(yaml_path))
    resolved_keystore = (
        Path(keystore_dir).resolve()
        if keystore_dir is not None
        else (Path(cfg.keystore).resolve() if cfg is not None else None)
    )
    if resolved_keystore is None:
        raise ValueError("compile_kit_bundle: provide keystore_dir, cfg, or yaml_path")
    if not resolved_keystore.is_dir():
        raise FileNotFoundError(f"keystore directory not found: {resolved_keystore}")

    if cfg is None:
        # The new manifest needs an Ed25519 signer. Synthesize a cfg from the
        # keystore so callers that pass keystore_dir without yaml_path still
        # work (this is the path tests like test_compile_kit_bundle_*
        # exercise, where the runtime is closed before the call).
        from .config import load

        sibling_yaml = resolved_keystore.parent / "tn.yaml"
        if sibling_yaml.exists():
            cfg = load(sibling_yaml)
        else:
            raise ValueError(
                "compile_kit_bundle: cannot locate a tn.yaml next to the "
                f"keystore at {resolved_keystore}. Pass cfg=... or yaml_path=... "
                "so the manifest can be signed."
            )

    from .export import export as _export

    return _export(
        out_path,
        kind=("full_keystore" if full else "kit_bundle"),
        cfg=cfg,
        keystore=resolved_keystore,
        groups=groups,
        confirm_includes_secrets=confirm_includes_secrets,
    )
