"""``tn compile`` — package a keystore's btn reader kits into a ``.tnpkg``.

Python parity for the TypeScript ``tn-js compile`` verb
(``ts-sdk/bin/tn-js.mjs::compileCmd`` → ``compileKitBundleToFile``).

This is a thin CLI over the existing Python SDK packaging surface
:func:`tn.compile.compile_kit_bundle` (which itself routes through the
universal ``tn.export`` producer). It does NOT reimplement zip/crypto —
the produced ``.tnpkg`` is the universal signed-manifest archive that
Python ``tn absorb`` and the chrome-ext / tn-js readers consume.

Flags mirror the TS CLI::

    tn compile --keystore <dir> --out <file.tnpkg> [--kit <group>]...
               [--label <text>] [--full]

On success it prints a single JSON line
(``{"ok": true, "out", "kits", "kind", "label"}``) like the TS verb, so
scripts can parse either implementation's output the same way. Exit code
0 on success, 2 on any failure (missing keystore, no kits, bad args).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .compile import compile_kit_bundle
from .tnpkg import _read_manifest


def _discover_yaml(keystore: Path) -> Path | None:
    """Find the ceremony ``tn.yaml`` for ``keystore``.

    The universal ``.tnpkg`` manifest is Ed25519-signed by the ceremony's
    device key, so the SDK needs the ``tn.yaml`` to resolve that key. The
    SDK auto-discovers a yaml that sits directly beside the keystore, but
    the modern on-disk layout nests the keystore at
    ``<root>/.tn/<stem>/keys/`` — the yaml lives further up at
    ``<root>/tn.yaml``. We walk up from the keystore and return the first
    ``tn.yaml`` we find, or ``None`` if none exists (the SDK then raises a
    pointed error which we surface as exit 2).
    """
    for parent in (keystore, *keystore.parents):
        candidate = parent / "tn.yaml"
        if candidate.is_file():
            return candidate
    return None


def cmd_compile(args: argparse.Namespace) -> int:
    """Compile keystore reader kits into a ``.tnpkg``.

    Expects an ``argparse.Namespace`` carrying:

    * ``keystore`` — keystore directory holding ``*.btn.mykit`` files.
    * ``out`` — destination ``.tnpkg`` path (required).
    * ``kit`` — optional list of group names to include (``None`` / empty
      means every group, matching the TS ``--kit`` repeatable flag).
    * ``label`` — optional human-readable label echoed in the result.
    * ``full`` — when true, bundle private key material too
      (``full_keystore`` kind); requires the secret-acknowledgment gate,
      which we pass through on the operator's behalf since ``--full`` is
      the explicit opt-in.
    """
    out = getattr(args, "out", None)
    if not out:
        print("compile: --out <file> is required", file=sys.stderr)
        return 2

    keystore = getattr(args, "keystore", None)
    if not keystore:
        print("compile: --keystore <dir> is required", file=sys.stderr)
        return 2

    groups = list(args.kit) if getattr(args, "kit", None) else None
    label = getattr(args, "label", None)
    full = bool(getattr(args, "full", False))

    keystore_path = Path(keystore)
    yaml_path = _discover_yaml(keystore_path) if keystore_path.is_dir() else None

    try:
        out_path = compile_kit_bundle(
            keystore,
            out_path=out,
            yaml_path=yaml_path,
            groups=groups,
            label=label,
            full=full,
            # --full is the explicit opt-in; pass the secret gate through
            # so the SDK's foot-gun guard doesn't reject the deliberate
            # request. Without --full this stays False and is a no-op.
            confirm_includes_secrets=full,
        )
    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"compile: {exc}", file=sys.stderr)
        return 2

    # Read the produced manifest back so the printed summary reflects the
    # archive on disk (kit names + kind), mirroring the TS CLI's JSON
    # line. The universal manifest carries the kit list + the
    # readers-only/full-keystore discriminator under ``state``.
    manifest, _body = _read_manifest(Path(out_path))
    state = manifest.state or {}
    kit_entries = state.get("kits") or []
    kits = [entry.get("name") for entry in kit_entries]
    # ``state.kind`` is the TS-compatible string ("readers-only" /
    # "full-keystore"); fall back to the manifest's own kind discriminator
    # if an older producer omitted it.
    kind = state.get("kind") or manifest.kind

    print(
        json.dumps(
            {
                "ok": True,
                "out": str(out_path),
                "kits": kits,
                "kind": kind,
                "label": label,
            }
        )
    )
    return 0
