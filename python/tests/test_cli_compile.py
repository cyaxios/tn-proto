"""Tests for ``tn.cli_compile.cmd_compile`` — the Python parity of the
TypeScript ``tn-js compile`` verb.

Exercises every branch of :func:`tn.cli_compile.cmd_compile`:
happy readers-only compile, ``--kit`` group selection, ``--full`` private-
key bundle, missing ``--out``, missing ``--keystore``, and the error
path when no ``*.btn.mykit`` files match. Each success case also asserts
the produced ``.tnpkg`` is a readable universal-manifest archive so we
prove cross-impl shape (the body holds ``body/<group>.btn.mykit`` kits
that the TS/chrome readers scan, under a Python-``absorb``-able manifest).
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

import pytest

import tn
from tn.cli_compile import cmd_compile
from tn.config import load_or_create
from tn.tnpkg import _read_manifest, _verify_manifest_signature


def _bootstrap_btn_keystore(tmp_path: Path) -> Path:
    """Init a btn ceremony so the keystore holds a ``*.btn.mykit`` file
    for compile to bundle. Returns the keystore directory.

    Mirrors the proven fixture in ``tests/test_compile.py``.
    """
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    cfg = load_or_create(yaml)
    return cfg.keystore


def _ns(**kw) -> argparse.Namespace:
    """Build an argparse.Namespace with the compile defaults filled in."""
    base = {"keystore": None, "out": None, "kit": None, "label": None, "full": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_compile_happy_readers_only(tmp_path: Path, capsys):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"

    rc = cmd_compile(_ns(keystore=str(keystore), out=str(out), label="my-kit"))

    assert rc == 0
    assert out.exists()

    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["ok"] is True
    assert payload["out"] == str(out.resolve())
    assert payload["label"] == "my-kit"
    # readers-only is the TS-compatible kind discriminator.
    assert payload["kind"] == "readers-only"
    assert payload["kits"], "expected at least one bundled kit"
    assert all(name.endswith(".btn.mykit") for name in payload["kits"])

    # The produced archive must be a readable universal `.tnpkg`: signed
    # manifest + body/<group>.btn.mykit kits that chrome-ext / tn-js scan.
    manifest, body = _read_manifest(out)
    assert manifest.kind == "kit_bundle"
    assert any(name.startswith("body/") and name.endswith(".btn.mykit") for name in body)
    # No private-key marker on the readers-only path.
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" not in body
    # The label is PERSISTED in the manifest (state.label), not merely
    # echoed in the JSON. A re-read of the archive recovers it, mirroring
    # the TS legacy manifest's top-level `label` field.
    assert manifest.state is not None
    assert manifest.state.get("label") == "my-kit"
    # The injected label rides inside the signature domain — the re-signed
    # manifest must still verify against the publisher's device key.
    assert _verify_manifest_signature(manifest) is True


def test_compile_kit_selection(tmp_path: Path, capsys):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "sel.tnpkg"

    # Select only the "default" group — it exists in a fresh btn ceremony.
    rc = cmd_compile(_ns(keystore=str(keystore), out=str(out), kit=["default"]))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["kind"] == "readers-only"
    # Every bundled kit belongs to the requested group.
    assert payload["kits"] == ["default.btn.mykit"]


def test_compile_label_persisted_in_reread(tmp_path: Path, capsys):
    """The label survives a full re-read of the produced ``.tnpkg`` and the
    re-signed manifest still verifies. This is the regression for the
    --label gap: the SDK producer dropped the label, so a re-read used to
    show no label even though the JSON echoed one."""
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "labelled.tnpkg"

    rc = cmd_compile(
        _ns(keystore=str(keystore), out=str(out), label="quarterly-readers")
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["label"] == "quarterly-readers"

    # Re-open the archive from disk (fresh read, no in-memory state) and
    # confirm the label is actually stored under manifest.state.label.
    manifest, _body = _read_manifest(out)
    assert manifest.state is not None
    assert manifest.state.get("label") == "quarterly-readers"
    # The producer's kit metadata is still present alongside the label.
    assert manifest.state.get("kind") == "readers-only"
    assert manifest.state.get("kits")
    # Signature still valid after the label injection + re-sign.
    assert _verify_manifest_signature(manifest) is True


def test_compile_no_label_omits_state_label(tmp_path: Path, capsys):
    """When --label is not given, no spurious label key is written into the
    manifest state, and the manifest is the producer's original signature
    (we don't needlessly re-sign)."""
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "nolabel.tnpkg"

    rc = cmd_compile(_ns(keystore=str(keystore), out=str(out)))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["label"] is None

    manifest, _body = _read_manifest(out)
    # No label key at all when none was requested.
    assert manifest.state is not None
    assert "label" not in manifest.state
    # Producer signature is intact regardless.
    assert _verify_manifest_signature(manifest) is True


def test_compile_full_bundles_private_keys(tmp_path: Path, capsys):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "full.tnpkg"

    rc = cmd_compile(_ns(keystore=str(keystore), out=str(out), full=True))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["kind"] == "full-keystore"

    manifest, body = _read_manifest(out)
    assert manifest.kind == "full_keystore"
    # The full path writes the zero-byte private-key warning marker.
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" in body
    assert body["body/WARNING_CONTAINS_PRIVATE_KEYS"] == b""


def test_compile_missing_out_returns_2(tmp_path: Path, capsys):
    keystore = _bootstrap_btn_keystore(tmp_path)
    rc = cmd_compile(_ns(keystore=str(keystore), out=None))
    assert rc == 2
    assert "--out" in capsys.readouterr().err


def test_compile_missing_keystore_returns_2(tmp_path: Path, capsys):
    rc = cmd_compile(_ns(keystore=None, out=str(tmp_path / "x.tnpkg")))
    assert rc == 2
    assert "--keystore" in capsys.readouterr().err


def test_compile_keystore_not_found_returns_2(tmp_path: Path, capsys):
    missing = tmp_path / "nope"
    rc = cmd_compile(_ns(keystore=str(missing), out=str(tmp_path / "x.tnpkg")))
    assert rc == 2
    err = capsys.readouterr().err
    assert "compile:" in err


def test_compile_keystore_dir_without_yaml_returns_2(tmp_path: Path, capsys):
    """A real (empty) keystore directory with no ``tn.yaml`` anywhere up
    the tree exercises ``_discover_yaml``'s no-match branch (returns None),
    after which the SDK can't sign the manifest → exit 2.
    """
    keystore = tmp_path / "isolated_keystore"
    keystore.mkdir()
    out = tmp_path / "x.tnpkg"
    rc = cmd_compile(_ns(keystore=str(keystore), out=str(out)))
    assert rc == 2
    assert "compile:" in capsys.readouterr().err
    assert not out.exists()


def test_compile_no_kits_returns_2(tmp_path: Path, capsys):
    """A keystore directory with no ``*.btn.mykit`` files but a sibling
    tn.yaml (so the manifest signer resolves) hits the SDK's 'no kits'
    RuntimeError, which the CLI maps to exit 2.
    """
    keystore = _bootstrap_btn_keystore(tmp_path)
    # Filter to a group that does not exist → no kits match.
    out = tmp_path / "empty.tnpkg"
    rc = cmd_compile(
        _ns(keystore=str(keystore), out=str(out), kit=["does-not-exist"])
    )
    assert rc == 2
    assert "compile:" in capsys.readouterr().err
    assert not out.exists()
