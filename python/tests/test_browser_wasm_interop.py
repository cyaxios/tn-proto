"""Cross-language interop: Python decrypts ciphertext minted by browser tn-wasm.

Wave 4 / Session 8 acceptance bar — the JS dashboard's snapshot_builder
must produce bytes that the Python SDK reads/verifies, AND wasm-side
encryption must yield ciphertext that `tn_btn.decrypt` reads.

Two-step pipeline:
  1. Run `node tnproto-org/static/dashboard/test/wasm_e2e.test.mjs` to
     produce `kit.bin`, `ciphertext.bin`, `plaintext.txt`, `snapshot.tnpkg`,
     and `meta.json` in <tmpdir>/wasm-interop/.
  2. Run this pytest — reads those artifacts and verifies:
       * `tn_btn.decrypt(kit, ct) == plaintext`  (BTN cipher interop)
       * `tn.tnpkg._read_manifest(snapshot)` parses cleanly      (zip interop)
       * `_verify_manifest_signature(manifest)` returns True     (sig interop)

If the wasm test hasn't been run, this test invokes it. The Node binary
is found via PATH; if absent the test skips with a clear message.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
WASM_TEST_PATH = REPO_ROOT / "tnproto-org" / "static" / "dashboard" / "test" / "wasm_e2e.test.mjs"
INTEROP_DIR = Path(tempfile.gettempdir()) / "wasm-interop"


def _ensure_wasm_artifacts() -> Path:
    """Run the Node wasm test to (re)generate artifacts under INTEROP_DIR.

    If `node` is not on PATH we skip — this test only makes sense in an
    environment that can run the JS side.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not on PATH; cannot generate wasm interop artifacts")
    if not WASM_TEST_PATH.exists():
        pytest.fail(f"wasm e2e test not found at {WASM_TEST_PATH}")
    proc = subprocess.run(
        [node, str(WASM_TEST_PATH)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"wasm_e2e.test.mjs failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return INTEROP_DIR


def test_python_decrypts_browser_wasm_ciphertext():
    """The headline assertion: Python's tn_btn.decrypt accepts wasm
    BtnPublisher.encrypt output, byte-for-byte plaintext recovery.
    """
    interop = _ensure_wasm_artifacts()
    kit_path = interop / "kit.bin"
    ct_path = interop / "ciphertext.bin"
    pt_path = interop / "plaintext.txt"
    for p in (kit_path, ct_path, pt_path):
        assert p.exists(), f"missing wasm artifact: {p}"

    import tn_btn

    kit = kit_path.read_bytes()
    ct = ct_path.read_bytes()
    expected = pt_path.read_bytes()

    decrypted = tn_btn.decrypt(kit, ct)
    assert decrypted == expected, (
        "Python tn_btn.decrypt did NOT recover the wasm-encrypted plaintext. "
        f"got {len(decrypted)} bytes, expected {len(expected)} bytes."
    )


def test_python_reads_browser_built_tnpkg_and_verifies_signature():
    """The structural assertion: snapshot_builder.js produces a real .tnpkg
    that tn.tnpkg._read_manifest accepts and _verify_manifest_signature
    confirms against from_did.
    """
    interop = _ensure_wasm_artifacts()
    pkg_path = interop / "snapshot.tnpkg"
    meta_path = interop / "meta.json"
    assert pkg_path.exists(), f"missing snapshot.tnpkg at {pkg_path}"
    assert meta_path.exists(), f"missing meta.json at {meta_path}"

    import json

    from tn.tnpkg import _read_manifest, _verify_manifest_signature

    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    manifest, body = _read_manifest(pkg_path)

    # Manifest fields match what the JS side emitted.
    assert manifest.kind == "kit_bundle"
    assert manifest.version == 1
    assert manifest.from_did == meta["from_did"]
    assert manifest.to_did == meta["to_did"]
    assert manifest.ceremony_id == meta["ceremony_id"]
    assert manifest.manifest_signature_b64, "manifest is signed"

    # Body files: at minimum the kit + admin.ndjson.
    assert "body/default.btn.mykit" in body, f"kit body file missing; got {sorted(body)}"
    assert "body/admin.ndjson" in body, f"admin ndjson missing; got {sorted(body)}"

    # The structural check.
    ok = _verify_manifest_signature(manifest)
    assert ok, (
        "Python _verify_manifest_signature rejected the JS-built manifest. "
        "Either the canonical-bytes serialization in snapshot_builder.js "
        "drifted from tn.canonical, or the signature wiring is wrong."
    )


def test_python_can_decrypt_kit_from_browser_built_tnpkg():
    """End-to-end: read the kit OUT of the JS-built tnpkg, then use it
    against the published ciphertext. Closes the loop on
    "Python recipient absorbs JS publisher's snapshot".
    """
    interop = _ensure_wasm_artifacts()
    pkg_path = interop / "snapshot.tnpkg"
    ct_path = interop / "ciphertext.bin"
    pt_path = interop / "plaintext.txt"

    from tn.tnpkg import _read_manifest

    _manifest, body = _read_manifest(pkg_path)
    kit_from_pkg = body.get("body/default.btn.mykit")
    assert kit_from_pkg is not None, "kit not present in browser-built tnpkg"

    import tn_btn

    decrypted = tn_btn.decrypt(kit_from_pkg, ct_path.read_bytes())
    assert decrypted == pt_path.read_bytes()


def test_browser_extracts_package_key_from_python_built_full_keystore_body(tmp_path):
    """Cross-language: Python builds a real `full_keystore` tnpkg, the JS
    body_unpacker pulls `local.private` out of its body, and the extracted
    key signs a message that Python verifies against the same DID.

    This is the headline assertion for Wave 5 (replace sessionStorage
    package-key stopgap with real body parsing).

    Two-step flow:
      1. Python writes /tmp/body-extract/{body.bin, expected_priv.bin,
         expected_did.txt, msg.bin}.
      2. Node script reads body.bin, runs extractPackageKeyFromBody,
         writes /tmp/body-extract/{actual_priv.bin, sig.bin, marker.txt}.
      3. Python verifies actual_priv.bin == expected_priv.bin AND that
         sig.bin verifies under expected_did's public key on msg.bin.
    """
    import json
    import os
    import shutil
    import subprocess
    import zipfile

    import tn
    from tn.export import export

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not on PATH; cannot run cross-language extract test")

    # ── Step 1: Python builds a real full_keystore tnpkg ──────────────
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()
    pkg_path = tmp_path / "full.tnpkg"
    export(pkg_path, kind="full_keystore", cfg=cfg, confirm_includes_secrets=True)
    tn.flush_and_close()

    # The tnpkg has manifest.json + body/<files>. Extract just the body
    # portion as a fresh inner-zip — that's what the browser sees after
    # decrypting an encrypted-blob (the encrypted-blob plaintext IS the
    # body zip, NOT the outer tnpkg). We synthesize that zip from the
    # tnpkg's body/* entries.
    keystore_dir = cfg.keystore
    expected_priv = (keystore_dir / "local.private").read_bytes()
    expected_did = cfg.device.did
    assert len(expected_priv) == 32, "Ed25519 seed is 32 bytes"

    # Build the body zip the browser would see (same files, no
    # manifest.json).
    body_zip_path = tmp_path / "body.zip"
    with zipfile.ZipFile(pkg_path) as src, zipfile.ZipFile(
        body_zip_path, "w", zipfile.ZIP_STORED,
    ) as dst:
        for name in src.namelist():
            if name == "manifest.json":
                continue
            dst.writestr(name, src.read(name))

    # ── Step 2: Pass artifacts to Node, get back signed proof ─────────
    work = Path(tempfile.gettempdir()) / "body-extract"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    msg = b"cross-language extract test: Python built body, JS pulled key, signed this."
    (work / "body.bin").write_bytes(body_zip_path.read_bytes())
    (work / "expected_priv.bin").write_bytes(expected_priv)
    (work / "expected_did.txt").write_text(expected_did, encoding="utf-8")
    (work / "msg.bin").write_bytes(msg)

    runner_path = (
        REPO_ROOT
        / "tnproto-org"
        / "static"
        / "dashboard"
        / "test"
        / "body_extract_runner.mjs"
    )
    assert runner_path.exists(), f"missing runner: {runner_path}"

    proc = subprocess.run(
        [node, str(runner_path), str(work)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
        env={**os.environ},
    )
    if proc.returncode != 0:
        pytest.fail(
            f"body_extract_runner.mjs failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    # ── Step 3: Python validates ──────────────────────────────────────
    actual_priv = (work / "actual_priv.bin").read_bytes()
    sig = (work / "sig.bin").read_bytes()
    marker = (work / "marker.txt").read_text(encoding="utf-8").strip()
    assert marker == "ok", f"runner marker not ok: {marker}"

    assert actual_priv == expected_priv, (
        "JS body_unpacker.extractPackageKeyFromBody returned different "
        "bytes than Python wrote into body/local.private. "
        f"expected {len(expected_priv)} bytes, got {len(actual_priv)} bytes; "
        f"first-byte expected={expected_priv[:1].hex()} got={actual_priv[:1].hex()}"
    )

    # The signature was produced by wasm.signMessage(extracted_priv, msg).
    # Verify under the DID's public key — proves the key isn't just byte-
    # equal but is the *real* signing key Python committed to.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from tn.tnpkg import _did_key_pub

    pub_bytes = _did_key_pub(expected_did)
    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, msg)


def test_python_encrypted_body_zip_round_trips_through_browser_parser(tmp_path):
    """Cross-language: Python builds an encrypted body in the new STORED-zip
    format (D-N), the JS dashboard's body parser (zip-first, custom-frame
    fallback) reads it, and the recovered file map matches byte-for-byte
    what Python wrote.

    Closes the loop on the body-format refactor: server side and browser
    side agree on the inner-zip plaintext shape.
    """
    import json
    import os
    import shutil
    import subprocess

    from tn.export import _encrypt_body_in_place

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not on PATH; cannot run cross-language body-zip test")

    # ── Step 1: Python encrypts a body dict in the new format ─────────
    body = {
        "body/local.private": b"\x42" * 32,
        "body/local.public": b"did:key:z6MkInteropPubkey",
        "body/tn.yaml": (
            b"ceremony_id: local_interop\n"
            b"cipher: btn\n"
            b"groups:\n"
            b"  default:\n"
            b"    policy: open\n"
            b"    cipher: btn\n"
            b"    recipients: []\n"
        ),
        "body/default.btn.mykit": os.urandom(160),
        "body/default.btn.state": os.urandom(120),
    }
    key = os.urandom(32)

    new_body, extras = _encrypt_body_in_place(body, {}, key)
    assert (
        extras["state"]["body_encryption"]["frame"] == "tn-encrypted-body-v2-zip"
    ), "Python should be writing the new zip-format extras label"
    blob = new_body["body/encrypted.bin"]

    # ── Step 2: Hand artifacts to Node ────────────────────────────────
    work = tmp_path / "encrypted-body-zip"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    (work / "blob.bin").write_bytes(blob)
    (work / "key.bin").write_bytes(key)

    runner_path = (
        REPO_ROOT
        / "tnproto-org"
        / "static"
        / "dashboard"
        / "test"
        / "encrypted_body_zip_runner.mjs"
    )
    assert runner_path.exists(), f"missing runner: {runner_path}"

    proc = subprocess.run(
        [node, str(runner_path), str(work)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
        env={**os.environ},
    )
    if proc.returncode != 0:
        pytest.fail(
            f"encrypted_body_zip_runner.mjs failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    # ── Step 3: Python validates ──────────────────────────────────────
    assert (work / "marker.txt").read_text(encoding="utf-8").strip() == "ok"
    manifest = json.loads((work / "recovered.json").read_text(encoding="utf-8"))
    assert manifest["format"] == "zip", (
        "JS parser took the legacy-frame path on a Python-built zip body; "
        "the format dispatch is broken"
    )
    assert set(manifest["files"].keys()) == set(body.keys()), (
        f"recovered file set differs: js={sorted(manifest['files'])} "
        f"py={sorted(body)}"
    )
    files_dir = work / "files"
    for name, expected in body.items():
        safe = name.replace("\\", "__").replace("/", "__")
        actual = (files_dir / safe).read_bytes()
        assert actual == expected, (
            f"file {name!r}: js recovered {len(actual)} bytes, python wrote "
            f"{len(expected)} bytes"
        )


if __name__ == "__main__":
    # Allow running standalone without pytest harness.
    test_python_decrypts_browser_wasm_ciphertext()
    test_python_reads_browser_built_tnpkg_and_verifies_signature()
    test_python_can_decrypt_kit_from_browser_built_tnpkg()
    print("ok: all browser↔python interop tests passed")
