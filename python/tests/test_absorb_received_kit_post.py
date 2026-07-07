"""Tests for the absorb -> /received-kits vault POST hook.

The dashboard's "Absorb" action POSTs to
``/api/v1/account/received-kits`` after the browser-side parse so the
/projects -> Received tab surfaces the absorbed kit. The CLI's
``tn absorb`` now does the same on success when the ceremony has been
bound to a vault account via ``tn account connect``. This test drives
``_absorb_kit_bundle`` end-to-end against an httpx.MockTransport-backed
VaultClient and asserts the exact POST body shape the vault expects.

Run:
    python -m pytest python/tests/test_absorb_received_kit_post.py -v
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import base64
import json
from pathlib import Path

import httpx
import pytest

import tn
from tn.absorb import _absorb_dispatch
from tn.config import load_or_create
from tn.export import export, export_identity_seed
from tn.identity import Identity, _default_identity_path
from tn.signing import DeviceKey
from tn.sync_state import mark_account_bound
from tn.vault_client import VaultClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


@pytest.fixture
def isolated_identity_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin TN_IDENTITY_DIR at a fresh tmp dir so Identity.load + ensure_written
    are scoped to this test."""
    idir = tmp_path / "tn-identity"
    monkeypatch.setenv("TN_IDENTITY_DIR", str(idir))
    return idir


class _FakeCfg:
    """Minimal LoadedConfig stand-in (mirrors test_kit_bundle_fanout)."""

    def __init__(self, host_dir: Path, device: DeviceKey):
        host_dir.mkdir(parents=True, exist_ok=True)
        self.yaml_path = host_dir / "tn.yaml"
        self.keystore = host_dir / "keys"
        self.keystore.mkdir(parents=True, exist_ok=True)
        self.device = device


def _install_recipient(workdir: Path, device: DeviceKey, name: str) -> _FakeCfg:
    pkg_path = workdir / f"{name}_id.tnpkg"
    export_identity_seed(pkg_path, device=device, nickname=name)
    cfg = _FakeCfg(workdir / name, device)
    receipt = _absorb_dispatch(cfg, pkg_path)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason
    return cfg


def _make_publisher(workdir: Path):
    yaml_path = workdir / "alice" / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    return load_or_create(yaml_path, cipher=_workflow_cipher("btn"))


def _install_mock_vault_client(
    monkeypatch: pytest.MonkeyPatch, handler
):
    """Replace VaultClient.for_identity with one that wires our transport."""

    def fake_for_identity(identity, base_url=None, *, auto_auth=True):
        from tn.vault_client import resolve_vault_url

        transport = httpx.MockTransport(handler)
        http = httpx.Client(transport=transport)
        client = VaultClient(
            base_url=resolve_vault_url(base_url),
            identity=identity,
            _http=http,
        )
        if auto_auth:
            client.authenticate()
        return client

    monkeypatch.setattr(
        VaultClient, "for_identity", staticmethod(fake_for_identity)
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_absorb_kit_bundle_posts_received_kit_when_account_bound(
    tmp_path: Path,
    isolated_identity_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """End-to-end: mint a kit_bundle, bind the recipient ceremony to a
    fake vault account, absorb, and verify the vault POST body."""
    # Publisher mints a kit_bundle for the recipient.
    alice_cfg = _make_publisher(tmp_path)
    bob_dev = DeviceKey.generate()
    bob_cfg = _install_recipient(tmp_path, bob_dev, "bob")

    out = tmp_path / "kit_for_bob.tnpkg"
    export(out, kind="kit_bundle", cfg=alice_cfg, to_dids=[bob_dev.did])

    # Stamp an on-disk identity that ties to bob's device key. Without
    # an on-disk identity, the POST hook silently skips (the operator
    # is running ephemeral).
    identity = Identity.create_new()
    identity.ensure_written(_default_identity_path())
    # And bind bob's ceremony to a fake vault account.
    mark_account_bound(bob_cfg.yaml_path, "acct_test_01HVAULT")

    # MockTransport that captures the POST.
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/challenge":
            return httpx.Response(200, json={"nonce": "n0nce"})
        if request.url.path == "/api/v1/auth/verify":
            return httpx.Response(200, json={"token": "test-jwt"})
        if request.url.path == "/api/v1/account/received-kits":
            captured["method"] = request.method
            captured["body"] = json.loads(request.content.decode("utf-8"))
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(
                201,
                json={
                    "kit_id": "01HKIT123",
                    "account_id": "acct_test_01HVAULT",
                    "project_id": captured["body"]["project_id"],
                    "publisher_identity": captured["body"]["publisher_identity"],
                    "recipient_identity": captured["body"]["recipient_identity"],
                    "label": captured["body"].get("label"),
                    "received_at": "2026-05-21T00:00:00+00:00",
                    "source_ts": captured["body"].get("source_ts"),
                    "source_ceremony_id": captured["body"].get("source_ceremony_id"),
                },
            )
        return httpx.Response(404)

    _install_mock_vault_client(monkeypatch, handler)

    # Drive the absorb (which now calls _maybe_post_received_kit on
    # success).
    receipt = _absorb_dispatch(bob_cfg, out)
    assert receipt.kind == "kit_bundle"
    assert receipt.legacy_status == "enrolment_applied"

    # POST was issued with the expected wire shape.
    assert captured.get("method") == "POST", f"no POST captured: {captured}"
    body = captured["body"]
    assert body["project_id"] == alice_cfg.ceremony_id
    assert body["publisher_identity"] == alice_cfg.device.device_identity
    assert body["recipient_identity"] == bob_dev.did
    # Manifest is the full dict.
    assert isinstance(body["manifest"], dict)
    assert body["manifest"]["kind"] == "kit_bundle"
    assert body["manifest"]["publisher_identity"] == alice_cfg.device.device_identity
    # Kit blob is base64 of body/<group>.btn.mykit. Decoding must yield bytes.
    assert isinstance(body["kit_blob_b64"], str) and body["kit_blob_b64"]
    decoded = base64.b64decode(body["kit_blob_b64"])
    assert len(decoded) > 0
    # source_ts / source_ceremony_id mirror the manifest.
    assert body["source_ts"] == body["manifest"]["as_of"]
    assert body["source_ceremony_id"] == alice_cfg.ceremony_id
    # Bearer auth was sent (the same JWT the challenge/verify dance produced).
    assert captured["auth"] == "Bearer test-jwt"


def test_absorb_kit_bundle_skips_post_when_not_account_bound(
    tmp_path: Path,
    isolated_identity_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Without `tn account connect`, the POST hook is a no-op."""
    alice_cfg = _make_publisher(tmp_path)
    bob_dev = DeviceKey.generate()
    bob_cfg = _install_recipient(tmp_path, bob_dev, "bob")

    out = tmp_path / "kit_for_bob.tnpkg"
    export(out, kind="kit_bundle", cfg=alice_cfg, to_dids=[bob_dev.did])

    # On-disk identity present, but ceremony NOT bound. No POST.
    identity = Identity.create_new()
    identity.ensure_written(_default_identity_path())
    # NB: mark_account_bound is intentionally NOT called.

    def handler(request: httpx.Request) -> httpx.Response:
        # Auth handshake may still get called by other code paths; only
        # /received-kits must never be hit.
        if request.url.path.endswith("/account/received-kits"):
            raise AssertionError(
                f"unexpected POST to {request.url}; absorb hit the vault "
                f"without an account binding"
            )
        # Default: succeed silently for any other path the helper might
        # try (challenge/verify, etc.).
        if request.url.path == "/api/v1/auth/challenge":
            return httpx.Response(200, json={"nonce": "n0nce"})
        if request.url.path == "/api/v1/auth/verify":
            return httpx.Response(200, json={"token": "test-jwt"})
        return httpx.Response(404)

    _install_mock_vault_client(monkeypatch, handler)

    receipt = _absorb_dispatch(bob_cfg, out)
    assert receipt.kind == "kit_bundle"
    assert receipt.legacy_status == "enrolment_applied"


def test_absorb_kit_bundle_swallows_vault_failure(
    tmp_path: Path,
    isolated_identity_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A 500 from the vault must NOT fail the local absorb."""
    alice_cfg = _make_publisher(tmp_path)
    bob_dev = DeviceKey.generate()
    bob_cfg = _install_recipient(tmp_path, bob_dev, "bob")

    out = tmp_path / "kit_for_bob.tnpkg"
    export(out, kind="kit_bundle", cfg=alice_cfg, to_dids=[bob_dev.did])

    identity = Identity.create_new()
    identity.ensure_written(_default_identity_path())
    mark_account_bound(bob_cfg.yaml_path, "acct_test")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/challenge":
            return httpx.Response(200, json={"nonce": "n0nce"})
        if request.url.path == "/api/v1/auth/verify":
            return httpx.Response(200, json={"token": "test-jwt"})
        if request.url.path == "/api/v1/account/received-kits":
            return httpx.Response(500, json={"detail": "boom"})
        return httpx.Response(404)

    _install_mock_vault_client(monkeypatch, handler)

    # Must NOT raise — local absorb is the source of truth, vault row
    # is metadata.
    receipt = _absorb_dispatch(bob_cfg, out)
    assert receipt.kind == "kit_bundle"
    assert receipt.legacy_status == "enrolment_applied"
