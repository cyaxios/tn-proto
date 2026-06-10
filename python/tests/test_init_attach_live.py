"""Live proof of ``_init_attach.attach_or_sync`` against the dev vault.

WARM_CREATE: a logged-in account + NEW project → register the project and
PUSH the body using the **cached AWK** (no passphrase at attach time).
WARM_SYNC: re-init the now-existing project → sync, NEVER re-link.

Skips when the dev vault is unreachable (same gate as the other ``*_live``
suites). Run with the tne2e stack up:
    TN_DAY1_VAULT=http://127.0.0.1:38790 python -m pytest \
        python/tests/test_init_attach_live.py -v
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml as _yaml

import tn
from tn._init_attach import (
    AttachMode,
    attach_or_sync,
    cache_account_awk,
)
from tn.cli import _try_warm_attach
from tn.config import load as _load_config
from tn.credential_store import FileCredentialStore, awk_key_name
from tn.identity import Identity, _default_identity_path
from tn.signing import DeviceKey
from tn.wallet_restore_passphrase import derive_account_awk

VAULT_URL = os.environ.get("TN_DAY1_VAULT", "http://127.0.0.1:34987")


def _vault_up() -> bool:
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                f"{VAULT_URL}/api/v1/auth/challenge",
                data=b'{"did":"did:key:z6MkProbe"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            ),
            timeout=3,
        )
    except urllib.error.HTTPError:
        return True  # any HTTP response means the server is live
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _vault_up(),
    reason=f"dev vault unreachable at {VAULT_URL} (TN_DAY1_VAULT)",
)


def _dev_login() -> tuple[str, str, str, str]:
    """``(handle, account_id, token, passphrase)`` for a fresh dev account."""
    handle = "ia" + secrets.token_hex(5)
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/dev/login",
        data=json.dumps({"handle": handle}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        doc = json.loads(resp.read())
    return (
        handle,
        doc["account_id"],
        doc["token"],
        doc.get("passphrase") or f"tn-dev-{handle}",
    )


def _register_device_did(account_token: str, device: DeviceKey) -> None:
    """Enroll ``device``'s DID under the dev account (challenge → sign →
    register) so DID-challenge auth + link_ceremony work for it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/account/dids/challenge",
        data=json.dumps({"did_hint": device.device_identity}).encode(),
        headers={
            "Authorization": f"Bearer {account_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        ch = json.loads(resp.read())
    nonce = base64.b64decode(ch["nonce_b64"])
    sig_b64 = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(device.private_bytes).sign(nonce)
    ).decode("ascii")
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/account/dids",
        data=json.dumps(
            {
                "did": device.device_identity,
                "challenge_id": ch["challenge_id"],
                "signature_b64": sig_b64,
                "source": "minted",
            }
        ).encode(),
        headers={
            "Authorization": f"Bearer {account_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        assert resp.getcode() == 201


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def test_warm_create_then_warm_sync(tmp_path: Path) -> None:
    _handle, account_id, account_token, passphrase = _dev_login()

    # A machine identity logged in to the account: enroll its DID + stamp it.
    identity = Identity.create_new(word_count=12)
    identity.linked_account_id = account_id
    identity.linked_vault = VAULT_URL
    device = DeviceKey.from_private_bytes(identity.device_private_key_bytes())
    _register_device_did(account_token, device)

    # Cache the account AWK (the "connect once" credential).
    awk = derive_account_awk(
        vault_url=VAULT_URL, bearer=account_token, passphrase=passphrase
    )
    store = FileCredentialStore(tmp_path / "credentials.json")
    store.set(awk_key_name(account_id), awk)

    # A fresh, NOT-yet-linked ceremony (no linked_project_id) → WARM_CREATE.
    yaml_path = tmp_path / "proj" / "tn.yaml"
    tn.init(yaml_path, cipher="btn", identity=identity, link=False)
    cfg = tn.current_config()
    tn.ensure_group(cfg, "payments", fields=["amount", "memo"])
    tn.info("order.created", amount=42, memo="hi")
    tn.flush_and_close()

    # Real warm-create precondition (mirrors production): a fresh mode:linked
    # ceremony pointed at the vault it will attach to, with NO linked_project_id
    # yet. The link_ceremony fix (guard on linked_project_id, not mode/vault)
    # is what lets link_ceremony CREATE the project here instead of
    # early-returning — the bug the mocked unit test never caught.
    doc = _yaml.safe_load(yaml_path.read_text()) or {}
    doc.setdefault("ceremony", {})["linked_vault"] = VAULT_URL
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))

    tn.init(yaml_path, identity=identity, link=False)
    cfg = tn.current_config()
    assert not cfg.linked_project_id, "precondition: project must be new"

    # === WARM_CREATE ===
    out = attach_or_sync(cfg, identity, VAULT_URL, store=store)
    tn.flush_and_close()
    assert out.mode is AttachMode.WARM_CREATE, out
    # The body backup ran on the cached AWK (no passphrase passed here).
    assert out.uploaded, f"expected body push; warnings={out.warnings}"
    assert not any("<passphrase>" in w for w in out.warnings), out.warnings
    project_id = out.project_id
    assert project_id, "WARM_CREATE must register the project"

    # === WARM_SYNC: reload the now-linked ceremony from disk (the runtime is
    # closed) and attach again → sync, NEVER re-link. ===
    cfg = _load_config(yaml_path)
    assert cfg.linked_project_id == project_id, "link must have persisted"
    out2 = attach_or_sync(cfg, identity, VAULT_URL, store=store)
    assert out2.mode is AttachMode.WARM_SYNC, out2
    assert out2.project_id == project_id, "must reuse the same project, not re-link"
    assert not any("<passphrase>" in w for w in out2.warnings), out2.warnings


def test_wired_connect_cache_then_init(tmp_path: Path, capsys, monkeypatch) -> None:
    """The fully WIRED path through the real CLI helpers, default store:

      `tn account connect --passphrase`  → cache_account_awk → DEFAULT store
      `tn init` (warm)                    → _try_warm_attach → reads DEFAULT
                                            store → body push, no passphrase.
    """
    # Isolate the machine default identity dir + credential store.
    monkeypatch.setenv("TN_IDENTITY_DIR", str(tmp_path / "id"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    _handle, account_id, account_token, passphrase = _dev_login()

    identity = Identity.create_new(word_count=12)
    identity.linked_account_id = account_id
    identity.linked_vault = VAULT_URL
    identity.ensure_written(_default_identity_path())
    device = DeviceKey.from_private_bytes(identity.device_private_key_bytes())
    _register_device_did(account_token, device)

    # Pre-build the ceremony pointed at the dev vault (the warm-attach target),
    # no project yet → WARM_CREATE. _try_warm_attach's internal tn_init LOADS
    # this existing yaml (preserving linked_vault) instead of re-minting.
    yaml_path = tmp_path / "proj" / "tn.yaml"
    tn.init(yaml_path, cipher="btn", identity=identity, link=False)
    cfg = tn.current_config()
    tn.ensure_group(cfg, "payments", fields=["amount"])
    tn.info("order.created", amount=1)
    tn.flush_and_close()
    doc = _yaml.safe_load(yaml_path.read_text()) or {}
    doc.setdefault("ceremony", {})["linked_vault"] = VAULT_URL
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))

    # `tn account connect --passphrase` step → cache the AWK to the DEFAULT store.
    cache_account_awk(identity, VAULT_URL, passphrase, account_id)

    # `tn init` warm path → reads the cached AWK from the DEFAULT store + pushes.
    ok = _try_warm_attach(yaml_path, identity, VAULT_URL, "btn")
    assert ok is True, "warm-attach should have run (not fall back to claim URL)"

    out = capsys.readouterr().out
    assert "Attached to your vault account" in out, out
    # The cached AWK was found + used: a real body push, no missing-credential warn.
    assert "uploaded: 0 file(s)" not in out, out
    assert "<passphrase>" not in out, out
