"""Day-1 TWO-DEVICE group sync against a LIVE dev vault.

Real round-trips, no mock. Exercises the append-only account-inbox MERGE
path (group_keys snapshot), NOT the last-write-wins body blob:

  - PUBLISH: ``tn.wallet.sync_ceremony`` packs the body blob AND, in
    addition, publishes a ``group_keys`` ``.tnpkg`` (group ``.btn.state`` /
    ``.btn.mykit`` + the yaml ``groups.<name>`` block, NO device secret) to
    the OWN account inbox via
    ``POST /api/v1/inbox/{did}/snapshots/{ceremony}/{ts}.tnpkg``, signed as
    the account-bound device DID.
  - PULL+ABSORB: the SECOND device on the same account pulls the account
    inbox (``GET /api/v1/account/inbox``), downloads each snapshot, and
    ``tn.absorb``s it. The ``group_keys`` absorb INSTALLS the key files
    content-addressed and UNION-merges the ``groups:`` yaml block, so a
    fresh ``tn.init`` over the same yaml routes ``tn.info`` / read through
    the new group — USABLE, not merely known.

Both devices belong to ONE dev account. Each device's Ed25519 DID is
registered under the account via ``/account/dids`` (challenge + sign) so
(a) the inbox POST authenticates AS that DID (the route requires
``auth_did == publisher_identity``) and (b) the account-inbox aggregator
surfaces the snapshot to the other device (``recipient_identity`` is one of
the account's owned DIDs).

Skips cleanly when the vault at ``$TN_DAY1_VAULT`` (default
``http://127.0.0.1:34987``) is unreachable.

Run:
    cd python && COVERAGE_CORE=sysmon PYTHONPATH=. \\
      <venv>/python.exe -m pytest -q \\
      tests/test_day1_two_device_group_sync_live.py
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import yaml as _yaml

import tn
from tn import wallet as _wallet
from tn.signing import DeviceKey
from tn.vault_client import VaultClient

VAULT_URL = os.environ.get("TN_DAY1_VAULT", "http://127.0.0.1:34987")


# ── Vault reachability gate ────────────────────────────────────────────


def _vault_reachable() -> bool:
    try:
        req = urllib.request.Request(
            f"{VAULT_URL}/api/v1/dev/login",
            data=json.dumps({"handle": "reach" + secrets.token_hex(3)}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.getcode() == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


pytestmark = pytest.mark.skipif(
    not _vault_reachable(),
    reason=f"dev vault unreachable at {VAULT_URL} (TN_DAY1_VAULT)",
)


# ── Account + DID helpers ──────────────────────────────────────────────


def _dev_login() -> tuple[str, str, str]:
    """POST /dev/login for a fresh unique handle.

    Returns ``(handle, account_token, passphrase)``. The dev passphrase is
    deterministic (``tn-dev-<handle>``).
    """
    handle = "g1" + secrets.token_hex(5)
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/dev/login",
        data=json.dumps({"handle": handle}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        doc = json.loads(resp.read())
    return handle, doc["token"], doc.get("passphrase") or f"tn-dev-{handle}"


def _ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(26))


def _register_device_did(account_token: str, device: DeviceKey) -> None:
    """Register ``device``'s DID under the dev account via the DID-challenge
    flow (/account/dids/challenge -> sign nonce -> /account/dids).

    After this, the device's DID is in ``accounts.minted_dids[]``, so:
      * a DID-challenge JWT for it resolves the account on account routes,
      * the inbox POST (auth_did == DID) succeeds,
      * the account-inbox aggregator surfaces snapshots addressed to it.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    # 1. Mint a challenge nonce (account-auth).
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/account/dids/challenge",
        data=json.dumps({"did_hint": device.did}).encode(),
        headers={
            "Authorization": f"Bearer {account_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        ch = json.loads(resp.read())
    nonce = base64.b64decode(ch["nonce_b64"])

    # 2. Sign the raw nonce bytes with the device key.
    priv = Ed25519PrivateKey.from_private_bytes(device.private_bytes)
    sig_b64 = base64.b64encode(priv.sign(nonce)).decode("ascii")

    # 3. Register.
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/account/dids",
        data=json.dumps(
            {
                "did": device.did,
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


# ── Ceremony builder + push via the real verb ──────────────────────────


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _stamp_ceremony_yaml(yaml_path: Path, *, project_id: str) -> None:
    """Link this ceremony to ``project_id`` on the dev vault."""
    doc = _yaml.safe_load(yaml_path.read_text()) or {}
    ceremony = doc.setdefault("ceremony", {})
    ceremony["mode"] = "linked"
    ceremony["linked_vault"] = VAULT_URL
    ceremony["linked_project_id"] = project_id
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))


def _init_ceremony(src_dir: Path, *, groups: list[str]) -> tuple[Path, DeviceKey]:
    """Init a btn ceremony with the given groups. Returns
    ``(yaml_path, device_key)``."""
    yaml_path = src_dir / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()
    for g in groups:
        tn.ensure_group(cfg, g, fields=["amount", "memo"])
    device = cfg.device
    tn.flush_and_close()
    return yaml_path, device


def _did_client(device: DeviceKey) -> VaultClient:
    """A VaultClient authed AS ``device``'s DID (DID-challenge). Its token
    resolves the account on account routes (the DID is in minted_dids[]) AND
    satisfies the inbox POST's auth_did==publisher_identity check."""
    from tn.handlers.vault_push import _DeviceKeyIdentity

    return VaultClient.for_identity(_DeviceKeyIdentity(device), VAULT_URL)


def _sync_push(yaml_path: Path, device: DeviceKey, passphrase: str) -> _wallet.SyncResult:
    """Drive the real ``tn.wallet.sync_ceremony`` (body push + group-keys
    publish) authed as ``device``'s DID."""
    tn.init(yaml_path)
    cfg = tn.current_config()
    client = _did_client(device)
    try:
        result = _wallet.sync_ceremony(
            cfg,
            client,
            passphrase=passphrase,
            sign_with=device,
            author_did=device.did,
        )
    finally:
        client.close()
    tn.flush_and_close()
    return result


def _sync_pull_absorb(yaml_path: Path, device: DeviceKey) -> list:
    """Pull the account inbox for ``device`` and absorb each staged snapshot.

    Mirrors ``tn.wallet_pull.stage_account_inbox`` + ``pull_and_absorb``,
    but inline here so the test owns the account-auth client lifecycle.
    Returns the list of absorb receipts (one per pulled snapshot).
    """
    from tn.pkg import absorb as _absorb

    tn.init(yaml_path)
    tn.flush_and_close()

    client = _did_client(device)
    receipts = []
    try:
        # GET the account-scoped inbox aggregator.
        resp = client._request("GET", "/api/v1/account/inbox")
        client._raise_for_status(resp)
        items = resp.json().get("items") or []
        for item in items:
            if item.get("consumed_at"):
                continue
            from_did = item["publisher_identity"]
            ceremony_id = item["ceremony_id"]
            ts = item["ts"]
            dl = client._request(
                "GET",
                f"/api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg",
            )
            client._raise_for_status(dl)
            body = dl.content
            # Stage to a temp file and absorb (mirrors wallet_pull.pull_and_absorb).
            staged = yaml_path.parent / ".tn" / "inbox_pull"
            staged.mkdir(parents=True, exist_ok=True)
            dest = staged / f"{from_did.replace(':', '_')}_{ts}.tnpkg"
            dest.write_bytes(body)
            tn.init(yaml_path)
            try:
                receipts.append(_absorb(dest))
            finally:
                tn.flush_and_close()
    finally:
        client.close()
    return receipts


# ── Test 1: B can USE A's group after sync ─────────────────────────────


def test_b_can_use_group_added_on_a(tmp_path: Path):
    """A `tn group add` G + sync; B sync (pull) -> B's config registers G
    AND B can tn.info to G + read it back DECRYPTED (USABLE)."""
    _handle, account_token, passphrase = _dev_login()
    project_a = _ulid()
    project_b = _ulid()

    # Device A: ceremony with group "payments".
    src_a = tmp_path / "a"
    src_a.mkdir()
    yaml_a, dev_a = _init_ceremony(src_a, groups=["payments"])
    _register_device_did(account_token, dev_a)
    _stamp_ceremony_yaml(yaml_a, project_id=project_a)

    # Device B: ceremony with NO extra group (only the default/tn.agents).
    src_b = tmp_path / "b"
    src_b.mkdir()
    yaml_b, dev_b = _init_ceremony(src_b, groups=[])
    _register_device_did(account_token, dev_b)
    _stamp_ceremony_yaml(yaml_b, project_id=project_b)

    # A pushes: body blob + publishes group_keys for "payments".
    res_a = _sync_push(yaml_a, dev_a, passphrase)
    assert res_a.errors == [], f"A push errors: {res_a.errors}"
    assert res_a.publish_warning is None, f"A publish warn: {res_a.publish_warning}"
    assert "payments" in res_a.published_groups, (
        f"A did not publish 'payments': {res_a.published_groups}"
    )

    # B pulls + absorbs. B should NOT have 'payments' before.
    tn.init(yaml_b)
    cfg_b_before = tn.current_config()
    assert "payments" not in cfg_b_before.groups, "B already had 'payments'?"
    tn.flush_and_close()

    receipts = _sync_pull_absorb(yaml_b, dev_b)
    # At least one absorbed snapshot accepted the group_keys.
    accepted_kinds = [getattr(r, "kind", None) for r in receipts]
    assert any(
        getattr(r, "accepted_count", 0) > 0 for r in receipts
    ), f"no group_keys absorbed; kinds={accepted_kinds}"

    # B's config now REGISTERS 'payments'.
    tn.init(yaml_b)
    cfg_b_after = tn.current_config()
    assert "payments" in cfg_b_after.groups, (
        f"B config did not register 'payments': {list(cfg_b_after.groups)}"
    )
    tn.flush_and_close()

    # B can tn.info to 'payments' (encrypt) and read it back DECRYPTED.
    tn.init(yaml_b)
    tn.info("payment.sent", amount=99, memo="b-writes-to-As-group", group="payments")
    tn.flush_and_close()

    tn.init(yaml_b)
    got = [
        (e.event_type, (e.fields or {}).get("amount"))
        for e in tn.read(group="payments")
    ]
    tn.flush_and_close()
    assert any(et == "payment.sent" for et, _ in got), f"B read empty/opaque: {got}"
    assert any(amt == 99 for _, amt in got), (
        f"B could not DECRYPT its own write to A's group: {got}"
    )


# ── Test 2: concurrent add-different-groups, union, no clobber ─────────


def test_concurrent_add_union_no_clobber(tmp_path: Path):
    """A adds alpha, B adds beta; sync both ways -> both groups on both,
    each USABLE. No clobber."""
    _handle, account_token, passphrase = _dev_login()
    project_a = _ulid()
    project_b = _ulid()

    src_a = tmp_path / "a"
    src_a.mkdir()
    yaml_a, dev_a = _init_ceremony(src_a, groups=["alpha"])
    _register_device_did(account_token, dev_a)
    _stamp_ceremony_yaml(yaml_a, project_id=project_a)

    src_b = tmp_path / "b"
    src_b.mkdir()
    yaml_b, dev_b = _init_ceremony(src_b, groups=["beta"])
    _register_device_did(account_token, dev_b)
    _stamp_ceremony_yaml(yaml_b, project_id=project_b)

    # Both publish their own group keys.
    res_a = _sync_push(yaml_a, dev_a, passphrase)
    res_b = _sync_push(yaml_b, dev_b, passphrase)
    assert "alpha" in res_a.published_groups, res_a.published_groups
    assert "beta" in res_b.published_groups, res_b.published_groups
    assert res_a.publish_warning is None and res_b.publish_warning is None

    # Cross-sync: A pulls B's beta, B pulls A's alpha.
    _sync_pull_absorb(yaml_a, dev_a)
    _sync_pull_absorb(yaml_b, dev_b)

    # Both groups present on BOTH devices (union, no clobber).
    tn.init(yaml_a)
    groups_a = set(tn.current_config().groups)
    tn.flush_and_close()
    tn.init(yaml_b)
    groups_b = set(tn.current_config().groups)
    tn.flush_and_close()

    assert {"alpha", "beta"} <= groups_a, f"A missing union: {sorted(groups_a)}"
    assert {"alpha", "beta"} <= groups_b, f"B missing union: {sorted(groups_b)}"

    # Each group is USABLE on the device that received it: A writes+reads
    # beta (B's group), B writes+reads alpha (A's group).
    tn.init(yaml_a)
    tn.info("from.a", amount=1, memo="a->beta", group="beta")
    tn.flush_and_close()
    tn.init(yaml_a)
    a_beta = [(e.fields or {}).get("amount") for e in tn.read(group="beta")]
    tn.flush_and_close()
    assert 1 in a_beta, f"A could not use B's 'beta': {a_beta}"

    tn.init(yaml_b)
    tn.info("from.b", amount=2, memo="b->alpha", group="alpha")
    tn.flush_and_close()
    tn.init(yaml_b)
    b_alpha = [(e.fields or {}).get("amount") for e in tn.read(group="alpha")]
    tn.flush_and_close()
    assert 2 in b_alpha, f"B could not use A's 'alpha': {b_alpha}"

    # No clobber: A's OWN alpha key material is still its original bytes
    # (A never received an alpha snapshot, only published one).
    keys_a = sorted(p.name for p in (src_a / ".tn" / "tn" / "keys").iterdir())
    assert "alpha.btn.state" in keys_a and "alpha.btn.mykit" in keys_a


# ── Test 3 (bonus): Python group_keys snapshot is cross-impl shaped ────


def test_published_group_keys_is_cross_impl_shaped(tmp_path: Path):
    """A Python-published group_keys snapshot is structurally the same kind
    the TS publishes: kind=full_keystore, scope=group_keys, self-addressed,
    body/keys/<group>.btn.{state,mykit}, state.groups.<group> block."""
    from tn.export import export_group_keys

    src = tmp_path / "c"
    src.mkdir()
    yaml_path, device = _init_ceremony(src, groups=["payments"])

    tn.init(yaml_path)
    cfg = tn.current_config()
    out = tmp_path / "gk.tnpkg"
    export_group_keys(out, cfg=cfg, sign_with=device, author_did=device.did)
    tn.flush_and_close()

    with zipfile.ZipFile(BytesIO(out.read_bytes())) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))

    assert manifest["kind"] == "full_keystore"
    assert manifest["scope"] == "group_keys"
    # Self-addressed: from_did == to_did.
    assert manifest["publisher_identity"] == manifest["recipient_identity"] == device.did
    # Key material carried for the group, NO device secret.
    assert "body/keys/payments.btn.state" in names
    assert "body/keys/payments.btn.mykit" in names
    assert not any("local.private" in n for n in names)
    # State carries the group block + the version marker.
    state = manifest.get("state") or {}
    assert state.get("kind") == "group-keys-v1"
    assert "payments" in (state.get("groups") or {})
