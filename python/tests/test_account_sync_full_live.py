"""CAPSTONE: the FULL ACCOUNT SYNC end-to-end journey against a LIVE dev vault.

The piecemeal Python live tests each prove ONE leg (``test_day1_backup_restore_live``
= body push + passphrase restore + group survives; ``test_day1_two_device_group_sync_live``
= the account-inbox group-keys publish/absorb merge). This file composes the
WHOLE multi-device account journey as one continuous test:

  Device A (new account):
    init a btn ceremony -> register its DID under a fresh dev account -> add
    TWO groups (G1, G2) with routed fields -> write several entries across the
    default group + G1 + G2 -> ``wallet.sync_ceremony`` (push body blob +
    publish the G1/G2 key snapshots to the OWN account inbox).

  Device B (same account, fresh identity dir = a different machine):
    register a SECOND device DID under the SAME account -> pull the account
    inbox + ``tn.absorb`` each snapshot. Assert B ends up with: BOTH groups
    present AND USABLE (B writes to G1+G2 and reads its own writes back
    decrypted). Then B body-restores A's pushed blob (passphrase path) and
    reads A's PRIOR entries (incl. the G1/G2-routed secrets), adopting A's
    device DID.

  Round-back:
    B adds a THIRD group G3 + writes + publishes; A pulls+absorbs -> A now has
    G3 present AND USABLE. Union both directions (A->B for G1/G2, B->A for G3),
    no clobber.

  Negatives woven into the journey:
    * a wrong passphrase on B's body restore fails CLEAN (RestoreError, no
      partial write);
    * a stale If-Match concurrent body push surfaces the precondition conflict
      (PushError) rather than silently overwriting.

HARD RULE: real round-trips, no mock. Skips cleanly when the vault at
``$TN_DAY1_VAULT`` (default ``http://127.0.0.1:34987``) is unreachable.

Run:
    cd python && COVERAGE_CORE=sysmon PYTHONPATH=. \\
      <venv>/python.exe -m pytest -q tests/test_account_sync_full_live.py
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import urllib.error
import urllib.request
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest
import yaml as _yaml

import tn
from tn import wallet as _wallet
from tn import wallet_push as _wallet_push
from tn.pkg import absorb as _absorb
from tn.signing import DeviceKey
from tn.vault_client import VaultClient
from tn.wallet_push import PushError
from tn.wallet_restore import RestoreError, _restore_with_token
from tn.wallet_restore_loopback import TransferToken
from tn.wallet_restore_passphrase import _derive_bek_via_passphrase

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


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


# ── Account + DID helpers ──────────────────────────────────────────────


def _dev_login() -> tuple[str, str, str]:
    """POST /dev/login for a fresh unique handle.

    Returns ``(handle, account_token, passphrase)``; the dev passphrase is
    deterministic (``tn-dev-<handle>``)."""
    handle = "af" + secrets.token_hex(5)
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/dev/login",
        data=json.dumps({"handle": handle}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        doc = json.loads(resp.read())
    return handle, doc["token"], doc.get("passphrase") or f"tn-dev-{handle}"


def _account_token(handle: str) -> str:
    """Mint a fresh account bearer for an EXISTING dev handle (a 2nd device's
    account-scoped token, distinct from device DID-challenge auth)."""
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/dev/login",
        data=json.dumps({"handle": handle}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read())["token"]


def _ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(26))


def _register_device_did(account_token: str, device: DeviceKey) -> None:
    """Register ``device``'s DID under the dev account (challenge -> sign ->
    register) so the inbox POST authenticates AS that DID and the account-inbox
    aggregator surfaces snapshots addressed to it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

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

    priv = Ed25519PrivateKey.from_private_bytes(device.private_bytes)
    sig_b64 = base64.b64encode(priv.sign(nonce)).decode("ascii")

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


def _did_client(device: DeviceKey) -> VaultClient:
    """A VaultClient authed AS ``device``'s DID (DID-challenge)."""
    from tn.handlers.vault_push import _DeviceKeyIdentity

    return VaultClient.for_identity(_DeviceKeyIdentity(device), VAULT_URL)


# ── Ceremony builder ───────────────────────────────────────────────────


def _stamp_ceremony_yaml(yaml_path: Path, *, project_id: str, sync_logs: bool) -> None:
    # The project-level ``vault:`` block is authoritative when present (a
    # fresh init writes one), so stamp it alongside the legacy fields.
    doc = _yaml.safe_load(yaml_path.read_text()) or {}
    ceremony = doc.setdefault("ceremony", {})
    ceremony["mode"] = "linked"
    ceremony["linked_vault"] = VAULT_URL
    ceremony["linked_project_id"] = project_id
    if sync_logs:
        ceremony["sync_logs"] = True
    vault = doc.setdefault("vault", {})
    vault["enabled"] = True
    vault["url"] = VAULT_URL
    vault["linked_project_id"] = project_id
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))


def _init_ceremony(
    src_dir: Path, *, groups: list[str], project_id: str, sync_logs: bool
) -> tuple[Path, DeviceKey]:
    """Init a btn ceremony with the given groups, linked to ``project_id``.
    Returns ``(yaml_path, device_key)``."""
    yaml_path = src_dir / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()
    for g in groups:
        tn.ensure_group(cfg, g, fields=["amount", "memo"])
    device = cfg.device
    tn.flush_and_close()
    _stamp_ceremony_yaml(yaml_path, project_id=project_id, sync_logs=sync_logs)
    return yaml_path, device


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
    """Pull the account inbox for ``device`` and absorb each staged snapshot."""
    tn.init(yaml_path)
    tn.flush_and_close()

    client = _did_client(device)
    receipts = []
    try:
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
            staged = yaml_path.parent / ".tn" / "inbox_pull"
            staged.mkdir(parents=True, exist_ok=True)
            dest = staged / f"{from_did.replace(':', '_')}_{ts}.tnpkg"
            dest.write_bytes(dl.content)
            tn.init(yaml_path)
            try:
                receipts.append(_absorb(dest))
            finally:
                tn.flush_and_close()
    finally:
        client.close()
    return receipts


def _groups_of(yaml_path: Path) -> set[str]:
    tn.init(yaml_path)
    groups = set(tn.current_config().groups)
    tn.flush_and_close()
    return {g for g in groups if g not in ("default", "tn.agents")}


def _assert_group_usable(yaml_path: Path, group: str, who: str) -> None:
    """Write a group-routed entry and read it back DECRYPTED (group USABLE)."""
    amount = secrets.randbelow(9000) + 1000
    tn.init(yaml_path)
    tn.info("usable.write", amount=amount, memo=f"{who}->{group}", group=group)
    tn.flush_and_close()
    tn.init(yaml_path)
    got = [(e.fields or {}).get("amount") for e in tn.read(group=group)]
    tn.flush_and_close()
    assert amount in got, f"{who}: group '{group}' not USABLE (read {got}, want {amount})"


# ── Passphrase body restore (B reads A's prior log) ────────────────────


def _restore_body_to_dir(
    *, out_dir: Path, token: str, passphrase: str, project_id: str
) -> Path:
    """Derive the BEK from the passphrase, fetch+decrypt the body blob, lay it
    out into a runnable ceremony dir. Mirrors the CLI ``_restore_via_passphrase``
    building blocks. Returns the restored yaml path."""
    bek = _derive_bek_via_passphrase(
        vault_url=VAULT_URL,
        bearer=token,
        project_id=project_id,
        passphrase=passphrase,
    )
    token_obj = TransferToken(
        vault_jwt=token,
        account_id="(capstone)",
        project_id=project_id,
        raw_bek_b64=urlsafe_b64encode(bek).decode("ascii").rstrip("="),
    )
    raw_dir = out_dir / "_raw"
    _restore_with_token(vault_url=VAULT_URL, token=token_obj, out_dir=raw_dir)
    members = {
        str(p.relative_to(raw_dir)).replace(os.sep, "/"): p
        for p in raw_dir.rglob("*")
        if p.is_file()
    }
    assert any(k == "body/tn.yaml" for k in members), (
        f"restore produced no body/tn.yaml; got {sorted(members)}"
    )
    yaml_path = out_dir / "tn.yaml"
    keys_dir = out_dir / ".tn" / "tn" / "keys"
    logs_dir = out_dir / ".tn" / "tn" / "logs"
    keys_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    for rel, path in members.items():
        data = path.read_bytes()
        if rel == "body/tn.yaml":
            yaml_path.write_bytes(data)
        elif rel.startswith("body/keys/"):
            (keys_dir / rel.split("/")[-1]).write_bytes(data)
        elif rel.startswith("body/logs/"):
            (logs_dir / rel.split("/")[-1]).write_bytes(data)
    return yaml_path


def _current_generation(token: str, project_id: str) -> int:
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/projects/{project_id}/encrypted-blob",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return int(json.loads(resp.read())["generation"])


# ── The capstone ───────────────────────────────────────────────────────


def test_full_account_sync_journey(tmp_path: Path):
    handle, account_token, passphrase = _dev_login()
    project_a = _ulid()  # A's linked project (carries A's body + log)
    project_b = _ulid()  # B's linked project (round-back side)

    # ───────────────────────── DEVICE A ─────────────────────────
    src_a = tmp_path / "a"
    src_a.mkdir()
    yaml_a, dev_a = _init_ceremony(
        src_a, groups=["g1", "g2"], project_id=project_a, sync_logs=True
    )
    _register_device_did(account_token, dev_a)
    assert _groups_of(yaml_a) == {"g1", "g2"}, "A must declare G1+G2"

    # Several entries across default + G1 + G2.
    tn.init(yaml_a)
    tn.info("acct.default.alpha", n=1)  # default group
    tn.info("acct.default.beta", n=2)  # default group
    tn.info("acct.g1.gamma", amount=11, memo="A-G1-SECRET", group="g1")
    tn.info("acct.g2.delta", amount=22, memo="A-G2-SECRET", group="g2")
    tn.flush_and_close()

    # A reads its own routed secrets back.
    tn.init(yaml_a)
    g1_a = [(e.fields or {}).get("memo") for e in tn.read(group="g1")]
    g2_a = [(e.fields or {}).get("memo") for e in tn.read(group="g2")]
    tn.flush_and_close()
    assert "A-G1-SECRET" in g1_a and "A-G2-SECRET" in g2_a

    a_did = dev_a.did

    # wallet sync: push body + publish G1/G2 key snapshots.
    res_a = _sync_push(yaml_a, dev_a, passphrase)
    assert res_a.errors == [], f"A push errors: {res_a.errors}"
    assert res_a.publish_warning is None, f"A publish warn: {res_a.publish_warning}"
    assert {"g1", "g2"} <= set(res_a.published_groups), (
        f"A must publish G1+G2: {res_a.published_groups}"
    )
    assert res_a.project_id == project_a

    # ───────────────────────── DEVICE B ─────────────────────────
    src_b = tmp_path / "b"
    src_b.mkdir()
    yaml_b, dev_b = _init_ceremony(
        src_b, groups=[], project_id=project_b, sync_logs=True
    )
    _register_device_did(account_token, dev_b)
    assert _groups_of(yaml_b) == set(), "B must start with no extra groups"

    # B pulls + absorbs -> installs+registers G1 and G2.
    receipts_b = _sync_pull_absorb(yaml_b, dev_b)
    assert any(getattr(r, "accepted_count", 0) > 0 for r in receipts_b), (
        f"B absorbed no group keys; receipts={receipts_b}"
    )
    assert {"g1", "g2"} <= _groups_of(yaml_b), (
        f"B must register G1+G2 after pull; got {_groups_of(yaml_b)}"
    )

    # USABLE: B writes to G1 and G2 and reads its own writes back.
    _assert_group_usable(yaml_b, "g1", "B")
    _assert_group_usable(yaml_b, "g2", "B")

    # ── A's PRIOR log readable on B via the body blob (passphrase restore). ──
    # The group-keys path makes the groups USABLE but does NOT carry A's event
    # log; A's prior entries travel in the body blob (project_a). B restores it
    # on a fresh dir and reads A's entries, adopting A's device DID.
    dst_b = tmp_path / "b_restore"
    dst_b.mkdir()
    restored_yaml = _restore_body_to_dir(
        out_dir=dst_b, token=account_token, passphrase=passphrase, project_id=project_a
    )
    tn.init(restored_yaml)
    assert tn.current_config().device.did == a_did, (
        "B's body-restored ceremony must adopt A's device DID"
    )
    prior = [e.event_type for e in tn.read()]
    g1_restored = [(e.fields or {}).get("memo") for e in tn.read(group="g1")]
    g2_restored = [(e.fields or {}).get("memo") for e in tn.read(group="g2")]
    tn.flush_and_close()
    assert "acct.default.alpha" in prior, "B must read A's default-group prior entry"
    assert "A-G1-SECRET" in g1_restored, "B must read A's G1 secret after body restore"
    assert "A-G2-SECRET" in g2_restored, "B must read A's G2 secret after body restore"

    # ───────────────────────── ROUND-BACK ─────────────────────────
    # B adds a NEW group G3, writes to it, then publishes.
    tn.init(yaml_b)
    tn.ensure_group(tn.current_config(), "g3", fields=["amount", "memo"])
    tn.flush_and_close()
    tn.init(yaml_b)
    tn.info("acct.g3.fromB", amount=33, memo="B-G3-SECRET", group="g3")
    tn.flush_and_close()

    res_b = _sync_push(yaml_b, dev_b, passphrase)
    assert res_b.publish_warning is None, f"B publish warn: {res_b.publish_warning}"
    assert "g3" in res_b.published_groups, f"B must publish G3: {res_b.published_groups}"

    # A pulls+absorbs -> A now has G3, and it is USABLE on A.
    assert "g3" not in _groups_of(yaml_a), "A must not know G3 before its pull"
    _sync_pull_absorb(yaml_a, dev_a)
    assert "g3" in _groups_of(yaml_a), (
        f"A must register G3 after pull; got {_groups_of(yaml_a)}"
    )
    _assert_group_usable(yaml_a, "g3", "A")

    # UNION both directions.
    assert {"g1", "g2", "g3"} <= _groups_of(yaml_a), "A union must hold G1+G2+G3"
    assert {"g1", "g2", "g3"} <= _groups_of(yaml_b), "B union must hold G1+G2+G3"

    # ───────────────────────── NEGATIVES (in-journey) ─────────────────────────
    # N1: a wrong passphrase on a body restore fails CLEAN (RestoreError).
    with pytest.raises(RestoreError):
        _derive_bek_via_passphrase(
            vault_url=VAULT_URL,
            bearer=account_token,
            project_id=project_a,
            passphrase=passphrase + "-WRONG",
        )

    # N2: a stale If-Match concurrent body push surfaces a PushError. A second
    # writer bumps the generation; the first writer retries with the stale gen.
    tn.init(yaml_a)
    body = _wallet._collect_body_members(tn.current_config())
    tn.flush_and_close()
    stale_gen = _current_generation(account_token, project_a)
    _wallet_push.push_ceremony_body(
        vault_url=VAULT_URL,
        bearer=account_token,
        project_id=project_a,
        passphrase=passphrase,
        body=body,
    )
    with pytest.raises(PushError) as info:
        _wallet_push.push_ceremony_body(
            vault_url=VAULT_URL,
            bearer=account_token,
            project_id=project_a,
            passphrase=passphrase,
            body=body,
            if_match=str(stale_gen),
        )
    assert "precondition" in str(info.value).lower()
