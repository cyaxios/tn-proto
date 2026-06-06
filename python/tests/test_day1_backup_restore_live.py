"""Day-1 single-user backup / restore / group-sync against a LIVE dev vault.

Real round-trips, byte-MATCH, no mock. Exercises the SUPPORTED AWK/BEK
whole-body model end to end:

  - PUSH: ``tn.wallet.sync_ceremony`` (rewritten onto
    ``tn.wallet_push.push_ceremony_body``) packs the ceremony body into a
    STORED zip, AES-256-GCM-encrypts it as a no-AAD ``nonce||ct`` frame
    under the project BEK (minted + wrapped under the account AWK), and
    PUTs ``encrypted-blob-account`` with ``If-Match``.
  - RESTORE: the passphrase building blocks the CLI verb uses
    (``wallet_restore_passphrase._derive_bek_via_passphrase`` +
    ``wallet_restore._restore_with_token``) derive the BEK, fetch the
    blob, decrypt, and unpack the STORED zip into a fresh identity dir.

NO sharing — single account, single user. The dev vault ships every
account a primary ``pbkdf2-sha256`` credential with a deterministic
passphrase ``tn-dev-<handle>``, so the AWK/BEK chain runs without a
browser.

Skips cleanly when the vault at ``$TN_DAY1_VAULT`` (default
``http://127.0.0.1:34987``) is unreachable.

Run:
    cd python && COVERAGE_CORE=sysmon PYTHONPATH=. \\
      <venv>/python.exe -m pytest -q tests/test_day1_backup_restore_live.py
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml as _yaml

import tn
from tn import wallet as _wallet
from tn import wallet_push as _wallet_push
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


# ── Dev account helper ─────────────────────────────────────────────────


def _dev_login() -> tuple[str, str, str]:
    """POST /dev/login for a fresh unique handle.

    Returns ``(handle, token, passphrase)``. The dev vault's passphrase is
    deterministic (``tn-dev-<handle>``); we assert that contract so a
    server change surfaces here rather than as a silent KDF mismatch.
    """
    handle = "d1" + secrets.token_hex(5)  # lowercase + digits, <=32 chars
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/dev/login",
        data=json.dumps({"handle": handle}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        doc = json.loads(resp.read())
    token = doc["token"]
    passphrase = doc.get("passphrase") or f"tn-dev-{handle}"
    assert passphrase == f"tn-dev-{handle}", "dev passphrase contract changed"
    return handle, token, passphrase


def _ulid() -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(26))


# ── Ceremony builder + push via the real verb ──────────────────────────


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _stamp_ceremony_yaml(yaml_path: Path, *, project_id: str) -> None:
    """Stamp the ceremony block to link this ceremony to ``project_id`` on
    the dev vault and enable ``sync_logs``.

    A fresh ``tn.init`` bakes ``mode: linked`` + ``linked_vault:
    <hosted>`` by default, so ``set_link_state`` to a different vault is
    rejected as a re-link. We write the link fields directly. Enabling
    ``sync_logs`` makes the body carry the ndjson log (where the entries
    live) — without it the restored ceremony has keys + yaml but no
    prior-entry history.
    """
    doc = _yaml.safe_load(yaml_path.read_text()) or {}
    ceremony = doc.setdefault("ceremony", {})
    ceremony["mode"] = "linked"
    ceremony["linked_vault"] = VAULT_URL
    ceremony["linked_project_id"] = project_id
    ceremony["sync_logs"] = True
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))


def _build_and_push(
    *,
    src_dir: Path,
    token: str,
    passphrase: str,
    project_id: str,
    group: str,
    entries: list[tuple[str, dict]],
) -> dict[str, bytes]:
    """Init a btn ceremony, add ``group``, write ``entries``, link it to
    ``project_id`` and PUSH via the real ``wallet.sync_ceremony``.

    Returns the body member map that was pushed (for byte-match asserts).
    """
    yaml_path = src_dir / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()
    tn.ensure_group(cfg, group, fields=["amount", "memo"])
    for et, fields in entries:
        tn.info(et, **fields)
    tn.flush_and_close()

    # Link the ceremony to the project under THIS account + enable log sync.
    # We write the ceremony block directly (the dev account auths by bearer,
    # not the DID-challenge link_ceremony dance); the project row is created
    # server-side by the first wrapped-key PUT inside the push.
    _stamp_ceremony_yaml(yaml_path, project_id=project_id)

    tn.init(yaml_path)
    cfg = tn.current_config()
    body = _wallet._collect_body_members(cfg)

    # Drive the real verb. It pulls the bearer from client.token; we inject
    # the dev-login token via a stub client so no DID handshake is needed.
    client = _StubBearerClient(token=token, base_url=VAULT_URL)
    result = _wallet.sync_ceremony(cfg, client, passphrase=passphrase)
    tn.flush_and_close()

    assert result.errors == [], f"push reported errors: {result.errors}"
    assert result.project_id == project_id
    # Every body member shows up in the uploaded list (body/ prefix stripped).
    expected_uploaded = sorted(k[len("body/"):] for k in body)
    assert result.uploaded == expected_uploaded
    return body


class _StubBearerClient:
    """Minimal VaultClient stand-in carrying a pre-issued account bearer.

    ``sync_ceremony`` only reads ``.token``, ``.base_url`` and calls
    ``.authenticate()`` when no token is set; the dev-login JWT is already
    an account token, so we expose it directly and never hit the
    DID-challenge flow.
    """

    def __init__(self, *, token: str, base_url: str):
        self.token = token
        self.base_url = base_url

    def authenticate(self) -> str:  # pragma: no cover - token always present
        return self.token

    def close(self) -> None:
        pass


# ── Restore via the real building blocks ───────────────────────────────


def _restore_to_dir(
    *,
    out_dir: Path,
    token: str,
    passphrase: str,
    project_id: str,
) -> Path:
    """Derive the BEK from the passphrase, fetch+decrypt the blob, and
    write the body into a runnable ceremony layout under ``out_dir``.

    Mirrors what the CLI ``_restore_via_passphrase`` does
    (``_derive_bek_via_passphrase`` -> ``_restore_with_token``), then maps
    the ``body/<name>`` members into the on-disk convention layout
    (yaml at ``out_dir/tn.yaml``, keys at ``out_dir/.tn/tn/keys/``, logs at
    ``out_dir/.tn/tn/logs/``) so ``tn.init`` can re-open it.

    Returns the restored yaml path.
    """
    from base64 import urlsafe_b64encode

    bek = _derive_bek_via_passphrase(
        vault_url=VAULT_URL,
        bearer=token,
        project_id=project_id,
        passphrase=passphrase,
    )
    token_obj = TransferToken(
        vault_jwt=token,
        account_id="(day1)",
        project_id=project_id,
        raw_bek_b64=urlsafe_b64encode(bek).decode("ascii").rstrip("="),
    )
    raw_dir = out_dir / "_raw"
    _restore_with_token(
        vault_url=VAULT_URL,
        token=token_obj,
        out_dir=raw_dir,
    )
    # _restore_with_token unpacks the STORED zip into raw_dir/body/<name>.
    members: dict[str, Path] = {
        str(p.relative_to(raw_dir)).replace(os.sep, "/"): p
        for p in raw_dir.rglob("*")
        if p.is_file()
    }
    assert any(
        k == "body/tn.yaml" for k in members
    ), f"restore produced no body/tn.yaml; got {sorted(members)}"

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


# ── A. Full backup -> restore ──────────────────────────────────────────


def test_a_full_backup_restore_roundtrip(tmp_path: Path):
    """init + group G + entries -> push -> restore into a FRESH dir ->
    keystore+yaml+G+log restored byte-for-byte; restored ceremony reads
    the prior entries AND writes+reads a new one."""
    _handle, token, passphrase = _dev_login()
    project_id = _ulid()

    src = tmp_path / "src"
    src.mkdir()
    pushed = _build_and_push(
        src_dir=src,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
        group="payments",
        entries=[
            ("acct.opened", {"who": "alice"}),
            ("note.added", {"text": "first"}),
        ],
    )

    dst = tmp_path / "dst"
    dst.mkdir()
    restored_yaml = _restore_to_dir(
        out_dir=dst,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
    )

    # Byte-MATCH every keystore file + yaml + log against what was pushed.
    keys_dir = dst / ".tn" / "tn" / "keys"
    logs_dir = dst / ".tn" / "tn" / "logs"
    for member, data in pushed.items():
        if member == "body/tn.yaml":
            assert restored_yaml.read_bytes() == data, "yaml mismatch"
        elif member.startswith("body/keys/"):
            name = member.split("/")[-1]
            assert (keys_dir / name).read_bytes() == data, f"key {name} mismatch"
        elif member.startswith("body/logs/"):
            name = member.split("/")[-1]
            assert (logs_dir / name).read_bytes() == data, f"log {name} mismatch"

    # Restored ceremony reads the PRIOR entries.
    tn.init(restored_yaml)
    prior = [e.event_type for e in tn.read()]
    tn.flush_and_close()
    assert "acct.opened" in prior
    assert "note.added" in prior

    # Restored ceremony writes a NEW entry and reads it back.
    tn.init(restored_yaml)
    tn.info("post.restore", ok=True)
    tn.flush_and_close()
    tn.init(restored_yaml)
    after = [e.event_type for e in tn.read()]
    tn.flush_and_close()
    assert "post.restore" in after
    # Prior entries survive alongside the new write.
    assert "acct.opened" in after


# ── B. Group survives restore ──────────────────────────────────────────


def test_b_group_survives_restore(tmp_path: Path):
    """The added group G is present + routable in the restored ceremony:
    its keystore files restored AND a write to G round-trips."""
    _handle, token, passphrase = _dev_login()
    project_id = _ulid()

    src = tmp_path / "src"
    src.mkdir()
    pushed = _build_and_push(
        src_dir=src,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
        group="payments",
        entries=[("acct.opened", {"who": "bob"})],
    )

    # The group's keystore artifacts were part of the body.
    assert any(
        m.startswith("body/keys/payments.") for m in pushed
    ), f"group keystore not in body: {sorted(pushed)}"

    dst = tmp_path / "dst"
    dst.mkdir()
    restored_yaml = _restore_to_dir(
        out_dir=dst,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
    )

    # Group is in the restored yaml.
    rdoc = _yaml.safe_load(restored_yaml.read_text()) or {}
    groups = rdoc.get("groups")
    group_names = list(groups.keys()) if isinstance(groups, dict) else (groups or [])
    assert "payments" in group_names, f"group missing after restore: {group_names}"

    # Group is routable: a write addressed to it round-trips on the
    # restored ceremony.
    tn.init(restored_yaml)
    tn.info("payment.sent", amount=42, memo="rent", group="payments")
    tn.flush_and_close()
    tn.init(restored_yaml)
    got = [
        (e.event_type, e.get("amount") if hasattr(e, "get") else None)
        for e in tn.read(group="payments")
    ]
    tn.flush_and_close()
    assert any(et == "payment.sent" for et, _ in got), f"group read empty: {got}"


# ── C. Negatives ───────────────────────────────────────────────────────


def test_c1_wrong_passphrase_fails_restore_cleanly(tmp_path: Path):
    """A wrong passphrase fails the BEK derivation with a clean
    RestoreError (no traceback leak, no partial write)."""
    _handle, token, passphrase = _dev_login()
    project_id = _ulid()

    src = tmp_path / "src"
    src.mkdir()
    _build_and_push(
        src_dir=src,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
        group="payments",
        entries=[("acct.opened", {"who": "carol"})],
    )

    with pytest.raises(RestoreError):
        _derive_bek_via_passphrase(
            vault_url=VAULT_URL,
            bearer=token,
            project_id=project_id,
            passphrase=passphrase + "-WRONG",
        )


def test_c2_concurrent_push_ifmatch_conflict_surfaced(tmp_path: Path):
    """A stale If-Match (a concurrent writer bumped the generation) surfaces
    as a PushError precondition failure rather than silently clobbering."""
    _handle, token, passphrase = _dev_login()
    project_id = _ulid()

    src = tmp_path / "src"
    src.mkdir()
    body = _build_and_push(
        src_dir=src,
        token=token,
        passphrase=passphrase,
        project_id=project_id,
        group="payments",
        entries=[("acct.opened", {"who": "dave"})],
    )

    # First push above set the blob to generation N. Read it.
    blob_doc_gen = _current_generation(token, project_id)

    # A SECOND writer pushes (auto-resolves If-Match to the current gen),
    # bumping the generation to N+1.
    _wallet_push.push_ceremony_body(
        vault_url=VAULT_URL,
        bearer=token,
        project_id=project_id,
        passphrase=passphrase,
        body=body,
    )

    # The FIRST writer now retries with the STALE generation it captured ->
    # 412 precondition failed, surfaced as PushError.
    with pytest.raises(PushError) as info:
        _wallet_push.push_ceremony_body(
            vault_url=VAULT_URL,
            bearer=token,
            project_id=project_id,
            passphrase=passphrase,
            body=body,
            if_match=str(blob_doc_gen),
        )
    assert "precondition" in str(info.value).lower()


def _current_generation(token: str, project_id: str) -> int:
    req = urllib.request.Request(
        f"{VAULT_URL}/api/v1/projects/{project_id}/encrypted-blob",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return int(json.loads(resp.read())["generation"])
