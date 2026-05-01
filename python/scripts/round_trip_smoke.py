"""Live round-trip smoke against a running tnproto-org.

Exercises the wire end-to-end without mocks:

  1. Spin up two ceremonies in temp dirs (publisher + consumer).
  2. Publisher mints a kit for the consumer's DID, exports an
     admin_log_snapshot, and POSTs it to the live vault inbox.
  3. Consumer's pull handler lists the inbox, downloads the snapshot,
     absorbs it; consumer's admin log gains the publisher's events.
  4. Confirms the cursor file holds the server-supplied since_marker
     (when emitted) or received_at (fallback) per spec §4.1.

Run:
    .venv/Scripts/python.exe tn-protocol/python/scripts/round_trip_smoke.py

Vault URL defaults to TN_VAULT_URL or http://localhost:8790. Boot
tnproto-org first:
    cd tnproto-org && python -m uvicorn src.app:app --port 8790

This is a smoke driver, not a regression test. It prints what it
saw on the wire so we can eyeball the contract works in practice.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Make the SDK importable when running from the repo root.
HERE = Path(__file__).resolve().parent
SDK_ROOT = HERE.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

import tn
from tn.export import export
from tn.handlers.vault_pull import VaultPullHandler, _SnapshotInboxClient
from tn.handlers.vault_push import _DeviceKeyIdentity
from tn.tnpkg import _read_manifest
from tn.vault_client import VaultClient, resolve_vault_url


def _force_admin_log_yaml(yaml_path: Path) -> None:
    import yaml as _yaml

    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_ceremony(root: Path, label: str) -> Path:
    d = root / label
    d.mkdir()
    yaml_path = d / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    return yaml_path


def main() -> int:
    vault_url = resolve_vault_url()
    print(f"== Round-trip smoke against {vault_url}")

    with tempfile.TemporaryDirectory(prefix="tn-roundtrip-") as tmp_str:
        tmp = Path(tmp_str)

        # 1. Build publisher + consumer ceremonies
        pub_yaml = _build_ceremony(tmp, "publisher")
        if not tn.using_rust():
            print("FAIL: Rust runtime not active (btn)", file=sys.stderr)
            return 2
        kit_dir = tmp / "_kits"
        kit_dir.mkdir()
        # Use the consumer's DID as recipient. We need the consumer ceremony
        # to exist first to learn its DID.
        tn.flush_and_close()

        cons_yaml = _build_ceremony(tmp, "consumer")
        cons_cfg = tn.current_config()
        consumer_did = cons_cfg.device.did
        print(f"   consumer DID = {consumer_did}")
        tn.flush_and_close()

        # Re-open publisher and add consumer as recipient
        tn.init(pub_yaml, cipher="btn")
        tn.admin.add_recipient("default", recipient_did=consumer_did, out_path=kit_dir / "default.btn.mykit")
        pub_cfg = tn.current_config()
        publisher_did = pub_cfg.device.did
        print(f"   publisher DID = {publisher_did}")

        # 2. Export a snapshot
        snap_path = tmp / "snap.tnpkg"
        export(snap_path, kind="admin_log_snapshot", cfg=pub_cfg, to_did=consumer_did)
        manifest, _ = _read_manifest(snap_path.read_bytes())
        print(f"   snapshot head_row_hash = {manifest.head_row_hash}")
        print(f"   manifest from_did = {manifest.from_did}")
        print(f"   manifest to_did = {manifest.to_did}")
        tn.flush_and_close()

        # 3. POST it to the vault using the publisher's identity.
        # We use a transient Identity built from the publisher's device key
        # so the vault challenge-response works without touching the user's
        # default identity file.
        pub_identity = _DeviceKeyIdentity(pub_cfg.device)
        client = VaultClient.for_identity(pub_identity, vault_url)
        try:
            # URL contract requires YYYYMMDDTHHMMSS<micro>Z UTC.
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            url_path = (
                f"/api/v1/inbox/{publisher_did}/snapshots/"
                f"{manifest.ceremony_id}/{ts}.tnpkg"
            )
            print(f"== POST {url_path}")
            url = f"{client.base_url}{url_path}"
            if manifest.head_row_hash:
                from urllib.parse import urlencode

                url = f"{url}?{urlencode({'head_row_hash': manifest.head_row_hash})}"
            headers = client._headers({"Content-Type": "application/octet-stream"})
            resp = client._http.request("POST", url, content=snap_path.read_bytes(), headers=headers)
            print(f"   POST -> HTTP {resp.status_code}")
            if resp.status_code not in (200, 201):
                print(f"   body: {resp.text[:500]}")
                return 1
            stored = resp.json()
            print(f"   stored: {stored}")
        finally:
            client.close()

        # 4. Consumer pulls
        tn.init(cons_yaml, cipher="btn")
        cons_cfg = tn.current_config()

        cons_identity = _DeviceKeyIdentity(cons_cfg.device)
        cons_vault = VaultClient.for_identity(cons_identity, vault_url)
        inbox_client = _SnapshotInboxClient(cons_vault)

        # Drive the pull handler with a real client
        h = VaultPullHandler(
            "smoke-pull",
            endpoint=vault_url,
            project_id="proj_xxx",
            cfg_provider=lambda: cons_cfg,
            client_factory=lambda *_: inbox_client,
            poll_interval=999.0,
            autostart=False,
        )
        try:
            absorbed = h.tick_once()
            print(f"== consumer absorbed {absorbed} snapshot(s)")
            if absorbed != 1:
                print("   FAIL: expected 1 absorbed", file=sys.stderr)
                return 1

            cursor_path = cons_cfg.yaml_path.parent / ".tn/admin" / "vault_pull.cursor.json"
            if not cursor_path.exists():
                print("   FAIL: no cursor written", file=sys.stderr)
                return 1
            cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
            print(f"   cursor.last_seen = {cursor.get('last_seen')!r}")

            # Second tick should be a noop (cursor caught up)
            absorbed2 = h.tick_once()
            print(f"== second tick absorbed {absorbed2} (expect 0)")
            if absorbed2 != 0:
                print("   FAIL: expected 0 on second tick", file=sys.stderr)
                return 1
        finally:
            h.close()
            cons_vault.close()
            tn.flush_and_close()

    print("\nOK: round-trip succeeded against live vault")
    return 0


if __name__ == "__main__":
    sys.exit(main())
