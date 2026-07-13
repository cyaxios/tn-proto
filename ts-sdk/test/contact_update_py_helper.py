"""Python side of the cross-impl contact_update interop test (GAP 1).

Driven by ts-sdk/test/contact_update_interop.test.ts. Proves the
contact_update `.tnpkg` round-trips between the TS SDK and the reference
Python implementation in BOTH directions:

  * `produce`: build a contact_update tnpkg (manifest signed by the
    ceremony's device key + body/contact_update.json) the way the vault
    server would, so the TS side can absorb it and reflect the contact in
    its contacts.yaml. Python has no `export(kind="contact_update")` (the
    vault emits these), so we assemble the tnpkg from tn.tnpkg directly.
  * `absorb`: absorb a TS-produced contact_update tnpkg via Python's
    `tn.absorb.absorb(cfg, source)` and dump the resulting contacts.yaml
    so the TS side can assert the contact landed.

Usage:
    python contact_update_py_helper.py produce <out_path> <yaml_path> <json_body>
    python contact_update_py_helper.py absorb  <tnpkg_path> <yaml_path>

`produce` prints {"ok": true, "publisher_identity": <did>}.
`absorb`  prints {"status": ..., "accepted_count": ..., "contacts": [...]}.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

_STDOUT = sys.stdout.buffer


def _write(s: str) -> None:
    _STDOUT.write(s.encode("utf-8"))


TN_SDK_PATH = HERE.parents[1] / "python"
if str(TN_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(TN_SDK_PATH))


def _do_produce(out_path: str, yaml_path: str, json_body: str) -> int:
    import tn

    tnpkg = importlib.import_module("tn.tnpkg")
    export_mod = importlib.import_module("tn.export")

    # Load the ceremony so we sign with its device key (the vault would
    # sign with its own device key; for the round-trip the publisher's
    # ceremony device is fine — the absorb only checks the signature
    # verifies against publisher_identity).
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    body_doc = json.loads(json_body)
    body = {
        "body/contact_update.json": json.dumps(
            body_doc, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"),
    }

    manifest = tnpkg.TnpkgManifest(
        kind="contact_update",
        publisher_identity=cfg.device.device_identity,
        ceremony_id=cfg.ceremony_id,
        as_of=export_mod._now_iso(),
        scope="admin",
    )
    tnpkg.sign_manifest_with_body(manifest, body, cfg.device.signing_key())
    tnpkg._write_tnpkg(Path(out_path), manifest, body)

    _write(
        json.dumps(
            {"ok": True, "publisher_identity": cfg.device.device_identity},
            sort_keys=True,
        )
        + "\n"
    )
    return 0


def _do_absorb(tnpkg_path: str, yaml_path: str) -> int:
    import tn

    absorb_mod = importlib.import_module("tn.absorb")
    conventions = importlib.import_module("tn.conventions")

    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    # Two-arg form returns an AbsorbResult (status/reason); the kind +
    # accepted_count live on the underlying AbsorbReceipt only on the
    # one-arg path. Surface whichever fields are present so the TS side
    # can assert non-rejection robustly.
    receipt = absorb_mod.absorb(cfg, tnpkg_path)

    contacts_path = conventions.tn_dir(cfg.yaml_path) / "contacts.yaml"
    contacts: list = []
    if contacts_path.exists():
        import yaml as _yaml

        doc = _yaml.safe_load(contacts_path.read_text(encoding="utf-8")) or {}
        if isinstance(doc, dict) and isinstance(doc.get("contacts"), list):
            contacts = doc["contacts"]

    # status: AbsorbResult.status, falling back to AbsorbReceipt.legacy_status.
    status = getattr(receipt, "status", None)
    if status is None:
        status = getattr(receipt, "legacy_status", None)
    reason = getattr(receipt, "reason", None)
    if reason is None:
        reason = getattr(receipt, "legacy_reason", None)

    payload = {
        "kind": getattr(receipt, "kind", None),
        "status": status,
        "reason": reason,
        "accepted_count": getattr(receipt, "accepted_count", None),
        "contacts": contacts,
    }
    _write(json.dumps(payload, sort_keys=True, default=str) + "\n")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: contact_update_py_helper.py produce|absorb ...\n")
        return 1
    cmd = sys.argv[1]
    if cmd == "produce":
        if len(sys.argv) < 5:
            sys.stderr.write("produce requires <out_path> <yaml_path> <json_body>\n")
            return 1
        return _do_produce(sys.argv[2], sys.argv[3], sys.argv[4])
    if cmd == "absorb":
        if len(sys.argv) < 4:
            sys.stderr.write("absorb requires <tnpkg_path> <yaml_path>\n")
            return 1
        return _do_absorb(sys.argv[2], sys.argv[3])
    sys.stderr.write(f"unknown subcommand {cmd!r}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
