"""Example 3: share a log while keeping customer details private.

Jamie shares a log with a partner. The partner's ``default`` reader kit
opens page paths and referrers. Customer email/IP fields belong to ``pii``;
request diagnostics belong to ``internal``. Both stay encrypted for the
partner.

``tn.ensure_group(cfg, name, fields=[...])`` updates field routing after
initialization. ``tn.read(as_recipient=..., group=...)`` reads with only the
specified recipient's kit. It does not use the publisher's keys.

Run: python ex03_groups.py
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import tn
from tn.signing import DeviceKey


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="tn-groups-") as td:
        workspace = Path(td)
        tn.init(workspace / "tn.yaml", cipher="btn")
        try:
            cfg = tn.current_config()
            cfg = tn.ensure_group(cfg, "pii", fields=["email", "ip", "user_agent"])
            cfg = tn.ensure_group(cfg, "internal", fields=["debug_trace"])
            print(f"groups now defined: {sorted(cfg.groups)}")

            # Issue a reader kit. No publisher state or signing key is shared.
            partner_keys = workspace / "partner-keys"
            partner_keys.mkdir()
            partner_did = DeviceKey.generate().did
            tn.admin.add_recipient(
                "default",
                recipient_did=partner_did,
                out_path=partner_keys / "default.btn.mykit",
                raw=True,
            )
            assert {p.name for p in partner_keys.iterdir()} == {"default.btn.mykit"}

            tn.info(
                "page.view",
                page_path="/checkout",
                referrer="newsletter",
                email="alice@example.com",
                ip="10.0.0.17",
                user_agent="Mozilla/5.0",
                debug_trace="cache_miss",
            )
            log_path = cfg.resolve_log_path()

            print("\n--- as publisher (hold every group's keys) ---")
            publisher_rows = list(tn.read(verify=True))
            assert len(publisher_rows) == 1
            publisher = publisher_rows[0]
            assert publisher.fields["email"] == "alice@example.com"
            assert publisher.fields["debug_trace"] == "cache_miss"
            assert not publisher.hidden_groups
            print(f"  fields: {publisher.fields}")

            print("\n--- as partner (only the default reader kit) ---")
            partner_rows = list(tn.read(
                log=log_path, as_recipient=partner_keys, group="default", verify=True,
            ))
            assert len(partner_rows) == 1
            partner = partner_rows[0]
            assert partner.fields["page_path"] == "/checkout"
            assert partner.fields["referrer"] == "newsletter"
            assert "email" not in partner.fields
            assert "debug_trace" not in partner.fields
            assert set(partner.hidden_groups) == {"pii", "internal"}
            print(f"  fields: {partner.fields}")
            print(f"  hidden_groups: {partner.hidden_groups}")

            # raw=True preserves each encrypted group in the public envelope.
            envelope = list(tn.read(
                log=log_path, as_recipient=partner_keys, group="default", raw=True, verify=True,
            ))[0]
            for group in ("pii", "internal"):
                size = len(base64.b64decode(envelope[group]["ciphertext"], validate=True))
                print(f"  {group}: [encrypted, {size}-byte ciphertext]")
        finally:
            tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
