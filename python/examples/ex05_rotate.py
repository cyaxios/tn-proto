"""Example 5: revoke an analyst's reader kit.

Revocation excludes the analyst's BTN leaf from new ciphertexts. Their
saved kit still opens entries written before revocation. The signed
``tn.recipient.revoked`` event is retained in the admin log.

This example uses ``tn.admin.add_recipient`` and its ``leaf_index`` result,
``tn.admin.revoke_recipient``, and ``tn.read(log="admin", verify=True)``.
The analyst reads with a directory containing only their reader kit.

Run: python ex05_rotate.py
"""

from __future__ import annotations

import tempfile
from contextlib import closing
from pathlib import Path

import tn
from tn.signing import DeviceKey


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="tn-revocation-") as td:
        workspace = Path(td)
        tn.init(workspace / "tn.yaml", cipher="btn")
        try:
            cfg = tn.current_config()
            analyst_keys = workspace / "analyst-keys"
            analyst_keys.mkdir()
            analyst_did = DeviceKey.generate().did
            reader = tn.admin.add_recipient(
                "default",
                recipient_did=analyst_did,
                out_path=analyst_keys / "default.btn.mykit",
                raw=True,
            )
            print(f"minted leaf {reader.leaf_index} for {analyst_did}")

            tn.info("request.served", request_id="r-1", report_path="/dashboard")
            tn.info("request.served", request_id="r-2", report_path="/reports")
            tn.admin.revoke_recipient("default", leaf_index=reader.leaf_index)
            print(f"revoked leaf {reader.leaf_index}")
            tn.info("request.served", request_id="r-3", report_path="/admin")

            # Keep one runtime open so all three entries remain in this run's log.
            with closing(tn.read(
                log=cfg.resolve_log_path(),
                as_recipient=analyst_keys,
                group="default",
                verify=True,
            )) as analyst_rows:
                assert next(analyst_rows).fields["report_path"] == "/dashboard"
                assert next(analyst_rows).fields["report_path"] == "/reports"
                print("[ok] analyst's old kit still decrypts data written BEFORE revocation")
                try:
                    next(analyst_rows)
                except tn.VerifyError as error:
                    assert error.sequence == 3
                    assert error.reasons == ["not_a_recipient"]
                else:
                    raise AssertionError("revoked kit opened a post-revocation entry")
                print("[ok] analyst's kit cannot decrypt data written AFTER revocation")

            # Admin events have their own log. Verification checks each signed row.
            admin_rows = list(tn.read(log="admin", verify=True))
            revoked = [row for row in admin_rows if row.event_type == "tn.recipient.revoked"]
            assert len(revoked) == 1, "expected one verified revocation event"
            assert revoked[0].fields["leaf_index"] == reader.leaf_index
            assert revoked[0].fields["group"] == "default"
            print(f"\nrevocation chain entries in the log: {len(revoked)}")
            print(f"  event_id={revoked[0].event_id} row_hash={revoked[0].row_hash}")
            print(f"  [ok] {len(admin_rows)} admin rows pass signature, row_hash, and chain verification")
        finally:
            tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
