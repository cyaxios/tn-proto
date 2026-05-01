"""Ad-hoc admin-API audit. Not part of the regular test suite. Smoke-tests
every admin verb under both ciphers and prints PASS/FAIL per scenario."""

from __future__ import annotations

import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn

PASS = "  ok  "
FAIL = "  FAIL  "


def section(t: str) -> None:
    print(f"\n=== {t} ===")


def ok(m: str) -> None:
    print(f"{PASS}{m}")


def bad(m: str) -> None:
    print(f"{FAIL}{m}")


# --------------------------------------------------------------------
# BGW path
# --------------------------------------------------------------------


def audit_bgw() -> None:
    section("BGW ensure_group + issue_key + rotate")
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        tn.init(ws / "tn.yaml", cipher="bgw")
        cfg = tn.current_config()

        cfg = tn.ensure_group(cfg, "finance", fields=["amount"])
        ok(f"ensure_group: finance added, groups={sorted(cfg.groups)}")
        assert "amount" in cfg.field_to_group, f"amount not routed: {cfg.field_to_group}"
        ok(f"ensure_group: field 'amount' routed to {cfg.field_to_group['amount']}")

        cfg = tn.ensure_group(cfg, "finance", fields=["credit_card"])
        if "credit_card" in cfg.field_to_group:
            ok("ensure_group: second call updated field_to_group in memory")
        else:
            bad(f"ensure_group: credit_card NOT in cfg.field_to_group ({cfg.field_to_group})")

        try:
            p = tn.issue_key(cfg, "finance", "did:key:zRecipient1")
            ok(f"issue_key: wrote {p.name}")
        except Exception as e:
            bad(f"issue_key: {type(e).__name__}: {e}")

        try:
            cfg = tn.admin.rotate("finance")
            ok(f"rotate(bgw): new index_epoch={cfg.groups['finance'].index_epoch}")
        except Exception as e:
            traceback.print_exc()
            bad(f"rotate(bgw): {type(e).__name__}: {e}")

        tn.flush_and_close()


# --------------------------------------------------------------------
# JWE path
# --------------------------------------------------------------------


def audit_jwe() -> None:
    section("JWE ensure_group + revoke_recipient + rotate")
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        tn.init(ws / "tn.yaml", cipher="jwe")
        cfg = tn.current_config()

        cfg = tn.ensure_group(cfg, "pii", fields=["email"])
        ok(f"ensure_group(jwe): pii added, groups={sorted(cfg.groups)}")

        # Log/read smoke with two groups
        tn.set_context(user_id=42)
        tn.info("order.created", amount=100)
        tn.info("profile.update", email="alice@example.com")
        tn.flush_and_close()

        tn.init(ws / "tn.yaml", cipher="jwe")
        cfg = tn.current_config()
        log = ws / ".tn/tn/logs" / "tn.ndjson"
        entries = list(tn.read(log, cfg))
        ok(f"log+read via ensure_group(jwe): {len(entries)} entries readable")
        for e in entries:
            assert e["valid"]["signature"], e
            assert e["valid"]["chain"], e
        ok("signatures + chain verify")

        # revoke_recipient bumps epoch
        old_epoch = cfg.groups["default"].index_epoch
        cfg = tn.revoke_recipient(cfg, "default", "did:ghost-recipient")
        new_epoch = cfg.groups["default"].index_epoch
        assert new_epoch == old_epoch + 1, (old_epoch, new_epoch)
        ok(f"revoke_recipient: index_epoch {old_epoch} -> {new_epoch}")

        # rotate(jwe): critical check — new entries after rotate still work
        try:
            cfg = tn.admin.rotate("pii")
            ok(f"rotate(jwe): new index_epoch={cfg.groups['pii'].index_epoch}")
        except Exception as e:
            traceback.print_exc()
            bad(f"rotate(jwe): {type(e).__name__}: {e}")
            tn.flush_and_close()
            return

        tn.flush_and_close()
        tn.init(ws / "tn.yaml", cipher="jwe")
        tn.info("profile.update", email="new@example.com")
        tn.flush_and_close()

        tn.init(ws / "tn.yaml", cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(log, cfg))
        ok(f"log+read after JWE rotate: {len(entries)} entries readable")
        for e in entries:
            assert e["valid"]["signature"], e
            assert e["valid"]["chain"], e
        ok("all signatures + chains verify across rotation boundary")
        tn.flush_and_close()


# --------------------------------------------------------------------
# Cross-cipher guards
# --------------------------------------------------------------------


def audit_guards() -> None:
    section("Cross-cipher guards")
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)

        # issue_key on JWE should raise
        tn.init(ws / "tn.yaml", cipher="jwe")
        cfg = tn.current_config()
        try:
            tn.issue_key(cfg, "default", "did:key:zFoo")
            bad("issue_key on JWE should have raised")
        except RuntimeError as e:
            ok(f"issue_key(jwe) raises: {str(e)[:70]}")
        tn.flush_and_close()

        # revoke_recipient on BGW should raise
        tn.init(ws / "tn2.yaml", cipher="bgw")
        cfg = tn.current_config()
        try:
            tn.revoke_recipient(cfg, "default", "did:key:zFoo")
            bad("revoke_recipient on BGW should have raised")
        except RuntimeError as e:
            ok(f"revoke_recipient(bgw) raises: {str(e)[:70]}")
        tn.flush_and_close()

        # import_key on JWE — this is the one we're not sure about
        tn.init(ws / "tn3.yaml", cipher="jwe")
        cfg = tn.current_config()
        fake_key_path = ws / "fake.read"
        fake_key_path.write_bytes(b"\x00" * 100)
        try:
            tn.import_key(cfg, "default", fake_key_path)
            bad("import_key on JWE ceremony succeeded (should have guarded?)")
        except RuntimeError as e:
            ok(f"import_key(jwe) raises RuntimeError: {str(e)[:70]}")
        except Exception as e:
            bad(f"import_key(jwe) raises {type(e).__name__} (not RuntimeError): {str(e)[:70]}")
        tn.flush_and_close()


def main() -> int:
    audit_bgw()
    audit_jwe()
    audit_guards()
    print("\n=== audit done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
