"""
Failing-first tests for the init-is-smart architectural hardening.

Three independent slices, one test each. Keep them small; they'll light
up red before the implementation lands and green after.

1. Scan helper reads both main log and PEL (protocol_events_location).
   The existing _emit_missing_group_added only walks the main log, so
   a ceremony that splits admin events into a dedicated file re-emits
   group.added on every init.

2. init auto-provisions recipients that are declared in tn.yaml but
   have no matching tn.recipient.added in the log(s). btn-only for
   now. Idempotent: second init is a no-op.

3. create_fresh refuses to clobber an existing keystore. If
   .tn/tn/keys/local.private already exists but tn.yaml does not, we raise
   instead of silently overwriting.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
from tn.config import create_fresh

RESULTS: list[tuple[str, bool, str]] = []


def ok(name: str) -> None:
    print(f"[ok]   {name}")
    RESULTS.append((name, True, ""))


def fail(name: str, why: str) -> None:
    print(f"[fail] {name}: {why}")
    RESULTS.append((name, False, why))


def _write_yaml(yaml_path: Path, text: str) -> None:
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(text, encoding="utf-8")


def _count_events(log_files: list[Path], event_type: str) -> int:
    n = 0
    for p in log_files:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get("event_type") == event_type:
                        n += 1
                except Exception:
                    pass
    return n


def _log_events_matching(log_files: list[Path], predicate) -> list[dict]:
    out: list[dict] = []
    for p in log_files:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    env = json.loads(line)
                except Exception:
                    continue
                if predicate(env):
                    out.append(env)
    return out


# -----------------------------------------------------------------------
# Slice 1: log-scan helper walks main log + PEL
# -----------------------------------------------------------------------


def test_slice1_scan_covers_main_and_pel() -> None:
    """_scan_attested_events must read both the main log and every PEL
    file so _emit_missing_* helpers see the full truth."""
    name = "slice1.scan_covers_main_and_pel"
    with tempfile.TemporaryDirectory(prefix="tninit_s1_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # Step 1: let tn.init create a fresh ceremony so `me.did` etc.
        # are populated for us.
        tn.init(yaml_path, cipher="btn")
        tn.flush_and_close()

        # Step 2: inject protocol_events_location so tn.* events route
        # to a dedicated file template on subsequent emits.
        yaml_text = yaml_path.read_text(encoding="utf-8")
        if "protocol_events_location:" not in yaml_text:
            yaml_text = yaml_text.replace(
                "ceremony:\n",
                "ceremony:\n  protocol_events_location: ./.tn/logs/admin/{event_type}.ndjson\n",
                1,
            )
            yaml_path.write_text(yaml_text, encoding="utf-8")

        # Step 3: trigger a new emit so the PEL file is created. Any
        # hand-edited recipient works as the trigger; the test for
        # slice 2 covers that path specifically, so here we just emit
        # a tn.group.added directly via the dispatch runtime so we
        # exercise the split-log write path without depending on
        # slice 2 being implemented yet.
        tn.init(yaml_path, cipher="btn")
        try:
            pass  # pragma: no cover — not used
        except Exception:
            pass
        # Emit one admin event to force the PEL to exist.
        from datetime import datetime, timezone

        try:
            tn._require_dispatch().emit(
                "info",
                "tn.group.added",
                {
                    "group": "default",
                    "cipher": "btn",
                    "publisher_did": tn.current_config().device.did,
                    "added_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception as exc:
            fail(name, f"could not emit tn.group.added for test setup: {exc}")
            tn.flush_and_close()
            return

        ws / ".tn/tn/logs" / "tn.ndjson"
        pel_dir = ws / ".tn/tn/logs" / "admin"
        pel_files = list(pel_dir.glob("*.ndjson")) if pel_dir.exists() else []

        pel_admin = _count_events(pel_files, "tn.group.added")
        if pel_admin < 1:
            fail(name, f"expected >=1 tn.group.added in PEL at {pel_dir}, got {pel_admin}")
            tn.flush_and_close()
            return

        try:
            from tn import _scan_attested_events
        except ImportError as exc:
            fail(name, f"_scan_attested_events not exported yet: {exc}")
            tn.flush_and_close()
            return

        cfg = tn.current_config()
        seen = _scan_attested_events(cfg, "tn.group.added")
        tn.flush_and_close()

        if "default" not in seen:
            fail(name, f"scan did not find the default group's added event; seen={seen}")
            return

        ok(name)


# -----------------------------------------------------------------------
# Slice 2: init auto-provisions missing recipients
# -----------------------------------------------------------------------


def test_slice2_init_provisions_missing_recipient() -> None:
    """Adding a recipient DID to tn.yaml by hand should cause the next
    tn.init to mint a kit and emit tn.recipient.added for that DID,
    idempotently."""
    name = "slice2.init_provisions_missing_recipient"
    with tempfile.TemporaryDirectory(prefix="tninit_s2_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # Fresh btn ceremony (publisher = only recipient initially).
        tn.init(yaml_path, cipher="btn")
        tn.flush_and_close()

        main_log = ws / ".tn/tn/logs" / "tn.ndjson"
        before = _count_events([main_log], "tn.recipient.added")

        # Hand-edit the yaml to add a second recipient. This simulates
        # what a human operator or a config-management tool would do.
        yaml_text = yaml_path.read_text(encoding="utf-8")
        bob_did = "did:key:z6MkfakeBobForProvisioningTestxxxxxxxxxxxxxxxx"
        # Insert a recipient under groups.default. Simple string manip
        # is fine for this fixture; a real yaml parser would also work.
        injected = yaml_text.replace(
            "- did: did:key:",
            f"- did: {bob_did}\n    - did: did:key:",
            1,
        )
        if injected == yaml_text:
            fail(name, "could not find 'did: did:key:' anchor in yaml to inject second recipient")
            return
        yaml_path.write_text(injected, encoding="utf-8")

        # Second init should notice bob is declared but unprovisioned.
        tn.init(yaml_path, cipher="btn")
        tn.flush_and_close()

        after = _count_events([main_log], "tn.recipient.added")
        if after != before + 1:
            fail(
                name,
                f"expected +1 tn.recipient.added after second init (before={before}, after={after})",
            )
            return

        # Confirm bob specifically is attested.
        bob_events = _log_events_matching(
            [main_log],
            lambda env: (
                env.get("event_type") == "tn.recipient.added"
                and env.get("recipient_did") == bob_did
            ),
        )
        if not bob_events:
            fail(name, f"no tn.recipient.added with recipient_did={bob_did!r}")
            return

        # A kit should have been written to a predictable location so
        # the operator can hand it off. We don't pin the path; just
        # require that the kit_sha256 from the event matches a file
        # somewhere under the ceremony dir.
        kit_sha = bob_events[0].get("kit_sha256")
        if not kit_sha:
            fail(name, "event missing kit_sha256")
            return

        import hashlib

        found_kit = False
        for root, _dirs, files in os.walk(ws):
            for fname in files:
                if fname.endswith(".mykit"):
                    raw = (Path(root) / fname).read_bytes()
                    have = "sha256:" + hashlib.sha256(raw).hexdigest()
                    if have == kit_sha:
                        found_kit = True
                        break
        if not found_kit:
            fail(name, f"no on-disk .mykit file hashes to {kit_sha}")
            return

        # Third init is a no-op: count stays the same.
        tn.init(yaml_path, cipher="btn")
        tn.flush_and_close()
        after2 = _count_events([main_log], "tn.recipient.added")
        if after2 != after:
            fail(name, f"third init was not idempotent (was {after}, now {after2})")
            return

        ok(name)


# -----------------------------------------------------------------------
# Slice 3: create_fresh refuses to clobber an existing keystore
# -----------------------------------------------------------------------


def test_slice3_create_fresh_refuses_to_clobber() -> None:
    """If .tn/tn/keys/local.private already exists but tn.yaml is missing,
    create_fresh should raise instead of generating a new device key
    on top of it."""
    name = "slice3.create_fresh_refuses_clobber"
    with tempfile.TemporaryDirectory(prefix="tninit_s3_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # First, create a real ceremony so the keystore is populated.
        tn.init(yaml_path, cipher="btn")
        tn.flush_and_close()

        # Now remove the yaml but leave the keystore.
        yaml_path.unlink()
        if not (ws / ".tn/tn/keys" / "local.private").exists():
            fail(name, "keystore missing after first init (setup failure)")
            return

        # Calling create_fresh (or init which will route to it) must
        # refuse rather than silently overwriting the existing key.
        try:
            create_fresh(yaml_path, cipher="btn")
        except Exception as exc:
            msg = str(exc)
            # Good: raised. Check the message is informative.
            if "keystore" in msg.lower() or "already" in msg.lower() or "exists" in msg.lower():
                ok(name)
                return
            fail(name, f"raised but message unhelpful: {exc!r}")
            return
        fail(name, "expected create_fresh to raise on existing keystore; it did not")


# -----------------------------------------------------------------------
# Driver
# -----------------------------------------------------------------------


def main() -> int:
    test_slice1_scan_covers_main_and_pel()
    test_slice2_init_provisions_missing_recipient()
    test_slice3_create_fresh_refuses_to_clobber()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = sum(1 for _, ok, _ in RESULTS if not ok)
    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
