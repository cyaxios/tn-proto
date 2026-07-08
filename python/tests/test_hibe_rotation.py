"""HIBE policy-path rotation (Phase 6): future seals move to a new identity
path; pre-rotation seals stay open for prior grantees (the honest limit of
the cipher — delegated keys are permanent trapdoors)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_hibe_rotation(tmp_path):
    ws = tmp_path
    a_yaml = ws / "authority" / "tn.yaml"
    a_log = ws / "authority" / "log.ndjson"

    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("epoch.a", body="sealed before rotation")
    kit = ws / "reader.tnpkg"
    tn.admin.grant_reader("default", reader_did="did:key:z6Mk-r", out_path=kit)

    new_path = tn.admin.rotate_reader_path("default", "policy-b")
    assert new_path == "policy-b"
    tn.info("epoch.b", body="sealed after rotation")
    tn.flush_and_close()

    # Reader with the PRE-rotation grant.
    r_yaml = ws / "reader" / "tn.yaml"
    tn.init(r_yaml, log_path=ws / "reader" / "log.ndjson")
    r_cfg = tn.current_config()
    tn.absorb(kit)
    entries = {
        e["envelope"]["event_type"]: e
        for e in tn.reader.read_as_recipient(a_log, r_cfg.keystore, group="default")
    }
    assert len(entries) == 2
    # Pre-rotation seal still opens (permanent-key property, documented).
    assert entries["epoch.a"]["plaintext"]["default"]["body"] == (
        "sealed before rotation"
    )
    # Post-rotation seal does NOT open for the old-path grantee.
    assert entries["epoch.b"]["plaintext"]["default"] == {"$no_read_key": True}, (
        entries["epoch.b"]["plaintext"]["default"]
    )
    tn.flush_and_close()

    # The authority itself still reads both epochs (msk + the recorded
    # path history mint keys for every epoch's path). Assert on the
    # actual field values, not just key presence — the sentinel shapes
    # also live under the group name.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    a_cfg = tn.current_config()
    both = {
        e["envelope"]["event_type"]: e["plaintext"]["default"]
        for e in tn.reader.read(a_log, a_cfg)
    }
    assert both["epoch.a"]["body"] == "sealed before rotation", both["epoch.a"]
    assert both["epoch.b"]["body"] == "sealed after rotation", both["epoch.b"]
    tn.flush_and_close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
