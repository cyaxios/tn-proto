"""tn.ensure_group emits a tn.group.added admin event."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_ensure_group_emits_tn_group_added(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    cfg = tn.current_config()
    tn.ensure_group(cfg, "pii", fields=["email"])
    tn.flush_and_close()

    tn.init(yaml)
    # Post-2026-04-24 admin events route to `.tn/tn/admin/admin.ndjson` by
    # default. Use the reducer-derived state, which scans both files.
    state = tn.admin.state()
    pii_groups = [g for g in state["groups"] if g["group"] == "pii"]
    assert len(pii_groups) == 1, f"expected exactly one tn.group.added for group=pii, got {pii_groups}"
    g = pii_groups[0]
    assert g["cipher"] in {"btn", "bearer", "jwe"}, f"unexpected cipher: {g['cipher']!r}"
    assert g["publisher_did"].startswith("did:"), (
        f"publisher_did does not look like a DID: {g['publisher_did']!r}"
    )
    assert g["added_at"], "added_at should be a non-empty ISO 8601 string"


def test_ensure_group_idempotent_no_duplicate_emit(tmp_path):
    """Calling ensure_group twice for the same group must not emit twice.

    ensure_group short-circuits when the group already exists in both
    cfg.groups and on disk (key_exists check). The second call returns
    early before reaching the emit block, so only one event should appear.
    """
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    cfg = tn.current_config()
    tn.ensure_group(cfg, "pii", fields=["email"])
    tn.ensure_group(cfg, "pii", fields=["email"])  # second call -- should short-circuit
    tn.flush_and_close()

    tn.init(yaml)
    # Scan the dedicated admin log directly: the reducer dedupes same-(group,
    # publisher) events into a single record so we count raw lines instead.
    import json as _json

    admin_log = yaml.parent / ".tn/tn/admin" / "admin.ndjson"
    added = []
    if admin_log.exists():
        with admin_log.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                env = _json.loads(line)
                if env.get("event_type") == "tn.group.added" and env.get("group") == "pii":
                    added.append(env)
    assert len(added) <= 1, (
        f"ensure_group should not emit duplicate group.added events: saw {len(added)} for group=pii"
    )
