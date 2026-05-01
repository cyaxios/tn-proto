"""tn.admin.rotate emits tn.rotation.completed with the catalog-shaped fields."""

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


def _rotation_events(yaml_path):
    """Read tn.rotation.completed envelopes from the dedicated admin log.

    Post-2026-04-24 admin events route to ``<yaml_dir>/.tn/admin/admin.ndjson``
    by default rather than the main log. This helper reads that file
    directly and returns the matching raw envelope dicts.
    """
    import json as _json

    admin_log = yaml_path.parent / ".tn/tn/admin" / "admin.ndjson"
    if not admin_log.exists():
        return []
    out = []
    with admin_log.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            env = _json.loads(line)
            if env.get("event_type") == "tn.rotation.completed":
                out.append(env)
    return out


def test_btn_rotate_emits_rotation_completed(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=100)
    tn.admin.rotate("default")
    tn.flush_and_close()

    # The reducer-derived view exposes the typed rotation record.
    tn.init(yaml)
    state = tn.admin.state()
    rots = [r for r in state["rotations"] if r["group"] == "default"]
    assert len(rots) == 1, f"expected 1 rotation, got {rots}"
    r = rots[0]
    assert r["cipher"] == "btn"
    assert r["generation"] >= 1
    assert r["previous_kit_sha256"].startswith("sha256:")
    assert r["rotated_at"]  # non-empty ISO 8601


def test_jwe_rotate_emits_rotation_completed(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")
    tn.info("order.created", amount=42)
    tn.admin.rotate("default")
    tn.flush_and_close()

    tn.init(yaml)
    # JWE doesn't ride the Rust reducer for admin_state rotations, so
    # scan the dedicated admin log envelope directly.
    rotation_envs = _rotation_events(yaml)
    assert len(rotation_envs) == 1, (
        f"expected 1 tn.rotation.completed for jwe, got {len(rotation_envs)}"
    )
    env = rotation_envs[0]
    assert env["group"] == "default"
    assert env["cipher"] == "jwe"
    assert env["generation"] >= 1
    assert env["previous_kit_sha256"].startswith("sha256:")
    assert env["rotated_at"]
    # pool_size fields are None for jwe
    assert env["old_pool_size"] is None
    assert env["new_pool_size"] is None


def test_no_legacy_tn_key_rotation_emitted(tmp_path):
    """Ensure the old event name is gone."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.rotate("default")
    tn.flush_and_close()

    tn.init(yaml)
    # The old event name would also have routed through the admin log;
    # neither the main log nor the admin log should contain it.
    import json as _json

    admin_log = yaml.parent / ".tn/tn/admin" / "admin.ndjson"
    legacy = []
    if admin_log.exists():
        with admin_log.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                env = _json.loads(line)
                if env.get("event_type") == "tn.key.rotation":
                    legacy.append(env)
    assert len(legacy) == 0, f"tn.key.rotation should no longer be emitted; saw: {legacy}"


def test_rotation_completed_catalog_fields_present(tmp_path):
    """All 7 catalog fields must be present in the emitted event."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.admin.rotate("default")
    tn.flush_and_close()

    tn.init(yaml)
    rotation_envs = _rotation_events(yaml)
    assert len(rotation_envs) == 1
    # btn ceremonies route the catalog fields through the encrypted
    # ``default`` payload; reload the entry through tn.read_all() so
    # plaintext is decoded for us.
    raw = next(
        r
        for r in tn.read_all()
        if r["envelope"].get("event_type") == "tn.rotation.completed"
    )
    flat = dict(raw["envelope"])
    for gname, gfields in (raw.get("plaintext") or {}).items():
        if isinstance(gfields, dict):
            flat.update(gfields)
    required_fields = [
        "group",
        "cipher",
        "generation",
        "previous_kit_sha256",
        "old_pool_size",
        "new_pool_size",
        "rotated_at",
    ]
    for field in required_fields:
        assert field in flat, (
            f"field {field!r} missing from tn.rotation.completed fields: {sorted(flat)}"
        )
