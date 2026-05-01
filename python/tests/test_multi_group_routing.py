"""Multi-group field routing.

A field listed under N groups in tn.yaml is encrypted into all N groups'
payloads. Each group's reader sees the same plaintext value independently.
This verifies the new canonical schema (`groups[<g>].fields`) plus the
back-compat path (legacy flat `fields:` block + DeprecationWarning).
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest
import yaml

import tn
from tn import config as tn_config


@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _read_user_envelopes(log_path: Path) -> list[dict]:
    out = []
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        env = json.loads(raw)
        if not env.get("event_type", "").startswith("tn."):
            out.append(env)
    return out


def _make_yaml(tmp_path: Path, *, body: dict, cipher: str = "jwe") -> Path:
    """Create a tn.yaml using the standard fresh ceremony, then overwrite
    the parts we care about (groups + fields) for the test scenario.

    Defaults to ``cipher="jwe"`` so emit stays on the Python path. (The
    btn dispatch routes through Rust, which has its own multi-group test
    suite in ``tn-core``.)
    """
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=cipher)
    # Force the runtime to flush so we can mutate yaml safely.
    tn.flush_and_close()

    # Add all the groups via admin so their cipher state is real on disk,
    # then rewrite groups[<g>].fields directly.
    cfg = tn_config.load(yaml_path)
    from tn import admin

    for gname in body["groups"]:
        if gname == "default":
            continue
        admin.ensure_group(cfg, gname, cipher=cipher)
    tn.flush_and_close()

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    # Drop the legacy flat fields block; we want canonical multi-group.
    doc["fields"] = {}
    # Apply per-group fields.
    for gname, gfields in body["groups"].items():
        if gname not in doc["groups"]:
            continue
        doc["groups"][gname]["fields"] = list(gfields)
    if "public_fields" in body:
        doc["public_fields"] = body["public_fields"]
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return yaml_path


# ---------------------------------------------------------------------------
# Canonical multi-group routing
# ---------------------------------------------------------------------------


def test_field_in_two_groups_routes_into_both(tmp_path):
    """A field listed under two groups ends up encrypted into both."""
    yaml_path = _make_yaml(
        tmp_path,
        body={"groups": {"default": [], "a": ["email"], "b": ["email"]}},
    )

    cfg = tn_config.load(yaml_path)
    assert cfg.field_to_groups["email"] == ["a", "b"]

    tn.init(yaml_path)
    tn.log("evt.multi", email="alice@example.com")
    # Reader walks while runtime is still live (current_config() requires it).
    log_path = yaml_path.parent / ".tn/tn/logs" / "tn.ndjson"
    entries_read = list(tn.read_raw(log_path))
    tn.flush_and_close()

    entries = _read_user_envelopes(yaml_path.parent / ".tn/tn/logs" / "tn.ndjson")
    assert len(entries) == 1
    env = entries[0]

    # Both groups carry a payload.
    assert "a" in env and "ciphertext" in env["a"]
    assert "b" in env and "ciphertext" in env["b"]

    # Reader sees the same value in both groups' plaintext.
    user_entries = [e for e in entries_read if not e["envelope"].get("event_type", "").startswith("tn.")]
    assert len(user_entries) == 1
    pt = user_entries[0]["plaintext"]
    assert pt["a"]["email"] == "alice@example.com"
    assert pt["b"]["email"] == "alice@example.com"

    # Field hashes per group are independent (different group key, different token).
    a_hashes = env["a"].get("field_hashes", {})
    b_hashes = env["b"].get("field_hashes", {})
    assert "email" in a_hashes and "email" in b_hashes
    assert a_hashes["email"] != b_hashes["email"]


def test_field_to_groups_sorted_alphabetically(tmp_path):
    """Insertion order must not affect canonical encoding."""
    yaml_path = _make_yaml(
        tmp_path,
        body={"groups": {"default": [], "zeta": ["x"], "alpha": ["x"]}},
    )
    cfg = tn_config.load(yaml_path)
    assert cfg.field_to_groups["x"] == ["alpha", "zeta"]


def test_field_in_zero_groups_and_not_public_raises_at_emit(tmp_path):
    """A field appearing nowhere in yaml AND no default group must fail emit."""
    yaml_path = _make_yaml(
        tmp_path,
        body={"groups": {"a": ["known"]}},
    )
    # Drop the default group so there's no fallback.
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if "default" in doc["groups"]:
        del doc["groups"]["default"]
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    # Remove the default keystore files too so load() doesn't pick it up.
    for f in (yaml_path.parent / ".tn/tn/keys").glob("default.*"):
        f.unlink()

    tn.init(yaml_path)
    with pytest.raises(ValueError, match="no group route"):
        tn.log("evt.bad", surprise_field="oops")


def test_field_routed_to_unknown_group_raises_at_load(tmp_path):
    """`groups[<g>].fields` referencing a group that isn't declared is a yaml error."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    # Add a phantom field route by pointing at a non-existent group via the
    # legacy flat block. (Canonical groups[<g>].fields can't reference
    # other groups, so the most direct way to test this is the flat block.)
    doc["fields"] = {"x": {"group": "ghost_group"}}
    # And clear any group-fields so we hit the legacy path.
    for g in doc["groups"].values():
        g.pop("fields", None)
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError, match="unknown group"):
            tn_config.load(yaml_path)


def test_field_in_public_and_group_is_ambiguous(tmp_path):
    """A field in both public_fields and a group's fields list is rejected."""
    yaml_path = _make_yaml(
        tmp_path,
        body={
            "groups": {"default": [], "a": ["email"]},
            "public_fields": ["email", "timestamp", "event_id", "event_type"],
        },
    )
    with pytest.raises(ValueError, match="public_fields and a group"):
        tn_config.load(yaml_path)


def test_legacy_flat_fields_loads_with_deprecation_warning(tmp_path):
    """Old yamls using flat `fields:` still load and route correctly."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    from tn import admin

    cfg = tn_config.load(yaml_path)
    admin.ensure_group(cfg, "secrets", cipher="btn")
    tn.flush_and_close()

    # Reach into yaml: clear groups[*].fields, set legacy flat fields block.
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    for g in doc["groups"].values():
        g.pop("fields", None)
    doc["fields"] = {"password": {"group": "secrets"}}
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg2 = tn_config.load(yaml_path)
        assert any(issubclass(w.category, DeprecationWarning) for w in caught), (
            "expected a DeprecationWarning for flat `fields:` block"
        )

    assert cfg2.field_to_groups["password"] == ["secrets"]


def test_default_group_absorbs_undeclared_fields(tmp_path):
    """Existing back-compat: an undeclared field falls into `default` when present."""
    yaml_path = _make_yaml(
        tmp_path,
        body={"groups": {"default": [], "secrets": ["password"]}},
    )
    tn.init(yaml_path)
    tn.log("evt.fallthrough", random_thing=42)
    tn.flush_and_close()
    entries = _read_user_envelopes(yaml_path.parent / ".tn/tn/logs" / "tn.ndjson")
    assert len(entries) == 1
    # The undeclared field landed in default.
    assert "default" in entries[0]
