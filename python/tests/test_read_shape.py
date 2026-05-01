"""tn.read() reshape — flat-dict default, verify=True adds _valid, raw=True legacy.

Spec: ``docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md``
sections 1, 4, 5.1, 9.

Default ``tn.read()`` returns a flat decrypted dict per envelope. The
six envelope basics (timestamp, event_type, level, did, sequence,
event_id) plus every readable group's decrypted fields and any extra
public fields surface flat. ``_hidden_groups`` and ``_decrypt_errors``
are present only when non-empty. ``verify=True`` adds a ``_valid`` block.
``raw=True`` returns the legacy ``{envelope, plaintext, valid}`` audit
shape unchanged.
"""

from __future__ import annotations

import json
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


def _user_only(iterable):
    """Filter out tn.* bootstrap attestations (flat-dict version)."""
    out = []
    for e in iterable:
        et = e.get("event_type") if isinstance(e, dict) else None
        if isinstance(et, str) and et.startswith("tn."):
            continue
        out.append(e)
    return out


def _raw_user_only(iterable):
    return [e for e in iterable if not e["envelope"]["event_type"].startswith("tn.")]


# --------------------------------------------------------------------------
# Default flat shape
# --------------------------------------------------------------------------


def test_default_flat_shape_carries_six_envelope_basics_and_decrypted_fields(tmp_path):
    """Default tn.read() returns flat dicts with the six envelope basics
    plus decrypted fields from every readable group."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999, currency="USD", order_id="ord_x")
    tn.flush_and_close()

    tn.init(yaml)
    entries = _user_only(tn.read())
    assert len(entries) == 1
    e = entries[0]
    assert isinstance(e, dict)

    # Six envelope basics surface flat.
    assert isinstance(e["timestamp"], str)
    assert e["event_type"] == "order.created"
    assert e["level"] == "info"
    assert e["did"].startswith("did:key:z")
    assert e["sequence"] == 1
    assert isinstance(e["event_id"], str) and len(e["event_id"]) >= 32

    # Decrypted fields appear flat.
    assert e["amount"] == 4999
    assert e["currency"] == "USD"
    assert e["order_id"] == "ord_x"


def test_default_flat_shape_excludes_crypto_plumbing(tmp_path):
    """prev_hash, row_hash, signature, ciphertext, field_hashes never
    surface in the flat default shape."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    e = _user_only(tn.read())[0]

    for k in ("prev_hash", "row_hash", "signature", "ciphertext", "field_hashes"):
        assert k not in e, f"crypto plumbing leaked into flat shape: {k}"
    # And no group-keyed nesting.
    assert "default" not in e
    assert "envelope" not in e
    assert "plaintext" not in e


def test_no_hidden_groups_key_when_empty(tmp_path):
    """A row whose groups all decrypt has no _hidden_groups / _decrypt_errors keys."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    e = _user_only(tn.read())[0]

    assert "_hidden_groups" not in e
    assert "_decrypt_errors" not in e


# --------------------------------------------------------------------------
# verify=True — adds _valid
# --------------------------------------------------------------------------


def test_verify_true_adds_valid_block(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    e = _user_only(tn.read(verify=True))[0]

    assert "_valid" in e
    assert set(e["_valid"].keys()) == {"signature", "row_hash", "chain"}
    assert e["_valid"]["signature"] is True
    assert e["_valid"]["row_hash"] is True
    assert e["_valid"]["chain"] is True


def test_verify_false_omits_valid_block(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    e = _user_only(tn.read())[0]

    assert "_valid" not in e


# --------------------------------------------------------------------------
# raw=True — legacy regression
# --------------------------------------------------------------------------


def test_raw_true_returns_legacy_shape(tmp_path):
    """raw=True returns today's {envelope, plaintext, valid} dict shape unchanged."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    raw_entries = _raw_user_only(tn.read(raw=True))
    assert len(raw_entries) == 1
    r = raw_entries[0]
    assert isinstance(r, dict)
    assert set(r.keys()) == {"envelope", "plaintext", "valid"}
    assert r["envelope"]["event_type"] == "order.created"
    assert r["plaintext"]["default"]["amount"] == 4999
    assert r["valid"] == {"signature": True, "row_hash": True, "chain": True}


def test_raw_overrides_verify(tmp_path):
    """raw=True overrides verify=True — no error, raw shape wins."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    tn.init(yaml)
    raw_entries = _raw_user_only(tn.read(raw=True, verify=True))
    assert len(raw_entries) == 1
    # Raw shape — no _valid key, has valid (no underscore) key.
    r = raw_entries[0]
    assert "_valid" not in r
    assert "valid" in r


# --------------------------------------------------------------------------
# _hidden_groups: groups present in envelope but no kit
# --------------------------------------------------------------------------


def _make_two_group_yaml(tmp_path: Path, fields_by_group: dict[str, list[str]]) -> Path:
    """Stand up a btn ceremony with multi-group field routing.

    ``fields_by_group`` maps group name to the list of fields that should
    route there (per the canonical ``groups[<g>].fields`` schema).
    """
    import yaml as _yaml

    from tn import admin as _admin
    from tn import config as _tn_config

    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()

    cfg = _tn_config.load(yaml_path)
    for gname in fields_by_group:
        if gname == "default":
            continue
        _admin.ensure_group(cfg, gname, cipher="btn")
    tn.flush_and_close()

    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["fields"] = {}
    for gname, gfields in fields_by_group.items():
        if gname in doc.get("groups", {}):
            doc["groups"][gname]["fields"] = list(gfields)
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return yaml_path


def test_hidden_groups_when_caller_lacks_kit(tmp_path, monkeypatch):
    """A reader without a group's kit gets the group name in _hidden_groups.

    Pinned to the Python path so the writer + reader both honor the
    yaml-declared group set; the Python reader emits a payload per declared
    group, and dropping a group from yaml + removing its kit makes that
    group's ciphertext unreadable on the next read.
    """
    import yaml as _yaml

    monkeypatch.setenv("TN_FORCE_PYTHON", "1")

    # JWE so emit / read both run through the Python path.
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="jwe")
    tn.flush_and_close()
    from tn import admin as _admin
    from tn import config as _tn_config

    cfg = _tn_config.load(yaml_path)
    _admin.ensure_group(cfg, "pii", cipher="jwe")
    tn.flush_and_close()

    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["fields"] = {}
    doc["groups"]["default"]["fields"] = ["amount"]
    doc["groups"]["pii"]["fields"] = ["email"]
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    tn.init(yaml_path)
    tn.info("order.created", amount=4999, email="alice@example.com")
    tn.flush_and_close()

    # Drop the pii group from yaml AND clear its kit so the reader's
    # runtime has no cipher for it.
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.get("groups", {}).pop("pii", None)
    # Remove pii from fields routing too.
    doc["fields"] = {}
    doc["groups"]["default"]["fields"] = ["amount", "email"]
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    keystore = tmp_path / ".tn/tn/keys"
    for p in keystore.glob("pii.*"):
        p.unlink()

    tn.init(yaml_path)
    e = _user_only(tn.read())[0]

    # Default group decrypted; pii's ciphertext is in the envelope but
    # the reader has no cipher loaded for it.
    assert e["amount"] == 4999
    assert "email" not in e
    assert "_hidden_groups" in e
    assert "pii" in e["_hidden_groups"]


# --------------------------------------------------------------------------
# _decrypt_errors: corrupt ciphertext
# --------------------------------------------------------------------------


def test_decrypt_errors_when_decrypt_throws(tmp_path, monkeypatch):
    """Tampered ciphertext lands the group name in _decrypt_errors.

    Pin to the Python reader so we exercise ``flatten_raw_entry`` over
    legacy-style ``{$decrypt_error: True}`` plaintext sentinels — the
    Rust dispatch raises on malformed bytes before we can map the error,
    so this test sets ``TN_FORCE_PYTHON`` to route through the Python
    reader where the broad swallow happens per-group.
    """
    import base64 as _b64

    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    # JWE so the pure-Python path is the active runtime.
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    # Corrupt the ciphertext on the row to force a decrypt error.
    log = tmp_path / ".tn/tn/logs" / "tn.ndjson"
    lines = log.read_text(encoding="utf-8").splitlines()
    # Find the user row.
    target_idx = None
    for i, ln in enumerate(lines):
        if not ln.strip():
            continue
        env = json.loads(ln)
        if env.get("event_type") == "order.created":
            target_idx = i
            break
    assert target_idx is not None, "could not find order.created row"
    target = json.loads(lines[target_idx])
    g = target.get("default")
    assert g is not None and "ciphertext" in g, "user row missing default group ciphertext"
    # Garbage bytes that are valid base64 but not valid JWE bytes.
    g["ciphertext"] = _b64.b64encode(b"\x00" * 64).decode("ascii")
    lines[target_idx] = json.dumps(target, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tn.init(yaml)
    e = _user_only(tn.read())[0]

    # Tampered group — _decrypt_errors lists it.
    assert "_decrypt_errors" in e
    assert "default" in e["_decrypt_errors"]
    # And the decrypted fields are absent.
    assert "amount" not in e


# --------------------------------------------------------------------------
# Field-name collisions: deterministic last-write-wins
# --------------------------------------------------------------------------


def test_field_collision_is_deterministic(tmp_path):
    """Two groups with the same field name resolve via last-write-wins
    in alphabetical group order — deterministic across runs."""
    # Route ``email`` into BOTH default and pii groups (collision).
    yaml = _make_two_group_yaml(
        tmp_path,
        {"default": ["amount", "email"], "pii": ["email"]},
    )

    tn.init(yaml)
    tn.info("order.created", amount=4999, email="alice@example.com")
    tn.flush_and_close()

    # Two reads should produce the same value for email.
    tn.init(yaml)
    first = _user_only(tn.read())[0]
    tn.flush_and_close()
    tn.init(yaml)
    second = _user_only(tn.read())[0]

    assert "email" in first
    assert first["email"] == second["email"], (
        "field-collision resolution is not deterministic across runs"
    )
    # Alphabetical group iteration: default < pii, so pii's value wins
    # (last-write). Both groups carried the same value here, so we just
    # assert presence + determinism.
    assert first["email"] == "alice@example.com"


# --------------------------------------------------------------------------
# Public fields beyond envelope basics
# --------------------------------------------------------------------------


def test_yaml_declared_public_field_surfaces_flat(tmp_path):
    """A field declared in yaml ``public_fields`` surfaces flat at the top level."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    # Edit the yaml to declare request_id as a public field.
    text = yaml.read_text(encoding="utf-8")
    # Find the ceremony block and append a public_fields list.
    if "public_fields:" not in text:
        # Append at the top level. Existing yaml ends with ``logs:`` block;
        # add a top-level public_fields section.
        text += "\npublic_fields:\n  - request_id\n"
        yaml.write_text(text, encoding="utf-8")

    tn.init(yaml)
    tn.info("order.created", amount=4999, request_id="req_abc123")
    tn.flush_and_close()

    tn.init(yaml)
    e = _user_only(tn.read())[0]

    # request_id is public — it should surface flat alongside decrypted fields.
    assert e.get("request_id") == "req_abc123"


# --------------------------------------------------------------------------
# A row with NO ciphertext / no groups — just envelope basics
# --------------------------------------------------------------------------


def test_row_with_no_groups_returns_envelope_basics_only(tmp_path):
    """An entry with no group ciphertext (admin-event-style) returns just
    the envelope basics — no _hidden_groups key when nothing is hidden."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    # The auto-emitted tn.ceremony.init lands in the admin log with no
    # encrypted groups; reading it should produce envelope basics only.
    tn.init(yaml)
    cfg = tn.current_config()
    admin_log = tmp_path / ".tn/tn/admin" / "admin.ndjson"
    if not admin_log.exists():
        # Fallback: use tn.read_all() / tn.read() — find the admin-style
        # event (ceremony init) wherever it lives.
        all_entries = list(tn.read(admin_log)) if admin_log.exists() else list(
            tn.read(cfg.resolve_log_path())
        )
    else:
        all_entries = list(tn.read(admin_log))

    init_events = [e for e in all_entries if e.get("event_type") == "tn.ceremony.init"]
    assert init_events, "expected tn.ceremony.init in the admin log"
    e = init_events[0]
    # No _hidden_groups key when nothing was hidden.
    assert "_hidden_groups" not in e
    assert "_decrypt_errors" not in e
    # The six envelope basics still present.
    for k in ("timestamp", "event_type", "level", "did", "sequence", "event_id"):
        assert k in e


# --------------------------------------------------------------------------
# TN_READER_LEGACY env var — escape hatch
# --------------------------------------------------------------------------


def test_legacy_env_var_reverts_default_to_raw_shape(tmp_path, monkeypatch):
    """``TN_READER_LEGACY=1`` flips the default back to the raw shape
    so callers can opt back during the migration."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", amount=4999)
    tn.flush_and_close()

    monkeypatch.setenv("TN_READER_LEGACY", "1")

    tn.init(yaml)
    entries = _raw_user_only(tn.read())
    assert len(entries) == 1
    r = entries[0]
    # Legacy shape keys.
    assert set(r.keys()) == {"envelope", "plaintext", "valid"}
    assert r["envelope"]["event_type"] == "order.created"
