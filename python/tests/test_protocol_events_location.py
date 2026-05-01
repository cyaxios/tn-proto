"""Tests for ceremony.protocol_events_location (spec 2026-04-21)."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import yaml as _yaml

import tn

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _fresh_x25519_pub() -> bytes:
    priv = X25519PrivateKey.generate()
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _init_jwe(tmp_path: Path, protocol_events_location: str | None = None) -> Path:
    """Create a JWE ceremony in tmp_path, optionally setting PEL in the yaml.

    Note: the yaml field was renamed ``protocol_events_location`` →
    ``admin_log_location`` (2026-04-24). The kwarg name preserves the
    test's vocabulary; we write into ``admin_log_location`` so the value
    is the one the runtime actually consults. If only the legacy key is
    set, the SDK accepts it with a DeprecationWarning, so writing into
    the new key is the path that exercises the active code.
    """
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="jwe")
    tn.flush_and_close()
    if protocol_events_location is not None:
        with open(yaml_path, encoding="utf-8") as f:
            doc = _yaml.safe_load(f)
        doc["ceremony"]["admin_log_location"] = protocol_events_location
        with open(yaml_path, "w", encoding="utf-8") as f:
            _yaml.safe_dump(doc, f, sort_keys=False)
    tn.init(yaml_path)
    return yaml_path


def _set_pel(yaml_path: Path, pel: str) -> None:
    """Replace the admin_log_location in an existing tn.yaml.

    See ``_init_jwe`` for the rename note. We replace rather than add a
    legacy key so the tested path is the active runtime path.
    """
    with open(yaml_path, encoding="utf-8") as f:
        doc = _yaml.safe_load(f)
    doc["ceremony"]["admin_log_location"] = pel
    with open(yaml_path, "w", encoding="utf-8") as f:
        _yaml.safe_dump(doc, f, sort_keys=False)


# ---------------------------------------------------------------------------
# Test 1: absent key → dedicated `.tn/tn/admin/admin.ndjson` (new default,
# 2026-04-24). Admin events do NOT land in the main log; they land in the
# dedicated file under the yaml directory.
# ---------------------------------------------------------------------------


def test_default_is_admin_log(tmp_path):
    yaml_path = _init_jwe(tmp_path)  # no PEL key
    cfg = tn.current_config()
    tn.admin.rotate("default")
    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()
    # Main log: no admin events.
    main_entries = list(tn.read(None, cfg))
    main_rot = [e for e in main_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(main_rot) == 0, "rotation.completed leaked into main log"
    # Admin log: rotation event lives there.
    admin_log = tmp_path / ".tn/tn/admin" / "admin.ndjson"
    assert admin_log.exists(), f"expected admin log at {admin_log}"
    admin_entries = list(tn.read(admin_log, cfg))
    rotation_entries = [e for e in admin_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(rotation_entries) == 1


# ---------------------------------------------------------------------------
# Test 2: explicit main_log literal
# ---------------------------------------------------------------------------


def test_main_log_literal(tmp_path):
    yaml_path = _init_jwe(tmp_path, protocol_events_location="main_log")
    cfg = tn.current_config()
    tn.admin.rotate("default")
    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()
    entries = list(tn.read(None, cfg))
    rotation_entries = [e for e in entries if e["event_type"] == "tn.rotation.completed"]
    assert len(rotation_entries) == 1


# ---------------------------------------------------------------------------
# Test 3: static path — rotation goes to separate file, absent from main log
# ---------------------------------------------------------------------------


def test_static_path(tmp_path):
    yaml_path = _init_jwe(tmp_path, protocol_events_location="./.tn/logs/tn.admin.ndjson")
    cfg = tn.current_config()
    tn.info("order.created", amount=1)
    tn.admin.rotate("default")
    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()

    admin_file = tmp_path / ".tn/logs" / "tn.admin.ndjson"
    assert admin_file.exists()
    admin_entries = list(tn.read(admin_file, cfg))
    assert any(e["event_type"] == "tn.rotation.completed" for e in admin_entries)

    main_entries = list(tn.read(None, cfg))
    main_rotation = [e for e in main_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(main_rotation) == 0


# ---------------------------------------------------------------------------
# Test 4: {event_type} substitution → one file per protocol event type
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _CRYPTO_AVAILABLE, reason="cryptography package required")
def test_event_type_substitution(tmp_path):
    template = "./.tn/logs/protocol/{event_type}.ndjson"
    yaml_path = _init_jwe(tmp_path, protocol_events_location=template)
    cfg = tn.current_config()

    tn.admin.rotate("default")
    cfg = tn.current_config()

    recipient_pub = _fresh_x25519_pub()
    recipient_did = "did:key:z6MkTestRecipientAAAAAAAAAAAA"
    tn.add_recipient(cfg, "default", recipient_did, recipient_pub)
    cfg = tn.current_config()
    tn.revoke_recipient(cfg, "default", recipient_did)

    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()

    rotation_file = tmp_path / ".tn/logs" / "protocol" / "tn.rotation.completed.ndjson"
    added_file = tmp_path / ".tn/logs" / "protocol" / "tn.recipient.added.ndjson"
    revoked_file = tmp_path / ".tn/logs" / "protocol" / "tn.recipient.revoked.ndjson"

    assert rotation_file.exists(), f"expected {rotation_file}"
    assert added_file.exists(), f"expected {added_file}"
    assert revoked_file.exists(), f"expected {revoked_file}"

    assert len(list(tn.read(rotation_file, cfg))) == 1
    assert len(list(tn.read(added_file, cfg))) == 1
    assert len(list(tn.read(revoked_file, cfg))) == 1


# ---------------------------------------------------------------------------
# Test 5: {date} substitution → today's date in filename
# ---------------------------------------------------------------------------


def test_date_substitution(tmp_path):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    template = "./.tn/logs/tn.admin.{date}.ndjson"
    _init_jwe(tmp_path, protocol_events_location=template)
    tn.current_config()
    tn.admin.rotate("default")
    tn.flush_and_close()

    expected_file = tmp_path / ".tn/logs" / f"tn.admin.{today}.ndjson"
    assert expected_file.exists(), f"expected {expected_file}"


# ---------------------------------------------------------------------------
# Test 6: {yaml_dir} substitution → absolute path within ceremony dir
# ---------------------------------------------------------------------------


def test_yaml_dir_substitution(tmp_path):
    template = "{yaml_dir}/audit/tn.admin.ndjson"
    _init_jwe(tmp_path, protocol_events_location=template)
    tn.current_config()
    tn.admin.rotate("default")
    tn.flush_and_close()

    expected_file = tmp_path / "audit" / "tn.admin.ndjson"
    assert expected_file.exists(), f"expected {expected_file}"


# ---------------------------------------------------------------------------
# Test 7: unknown token raises ValueError at load time
# ---------------------------------------------------------------------------


def test_unknown_token_rejected_at_load(tmp_path):
    yaml_path = _init_jwe(tmp_path)
    tn.flush_and_close()
    _set_pel(yaml_path, "./.tn/logs/{foo}.ndjson")
    with pytest.raises(
        ValueError, match=r"unknown substitution \{foo\} in protocol_events_location"
    ):
        tn.init(yaml_path)


# ---------------------------------------------------------------------------
# Test 8: path traversal raises ValueError at load time
# ---------------------------------------------------------------------------


def test_path_traversal_rejected(tmp_path):
    yaml_path = _init_jwe(tmp_path)
    tn.flush_and_close()
    _set_pel(yaml_path, "../../etc/passwd")
    with pytest.raises(ValueError, match="resolves outside ceremony directory"):
        tn.init(yaml_path)


# ---------------------------------------------------------------------------
# Test 9: chain continuity across files
# ---------------------------------------------------------------------------


def test_chain_continuity_across_files(tmp_path):
    yaml_path = _init_jwe(tmp_path, protocol_events_location="./.tn/logs/tn.admin.ndjson")
    cfg = tn.current_config()

    tn.info("order.created", amount=1)
    tn.admin.rotate("default")
    cfg = tn.current_config()

    tn.info("order.created", amount=2)
    tn.info("order.created", amount=3)
    tn.admin.rotate("default")
    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()

    # Admin file: two rotation entries with valid chain
    admin_file = tmp_path / ".tn/logs" / "tn.admin.ndjson"
    admin_entries = list(tn.read(admin_file, cfg, verify=True))
    rot_entries = [e for e in admin_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(rot_entries) == 2, f"expected 2 rotation entries, got {len(rot_entries)}"
    assert all(all(e["_valid"].values()) for e in rot_entries), "chain/sig broken in admin file"

    # Main log: three order.created entries with valid chain, zero rotations
    main_entries = list(tn.read(None, cfg, verify=True))
    order_entries = [e for e in main_entries if e["event_type"] == "order.created"]
    assert len(order_entries) == 3, f"expected 3 order.created entries, got {len(order_entries)}"
    assert all(all(e["_valid"].values()) for e in order_entries), "chain broken in main log"
    main_rot = [e for e in main_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(main_rot) == 0, "rotation entries leaked into main log"


# ---------------------------------------------------------------------------
# Test 10: tn.read() excludes protocol events when they're in a separate file
# ---------------------------------------------------------------------------


def test_read_default_excludes_protocol_events_when_split(tmp_path):
    _init_jwe(tmp_path, protocol_events_location="./.tn/logs/tn.admin.ndjson")
    tn.current_config()
    tn.info("order.created", amount=42)
    tn.admin.rotate("default")
    tn.flush_and_close()
    tn.init(tmp_path / "tn.yaml")

    entries = list(tn.read())
    event_types = {e["event_type"] for e in entries}
    assert "tn.rotation.completed" not in event_types
    assert "order.created" in event_types


# ---------------------------------------------------------------------------
# Test 11: tn.read_all() merges main + admin by timestamp
# ---------------------------------------------------------------------------


def test_read_all_merges_by_timestamp(tmp_path):
    _init_jwe(tmp_path, protocol_events_location="./.tn/logs/tn.admin.ndjson")
    tn.current_config()
    tn.info("order.created", amount=1)
    tn.admin.rotate("default")
    tn.info("order.shipped", tracking="T1")
    tn.flush_and_close()
    tn.init(tmp_path / "tn.yaml")

    entries = list(tn.read_all())
    event_types = [e["envelope"]["event_type"] for e in entries]
    assert "order.created" in event_types
    assert "tn.rotation.completed" in event_types
    assert "order.shipped" in event_types

    timestamps = [e["envelope"]["timestamp"] for e in entries]
    assert timestamps == sorted(timestamps), "read_all did not sort by timestamp"


# ---------------------------------------------------------------------------
# Test 12: mid-stream switch between main_log and a separate file
# ---------------------------------------------------------------------------


def test_mid_stream_switch(tmp_path):
    # Start with the legacy `main_log` literal so the first rotation lands
    # in the main log; the body of the test is about the *transition* from
    # main_log to a dedicated file, not about the default.
    yaml_path = _init_jwe(tmp_path, protocol_events_location="main_log")
    cfg = tn.current_config()
    tn.admin.rotate("default")  # rotation #1 → in main log
    tn.flush_and_close()

    # Switch to separate admin file
    _set_pel(yaml_path, "./.tn/logs/tn.admin.ndjson")
    tn.init(yaml_path)
    cfg = tn.current_config()
    tn.admin.rotate("default")  # rotation #2 → in admin file
    tn.flush_and_close()
    tn.init(yaml_path)
    cfg = tn.current_config()

    # Main log has exactly one rotation (the pre-switch one)
    main_entries = list(tn.read(None, cfg))
    main_rot = [e for e in main_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(main_rot) == 1

    # Admin file has exactly one rotation (the post-switch one)
    admin_file = tmp_path / ".tn/logs" / "tn.admin.ndjson"
    admin_entries = list(tn.read(admin_file, cfg))
    admin_rot = [e for e in admin_entries if e["event_type"] == "tn.rotation.completed"]
    assert len(admin_rot) == 1

    # Each reads as a valid independent chain (first entry seen is always valid)
    main_verified = list(tn.read(None, cfg, verify=True))
    main_rot_v = [e for e in main_verified if e["event_type"] == "tn.rotation.completed"]
    admin_verified = list(tn.read(admin_file, cfg, verify=True))
    admin_rot_v = [e for e in admin_verified if e["event_type"] == "tn.rotation.completed"]
    assert all(all(e["_valid"].values()) for e in main_rot_v)
    assert all(all(e["_valid"].values()) for e in admin_rot_v)


# ---------------------------------------------------------------------------
# Tests for the 2026-04-24 admin-log default flip (per docs/.../
# 2026-04-24-tn-admin-log-architecture.md §1).
# ---------------------------------------------------------------------------


def test_fresh_ceremony_writes_recipient_added_to_admin_log_not_main(tmp_path):
    """A fresh ceremony with no PEL override must route ``tn.recipient.added``
    to ``<yaml_dir>/.tn/admin/admin.ndjson``, not the main log."""
    _init_jwe(tmp_path)  # no PEL key — exercises the new default
    cfg = tn.current_config()
    # Add a recipient so the runtime emits tn.recipient.added.
    recipient_pub = _fresh_x25519_pub()
    tn.add_recipient(cfg, "default", "did:key:z6MkAdminLogFlipTestAA", recipient_pub)
    tn.flush_and_close()

    admin_log = tmp_path / ".tn/tn/admin" / "admin.ndjson"
    main_log = tmp_path / ".tn/logs" / "tn.ndjson"

    assert admin_log.exists(), (
        f"expected admin log at {admin_log}; .tn/tn/admin/ contents: "
        f"{list((tmp_path / '.tn/tn/admin').iterdir()) if (tmp_path / '.tn/tn/admin').exists() else 'missing'}"
    )

    import json as _json

    admin_lines = [
        _json.loads(line)
        for line in admin_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    admin_added = [e for e in admin_lines if e.get("event_type") == "tn.recipient.added"]
    assert admin_added, "tn.recipient.added must land in the admin log"

    # Main log: must NOT contain tn.recipient.added.
    main_added = []
    if main_log.exists():
        main_added = [
            _json.loads(line)
            for line in main_log.read_text(encoding="utf-8").splitlines()
            if line.strip() and _json.loads(line).get("event_type") == "tn.recipient.added"
        ]
    assert not main_added, "tn.recipient.added leaked into main log"


def test_legacy_main_log_yaml_still_routes_admin_to_main(tmp_path, recwarn):
    """A yaml that explicitly sets ``protocol_events_location: main_log``
    keeps the legacy behavior (admin events on the main log) and emits
    a ``DeprecationWarning`` on load.
    """
    import warnings

    # The deprecation warning is captured via recwarn; explicitly enable
    # the filter so it isn't swallowed by an upstream filterwarnings rule.
    warnings.simplefilter("always")

    yaml_path = _init_jwe(tmp_path, protocol_events_location="main_log")
    cfg = tn.current_config()

    # Reload to force the load() path that fires the warning.
    tn.flush_and_close()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        tn.init(yaml_path)
        assert any(
            issubclass(w.category, DeprecationWarning)
            and "protocol_events_location" in str(w.message)
            for w in caught
        ), f"expected DeprecationWarning for protocol_events_location, got: {[(w.category.__name__, str(w.message)) for w in caught]}"

    cfg = tn.current_config()
    recipient_pub = _fresh_x25519_pub()
    tn.add_recipient(cfg, "default", "did:key:z6MkLegacyMainLogTestAA", recipient_pub)
    tn.flush_and_close()

    main_log = tmp_path / ".tn/logs" / "tn.ndjson"
    admin_log = tmp_path / ".tn/tn/admin" / "admin.ndjson"

    assert main_log.exists(), "main log must exist when admin events route to it"
    import json as _json

    main_lines = [
        _json.loads(line)
        for line in main_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    main_added = [e for e in main_lines if e.get("event_type") == "tn.recipient.added"]
    assert main_added, "legacy main_log setting must route tn.recipient.added to main log"

    # Admin log either does not exist or, if a previous test in the
    # process left a stale dir, contains no recipient.added envelopes.
    if admin_log.exists():
        admin_lines = [
            _json.loads(line)
            for line in admin_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        leaked = [e for e in admin_lines if e.get("event_type") == "tn.recipient.added"]
        assert not leaked, "main_log override must NOT route admin events to .tn/tn/admin/"
