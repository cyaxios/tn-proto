"""tn.scope_to(*dids).spawn() — per-DID scoped capability handle (Python).

Mirror of ts-sdk/test/scope_to_spawn.test.ts. The seeded ceremony is the
project publisher and holds ciphers for every group. ``tn.scope_to(did)
.spawn()`` returns a read-only handle that opens ONLY the groups where one
of the scoped DIDs is a listed recipient, leaving every other group
sealed — the mesh primitive over a handed-in tn stream.
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

from pathlib import Path

import pytest
import yaml

import tn
from tn import admin
from tn import config as tn_config
from tn.signing import DeviceKey


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


# A publisher ceremony with two private btn groups whose recipient lists
# differ:
#   - `shared`: recipients = [publisher, reader_did]   fields = [note]
#   - `secret`: recipients = [publisher, tier_did]     fields = [ssn]
# The publisher holds kits for both (btn broadcast), so the scoping is a
# capability FILTER over the declared recipients, not a missing-key
# accident.
def _make_scope_ceremony(tmp_path: Path, reader_did: str, tier_did: str) -> Path:
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=_workflow_cipher("btn"))
    tn.flush_and_close()

    cfg = tn_config.load(yaml_path)
    admin.ensure_group(cfg, "shared", cipher=_workflow_cipher("btn"), fields=["note"])
    admin.ensure_group(cfg, "secret", cipher=_workflow_cipher("btn"), fields=["ssn"])
    tn.flush_and_close()

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    publisher = doc["device"]["device_identity"]
    doc["groups"]["shared"]["recipients"] = [
        {"recipient_identity": publisher},
        {"recipient_identity": reader_did},
    ]
    doc["groups"]["secret"]["recipients"] = [
        {"recipient_identity": publisher},
        {"recipient_identity": tier_did},
    ]
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return yaml_path


def _log_message(yaml_path: Path) -> str:
    return (yaml_path.parent / ".tn/tn/logs" / "tn.ndjson").read_text(encoding="utf-8")


def test_scope_to_opens_only_recipient_groups(tmp_path):
    reader = DeviceKey.generate().device_identity
    tier = DeviceKey.generate().device_identity
    yaml_path = _make_scope_ceremony(tmp_path, reader, tier)

    tn.init(yaml_path)
    tn.log("user.action", note="hello", ssn="123-45-6789")
    message = _log_message(yaml_path)

    entries = [
        e for e in tn.scope_to(reader).spawn().read(message) if e.event_type == "user.action"
    ]
    tn.flush_and_close()

    assert len(entries) == 1
    e = entries[0]
    # `shared` lists the reader → note is visible.
    assert e.fields.get("note") == "hello"
    # `secret` does not list the reader → ssn stays sealed.
    assert "ssn" not in e.fields
    assert "secret" in e.hidden_groups


def test_scope_to_unions_capabilities(tmp_path):
    reader = DeviceKey.generate().device_identity
    tier = DeviceKey.generate().device_identity
    yaml_path = _make_scope_ceremony(tmp_path, reader, tier)

    tn.init(yaml_path)
    tn.log("user.action", note="hello", ssn="123-45-6789")
    message = _log_message(yaml_path)

    # The mesh shape: "that user's did plus its own did" → both groups.
    entries = [
        e
        for e in tn.scope_to(reader, tier).spawn().read(message)
        if e.event_type == "user.action"
    ]
    tn.flush_and_close()

    assert len(entries) == 1
    e = entries[0]
    assert e.fields.get("note") == "hello"
    assert e.fields.get("ssn") == "123-45-6789"
    # Both targeted groups opened. (`default` carries unrouted private
    # fields like run_id and lists only the publisher, so it stays sealed.)
    assert "shared" not in e.hidden_groups
    assert "secret" not in e.hidden_groups


def test_scope_to_stranger_opens_nothing(tmp_path):
    reader = DeviceKey.generate().device_identity
    tier = DeviceKey.generate().device_identity
    stranger = DeviceKey.generate().device_identity
    yaml_path = _make_scope_ceremony(tmp_path, reader, tier)

    tn.init(yaml_path)
    tn.log("user.action", note="hello", ssn="123-45-6789")
    message = _log_message(yaml_path)

    scoped = tn.scope_to(stranger).spawn()
    assert scoped.groups == []

    entries = [e for e in scoped.read(message) if e.event_type == "user.action"]
    tn.flush_and_close()

    assert len(entries) == 1
    e = entries[0]
    assert "note" not in e.fields and "ssn" not in e.fields
    assert "shared" in e.hidden_groups and "secret" in e.hidden_groups


def test_scope_to_read_accepts_bytes(tmp_path):
    reader = DeviceKey.generate().device_identity
    tier = DeviceKey.generate().device_identity
    yaml_path = _make_scope_ceremony(tmp_path, reader, tier)

    tn.init(yaml_path)
    tn.log("user.action", note="hello", ssn="123-45-6789")
    # Hand over the raw bytes a Worker / mesh would have received.
    message_bytes = (yaml_path.parent / ".tn/tn/logs" / "tn.ndjson").read_bytes()

    entries = [
        e
        for e in tn.scope_to(reader).spawn().read(message_bytes)
        if e.event_type == "user.action"
    ]
    tn.flush_and_close()

    assert len(entries) == 1
    assert entries[0].fields.get("note") == "hello"
