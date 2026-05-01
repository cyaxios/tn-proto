"""Cross-language byte-compare tests for ``tn.secure_read()`` flat output
and ``tn.agents`` pre-encryption canonical bytes.

Spec: ``docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md``
section 5.4.

Each language commits two fixtures:

    secure_read_canonical.json
        Canonical-JSON dump of the dict shape ``tn.secure_read()`` hands to
        the LLM, for the canonical scenario (one ``order.created`` row
        without policy + one ``payment.completed`` row with policy).

    tn_agents_pre_encryption.json
        The canonical pre-encryption bytes of the ``tn.agents`` group's
        plaintext for ``payment.completed`` — the cipher's input.

This module:

    1. Builds the same two outputs locally from the canonical scenario.
    2. Loads the OTHER two languages' fixtures.
    3. Asserts byte-identity for both.

If a fixture is missing, the cross-consume tests skip rather than fail —
fixtures are built explicitly via each language's builder script.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def _load_builder_module():
    """Load the fixture builder by file path. ``tests/fixtures/`` is not a
    package (no ``__init__.py``), so the relative-import form doesn't work
    for the cross-consume tests in pytest's flat layout.
    """
    builder_path = HERE / "fixtures" / "build_secure_read_fixtures.py"
    spec = importlib.util.spec_from_file_location(
        "tests_fixtures_build_secure_read", builder_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load builder spec from {builder_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_builder = _load_builder_module()

PYDIR = HERE.parent
REPO = PYDIR.parent  # tn-protocol/

PYTHON_FIXTURE_DIR = HERE / "fixtures"
RUST_FIXTURE_DIR = REPO / "crypto" / "tn-core" / "tests" / "fixtures"
TS_FIXTURE_DIR = REPO / "ts-sdk" / "test" / "fixtures"

SECURE_READ_NAME = "secure_read_canonical.json"
PRE_ENC_NAME = "tn_agents_pre_encryption.json"
ADMIN_NAME = "admin_events_canonical.json"


def _canonical_json_bytes(obj: object) -> bytes:
    """Same encoding as the builder writes — sorted keys, compact separators,
    UTF-8, no ASCII escaping."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# --------------------------------------------------------------------------
# Local sanity: building from the same scenario reproduces our committed
# fixture byte-for-byte. Catches drift in the projection function.
# --------------------------------------------------------------------------


def test_python_local_secure_read_matches_committed_fixture():
    local = _canonical_json_bytes(_builder.build_secure_read_canonical())
    on_disk = (PYTHON_FIXTURE_DIR / SECURE_READ_NAME).read_bytes()
    assert local == on_disk, (
        "Python's local secure_read output drifted from the committed fixture. "
        "Re-run tests/fixtures/build_secure_read_fixtures.py."
    )


def test_python_local_pre_encryption_matches_committed_fixture():
    local = _canonical_json_bytes(_builder.build_tn_agents_pre_encryption())
    on_disk = (PYTHON_FIXTURE_DIR / PRE_ENC_NAME).read_bytes()
    assert local == on_disk, (
        "Python's local tn.agents pre-encryption output drifted from the "
        "committed fixture. Re-run tests/fixtures/build_secure_read_fixtures.py."
    )


# --------------------------------------------------------------------------
# Cross-language byte-compare: load the Rust + TS fixtures and assert
# byte-identity against the Python-produced output.
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    not (RUST_FIXTURE_DIR / SECURE_READ_NAME).exists(),
    reason=(
        f"Rust fixture not built: {RUST_FIXTURE_DIR / SECURE_READ_NAME} "
        "(run `cargo test -p tn-core --features fs --test secure_read_fixture_builder -- --ignored`)"
    ),
)
def test_rust_secure_read_byte_compare():
    py = _canonical_json_bytes(_builder.build_secure_read_canonical())
    rust = (RUST_FIXTURE_DIR / SECURE_READ_NAME).read_bytes()
    assert py == rust, (
        "Rust-produced secure_read fixture differs from Python output. "
        "This is a cross-language wire drift; identify and fix the divergence."
    )


@pytest.mark.skipif(
    not (TS_FIXTURE_DIR / SECURE_READ_NAME).exists(),
    reason=(
        f"TS fixture not built: {TS_FIXTURE_DIR / SECURE_READ_NAME} "
        "(run `node --import tsx test/fixtures/build_secure_read_fixtures.ts`)"
    ),
)
def test_ts_secure_read_byte_compare():
    py = _canonical_json_bytes(_builder.build_secure_read_canonical())
    ts = (TS_FIXTURE_DIR / SECURE_READ_NAME).read_bytes()
    assert py == ts, (
        "TS-produced secure_read fixture differs from Python output. "
        "This is a cross-language wire drift; identify and fix the divergence."
    )


@pytest.mark.skipif(
    not (RUST_FIXTURE_DIR / PRE_ENC_NAME).exists(),
    reason=f"Rust fixture not built: {RUST_FIXTURE_DIR / PRE_ENC_NAME}",
)
def test_rust_tn_agents_pre_encryption_byte_compare():
    py = _canonical_json_bytes(_builder.build_tn_agents_pre_encryption())
    rust = (RUST_FIXTURE_DIR / PRE_ENC_NAME).read_bytes()
    assert py == rust, (
        "Rust-produced tn.agents pre-encryption fixture differs from Python "
        "output. This is a cross-language wire drift; identify and fix the "
        "divergence."
    )


@pytest.mark.skipif(
    not (TS_FIXTURE_DIR / PRE_ENC_NAME).exists(),
    reason=f"TS fixture not built: {TS_FIXTURE_DIR / PRE_ENC_NAME}",
)
def test_ts_tn_agents_pre_encryption_byte_compare():
    py = _canonical_json_bytes(_builder.build_tn_agents_pre_encryption())
    ts = (TS_FIXTURE_DIR / PRE_ENC_NAME).read_bytes()
    assert py == ts, (
        "TS-produced tn.agents pre-encryption fixture differs from Python "
        "output. This is a cross-language wire drift; identify and fix the "
        "divergence."
    )


# --------------------------------------------------------------------------
# Per-admin-event canonical-bytes byte-compare. One entry per admin
# event_type in the catalog. Pins the canonical encoding for every admin
# event shape across Python / Rust / TS — would have caught the
# 2026-04-25 e2e canonicalization-drift report on `tn.agents.policy_published`
# (list-valued + multiline string fields) before it shipped.
# --------------------------------------------------------------------------


def test_python_local_admin_events_matches_committed_fixture():
    local = _canonical_json_bytes(_builder.build_admin_events_canonical())
    on_disk = (PYTHON_FIXTURE_DIR / ADMIN_NAME).read_bytes()
    assert local == on_disk, (
        "Python's local admin_events canonical output drifted from the "
        "committed fixture. Re-run tests/fixtures/build_secure_read_fixtures.py."
    )


@pytest.mark.skipif(
    not (RUST_FIXTURE_DIR / ADMIN_NAME).exists(),
    reason=f"Rust fixture not built: {RUST_FIXTURE_DIR / ADMIN_NAME}",
)
def test_rust_admin_events_byte_compare():
    py = _canonical_json_bytes(_builder.build_admin_events_canonical())
    rust = (RUST_FIXTURE_DIR / ADMIN_NAME).read_bytes()
    assert py == rust, (
        "Rust-produced admin_events canonical fixture differs from Python "
        "output. One of the catalog event types canonicalizes differently "
        "between the two SDKs — diff the fixtures field by field to find "
        "which event_type drifted."
    )


@pytest.mark.skipif(
    not (TS_FIXTURE_DIR / ADMIN_NAME).exists(),
    reason=f"TS fixture not built: {TS_FIXTURE_DIR / ADMIN_NAME}",
)
def test_ts_admin_events_byte_compare():
    py = _canonical_json_bytes(_builder.build_admin_events_canonical())
    ts = (TS_FIXTURE_DIR / ADMIN_NAME).read_bytes()
    assert py == ts, (
        "TS-produced admin_events canonical fixture differs from Python "
        "output. One of the catalog event types canonicalizes differently "
        "between the two SDKs — diff the fixtures field by field to find "
        "which event_type drifted."
    )
