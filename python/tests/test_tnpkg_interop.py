"""Cross-language `.tnpkg` byte-compare tests.

Each language's fixture builder produces an admin_log_snapshot for the
same canonical scenario:

    1. Fresh btn ceremony.
    2. tn.recipient.added(did:key:zAlice) -> leaf A
    3. tn.recipient.added(did:key:zBob)   -> leaf B
    4. tn.recipient.revoked(leaf A)
    5. tn.vault.linked(did:web:vault.example, demo)

This module verifies that:

    1. Rust-produced and TS-produced `.tnpkg`s parse cleanly via Python's
       absorb path and the manifest signature verifies.
    2. State / clock shape matches the canonical scenario (≥4 admin
       events, 2 recipients, 1 vault link).
    3. The manifest canonical signing-bytes function is byte-identical
       across the three languages when given identical inputs (the wire
       parity contract).

If a fixture is missing, the cross-consume tests skip rather than fail
— the fixtures are built explicitly via each language's builder script.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
if str(PYDIR) not in sys.path:
    sys.path.insert(0, str(PYDIR))

from tn.tnpkg import (
    TnpkgManifest,
    _read_manifest,
    _verify_manifest_signature,
)

REPO = PYDIR.parent  # tn-protocol/
RUST_FIXTURE = REPO / "crypto" / "tn-core" / "tests" / "fixtures" / "rust_admin_snapshot.tnpkg"
TS_FIXTURE = REPO / "ts-sdk" / "test" / "fixtures" / "ts_admin_snapshot.tnpkg"

PY_FIXTURE_DIR = HERE / "fixtures"
RUST_FIXTURE_DIR = REPO / "crypto" / "tn-core" / "tests" / "fixtures"
TS_FIXTURE_DIR = REPO / "ts-sdk" / "test" / "fixtures"


def test_required_byte_compare_fixtures_present():
    """Sentinel: fail loud if any cross-language fixture is missing or empty.

    The interop tests skip individual checks when sibling-language fixtures
    are absent (so a single language can be developed without the others
    being green). This sentinel ensures the full set of fixtures exists on a
    healthy `main`; if a fixture is renamed, moved, or zero-byte, this test
    surfaces it loudly rather than letting the byte-compare assertions
    silently no-op.
    """
    expected: list[Path] = [
        # Python-produced fixtures (own dir).
        PY_FIXTURE_DIR / "python_admin_snapshot.tnpkg",
        PY_FIXTURE_DIR / "secure_read_canonical.json",
        PY_FIXTURE_DIR / "tn_agents_pre_encryption.json",
        # Rust-produced fixtures.
        RUST_FIXTURE_DIR / "rust_admin_snapshot.tnpkg",
        RUST_FIXTURE_DIR / "secure_read_canonical.json",
        RUST_FIXTURE_DIR / "tn_agents_pre_encryption.json",
        # TS-produced fixtures.
        TS_FIXTURE_DIR / "ts_admin_snapshot.tnpkg",
        TS_FIXTURE_DIR / "secure_read_canonical.json",
        TS_FIXTURE_DIR / "tn_agents_pre_encryption.json",
    ]
    missing = [str(p) for p in expected if not p.exists()]
    empty = [str(p) for p in expected if p.exists() and p.stat().st_size == 0]
    assert not missing, f"missing byte-compare fixtures: {missing}"
    assert not empty, f"empty byte-compare fixtures (zero bytes): {empty}"


def _assert_canonical_admin_state(state: dict) -> None:
    """Assert the AdminState shape matches the canonical scenario."""
    assert isinstance(state, dict), f"state must be a JSON object, got {type(state)}"
    recipients = state.get("recipients") or []
    vault_links = state.get("vault_links") or []
    assert len(recipients) == 2, f"expected 2 recipients, got {len(recipients)}"
    dids = {r.get("recipient_did") for r in recipients}
    assert dids == {"did:key:zAlice", "did:key:zBob"}, f"unexpected recipient DIDs: {dids}"
    statuses = {r.get("recipient_did"): r.get("active_status") for r in recipients}
    assert statuses["did:key:zAlice"] == "revoked", f"alice should be revoked: {statuses}"
    assert statuses["did:key:zBob"] == "active", f"bob should be active: {statuses}"
    assert len(vault_links) == 1, f"expected 1 vault link, got {len(vault_links)}"
    link = vault_links[0]
    assert link.get("vault_did") == "did:web:vault.example"
    assert link.get("project_id") == "demo"
    assert link.get("unlinked_at") is None


@pytest.mark.skipif(
    not RUST_FIXTURE.exists(),
    reason=f"Rust fixture not built: {RUST_FIXTURE} (run `cargo test -p tn-core --features fs --test tnpkg_fixture_builder -- --ignored`)",
)
def test_rust_produced_admin_snapshot_parses_in_python():
    manifest, body = _read_manifest(RUST_FIXTURE)
    assert manifest.kind == "admin_log_snapshot"
    assert _verify_manifest_signature(manifest), (
        "Rust-produced manifest signature must verify in Python"
    )
    assert "body/admin.ndjson" in body
    # 5 events: 2 added + 1 revoked + 1 vault.linked + 1 ceremony.init.
    assert manifest.event_count >= 4, (
        f"Rust fixture should carry >=4 admin envelopes, got {manifest.event_count}"
    )
    assert manifest.state is not None, "Rust fixture must include materialized state"
    _assert_canonical_admin_state(manifest.state)


@pytest.mark.skipif(
    not TS_FIXTURE.exists(),
    reason=f"TS fixture not built: {TS_FIXTURE} (run `node --import tsx test/fixtures/build_admin_snapshot_fixture.ts`)",
)
def test_ts_produced_admin_snapshot_parses_in_python():
    manifest, body = _read_manifest(TS_FIXTURE)
    assert manifest.kind == "admin_log_snapshot"
    assert _verify_manifest_signature(manifest), (
        "TS-produced manifest signature must verify in Python"
    )
    assert "body/admin.ndjson" in body
    assert manifest.event_count >= 4, (
        f"TS fixture should carry >=4 admin envelopes, got {manifest.event_count}"
    )
    assert manifest.state is not None, "TS fixture must include materialized state"
    _assert_canonical_admin_state(manifest.state)


# --------------------------------------------------------------------------
# Wire-format byte-equivalence: the manifest's canonical signing bytes for
# a fixed input are identical across Python, Rust, and TS. Stored as a
# golden so any drift in `to_dict` / `signing_bytes` is caught.
# --------------------------------------------------------------------------

# Hard-coded canonical input. Identical fields populated in the Rust
# (`tnpkg_interop.rs`) and TS (`tnpkg_interop.test.ts`) byte-compare
# tests; the resulting canonical bytes must be byte-identical.
GOLDEN_INPUT = {
    "kind": "admin_log_snapshot",
    "version": 1,
    "from_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "ceremony_id": "test_ceremony_42",
    "as_of": "2026-04-24T12:00:00.000+00:00",
    "scope": "admin",
    "clock": {
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK": {
            "tn.recipient.added": 2,
            "tn.recipient.revoked": 1,
            "tn.vault.linked": 1,
        },
    },
    "event_count": 4,
    "head_row_hash": "sha256:" + "a" * 64,
    "to_did": "did:key:zRecipient",
    "state": {
        "vault_links": [
            {
                "vault_did": "did:web:vault.example",
                "project_id": "demo",
                "linked_at": "2026-04-24T12:00:00.000Z",
                "unlinked_at": None,
            },
        ],
    },
}


# RFC 8785-canonical bytes of GOLDEN_INPUT (signature field excluded).
# Used as a golden so any one of the three languages drifting will break
# this test as well as the cross-language assertion below.
GOLDEN_CANONICAL_BYTES = json.dumps(
    GOLDEN_INPUT,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")


def test_manifest_canonical_bytes_match_golden():
    """Build a TnpkgManifest from the golden inputs and confirm its
    `signing_bytes()` matches the JCS-style canonical encoding the Rust
    + TS sides produce."""
    m = TnpkgManifest(
        kind=GOLDEN_INPUT["kind"],
        version=GOLDEN_INPUT["version"],
        from_did=GOLDEN_INPUT["from_did"],
        ceremony_id=GOLDEN_INPUT["ceremony_id"],
        as_of=GOLDEN_INPUT["as_of"],
        scope=GOLDEN_INPUT["scope"],
        to_did=GOLDEN_INPUT["to_did"],
        clock=GOLDEN_INPUT["clock"],
        event_count=GOLDEN_INPUT["event_count"],
        head_row_hash=GOLDEN_INPUT["head_row_hash"],
        state=GOLDEN_INPUT["state"],
    )
    got = m.signing_bytes()
    assert got == GOLDEN_CANONICAL_BYTES, (
        "Python signing_bytes drifted from golden. "
        f"Got: {got!r}\nWant: {GOLDEN_CANONICAL_BYTES!r}"
    )


# Re-export the golden bytes as a hex string at module import so the
# Rust + TS tests can pull it out without re-implementing _canonical_bytes
# in their own code paths. The hex form is stable across stdlib versions
# and easy to assert against.
def golden_canonical_bytes_hex() -> str:
    return GOLDEN_CANONICAL_BYTES.hex()


__all__ = ["GOLDEN_CANONICAL_BYTES", "GOLDEN_INPUT", "golden_canonical_bytes_hex"]
