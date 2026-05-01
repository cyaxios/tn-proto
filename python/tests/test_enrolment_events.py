"""compile_enrolment emits tn.enrolment.compiled; absorb emits tn.enrolment.absorbed."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import admin
from tn.absorb import absorb
from tn.compile import compile_enrolment, emit_to_outbox
from tn.config import load_or_create
from tn.offer import _ensure_mykey


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _enrolments_from_admin_log(yaml_path, *, event_type="tn.enrolment.compiled"):
    """Load raw enrolment envelopes from the dedicated admin log.

    Post-2026-04-24 admin events route to ``<yaml_dir>/.tn/admin/admin.ndjson``
    by default. ``tn.admin.state()['enrolments']`` is the higher-level
    reducer view, but tests that inspect raw event envelopes (e.g. to
    verify catalog field presence) read the file directly.
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
            if env.get("event_type") == event_type:
                out.append(env)
    return out


def test_compile_enrolment_emits_event(tmp_path):
    """compile_enrolment emits tn.enrolment.compiled with all catalog fields."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")

    cfg = tn.current_config()
    peer_did = "did:key:zBob"
    # add_recipient (with a pub key) is the normal caller of compile_enrolment;
    # calling compile_enrolment directly is also valid and exercises the emit.
    peer_pub = os.urandom(32)
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, peer_pub)
    tn.flush_and_close()

    tn.init(yaml)
    state = tn.admin.state()
    matches = [r for r in state["enrolments"] if r.get("peer_did") == peer_did]
    assert len(matches) >= 1, (
        f"expected at least 1 enrolment for {peer_did!r}, got {state['enrolments']}"
    )
    r = matches[0]
    assert r["group"] == "default", f"group mismatch: {r['group']!r}"
    assert r["peer_did"] == peer_did, f"peer_did mismatch: {r['peer_did']!r}"
    assert r["package_sha256"].startswith("sha256:"), (
        f"package_sha256 should start with 'sha256:': {r['package_sha256']!r}"
    )
    assert r["compiled_at"], "compiled_at must be a non-empty ISO 8601 string"


def test_compile_enrolment_all_catalog_fields_present(tmp_path):
    """All 4 required catalog fields must appear in the emitted event."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")

    cfg = tn.current_config()
    peer_did = "did:key:zCarol"
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, os.urandom(32))
    tn.flush_and_close()

    tn.init(yaml)
    # Inspect the raw envelope directly so we catch any field renames at
    # the on-disk shape, not just at the reducer projection.
    envs = _enrolments_from_admin_log(yaml)
    assert envs, "expected tn.enrolment.compiled envelope in admin log"
    env = envs[0]
    # JWE encrypts catalog fields into the `default` group payload; for
    # this on-disk inspection we only need the public envelope to carry
    # the required fields. add_recipient stores them publicly so the
    # vault reducer can read without decrypting.
    flat = dict(env)
    for field in ("group", "peer_did", "package_sha256", "compiled_at"):
        assert field in flat, (
            f"required field {field!r} missing from tn.enrolment.compiled: {sorted(flat)}"
        )


def test_compile_enrolment_direct_call_emits_event(tmp_path):
    """Calling compile_enrolment directly while tn is init'd emits the event."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="jwe")

    cfg = tn.current_config()
    peer_did = "did:key:zDave"
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, os.urandom(32))
    # add_recipient already compiled once; call directly for a second compile.
    pkg = compile_enrolment(cfg, "default", peer_did)
    assert pkg is not None
    tn.flush_and_close()

    tn.init(yaml)
    state = tn.admin.state()
    matches = [r for r in state["enrolments"] if r.get("peer_did") == peer_did]
    # Reducer dedupes per (group, peer_did) so only one entry, but the on-disk
    # log holds both compile events. Verify both: the reduced state, and the
    # raw envelopes.
    assert len(matches) >= 1, (
        f"expected >=1 enrolment for peer_did={peer_did!r}, got {state['enrolments']}"
    )
    raw_envs = [
        e for e in _enrolments_from_admin_log(yaml) if e.get("peer_did") == peer_did
    ]
    assert len(raw_envs) >= 1, (
        f"expected >=1 tn.enrolment.compiled envelope for {peer_did!r}, got {raw_envs}"
    )


def test_compile_enrolment_no_emit_without_runtime(tmp_path):
    """compile_enrolment must not raise if called without tn.init() (no runtime)."""
    from tn.config import load_or_create

    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    peer_did = "did:key:zEve"
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, os.urandom(32))
    # tn is not init'd — _runtime is None; compile should succeed silently.
    pkg = compile_enrolment(cfg, "default", peer_did)
    assert pkg is not None, "compile_enrolment should return a Package even without runtime"


def test_absorb_emits_event(tmp_path):
    """absorb() emits tn.enrolment.absorbed with all 4 required catalog fields.

    Setup mirrors test_absorb_enrolment_makes_recipient_read: Bob generates a
    mykey so compile_enrolment can encrypt to him, Alice compiles and emits a
    .tnpkg, Bob absorbs it while tn is initialised against his workspace.
    from_did must be Alice's DID (the compiler/signer), not Bob's.
    package_sha256 must match compile's hash (same _canonical_bytes on the same
    Package fields).
    """
    # Alice: create workspace, set up Bob as a recipient, compile + emit.
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")
    alice_did = alice_cfg.device.did

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    bob_pub = _ensure_mykey(bob_cfg, "default")

    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.did, bob_pub)
    pkg = compile_enrolment(alice_cfg, "default", bob_cfg.device.did)
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    # Bob: init TN against his workspace so _runtime is live, then absorb.
    tn.init(str(bob_cfg.yaml_path))
    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", (
        f"absorb must succeed before the event can be checked; reason: {result.reason}"
    )
    tn.flush_and_close()

    # Read Bob's admin log directly and look for tn.enrolment.absorbed.
    # (Post-2026-04-24, admin events route to .tn/tn/admin/admin.ndjson by
    # default rather than the main log.)
    tn.init(str(bob_cfg.yaml_path))
    events = _enrolments_from_admin_log(
        bob_cfg.yaml_path, event_type="tn.enrolment.absorbed"
    )
    tn.flush_and_close()

    assert events, "tn.enrolment.absorbed must appear in Bob's admin log after absorb"
    e = events[0]

    # All 4 catalog fields must be present and non-empty.
    assert e["group"] == "default", f"group mismatch: {e['group']!r}"
    assert e["from_did"] == alice_did, (
        f"from_did must be the compiler's (Alice's) DID, got {e['from_did']!r}"
    )
    assert e["package_sha256"].startswith("sha256:"), (
        f"package_sha256 must start with 'sha256:': {e['package_sha256']!r}"
    )
    assert e["absorbed_at"], "absorbed_at must be a non-empty ISO 8601 string"


def test_absorb_no_emit_without_runtime(tmp_path):
    """absorb() must not raise if called without tn.init() (no runtime)."""
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    bob_pub = _ensure_mykey(bob_cfg, "default")

    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.did, bob_pub)
    pkg = compile_enrolment(alice_cfg, "default", bob_cfg.device.did)
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    # tn is NOT init'd for bob — _runtime is None; absorb must succeed silently.
    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", (
        f"absorb must succeed even without a runtime; reason: {result.reason}"
    )
