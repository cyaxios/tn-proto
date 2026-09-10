"""compile_enrolment emits tn.enrolment.compiled; absorb emits tn.enrolment.absorbed."""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import admin
from tn.absorb import absorb
from tn.compile import compile_enrolment, emit_to_outbox
from tn.config import LoadedConfig, load_or_create
from tn.conventions import outbox_dir
from tn.enrollment import EnrollmentStore
from tn.offer import _ensure_mykey, offer
from tn.trust import AcceptedOffer


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


# add_recipient no longer auto-emits an enrolment (its internal call to the old
# 3-arg compile_enrolment is dead), and compile_enrolment now requires a
# durably reconciled AcceptedOffer obtained through the real trusted-offer
# ceremony (a hand-built one is rejected with TrustReason.UNTRUSTED_PRINCIPAL).
# These helpers drive that ceremony end to end so the tests can compile a real
# enrolment against a real reader, mirroring
# tests/test_jwe_trusted_enrollment_e2e.py.
def _only_outbox_artifact(cfg: LoadedConfig) -> Path:
    artifacts = list(outbox_dir(cfg.yaml_path).glob("*.tnpkg"))
    assert len(artifacts) == 1
    return artifacts[0]


def _accepted_flow(
    publisher: LoadedConfig, reader: LoadedConfig, group: str = "default"
) -> AcceptedOffer:
    store = EnrollmentStore(publisher, publisher.device)
    store.preauthorize(reader.device.did, group)
    challenge = store.issue_challenge(reader.device.did, group, timedelta(minutes=10))
    offer(reader, publisher.device.did, challenge=challenge, group=group)
    receipt = absorb(publisher, _only_outbox_artifact(reader))
    assert receipt.offer_digest is not None
    now = datetime.now(timezone.utc)
    return store.reconcile(store.pending_offer(receipt.offer_digest, now=now), now=now)


def _enrolments_from_admin_log(yaml_path, *, event_type="tn.enrolment.compiled"):
    """Load raw enrolment envelopes from the dedicated admin log.

    Admin events route to the dedicated per-stream admin log
    (``.tn/tn/admin/default.ndjson`` for an explicit-yaml mint).
    ``tn.admin.state()['enrolments']`` is the higher-level reducer view,
    but tests that inspect raw event envelopes (e.g. to verify catalog
    field presence) read the file directly.
    """
    import json as _json

    admin_log = yaml_path.parent / ".tn/tn/admin" / "default.ndjson"
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
    # The peer is a real DeviceKey-backed reader who enrolls through the real
    # trusted-offer ceremony; add_recipient wires the reader's key into the
    # cipher and compile_enrolment (run with the publisher runtime live) emits
    # the attestation.
    reader_cfg = load_or_create(
        tmp_path / "reader" / "tn.yaml", cipher=_workflow_cipher("jwe")
    )
    peer_did = reader_cfg.device.device_identity
    peer_pub = _ensure_mykey(reader_cfg, "default")

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("jwe"))

    cfg = tn.current_config()
    accepted = _accepted_flow(cfg, reader_cfg)
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, peer_pub)
    compile_enrolment(cfg, "default", peer_did, accepted_offer=accepted)
    tn.flush_and_close()

    tn.init(yaml)
    state = tn.admin.state()
    matches = [r for r in state["enrolments"] if r.get("peer_identity") == peer_did]
    assert len(matches) >= 1, (
        f"expected at least 1 enrolment for {peer_did!r}, got {state['enrolments']}"
    )
    r = matches[0]
    assert r["group"] == "default", f"group mismatch: {r['group']!r}"
    assert r["peer_identity"] == peer_did, f"peer_did mismatch: {r['peer_did']!r}"
    assert r["package_sha256"].startswith("sha256:"), (
        f"package_sha256 should start with 'sha256:': {r['package_sha256']!r}"
    )
    assert r["compiled_at"], "compiled_at must be a non-empty ISO 8601 string"


def test_compile_enrolment_all_catalog_fields_present(tmp_path):
    """All 4 required catalog fields must appear in the emitted event."""
    reader_cfg = load_or_create(
        tmp_path / "reader" / "tn.yaml", cipher=_workflow_cipher("jwe")
    )
    peer_did = reader_cfg.device.device_identity
    peer_pub = _ensure_mykey(reader_cfg, "default")

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("jwe"))

    cfg = tn.current_config()
    accepted = _accepted_flow(cfg, reader_cfg)
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, peer_pub)
    compile_enrolment(cfg, "default", peer_did, accepted_offer=accepted)
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
    for field in ("group", "peer_identity", "package_sha256", "compiled_at"):
        assert field in flat, (
            f"required field {field!r} missing from tn.enrolment.compiled: {sorted(flat)}"
        )


def test_compile_enrolment_direct_call_emits_event(tmp_path):
    """Calling compile_enrolment directly while tn is init'd emits the event."""
    reader_cfg = load_or_create(
        tmp_path / "reader" / "tn.yaml", cipher=_workflow_cipher("jwe")
    )
    peer_did = reader_cfg.device.device_identity
    peer_pub = _ensure_mykey(reader_cfg, "default")

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("jwe"))

    cfg = tn.current_config()
    accepted = _accepted_flow(cfg, reader_cfg)
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, peer_pub)
    # A direct compile against the reconciled offer emits tn.enrolment.compiled.
    pkg = compile_enrolment(cfg, "default", peer_did, accepted_offer=accepted)
    assert pkg is not None
    tn.flush_and_close()

    tn.init(yaml)
    state = tn.admin.state()
    matches = [r for r in state["enrolments"] if r.get("peer_identity") == peer_did]
    # Reducer dedupes per (group, peer_did) so only one entry; the on-disk log
    # holds the compile event. Verify both: the reduced state and the raw
    # envelopes.
    assert len(matches) >= 1, (
        f"expected >=1 enrolment for to_did={peer_did!r}, got {state['enrolments']}"
    )
    raw_envs = [
        e for e in _enrolments_from_admin_log(yaml) if e.get("peer_identity") == peer_did
    ]
    assert len(raw_envs) >= 1, (
        f"expected >=1 tn.enrolment.compiled envelope for {peer_did!r}, got {raw_envs}"
    )


def test_compile_enrolment_no_emit_without_runtime(tmp_path):
    """compile_enrolment must not raise if called without tn.init() (no runtime)."""
    cfg = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher=_workflow_cipher("jwe"))
    reader_cfg = load_or_create(
        tmp_path / "reader" / "tn.yaml", cipher=_workflow_cipher("jwe")
    )
    peer_did = reader_cfg.device.device_identity
    peer_pub = _ensure_mykey(reader_cfg, "default")
    accepted = _accepted_flow(cfg, reader_cfg)
    admin._add_recipient_jwe_impl(cfg, "default", peer_did, peer_pub)
    # tn is not init'd — _runtime is None; compile should succeed silently.
    pkg = compile_enrolment(cfg, "default", peer_did, accepted_offer=accepted)
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
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    alice_did = alice_cfg.device.device_identity

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    bob_pub = _ensure_mykey(bob_cfg, "default")

    # Bob enrolls through the real trusted-offer ceremony; his retained
    # outbound offer is what makes the enrolment response absorb cleanly.
    accepted = _accepted_flow(alice_cfg, bob_cfg)
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.device_identity, bob_pub)
    pkg = compile_enrolment(
        alice_cfg, "default", bob_cfg.device.device_identity, accepted_offer=accepted
    )
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    # Bob: init TN against his workspace so _runtime is live, then absorb.
    tn.init(str(bob_cfg.yaml_path))
    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", (
        f"absorb must succeed before the event can be checked; reason: {result.reason}"
    )
    tn.flush_and_close()

    # Read Bob's admin log directly and look for tn.enrolment.absorbed.
    # (Post-2026-04-24, admin events route to .tn/tn/admin/default.ndjson by
    # default rather than the main log.)
    tn.init(str(bob_cfg.yaml_path))
    events = _enrolments_from_admin_log(
        bob_cfg.yaml_path, event_type="tn.enrolment.absorbed"
    )
    tn.flush_and_close()

    # BLOCKED (design decision): the modern trusted enrolment absorb path
    # (absorb._absorb_enrolment_kind -> enrollment.install_enrollment_response)
    # does NOT emit tn.enrolment.absorbed — enrollment.py has no emit at all, and
    # the only surviving emitter is the legacy absorb._apply_enrolment branch,
    # unreachable once a package carries an enrollment_response (compile_enrolment
    # always attaches one). The setup below is fully migrated to the real
    # trusted-offer ceremony and the absorb SUCCEEDS (see the enrolment_applied
    # assertion above); only this event-emission assertion cannot hold until the
    # response-install path re-emits the attestation. Not editing source to add
    # that emit; left red and reported rather than hacked green.
    assert events, "tn.enrolment.absorbed must appear in Bob's admin log after absorb"
    e = events[0]

    # All 4 catalog fields must be present and non-empty.
    assert e["group"] == "default", f"group mismatch: {e['group']!r}"
    assert e["publisher_identity"] == alice_did, (
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
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    bob_pub = _ensure_mykey(bob_cfg, "default")

    accepted = _accepted_flow(alice_cfg, bob_cfg)
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.device_identity, bob_pub)
    pkg = compile_enrolment(
        alice_cfg, "default", bob_cfg.device.device_identity, accepted_offer=accepted
    )
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    # tn is NOT init'd for bob — _runtime is None; absorb must succeed silently.
    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", (
        f"absorb must succeed even without a runtime; reason: {result.reason}"
    )
