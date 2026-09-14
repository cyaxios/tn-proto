"""HIBE delegation ceremony (Phase 5): authority grants a reader key as a
``.tnpkg``; the reader absorbs it and opens the authority's log.

Also pins the custody rules: the kit carries mpk/idpath/sk but NEVER the
authority master secret, and absorb refuses a ``.hibe.msk`` smuggled into a
non-self-addressed bundle.
"""

from __future__ import annotations

import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader


UTC = timezone.utc


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires) and empty
    request context (set_context would otherwise leak into later tests
    in the same process)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()


def test_hibe_grant_absorb(tmp_path):
    ws = tmp_path

    # Readers create their own real Ed25519 did:key identities first. The
    # authority will issue a scoped challenge and require each reader to prove
    # control before it delivers a bearer HIBE key.
    r_yaml = ws / "reader" / "tn.yaml"
    r_log = ws / "reader" / "log.ndjson"
    tn.init(r_yaml, log_path=r_log)
    r1_cfg = tn.current_config()
    r1_did = r1_cfg.device.device_identity
    tn.flush_and_close()

    r2_yaml = ws / "reader2" / "tn.yaml"
    r2_log = ws / "reader2" / "log.ndjson"
    tn.init(r2_yaml, log_path=r2_log)
    r2_cfg = tn.current_config()
    r2_did = r2_cfg.device.device_identity
    tn.flush_and_close()

    # --- Authority side: hibe ceremony, one sealed entry, one grant.
    a_yaml = ws / "authority" / "tn.yaml"
    a_log = ws / "authority" / "log.ndjson"
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    authority_cfg = tn.current_config()
    tn.set_context(user_id=7)
    tn.info("governed.entry", secret="for-granted-readers-only")
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default", r1_did, cfg=authority_cfg
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=r1_cfg,
    )
    kit_path = ws / "reader.tnpkg"
    res = tn.admin.grant_reader(
        "default",
        reader_did=r1_did,
        out_path=kit_path,
        proof=proof,
    )
    assert res.kit_path == kit_path and kit_path.exists()
    assert not res.unsafe
    assert not res.delegated_subauthority
    tn.flush_and_close()

    # The kit must carry exactly the reader files — never the msk.
    with zipfile.ZipFile(kit_path) as zf:
        names = zf.namelist()
    assert not any(n.endswith(".hibe.msk") for n in names), names
    assert "body/encrypted.bin" in names
    assert not any(n.endswith(".hibe.sk") for n in names), names

    # --- Reader side: own (btn) ceremony, absorb the kit, read the log.
    tn.init(r_yaml, log_path=r_log)
    r_cfg = tn.current_config()
    receipt = tn.absorb(kit_path)
    assert (r_cfg.keystore / "default.hibe.sk").exists(), receipt
    assert (r_cfg.keystore / "default.hibe.mpk").exists(), receipt
    sk1 = (r_cfg.keystore / "default.hibe.sk").read_bytes()

    entries = list(
        tn.reader.read_as_recipient(a_log, r_cfg.keystore, group="default")
    )
    assert len(entries) == 1
    body = entries[0]["plaintext"]["default"]
    assert body.get("secret") == "for-granted-readers-only", body
    tn.flush_and_close()

    # --- Independent second grant: different key bytes, same access.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    authority_cfg = tn.current_config()
    challenge2 = tn.admin.issue_hibe_reader_challenge(
        "default", r2_did, cfg=authority_cfg
    )
    proof2 = tn.admin.create_hibe_reader_proof(
        challenge2,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=r2_cfg,
    )
    kit2 = ws / "reader2.tnpkg"
    # The cipher-agnostic admin surface forwards the same authenticated HIBE
    # proof and preserves the sealed-delivery result.
    add_result = tn.admin.add_recipient(
        "default",
        recipient_did=r2_did,
        out_path=kit2,
        proof=proof2,
    )
    assert add_result.kit_path == kit2
    assert not add_result.unsafe
    tn.flush_and_close()

    tn.init(r2_yaml, log_path=r2_log)
    reader2_cfg = tn.current_config()
    tn.absorb(kit2)
    sk2 = (reader2_cfg.keystore / "default.hibe.sk").read_bytes()
    tn.flush_and_close()
    assert sk1 != sk2, "each grant must mint independently randomized key material"


def test_hibe_grant_fails_closed_without_real_did_and_scoped_proof(tmp_path: Path) -> None:
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    cfg = tn.current_config()

    with pytest.raises(ValueError):
        tn.admin.grant_reader(
            "default",
            reader_did=None,
            out_path=tmp_path / "missing-did.tnpkg",
            cfg=cfg,
        )
    with pytest.raises(ValueError):
        tn.admin.grant_reader(
            "default",
            reader_did="did:key:z6Mk-abbreviated",
            out_path=tmp_path / "abbreviated-did.tnpkg",
            cfg=cfg,
        )


def test_hibe_unsafe_plaintext_is_explicit_warned_audited_and_marked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tn.security_audit import TnSecurityWarning
    from tn.tnpkg import _read_manifest

    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    cfg = tn.current_config()
    reader_did = cfg.device.device_identity
    events: list[tuple[str, dict[str, object]]] = []

    def capture(event_type: str, **fields: object) -> None:
        events.append((event_type, dict(fields)))

    monkeypatch.setattr(tn, "info", capture)
    kit = tmp_path / "unsafe.tnpkg"
    with pytest.warns(TnSecurityWarning):
        result = tn.admin.grant_reader(
            "default",
            reader_did=reader_did,
            out_path=kit,
            cfg=cfg,
            unsafe_plaintext=True,
        )

    manifest, body = _read_manifest(kit, verify_signature=True)
    assert result.unsafe is True
    assert result.delegated_subauthority is False
    assert "body/default.hibe.sk" in body
    assert (manifest.state or {})["hibe_grant"] == {
        "delivery": "unsafe-plaintext-bearer",
        "delegated_subauthority": False,
        "id_path": "self",
        "unsafe": True,
    }
    assert events == [
        (
            "tn.security.unsafe_operation",
            {
                "artifact_digest": None,
                "group": "default",
                "operation": "hibe_grant",
                "relaxations": ["plaintext_bearer_delivery"],
                "subject_did": reader_did,
            },
        )
    ]


@pytest.mark.parametrize("reader_did", [None, "did:key:z6Mk-abbreviated"])
def test_hibe_unsafe_plaintext_still_requires_complete_real_reader_did(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reader_did: str | None,
) -> None:
    import warnings

    from tn.trust import TrustError, TrustReason

    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    cfg = tn.current_config()
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        tn,
        "info",
        lambda event_type, **fields: events.append((event_type, dict(fields))),
    )
    kit = tmp_path / "must-not-exist.tnpkg"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(TrustError) as raised:
            tn.admin.grant_reader(
                "default",
                reader_did=reader_did,
                out_path=kit,
                cfg=cfg,
                unsafe_plaintext=True,
            )

    assert raised.value.reason is TrustReason.DID_INVALID
    assert caught == []
    assert events == []
    assert not kit.exists()


def test_hibe_ancestor_grant_requires_opt_in_and_records_delegation(tmp_path: Path) -> None:
    from tn.tnpkg import _read_manifest

    reader_yaml = tmp_path / "reader" / "tn.yaml"
    tn.init(reader_yaml)
    reader_cfg = tn.current_config()
    tn.flush_and_close()

    authority_yaml = tmp_path / "authority" / "tn.yaml"
    tn.init(authority_yaml, cipher="hibe")
    authority_cfg = tn.current_config()
    authority_cfg.groups["default"].cipher.rotate_id_path("org/fraud")
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default", reader_cfg.device.device_identity, cfg=authority_cfg
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )

    with pytest.raises(ValueError, match="allow_subauthority"):
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            id_path="org",
            out_path=tmp_path / "must-not-exist.tnpkg",
            proof=proof,
            cfg=authority_cfg,
        )

    kit = tmp_path / "subauthority.tnpkg"
    result = tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        id_path="org",
        out_path=kit,
        proof=proof,
        allow_subauthority=True,
        cfg=authority_cfg,
    )
    manifest, _ = _read_manifest(kit, verify_signature=True)
    assert result.delegated_subauthority is True
    assert (manifest.state or {})["hibe_grant"] == {
        "delivery": "recipient-seal-v1",
        "delegated_subauthority": True,
        "id_path": "org",
        "unsafe": False,
    }

    tn.flush_and_close()
    tn.init(reader_yaml)
    installed = tn.current_config()
    tn.absorb(kit)
    assert tn._hibe.key_id_path(
        (installed.keystore / "default.hibe.sk").read_bytes()
    ) == "org"


def test_caller_constructed_verified_principal_is_not_trusted_without_local_record(
    tmp_path: Path,
) -> None:
    from tn.trust import TrustError, TrustReason, VerifiedPrincipal

    tn.init(tmp_path / "reader" / "tn.yaml")
    reader_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    authority_cfg = tn.current_config()
    now = datetime.now(UTC)
    forged = VerifiedPrincipal(
        did=reader_cfg.device.device_identity,
        purpose="hibe-reader",
        audience_did=authority_cfg.device.device_identity,
        ceremony_id=authority_cfg.ceremony_id,
        group="default",
        proof_digest="sha256:" + "00" * 32,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(TrustError) as raised:
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            out_path=tmp_path / "forged.tnpkg",
            proof=forged,
            cfg=authority_cfg,
        )
    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL


def test_hibe_grant_rejects_expired_and_mismatched_reader_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.admin as admin_mod
    from tn.trust import TrustError, TrustReason

    tn.init(tmp_path / "reader" / "tn.yaml")
    reader_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "other-reader" / "tn.yaml")
    other_reader_did = tn.current_config().device.device_identity
    tn.flush_and_close()
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    authority_cfg = tn.current_config()
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )

    monkeypatch.setattr(
        admin_mod,
        "_now_utc",
        lambda _now: proof.expires_at + timedelta(microseconds=1),
    )
    expired_path = tmp_path / "expired.tnpkg"
    with pytest.raises(TrustError) as expired:
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            out_path=expired_path,
            proof=proof,
            cfg=authority_cfg,
        )
    assert expired.value.reason is TrustReason.STATEMENT_EXPIRED
    assert not expired_path.exists()

    monkeypatch.setattr(admin_mod, "_now_utc", lambda _now: proof.issued_at)
    mismatched_path = tmp_path / "mismatched.tnpkg"
    with pytest.raises(TrustError) as mismatched:
        tn.admin.grant_reader(
            "default",
            reader_did=other_reader_did,
            out_path=mismatched_path,
            proof=proof,
            cfg=authority_cfg,
        )
    assert mismatched.value.reason is TrustReason.DID_SIGNER_MISMATCH
    assert not mismatched_path.exists()


def test_hibe_reader_challenge_exact_replay_recovers_and_conflicting_proof_is_rejected(
    tmp_path: Path,
) -> None:
    from tn.trust import TrustError, TrustReason

    tn.init(tmp_path / "reader" / "tn.yaml")
    reader_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    authority_cfg = tn.current_config()
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )
    first = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )
    second = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
        now=first.issued_at + timedelta(microseconds=1),
    )
    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        out_path=tmp_path / "first.tnpkg",
        proof=first,
        cfg=authority_cfg,
    )
    first_bytes = (tmp_path / "first.tnpkg").read_bytes()

    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        out_path=tmp_path / "replay.tnpkg",
        proof=first,
        cfg=authority_cfg,
    )
    assert (tmp_path / "replay.tnpkg").read_bytes() == first_bytes
    with pytest.raises(TrustError) as conflict:
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            out_path=tmp_path / "conflict.tnpkg",
            proof=second,
            cfg=authority_cfg,
        )
    assert conflict.value.reason is TrustReason.REPLAY_CONFLICT


def test_hibe_grant_commit_recovers_from_registry_and_delivery_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.admin as admin_mod

    tn.init(tmp_path / "reader" / "tn.yaml")
    reader_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    authority_cfg = tn.current_config()
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )

    real_update = admin_mod._hibe_grants_update
    update_calls = 0

    def fail_first_update(*args, **kwargs):
        nonlocal update_calls
        update_calls += 1
        if update_calls == 1:
            raise OSError("injected registry failure")
        return real_update(*args, **kwargs)

    monkeypatch.setattr(admin_mod, "_hibe_grants_update", fail_first_update)
    with pytest.raises(OSError, match="injected registry failure"):
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            out_path=tmp_path / "first-attempt.tnpkg",
            proof=proof,
            cfg=authority_cfg,
        )
    assert not (tmp_path / "first-attempt.tnpkg").exists()

    real_deliver = admin_mod._deliver_hibe_grant
    delivery_calls = 0

    def fail_first_delivery(source: Path, destination: Path) -> None:
        nonlocal delivery_calls
        delivery_calls += 1
        if delivery_calls == 1:
            raise OSError("injected delivery failure")
        real_deliver(source, destination)

    monkeypatch.setattr(admin_mod, "_deliver_hibe_grant", fail_first_delivery)
    with pytest.raises(OSError, match="injected delivery failure"):
        tn.admin.grant_reader(
            "default",
            reader_did=reader_cfg.device.device_identity,
            out_path=tmp_path / "second-attempt.tnpkg",
            proof=proof,
            cfg=authority_cfg,
        )
    assert not (tmp_path / "second-attempt.tnpkg").exists()

    monkeypatch.setattr(
        admin_mod,
        "_now_utc",
        lambda _now: proof.expires_at + timedelta(seconds=1),
    )
    recovered = tmp_path / "recovered.tnpkg"
    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        out_path=recovered,
        proof=proof,
        cfg=authority_cfg,
    )
    assert recovered.exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
