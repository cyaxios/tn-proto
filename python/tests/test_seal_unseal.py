"""tn.seal / tn.unseal round-trip and verification tests."""

import base64
import json
import os

import pytest

import tn
from tn import UnsealError, VerifyError, admin
from tn.absorb import absorb
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.compile import compile_enrolment, emit_to_outbox
from tn.config import load_or_create
from tn.offer import _ensure_mykey
from tn.signing import DeviceKey, _signature_from_b64


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    tn.flush_and_close()


def _workflow_cipher(default: str) -> str:
    return os.environ.get("TN_TEST_CIPHER", default)


def test_seal_returns_sealed_object(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", amount=9800, customer="acme")

    assert isinstance(sealed, dict)
    # str() renders compact wire JSON (the log's line format), not Python repr
    parsed = json.loads(str(sealed))
    assert parsed == dict(sealed)

    # standalone conventions
    assert sealed["sequence"] == 0
    assert sealed["prev_hash"] == ""
    assert sealed["tn_sealed"] == 1
    assert sealed["event_type"] == "obj.invoice.v1"

    # fields are encrypted, not in the clear
    assert "amount" not in sealed
    assert "customer" not in sealed
    assert "ciphertext" in sealed["default"]

    # always signed, and the signature verifies
    assert DeviceKey.verify(
        sealed["device_identity"],
        sealed["row_hash"].encode("ascii"),
        _signature_from_b64(sealed["signature"]),
    )

    # row_hash is honestly derived from the envelope contents: the
    # standalone preimage hashes prev_hash "" (not ZERO_HASH), excludes
    # sequence, and binds the tn_sealed marker as a public field
    groups = {
        "default": {
            "ciphertext": base64.b64decode(sealed["default"]["ciphertext"]),
            "field_hashes": sealed["default"]["field_hashes"],
        }
    }
    assert sealed["row_hash"] == _compute_row_hash(
        device_identity=sealed["device_identity"],
        timestamp=sealed["timestamp"],
        event_id=sealed["event_id"],
        event_type=sealed["event_type"],
        level=sealed["level"],
        prev_hash=sealed["prev_hash"],
        public_fields={"tn_sealed": sealed["tn_sealed"]},
        groups=groups,
    )
    # no aad passed -> no tn_aad echo; aad-free wire shape stays minimal
    assert "tn_aad" not in sealed


def test_seal_rejects_reserved_field(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    with pytest.raises(ValueError, match="tn_sealed"):
        tn.seal("obj.test.v1", tn_sealed=1)


def test_seal_does_not_disturb_chain(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.seal("obj.test.v1", receipt=False, x=1)
    # chains are per-event_type: log the SAME type the seal used. If seal
    # had advanced that chain, this row would be sequence 2 with a real
    # prev_hash instead of the genesis link.
    row = tn.log("obj.test.v1", y=2)
    assert row["sequence"] == 1
    assert row["prev_hash"] == ZERO_HASH


def test_seal_writes_receipt_row_by_default(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", amount=1)
    # tn.* events route to the admin/protocol-events log by default (a
    # dedicated file, not the main ceremony log), per logger.py's
    # `event_type.startswith("tn.")` routing — read that surface.
    receipts = list(tn.read("tn.object.sealed", log="admin"))
    assert len(receipts) == 1
    r = receipts[0]
    assert r.fields["object_id"] == sealed["row_hash"]
    assert r.fields["object_type"] == "obj.invoice.v1"
    assert r.fields["groups"] == ["default"]


def test_seal_receipt_false_writes_nothing(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.seal("obj.invoice.v1", receipt=False, amount=1)
    assert list(tn.read("tn.object.sealed", log="admin")) == []


def test_unseal_roundtrip_own_ceremony(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", receipt=False, amount=9800, customer="acme")
    entry = tn.unseal(sealed)
    assert entry.event_type == "obj.invoice.v1"
    # exact: the tn_sealed wire marker must NOT leak into user fields
    assert entry.fields == {"amount": 9800, "customer": "acme"}
    assert entry.sequence == 0
    assert entry.prev_hash == ""
    assert entry.did == sealed["device_identity"]
    assert entry.hidden_groups == []


def test_unseal_accepts_all_source_shapes(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    as_dict = tn.unseal(dict(sealed))
    as_str = tn.unseal(str(sealed))
    as_bytes = tn.unseal(str(sealed).encode("utf-8"))
    p = tmp_path / "obj.json"
    p.write_text(str(sealed), encoding="utf-8")
    as_path = tn.unseal(p)
    for e in (as_dict, as_str, as_bytes, as_path):
        assert e.fields["x"] == 1


def test_unseal_raw_returns_triple(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    triple = tn.unseal(sealed, raw=True)
    assert set(triple) == {"envelope", "plaintext", "valid"}
    assert triple["envelope"]["row_hash"] == sealed["row_hash"]
    assert triple["plaintext"]["default"] == {"x": 1}
    assert triple["valid"]["signature"] is True
    assert triple["valid"]["row_hash"] is True


def test_unseal_verify_false_reports_unverified(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    triple = tn.unseal(sealed, verify=False, raw=True)
    assert triple["valid"] == {"signature": False, "row_hash": False}


def test_unseal_tampered_public_field_raises(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    tampered = dict(sealed)
    tampered["tn_sealed"] = 2
    with pytest.raises(VerifyError):
        tn.unseal(tampered)


def test_unseal_tampered_ciphertext_raises(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    tampered = json.loads(str(sealed))
    block = tampered["default"]["ciphertext"]
    tampered["default"]["ciphertext"] = block[:-4] + ("AAAA" if block[-4:] != "AAAA" else "BBBB")
    with pytest.raises(VerifyError):
        tn.unseal(tampered)


def test_unseal_swapped_signature_raises(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    other = tn.seal("obj.other.v1", receipt=False, y=2)
    # a validly-encoded signature from a different object: row_hash still
    # recomputes, so only the signature check trips
    tampered = dict(sealed)
    tampered["signature"] = other["signature"]
    with pytest.raises(VerifyError) as exc:
        tn.unseal(tampered)
    assert "signature" in exc.value.failed_checks
    assert "row_hash" not in exc.value.failed_checks


def test_unseal_verify_false_returns_despite_tamper(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    tampered = dict(sealed)
    tampered["tn_sealed"] = 2
    entry = tn.unseal(tampered, verify=False)
    assert entry.event_type == "obj.test.v1"


def test_seal_aad_binds_and_roundtrips(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, aad={"case": "A-17"}, x=1)
    assert "tn_aad" in sealed          # authenticated public echo present
    entry = tn.unseal(sealed)          # _aad_bytes_for reconstructs binding
    assert entry.fields["x"] == 1
    tampered = dict(sealed)
    tampered["tn_aad"] = tampered["tn_aad"].replace("A-17", "B-99")
    with pytest.raises(VerifyError):   # echo is bound into row_hash
        tn.unseal(tampered)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("not json at all", id="not-json"),
        pytest.param("[1,2,3]", id="json-array"),
        pytest.param("{}", id="empty-object"),
        pytest.param(b"\xff\xfe", id="invalid-utf8"),
        pytest.param({"event_type": "x"}, id="missing-most-keys"),
        # four original keys present but timestamp/event_id/sequence
        # missing — the strict shape requires all seven.
        pytest.param(
            {"device_identity": "d", "event_type": "x", "row_hash": "h", "signature": "s"},
            id="missing-3-of-7",
        ),
    ],
)
def test_unseal_malformed_sources_raise_unsealerror(tmp_path, bad):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    with pytest.raises(UnsealError):
        tn.unseal(bad)


def _two_peer(tmp_path):
    """Alice seals into 'partners'; Bob is enrolled in that group only.

    Bob's own ceremony has NO 'partners' group, so unseal's pass 1
    (own-ceremony group ciphers) structurally cannot open that block —
    only the pass-2 keystore key-bag can. The sealed object also
    carries an Alice-only 'default' block ('note'), making the
    enrolled-peer open a real partial open.

    The absorb step is the real enrolment flow and must apply cleanly,
    but it is not what makes the decrypt work: JWE decrypt needs only
    partners.jwe.mykey (the ECDH-ES ephemeral travels in the envelope
    header), and _ensure_mykey already minted that file into Bob's
    keystore.

    Leaves Bob's ceremony ACTIVE (the key-bag tests rely on that).
    Returns ``(sealed, bob_keystore)`` where ``bob_keystore`` is Bob's
    real keystore directory (``cfg.keystore``), usable as an
    ``as_recipient=`` target after the ceremony closes.
    """
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")
    alice_cfg = admin.ensure_group(alice_cfg, "partners", fields=["body"])
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    bob_pub = _ensure_mykey(bob_cfg, "partners")
    admin._add_recipient_jwe_impl(
        alice_cfg, "partners", bob_cfg.device.device_identity, bob_pub
    )
    pkg = compile_enrolment(alice_cfg, "partners", bob_cfg.device.device_identity)
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    tn.init(str(alice_cfg.yaml_path))
    # body -> partners (routed), note -> default (unrouted fallback)
    sealed = tn.seal(
        "obj.memo.v1", receipt=False, body="for bob's eyes", note="alice private"
    )
    tn.flush_and_close()
    assert "partners" in sealed and "default" in sealed, (
        f"setup must seal two group blocks, got: {sorted(sealed)}"
    )

    tn.init(str(bob_cfg.yaml_path))
    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", (
        f"absorb must succeed before cross-ceremony unseal; reason: {result.reason}"
    )
    return sealed, bob_cfg.keystore


def test_enrolled_peer_opens_their_slice(tmp_path):
    sealed, _bob_keystore = _two_peer(tmp_path)
    # Structural guard: Bob's active ceremony has no 'partners' group, so
    # pass 1 (own-ceremony group ciphers) cannot fire for that block; an
    # open below proves the pass-2 keystore key-bag walk did it.
    assert "partners" not in tn.current_config().groups
    entry = tn.unseal(sealed)  # active ceremony is Bob's
    # partial open: exactly Bob's slice; Alice's private block stays sealed
    assert entry.fields == {"body": "for bob's eyes"}
    assert "default" in entry.hidden_groups


def test_unenrolled_peer_gets_public_frame_no_error(tmp_path):
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    tn.init(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.memo.v1", receipt=False, body="private")
    tn.flush_and_close()

    carol_dir = tmp_path / "carol"
    carol_dir.mkdir()
    tn.init(carol_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    entry = tn.unseal(sealed)  # Carol holds no fitting key -> no exception
    assert entry.event_type == "obj.memo.v1"
    assert "body" not in entry.fields
    assert "default" in entry.hidden_groups


def test_as_recipient_single_kit_override(tmp_path):
    sealed, bob_keystore = _two_peer(tmp_path)
    tn.flush_and_close()
    # no active ceremony needed: bring-your-own-kit against Bob's keystore,
    # opening only the named group
    entry = tn.unseal(sealed, as_recipient=bob_keystore, group="partners")
    assert entry.fields == {"body": "for bob's eyes"}
    assert "default" in entry.hidden_groups


def test_seal_unseal_btn_ceremony(tmp_path):
    # btn-only ceremonies dispatch tn.log through the Rust runtime, but
    # seal's receipt is an internal event and — like every internal
    # tn.* emit in the codebase — goes through the pure-Python runtime.
    # So this round-trip coexists a Python-side btn encrypt (seal) and
    # Python-side receipt emit with a Rust-dispatched probe emit
    # (tn.log below) against the same publisher sealing state, proving
    # neither path corrupts the other.
    tn.init(tmp_path / "tn.yaml", cipher="btn")
    sealed = tn.seal("obj.test.v1", x=1)  # receipt on: Python-side internal emit
    row = tn.log("probe.v1", y=2)  # the Rust emit path (btn-only dispatch)
    assert row is not None
    entry = tn.unseal(sealed)
    assert entry.fields["x"] == 1
    # both log surfaces still verify after the Python-side btn encrypt:
    # the probe row chains into the main ceremony log...
    main = list(tn.read(verify="raise"))
    assert "probe.v1" in [e.event_type for e in main]
    # ...and the seal receipt chains into the admin/protocol-events log.
    receipts = list(tn.read("tn.object.sealed", log="admin", verify="raise"))
    assert len(receipts) == 1
    assert receipts[0].fields["object_id"] == sealed["row_hash"]


def test_unseal_pre_rotation_object_after_rotation(tmp_path):
    # Pinned to jwe (not _workflow_cipher): rotation retains the old
    # recipient key as <group>.jwe.mykey.revoked.<ts>, and JWE decrypt
    # walks those priors (active key first, then each revoked key
    # newest-first), so a pre-rotation object still opens. btn also
    # retains its prior kit (.btn.mykit.retired.<epoch>) but only the
    # Rust runtime's multi-kit read path walks that archive — the
    # pure-Python unseal walk does not, so this expectation holds for
    # jwe only today.
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    admin.rotate("default")
    entry = tn.unseal(sealed)
    assert entry.fields["x"] == 1
