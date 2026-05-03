"""Tests for tn_core.admin: the PyO3 surface of the Rust catalog/reducer."""

from __future__ import annotations

import pytest  # type: ignore[import-not-found]
import tn_core  # type: ignore[import-not-found]


def test_kinds_returns_full_catalog():
    kinds = tn_core.admin.kinds()
    event_types = {k["event_type"] for k in kinds}
    assert event_types == {
        "tn.ceremony.init",
        "tn.group.added",
        "tn.recipient.added",
        "tn.recipient.revoked",
        "tn.coupon.issued",
        "tn.rotation.completed",
        "tn.enrolment.compiled",
        "tn.enrolment.absorbed",
        "tn.vault.linked",
        "tn.vault.unlinked",
        # 2026-04-25 read-ergonomics + agents-group spec.
        "tn.agents.policy_published",
        "tn.read.tampered_row_skipped",
    }
    assert len(kinds) == len(event_types)


def test_every_kind_is_signed():
    """Every admin event_type signs. Sync varies per event."""
    # ``tn.read.tampered_row_skipped`` is a local-only forensic event
    # (never replicated); every other admin event is sync-replicable.
    for k in tn_core.admin.kinds():
        assert k["sign"] is True
        if k["event_type"] == "tn.read.tampered_row_skipped":
            assert k["sync"] is False
        else:
            assert k["sync"] is True


def test_schema_shape_is_list_of_name_type_pairs():
    r = next(k for k in tn_core.admin.kinds() if k["event_type"] == "tn.recipient.added")
    # schema -> list of [name, type] pairs
    assert all(isinstance(pair, list) and len(pair) == 2 for pair in r["schema"])
    names = [p[0] for p in r["schema"]]
    assert names == ["group", "leaf_index", "recipient_did", "kit_sha256", "cipher"]


def test_validate_emit_ok():
    tn_core.admin.validate_emit(
        "tn.recipient.added",
        {
            "group": "default",
            "leaf_index": 2,
            "recipient_did": "did:key:zFrank",
            "kit_sha256": "sha256:abc",
            "cipher": "btn",
        },
    )  # no exception = pass


def test_validate_emit_missing_field_raises():
    with pytest.raises(ValueError, match="missing required field"):
        tn_core.admin.validate_emit(
            "tn.recipient.added",
            {
                "group": "default",
            },
        )


def test_validate_emit_unknown_event_type_raises():
    with pytest.raises(ValueError, match="unknown admin event_type"):
        tn_core.admin.validate_emit("tn.bogus", {})


def test_reduce_recipient_added_produces_correct_delta():
    envelope = {
        "event_type": "tn.recipient.added",
        "did": "did:key:zAlice",
        "level": "info",
        "group": "default",
        "leaf_index": 2,
        "recipient_did": "did:key:zFrank",
        "kit_sha256": "sha256:abc",
        "cipher": "btn",
    }
    delta = tn_core.admin.reduce(envelope)
    assert delta["kind"] == "recipient_added"
    assert delta["group"] == "default"
    assert delta["leaf_index"] == 2
    assert delta["recipient_did"] == "did:key:zFrank"


def test_reduce_unknown_event_returns_unknown_delta():
    envelope = {"event_type": "order.created", "did": "did:key:zX"}
    delta = tn_core.admin.reduce(envelope)
    assert delta == {"kind": "unknown", "event_type": "order.created"}


def test_reduce_vault_unlinked_null_reason():
    envelope = {
        "event_type": "tn.vault.unlinked",
        "did": "did:key:zA",
        "vault_did": "did:web:tn-proto.org",
        "project_id": "proj_test",
        "reason": None,
        "unlinked_at": "2026-04-22T12:00:00Z",
    }
    delta = tn_core.admin.reduce(envelope)
    assert delta["kind"] == "vault_unlinked"
    assert delta["reason"] is None


def test_reduce_schema_violation_raises():
    # tn.recipient.added missing kit_sha256.
    envelope = {
        "event_type": "tn.recipient.added",
        "did": "did:key:zA",
        "group": "default",
        "leaf_index": 1,
        "recipient_did": None,
        "cipher": "btn",
    }
    with pytest.raises(ValueError, match="schema violation"):
        tn_core.admin.reduce(envelope)


def test_reduce_missing_event_type_raises():
    with pytest.raises(ValueError, match="missing event_type"):
        tn_core.admin.reduce({"did": "did:key:zA"})
