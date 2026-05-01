"""Schemas round-trip cleanly and reject bad input."""
from __future__ import annotations

import pytest

from tn.mcp.schemas import (
    StatusInput,
    StatusOutput,
    ReadInput,
    ReadOutput,
    SecureReadInput,
    SecureReadOutput,
    GroupSummary,
    Entry,
    InvalidReason,
)


def test_status_input_no_args():
    """StatusInput accepts {} (no fields)."""
    inp = StatusInput.model_validate({})
    assert inp.model_dump() == {}


def test_status_output_minimal():
    """StatusOutput requires the core fields."""
    out = StatusOutput(
        did="did:key:z6MkExample",
        ceremony_path="/abs/path/tn.yaml",
        cipher="btn",
        link_state="local",
        groups=[],
        runs={"current_id": "r-abc", "total": 1},
        rust_path=True,
    )
    dumped = out.model_dump()
    assert dumped["did"] == "did:key:z6MkExample"
    assert dumped["cipher"] == "btn"


def test_status_output_with_groups():
    """StatusOutput carries group summaries."""
    out = StatusOutput(
        did="did:key:z6Mk",
        ceremony_path="/p/tn.yaml",
        cipher="jwe",
        link_state="local",
        groups=[
            GroupSummary(name="default", fields=["order_id"], recipient_count=2),
            GroupSummary(name="pii", fields=["email", "ip"], recipient_count=1),
        ],
        runs={"current_id": "r-1", "total": 3},
        rust_path=False,
    )
    assert len(out.groups) == 2


def test_read_input_defaults():
    """ReadInput has sensible defaults: no filter, current run only."""
    inp = ReadInput.model_validate({})
    assert inp.all_runs is False
    assert inp.where is None
    assert inp.verify is False


def test_read_input_where_clause_string():
    """ReadInput accepts a Python expression string for `where`."""
    inp = ReadInput.model_validate({"where": "e.get('event_type') == 'order.created'"})
    assert inp.where == "e.get('event_type') == 'order.created'"


def test_read_output_carries_entries():
    """ReadOutput holds a list of flat-dict entries plus a count."""
    out = ReadOutput(
        entries=[
            Entry(event_type="order.created", fields={"order_id": "A100"}),
        ],
        total=1,
    )
    assert out.total == 1
    assert out.entries[0].event_type == "order.created"


def test_secure_read_input_default_skip():
    """SecureReadInput defaults on_invalid to 'skip'."""
    inp = SecureReadInput.model_validate({})
    assert inp.on_invalid == "skip"


def test_secure_read_input_rejects_bad_mode():
    """SecureReadInput rejects on_invalid not in skip|raise|forensic."""
    with pytest.raises(ValueError):
        SecureReadInput.model_validate({"on_invalid": "ignore"})


def test_secure_read_output_forensic_shape():
    """SecureReadOutput in forensic mode includes invalid_reasons."""
    out = SecureReadOutput(
        entries=[Entry(event_type="x", fields={})],
        skipped_count=1,
        invalid_reasons=[
            InvalidReason(envelope_hash="h1", reasons=["bad_signature"]),
        ],
    )
    assert out.skipped_count == 1
    assert len(out.invalid_reasons or []) == 1
