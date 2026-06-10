"""The core-verb schemas round-trip cleanly, reject bad input, and never
expose anything that evaluates agent input as code."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

import tn.mcp.schemas as schemas
from tn.mcp.schemas import (
    DecryptFailure,
    DecryptInput,
    DecryptOutput,
    DecryptedRow,
    Entry,
    GroupSummary,
    ReadInput,
    ReadOutput,
    StatusInput,
    StatusOutput,
)


def _entry(**overrides) -> Entry:
    """A fully-populated Entry; tests override what they assert on."""
    base = dict(
        event_type="order.created",
        timestamp="2026-06-09T12:00:00+00:00",
        level="info",
        message=None,
        device_identity="did:key:z6MkExample",
        sequence=1,
        event_id="evt-1",
        fields={"order_id": "A100"},
        hidden_groups=[],
    )
    base.update(overrides)
    return Entry(**base)


# --------------------------------------------------------------------- #
#  The removed forensic surface stays removed                            #
# --------------------------------------------------------------------- #


def test_stale_models_are_gone():
    """The stub-era models were deliberately removed: SecureRead* (dead
    forensic model), InvalidReason, and the eval'd `where` string filter."""
    for name in ("SecureReadInput", "SecureReadOutput", "InvalidReason"):
        assert not hasattr(schemas, name), f"{name} should no longer exist"
    assert "where" not in ReadInput.model_fields
    with pytest.raises(ValidationError):
        # extra="forbid" means the old expression filter is rejected, not
        # silently ignored. No parameter is ever evaluated as code.
        ReadInput.model_validate({"where": "e.get('event_type') == 'x'"})


# --------------------------------------------------------------------- #
#  tn_status                                                            #
# --------------------------------------------------------------------- #


def test_status_input_no_args():
    """StatusInput accepts {} and forbids stray fields."""
    inp = StatusInput.model_validate({})
    assert inp.model_dump() == {}
    with pytest.raises(ValidationError):
        StatusInput.model_validate({"verbose": True})


def test_status_output_round_trip():
    out = StatusOutput(
        did="did:key:z6MkExample",
        yaml_path="/abs/path/tn.yaml",
        ceremony_id="local_a1b2c3d4",
        cipher="jwe",
        mode="local",
        sign=True,
        chain=True,
        rust_path=False,
        groups=[
            GroupSummary(name="default", fields=[]),
            GroupSummary(name="pii", fields=["email", "ip"]),
        ],
    )
    dumped = out.model_dump(mode="json")
    assert dumped["ceremony_id"] == "local_a1b2c3d4"
    assert dumped["linked_vault"] is None
    assert dumped["linked_project_id"] is None
    assert dumped["project_name"] is None
    assert dumped["groups"][1] == {"name": "pii", "fields": ["email", "ip"]}
    # And back in through validation.
    again = StatusOutput.model_validate(dumped)
    assert again == out


def test_group_summary_defaults_to_no_fields():
    assert GroupSummary(name="default").fields == []


# --------------------------------------------------------------------- #
#  Entry                                                                #
# --------------------------------------------------------------------- #


def test_entry_full_shape():
    """Entry carries the full 9-field serialized shape, nothing else."""
    e = _entry(hidden_groups=["pii"])
    assert set(e.model_dump()) == {
        "event_type",
        "timestamp",
        "level",
        "message",
        "device_identity",
        "sequence",
        "event_id",
        "fields",
        "hidden_groups",
    }
    assert e.hidden_groups == ["pii"]


# --------------------------------------------------------------------- #
#  tn_read                                                              #
# --------------------------------------------------------------------- #


def test_read_input_defaults():
    inp = ReadInput.model_validate({})
    assert inp.log is None
    assert inp.verify is False
    assert inp.event_type is None
    assert inp.since is None
    assert inp.until is None
    assert inp.fields_equal is None
    assert inp.limit == 100


def test_read_input_limit_bounds():
    """limit is clamped to 1..1000 at the schema layer."""
    assert ReadInput.model_validate({"limit": 1}).limit == 1
    assert ReadInput.model_validate({"limit": 1000}).limit == 1000
    with pytest.raises(ValidationError):
        ReadInput.model_validate({"limit": 0})
    with pytest.raises(ValidationError):
        ReadInput.model_validate({"limit": 1001})


def test_read_input_verify_modes():
    """verify accepts the tn.read passthrough values and nothing else."""
    for value in (False, True, "skip", "raise"):
        assert ReadInput.model_validate({"verify": value}).verify == value
    with pytest.raises(ValidationError):
        ReadInput.model_validate({"verify": "forensic"})


def test_read_output_counters():
    out = ReadOutput(
        entries=[_entry()],
        total_scanned=3,
        returned=1,
        truncated=True,
    )
    dumped = out.model_dump(mode="json")
    assert dumped["total_scanned"] == 3
    assert dumped["returned"] == 1
    assert dumped["truncated"] is True
    assert dumped["entries"][0]["event_type"] == "order.created"


# --------------------------------------------------------------------- #
#  tn_decrypt                                                           #
# --------------------------------------------------------------------- #


def test_decrypt_input_defaults_and_required_content():
    inp = DecryptInput.model_validate({"content": "{}"})
    assert inp.yaml is None
    assert inp.group is None
    with pytest.raises(ValidationError):
        DecryptInput.model_validate({})


def test_decrypt_output_round_trip():
    out = DecryptOutput(
        entries=[
            DecryptedRow(
                line=1,
                entry=_entry(),
                signature_valid=True,
                chain_valid=True,
            ),
        ],
        total_lines=2,
        returned=1,
        signatures_checked=True,
        failures=[DecryptFailure(line=2, error="invalid JSON: ...")],
    )
    dumped = out.model_dump(mode="json")
    assert dumped["entries"][0]["line"] == 1
    assert dumped["entries"][0]["signature_valid"] is True
    assert dumped["failures"] == [{"line": 2, "error": "invalid JSON: ..."}]
    again = DecryptOutput.model_validate(dumped)
    assert again.returned == 1
