"""Pydantic v2 models for MCP tool input/output.

Every tool input is a model whose name ends in ``Input``; every tool output
ends in ``Output``. The MCP server uses these for both schema generation
(via ``model_json_schema()``) and runtime validation. Keeping the models
explicit (no auto-generation) gives us hand-crafted descriptions that the
agent reads.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------- #
#  Shared shapes                                                        #
# --------------------------------------------------------------------- #


class GroupSummary(BaseModel):
    """One group's snapshot (name + fields + recipient count)."""
    model_config = ConfigDict(frozen=True)

    name: str
    fields: list[str] = Field(default_factory=list)
    recipient_count: int = 0


class Entry(BaseModel):
    """One log entry as returned by ``tn.read()``: event_type + flat fields."""
    model_config = ConfigDict(frozen=False)  # fields dict is mutable

    event_type: str
    fields: dict[str, Any] = Field(default_factory=dict)


class InvalidReason(BaseModel):
    """One forensic-mode failure: envelope hash + the reasons it failed verify."""
    model_config = ConfigDict(frozen=True)

    envelope_hash: str
    reasons: list[str]


# --------------------------------------------------------------------- #
#  tn_status                                                            #
# --------------------------------------------------------------------- #


class StatusInput(BaseModel):
    """tn_status takes no arguments."""
    model_config = ConfigDict(extra="forbid")


class StatusOutput(BaseModel):
    """One-shot summary of the current ceremony."""
    did: str = Field(description="Owning DID of the ceremony, e.g. did:key:z6Mk...")
    ceremony_path: str = Field(description="Absolute path to tn.yaml")
    cipher: Literal["btn", "jwe"] = Field(description="Active cipher")
    link_state: Literal["local", "linked"] = Field(description="Vault link mode")
    groups: list[GroupSummary] = Field(
        default_factory=list,
        description="Configured groups with field membership and recipient counts.",
    )
    runs: dict[str, Any] = Field(
        description="Run identifiers: current_id (str) and total (int).",
    )
    rust_path: bool = Field(
        description="Whether the Rust tn_core extension is being used (vs Python fallback).",
    )


# --------------------------------------------------------------------- #
#  tn_read                                                              #
# --------------------------------------------------------------------- #


class ReadInput(BaseModel):
    """Read the current ceremony's log as flat dicts."""
    model_config = ConfigDict(extra="forbid")

    where: str | None = Field(
        default=None,
        description=(
            "Optional Python expression filter, evaluated as `lambda e: <expr>`. "
            "`e` is the flat dict for each entry. Example: \"e.get('event_type') == 'order.created'\"."
        ),
    )
    all_runs: bool = Field(
        default=False,
        description="If True, include entries from prior process runs (default: current run only).",
    )
    verify: bool = Field(
        default=False,
        description="If True, attach a `_valid` audit block per entry.",
    )


class ReadOutput(BaseModel):
    entries: list[Entry]
    total: int = Field(description="Number of entries returned.")


# --------------------------------------------------------------------- #
#  tn_secure_read                                                       #
# --------------------------------------------------------------------- #


class SecureReadInput(BaseModel):
    """Verified read with fail-closed semantics."""
    model_config = ConfigDict(extra="forbid")

    on_invalid: Literal["skip", "raise", "forensic"] = Field(
        default="skip",
        description=(
            "skip = silently skip tampered rows (default); "
            "raise = halt on any anomaly (use when you want to assert clean); "
            "forensic = yield with _valid + _invalid_reasons fields populated."
        ),
    )
    where: str | None = Field(
        default=None,
        description="Optional filter as in tn_read.",
    )


class SecureReadOutput(BaseModel):
    entries: list[Entry]
    skipped_count: int = Field(
        default=0,
        description="Number of rows skipped due to verification failures (skip mode).",
    )
    invalid_reasons: list[InvalidReason] | None = Field(
        default=None,
        description="Populated only when on_invalid='forensic'.",
    )


# --------------------------------------------------------------------- #
#  Public surface                                                       #
# --------------------------------------------------------------------- #


__all__ = [
    "Entry",
    "GroupSummary",
    "InvalidReason",
    "ReadInput",
    "ReadOutput",
    "SecureReadInput",
    "SecureReadOutput",
    "StatusInput",
    "StatusOutput",
]
