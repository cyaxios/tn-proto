"""Pydantic v2 models for MCP tool input/output.

Every tool input is a model whose name ends in ``Input``; every tool output
ends in ``Output``. The MCP server uses these for both schema generation
(via ``model_json_schema()``) and runtime validation. Keeping the models
explicit (no auto-generation) gives us hand-crafted descriptions that the
agent reads.

The three core verbs these models serve:

* ``tn_status``  - one-shot summary of the active ceremony.
* ``tn_read``    - read the ceremony's attested log with structured filters.
* ``tn_decrypt`` - decrypt raw TN ndjson lines pasted inline.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------- #
#  Shared shapes                                                        #
# --------------------------------------------------------------------- #


class GroupSummary(BaseModel):
    """One group's snapshot: name plus the fields routed into it."""
    model_config = ConfigDict(frozen=True)

    name: str
    fields: list[str] = Field(
        default_factory=list,
        description="Field names the ceremony routes into this group.",
    )


class Entry(BaseModel):
    """One serialized log entry as returned by ``tn.read()``."""
    model_config = ConfigDict(frozen=False)  # fields dict is mutable

    event_type: str
    timestamp: str = Field(description="ISO-8601 timestamp of the entry.")
    level: str = Field(description="Log level, e.g. 'info' or 'warning'.")
    message: str | None = Field(
        default=None,
        description="Positional message, when the emitter passed one.",
    )
    device_identity: str = Field(
        description="Authoring DID, e.g. did:key:z6Mk... (the envelope's device_identity).",
    )
    sequence: int = Field(description="Per-event-type chain sequence number.")
    event_id: str
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Decrypted user payload merged across readable groups.",
    )
    hidden_groups: list[str] = Field(
        default_factory=list,
        description=(
            "Groups whose ciphertext was present but could not be decrypted "
            "with the available kits. Non-empty means part of this row is "
            "hidden from the reader."
        ),
    )


# --------------------------------------------------------------------- #
#  tn_status                                                            #
# --------------------------------------------------------------------- #


class StatusInput(BaseModel):
    """tn_status takes no arguments."""
    model_config = ConfigDict(extra="forbid")


class StatusOutput(BaseModel):
    """One-shot summary of the current ceremony."""
    did: str = Field(description="Owning DID of the ceremony, e.g. did:key:z6Mk...")
    yaml_path: str = Field(description="Absolute path to the ceremony yaml.")
    ceremony_id: str = Field(description="Ceremony identifier, e.g. local_a1b2c3d4.")
    cipher: str = Field(description="Active cipher: 'btn' or 'jwe'.")
    mode: str = Field(description="Vault link mode: 'local' or 'linked'.")
    linked_vault: str | None = Field(
        default=None,
        description="Linked vault base URL when mode='linked', else null.",
    )
    linked_project_id: str | None = Field(
        default=None,
        description="Vault-side project id when linked, else null.",
    )
    project_name: str | None = Field(
        default=None,
        description="Operator-chosen project label, when set in the yaml.",
    )
    sign: bool = Field(
        description="Whether rows are Ed25519-signed (ceremony.sign).",
    )
    chain: bool = Field(
        description="Whether rows are hash-chained (ceremony.chain).",
    )
    rust_path: bool = Field(
        description="Whether the Rust tn_core runtime is active (vs Python fallback).",
    )
    groups: list[GroupSummary] = Field(
        default_factory=list,
        description="Configured groups with their field membership.",
    )


# --------------------------------------------------------------------- #
#  tn_read                                                              #
# --------------------------------------------------------------------- #


class ReadInput(BaseModel):
    """Read the active ceremony's log with structured, declarative filters.

    There is deliberately no free-form expression filter: every filter is
    a typed parameter, so nothing the agent sends is ever evaluated as code.
    """
    model_config = ConfigDict(extra="forbid")

    log: str | None = Field(
        default=None,
        description=(
            "Source log. None (default) reads the active ceremony's main "
            "log. Accepts a file path or the literal 'admin' for the "
            "ceremony's admin log (tn.* protocol events)."
        ),
    )
    verify: bool | Literal["skip", "raise"] = Field(
        default=False,
        description=(
            "Integrity-check mode, passed through to tn.read unchanged. "
            "False (default): no signature/row_hash/chain verification; "
            "every row is returned as-is. "
            "True or 'raise' (synonyms): verify each row and fail the whole "
            "read on the first row that fails a check. "
            "'skip': verify each row and silently drop failing rows "
            "(dropped rows are counted, not returned)."
        ),
    )
    event_type: str | None = Field(
        default=None,
        description=(
            "Event-type filter. Exact match by default; a trailing '*' "
            "switches to prefix match, e.g. 'order.*' matches "
            "'order.created' and 'order.shipped'."
        ),
    )
    since: str | None = Field(
        default=None,
        description=(
            "ISO-8601 timestamp; only entries at or after this instant are "
            "returned. Naive timestamps are interpreted as UTC."
        ),
    )
    until: str | None = Field(
        default=None,
        description=(
            "ISO-8601 timestamp; only entries at or before this instant are "
            "returned. Naive timestamps are interpreted as UTC."
        ),
    )
    fields_equal: dict[str, str] | None = Field(
        default=None,
        description=(
            "Field equality filter: every named field must be present and "
            "its value must equal the given string (values are compared "
            "via str())."
        ),
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of entries to return (1-1000).",
    )


class ReadOutput(BaseModel):
    entries: list[Entry]
    total_scanned: int = Field(
        description="Number of entries read from the log before filtering.",
    )
    returned: int = Field(description="Number of entries returned.")
    truncated: bool = Field(
        description="True when more entries matched the filters than `limit`.",
    )


# --------------------------------------------------------------------- #
#  tn_decrypt                                                           #
# --------------------------------------------------------------------- #


class DecryptInput(BaseModel):
    """Decrypt raw TN ndjson lines pasted inline, using the local keystore."""
    model_config = ConfigDict(extra="forbid")

    content: str = Field(
        description=(
            "Raw TN ndjson content: one envelope JSON object per line, "
            "exactly as it appears in a .ndjson log. Blank lines are "
            "ignored."
        ),
    )
    yaml: str | None = Field(
        default=None,
        description=(
            "Path to a ceremony yaml whose keystore should be used for "
            "decryption. None (default) uses the active ceremony's "
            "keystore."
        ),
    )
    group: str | None = Field(
        default=None,
        description=(
            "Restrict decryption to this single group's fields. None "
            "(default) decrypts every group a kit exists for."
        ),
    )


class DecryptFailure(BaseModel):
    """One input line that could not be processed, with the reason."""
    model_config = ConfigDict(frozen=True)

    line: int = Field(description="1-based line number within `content`.")
    error: str = Field(description="Why this line could not be processed.")


class DecryptedRow(BaseModel):
    """One successfully parsed line: the decrypted entry plus validity flags."""
    line: int = Field(description="1-based line number within `content`.")
    entry: Entry
    signature_valid: bool = Field(
        description=(
            "Ed25519 signature check result for this row. Always True when "
            "`signatures_checked` is False on the output."
        ),
    )
    chain_valid: bool = Field(
        description=(
            "prev_hash continuity check, per event_type, within the pasted "
            "lines only (the first row of each event_type is trivially "
            "valid)."
        ),
    )


class DecryptOutput(BaseModel):
    entries: list[DecryptedRow]
    total_lines: int = Field(
        description="Number of non-blank input lines received.",
    )
    returned: int = Field(description="Number of rows decrypted and returned.")
    signatures_checked: bool = Field(
        description=(
            "Whether signatures were verified. False when the ceremony was "
            "created with sign: false (a signature check would be "
            "meaningless)."
        ),
    )
    failures: list[DecryptFailure] = Field(
        default_factory=list,
        description="Per-line failures: invalid JSON or non-envelope lines.",
    )


# --------------------------------------------------------------------- #
#  Public surface                                                       #
# --------------------------------------------------------------------- #


__all__ = [
    "DecryptFailure",
    "DecryptInput",
    "DecryptOutput",
    "DecryptedRow",
    "Entry",
    "GroupSummary",
    "ReadInput",
    "ReadOutput",
    "StatusInput",
    "StatusOutput",
]
