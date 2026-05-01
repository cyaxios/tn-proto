"""Finding dataclass: a single lint result."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True, slots=True)
class Finding:
    """One violation reported by a rule.

    Attributes:
        file: Absolute or repo-relative path to the source file.
        line: 1-indexed line number of the offending node.
        col:  1-indexed column number (AST col_offset + 1).
        rule: Rule id, e.g. ``"R1"``.
        message: Human-readable message.
        severity: ``"error"`` or ``"warning"``.
    """

    file: str
    line: int
    col: int
    rule: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.file, self.line, self.col, self.rule)

    def format_human(self) -> str:
        return f"{self.file}:{self.line}:{self.col}: {self.rule}: {self.message}"
