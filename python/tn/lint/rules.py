"""Lint rules for tn.lint.

Each rule is a class with:
    id          - short id (R1, R2, ...)
    name        - one-line description
    severity    - "error" or "warning"
    check(call) - given a TNCall record, yield Findings.

Rule R1 inspects the first positional arg (event_type literal) for PII
patterns. Rules R2 and R3 inspect kwarg names. R4 and R5 are stubs --
they appear in --rules listings but never fire (documented as future
work in the README).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Protocol

from tn.lint.config import LintConfig, RESERVED_KWARGS
from tn.lint.findings import Finding


# --------------------------------------------------------------------------- #
# TNCall: what the engine hands to each rule.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TNKwarg:
    name: str
    line: int
    col: int


@dataclass(frozen=True)
class TNCall:
    """A single tn.<method>(...) call discovered by the AST walker."""

    file: str
    method: str  # info, warning, error, attest, log
    line: int
    col: int
    event_type_literal: str | None  # None if first arg is non-literal
    event_type_line: int
    event_type_col: int
    kwargs: tuple[TNKwarg, ...]


# --------------------------------------------------------------------------- #
# Rule protocol
# --------------------------------------------------------------------------- #


class Rule(Protocol):
    id: str
    name: str
    severity: str

    def check(self, call: TNCall, cfg: LintConfig) -> Iterable[Finding]: ...


# --------------------------------------------------------------------------- #
# R1 - PII pattern in event_type literal
# --------------------------------------------------------------------------- #


# Compiled once at import time.
_R1_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.\w+")),
    ("card-shape", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)


class R1PiiInEventType:
    id = "R1"
    name = "PII pattern in event_type literal"
    severity = "error"

    def check(self, call: TNCall, cfg: LintConfig) -> Iterator[Finding]:
        del cfg  # R1 only inspects the event_type literal; config not needed
        if call.event_type_literal is None:
            return
        literal = call.event_type_literal
        for label, pat in _R1_PATTERNS:
            m = pat.search(literal)
            if m:
                yield Finding(
                    file=call.file,
                    line=call.event_type_line,
                    col=call.event_type_col,
                    rule=self.id,
                    severity=self.severity,
                    message=(
                        f"PII pattern ({label}) in event_type literal "
                        f'"{literal}". Move values into fields; the event '
                        "type should be a stable identifier like "
                        '"order.created".'
                    ),
                )
                return  # one finding per call is enough


# --------------------------------------------------------------------------- #
# R2 - Undeclared field kwarg
# --------------------------------------------------------------------------- #


class R2UndeclaredField:
    id = "R2"
    name = "Undeclared field used as kwarg"
    severity = "warning"

    def check(self, call: TNCall, cfg: LintConfig) -> Iterator[Finding]:
        for kw in call.kwargs:
            if kw.name in RESERVED_KWARGS:
                continue
            if kw.name in cfg.known_field_names:
                continue
            yield Finding(
                file=call.file,
                line=kw.line,
                col=kw.col,
                rule=self.id,
                severity=self.severity,
                message=(
                    f"undeclared field '{kw.name}' -- add it to tn.yaml "
                    "fields, public_fields, or extend an industry pack "
                    "that declares it."
                ),
            )


# --------------------------------------------------------------------------- #
# R3 - forbidden_post_auth field referenced
# --------------------------------------------------------------------------- #


class R3ForbiddenPostAuth:
    id = "R3"
    name = "forbidden_post_auth field referenced"
    severity = "error"

    def check(self, call: TNCall, cfg: LintConfig) -> Iterator[Finding]:
        if not cfg.forbidden_post_auth:
            return
        for kw in call.kwargs:
            if kw.name in cfg.forbidden_post_auth:
                yield Finding(
                    file=call.file,
                    line=kw.line,
                    col=kw.col,
                    rule=self.id,
                    severity=self.severity,
                    message=(
                        f"field '{kw.name}' is forbidden after authorization "
                        "(see pack notes). It must never be persisted, "
                        "even encrypted. Drop it before logging."
                    ),
                )


# --------------------------------------------------------------------------- #
# R4, R5 - documented future work, never fire
# --------------------------------------------------------------------------- #


class R4PlainLoggingInSensitivePaths:
    id = "R4"
    name = "plain logging in sensitive paths (stub)"
    severity = "warning"

    def check(self, call: TNCall, cfg: LintConfig) -> Iterator[Finding]:
        del call, cfg  # stub: future-work rule, never fires today
        return iter(())


class R5GroupPolicyDisagreement:
    id = "R5"
    name = "project group policy disagrees with pack policy (stub)"
    severity = "warning"

    def check(self, call: TNCall, cfg: LintConfig) -> Iterator[Finding]:
        del call, cfg  # stub: future-work rule, never fires today
        return iter(())


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


ALL_RULES: tuple[Rule, ...] = (
    R1PiiInEventType(),
    R2UndeclaredField(),
    R3ForbiddenPostAuth(),
    R4PlainLoggingInSensitivePaths(),
    R5GroupPolicyDisagreement(),
)


def select_rules(ids: Iterable[str] | None) -> tuple[Rule, ...]:
    if ids is None:
        return ALL_RULES
    wanted = {x.strip() for x in ids if x.strip()}
    if not wanted:
        return ALL_RULES
    return tuple(r for r in ALL_RULES if r.id in wanted)
