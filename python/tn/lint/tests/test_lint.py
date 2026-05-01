"""End-to-end tests for tn.lint.

Loads the fixture tn.yaml, lints each fixture .py file, and asserts the
expected rule (R1/R2/R3) fires once and only once.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tn.lint.config import load_config
from tn.lint.engine import lint_paths
from tn.lint.rules import ALL_RULES


FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def cfg():
    return load_config(FIXTURES / "tn.yaml", cwd=FIXTURES)


def _findings_for(cfg, fixture_name: str):
    return lint_paths([FIXTURES / fixture_name], cfg, ALL_RULES, relative_to=FIXTURES)


def test_extends_resolves_to_repo_pack(cfg) -> None:
    assert "pci-cardholder" in cfg.extends_loaded
    assert "cvv" in cfg.forbidden_post_auth
    assert "pin" in cfg.forbidden_post_auth


def test_r1_pii_in_event_type(cfg) -> None:
    findings = _findings_for(cfg, "r1_violation.py")
    rules_hit = {f.rule for f in findings}
    assert "R1" in rules_hit
    r1 = [f for f in findings if f.rule == "R1"]
    assert len(r1) == 1
    assert "email" in r1[0].message.lower()


def test_r2_undeclared_field(cfg) -> None:
    findings = _findings_for(cfg, "r2_violation.py")
    r2 = [f for f in findings if f.rule == "R2"]
    assert len(r2) == 1
    assert "shoe_size" in r2[0].message


def test_r3_forbidden_post_auth(cfg) -> None:
    findings = _findings_for(cfg, "r3_violation.py")
    r3 = [f for f in findings if f.rule == "R3"]
    assert len(r3) == 1
    assert r3[0].severity == "error"
    assert "cvv" in r3[0].message


def test_clean_fixture_silent(cfg) -> None:
    findings = _findings_for(cfg, "clean.py")
    assert findings == [], f"expected no findings, got: {findings}"


def test_human_format_shape(cfg) -> None:
    findings = _findings_for(cfg, "r1_violation.py")
    assert findings
    formatted = findings[0].format_human()
    assert ":" in formatted
    assert "R1:" in formatted
