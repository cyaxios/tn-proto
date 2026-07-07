"""tn.agents.policy() exposes the active agent PolicyDocument.

Parity with the TS `tn.agents.policy()` accessor: returns the parsed
`.tn/config/agents.md` PolicyDocument loaded at init (the same doc that drives
the tn.agents field splice), or None when no agents.md is present.
"""
from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

from pathlib import Path

import tn
from tn._agents_policy import PolicyDocument

_POLICY = """\
## payment.completed

### instruction
do the thing

### use_for
settled payments

### do_not_use_for
disputes

### consequences
auditable

### on_violation_or_error
POST https://example.com/v1
"""


def _write_policy(yaml_dir: Path) -> None:
    p = yaml_dir / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_POLICY, encoding="utf-8")


def test_agents_policy_is_none_without_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    yaml = tmp_path / "tn.yaml"
    try:
        tn.init(yaml, cipher=_workflow_cipher("btn"))
        assert tn.agents.policy() is None
    finally:
        tn.flush_and_close()


def test_agents_policy_returns_document(tmp_path, monkeypatch):
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path)
    try:
        tn.init(yaml, cipher=_workflow_cipher("btn"))
        doc = tn.agents.policy()
        assert isinstance(doc, PolicyDocument)
        assert "payment.completed" in doc.templates
        assert doc.content_hash.startswith("sha256:")
    finally:
        tn.flush_and_close()
