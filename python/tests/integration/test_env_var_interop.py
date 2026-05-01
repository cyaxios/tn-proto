"""Cross-language env-var substitution: shared yaml fixture, three SDKs.

This test pins the *contract* — a yaml file with
``${TN_TEST_CEREMONY_ID:-default_id}`` resolves identically across the
Python, TypeScript, and Rust loaders.

The Python side runs end-to-end here. The TS and Rust sides have their
own native tests that cover the same fixture shape:

* TypeScript: ``tn-protocol/ts-sdk/test/config_env_vars.test.ts``
  ("loadConfig propagates env-var substitution end-to-end")
* Rust:       ``tn-protocol/crypto/tn-core/tests/config_env_vars.rs``
  (``mixed_substitutions_yaml`` and ``default_used_when_var_absent``)

Spawning all three SDKs in one harness is deferred — wiring the
existing ``test/interop_driver.sh`` to drive a yaml-config-loading
case is a small follow-up. For now this Python-only test plus the
pinned syntax ensures parity by construction (each SDK has a
near-identical test against the same syntax).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tn.config import _substitute_env_vars

# This fixture is the shared contract — any change here must update the
# TS and Rust mirrors.
FIXTURE_YAML = """\
ceremony:
  id: ${TN_TEST_CEREMONY_ID:-default_id}
  mode: local
  cipher: btn
  literal: $${LITERAL_TEMPLATE}
logs:
  path: ${TN_TEST_LOG_PATH:-./.tn/logs/tn.ndjson}
keystore:
  path: ./.tn/keys
me:
  did: ${TN_TEST_DID}
groups:
  default:
    policy: private
    cipher: btn
"""


def test_default_used_when_var_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TN_TEST_CEREMONY_ID", raising=False)
    monkeypatch.delenv("TN_TEST_LOG_PATH", raising=False)
    monkeypatch.setenv("TN_TEST_DID", "did:key:zABC")

    out = _substitute_env_vars(FIXTURE_YAML, tmp_path / "tn.yaml")
    assert "id: default_id" in out
    assert "literal: ${LITERAL_TEMPLATE}" in out
    assert "path: ./.tn/logs/tn.ndjson" in out
    assert "did: did:key:zABC" in out


def test_var_value_overrides_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TN_TEST_CEREMONY_ID", "real_ceremony_42")
    monkeypatch.setenv("TN_TEST_LOG_PATH", "/var/log/tn.ndjson")
    monkeypatch.setenv("TN_TEST_DID", "did:key:zXYZ")

    out = _substitute_env_vars(FIXTURE_YAML, tmp_path / "tn.yaml")
    assert "id: real_ceremony_42" in out
    assert "path: /var/log/tn.ndjson" in out
    assert "did: did:key:zXYZ" in out
    # Escape still survives.
    assert "literal: ${LITERAL_TEMPLATE}" in out


def test_missing_required_var_is_diagnosable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # `TN_TEST_DID` is the only required (no-default) var in the fixture.
    monkeypatch.delenv("TN_TEST_DID", raising=False)
    p = tmp_path / "tn.yaml"
    with pytest.raises(ValueError) as exc:
        _substitute_env_vars(FIXTURE_YAML, p)
    msg = str(exc.value)
    assert "TN_TEST_DID" in msg
    assert str(p) in msg
