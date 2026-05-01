"""Env-var substitution in tn.config yaml loader.

Covers ``${VAR}`` and ``${VAR:-default}`` semantics, plus the
`$${literal}` escape. Mirrors the TS test in
``tn-protocol/ts-sdk/test/config_env_vars.test.ts`` and the Rust test
in ``tn-protocol/crypto/tn-core/tests/config_env_vars.rs`` for
cross-language parity.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tn.config import _substitute_env_vars


def _path(tmp_path: Path) -> Path:
    return tmp_path / "tn.yaml"


def test_required_var_present_is_substituted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TN_TEST_HOST", "atlas.cluster.example")
    out = _substitute_env_vars("uri: ${TN_TEST_HOST}\n", _path(tmp_path))
    assert out == "uri: atlas.cluster.example\n"


def test_required_var_absent_raises_with_var_and_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("TN_TEST_MISSING", raising=False)
    p = _path(tmp_path)
    with pytest.raises(ValueError) as exc:
        _substitute_env_vars("uri: ${TN_TEST_MISSING}\n", p)
    msg = str(exc.value)
    assert "TN_TEST_MISSING" in msg
    assert str(p) in msg
    # Line numbers are 1-indexed; the var is on line 1.
    assert ":1:" in msg


def test_default_used_when_var_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TN_TEST_ABSENT", raising=False)
    out = _substitute_env_vars("id: ${TN_TEST_ABSENT:-fallback_id}\n", _path(tmp_path))
    assert out == "id: fallback_id\n"


def test_default_ignored_when_var_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TN_TEST_PRESENT", "real_value")
    out = _substitute_env_vars("id: ${TN_TEST_PRESENT:-fallback}\n", _path(tmp_path))
    assert out == "id: real_value\n"


def test_empty_default_substitutes_empty_string(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("TN_TEST_EMPTY", raising=False)
    out = _substitute_env_vars('id: "${TN_TEST_EMPTY:-}"\n', _path(tmp_path))
    assert out == 'id: ""\n'


def test_escape_double_dollar_passes_through(tmp_path: Path) -> None:
    # $${LITERAL} is the docker-compose escape; it should emerge as
    # ${LITERAL} verbatim, never looked up against the environment.
    out = _substitute_env_vars("note: $${LITERAL}\n", _path(tmp_path))
    assert out == "note: ${LITERAL}\n"


def test_escape_at_start_of_line_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TN_TEST_X", "X_VAL")
    # Two independent constructs separated by whitespace: the first
    # is escaped, the second is substituted. The combined `$$${X}`
    # form is intentionally NOT supported (left ambiguous, like in
    # docker-compose's earlier releases) — callers that need both on
    # the same line should put a space between them.
    out = _substitute_env_vars("v: $${A} ${TN_TEST_X}\n", _path(tmp_path))
    assert out == "v: ${A} X_VAL\n"


def test_mixed_substitutions_yaml(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TN_TEST_DID", "did:key:zABC")
    monkeypatch.delenv("TN_TEST_LOG_DIR", raising=False)
    yaml_text = """\
ceremony:
  id: ${TN_TEST_DID}
  literal: $${LITERAL_TEMPLATE}
logs:
  path: ${TN_TEST_LOG_DIR:-./.tn/logs/tn.ndjson}
"""
    out = _substitute_env_vars(yaml_text, _path(tmp_path))
    assert "id: did:key:zABC" in out
    assert "literal: ${LITERAL_TEMPLATE}" in out
    assert "path: ./.tn/logs/tn.ndjson" in out


def test_malformed_var_name_raises(tmp_path: Path) -> None:
    # `${1FOO}` — name starts with a digit, not a valid identifier.
    p = _path(tmp_path)
    with pytest.raises(ValueError) as exc:
        _substitute_env_vars("id: ${1FOO}\n", p)
    msg = str(exc.value)
    assert "${1FOO}" in msg
    assert "malformed" in msg
    assert str(p) in msg


def test_no_recursive_expansion(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # If $X resolves to "${Y}", that text is NOT re-scanned; it lands
    # in the yaml as the literal string "${Y}". Document the behavior.
    monkeypatch.setenv("TN_TEST_RECURSE", "${TN_TEST_NESTED}")
    monkeypatch.setenv("TN_TEST_NESTED", "should_not_expand")
    out = _substitute_env_vars("v: ${TN_TEST_RECURSE}\n", _path(tmp_path))
    assert out == "v: ${TN_TEST_NESTED}\n"


def test_load_uses_substitution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: tn.config.load() expands env vars before parsing yaml."""
    from tn.config import create_fresh, load

    yaml_path = tmp_path / "tn.yaml"
    create_fresh(yaml_path, cipher="jwe")
    text = yaml_path.read_text(encoding="utf-8")

    # Replace the literal ceremony id with an env-var reference.
    cfg_real = load(yaml_path)
    real_id = cfg_real.ceremony_id
    rewritten = text.replace(f"id: {real_id}", "id: ${TN_TEST_CEREMONY_ID}")
    assert "${TN_TEST_CEREMONY_ID}" in rewritten
    yaml_path.write_text(rewritten, encoding="utf-8")

    monkeypatch.setenv("TN_TEST_CEREMONY_ID", real_id)
    cfg = load(yaml_path)
    assert cfg.ceremony_id == real_id


def test_load_propagates_missing_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tn.config import create_fresh, load

    yaml_path = tmp_path / "tn.yaml"
    create_fresh(yaml_path, cipher="jwe")
    text = yaml_path.read_text(encoding="utf-8")
    cfg_real = load(yaml_path)
    real_id = cfg_real.ceremony_id
    rewritten = text.replace(f"id: {real_id}", "id: ${TN_TEST_DEFINITELY_UNSET_VAR}")
    yaml_path.write_text(rewritten, encoding="utf-8")
    monkeypatch.delenv("TN_TEST_DEFINITELY_UNSET_VAR", raising=False)

    with pytest.raises(ValueError) as exc:
        load(yaml_path)
    assert "TN_TEST_DEFINITELY_UNSET_VAR" in str(exc.value)
    assert str(yaml_path.resolve()) in str(exc.value)
