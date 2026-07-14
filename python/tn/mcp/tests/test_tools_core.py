"""Direct (no-transport) tests for the core verb implementations.

Each test builds a throwaway jwe ceremony in tmp_path, emits a known
spread of entries, closes the runtime, and then calls the ``*_impl``
functions exactly the way the MCP server's tool wrappers do. The impls
rebind from disk via the load-only autoinit path, mirroring how a
freshly-spawned server discovers a ceremony in its cwd.

Containment law coverage lives here too: a tampered log under
``verify="raise"`` must surface as a one-line error, never a traceback,
and bad decrypt input must come back as data, not an exception.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import tn
import tn.mcp.tools_core as tools_core
from tn.security_audit import TnSecurityWarning
from tn.mcp.schemas import DecryptInput, ReadInput
from tn.mcp.tools_core import tn_decrypt_impl, tn_read_impl, tn_status_impl

LOG_REL = Path(".tn") / "tn" / "logs" / "tn.ndjson"

ENTRY_KEYS = {
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


def _close_quietly() -> None:
    """Flush and unbind the process-global runtime between tests."""
    try:
        tn.flush_and_close()
    except Exception:  # noqa: BLE001
        # Nothing bound yet; that's the state we want anyway.
        pass


def _isolate_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_IDENTITY_DIR", str(tmp_path / "id"))
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def ceremony(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fresh jwe ceremony with three emitted entries; runtime closed.

    Leaves cwd at the ceremony dir so the impls' load-only autoinit can
    rebind from ./tn.yaml. Yields the yaml path.
    """
    _isolate_env(tmp_path, monkeypatch)
    _close_quietly()

    yaml_path = tmp_path / "tn.yaml"
    h = tn.init(str(yaml_path), cipher="jwe")
    tn.ensure_group(h.cfg, "finance", fields=["amount", "account"])
    h.invalidate_cfg()
    tn.info("order.created", order_id="A100", amount=4999)
    tn.info("order.created", order_id="A101", amount=1)
    tn.info("user.signed_in", user_id="u_1")
    tn.flush_and_close()

    yield yaml_path
    _close_quietly()


def _log_lines(tmp_path: Path) -> list[str]:
    text = (tmp_path / LOG_REL).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]


def _tamper_second_row(tmp_path: Path) -> None:
    """Flip the tail of line 2's row_hash and write the log back."""
    log_path = tmp_path / LOG_REL
    lines = _log_lines(tmp_path)
    env = json.loads(lines[1])
    env["row_hash"] = env["row_hash"][:-6] + "abcdef"
    lines[1] = json.dumps(env, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------- #
#  tn_status                                                            #
# --------------------------------------------------------------------- #


def test_status_shape(ceremony, tmp_path):
    out = tn_status_impl()
    assert "error" not in out
    assert out["did"].startswith("did:key:z6Mk")
    assert Path(out["yaml_path"]) == ceremony
    assert out["ceremony_id"].startswith("local_")
    assert out["cipher"] == "jwe"
    assert out["sign"] is True
    assert out["chain"] is True
    assert isinstance(out["rust_path"], bool)
    groups = {g["name"]: g["fields"] for g in out["groups"]}
    assert "default" in groups
    assert groups["finance"] == ["account", "amount"]  # sorted


def test_status_no_ceremony_returns_error_payload(tmp_path, monkeypatch):
    """No ceremony anywhere: a contained {error, detail} payload, no raise."""
    _isolate_env(tmp_path, monkeypatch)
    _close_quietly()
    out = tn_status_impl()
    assert out["error"].startswith("No ceremony found")
    assert "tn init" in out["error"]
    assert "no ceremony found" in out["detail"]


# --------------------------------------------------------------------- #
#  tn_read                                                              #
# --------------------------------------------------------------------- #


def test_read_limit_and_truncation(ceremony):
    out = tn_read_impl(ReadInput(limit=2))
    assert out["total_scanned"] == 3
    assert out["returned"] == 2
    assert out["truncated"] is True
    assert set(out["entries"][0]) == ENTRY_KEYS
    first = out["entries"][0]
    assert first["event_type"] == "order.created"
    assert first["sequence"] == 1
    assert first["fields"] == {"order_id": "A100", "amount": 4999}

    everything = tn_read_impl(ReadInput())
    assert everything["returned"] == 3
    assert everything["truncated"] is False


def test_read_event_type_exact_and_prefix(ceremony):
    exact = tn_read_impl(ReadInput(event_type="user.signed_in"))
    assert exact["returned"] == 1
    assert exact["entries"][0]["fields"] == {"user_id": "u_1"}

    prefix = tn_read_impl(ReadInput(event_type="order.*"))
    assert prefix["returned"] == 2
    assert {e["event_type"] for e in prefix["entries"]} == {"order.created"}


def test_read_fields_equal(ceremony):
    one = tn_read_impl(ReadInput(fields_equal={"order_id": "A100"}))
    assert one["returned"] == 1
    assert one["entries"][0]["fields"]["order_id"] == "A100"

    # Values compare via str(), so a numeric field matches its string form.
    numeric = tn_read_impl(ReadInput(fields_equal={"amount": "1"}))
    assert numeric["returned"] == 1
    assert numeric["entries"][0]["fields"]["order_id"] == "A101"

    missing = tn_read_impl(ReadInput(fields_equal={"no_such_field": "x"}))
    assert missing["returned"] == 0
    assert missing["truncated"] is False


def test_read_since_until_bounds(ceremony):
    past = "2000-01-01T00:00:00Z"
    future = "2100-01-01T00:00:00Z"

    assert tn_read_impl(ReadInput(since=past))["returned"] == 3
    assert tn_read_impl(ReadInput(until=future))["returned"] == 3

    none_yet = tn_read_impl(ReadInput(since=future))
    assert none_yet["returned"] == 0
    assert none_yet["total_scanned"] == 3

    assert tn_read_impl(ReadInput(until=past))["returned"] == 0


def test_read_bad_timestamp_is_one_clear_line(ceremony):
    with pytest.raises(ValueError) as excinfo:
        tn_read_impl(ReadInput(since="not-a-date"))
    message = str(excinfo.value)
    assert "not a valid ISO-8601" in message
    assert "not-a-date" in message
    assert "\n" not in message


def test_read_verify_false_returns_tampered_rows(ceremony, tmp_path):
    """Only the explicit compatibility switch disables checks."""
    _tamper_second_row(tmp_path)
    with pytest.warns(TnSecurityWarning):
        out = tn_read_impl(ReadInput(verify=False))
    assert out["returned"] == 3


def test_read_default_auto_rejects_tampered_rows(ceremony, tmp_path):
    _tamper_second_row(tmp_path)
    with pytest.raises(RuntimeError, match=r"tn_read failed \(-32001\)"):
        tn_read_impl(ReadInput())


def test_read_verify_raise_surfaces_one_line(ceremony, tmp_path):
    _tamper_second_row(tmp_path)
    for mode in ("raise", True):
        with pytest.raises(RuntimeError) as excinfo:
            tn_read_impl(ReadInput(verify=mode))
        message = str(excinfo.value)
        assert message.startswith("tn_read failed (-32001)")
        assert "seq=2" in message
        assert "order.created" in message
        # Containment law: one clear sentence, never a stack trace.
        assert "\n" not in message
        assert "Traceback" not in message


def test_read_verify_skip_drops_tampered_row(ceremony, tmp_path):
    _tamper_second_row(tmp_path)
    out = tn_read_impl(ReadInput(verify="skip"))
    assert out["returned"] == 2
    seen = {(e["event_type"], e["sequence"]) for e in out["entries"]}
    assert ("order.created", 2) not in seen
    assert seen == {("order.created", 1), ("user.signed_in", 1)}


def test_read_forwards_every_trust_policy_parameter(monkeypatch):
    captured: dict[str, Any] = {}

    def fake_read(selector, **kwargs):
        captured["selector"] = selector
        captured.update(kwargs)
        return iter(())

    monkeypatch.setattr(tools_core, "_tn_read", fake_read)
    out = tn_read_impl(
        ReadInput(
            verify=False,
            require_signature=False,
            allow_unauthenticated=True,
            trusted_writers=["did:key:z6MkhDA92BRnspkcBZVVMhfdRVhZSHWejjYqUipaj8zvXUs5"],
            allow_unknown_writers=True,
            log="admin",
        ),
    )

    assert out["returned"] == 0
    assert captured == {
        "selector": None,
        "filter": None,
        "verify": False,
        "require_signature": False,
        "allow_unauthenticated": True,
        "trusted_writers": [
            "did:key:z6MkhDA92BRnspkcBZVVMhfdRVhZSHWejjYqUipaj8zvXUs5",
        ],
        "allow_unknown_writers": True,
        "log": "admin",
    }


# --------------------------------------------------------------------- #
#  tn_decrypt                                                           #
# --------------------------------------------------------------------- #


def test_decrypt_round_trip_with_per_line_failure(ceremony, tmp_path):
    lines = _log_lines(tmp_path)
    content = lines[0] + "\n" + lines[1] + "\n{garbage\n"
    out = tn_decrypt_impl(DecryptInput(content=content))
    assert "error" not in out
    assert out["total_lines"] == 3
    assert out["returned"] == 2
    assert out["signatures_checked"] is True

    rows = out["entries"]
    assert [r["line"] for r in rows] == [1, 2]
    assert all(r["signature_valid"] and r["chain_valid"] for r in rows)
    assert rows[0]["entry"]["fields"] == {"order_id": "A100", "amount": 4999}
    assert rows[1]["entry"]["fields"] == {"order_id": "A101", "amount": 1}

    assert len(out["failures"]) == 1
    failure = out["failures"][0]
    assert failure["line"] == 3
    assert failure["error"].startswith("invalid JSON")
    assert "Traceback" not in failure["error"]

    # The decrypted rows agree with what tn.read sees on the same log.
    read_back = tn_read_impl(ReadInput(event_type="order.created"))
    assert [r["entry"]["fields"] for r in rows] == [
        e["fields"] for e in read_back["entries"]
    ]


def test_decrypt_group_filter(ceremony, tmp_path):
    lines = _log_lines(tmp_path)
    out = tn_decrypt_impl(DecryptInput(content=lines[0], group="finance"))
    assert out["returned"] == 1
    fields = out["entries"][0]["entry"]["fields"]
    assert fields == {"amount": 4999}  # order_id rides in 'default', excluded


def test_decrypt_non_envelope_lines_fail_per_line(ceremony):
    content = '{"event_type": "x"}\n[1, 2, 3]\n\n'
    out = tn_decrypt_impl(DecryptInput(content=content))
    assert out["total_lines"] == 2  # the blank line is ignored
    assert out["returned"] == 0
    errors = {f["line"]: f["error"] for f in out["failures"]}
    assert errors[1].startswith("not a TN envelope: missing")
    assert "prev_hash" in errors[1] and "row_hash" in errors[1]
    assert errors[2] == "not a TN envelope: JSON value is not an object"


def test_decrypt_bad_yaml_is_contained(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    _close_quietly()
    missing = tmp_path / "missing.yaml"
    out = tn_decrypt_impl(DecryptInput(content="{}", yaml=str(missing)))
    assert out["error"].startswith("Could not load ceremony yaml")
    assert "missing.yaml" in out["error"]


def test_decrypt_no_ceremony_is_contained(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    _close_quietly()
    out = tn_decrypt_impl(DecryptInput(content="{}"))
    assert out["error"].startswith("No ceremony found")
    assert "detail" in out
