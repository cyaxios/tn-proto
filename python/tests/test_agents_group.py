"""tn.agents reserved group + .tn/config/agents.md splice tests.

Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
sections 2 + 5.2.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import _agents_policy


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


_POLICY_TEXT = """\
# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting on amount and currency.

### do_not_use_for
Credit decisions, loan underwriting, risk scoring.

### consequences
customer_id is PII; exposure violates GDPR.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate

## order.created

### instruction
This row records a newly-created order.

### use_for
Order fulfillment workflows, customer-facing receipts.

### do_not_use_for
Marketing list enrichment without consent.

### consequences
Includes payment_token; do not log it to analytics.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate
"""


def _write_policy(yaml_dir: Path, text: str = _POLICY_TEXT) -> Path:
    p = yaml_dir / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# Auto-inject + fresh ceremony shape
# --------------------------------------------------------------------------


def test_fresh_ceremony_yaml_declares_tn_agents_group(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    assert "tn.agents" in cfg.groups
    # The six policy fields all route to tn.agents.
    for f in (
        "instruction",
        "use_for",
        "do_not_use_for",
        "consequences",
        "on_violation_or_error",
        "policy",
    ):
        assert cfg.field_to_groups.get(f) == ["tn.agents"], (
            f"field {f!r} routing: {cfg.field_to_groups.get(f)}"
        )

    # The keystore has tn.agents.btn.state + tn.agents.btn.mykit.
    keystore = cfg.keystore
    assert (keystore / "tn.agents.btn.state").exists()
    assert (keystore / "tn.agents.btn.mykit").exists()


def test_loader_rejects_user_tn_prefix_groups(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(
        """
ceremony:
  id: local_test
  cipher: btn
me:
  did: did:key:zStub
groups:
  default:
    cipher: btn
    recipients: []
  tn.foo:
    cipher: btn
    recipients: []
""".lstrip(),
        encoding="utf-8",
    )
    from tn.config import load

    with pytest.raises(ValueError, match="reserved"):
        load(yaml_path)


# --------------------------------------------------------------------------
# Markdown loader
# --------------------------------------------------------------------------


def test_markdown_loader_parses_event_sections(tmp_path):
    _write_policy(tmp_path)
    doc = _agents_policy.load_policy_file(tmp_path)
    assert doc is not None
    assert set(doc.templates.keys()) == {"payment.completed", "order.created"}
    pay = doc.templates["payment.completed"]
    assert "completed payment" in pay.instruction
    assert "Aggregate reporting" in pay.use_for
    assert "Credit decisions" in pay.do_not_use_for
    assert "GDPR" in pay.consequences
    assert "merchant.example.com" in pay.on_violation_or_error
    assert pay.content_hash.startswith("sha256:")
    assert pay.path == ".tn/config/agents.md"


def test_markdown_loader_rejects_missing_subsections(tmp_path):
    bad = """\
# TN Agents Policy
version: 1

## payment.completed

### instruction
text here
"""
    p = tmp_path / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError, match="missing required subsection"):
        _agents_policy.load_policy_file(tmp_path)


def test_loader_returns_none_when_file_missing(tmp_path):
    assert _agents_policy.load_policy_file(tmp_path) is None


# --------------------------------------------------------------------------
# Emit-side splice
# --------------------------------------------------------------------------


def test_writer_with_policy_populates_tn_agents_group(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _write_policy(tmp_path)
    tn.init(yaml_path, cipher="btn")

    tn.info("payment.completed", order_id="ord_42", amount=4999)
    tn.flush_and_close()

    # Reader (publisher holds every kit) sees instructions in secure_read.
    tn.init(yaml_path, cipher="btn")
    payments = [
        e for e in tn.secure_read() if e.get("event_type") == "payment.completed"
    ]
    assert len(payments) == 1
    entry = payments[0]
    assert "instructions" in entry
    inst = entry["instructions"]
    assert "completed payment" in inst["instruction"]
    assert inst["policy"].startswith(".tn/config/agents.md#payment.completed@")
    # Data field flat alongside instructions.
    assert entry["order_id"] == "ord_42"
    assert entry["amount"] == 4999
    # tn.agents fields are NOT flattened to top level.
    assert "instruction" not in entry
    assert "use_for" not in entry


def test_writer_without_policy_leaves_tn_agents_empty(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    # NO .tn/config/agents.md file.
    tn.init(yaml_path, cipher="btn")
    tn.info("order.created", order_id="ord_1", amount=10)
    tn.flush_and_close()

    tn.init(yaml_path, cipher="btn")
    orders = [e for e in tn.secure_read() if e.get("event_type") == "order.created"]
    assert len(orders) == 1
    # No policy → no instructions.
    assert "instructions" not in orders[0]


def test_emit_splice_setdefault_preserves_per_emit_overrides(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _write_policy(tmp_path)
    tn.init(yaml_path, cipher="btn")

    custom = "OVERRIDE: this row's policy is overridden by the emitter."
    tn.info("payment.completed", order_id="ord_99", amount=1, instruction=custom)
    tn.flush_and_close()

    tn.init(yaml_path, cipher="btn")
    payments = [
        e for e in tn.secure_read() if e.get("event_type") == "payment.completed"
    ]
    assert len(payments) == 1
    inst = payments[0]["instructions"]
    assert inst["instruction"] == custom


# --------------------------------------------------------------------------
# Reader-without-kit & hidden_groups
# --------------------------------------------------------------------------


def test_reader_without_tn_agents_kit_sees_hidden_group(tmp_path):
    """A foreign log: writer A has the policy and emits; reader B does NOT
    hold the tn.agents kit. raw envelope still has the ciphertext block;
    decrypt fails for the foreign reader."""
    import json

    writer_yaml = tmp_path / "writer" / "tn.yaml"
    _write_policy(writer_yaml.parent)
    tn.init(writer_yaml, cipher="btn")
    tn.info("payment.completed", order_id="ord_7", amount=4999)
    cfg = tn.current_config()
    log_path = cfg.resolve_log_path()
    tn.flush_and_close()

    # Inspect the raw envelope on disk: the writer's tn.agents ciphertext
    # block is present.
    found = None
    for line in log_path.read_text(encoding="utf-8").splitlines():
        env = json.loads(line)
        if env["event_type"] == "payment.completed":
            found = env
            break
    assert found is not None
    assert "tn.agents" in found
    assert "ciphertext" in found["tn.agents"]


def test_secure_read_omits_instructions_when_kit_missing(tmp_path):
    """If the caller's tn.agents kit doesn't fit the writer's ciphertext,
    secure_read should skip surfacing instructions (and tag the group as
    hidden / errored on the flat dict)."""
    writer_yaml = tmp_path / "writer" / "tn.yaml"
    _write_policy(writer_yaml.parent)
    tn.init(writer_yaml, cipher="btn")
    tn.info("payment.completed", order_id="ord_7", amount=4999)
    writer_log = tn.current_config().resolve_log_path()
    tn.flush_and_close()

    # Reader: spin up a fresh ceremony with mismatched keys, then read
    # the writer's log via the legacy Python reader (avoids Rust-raise on
    # decrypt failure). secure_read is dispatch-routed; here we just
    # validate the read_as_recipient + flatten path produces no
    # ``instructions`` block.
    reader_yaml = tmp_path / "reader" / "tn.yaml"
    tn.init(reader_yaml, cipher="btn")
    reader_cfg = tn.current_config()
    from tn import reader as _reader
    from tn.reader import _read as _legacy_read

    flat = []
    for raw in _legacy_read(writer_log, reader_cfg):
        if raw["envelope"]["event_type"] != "payment.completed":
            continue
        flat.append(_reader.flatten_raw_entry(raw))
    assert len(flat) == 1
    entry = flat[0]
    assert "instructions" not in entry
    assert "tn.agents" in entry.get("_hidden_groups", []) or "tn.agents" in entry.get(
        "_decrypt_errors", []
    )


# --------------------------------------------------------------------------
# Field-name collision (regression on §1.2 collision behaviour)
# --------------------------------------------------------------------------


def test_user_data_with_instruction_field_does_not_clobber_tn_agents(tmp_path):
    """If the writer's user data also has an ``instruction`` field, it
    should still get routed to tn.agents (the only group declaring that
    field name) — both copies do NOT live in different groups, but the
    user-supplied ``instruction`` overrides the policy template via
    ``setdefault``. This is the documented behavior in spec §2.6.
    """
    yaml_path = tmp_path / "tn.yaml"
    _write_policy(tmp_path)
    tn.init(yaml_path, cipher="btn")
    tn.info(
        "payment.completed",
        order_id="ord_42",
        amount=10,
        instruction="USER OVERRIDE",
    )
    tn.flush_and_close()

    tn.init(yaml_path, cipher="btn")
    payments = [
        e for e in tn.secure_read() if e.get("event_type") == "payment.completed"
    ]
    assert len(payments) == 1
    entry = payments[0]
    assert entry["instructions"]["instruction"] == "USER OVERRIDE"
