"""tn.secure_read() tests.

Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
section 3 + 5.3.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


_POLICY_TEXT = """\
## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting only.

### do_not_use_for
Credit decisions.

### consequences
PII present.

### on_violation_or_error
POST https://example.com/escalate
"""


def _write_policy(yaml_dir: Path) -> None:
    p = yaml_dir / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_POLICY_TEXT, encoding="utf-8")


def _user(events):
    return [e for e in events if not str(e.get("event_type", "")).startswith("tn.")]


def _tamper_log(log_path: Path, target_event: str, *, mode: str) -> None:
    """Mutate one entry in the on-disk ndjson to break a verification check.

    mode:
      'sig'  - flip a byte in the signature
      'hash' - flip a byte in row_hash
      'chain' - flip prev_hash so chain.advance fails
    """
    lines = log_path.read_text(encoding="utf-8").splitlines()
    out = []
    flipped = False
    for ln in lines:
        env = json.loads(ln)
        if not flipped and env.get("event_type") == target_event:
            if mode == "sig":
                sig = env["signature"]
                # Flip first base64 char to one that decodes differently.
                new_first = "B" if sig[0] != "B" else "C"
                env["signature"] = new_first + sig[1:]
            elif mode == "hash":
                rh = env["row_hash"]
                # Flip a hex char in the hash (after the 'sha256:' prefix).
                idx = len("sha256:")
                ch = rh[idx]
                replacement = "0" if ch != "0" else "1"
                env["row_hash"] = rh[:idx] + replacement + rh[idx + 1 :]
            elif mode == "chain":
                ph = env["prev_hash"]
                idx = len("sha256:") if ph.startswith("sha256:") else 0
                ch = ph[idx] if idx < len(ph) else "0"
                replacement = "0" if ch != "0" else "1"
                env["prev_hash"] = ph[:idx] + replacement + ph[idx + 1 :]
            flipped = True
            out.append(json.dumps(env, separators=(",", ":")))
        else:
            out.append(ln)
    log_path.write_text("\n".join(out) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_secure_read_yields_verified_entries(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", order_id="ord_1", amount=100)
    tn.info("order.created", order_id="ord_2", amount=200)
    tn.flush_and_close()

    tn.init(yaml, cipher="btn")
    user_orders = _user(list(tn.secure_read()))
    user_orders = [e for e in user_orders if e.get("event_type") == "order.created"]
    assert len(user_orders) == 2
    assert user_orders[0]["order_id"] == "ord_1"
    assert user_orders[1]["amount"] == 200


def test_secure_read_with_tn_agents_kit_yields_instructions(tmp_path):
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path)
    tn.init(yaml, cipher="btn")
    tn.info("payment.completed", order_id="ord_1", amount=100)
    tn.flush_and_close()

    tn.init(yaml, cipher="btn")
    payments = [
        e for e in tn.secure_read() if e.get("event_type") == "payment.completed"
    ]
    assert len(payments) == 1
    assert "instructions" in payments[0]
    inst = payments[0]["instructions"]
    assert inst["instruction"] == "This row records a completed payment."
    # The six tn.agents fields are NOT flattened to top level.
    assert "instruction" not in payments[0]


def test_secure_read_no_policy_no_instructions(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", order_id="ord_1")
    tn.flush_and_close()

    tn.init(yaml, cipher="btn")
    orders = [e for e in tn.secure_read() if e.get("event_type") == "order.created"]
    assert len(orders) == 1
    assert "instructions" not in orders[0]


# --------------------------------------------------------------------------
# Tampering: signature, row_hash, chain
# --------------------------------------------------------------------------


def _emit_some_user_events(yaml: Path) -> Path:
    tn.init(yaml, cipher="btn")
    tn.info("order.created", order_id="ord_1", amount=100)
    tn.info("order.created", order_id="ord_2", amount=200)
    log_path = tn.current_config().resolve_log_path()
    tn.flush_and_close()
    return log_path


def test_secure_read_skips_signature_tampered_row(tmp_path):
    yaml = tmp_path / "tn.yaml"
    log_path = _emit_some_user_events(yaml)
    _tamper_log(log_path, "order.created", mode="sig")

    tn.init(yaml, cipher="btn")
    visible = [
        e for e in tn.secure_read(on_invalid="skip")
        if e.get("event_type") == "order.created"
    ]
    # One entry got dropped.
    assert len(visible) == 1
    tn.flush_and_close()

    # A tn.read.tampered_row_skipped event was written.
    tn.init(yaml, cipher="btn")
    tampered = [
        e
        for e in tn.read()
        if e.get("event_type") == "tn.read.tampered_row_skipped"
    ]
    assert len(tampered) >= 1
    assert tampered[0]["envelope_event_type"] == "order.created"
    assert "signature" in tampered[0]["invalid_reasons"]


def test_secure_read_skips_row_hash_tampered_row(tmp_path):
    """Tampering with row_hash on the LAST entry: the chain check for
    that entry still works (it's the last one), but row_hash recompute
    fails. secure_read must skip it."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("order.created", order_id="ord_1", amount=100)
    tn.info("payment.completed", order_id="ord_1", amount=100)
    log_path = tn.current_config().resolve_log_path()
    tn.flush_and_close()

    # Tamper the last (payment.completed) entry — its row_hash break does
    # not affect any subsequent chain check (no later entries).
    _tamper_log(log_path, "payment.completed", mode="hash")

    tn.init(yaml, cipher="btn")
    payments = [
        e for e in tn.secure_read(on_invalid="skip")
        if e.get("event_type") == "payment.completed"
    ]
    # The tampered row was skipped.
    assert payments == []
    tn.flush_and_close()

    tn.init(yaml, cipher="btn")
    tampered = [
        e
        for e in tn.read()
        if e.get("event_type") == "tn.read.tampered_row_skipped"
    ]
    assert any("row_hash" in e["invalid_reasons"] for e in tampered)


def test_secure_read_skips_chain_tampered_row(tmp_path):
    yaml = tmp_path / "tn.yaml"
    log_path = _emit_some_user_events(yaml)
    _tamper_log(log_path, "order.created", mode="chain")

    tn.init(yaml, cipher="btn")
    visible = [
        e for e in tn.secure_read(on_invalid="skip")
        if e.get("event_type") == "order.created"
    ]
    assert len(visible) == 1


# --------------------------------------------------------------------------
# on_invalid="raise"
# --------------------------------------------------------------------------


def test_secure_read_raises_on_invalid(tmp_path):
    yaml = tmp_path / "tn.yaml"
    log_path = _emit_some_user_events(yaml)
    _tamper_log(log_path, "order.created", mode="sig")

    tn.init(yaml, cipher="btn")
    with pytest.raises(tn.VerificationError) as exc:
        list(tn.secure_read(on_invalid="raise"))
    assert "signature" in exc.value.invalid_reasons


# --------------------------------------------------------------------------
# on_invalid="forensic"
# --------------------------------------------------------------------------


def test_secure_read_forensic_yields_with_invalid_reasons(tmp_path):
    yaml = tmp_path / "tn.yaml"
    log_path = _emit_some_user_events(yaml)
    _tamper_log(log_path, "order.created", mode="sig")

    tn.init(yaml, cipher="btn")
    forensic = [
        e for e in tn.secure_read(on_invalid="forensic")
        if e.get("event_type") == "order.created"
    ]
    # Both entries surfaced; one carries _invalid_reasons.
    invalid = [e for e in forensic if e.get("_invalid_reasons")]
    assert len(invalid) == 1
    assert "signature" in invalid[0]["_invalid_reasons"]
    assert invalid[0]["_valid"]["signature"] is False


# --------------------------------------------------------------------------
# Tampered row + caller has all kits → still skipped
# --------------------------------------------------------------------------


def test_tampered_row_with_kit_held_still_skipped(tmp_path):
    """The verification IS the contract — even when the caller could
    decrypt the bad row, secure_read must drop it. No instructions should
    leak from a non-verifying entry."""
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path)

    tn.init(yaml, cipher="btn")
    tn.info("payment.completed", order_id="ord_1", amount=100)
    log_path = tn.current_config().resolve_log_path()
    tn.flush_and_close()

    _tamper_log(log_path, "payment.completed", mode="sig")

    tn.init(yaml, cipher="btn")
    payments = [
        e for e in tn.secure_read(on_invalid="skip")
        if e.get("event_type") == "payment.completed"
    ]
    # Skipped entirely.
    assert payments == []


def test_secure_read_invalid_value_raises(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    with pytest.raises(ValueError, match="on_invalid"):
        list(tn.secure_read(on_invalid="nope"))
