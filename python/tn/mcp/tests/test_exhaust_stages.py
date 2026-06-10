"""Stage tests for the ported Know-Your-Exhaust engine (tn.mcp.exhaust).

Every test runs on small synthetic fixtures built in tmp_path - no committed
samples, no network. The durable surfaces (registry DB, sensitivity cache) are
repointed at tmp_path so no test writes into the package dir or the repo.

Coverage:
  - profile          : JSON-lines vs plain-text detection, with a checkpoint
  - inventory_exhaust: record/event-type/category counts on both formats
  - mine_templates   : drain3 collapses repeated lines; contained when absent
  - classify_fields  : value PII flagged, opaque business ids stay non-linking
  - linkage_graph    : a value threading two event types surfaces as a join key
  - emit_hook        : default-private routing; kit written under an out_dir
  - registry         : remember -> human pin survives re-runs -> linkage
                       escalation -> unwind -> clear
  - decrypt_stream   : init failure surfaces as a clear error dict, no raise
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tn.mcp.exhaust import registry as _reg
from tn.mcp.exhaust import sensitivity as _sens
from tn.mcp.exhaust import stages


@pytest.fixture(autouse=True)
def _isolated_engine_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Repoint the engine's durable state at tmp_path and chdir there.

    The registry DB default is cwd-relative and the sensitivity cache sits
    next to the module, so both are patched per test: stage calls must never
    touch the package dir, and no classification bleeds between tests.
    """
    monkeypatch.setattr(_reg, "DB_PATH", tmp_path / "exhaust_registry.db")
    monkeypatch.setattr(_sens, "CACHE_PATH", tmp_path / "sensitivity_cache.json")
    monkeypatch.chdir(tmp_path)


# --- synthetic fixtures ------------------------------------------------------

_ORDERS = [
    ("ord_1001", "alice@example.com", "10.0.0.1", "visit_abc", 124.5),
    ("ord_1002", "bob@example.com", "10.0.0.2", "visit_def", 75.0),
    ("ord_1003", "carol@example.com", "10.0.0.3", "visit_ghi", 19.99),
    ("ord_1004", "dave@example.com", "10.0.0.4", "visit_jkl", 200.0),
]


def _event_records() -> list[dict]:
    """8 JSON records, 2 event types. correlation_id threads the pair for each
    order (the planted join key); email/ip are the planted value PII and appear
    in only ONE event type so they never bridge."""
    rows: list[dict] = []
    for oid, email, ip, corr, amount in _ORDERS:
        rows.append({"event_type": "order.created", "order_id": oid,
                     "email": email, "ip": ip, "correlation_id": corr,
                     "amount": amount, "status": "ok"})
    for i, (_oid, _email, _ip, corr, _amount) in enumerate(_ORDERS, 1):
        rows.append({"event_type": "payment.captured", "payment_id": f"pay_200{i}",
                     "correlation_id": corr, "status": "ok", "method": "card"})
    return rows


@pytest.fixture
def events_ndjson(tmp_path: Path) -> Path:
    p = tmp_path / "events.ndjson"
    p.write_text("\n".join(json.dumps(r) for r in _event_records()) + "\n",
                 encoding="utf-8")
    return p


@pytest.fixture
def plain_log(tmp_path: Path) -> Path:
    """10 plain-text lines from two repeated templates, with planted IPs and
    emails so the value detectors (not field names) do the work."""
    lines = []
    for i, ip in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7",
                            "10.0.0.8", "10.0.0.9", "10.0.0.10"]):
        lines.append(f"2026-06-09 10:00:0{i} INFO Accepted connection "
                     f"from {ip} port 5{i}022")
    for i, email in enumerate(["bob@example.com", "carol@example.com",
                               "dave@example.com", "erin@example.com"]):
        lines.append(f"2026-06-09 10:01:0{i} ERROR Failed password "
                     f"for {email} after 3 attempts")
    p = tmp_path / "plain.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# --- profile ------------------------------------------------------------------

def test_profile_detects_json_lines(events_ndjson: Path) -> None:
    out = stages.profile(str(events_ndjson))
    assert out["format"] == "json"
    assert out["example"].startswith("{")
    # the detected shape is surfaced as a checkpoint, never silently resolved
    assert len(out["decisions"]) == 1
    d = out["decisions"][0]
    assert set(d) == {"stage", "id", "finding", "question", "options", "recommended"}
    assert d["stage"] == "profile"
    assert d["recommended"] in d["options"]


def test_profile_detects_plain_text(plain_log: Path) -> None:
    out = stages.profile(str(plain_log))
    assert out["format"] == "freetext"
    assert out["decisions"][0]["stage"] == "profile"
    assert "freetext" in out["decisions"][0]["finding"]


# --- inventory_exhaust ----------------------------------------------------------

def test_inventory_exhaust_counts_json_events(events_ndjson: Path) -> None:
    inv = stages.inventory_exhaust(str(events_ndjson))
    assert inv["record_count"] == 8
    assert inv["format"] == "json"
    assert inv["event_type_count"] == 2
    assert inv["categories"] == ["order", "payment"]
    assert inv["events"]["order.created"]["count"] == 4
    assert inv["events"]["payment.captured"]["count"] == 4
    leaves = {f["leaf"]: f for f in inv["events"]["order.created"]["fields"]}
    assert "alice@example.com" in leaves["email"]["samples"]
    assert leaves["correlation_id"]["distinct"] == 4
    assert leaves["email"]["example_context"]  # full-record context travels along


def test_inventory_exhaust_accepts_in_memory_records() -> None:
    inv = stages.inventory_exhaust(_event_records())
    assert inv["record_count"] == 8
    assert inv["format"] == "json"
    assert inv["event_type_count"] == 2


def test_inventory_exhaust_recovers_structure_from_plain_text(plain_log: Path) -> None:
    inv = stages.inventory_exhaust(str(plain_log))
    assert inv["record_count"] == 10
    assert inv["format"] == "plain-text (freetext)"
    assert inv["event_type_count"] == 2
    assert inv["categories"] == ["accepted", "failed"]


# --- mine_templates -------------------------------------------------------------

def test_mine_templates_collapses_repeated_lines(plain_log: Path) -> None:
    out = stages.mine_templates(str(plain_log))
    assert "error" not in out
    assert out["line_count"] == 10
    assert out["template_count"] == 2
    counts = sorted(t["count"] for t in out["templates"])
    assert counts == [4, 6]
    assert all(t["slug"] for t in out["templates"])
    # the variable slots (ip / email / port) are parameterized away
    assert any("<*>" in t["template"] for t in out["templates"])


def test_mine_templates_contained_when_drain3_missing(
    plain_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stages, "_HAVE_DRAIN3", False)
    out = stages.mine_templates(str(plain_log))
    assert out["templates"] == []
    assert "drain3" in out["error"]
    assert "pip install drain3" in out["error"]


# --- classify_fields ------------------------------------------------------------

def test_classify_fields_flags_value_pii(events_ndjson: Path) -> None:
    inv = stages.inventory_exhaust(str(events_ndjson))
    rep = stages.classify_fields(inv)
    assert rep["record_count"] == 8
    fields = {f["leaf"]: f for f in rep["events"]["order.created"]["fields"]}

    assert fields["email"]["class"] == "pii_direct"
    assert fields["email"]["confidence"] >= 0.9
    assert fields["email"]["recommended_group"] == "pii"
    assert "value:email" in fields["email"]["detectors"]

    assert fields["ip"]["class"] == "pii_direct"
    assert fields["ip"]["recommended_group"] == "pii"

    # an opaque business id is NOT person-linking in isolation
    assert fields["order_id"]["class"] == "id"
    assert fields["order_id"]["recommended_group"] not in (
        "pii", "identity", "geo_device", "clinical")

    # low-confidence fields come back as checkpoints for the agent to ask about
    decision_ids = {d["id"] for d in rep["decisions"]}
    assert "field:amount" in decision_ids


# --- linkage_graph --------------------------------------------------------------

def test_linkage_graph_surfaces_cross_event_join_key(events_ndjson: Path) -> None:
    out = stages.linkage_graph(str(events_ndjson))
    assert out["record_count"] == 8
    candidates = {c["field"]: c for c in out["linkage_candidates"]}
    # correlation_id is the ONLY join key: each value threads both event types.
    # email/ip/order_id live in one event type; status/method are denylisted.
    assert list(candidates) == ["correlation_id"]
    corr = candidates["correlation_id"]
    assert corr["spans_event_types"] == ["order.created", "payment.captured"]
    assert corr["max_threaded_event_types"] == 2
    assert corr["bridging_value_count"] == 4
    assert "join key" in corr["risk"]
    assert set(corr["example_bridges"]).issubset(
        {"visit_abc", "visit_def", "visit_ghi", "visit_jkl"})


# --- emit_hook ------------------------------------------------------------------

def test_emit_hook_routes_default_private(events_ndjson: Path) -> None:
    rep = stages.classify_fields(stages.inventory_exhaust(str(events_ndjson)))
    out = stages.emit_hook(rep)
    assert out["written_to"] is None
    assert out["review_count"] == len(out["review_flags"]) > 0

    kit = yaml.safe_load(out["kit_yaml"])
    assert kit["default_policy"] == "private"
    assert kit["groups"]["pii"]["fields"] == ["email", "ip"]
    assert kit["groups"]["pii"]["policy"] == "private"
    # unclassified and opaque-id fields fall to the encrypted default group,
    # never to the clear
    assert {"amount", "correlation_id", "order_id", "payment_id"} <= set(
        kit["groups"]["default"]["fields"])
    # only the operational allowlist rides public
    assert set(kit["public_fields"]) == {"event_type", "status", "method"}
    assert "email" not in kit["public_fields"]


def test_emit_hook_writes_derived_kit(events_ndjson: Path, tmp_path: Path) -> None:
    rep = stages.classify_fields(stages.inventory_exhaust(str(events_ndjson)))
    out_dir = tmp_path / ".tn"
    out = stages.emit_hook(rep, out_dir=str(out_dir))
    written = Path(out["written_to"])
    assert written == out_dir / "kye-kit.yaml"
    assert written.exists()
    assert (out_dir / "kye-agents.md").exists()
    kit = yaml.safe_load(written.read_text(encoding="utf-8"))
    assert "email" in kit["groups"]["pii"]["fields"]


# --- registry lifecycle ---------------------------------------------------------

def test_registry_lifecycle(events_ndjson: Path) -> None:
    assert stages.registry_status()["empty"] is True

    inv = stages.inventory_exhaust(str(events_ndjson))
    rep = stages.classify_fields(inv)

    # remember: one observation per field per event type
    rec = stages.remember_classification(rep)
    assert rec["recorded"] == 12
    status = stages.registry_status()
    assert status["empty"] is False
    assert status["field_count"] == 9
    assert set(status["sensitive_fields"]) == {"email", "ip"}
    assert status["by_source"] == {"detector": 9}

    # human pin wins and survives a later detector pass
    pinned = stages.set_field_group("order_id", "identity", note="ops pinned")
    assert pinned["overridden"] is True
    assert "order_id" in pinned["groups"]["identity"]
    stages.remember_classification(rep)
    assert "order_id" in stages.groups_registry()["groups"]["identity"]
    assert stages.registry_status()["human_overrides"] == 1

    # linkage escalates the join key into identity (it was non-sensitive)
    linkage = stages.linkage_graph(str(events_ndjson))
    applied = stages.apply_linkage(linkage)
    assert applied["escalated"] == ["correlation_id"]
    assert applied["kept_already_restricted"] == []
    assert "correlation_id" in applied["groups"]["identity"]
    assert stages.registry_status()["linkage_escalations"] == 1

    # unwind steps the escalation back to the prior group
    undone = stages.unwind()
    assert undone["unwound"] == "correlation_id"
    assert undone["restored_group"] == "public"
    groups = stages.groups_registry()["groups"]
    assert "correlation_id" not in groups.get("identity", [])
    assert "order_id" in groups["identity"]  # the human pin remains

    # clear empties the catalog
    cleared = stages.clear_registry()
    assert cleared == {"cleared": 9, "field_count": 0}
    assert stages.registry_status()["empty"] is True


def test_registry_overlay_reaches_emitted_kit(events_ndjson: Path) -> None:
    """A human pin in the registry lands in the synthesized kit when
    emit_hook(use_registry=True) is asked for, including the public demotion."""
    rep = stages.classify_fields(stages.inventory_exhaust(str(events_ndjson)))
    stages.remember_classification(rep)
    stages.set_field_group("amount", "clinical", note="dosage amounts here")
    out = stages.emit_hook(rep, use_registry=True)
    assert out["registry_overlaid_fields"] > 0
    kit = yaml.safe_load(out["kit_yaml"])
    assert "amount" in kit["groups"]["clinical"]["fields"]
    assert "amount" not in kit["groups"].get("default", {}).get("fields", [])


# --- decrypt_stream containment -------------------------------------------------

def test_decrypt_stream_contains_init_failure(tmp_path: Path) -> None:
    """A broken tn.yaml surfaces as a clear error dict - the engine never
    raises into the host and never leaks a traceback where a sentence does."""
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "tn.yaml").write_text("not: [valid: yaml: {", encoding="utf-8")
    result = stages.decrypt_stream(
        log=str(tmp_path / "missing.ndjson"), tn_yaml=str(broken / "tn.yaml"))
    assert result["rows"] == []
    assert result["error"].startswith("tn.init failed:")
    assert "Traceback" not in result["error"]
