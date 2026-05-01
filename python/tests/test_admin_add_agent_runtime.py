"""tn.admin.add_agent_runtime() convenience verb.

Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
section 2.8.
"""

from __future__ import annotations

import sys
import zipfile
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


def _kit_filenames_in_bundle(tnpkg: Path) -> set[str]:
    """Return the set of ``*.btn.mykit`` filenames inside a kit bundle."""
    out: set[str] = set()
    with zipfile.ZipFile(tnpkg, "r") as z:
        for n in z.namelist():
            base = Path(n).name
            if base.endswith(".btn.mykit"):
                out.add(base)
    return out


def test_admin_add_agent_runtime_includes_tn_agents_kit(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    out = tn.admin.add_agent_runtime(
        "did:key:zRuntime1",
        groups=["default"],
        out_path=tmp_path / "agent.tnpkg",
    )
    assert out.exists()
    names = _kit_filenames_in_bundle(out)
    assert "default.btn.mykit" in names
    assert "tn.agents.btn.mykit" in names


def test_admin_add_agent_runtime_dedupes_tn_agents(tmp_path):
    """Passing tn.agents in groups list should not double-mint."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    out = tn.admin.add_agent_runtime(
        "did:key:zRuntime2",
        groups=["default", "tn.agents"],
        out_path=tmp_path / "agent.tnpkg",
    )
    names = _kit_filenames_in_bundle(out)
    # Exactly one tn.agents kit (not two).
    assert sum(1 for n in names if n == "tn.agents.btn.mykit") == 1
    assert "default.btn.mykit" in names

    # And the recipients() reducer should show exactly one new tn.agents
    # recipient with our DID (the publisher's self-kit + the new one = 2).
    rcpts = tn.admin.recipients("tn.agents")
    matching = [r for r in rcpts if r.get("recipient_did") == "did:key:zRuntime2"]
    assert len(matching) == 1


def test_admin_add_agent_runtime_unknown_group_raises(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    with pytest.raises(ValueError, match="not declared"):
        tn.admin.add_agent_runtime(
            "did:key:zX",
            groups=["doesnotexist"],
            out_path=tmp_path / "agent.tnpkg",
        )


def test_runtime_imports_bundle_and_secure_reads_instructions(tmp_path):
    """Mint a runtime bundle, ship it to a fresh ceremony, and verify
    the runtime can read the publisher's log via secure_read with
    instructions populated."""
    pub_yaml = tmp_path / "publisher" / "tn.yaml"

    # Publisher: write a policy + emit a payment.completed.
    p = pub_yaml.parent / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        """\
## payment.completed

### instruction
This is a payment row.

### use_for
Reporting only.

### do_not_use_for
Credit decisions.

### consequences
PII present.

### on_violation_or_error
POST https://example.com/escalate
""",
        encoding="utf-8",
    )

    tn.init(pub_yaml, cipher="btn")
    runtime_did = "did:key:zRuntimeAlice"
    bundle = tn.admin.add_agent_runtime(
        runtime_did,
        groups=["default"],
        out_path=tmp_path / "agent.tnpkg",
        label="alice-runtime",
    )
    tn.info("payment.completed", order_id="ord_42", amount=4999)
    pub_log = tn.current_config().resolve_log_path()
    tn.flush_and_close()

    # Runtime side: spin up a fresh ceremony and absorb the bundle.
    rt_yaml = tmp_path / "runtime" / "tn.yaml"
    tn.init(rt_yaml, cipher="btn")
    # Drop the bundled kits into the runtime's keystore directly. This
    # mirrors the absorb path for kit_bundle archives — extract every
    # ``body/*.btn.mykit`` into the keystore as ``<group>.btn.mykit``.
    rt_keystore = tn.current_config().keystore
    with zipfile.ZipFile(bundle, "r") as z:
        for n in z.namelist():
            base = Path(n).name
            if base.endswith(".btn.mykit"):
                (rt_keystore / base).write_bytes(z.read(n))
    tn.flush_and_close()

    # Re-init so the runtime picks up the new kits.
    tn.init(rt_yaml, cipher="btn")
    # Now read the publisher's log file.
    payments = []
    for entry in tn.secure_read(log_path=pub_log):
        if entry.get("event_type") == "payment.completed":
            payments.append(entry)
    assert len(payments) == 1
    inst = payments[0].get("instructions") or {}
    assert "payment row" in inst.get("instruction", "")
    # The decrypted data field is also visible.
    assert payments[0]["amount"] == 4999
