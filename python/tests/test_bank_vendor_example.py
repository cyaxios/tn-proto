"""Exercise the example's real signatures, group capabilities and decisions."""
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import tn


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "bank_vendor.py"


def test_bank_vendor_command_reports_verified_result():
    result = subprocess.run(
        [sys.executable, "-B", str(EXAMPLE)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "Aggregate: 35", "Contracts: 2", "Sources: 2",
        "Identity: unavailable", "Denied use: no business data returned",
    ]


def test_aggregate_keeps_exact_contracts_and_sources_without_identity():
    example = runpy.run_path(str(EXAMPLE))
    with example["configured"]() as parties:
        inputs = example["publish_inputs"](parties)
        result = example["aggregate"](parties, inputs)
        report = parties.bank.receive(result, purpose="inspect-report")
        assert parties.bank.did != parties.vendor.did
        assert result.writer == parties.vendor.did
        assert result.object_type == "vendor.report"
        assert set(result.group_names) == {"amounts", "tn.agents"}
        assert report.get(group="amounts") == {"aggregate": 35}
        assert not report.hidden_groups
        assert len(report.policies) == 2
        assert any(p.matches_contract(parties.bank_contract) for p in report.policies)
        assert any(p.matches_contract(parties.report_contract) for p in report.policies)
        sources = report.governance.sources
        assert {source.object_id for source in sources} == {item.id for item in inputs}
        assert len(sources) == 2
        assert all(source.writer == parties.bank.did for source in sources)
        assert b'"Alice"' not in result.forward()
        assert b'"Bob"' not in result.forward()


def test_vendor_cannot_open_identity_even_with_a_permissive_decision():
    example = runpy.run_path(str(EXAMPLE))
    with example["configured"]() as parties:
        first, _ = example["publish_inputs"](parties)
        admitted = parties.vendor.receive(first, purpose="aggregate")
        assert admitted.get("values", group="amounts") == [12, 18]
        assert admitted.hidden_groups == ["identity"]
        with pytest.raises(tn.governed.NotEntitled):
            parties.vendor.receive(
                first, use=tn.UseContext("vendor", "probe", "read"),
                groups=["identity"], decide=lambda _: True,
            )


@pytest.mark.parametrize("rejected", ["writer", "contract", "use"])
def test_admission_refuses_unapproved_input_before_returning_business_data(rejected):
    example = runpy.run_path(str(EXAMPLE))
    with example["configured"]() as parties:
        source = example["publish_inputs"](parties)[0]
        purpose = "aggregate"
        if rejected == "writer":
            source = parties.vendor.create(
                {"values": [900]}, parties.bank_contract, group="amounts"
            ).snapshot
        elif rejected == "contract":
            altered = tn.Governance.from_markdown(
                parties.bank.did,
                example["BANK_POLICY"].replace("Approved aggregate reporting.", "Marketing."),
                "bank-policy.md", "bank.batch",
            )
            source = parties.bank.create({"values": [900]}, altered, group="amounts").snapshot
        else:
            purpose = "marketing"
        returned = []
        with pytest.raises(tn.governed.UseDenied):
            returned.append(parties.vendor.receive(source, purpose=purpose))
        assert returned == []
