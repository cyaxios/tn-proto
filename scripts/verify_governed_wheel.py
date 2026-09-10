"""Exercise an installed release wheel outside the source checkout."""
import importlib.metadata
import os
from pathlib import Path
import sys
import tempfile

import tn

POLICY = """## research.sample
### instruction
Prepare aggregate research.
### use_for
Aggregate analysis.
### do_not_use_for
Individual disclosure.
### consequences
Review the contract.
### on_violation_or_error
Refuse the operation.
"""


def main():
    expected = sys.argv[1]
    assert importlib.metadata.version("tn-proto") == expected
    checkout = Path(__file__).resolve().parents[1]
    assert not Path(tn.__file__).resolve().is_relative_to(checkout)
    assert tn._native.__file__.endswith((".pyd", ".so"))
    for name in ("Session", "UseContext", "DatasetCatalog", "PolicyDag", "LineageVerifier"):
        assert hasattr(tn, name), name
    with tempfile.TemporaryDirectory() as temporary:
        previous = Path.cwd()
        os.chdir(temporary)
        try:
            with tn.Session(POLICY) as source, tn.Session(POLICY) as other:
                assert source.did != other.did
                use = tn.UseContext("analytics", "aggregate_research", "calculate")
                data = source.create_obj({"amount": 42}, source.policy("research.sample"),
                                         object_type="research.sample")
                original = data.snapshot
                try:
                    source.receive(original, use=use, decide=lambda _: False)
                except tn.governed.UseDenied:
                    pass
                else:
                    raise AssertionError("Rejected use exposed a working object")
                try:
                    other.governance(original)
                except tn.governed.NotEntitled:
                    pass
                else:
                    raise AssertionError("Independent session opened unassigned governance")
                opened = source.receive(original, use=use, decide=lambda _: True)
                opened.data["amount"] = 84
                result = opened.release(use=use, to="research", decide=lambda _: True)
                assert result.id != original.id
                assert source.receive(original, use=use, decide=lambda _: True).data["amount"] == 42
                received = source.receive(result, use=use, decide=lambda _: True)
                assert received.data["amount"] == 84
                assert received.governance.sources[0].references(original)
                assert all(any(p.matches_contract(old) for p in received.policies)
                           for old in opened.policies)
        finally:
            os.chdir(previous)
    print(f"Installed tn-proto {expected}: native sessions, admission, mutation, lineage and release passed")


if __name__ == "__main__":
    main()
