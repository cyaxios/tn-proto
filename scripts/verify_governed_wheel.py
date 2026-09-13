"""Exercise an installed release wheel outside the source checkout."""
import importlib.metadata
import os
from pathlib import Path
import shutil
import subprocess
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
    for name in ("Session", "UseContext", "DatasetCatalog", "PolicyDag", "LineageVerifier", "ObjectRegisters", "Workflow"):
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
                opened = source.unseal(original, use=use, decide=lambda _: True)
                opened.set("amount", 84)
                result = opened.seal(use=use, to="research", decide=lambda _: True)
                assert result.id != original.id
                assert source.receive(original, use=use, decide=lambda _: True).data["amount"] == 42
                received = source.receive(result, use=use, decide=lambda _: True)
                assert received.data["amount"] == 84
                assert received.governance.sources[0].references(original)
                assert all(any(p.matches_contract(old) for p in received.policies)
                           for old in opened.policies)
        finally:
            os.chdir(previous)
    verify_examples_and_tests(checkout)
    print(f"Installed tn-proto {expected}: governed API, providers, persistent keys and enterprise examples passed")


def verify_examples_and_tests(checkout):
    with tempfile.TemporaryDirectory(prefix="tn-wheel-tests-") as temporary:
        root = Path(temporary)
        tests = root / "python" / "tests"
        tests.mkdir(parents=True)
        for source in (checkout / "python/tests").glob("test_governed*.py"):
            if source.name != "test_governed_cross_language.py":
                shutil.copy2(source, tests / source.name)
        shutil.copy2(checkout / "python/tests/test_bank_vendor_example.py", tests)
        shutil.copytree(
            checkout / "python/examples", root / "python/examples",
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
        )
        shutil.copytree(checkout / "tests/fixtures/governed", root / "tests/fixtures/governed")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.update(TN_NO_STDOUT="1", TN_NO_LINK="1", TN_VAULT_URL="http://127.0.0.1:9",
                           TN_STATE_DIR=str(root / "state"))
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             str(tests), str(root / "python/examples/enterprise")],
            cwd=root, env=environment, check=True,
        )


if __name__ == "__main__":
    main()
