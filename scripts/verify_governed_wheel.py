"""Exercise an installed release wheel outside the source checkout."""
import importlib.metadata
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import tn

README_EXAMPLE_COUNTS = {
    "key-access": 1,
    "greeting": 7,
    "bank-vendor": 1,
    "optional-rule": 1,
}

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
        verify_getting_started(checkout, root, environment)
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             str(tests), str(root / "python/examples/enterprise")],
            cwd=root, env=environment, check=True,
        )


def read_readme_examples(path):
    markdown = path.read_text(encoding="utf-8")
    pattern = r"^(`{3,}|~{3,})(python|python3|py)[ \t]*\n(.*?)^\1[ \t]*$"
    matches = list(re.finditer(pattern, markdown, re.M | re.S | re.I))
    openings = re.findall(r"^[ \t]*(?:`{3,}|~{3,})[ \t]*(?:python|python3|py)\b",
                          markdown, re.M | re.I)
    assert len(matches) == len(openings), f"{path}: unsupported or unclosed Python fence"
    blocks = []
    for match in matches:
        preceding = markdown[:match.start()].rstrip().splitlines()
        marker = re.fullmatch(r"<!-- tn-example: ([a-z0-9-]+) -->",
                              preceding[-1] if preceding else "")
        assert marker is not None, f"{path}: Python fence is missing its tn-example marker"
        name = marker.group(1)
        assert name in README_EXAMPLE_COUNTS, f"{path}: unknown tn-example group {name!r}"
        blocks.append((name, match.group(3)))
    for name, expected in README_EXAMPLE_COUNTS.items():
        actual = sum(group == name for group, _ in blocks)
        assert actual == expected, f"{path}: expected {expected} {name!r} blocks, found {actual}"
    return blocks


def verify_getting_started(checkout, root, environment):
    blocks = read_readme_examples(checkout / "README.md")
    pypi_blocks = read_readme_examples(checkout / "python/README.md")
    assert blocks == pypi_blocks, "README executable examples or group order differ"
    example = root / "python/examples/getting_started"
    shutil.copy2(example / "agents.md", root / "agents.md")
    outputs = {
        "key-access": [],
        "greeting": ["Hello, world!", "Hello again!", "Hello again!"],
        "bank-vendor": ["35", "2", "2"],
        "optional-rule": ["Hello, world!"],
    }
    key_access_setup = '''from pathlib import Path
import tn
session = tn.Session(Path("agents.md").read_text(encoding="utf-8"))
sealed = session.create({"message": "Hello, world!"}, session.policy("hello.message")).snapshot
'''
    key_access_check = '\nassert data.get("message") == "Hello, world!"\nsession.close()\n'
    commands = []
    for name, output in outputs.items():
        code = "\n\n".join(code for group, code in blocks if group == name)
        if name == "key-access":
            code = key_access_setup + code + key_access_check
        commands.append((name, [sys.executable, "-c", code], output))
    commands.append(("hello.py", [sys.executable, str(example / "hello.py")], outputs["greeting"]))
    for name, command, output in commands:
        result = subprocess.run(command, cwd=root, env=environment, text=True,
                                capture_output=True, check=True)
        assert result.stdout.splitlines() == output, f"{name}: unexpected output {result.stdout!r}"
    print("README key-access, greeting, bank-vendor, optional-rule and standalone hello.py passed")


if __name__ == "__main__":
    main()
