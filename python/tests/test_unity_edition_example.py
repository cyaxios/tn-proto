"""Real TN edition admission with Unity's HTTP boundary supplied locally."""
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest
import tn

from test_unity_catalog_example import catalog


EXAMPLES = Path(__file__).resolve().parents[1] / "examples/providers"
VOLUME = "unity.default.invoices"


@pytest.fixture
def example():
    assert (EXAMPLES / "unity_edition_setup.py").is_file(), "edition setup example is missing"
    assert (EXAMPLES / "unity_edition.py").is_file(), "edition calculation example is missing"
    return runpy.run_path(str(EXAMPLES / "unity_edition_setup.py"))


@pytest.fixture
def prepared(example, catalog, tmp_path):
    workspace = tmp_path / "invoices"
    location = example["prepare"](workspace)
    catalog.state["body"] = {"full_name": VOLUME, "storage_location": location}
    return workspace


def test_commands_total_a_selected_edition_and_retain_its_evidence(example, catalog, tmp_path):
    workspace = tmp_path / "commands"
    setup = subprocess.run([sys.executable, "-B", str(EXAMPLES / "unity_edition_setup.py"), str(workspace)],
                           capture_output=True, text=True)
    assert setup.returncode == 0, setup.stderr
    assert setup.stdout.splitlines() == [(workspace / "publications").as_uri()]
    catalog.state["body"] = {"full_name": VOLUME, "storage_location": setup.stdout.strip()}
    before = {p.name: p.read_bytes() for p in (workspace / "publications").iterdir()}
    assert set(before) == {"source.tn", "revision.tn", "edition.tn"}
    command = [sys.executable, "-B", str(EXAMPLES / "unity_edition.py"), str(workspace),
               "--url", catalog.url, "--volume", VOLUME]
    for _ in range(2):
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == ["35"]
    assert {p.name: p.read_bytes() for p in (workspace / "publications").iterdir()} == before
    reports = list((workspace / "private/reports").glob("*.tn"))
    assert len(reports) == 2
    session, rules, administration = example["configure"](workspace)
    with session:
        entry = example["resolve"](workspace, session, rules, administration,
                                   url=catalog.url, volume=VOLUME)
        source = session.unseal(entry.publication, use=example["READ_USE"],
                                groups=["default"], decide=rules.accept, selection=entry.selection)
        for path in reports:
            report = tn.GovernedObject.read(path)
            assert path.stem == report.id.removeprefix("sha256:")
            assert path.read_bytes() == report.forward()
            received = session.unseal(report, use=example["WRITE_USE"], groups=["default"],
                                      decide=rules.accept)
            assert received.get() == {"total": 35}
            assert len(received.policies) == 1
            assert received.policies[0].matches_contract(source.policies[0])
            assert received.dataset_bindings == [entry.selection.binding]
            assert entry.publication.id in {ref.object_id for ref in received.governance.sources}


@pytest.mark.parametrize("field", ["revision_id", "record_id", "source_id"])
def test_wrong_expected_identity_is_refused(example, prepared, catalog, field):
    path = prepared / "private/expected-edition.json"
    expected = json.loads(path.read_text())
    expected[field] = "sha256:" + "0" * 64
    path.write_text(json.dumps(expected))
    session, rules, administration = example["configure"](prepared)
    with session, pytest.raises(ValueError, match="publication_id"):
        example["resolve"](prepared, session, rules, administration, url=catalog.url, volume=VOLUME)


@pytest.mark.parametrize("filename", ["revision.tn", "edition.tn", "source.tn"])
def test_valid_publication_substitution_is_refused(example, prepared, catalog, filename):
    files = prepared / "publications"
    replacement = "source.tn" if filename != "source.tn" else "edition.tn"
    (files / filename).write_bytes((files / replacement).read_bytes())
    session, rules, administration = example["configure"](prepared)
    with session, pytest.raises(ValueError, match="publication_id"):
        example["resolve"](prepared, session, rules, administration, url=catalog.url, volume=VOLUME)


@pytest.mark.parametrize("use", [
    ("other-service", "accounting", "total"),
    ("invoice-service", "marketing", "total"),
    ("invoice-service", "accounting", "export"),
])
def test_wrong_complete_use_is_refused_by_native_selection(example, prepared, catalog, use):
    session, rules, administration = example["configure"](prepared)
    with session, pytest.raises(tn.governed.UseDenied):
        example["resolve"](prepared, session, rules, administration, url=catalog.url, volume=VOLUME,
                           use=tn.UseContext(*use))


def test_refused_metadata_authority_never_opens_metadata(example, prepared, catalog):
    session, rules, administration = example["configure"](prepared)
    opened = []

    class UntrustedAuthority:
        did = "did:untrusted"

        def governance(self, publication):
            return session.governance(publication)

        def open(self, admitted, groups):
            opened.append(groups)
            return session.open(admitted, groups)

    with session, pytest.raises(tn.governed.UseDenied):
        example["resolve"](prepared, UntrustedAuthority(), rules, administration,
                           url=catalog.url, volume=VOLUME)
    assert opened == []


def test_prepare_does_not_overwrite_existing_workspace(example, prepared):
    retained = (prepared / "private/expected-edition.json").read_bytes()
    with pytest.raises(FileExistsError):
        example["prepare"](prepared)
    assert (prepared / "private/expected-edition.json").read_bytes() == retained
