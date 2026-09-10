"""Replay the retained Rust M1 publications through the installed native Python API."""

import base64
import json
from pathlib import Path

import pytest

import tn
from tn import governed as g


FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/governed/v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def retained(tmp_path_factory):
    assert MANIFEST["schema"] == "tn-governed-m1-fixtures@v1"
    assert MANIFEST["test_only"] is True
    assert MANIFEST["private_seed_hex"] == "51" * 32
    root = tmp_path_factory.mktemp("m1-native-fixture")
    keys = root / "keys"
    keys.mkdir()
    (keys / "local.private").write_bytes(bytes.fromhex(MANIFEST["private_seed_hex"]))
    (keys / "index_master.key").write_bytes(bytes.fromhex(MANIFEST["index_master_hex"]))
    for name, material in MANIFEST["groups"].items():
        assert name in {"tn.agents", "policy_revision", "dataset_edition", "finance", "audit"}
        for field, suffix in [("publisher_state_base64", "state"), ("reader_kit_base64", "mykit")]:
            (keys / f"{name}.btn.{suffix}").write_bytes(base64.b64decode(material[field], validate=True))
    config = {
        "ceremony": {"id": "cer_governed_m1_test_fixture", "cipher": "btn", "mode": "local"},
        "keystore": {"path": "keys"},
        "device": {"device_identity": MANIFEST["writer"]},
        "groups": {name: {"cipher": "btn", "policy": "private", "index_epoch": 0} for name in MANIFEST["groups"]},
    }
    config_path = root / "tn.yaml"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with tn.Session.from_config(config_path) as session:
        assert session.did == MANIFEST["writer"]
        objects = {name: g.GovernedObject.parse(record["wire"]) for name, record in MANIFEST["publications"].items()}
        for name, obj in objects.items():
            record = MANIFEST["publications"][name]
            assert (obj.id, obj.writer, obj.object_type, obj.wire) == (
                record["object_id"], record["writer"], record["object_type"], record["wire"],
            )
        uses = {name: g.UseContext(**values) for name, values in MANIFEST["uses"].items()}
        dag, catalog = g.PolicyDag(), g.DatasetCatalog()
        selections = {}

        def metadata(obj, group):
            admitted = session.governance(obj).accept(
                use=g.UseContext("fixture.catalog", "administration", "inspect"),
                groups=[group], decide=lambda context: context.writer == session.did,
            )
            return session.open(admitted, [group])

        for name in ("earlier", "later"):
            revision = g.PolicyRevision.from_opened(metadata(objects[f"policy_{name}"], "policy_revision"))
            dag.admit(revision, lambda item, parent: item.writer == session.did)
            record = g.DatasetEdition.from_opened(metadata(objects[f"edition_{name}"], "dataset_edition"))
            catalog.admit(record, dag, lambda item: item.writer == session.did)
            selections[name] = catalog.select(record.dataset, record.edition, record.id, uses["source"])
        by_id = {obj.id: obj for obj in objects.values()}
        yield session, objects, uses, dag, catalog, selections, by_id


def test_retained_release_graphs_match_rust_expected_identities_and_metadata(retained):
    session, objects, _, dag, catalog, _, by_id = retained
    assert objects["source_earlier"].id != objects["source_later"].id
    assert objects["policy_earlier"].id != objects["policy_later"].id
    for name, expected in MANIFEST["expected_releases"].items():
        view = session.governance(objects[name])
        proof = g.LineageVerifier().verify(view, catalog, dag, lambda identity: session.governance(by_id[identity]))
        assert proof.object_ids == expected["lineage_object_ids"]
        assert proof.source_object_ids == sorted([objects["source_earlier"].id, objects["source_later"].id])
        assert [policy.revision_id for policy in view.governance.policies] == expected["contracts"]
        assert [binding.fields for binding in view.governance.dataset_bindings] == expected["dataset_bindings"]
        assert [source.object_id for source in view.governance.sources] == expected["parent_ids"]


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["name"])
def test_retained_admission_outcomes_match_rust(retained, case):
    session, objects, uses, dag, catalog, selections, by_id = retained
    obj = objects[case["publication"]]
    view = session.governance(obj)
    selection = selections.get(case["selection"])
    calls = []
    failure = RuntimeError("fixture callback error")

    def decide(context):
        calls.append(context)
        assert context.object.id == obj.id
        assert context.object.wire == obj.wire
        if case["decision"] == "error":
            raise failure
        if case["decision"] == "refuse":
            return False
        if selection is None:
            g.LineageVerifier().verify(view, catalog, dag, lambda identity: session.governance(by_id[identity]))
            return catalog.accepts(context, dag)
        return context.writer == session.did

    def receive():
        return session.receive(
            obj.wire, use=uses[case["use_name"]], groups=case["groups"],
            selection=selection, decide=decide,
        )

    if case["allowed"]:
        data = receive()
        if selection is not None:
            assert data.dataset_bindings == [selection.binding]
            assert data.data["wealth_path"] == [100, 120, 90, 135]
        else:
            expected = MANIFEST["expected_releases"][case["publication"]]
            assert data.state.groups["finance"] == expected["finance"]
            assert [binding.fields for binding in data.dataset_bindings] == expected["dataset_bindings"]
    else:
        with pytest.raises((ValueError, g.UseDenied, RuntimeError)) as caught:
            receive()
        if case["decision"] == "error":
            assert caught.value is failure
        elif case["error_contains"] == "application refused operation":
            assert isinstance(caught.value, g.UseDenied)
            assert str(caught.value) == uses[case["use_name"]].operation
        else:
            assert case["error_contains"] in str(caught.value)
    assert len(calls) == case["decision_calls"]
    assert obj.wire == MANIFEST["publications"][case["publication"]]["wire"]
