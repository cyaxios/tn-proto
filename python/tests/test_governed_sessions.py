"""The governed SDK owns independent native contexts, with real cryptography."""

import json

import pytest

import tn

POLICY = """---
version: 1
schema: tn-agents-policy@v1
---
## research.sample
### instruction
Create an aggregate report.
### use_for
Aggregate research.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"""


def test_sessions_own_independent_native_contexts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert hasattr(tn, "Session"), "the governed Python SDK needs an instance-owned Session"
    prior = tn._dispatch_rt
    alice = tn.Session(POLICY, groups=["observations", "identities"], policy_id="alice.md")
    bob = tn.Session(POLICY, groups=["observations"], policy_id="bob.md")
    assert alice.did != bob.did
    source = alice.seal(
        alice.draft("research.sample")
        .group("observations", {"counts": [12, 18]})
        .group("identities", {"names": ["Alice", "Bob"]})
    )
    assert source.writer == alice.did
    assert source.envelope["tn_sealed"] == 1
    assert '"Alice"' not in source.wire
    assert source.envelope["signature"]
    aad = json.loads(source.envelope["tn_aad"])
    assert aad["observations"] == aad["identities"] == aad["tn.agents"]
    with pytest.raises(tn.governed.NotEntitled):
        bob.governance(source)
    reader = alice.reader(groups=["tn.agents", "observations"])
    view = reader.governance(source)
    admitted = view.authorize(
        "aggregate",
        lambda contract, operation: operation == "aggregate" and contract.governed_by == alice.did,
    )
    with pytest.raises(tn.governed.NotEntitled):
        reader.open(admitted, ["identities"])
    opened = reader.open(admitted, ["observations"])
    assert opened.hidden_groups == ["identities"]
    result = bob.seal(
        opened.derive("report.generated").group(
            "observations", {"total": sum(opened.groups["observations"]["counts"])}
        )
    )
    contract = bob.governance(result).governance
    assert result.writer == bob.did
    assert contract.governed_by == alice.did
    assert contract.fields["source_lineage"][0]["object_id"] == source.id
    assert opened.object.wire == source.wire
    alice.close()
    assert alice.closed and not bob.closed
    with pytest.raises(tn.governed.SessionClosed):
        alice.draft("research.sample")
    assert bob.seal(bob.draft("research.sample")).writer == bob.did
    assert reader.governance(source).object.wire == source.wire
    bob.close()
    assert tn._dispatch_rt is prior
    assert list(tmp_path.iterdir()) == []


def make_object(session, fields=None):
    return session.seal(session.draft("research.sample").group("default", fields or {"amount": 42}))


def admit(session, source):
    return session.governance(source).authorize("aggregate", lambda policy, operation: True)


def test_native_types_require_admission_and_propagate_callback_decisions():
    from tn._native import governed as native

    assert tn.Session is native.Session is tn.governed.Session
    with tn.Session(POLICY) as session:
        source = make_object(session)
        view = session.governance(source)
        with pytest.raises(tn.governed.UseDenied):
            view.authorize("aggregate", lambda policy, operation: False)
        for result in [None, 1, "yes", [], {}]:
            with pytest.raises(TypeError, match="bool"):
                view.authorize("aggregate", lambda policy, operation: result)
        failure = RuntimeError("policy service unavailable")

        def failed_decision(policy, operation):
            raise failure

        with pytest.raises(RuntimeError) as caught:
            view.authorize("aggregate", failed_decision)
        assert caught.value is failure
        with pytest.raises(TypeError):
            session.open(source, ["default"])
        with pytest.raises(TypeError):
            tn.governed.AdmittedObject()
        with pytest.raises(ValueError):
            session.reader(groups=["default", "default"])
        with pytest.raises(TypeError):
            session.reader(groups="default")
        admitted = view.authorize("aggregate", lambda policy, operation: True)
        assert session.open(admitted, ["default"]).groups == {"default": {"amount": 42}}


def test_python_views_are_copies_and_native_objects_remain_immutable():
    with tn.Session(POLICY) as session:
        fields = {"nested": {"items": [1, 2]}}
        draft = session.draft("research.sample").group("default", fields)
        fields["nested"]["items"].append(99)
        source = session.seal(draft)
        envelope = source.envelope
        envelope["event_type"] = "changed"
        assert source.object_type == "research.sample"
        with pytest.raises(AttributeError):
            source.wire = "changed"
        view = session.governance(source)
        contract = view.governance.fields
        contract["instruction"] = "changed"
        assert view.governance.get("instruction") == "Create an aggregate report."
        opened = session.open(admit(session, source), ["default"])
        fields = opened.groups
        fields["default"]["nested"]["items"].append(99)
        assert opened.groups["default"]["nested"]["items"] == [1, 2]
        assert str(source) == source.wire
        assert bytes(source) == source.wire.encode()
        assert tn.GovernedObject.parse(bytes(source)).wire == source.wire
        assert session.verify(source.wire).id == source.id


def test_json_values_preserve_large_integers_and_reject_unrepresentable_inputs():
    fields = {
        "large": 2**64 - 1,
        "small": -(2**63),
        "boolean": True,
        "array": [False, None, 1.25, "héllo\nworld"],
        "tuple": (1, 2),
    }
    with tn.Session(POLICY) as session:
        source = make_object(session, fields)
        opened = session.open(admit(session, source), ["default"])
        assert opened.groups["default"] == {**fields, "tuple": [1, 2]}
        assert type(opened.groups["default"]["large"]) is int
        assert type(opened.groups["default"]["boolean"]) is bool
        for value in [2**64, -(2**63) - 1]:
            with pytest.raises(OverflowError):
                session.draft("research.sample").group("default", {"value": value})
        for value in [float("nan"), float("inf")]:
            with pytest.raises(ValueError, match="finite"):
                session.draft("research.sample").group("default", {"value": value})
        for value in [object(), b"bytes", {1: "non-string key"}]:
            with pytest.raises(TypeError):
                session.draft("research.sample").group("default", {"value": value})
        cycle = []
        cycle.append(cycle)
        with pytest.raises(ValueError, match="nesting"):
            session.draft("research.sample").group("default", {"cycle": cycle})


def test_verification_rejects_mutation_and_duplicate_json():
    with tn.Session(POLICY) as session:
        source = make_object(session)
        changed = source.envelope
        changed["event_type"] = "changed.type"
        with pytest.raises(tn.governed.VerificationError):
            tn.GovernedObject.parse(json.dumps(changed))
        duplicate = source.wire.replace("{", '{"sequence":0,', 1)
        with pytest.raises(ValueError, match="duplicate"):
            tn.GovernedObject.parse(duplicate)
        with pytest.raises(ValueError, match="UTF-8"):
            tn.GovernedObject.parse(b"\xff")


def test_finite_floats_round_trip_exactly():
    values = [
        449.49106478873813,
        945.2706955539223,
        -1.5432835417340557e88,
        float.fromhex("0x1.fffffffffffffp+1023"),
        float.fromhex("0x0.0000000000001p-1022"),
        -0.0,
    ]
    with tn.Session(POLICY) as session:
        source = make_object(session, {"values": values})
        opened = session.open(admit(session, source), ["default"])
        actual = opened.groups["default"]["values"]
        assert [value.hex() for value in actual] == [value.hex() for value in values]


def test_nested_contexts_close_only_their_own_session():
    with tn.Session(POLICY) as outer:
        before = outer.did
        with pytest.raises(RuntimeError, match="stop inner"):
            with tn.Session(POLICY) as inner:
                assert outer.did == before
                assert make_object(outer).writer != make_object(inner).writer
                raise RuntimeError("stop inner")
        assert inner.closed
        assert not outer.closed
        assert make_object(outer).writer == before
    assert outer.closed
    outer.close()
    with pytest.raises(tn.governed.SessionClosed):
        outer.__enter__()


def test_explicit_output_policy_keeps_the_source_contract_in_lineage():
    with tn.Session(POLICY, policy_id="input.md") as source_session:
        with tn.Session(
            POLICY.replace("version: 1", "version: 2"), policy_id="output.md"
        ) as output_session:
            source = make_object(source_session)
            opened = source_session.open(admit(source_session, source), ["default"])
            output_policy = output_session.policy("research.sample")
            result = output_session.seal(
                opened.derive_under("report.released", output_policy).group(
                    "default", {"total": 42}
                )
            )
            policy = output_session.governance(result).governance
            assert policy.policy_ref == output_policy.policy_ref
            assert policy.fields["source_lineage"][0]["policy"] == opened.governance.policy_ref
            explicit = tn.Governance.from_markdown(
                output_session.did, POLICY, "explicit.md", "research.sample"
            )
            assert (
                output_session.draft("report.other", governance=explicit).governance.policy_ref
                == explicit.policy_ref
            )


def test_sessions_and_one_shared_session_work_across_python_threads():
    from concurrent.futures import ThreadPoolExecutor

    with tn.Session(POLICY) as alice, tn.Session(POLICY) as bob:

        def round_trip(item):
            session, value = item
            source = make_object(session, {"value": value})
            opened = session.open(admit(session, source), ["default"])
            return source.writer, source.id, opened.groups["default"]["value"]

        jobs = [(alice if i % 2 else bob, i) for i in range(16)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(round_trip, jobs))
        assert len({row[1] for row in results}) == 16
        assert [row[2] for row in results] == list(range(16))
        assert [row[0] for row in results] == [session.did for session, _ in jobs]


def configured_session_files(root):
    """Existing configuration and keys, provisioned independently of Session."""
    import os

    import yaml
    from tn._native.btn import PublisherState
    from tn.signing import DeviceKey

    keys = root / ".tn" / "keys"
    keys.mkdir(parents=True)
    policy_dir = root / ".tn" / "config"
    policy_dir.mkdir()
    (policy_dir / "agents.md").write_text(POLICY, encoding="utf-8")
    device = DeviceKey.generate()
    (keys / "local.private").write_bytes(device.private_bytes)
    (keys / "index_master.key").write_bytes(os.urandom(32))
    groups = {}
    for name in ["default", "tn.agents"]:
        state = PublisherState()
        (keys / f"{name}.btn.mykit").write_bytes(state.mint())
        (keys / f"{name}.btn.state").write_bytes(state.to_bytes())
        groups[name] = {
            "policy": "private",
            "cipher": "btn",
            "index_epoch": 0,
            "recipients": [{"recipient_identity": device.did}],
        }
    # This location deliberately cannot be opened as a log file.
    (root / "unusable-log").mkdir()
    config = {
        "ceremony": {
            "id": "cer_governed",
            "mode": "local",
            "cipher": "btn",
            "protocol_events_location": "main_log",
        },
        "keystore": {"path": "./.tn/keys"},
        "device": {"device_identity": device.did},
        "logs": {"path": "./unusable-log"},
        "groups": groups,
        "public_fields": [],
        "default_policy": "private",
        "fields": {},
        "llm_classifier": {"enabled": False, "provider": "", "model": ""},
    }
    path = root / "tn.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path, device.did


def test_configured_sessions_load_independently_and_reopen_existing_objects(tmp_path):
    first_path, first_did = configured_session_files(tmp_path / "first")
    second_path, second_did = configured_session_files(tmp_path / "second")

    def files():
        return {
            path.relative_to(tmp_path): path.read_bytes()
            for path in tmp_path.rglob("*")
            if path.is_file()
        }

    before = files()
    prior = tn._dispatch_rt
    with (
        tn.Session.from_config(first_path) as first,
        tn.Session.from_config(str(second_path)) as second,
    ):
        assert first.did == first_did and second.did == second_did
        source = make_object(first)
        with pytest.raises(tn.governed.NotEntitled):
            second.governance(source)
        assert make_object(second).writer == second_did
    with tn.Session.from_config(first_path) as reopened:
        verified = reopened.verify(source.wire)
        assert (
            reopened.open(admit(reopened, verified), ["default"]).groups["default"]["amount"] == 42
        )
    assert files() == before
    assert tn._dispatch_rt is prior


def test_governed_sessions_coexist_with_an_active_event_session(tmp_path):
    with tn.session(tmp_path) as event_session:
        event_runtime = tn._dispatch_rt
        event_did = event_session.did
        with tn.Session(POLICY) as governed:
            source = make_object(governed)
            assert source.writer != event_did
            assert (
                governed.open(admit(governed, source), ["default"]).groups["default"]["amount"]
                == 42
            )
            assert tn._dispatch_rt is event_runtime
        assert tn._dispatch_rt is event_runtime
        event_session.info("governed.coexistence", value=7)


def test_authorization_callback_can_close_its_session_from_another_thread():
    from concurrent.futures import ThreadPoolExecutor

    session = tn.Session(POLICY)
    source = make_object(session)
    reader = session.reader(groups=["tn.agents", "default"])

    def decide(policy, operation):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(session.close).result(timeout=5)
        return True

    admitted = reader.governance(source).authorize("aggregate", decide)
    assert session.closed
    assert reader.open(admitted, ["default"]).groups["default"]["amount"] == 42
    with pytest.raises(tn.governed.SessionClosed):
        session.open(admitted, ["default"])
