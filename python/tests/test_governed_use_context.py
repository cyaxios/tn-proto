"""Complete use and admission stay native across independent Python sessions."""

import pytest

import tn
from test_governed_sessions import POLICY, configured_session_files, make_object


def requested_use(operation="calculate"):
    return tn.governed.UseContext("deepvest", "portfolio_analysis", operation)


def source(session):
    return session.seal(
        session.draft("research.sample")
        .group("finance", {"amount": 42})
        .group("identities", {"person": "Alice"})
    )


@pytest.fixture
def session():
    with tn.Session(POLICY, groups=["finance", "identities"]) as value:
        yield value


def test_use_context_is_native_validated_immutable_and_value_comparable():
    from tn._native import governed as native

    assert tn.governed.UseContext is native.UseContext
    use = requested_use()
    assert (use.application, use.purpose, use.operation) == (
        "deepvest", "portfolio_analysis", "calculate"
    )
    assert use == requested_use()
    assert use != requested_use("export")
    with pytest.raises(AttributeError):
        use.operation = "export"
    for args in [("", "analysis", "read"), ("app", " ", "read"), ("app", "analysis", ""), ("a\0b", "analysis", "read")]:
        with pytest.raises(ValueError):
            native.UseContext(*args)


def test_session_acceptance_binds_its_reader_groups_and_complete_use(session):
    wire = source(session)
    seen = []

    def decide(context):
        seen.append(context)
        assert context.use_context == requested_use()
        assert context.purpose == "portfolio_analysis"
        assert context.operation == "calculate"
        assert context.groups == ["finance"]
        assert context.object.id == wire.id
        assert len(context.policies) == 1
        return True

    admitted = session.governance(wire).accept(use=requested_use(), groups=["finance"], decide=decide)
    assert len(seen) == 1
    assert admitted.use_context == requested_use()
    assert admitted.selected_groups == ["finance"]
    with pytest.raises(ValueError):
        session.open(admitted, ["finance", "identities"])
    with pytest.raises(ValueError):
        session.reader().open(admitted, ["finance"])
    opened = session.open(admitted, ["finance"])
    assert opened.use_context == requested_use()
    assert opened.groups == {"finance": {"amount": 42}}
    assert opened.hidden_groups == ["identities"]


def test_strict_receive_delegates_decisions_and_preserves_python_exceptions(session):
    wire = source(session)
    kwargs = dict(use=requested_use(), groups=["finance"])
    received = session.receive(wire, **kwargs, decide=lambda context: context.use_context == requested_use())
    assert received.data["amount"] == 42
    with pytest.raises(tn.governed.UseDenied):
        session.receive(wire, **kwargs, decide=lambda context: False)
    for answer in [None, 1, "yes"]:
        with pytest.raises(TypeError, match="bool"):
            session.receive(wire, **kwargs, decide=lambda context: answer)
    failure = RuntimeError("evaluator unavailable")

    def failed(context):
        raise failure

    with pytest.raises(RuntimeError) as caught:
        session.receive(wire, **kwargs, decide=failed)
    assert caught.value is failure
    with pytest.raises(ValueError):
        session.receive(wire, use=requested_use(), groups=["missing"], decide=lambda context: pytest.fail("native validation must precede callback"))
    with pytest.raises(TypeError):
        session.receive(wire, purpose="calculate", **kwargs, decide=lambda context: pytest.fail("ambiguous use must be rejected"))
    with pytest.raises(TypeError):
        session.receive(wire, groups=["finance"], decide=lambda context: True)


def test_native_copy_has_independent_data_and_preserves_session_ownership(session):
    received = session.receive(source(session), use=requested_use(), groups=["finance"], decide=lambda context: True)
    copied = received.copy()
    copied.data["amount"] = 99
    assert received.data["amount"] == 42
    assert copied.data["amount"] == 99
    assert copied.snapshot.id == received.snapshot.id
    assert copied.policies[0].matches_contract(received.policies[0])
    session.close()
    with pytest.raises(tn.governed.SessionClosed):
        copied.release(use=requested_use("release_calculation"), to="report-service", decide=lambda context: True)


def test_strict_release_carries_native_use_and_refuses_stale_decisions(session):
    received = session.receive(source(session), use=requested_use(), groups=["finance"], decide=lambda context: True)
    release_use = requested_use("release_calculation")
    seen = []

    def decide(context):
        seen.append(context)
        assert context.use_context == release_use
        assert context.purpose == "portfolio_analysis"
        assert context.destination == "report-service"
        assert context.data.groups["finance"]["amount"] == 42
        return True

    released = received.release(use=release_use, to="report-service", decide=decide)
    assert len(seen) == 1
    assert session.governance(released).governance.fields["release_context"] == {
        "application": "deepvest", "purpose": "portfolio_analysis",
        "operation": "release_calculation", "destination": "report-service",
    }
    with pytest.raises(TypeError):
        received.release(use=release_use, purpose="aggregate", to="report-service", decide=lambda context: True)
    failure = RuntimeError("release evaluator unavailable")

    def failed(context):
        raise failure

    with pytest.raises(RuntimeError) as caught:
        received.release(use=release_use, to="report-service", decide=failed)
    assert caught.value is failure
    assert received.snapshot.id == released.id

    def stale(context):
        received.data["amount"] = 43
        return True

    with pytest.raises(tn.governed.GovernedError, match="changed"):
        received.release(use=release_use, to="report-service", decide=stale)
    assert received.snapshot.id == released.id
    assert received.data["amount"] == 43


def test_closing_session_during_admission_prevents_opening(session):
    wire = source(session)

    def close(context):
        session.close()
        return True

    with pytest.raises(tn.governed.SessionClosed):
        session.receive(wire, use=requested_use(), groups=["finance"], decide=close)


def test_configured_sessions_with_identical_keys_still_require_their_own_acceptance(tmp_path):
    path, did = configured_session_files(tmp_path / "configured")
    before = {item: item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()}
    with tn.Session.from_config(path) as first, tn.Session.from_config(path) as second:
        assert first.did == second.did == did
        wire = make_object(first)
        admitted = first.governance(wire).accept(use=requested_use(), groups=["default"], decide=lambda context: True)
        with pytest.raises(ValueError):
            second.open(admitted, ["default"])
        assert first.open(admitted, ["default"]).groups == {"default": {"amount": 42}}
        received = second.receive(wire, use=requested_use(), decide=lambda context: context.writer == did)
        assert received.data["amount"] == 42
    assert {item: item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()} == before
