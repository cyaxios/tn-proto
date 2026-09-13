"""The application interface delegates creation and configured receipt to Rust."""
import pytest
import tn

POLICY = """## hello.message
### instruction
Read the message.
### use_for
Greeting.
### do_not_use_for
Other uses.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def test_hello_world():
    with tn.Session(POLICY) as session:
        expected = session.policy("hello.message")
        calls = []

        def decide(context):
            calls.append((context.purpose, context.operation))
            return context.writer == session.did and context.governance.matches_contract(expected)

        session.configure_receive(use=tn.UseContext("hello", "greeting", "read"), decide=decide)
        source = session.create_obj({"message": "Hello, world!"}, policy=expected)
        received = session.receive(source, purpose="greeting")
        assert received.data["message"] == "Hello, world!"
        assert source.object_type == "hello.message"
        assert calls == [("greeting", "read")]
        assert session.receive(received, purpose="greeting").data["message"] == "Hello, world!"
        assert "Hello, world!" not in source.snapshot.wire
        assert session.receive(source.snapshot.wire, purpose="greeting").data["message"] == "Hello, world!"
        source.data["message"] = "Changed"
        with pytest.raises(ValueError, match="release"):
            session.receive(source, purpose="greeting")


def test_configuration_and_denial():
    with tn.Session(POLICY) as session, tn.Session(POLICY) as other:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        with pytest.raises(ValueError, match="not configured"):
            session.receive(source, purpose="greeting")
        use = tn.UseContext("hello", "greeting", "read")
        session.configure_receive(use=use, decide=lambda _: False)
        with pytest.raises(tn.governed.UseDenied):
            session.receive(source, purpose="greeting")
        with pytest.raises(ValueError, match="already configured"):
            session.configure_receive(use=use, decide=lambda _: True)
        other.configure_receive(use=use, decide=lambda _: pytest.fail("must not reach admission"))
        with pytest.raises(tn.governed.NotEntitled):
            other.receive(source, purpose="greeting")


def test_evaluator_failure_and_close():
    with tn.Session(POLICY) as session:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        session.configure_receive(use=tn.UseContext("hello", "greeting", "read"), decide=lambda _: "yes")
        with pytest.raises(ValueError, match="must return bool"):
            session.receive(source, purpose="greeting")
    with pytest.raises(tn.governed.SessionClosed):
        session.receive(source, purpose="greeting")


def test_selected_groups_and_explicit_overrides():
    with tn.Session(POLICY, groups=["default", "private"]) as session:
        source = session.create_obj_with_groups(
            {"default": {"message": "hello"}, "private": {"number": 42}},
            session.policy("hello.message"), object_type="hello.message",
        )
        session.configure_receive(
            use=tn.UseContext("hello", "private_read", "read"),
            groups=["private", "default"], decide=lambda _: True,
        )
        assert session.receive(source, purpose="private_read").data["number"] == 42
        with pytest.raises(TypeError, match="requires decide"):
            session.receive(source, purpose="private_read", groups=["default"])


def test_tampered_publication_and_closing_in_evaluator():
    import json

    with tn.Session(POLICY) as session:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        called = []

        def admit(context):
            called.append(context)
            session.close()
            return True

        session.configure_receive(use=tn.UseContext("hello", "greeting", "read"), decide=admit)
        body = json.loads(source.snapshot.wire)
        body["signature"] = "invalid"
        with pytest.raises(tn.governed.VerificationError):
            session.receive(json.dumps(body), purpose="greeting")
        assert called == []
        with pytest.raises(ValueError, match="session is closed"):
            session.receive(source, purpose="greeting")


def test_external_selected_policy_keeps_authority_and_infers_type():
    with tn.Session(POLICY) as session, tn.Session(POLICY) as external:
        policy = external.policy("hello.message")
        source = session.create_obj({"message": "hello"}, policy)
        assert source.object_type == "hello.message"
        assert source.governance.governed_by == external.did
        assert source.snapshot.writer == session.did
        grouped = session.create_obj_with_groups({"default": {"message": "hello"}}, policy)
        assert grouped.object_type == "hello.message"


def test_two_input_types_share_one_purpose():
    policy = POLICY + "\n" + POLICY.replace("hello.message", "hello.positions")
    with tn.Session(policy, groups=["prices", "holdings"]) as session:
        use = tn.UseContext("analytics", "valuation", "calculate")
        session.configure_receive(use=use, object_type="hello.message", groups=["prices"], decide=lambda _: True)
        session.configure_receive(use=use, object_type="hello.positions", groups=["holdings"], decide=lambda _: True)
        prices = session.create_obj({"price": 125}, session.policy("hello.message"), group="prices")
        positions = session.create_obj({"quantity": 2}, session.policy("hello.positions"), group="holdings")
        assert session.receive(prices, purpose="valuation").data["price"] == 125
        assert session.receive(positions, purpose="valuation").data["quantity"] == 2


def test_configured_release_and_attachment_preserve_history():
    with tn.Session(POLICY) as session, tn.Session(POLICY) as authority:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        initial = source.snapshot
        with pytest.raises(ValueError, match="not configured"):
            source.attach(authority.policy("hello.message"))
        session.configure_attach(decide=lambda c: c.authority == session.did and c.policy.governed_by == authority.did)
        source.attach(authority.policy("hello.message"))
        assert len(source.policies) == 2
        source.data["message"] = "Hello, world!"
        session.configure_release(use=tn.UseContext("hello", "greeting", "send"), to="caller", object_type="hello.reply",
                                  decide=lambda c: len(c.policies) == 2 and c.data.groups["default"]["message"] == "Hello, world!")
        with pytest.raises(tn.governed.UseDenied):
            source.release(purpose="greeting", decide=lambda _: False)
        assert source.snapshot.id == initial.id
        output = source.release(purpose="greeting")
        assert output.object_type == "hello.reply"
        assert not source.has_unreleased_changes
        assert session.release(source, purpose="greeting").object_type == "hello.reply"
        source.data["message"] = "wrong"
        with pytest.raises(tn.governed.UseDenied):
            source.release(purpose="greeting", decide=lambda _: True)
        assert source.has_unreleased_changes


def test_configured_release_refuses_mutation_during_decision():
    with tn.Session(POLICY) as session:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        initial = source.snapshot
        def mutate(_):
            source.data["message"] = "changed"
            return True
        session.configure_release(use=tn.UseContext("hello", "greeting", "send"), to="caller", object_type="hello.reply", decide=mutate)
        with pytest.raises(tn.governed.GovernedError, match="object changed"):
            source.release(purpose="greeting")
        assert source.snapshot.id == initial.id
        assert source.data["message"] == "changed"


def test_configured_attachment_refuses_mutation_during_decision():
    with tn.Session(POLICY) as session, tn.Session(POLICY) as authority:
        source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        def mutate(_):
            source.data["message"] = "changed"
            return True
        session.configure_attach(decide=mutate)
        with pytest.raises(tn.governed.GovernedError, match="object changed"):
            source.attach(authority.policy("hello.message"))
        assert len(source.policies) == 1
        assert source.data["message"] == "changed"


def test_bound_workflow_live_authority_and_fixed_routes():
    session = tn.Session(POLICY)
    active = [True]
    session.configure_receive(use=tn.UseContext("hello", "read", "read"), decide=lambda _: active[0])
    with pytest.raises(ValueError, match="not configured"):
        session.workflow(receive="read", release="send")
    session.configure_release(use=tn.UseContext("hello", "send", "publish"), to="receiver", object_type="hello.message", decide=lambda _: active[0])
    session.configure_attach(decide=lambda _: True)
    work = session.workflow(receive="read", release="send")
    assert isinstance(work, tn.Workflow)
    session.configure_receive(use=tn.UseContext("hello", "read", "read"), object_type="hello.message", decide=lambda _: False)
    source = session.create_obj({"message": "hello"}, session.policy("hello.message"))
    with pytest.raises(tn.governed.UseDenied):
        session.receive(source, purpose="read")
    data = work.receive(source)
    work.attach(data, session.policy("hello.message"))
    data.data["message"] = "updated"
    with pytest.raises(ValueError, match="release"):
        work.receive(data)
    with pytest.raises(tn.governed.UseDenied):
        work.release(data, decide=lambda _: False)
    result = work.release(data)
    assert work.receive(result).data["message"] == "updated"
    active[0] = False
    with pytest.raises(tn.governed.UseDenied):
        work.release(data, decide=lambda _: True)
    with pytest.raises(tn.governed.UseDenied):
        work.receive(result)
    session.close()
    for call in [lambda: work.receive(result), lambda: work.release(data), lambda: work.attach(data, session.policy("hello.message"))]:
        with pytest.raises(tn.governed.SessionClosed):
            call()


def test_workflow_release_rejects_callback_mutation():
    with tn.Session(POLICY) as session:
        session.configure_receive(use=tn.UseContext("hello", "read", "read"), decide=lambda _: True)
        session.configure_release(use=tn.UseContext("hello", "send", "publish"), to="receiver", object_type="hello.message", decide=lambda _: True)
        work = session.workflow(receive="read", release="send")
        data = work.receive(session.create_obj({"message": "hello"}, session.policy("hello.message")))
        original = data.snapshot.wire
        def change(_):
            data.data["message"] = "changed during decision"
            return True
        with pytest.raises(tn.governed.GovernedError, match="changed during"):
            work.release(data, decide=change)
        assert data.snapshot.wire == original


def test_workflow_attachment_rejects_callback_mutation():
    with tn.Session(POLICY) as session:
        session.configure_receive(use=tn.UseContext("hello", "read", "read"), decide=lambda _: True)
        session.configure_release(use=tn.UseContext("hello", "send", "publish"), to="receiver", object_type="hello.message", decide=lambda _: True)
        data = session.create_obj({"message": "hello"}, session.policy("hello.message"))
        def change(_):
            data.data["message"] = "changed during attachment"
            return True
        session.configure_attach(decide=change)
        work = session.workflow(receive="read", release="send")
        original = data.snapshot.wire
        with pytest.raises(tn.governed.GovernedError, match="changed during"):
            work.attach(data, session.policy("hello.message"))
        assert data.snapshot.wire == original
        assert data.data["message"] == "changed during attachment"
