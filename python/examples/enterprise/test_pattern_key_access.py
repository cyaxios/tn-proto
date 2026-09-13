"""Every chapter enters the real TN workflow with an unrelated business key."""
import pytest
import tn
from secrets import token_bytes
from tn._native.btn import PublisherState
from tn.providers import (
    LocalIdentity, GroupCapability, KeySet, Providers, PolicyDirectory,
    PolicyRequest, WorkflowRequest, WorkflowPolicy, InputRule,
)
import verb_patterns as patterns
from verb_support import Approval, Edit, ObservationRequest, QuoteSelection
from pattern_environment import POLICY


@pytest.fixture
def encrypted_boundary():
    identities = LocalIdentity("pattern-service")
    identity = identities.resolve("pattern-service")
    policy = tn.Governance.from_markdown(identity.did, POLICY, "agents.md", "example.input")
    public_state, governance_state, unrelated_state = (PublisherState() for _ in range(3))
    business_kit, governance_kit, unrelated_kit = (
        state.mint() for state in (public_state, governance_state, unrelated_state)
    )
    index, governance_index = token_bytes(32), token_bytes(32)
    governance = GroupCapability.btn_publisher(
        "tn.agents", governance_state.to_bytes(), [governance_kit], governance_index,
    )
    correct = GroupCapability.btn_publisher("result", public_state.to_bytes(), [business_kit], index)
    wrong = GroupCapability.btn_reader("result", [unrelated_kit], index)
    reading = tn.UseContext(identity.application, "work", "calculate")
    sending = tn.UseContext(identity.application, "publish", "publish")
    workflow = WorkflowRequest(reading, sending)
    rules = PolicyDirectory()
    rules.trust(identity)
    rules.add_policy(PolicyRequest("example.input", reading), policy)
    rules.add_policy(PolicyRequest("example.input", sending), policy)
    rules.add_workflow(workflow, WorkflowPolicy([InputRule(["result"])], "example.output", "review"))

    class Assigned:
        def __init__(self, capability):
            self.keys = KeySet(identity, [governance, capability])

        def resolve(self, requested):
            if requested.did != identity.did:
                raise ValueError("unknown identity")
            return self.keys

    sessions = [Providers(identities, Assigned(key), rules).session(
        identity.application, workflows=[workflow],
    ) for key in (correct, wrong)]
    good, denied = sessions
    source = good.create({"message": "licensed value"}, policy, group="result").snapshot
    # Same identity, contract, use and group name. Only the business key differs.
    assert denied.governance(source).governance.matches_contract(policy)
    assert good.receive(source, purpose="work").get("message") == "licensed value"
    try:
        yield denied.workflow(receive="work", release="publish"), source, policy
    finally:
        for session in sessions:
            session.close()


@pytest.mark.parametrize("number", range(1, 16))
def test_pattern_requires_assigned_business_key(encrypted_boundary, number):
    work, source, policy = encrypted_boundary
    # Arguments needed after opening are deliberately unused on this path.
    calls = {
        1: lambda: patterns.approve(work, source, Approval(source.id, "client-7"), policy),
        2: lambda: patterns.reply(work, source, source, None),
        3: lambda: patterns.consume(work, source, source, None, None),
        4: lambda: patterns.cancel(work, source, source),
        5: lambda: patterns.deliver(work, source, None),
        6: lambda: patterns.project(work, [source], source.id),
        7: lambda: patterns.analyst_view(work, source, source),
        8: lambda: patterns.aggregate(work, source, [], QuoteSelection((), (), "close")),
        9: lambda: patterns.normalize(work, source, ()),
        10: lambda: patterns.receive_edition(work, source, None),
        11: lambda: patterns.edit(work, source, Edit("report", "account", "title"), None),
        12: lambda: patterns.archive(work, source, None),
        13: lambda: patterns.cached_observation(work, source, ObservationRequest(source.id, "ALPHA", "close")),
        14: lambda: patterns.finish(work, source, source, None),
        15: lambda: patterns.execute(work, source, None, None),
    }
    with pytest.raises(tn.governed.NotEntitled, match="result"):
        calls[number]()
