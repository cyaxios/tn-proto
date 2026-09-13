"""HIBE delegation and governed publication, with cryptography executed in Rust."""
from pathlib import Path
from secrets import token_bytes
from tn import _hibe, Governance, UseContext
from tn.providers import (
    GroupCapability, KeySet, LocalIdentity, Providers, PolicyDirectory,
    PolicyRequest, WorkflowRequest, WorkflowPolicy, InputRule,
)


def main():
    # The authority issues a parent grant. The parent holder delegates one child.
    public, master = _hibe.setup(3)
    parent = _hibe.keygen(public, master, "reporting")
    child = _hibe.delegate(public, parent, "valuation")
    assert _hibe.key_id_path(child) == "reporting/valuation"
    index = token_bytes(32)
    finance = GroupCapability.hibe(
        "finance", public, "reporting/valuation", [child], index,
    )

    # Governance has a separately assigned key and path.
    governance_key = _hibe.keygen(public, master, "contracts")
    governance_group = GroupCapability.hibe(
        "tn.agents", public, "contracts", [governance_key], token_bytes(32),
    )
    identities = LocalIdentity("report-service")
    identity = identities.resolve("report-service")
    assigned = KeySet(identity, [finance, governance_group])

    class AssignedKeys:
        def resolve(self, requested):
            if requested.did != identity.did:
                raise ValueError("No assignment for this identity")
            return assigned

    reading = UseContext(identity.application, "greeting", "read")
    sending = UseContext(identity.application, "delivery", "publish")
    workflow = WorkflowRequest(reading, sending)
    policy = Governance.from_markdown(
        identity.did, Path(__file__).with_name("agents.md").read_text(),
        "agents.md", "hello.message",
    )
    rules = PolicyDirectory()
    rules.trust(identity)
    rules.add_policy(PolicyRequest("hello.message", reading), policy)
    rules.add_policy(PolicyRequest("hello.message", sending), policy)
    rules.add_workflow(workflow, WorkflowPolicy(
        [InputRule(["finance"])], "hello.message", "greeting-reader",
    ))
    providers = Providers(identities, AssignedKeys(), rules)
    with providers.session(identity.application, workflows=[workflow]) as session:
        source = session.create({"message": "Hello, world!"}, policy, group="finance")
        work = session.workflow(receive="greeting", release="delivery")
        result = work.release(work.receive(source))
        received = session.receive(result, purpose="greeting")
        assert received.get("message") == "Hello, world!"

    # A sibling grant cannot open the child's ciphertext.
    sibling = _hibe.keygen(public, master, "reporting/research")
    encrypted = _hibe.seal(public, "reporting/valuation", b"Hello, world!")
    assert _hibe.open(public, child, encrypted) == b"Hello, world!"
    try:
        _hibe.open(public, sibling, encrypted)
    except _hibe.HibeCryptoError:
        pass
    else:
        raise AssertionError("Sibling grant opened valuation data")
    print("Delegated grant: governed greeting opened; sibling grant rejected")


if __name__ == "__main__":
    main()
