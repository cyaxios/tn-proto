"""Shared Python provisioning for the chapter excerpts; TN executes in Rust."""
import tn
from tn.providers import (
    LocalIdentity, LocalKeys, Providers, PolicyDirectory,
    PolicyRequest, WorkflowRequest, WorkflowPolicy, InputRule,
)

POLICY = """## example.input
### instruction
Use admitted inputs for the configured reporting operation.
### use_for
Internal calculation and approved reporting.
### do_not_use_for
Unapproved disclosure.
### consequences
Review the affected release.
### on_violation_or_error
Refuse the operation.
"""


class ReportingRules:
    """Use native contract decisions and require the configured report recipient."""
    def __init__(self, directory, recipient):
        self.directory, self.recipient = directory, recipient

    def policy(self, request):
        return self.directory.policy(request)

    def workflow(self, request):
        return self.directory.workflow(request)

    def accept(self, context):
        return self.directory.accept(context)

    def attach(self, context):
        return self.directory.attach(context)

    def release(self, context):
        return (self.directory.release(context)
                and context.data.groups.get("result", {}).get("recipient", self.recipient)
                == self.recipient)


def configured_example(application="examples", recipient="client-7"):
    """Return the session, bound workflow and originating policy for the examples."""
    identities = LocalIdentity(application)
    identity = identities.resolve(application)
    keys = LocalKeys(["result", "prices", "holdings"])
    keys.assign(identity, read=["result", "prices", "holdings"],
                publish=["result", "prices", "holdings", "tn.agents"])
    reading = tn.UseContext(application, "work", "calculate")
    sending = tn.UseContext(application, "publish", "publish")
    request = WorkflowRequest(reading, sending)
    policy = tn.Governance.from_markdown(identity.did, POLICY, "agents.md", "example.input")
    directory = PolicyDirectory()
    directory.trust(identity)
    directory.add_policy(PolicyRequest("example.input", reading), policy)
    directory.add_policy(PolicyRequest("example.input", sending), policy)
    directory.add_workflow(request, WorkflowPolicy([
        InputRule(["result"]),
        InputRule(["prices"], object_type="market.prices"),
        InputRule(["holdings"], object_type="client.holdings"),
    ], "example.output", "internal-review"))
    providers = Providers(identities, keys, ReportingRules(directory, recipient))
    session = providers.session(application, workflows=[request])
    return session, session.workflow(receive="work", release="publish"), policy
