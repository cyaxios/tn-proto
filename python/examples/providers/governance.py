"""Provision contracts and explicit complete uses for the local example."""
from tn.governed import Governance, UseContext
from tn.providers import PolicyDirectory, PolicyRequest, WorkflowRequest, WorkflowPolicy, InputRule

POLICY = """## example.value
### instruction
Calculate a result from the supplied value.
### use_for
Approved analysis and reporting.
### do_not_use_for
Other uses.
### consequences
Review the operation.
### on_violation_or_error
Refuse the operation.
"""

def provision(identity):
    incoming = UseContext(identity.application, "analysis", "calculate")
    outgoing = UseContext(identity.application, "report", "publish")
    request = PolicyRequest("example.value", incoming)
    workflow = WorkflowRequest(incoming, outgoing)
    contract = Governance.from_markdown(identity.did, POLICY, "agents.md", request.object_type)
    directory = PolicyDirectory()
    directory.trust(identity)
    directory.add_policy(request, contract)
    directory.add_policy(PolicyRequest(request.object_type, outgoing), contract)
    directory.add_workflow(workflow, WorkflowPolicy([InputRule(["default"])], "example.report", "reporting"))
    return directory, request, workflow
