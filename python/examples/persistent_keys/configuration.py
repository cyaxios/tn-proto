"""Reopen identity and native cipher capabilities without generating new keys."""
import json
from pathlib import Path
from tn import Governance, UseContext, ObjectRegisters
from tn.providers import (
    FileKeyStore, Providers, PolicyDirectory, PolicyRequest,
    WorkflowRequest, WorkflowPolicy, InputRule, FileRegisters,
)


def configure(directory, expected_cipher):
    directory = Path(directory)
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    store = FileKeyStore.open(directory / "keys" / "keystore.json")
    if store.cipher != expected_cipher or config["cipher"] != expected_cipher:
        raise ValueError("example and stored cipher must match")
    if sorted(store.groups) != sorted(config["groups"] + ["tn.agents"]):
        raise ValueError("configuration groups differ from stored capabilities")
    identity = store.resolve(config["application"])
    reading = UseContext(identity.application, "greeting", "read")
    sending = UseContext(identity.application, "delivery", "publish")
    request = PolicyRequest("hello.message", reading)
    workflow = WorkflowRequest(reading, sending)
    policy = Governance.from_markdown(identity.did, (directory / "agents.md").read_text(encoding="utf-8"), "agents.md", request.object_type)
    governance = PolicyDirectory()
    governance.trust(identity)
    governance.add_policy(request, policy)
    governance.add_policy(PolicyRequest(request.object_type, sending), policy)
    governance.add_workflow(workflow, WorkflowPolicy([InputRule(config["groups"])], request.object_type, "greeting-reader"))
    registers = FileRegisters(ObjectRegisters(creation=directory / "creations.jsonl", release=directory / "releases.jsonl"))
    providers = Providers(store, store, governance, registers=registers)
    return providers.session(identity.application, workflows=[workflow]), providers.policy(request)
