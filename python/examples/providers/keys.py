"""Assign a publisher and reader capability to a resolved identity."""
from tn.providers import LocalKeys

def provision(identity):
    keys = LocalKeys(["default", "policy_revision", "dataset_edition"])
    keys.assign(identity, read=["default"], publish=["default", "tn.agents", "policy_revision", "dataset_edition"])
    return keys
