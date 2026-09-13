"""Provision an application identity without a literal DID."""
from tn.providers import LocalIdentity

def provision(application):
    return LocalIdentity(application)
