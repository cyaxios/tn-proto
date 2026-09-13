"""Typed identity provider contract. Protocol operations execute in Rust."""
from typing import Protocol
from tn._native.governed import ApplicationIdentity, LocalIdentity

class IdentityProvider(Protocol):
    def resolve(self, application: str) -> ApplicationIdentity: ...
