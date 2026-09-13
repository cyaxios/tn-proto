"""Typed keys provider contract. Protocol operations execute in Rust."""
from typing import Protocol
from tn._native.governed import ApplicationIdentity, GroupCapability, KeySet, LocalKeys

class KeyProvider(Protocol):
    def resolve(self, identity: ApplicationIdentity) -> KeySet: ...
