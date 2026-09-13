"""Typed register provider contract. Protocol operations execute in Rust."""
from typing import Protocol
from tn._native.governed import RegisterEvent, FileRegisters

class RegisterProvider(Protocol):
    def record(self, event: RegisterEvent) -> None: ...
