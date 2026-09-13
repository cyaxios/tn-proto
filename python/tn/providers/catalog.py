"""Typed catalog provider contract. Protocol operations execute in Rust."""
from typing import Protocol
from tn._native.governed import CatalogRequest, CatalogEntry, EditionCatalog

class CatalogProvider(Protocol):
    def resolve(self, request: CatalogRequest) -> CatalogEntry: ...
