"""Governed data objects and independent Rust-backed session instances.

Create a Session from policy text or use Session.from_config(path). Each
instance owns its context; calls never select a module-global runtime.
"""

from tn._native.governed import (
    AdmissionContext,
    AdmittedObject,
    AttachmentContext,
    DataObject,
    DataState,
    Governance,
    GovernanceView,
    GovernedDraft,
    GovernedError,
    GovernedObject,
    GovernedReader,
    NotAPublisher,
    NotEntitled,
    OpenedObject,
    PublicationReport,
    ReleaseContext,
    Session,
    SessionClosed,
    SourceReference,
    UseDenied,
    VerificationError,
)

__all__ = [
    "AdmissionContext",
    "AdmittedObject",
    "AttachmentContext",
    "DataObject",
    "DataState",
    "Governance",
    "GovernanceView",
    "GovernedDraft",
    "GovernedError",
    "GovernedObject",
    "GovernedReader",
    "NotAPublisher",
    "NotEntitled",
    "OpenedObject",
    "PublicationReport",
    "ReleaseContext",
    "Session",
    "SessionClosed",
    "SourceReference",
    "UseDenied",
    "VerificationError",
]
