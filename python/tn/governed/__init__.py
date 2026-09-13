"""Governed data objects and independent Rust-backed session instances.

Create a Session from policy text or use Session.from_config(path). Each
instance owns its context; calls never select a module-global runtime.
"""

from __future__ import annotations

from collections.abc import Callable as _Callable, Sequence as _Sequence

from tn._native.governed import (
    AdmissionContext,
    AdmittedObject,
    AttachmentContext,
    ContractBinding,
    DataObject,
    DataState,
    DatasetBinding,
    DatasetCatalog,
    DatasetEdition,
    DatasetEditionDraft,
    DatasetSelection,
    EvaluatorArtifactSet,
    Governance,
    GovernanceView,
    GovernedDraft,
    GovernedError,
    GovernedObject,
    GovernedReader,
    LineageVerifier,
    NotAPublisher,
    NotEntitled,
    OpenedObject,
    PolicyDag,
    PolicyParent,
    PolicyRelation,
    PolicyRevision,
    PolicyRevisionDraft,
    PublicationReport,
    ReleaseContext,
    ObjectRegisters,
    Session,
    Workflow,
    SessionClosed,
    SourceReference,
    UseContext,
    UseDenied,
    VerificationError,
    VerifiedLineage,
)


def _session_unseal(
    self: Session,
    sealed: str | bytes | GovernedObject | DataObject,
    *,
    decide: _Callable[[AdmissionContext], bool] | None = None,
    purpose: str | None = None,
    use: UseContext | None = None,
    groups: _Sequence[str] | None = None,
    selection: DatasetSelection | None = None,
) -> DataObject:
    """Verify a publication, admit its use, and open the selected groups."""
    return self.receive(
        sealed, decide=decide, purpose=purpose, use=use, groups=groups,
        selection=selection,
    )


def _workflow_unseal(
    self: Workflow,
    source: GovernedObject | DataObject | str | bytes,
    *,
    selection: DatasetSelection | None = None,
) -> DataObject:
    """Open a publication under this workflow's configured input rules."""
    return self.receive(source, selection=selection)


def _workflow_seal(
    self: Workflow,
    data: DataObject,
    *,
    decide: _Callable[[ReleaseContext], bool] | None = None,
) -> GovernedObject:
    """Publish working data after the workflow's output rules accept it."""
    return self.release(data, decide=decide)


def _data_seal(
    self: DataObject,
    *,
    to: str | None = None,
    decide: _Callable[[ReleaseContext], bool] | None = None,
    purpose: str | None = None,
    use: UseContext | None = None,
    object_type: str | None = None,
) -> GovernedObject:
    """Publish working data after configured or explicit release approval."""
    return self.release(
        to=to, decide=decide, purpose=purpose, use=use, object_type=object_type,
    )


Session.unseal = _session_unseal
Workflow.unseal = _workflow_unseal
Workflow.seal = _workflow_seal
DataObject.seal = _data_seal

__all__ = [
    "AdmissionContext",
    "AdmittedObject",
    "AttachmentContext",
    "ContractBinding",
    "DataObject",
    "DataState",
    "DatasetBinding",
    "DatasetCatalog",
    "DatasetEdition",
    "DatasetEditionDraft",
    "DatasetSelection",
    "EvaluatorArtifactSet",
    "Governance",
    "GovernanceView",
    "GovernedDraft",
    "GovernedError",
    "GovernedObject",
    "GovernedReader",
    "LineageVerifier",
    "NotAPublisher",
    "NotEntitled",
    "OpenedObject",
    "PolicyDag",
    "PolicyParent",
    "PolicyRelation",
    "PolicyRevision",
    "PolicyRevisionDraft",
    "PublicationReport",
    "ReleaseContext",
    "Session",
    "ObjectRegisters",
    "Workflow",
    "SessionClosed",
    "SourceReference",
    "UseContext",
    "UseDenied",
    "VerificationError",
    "VerifiedLineage",
]
