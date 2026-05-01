"""Vault verbs: link, unlink.

The user-facing vault-link operations. Internally delegates to
`tn.vault_client` (HTTP client) and `tn._dispatch_rt` (runtime singleton).
"""
from __future__ import annotations


def link(vault_did: str, project_id: str) -> None:
    """Record a link to a vault. See tn/__init__.py:_vault_link_impl
    for the full keyword-arg contract.
    """
    from . import _vault_link_impl
    return _vault_link_impl(vault_did, project_id)


def unlink(
    vault_did: str,
    project_id: str,
    reason: str | None = None,
) -> None:
    """Record an unlink. See tn/__init__.py:_vault_unlink_impl."""
    from . import _vault_unlink_impl
    return _vault_unlink_impl(vault_did, project_id, reason)
