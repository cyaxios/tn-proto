"""Vault verbs: link / unlink implementations."""
from __future__ import annotations

import logging

_logger = logging.getLogger("tn")


def _vault_link_impl(vault_did: str, project_id: str) -> None:
    """Emit a signed tn.vault.linked admin event.

    The event is written to the local log and ships via any configured
    vault.sync handler. Use this when you decide to start syncing a
    ceremony to a vault project; the event records the pairing in the
    attested record.

    Idempotent: if an active link to the same (vault_did, project_id)
    already exists (unlinked_at is None), this call is a no-op. Call
    vault.unlink() first to unlink before re-linking.
    """
    import tn
    from . import admin as _admin
    tn._maybe_autoinit_load_only()
    # Idempotency: skip if already linked to this (vault_did, project_id).
    try:
        state = _admin.state()
        for link in state.get("vault_links", []):
            if (
                link.get("vault_did") == vault_did
                and link.get("project_id") == project_id
                and link.get("unlinked_at") is None
            ):
                # Already linked; no-op.
                return
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        # admin.state may fail for corrupt logs; proceed with emit.
        _logger.debug("vault_link idempotency check failed; emitting anyway", exc_info=True)

    from datetime import datetime
    from datetime import timezone as _tz

    tn._require_dispatch().emit(
        "info",
        "tn.vault.linked",
        {
            "vault_did": vault_did,
            "project_id": project_id,
            "linked_at": datetime.now(_tz.utc).isoformat(),
        },
    )
    tn._refresh_admin_cache_if_present()


def _vault_unlink_impl(
    vault_did: str,
    project_id: str,
    reason: str | None = None,
) -> None:
    """Emit a signed tn.vault.unlinked admin event.

    Handlers subscribed to vault-link events interpret this as 'flush
    remaining batches, revoke JWT, stop syncing.' The vault may
    cooperatively delete stored envelopes on receipt.
    """
    import tn
    tn._maybe_autoinit_load_only()
    from datetime import datetime
    from datetime import timezone as _tz

    tn._require_dispatch().emit(
        "info",
        "tn.vault.unlinked",
        {
            "vault_did": vault_did,
            "project_id": project_id,
            "reason": reason,
            "unlinked_at": datetime.now(_tz.utc).isoformat(),
        },
    )
    tn._refresh_admin_cache_if_present()
