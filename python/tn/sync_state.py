"""Persisted sync state for vault interactions.

Tracks state that needs to survive process restarts so that one-shot
CLI invocations (the future ``tn sync`` verb) and long-lived handlers
agree on what's been shipped to the vault.

State file location: ``<yaml_dir>/.tn/sync/state.json``.

Schema (all fields optional; presence-based):

```json
{
    "vault_endpoint": "https://tnproto.org",
    "last_pushed_admin_head": "sha256:...",
    "last_pushed_yaml_sha": "sha256:...",
    "last_synced_generation": 7,
    "inbox_cursor": "...",
    "contacts_cursor": "...",
    "pending_claims_cursor": "...",

    "account_id": "01J...",
    "account_bound": false,
    "pending_claim": {
        "vault_id": "01J...",
        "expires_at": "2026-04-29T13:30:00+00:00",
        "claim_url": "https://tnproto.org/claim/01J.../#abc...",
        "password_b64": "abc..."
    }
}
```

Spec ref: §4.9 (Persisted sync state) and §10 deferred workstream
item 5. This module implements the push-side idempotency tracking
(``last_pushed_admin_head``); the other fields are reserved for the
``tn sync`` verb expansion (item 3) and ``marked-for-merge`` CLI
_reconcile (item 12 client side). They have no readers in this
module; just write-through is supported via :func:`update_sync_state`.

Init-upload mode fields (``account_id``, ``account_bound``,
``pending_claim``) are read by the ``vault.push`` handler to decide
between init-upload and steady-state modes per D-19 / plan
``2026-04-28-pending-claim-flow.md`` §"How the handler distinguishes…".
The ``password_b64`` field is the AES-GCM key used to encrypt the body
on this machine. It travels in the URL fragment to the browser; persisting
it locally lets a handler restart re-derive the same claim URL inside the
30-min TTL window without re-uploading.

Concurrency: writes are atomic-via-rename. Concurrent processes
mutating the same state file will race on the rename, with
last-writer-wins. For the expected use (one publisher process per
ceremony plus occasional CLI invocations), this is sufficient.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

_log = logging.getLogger("tn.sync_state")

STATE_FILE = "state.json"
SYNC_DIR = "sync"


def _state_dir(yaml_path: Path) -> Path:
    """The conventional sync-state directory for a ceremony."""
    return yaml_path.parent / ".tn" / SYNC_DIR


def state_path(yaml_path: Path) -> Path:
    """Absolute path to the sync state file for this ceremony."""
    return _state_dir(yaml_path) / STATE_FILE


def load_sync_state(yaml_path: Path) -> dict[str, Any]:
    """Load the sync state for this ceremony.

    Returns an empty dict if the file doesn't exist or is corrupt
    (warning logged in the corrupt case). Never raises on read errors;
    callers should treat a missing/corrupt file as "no prior state."
    """
    path = state_path(yaml_path)
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text)
        if not isinstance(doc, dict):
            _log.warning(
                "sync_state: %s is not a JSON object (got %s); resetting",
                path, type(doc).__name__,
            )
            return {}
        return doc
    except (OSError, json.JSONDecodeError) as e:
        _log.warning("sync_state: %s unreadable (%s); resetting", path, e)
        return {}


def save_sync_state(yaml_path: Path, state: dict[str, Any]) -> None:
    """Atomic-via-rename write of the sync state.

    Creates the directory on demand. Rename is atomic on POSIX and
    "best-effort atomic" on Windows (Python's ``os.replace`` uses
    ``MoveFileExW`` with ``MOVEFILE_REPLACE_EXISTING``, which is
    atomic on the same volume).

    Logs and swallows write errors; sync state is best-effort and
    should not bring down the caller. A failed save means the next
    process won't see the latest state and may re-push, which is
    handled by the receiver's idempotency (head_row_hash dedup).
    """
    path = state_path(yaml_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as e:
        _log.warning("sync_state: failed to save %s: %s", path, e)


def update_sync_state(yaml_path: Path, **fields: Any) -> dict[str, Any]:
    """Read-modify-write convenience: load, merge in ``fields``, save.

    Returns the new state. Pass ``None`` for a field to delete that key:

        update_sync_state(yaml_path, last_pushed_admin_head="sha256:abc")
        update_sync_state(yaml_path, last_pushed_admin_head=None)  # clear
    """
    state = load_sync_state(yaml_path)
    for k, v in fields.items():
        if v is None:
            state.pop(k, None)
        else:
            state[k] = v
    save_sync_state(yaml_path, state)
    return state


# --- Field-specific helpers (typed wrappers for the most common ops) ---


def get_last_pushed_admin_head(yaml_path: Path) -> str | None:
    """Return the persisted ``last_pushed_admin_head`` if any.

    Used by the push-side handler / one-shot CLI to skip re-pushing
    the same admin-log snapshot when the head hasn't advanced.
    """
    state = load_sync_state(yaml_path)
    val = state.get("last_pushed_admin_head")
    return val if isinstance(val, str) else None


def set_last_pushed_admin_head(yaml_path: Path, head: str) -> None:
    """Persist a new ``last_pushed_admin_head`` value."""
    update_sync_state(yaml_path, last_pushed_admin_head=head)


# --- Init-upload / claim-binding helpers (D-19, plan §"How the handler…") ---


def get_account_id(yaml_path: Path) -> str | None:
    """Return the persisted ``account_id`` if any."""
    state = load_sync_state(yaml_path)
    val = state.get("account_id")
    return val if isinstance(val, str) else None


def is_account_bound(yaml_path: Path) -> bool:
    """True iff ``account_bound`` was previously stamped True.

    Per D-19 / plan: once the user claims, a subsequent vault probe (or
    the bind-echo) flips this to True. The handler reads it on every
    push to decide between init-upload (False) and steady-state (True).
    Default False so a handler that's never seen a successful bind keeps
    routing through the unauthenticated init-upload path.
    """
    state = load_sync_state(yaml_path)
    val = state.get("account_bound")
    return bool(val) if isinstance(val, bool) else False


def get_pending_claim(yaml_path: Path) -> dict[str, Any] | None:
    """Return the persisted in-flight ``pending_claim`` dict, if any.

    Shape (per the plan § "Wire contract" + D-19):
        {"vault_id": str, "expires_at": str (ISO-8601),
         "claim_url": str, "password_b64": str}

    Returns None if no pending claim is recorded. Caller decides what
    to do about expiry — this helper does no time math (so the field
    set stays presence-based; expiry checking happens at the handler).
    """
    state = load_sync_state(yaml_path)
    pc = state.get("pending_claim")
    if isinstance(pc, dict) and pc.get("vault_id"):
        return dict(pc)
    return None


def set_pending_claim(
    yaml_path: Path,
    *,
    vault_id: str,
    expires_at: str,
    claim_url: str,
    password_b64: str,
) -> None:
    """Persist a fresh ``pending_claim`` block on init-upload."""
    update_sync_state(
        yaml_path,
        pending_claim={
            "vault_id": vault_id,
            "expires_at": expires_at,
            "claim_url": claim_url,
            "password_b64": password_b64,
        },
    )


def clear_pending_claim(yaml_path: Path) -> None:
    """Drop the pending_claim block — call once the bind is confirmed."""
    update_sync_state(yaml_path, pending_claim=None)


def mark_account_bound(yaml_path: Path, account_id: str) -> None:
    """Stamp the persistent state with the bound account.

    Side-effect: clears any in-flight pending_claim too — the bind has
    happened, that link is consumed.
    """
    state = load_sync_state(yaml_path)
    state["account_id"] = account_id
    state["account_bound"] = True
    state.pop("pending_claim", None)
    save_sync_state(yaml_path, state)


__all__ = [
    "STATE_FILE",
    "SYNC_DIR",
    "clear_pending_claim",
    "get_account_id",
    "get_last_pushed_admin_head",
    "get_pending_claim",
    "is_account_bound",
    "load_sync_state",
    "mark_account_bound",
    "save_sync_state",
    "set_last_pushed_admin_head",
    "set_pending_claim",
    "state_path",
    "update_sync_state",
]
