"""Persisted sync state for vault interactions.

Tracks state that needs to survive process restarts so that one-shot
CLI invocations (the future ``tn sync`` verb) and long-lived handlers
agree on what's been shipped to the vault.

State file location: ``<yaml_dir>/.tn/sync/state.json``.

Schema (all fields optional; presence-based):

```json
{
    "vault_endpoint": "https://vault.tn-proto.org",
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
        "claim_url": "https://vault.tn-proto.org/claim/01J.../#abc...",
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._keystore_backend import secure_write_text

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
    """Owner-only atomic write of the sync state.

    Creates the directory on demand and routes the write through
    :func:`secure_write_text` (same-dir tmp created ``0600`` + fsync +
    ``os.replace``). The state file holds the pending_claim record,
    which includes the BEK (``password_b64``) and the full claim URL, so
    it must be owner-only at rest (POSIX 0600; on Windows the
    user-profile ACL is the protection). The rename is atomic on POSIX
    and on Windows for same-volume moves (``MoveFileExW`` with
    ``MOVEFILE_REPLACE_EXISTING``); the tmp file is a sibling so this
    holds.

    Logs and swallows write errors; sync state is best-effort and
    should not bring down the caller. A failed save means the next
    process won't see the latest state and may re-push, which is
    handled by the receiver's idempotency (head_row_hash dedup).
    """
    path = state_path(yaml_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        secure_write_text(path, json.dumps(state, indent=2, sort_keys=True))
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


# ---------------------------------------------------------------------
# Signing-identity cascade for `tn account connect`
# ---------------------------------------------------------------------
#
# `account connect` signs sha256(code) and binds the SIGNER'S DID as an
# account principal (it lands in accounts.minted_dids[]). Python and
# TypeScript historically picked DIFFERENT signing keys for this, so the
# same operator bound a different DID depending on which binary ran. The
# resolver below is the single, language-mirrored decision of which key
# signs the redeem. Its TS twin is
# `tn-proto/ts-sdk/src/account/signing_identity.ts::resolveSigningIdentity`.
#
# Cascade — first available wins:
#   tier 2  SUPPLIED   — an explicit identity path passed by the caller
#                        (`--identity <path>`); the explicit override.
#   tier 1  MACHINE    — the machine-global identity.json under
#                        TN_IDENTITY_DIR / the platform default. This is
#                        the DEFAULT when a machine identity exists, and
#                        matches Python's historical behaviour.
#   tier 3  CEREMONY   — the per-ceremony keystore key
#                        (`<keystore>/local.private`). The FALLBACK for
#                        the headless / CI case where no machine identity
#                        has been minted (matches TS's historical
#                        behaviour).


class SigningIdentityError(Exception):
    """No signing identity could be resolved through the cascade."""


@dataclass(frozen=True)
class ResolvedSigningIdentity:
    """The key chosen by the cascade to sign an `account connect` redeem.

    Attributes
    ----------
    did
        The ``did:key:z...`` that will be bound as the account principal.
    private_key
        The Ed25519 private key matching ``did`` (used by
        :func:`tn.vault_client.redeem_connect_code`).
    tier
        Which cascade tier produced this key: ``"supplied"`` (2),
        ``"machine"`` (1) or ``"ceremony"`` (3).
    source_path
        The on-disk artefact the key was read from (identity.json for
        tiers 1/2, ``local.private`` for tier 3). Diagnostic only.
    """

    did: str
    private_key: Any  # Ed25519PrivateKey — typed Any to avoid a hard import here
    tier: str
    source_path: Path


def resolve_signing_identity(
    yaml_path: Path,
    *,
    supplied_identity_path: Path | str | None = None,
    machine_identity_path: Path | None = None,
) -> ResolvedSigningIdentity:
    """Resolve which Ed25519 key signs an `account connect` redeem.

    See the module-level cascade note. The TS twin is
    ``resolveSigningIdentity`` in
    ``ts-sdk/src/account/signing_identity.ts``; keep the two in lockstep.

    Parameters
    ----------
    yaml_path
        The ceremony yaml. Used to locate the per-ceremony keystore for
        the tier-3 fallback.
    supplied_identity_path
        Tier 2 override: an explicit ``identity.json`` path (e.g. from a
        ``--identity`` flag). When given and loadable, it wins outright.
    machine_identity_path
        Tier 1 path override (defaults to ``_default_identity_path()``).
        Exposed for tests; production passes the default.

    Raises
    ------
    SigningIdentityError
        When the cascade exhausts without finding any usable key.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from .identity import Identity, IdentityError, _default_identity_path

    # --- tier 2: SUPPLIED override -----------------------------------
    if supplied_identity_path is not None:
        sup = Path(supplied_identity_path)
        try:
            identity = Identity.load(sup)
        except IdentityError as exc:
            raise SigningIdentityError(
                f"--identity {sup} could not be loaded: {exc}",
            ) from exc
        sk = Ed25519PrivateKey.from_private_bytes(
            identity.device_private_key_bytes()
        )
        return ResolvedSigningIdentity(
            did=identity.did,
            private_key=sk,
            tier="supplied",
            source_path=sup,
        )

    # --- tier 1: MACHINE-GLOBAL identity (the default) ---------------
    machine_path = machine_identity_path or _default_identity_path()
    if machine_path.is_file():
        try:
            identity = Identity.load(machine_path)
        except IdentityError:
            identity = None
        if identity is not None:
            sk = Ed25519PrivateKey.from_private_bytes(
                identity.device_private_key_bytes()
            )
            return ResolvedSigningIdentity(
                did=identity.did,
                private_key=sk,
                tier="machine",
                source_path=machine_path,
            )

    # --- tier 3: PER-CEREMONY keystore key (the fallback) ------------
    keystore_priv = _ceremony_keystore_private(yaml_path)
    if keystore_priv is not None:
        priv_path, seed = keystore_priv
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        did = _did_key_from_ed25519_private(sk)
        return ResolvedSigningIdentity(
            did=did,
            private_key=sk,
            tier="ceremony",
            source_path=priv_path,
        )

    raise SigningIdentityError(
        "no signing identity for `account connect`: no machine identity at "
        f"{machine_path} and no ceremony keystore key for {yaml_path}. "
        "Run `tn init <project>` to create one, or pass --identity <path>.",
    )


def _ceremony_keystore_private(yaml_path: Path) -> tuple[Path, bytes] | None:
    """Return ``(local.private path, 32-byte seed)`` for the ceremony at
    ``yaml_path``, or ``None`` when the keystore key is absent.

    Mirrors the keystore-path resolution in
    ``tn.config._load_keystore_and_keys`` (``keystore.path`` in the yaml,
    default ``./.tn/keys``) so the fallback signs with the exact key the
    TS ``loadKeystore`` would pick.
    """
    try:
        import yaml as _yaml

        with Path(yaml_path).open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh) or {}
    except Exception:  # noqa: BLE001 — any read/parse failure = no keystore
        return None
    keystore_section = doc.get("keystore") if isinstance(doc, dict) else None
    raw_path = (
        keystore_section.get("path")
        if isinstance(keystore_section, dict)
        else None
    )
    keystore_dir = (
        (Path(yaml_path).parent / raw_path).resolve()
        if raw_path
        else (Path(yaml_path).parent / ".tn" / "keys").resolve()
    )
    priv_path = keystore_dir / "local.private"
    if not priv_path.is_file():
        return None
    seed = priv_path.read_bytes()
    if len(seed) != 32:
        return None
    return priv_path, seed


def _did_key_from_ed25519_private(sk: Any) -> str:
    """did:key for an Ed25519 private key (matches identity encoding)."""
    from cryptography.hazmat.primitives import serialization

    from .identity import _did_key_from_ed25519_pub

    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _did_key_from_ed25519_pub(pub)


__all__ = [
    "STATE_FILE",
    "SYNC_DIR",
    "ResolvedSigningIdentity",
    "SigningIdentityError",
    "clear_pending_claim",
    "get_account_id",
    "get_last_pushed_admin_head",
    "get_pending_claim",
    "is_account_bound",
    "load_sync_state",
    "mark_account_bound",
    "resolve_signing_identity",
    "save_sync_state",
    "set_last_pushed_admin_head",
    "set_pending_claim",
    "state_path",
    "update_sync_state",
]
