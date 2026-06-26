"""Init-time account attach/sync — the single decision both ``tn init``
paths (CLI ``cmd_init`` and library ``_auto_link_after_init``) share so
they can never diverge again.

CONTRACT (this is the spec; the implementation below must match it). When
``tn.init()`` runs and vault linking is enabled, exactly one of three modes
fires, chosen from purely-local signals (no network needed to decide):

    ┌─ logged-in account?  (identity.linked_account_id set, OR TN_API_KEY env)
    │
    ├─ NO  ──────────────────────────────────────────────►  MODE: CLAIM_URL
    │        The machine has never connected to a vault account. Mint an
    │        anonymous ``full_keystore`` pending-claim and surface a CLAIM
    │        URL the user opens in a browser to create / attach an account.
    │        Credential-free (the BEK rides in the URL fragment; the browser
    │        binds it to the account at claim time). This is the legacy
    │        ``init_upload`` behavior, unchanged.
    │
    └─ YES ─┬─ project already exists?  (cfg.linked_project_id set)
            │
            ├─ NO  ──────────────────────────────────────►  MODE: WARM_CREATE
            │        Connected account, but THIS project isn't registered
            │        yet. Authenticate as the device DID (credential-free —
            │        the device key is a minted DID on the account), then:
            │          1. link_ceremony()   → CREATE the project row.
            │          2. sync_ceremony()   → PUSH the backup.
            │        No browser, no claim URL.
            │
            └─ YES ──────────────────────────────────────►  MODE: WARM_SYNC
                     Connected account AND the project already exists. Do
                     NOT re-link (that double-registers). Reconcile:
                       1. pull + absorb the account inbox (credential-free).
                       2. sync_ceremony()  → PUSH local changes up.

CREDENTIAL MODEL (the gh/claude pattern: cache a derived key, never the
master secret, in the OS keychain with a 0600-file fallback):
  * Device-DID auth, project registration (link_ceremony), inbox pull, and
    the signed-manifest/snapshot push are ALL credential-free — the device
    key (local) signs the vault's challenge, minting an EPHEMERAL DID JWT
    (no stored session token to leak). No passphrase required.
  * The full BODY backup (the encrypted keystore blob) needs the account
    **AWK** to wrap the project BEK (wallet.py:378 skips the body push when
    it can't derive one). The AWK is obtained ONCE: ``tn account connect``
    (or ``tn account connect --passphrase``) takes the passphrase, runs the
    ``passphrase → credential-key → AWK`` unwrap, and CACHES the derived AWK
    in the machine ``CredentialStore`` (OS keychain when available, 0600
    file fallback for headless / CI / containers). The master passphrase is
    NEVER persisted — only the account-scoped AWK ("token, not password").
  * Warm-attach / sync READ the cached AWK from the CredentialStore, so the
    body backup runs NON-INTERACTIVELY after a one-time connect. If the
    store holds no AWK (never unlocked), the credential-free legs still run
    (project registered, inbox pulled, manifest pushed) and the body backup
    is a single contained warning pointing at ``tn account connect --passphrase`` — NOT an
    error, NOT a raise.

CONTAINMENT LAW ([[feedback-sdk-never-crashes-userspace]]): nothing in this
module may raise into the caller's ``init()``. Every vault failure is caught
and returned as a warning on the AttachOutcome; the on-disk ceremony always
stays valid. The only exceptions a caller ever sees are ones it explicitly
asked for elsewhere — never from attach.

This module owns the decision + orchestration only. The crypto/wire work
lives in wallet.py (link_ceremony / sync_ceremony), handlers/vault_push.py
(init_upload), handlers/vault_pull.py + cli pull-absorb, and sync_state.py
(the local detection signals).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import wallet as _wallet
from . import wallet_pull as _wallet_pull
from .config import load as _load_config
from .credential_store import (
    CredentialStore,
    awk_key_name,
    default_credential_store,
)
from .handlers.vault_push import _default_client_factory, init_upload
from .vault_client import VaultClient
from .wallet_restore_passphrase import derive_account_awk

if TYPE_CHECKING:  # import-cycle-safe: types only, no runtime import
    from .config import LoadedConfig
    from .identity import Identity


class AttachMode(str, Enum):
    """Which of the three init paths fired. Returned on AttachOutcome so the
    caller (and tests) can assert the decision without re-deriving it."""

    CLAIM_URL = "claim_url"     # no logged-in account → anonymous pending-claim
    WARM_CREATE = "warm_create"  # logged-in + new project → link + push
    WARM_SYNC = "warm_sync"      # logged-in + existing project → pull/merge + push


@dataclass
class AttachOutcome:
    """The result of an init-time attach/sync. Never an exception — failures
    are contained and surfaced in ``warnings`` (the containment law)."""

    mode: AttachMode
    #: True iff the warm attach actually completed (device authed + project
    #: registered/synced). False on a contained hard failure (auth/connect/
    #: attach) where the ceremony stayed local-only. The CLI reads this so it
    #: never prints "Attached" when the vault was unreachable. CLAIM_URL mode
    #: leaves this False (nothing is attached until the browser claim).
    attached: bool = False
    #: vault-side project id once known (None in CLAIM_URL mode pre-claim).
    project_id: str | None = None
    #: body-member names pushed by sync_ceremony (empty when no passphrase).
    uploaded: list[str] = field(default_factory=list)
    #: inbox snapshots pulled + absorbed (WARM_SYNC only).
    pulled: int = 0
    #: claim URL surfaced in CLAIM_URL mode (None otherwise).
    claim_url: str | None = None
    #: contained, non-fatal notes (e.g. "body backup skipped: no passphrase").
    warnings: list[str] = field(default_factory=list)


def _warm_attach_signal(identity: Identity, vault_url: str) -> str | None:
    """Pick the credential for the warm (no-browser) attach, or None to
    fall through to the claim-URL flow.

    ``TN_API_KEY`` is an explicit, operator-supplied key for this run and
    always wins. The remembered ``identity.linked_account_id`` only
    applies when the target ``vault_url`` is the vault that account
    actually lives on (``identity.linked_vault``): re-pointing a device at
    a different vault (e.g. ``tn init --link <other>``) must NOT reuse the
    old account, or the project would be registered on the wrong vault
    under the bare device DID instead of being claimed under the user's
    account there.

    Lives HERE (not in the CLI) so it gates BOTH ``attach_or_sync``
    callers: ``cli.cmd_init`` and the library ``tn.__init__
    ._auto_link_after_init`` path.
    """
    api_key = os.environ.get("TN_API_KEY")
    if api_key:
        return api_key
    if identity.linked_account_id and identity.linked_vault == vault_url:
        return identity.linked_account_id
    return None


def attach_or_sync(
    cfg: LoadedConfig,
    identity: Identity,
    vault_url: str,
    *,
    store: CredentialStore | None = None,
    pull_absorb: Callable[[Any, Identity, Path], int] | None = None,
) -> AttachOutcome:
    """Decide and execute the init-time vault interaction per the module
    CONTRACT above. Pure orchestration; NEVER raises (the containment law).

    Parameters
    ----------
    cfg
        The loaded ceremony config (caller loads it; keeps this module free
        of the ``tn.init`` import cycle). ``cfg.linked_project_id`` is the
        project-exists signal.
    identity
        The machine identity. ``identity.linked_account_id`` is the
        logged-in-account signal.
    vault_url
        Resolved vault base URL.
    store
        CredentialStore holding the cached AWK; defaults to
        :func:`default_credential_store`.
    pull_absorb
        The WARM_SYNC inbox pull+absorb step. Defaults to
        :func:`tn.wallet_pull.pull_and_absorb` (quiet — ``report=None``) so
        the library ``tn.init()`` path reconciles DOWN before pushing UP. The
        CLI injects a narrating variant (``_pull_absorb_step``, which passes
        ``print``); tests inject a stub.

    Returns
    -------
    AttachOutcome
        Which mode ran and what it did. Inspect ``.warnings`` for contained
        failures; the call itself never raises.
    """
    account_id = identity.linked_account_id
    if not _warm_attach_signal(identity, vault_url):
        # MODE CLAIM_URL — no logged-in account usable for THIS vault
        # (never connected, or the remembered account lives on a different
        # vault and must not be reused) → anonymous pending-claim.
        try:
            client = _default_client_factory(vault_url, identity)
            result = init_upload(cfg, client, vault_base=vault_url)
            return AttachOutcome(
                mode=AttachMode.CLAIM_URL,
                claim_url=result.get("claim_url"),
            )
        except Exception as e:  # noqa: BLE001 — contain; ceremony stays valid
            return AttachOutcome(
                mode=AttachMode.CLAIM_URL,
                warnings=[f"claim-url upload failed: {type(e).__name__}: {e}"],
            )

    # Logged-in account. The cached AWK (None until `tn account connect --passphrase`).
    cred_store = store or default_credential_store()
    try:
        awk = cred_store.get(awk_key_name(account_id))
    except Exception:  # noqa: BLE001 — a broken store must not break init
        awk = None

    project_exists = bool(getattr(cfg, "linked_project_id", None))
    mode = AttachMode.WARM_SYNC if project_exists else AttachMode.WARM_CREATE
    # Default the pull leg to the shared engine so the library path reconciles
    # DOWN too; the CLI injects a narrating variant.
    pull = pull_absorb if pull_absorb is not None else _wallet_pull.pull_and_absorb
    warnings: list[str] = []

    try:
        client = VaultClient.for_identity(identity, vault_url)
    except Exception as e:  # noqa: BLE001 — auth failure → contain, stay local
        return AttachOutcome(
            mode=mode,
            project_id=getattr(cfg, "linked_project_id", None),
            warnings=[f"account auth failed: {type(e).__name__}: {e}"],
        )

    try:
        if mode is AttachMode.WARM_CREATE:
            # New project: register it under the account (credential-free).
            # link_ceremony persists linked_project_id to disk (set_link_state)
            # but does NOT refresh cfg in place — reload so the push below sees
            # the freshly-assigned project id.
            _wallet.link_ceremony(cfg, client)
            cfg = _load_config(cfg.yaml_path)
        else:
            # Existing project (WARM_SYNC): reconcile DOWN first (never
            # re-link). ``pull`` defaults to wallet_pull.pull_and_absorb.
            try:
                pull(cfg, identity, cfg.yaml_path)
            except Exception as e:  # noqa: BLE001 — pull is best-effort
                warnings.append(f"pull/merge failed: {type(e).__name__}: {e}")

        # Push UP. The body backup runs iff an AWK was cached; otherwise the
        # credential-free legs already ran and sync_ceremony records a
        # contained ``<passphrase>`` note in errors (NOT a raise).
        result = _wallet.sync_ceremony(cfg, client, awk=awk)
        for key, msg in getattr(result, "errors", []) or []:
            warnings.append(f"{key}: {msg}")
        # Reached here only after device auth + link/sync succeeded. Soft
        # notes (e.g. body-backup-skipped) may still ride in `warnings`, but
        # the account attach itself completed → attached=True.
        return AttachOutcome(
            mode=mode,
            attached=True,
            project_id=getattr(cfg, "linked_project_id", None),
            uploaded=list(getattr(result, "uploaded", []) or []),
            warnings=warnings,
        )
    except Exception as e:  # noqa: BLE001 — contain everything; never crash init
        return AttachOutcome(
            mode=mode,
            project_id=getattr(cfg, "linked_project_id", None),
            warnings=[*warnings, f"attach failed: {type(e).__name__}: {e}"],
        )
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001 — best-effort client close
            pass


def cache_account_awk(
    identity: Identity,
    vault_url: str,
    passphrase: str,
    account_id: str,
    *,
    store: CredentialStore | None = None,
) -> None:
    """Derive the account AWK from ``passphrase`` and cache it — the "connect
    once, logged in for good" step (called by ``tn account connect`` /
    ``tn account connect --passphrase``).

    Authenticates as the device DID (challenge JWT) to read the credential
    wrap, runs ``passphrase → credential-key → AWK``, and stores ONLY the
    derived AWK (never the passphrase) under ``awk_key_name(account_id)``.
    Raises on failure so the caller can decide how loudly to report it.
    """
    client = VaultClient.for_identity(identity, vault_url)
    try:
        bearer = client.token or client.authenticate()
        awk = derive_account_awk(
            vault_url=vault_url, bearer=bearer, passphrase=passphrase
        )
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001 — best-effort client close
            pass
    (store or default_credential_store()).set(awk_key_name(account_id), awk)
