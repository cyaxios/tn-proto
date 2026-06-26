"""``tn.auth`` - account / session / device-enrollment namespace.

Library-first: every verb returns an :class:`AuthState` (or raises
:class:`AuthError`); the CLI is a thin printer over this. The runtime/init and
the legacy ``tn account connect`` call the same helpers, so there is one
implementation of each piece.

Parity: this mirrors ``ts-sdk/src/auth/``. The :class:`Verdict` values and the
``VERDICT_MESSAGE`` table are IDENTICAL across both SDKs and are asserted equal
by a cross-impl parity test. Design:
``docs/guide/auth-namespace-design.md``.

State machine (the resting state is BACKED_UP), keyed on three layers:
    linked      - the local file claims an account
    enrolled    - the vault agrees this device belongs to that account
    key_cached  - the backup key (AWK) is cached on this machine

Note on TN_API_KEY cold-start (spec G1): the bootstrap is keystore-population
and is ceremony-scoped (needs a yaml + keystore + vault DID), so it lives in
the init/runtime layer, not in account-level ``login``. ``login`` covers
``TN_VAULT_SESSION_TOKEN`` > ``code`` > ``account_passphrase``. Browser sign-in
is interactive I/O and belongs to the CLI, not this library.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._init_attach import cache_account_awk
from .credential_store import awk_key_name, default_credential_store
from .identity import Identity, _default_identity_path
from .vault_client import (
    VaultClient,
    VaultError,
    redeem_connect_code,
    resolve_vault_url,
)

# ---------------------------------------------------------------------------
# Shared contract layer - COMPLETE (parity-tested for Py<->TS equality).
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """The four resting/transition states. String values are the wire
    contract - keep identical to the TS ``Verdict`` union."""

    NOT_LOGGED_IN = "not_logged_in"
    ONE_SIDED_LINK = "one_sided_link"
    LINKED_NO_KEY = "linked_no_key"
    BACKED_UP = "backed_up"


#: ``Verdict`` -> one-line human message. MUST stay byte-identical to the TS
#: ``VERDICT_MESSAGE`` in ``ts-sdk/src/auth/state.ts`` (cross-impl parity test).
VERDICT_MESSAGE: dict[Verdict, str] = {
    Verdict.NOT_LOGGED_IN: "Not logged in - run `tn auth login`.",
    Verdict.ONE_SIDED_LINK: (
        "One-sided link: this device claims an account the vault has not "
        "enrolled. Run `tn auth login` to repair."
    ),
    Verdict.LINKED_NO_KEY: (
        "Linked, but no backup key cached - backups will not run. Run "
        "`tn auth login --account-passphrase`."
    ),
    Verdict.BACKED_UP: "Backed up and ready.",
}


def compute_verdict(
    *, linked: bool, enrolled: bool | None, key_cached: bool
) -> Verdict:
    """Map the three layers onto the state machine. Pure; the shared contract.

    ``enrolled`` is tri-state: ``None`` means "not checked this call" and is
    treated as not-failing (so a verify-less ``status`` can still report
    ``backed_up`` from local signals)."""
    if not linked:
        return Verdict.NOT_LOGGED_IN
    if enrolled is False:
        return Verdict.ONE_SIDED_LINK
    if not key_cached:
        return Verdict.LINKED_NO_KEY
    return Verdict.BACKED_UP


class AuthError(Exception):
    """The ONLY exception ``tn.auth`` verbs raise - the failure the caller
    explicitly asked about (a rejected connect code, or a ``login`` with no
    usable credential). Per the no-crash law, nothing else escapes a verb."""


@dataclass(frozen=True)
class AuthState:
    """Immutable snapshot returned by every ``tn.auth`` verb."""

    device_did: str | None
    account_id: str | None
    vault_url: str
    linked: bool
    enrolled: bool | None
    key_cached: bool

    @property
    def verdict(self) -> Verdict:
        return compute_verdict(
            linked=self.linked, enrolled=self.enrolled, key_cached=self.key_cached
        )

    @property
    def message(self) -> str:
        return VERDICT_MESSAGE[self.verdict]


# ---------------------------------------------------------------------------
# Shared helpers - the single implementation of each piece. Used by the verbs
# AND (via the CLI / init) by the rest of the SDK, so nothing is duplicated.
# ---------------------------------------------------------------------------


def _load_identity() -> Identity | None:
    """Load the machine identity, or ``None`` if absent/unreadable. Never raises."""
    path = _default_identity_path()
    if not path.exists():
        return None
    try:
        return Identity.load(path)
    except Exception:  # noqa: BLE001 - a corrupt file reads as "not logged in"
        return None


def _load_or_mint_identity() -> Identity:
    """Load the machine identity, minting a fresh device key if none exists."""
    path = _default_identity_path()
    if path.exists():
        return Identity.load(path)
    identity = Identity.create_new(word_count=12)
    identity.ensure_written(path)
    return identity


def _resolve_vault(identity: Identity | None, override: str | None) -> str:
    """Vault URL precedence: explicit arg > identity.linked_vault > env/default."""
    return (
        override
        or (identity.linked_vault if identity else None)
        or resolve_vault_url(None)
    )


def _session_token(override: str | None = None) -> str | None:
    """The pre-auth session token (arg, or TN_VAULT_SESSION_TOKEN / legacy JWT)."""
    return (
        override
        or os.environ.get("TN_VAULT_SESSION_TOKEN")
        or os.environ.get("TN_VAULT_JWT")
    )


def _account_passphrase(override: str | None = None) -> str | None:
    return override or os.environ.get("TN_ACCOUNT_PASSPHRASE")


def _backup_key_cached(account_id: str | None) -> bool:
    """Is the backup key (AWK) cached locally for ``account_id``? Never raises."""
    if not account_id:
        return False
    try:
        return default_credential_store().get(awk_key_name(account_id)) is not None
    except Exception:  # noqa: BLE001 - a broken store reads as "not cached"
        return False


def _vault_enrolled(
    identity: Identity, vault_url: str, session_token: str | None
) -> bool:
    """Best-effort: does the vault accept this device's DID as account-bound?
    ``GET /api/v1/account/me`` succeeds only for an enrolled DID. Never raises."""
    try:
        client = VaultClient.for_identity(
            identity, vault_url, session_token=session_token
        )
        try:
            resp = client._request("GET", "/api/v1/account/me")
            return resp.status_code == 200
        finally:
            client.close()
    except Exception:  # noqa: BLE001 - status must never raise
        return False


def _state(
    identity: Identity | None,
    *,
    vault_url: str,
    verify: bool,
    session_token: str | None = None,
) -> AuthState:
    """Build an :class:`AuthState` from local signals (+ an optional vault check)."""
    if identity is None:
        return AuthState(
            device_did=None,
            account_id=None,
            vault_url=vault_url,
            linked=False,
            enrolled=None,
            key_cached=False,
        )
    account_id = identity.linked_account_id
    enrolled: bool | None = None
    if verify and account_id:
        enrolled = _vault_enrolled(identity, vault_url, session_token)
    return AuthState(
        device_did=identity.did,
        account_id=account_id,
        vault_url=vault_url,
        linked=account_id is not None,
        enrolled=enrolled,
        key_cached=_backup_key_cached(account_id),
    )


def _redeem(identity: Identity, code: str, vault_url: str) -> str:
    """Redeem a connect code as this device; return the bound ``account_id``.
    Raises :class:`AuthError` on any vault rejection."""
    sk = Ed25519PrivateKey.from_private_bytes(identity.device_private_key_bytes())
    try:
        resp = redeem_connect_code(code, identity.did, sk, base_url=vault_url)
    except VaultError as exc:
        raise AuthError(f"connect code rejected: {exc}") from exc
    account_id = resp.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        raise AuthError(
            f"vault accepted the code but returned no account_id: {resp!r}"
        )
    return account_id


def _try_cache_key(
    identity: Identity, vault_url: str, passphrase: str | None, account_id: str
) -> None:
    """Cache the backup key (AWK) if a passphrase is available. Best-effort:
    a failure leaves the state at ``linked_no_key`` rather than crashing."""
    if not passphrase:
        return
    try:
        cache_account_awk(identity, vault_url, passphrase, account_id)
    except Exception:  # noqa: BLE001 - contained; state will show key_cached=False
        pass


# ---------------------------------------------------------------------------
# The namespace - thin verbs over the helpers above.
# ---------------------------------------------------------------------------


class _AuthNamespace:
    """``tn.auth`` namespace (mirrors ``tn.agents``). Verbs return
    :class:`AuthState`; only :meth:`login` / :meth:`connect` may raise
    :class:`AuthError`."""

    def status(self, *, vault: str | None = None, verify: bool = True) -> AuthState:
        identity = _load_identity()
        vault_url = _resolve_vault(identity, vault)
        return _state(
            identity,
            vault_url=vault_url,
            verify=verify,
            session_token=_session_token(),
        )

    def whoami(self) -> AuthState:
        return self.status(verify=False)

    def use(self, vault: str) -> AuthState:
        identity = _load_or_mint_identity()
        vault_url = vault.rstrip("/")
        prior = identity.linked_vault
        identity.linked_vault = vault_url
        if prior and prior != vault_url and identity.linked_account_id:
            # The account lived on the old vault; clear it so no one-sided link.
            identity.linked_account_id = None
        identity.ensure_written(_default_identity_path())
        return _state(identity, vault_url=vault_url, verify=False)

    def logout(self) -> AuthState:
        identity = _load_identity()
        if identity is None:
            return _state(None, vault_url=resolve_vault_url(None), verify=False)
        account_id = identity.linked_account_id
        if account_id:
            try:
                default_credential_store().delete(awk_key_name(account_id))
            except Exception:  # noqa: BLE001 - a missing key is fine
                pass
        identity.linked_account_id = None
        identity.linked_vault = None
        identity.ensure_written(_default_identity_path())
        return _state(identity, vault_url=resolve_vault_url(None), verify=False)

    def connect(
        self,
        code: str,
        *,
        account_passphrase: str | None = None,
        vault: str | None = None,
    ) -> AuthState:
        identity = _load_or_mint_identity()
        vault_url = _resolve_vault(identity, vault)
        account_id = _redeem(identity, code, vault_url)
        # Persist the link ONLY after the vault confirms (no one-sided links).
        identity.linked_account_id = account_id
        identity.linked_vault = vault_url
        identity.ensure_written(_default_identity_path())
        _try_cache_key(identity, vault_url, _account_passphrase(account_passphrase), account_id)
        return _state(
            identity, vault_url=vault_url, verify=False, session_token=_session_token()
        )

    def login(
        self,
        *,
        vault: str | None = None,
        code: str | None = None,
        account_passphrase: str | None = None,
        interactive: bool | None = None,  # reserved for the CLI browser path
    ) -> AuthState:
        identity = _load_or_mint_identity()
        vault_url = _resolve_vault(identity, vault)
        passphrase = _account_passphrase(account_passphrase)

        # Credential precedence: code (enroll) > already-enrolled + passphrase
        # (codeless key cache). Session token flows through the vault calls.
        if code:
            return self.connect(
                code, account_passphrase=passphrase, vault=vault_url
            )

        account_id = identity.linked_account_id
        if account_id and passphrase:
            try:
                cache_account_awk(identity, vault_url, passphrase, account_id)
            except Exception as exc:  # noqa: BLE001 - explicit action -> surface it
                raise AuthError(f"could not cache backup key: {exc}") from exc
            return _state(
                identity,
                vault_url=vault_url,
                verify=True,
                session_token=_session_token(),
            )

        raise AuthError(
            "login needs a credential: pass code=<tn_connect_...>, or "
            "account_passphrase= for an already-enrolled device (or set "
            "TN_ACCOUNT_PASSPHRASE). Browser sign-in is handled by the CLI."
        )


#: The ``tn.auth`` namespace instance (parity with ``tn.agents``).
auth = _AuthNamespace()

__all__ = [
    "AuthError",
    "AuthState",
    "Verdict",
    "VERDICT_MESSAGE",
    "compute_verdict",
    "auth",
]
