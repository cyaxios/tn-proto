"""``tn auth`` / ``tn account connect`` CLI verbs.

The ``tn auth ...`` verbs are a THIN printer over the :mod:`tn.auth` library
namespace (``tn/auth.py``): all logic + state lives in the library; these
functions only parse args and format output. Credential model:
``docs/guide/environment-variables.md``.

``tn account connect`` is the legacy alias for connect-code redemption
(``tn auth connect`` is the canonical home). It is kept here because it shares
the signing-identity cascade and warm-attach plumbing; it persists the binding
directly via :mod:`tn.sync_state` rather than going through the namespace.
"""

from __future__ import annotations

import argparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._cache_policy import should_cache_key
from ._init_attach import cache_account_awk
from .auth import AuthError, AuthState, _load_or_mint_identity
from .awk_pickup import drain_pending_awk, redeem_awk_pickup
from .auth import auth as _auth_ns
from .cli_common import _die, _resolve_yaml_or_discover
from .device_flow import (
    DeviceFlowError,
    open_browser,
    poll_device_token,
    request_device_code,
)
from .identity import Identity, _default_identity_path
from .sync_state import (
    SigningIdentityError,
    mark_account_bound,
    resolve_signing_identity,
)
from .vault_client import VaultError, redeem_connect_code, resolve_vault_url


def cmd_account_connect(args: argparse.Namespace) -> int:
    """Redeem a connect code against the vault and persist the binding.

    The receive-side dashboard mints a single-use ``tn_connect_<random>``
    code when the operator clicks "Connect a new app or device". The
    CLI counterpart pastes that code here. We load the device key from
    ``identity.json``, sign SHA-256 of the code with it, POST
    ``{code, did, signature_b64}`` to
    ``/api/v1/account/connect-codes/redeem``, and on success persist the
    returned ``account_id`` into the ceremony's sync state so subsequent
    verbs (``tn sync --pull``, ``tn absorb``) know which account this
    DID belongs to.

    The endpoint is intentionally unauthenticated — the code + signature
    are the authorization. Once the bind lands the DID is in the
    account's ``minted_dids[]`` and subsequent DID-challenge auth calls
    against ``/account/*`` routes work for this DID.
    """
    yaml_path = _resolve_yaml_or_discover(args.yaml)

    # Signing-identity CASCADE (mirrors TS resolveSigningIdentity):
    #   tier 2 supplied (--identity) > tier 1 machine-global identity.json >
    #   tier 3 per-ceremony keystore key. The chosen key's DID is what binds
    #   as the account principal, so it MUST agree across CLIs on one machine.
    try:
        signer = resolve_signing_identity(
            yaml_path,
            supplied_identity_path=getattr(args, "identity", None),
        )
    except SigningIdentityError as exc:
        _die(str(exc))
    sk = signer.private_key
    bound_did = signer.did

    # The machine-global identity (if any) still drives warm-attach
    # (linked_account_id / linked_vault), independent of which tier signed.
    identity_path = _default_identity_path()
    identity = (
        Identity.load(identity_path) if identity_path.is_file() else None
    )

    base_url = args.vault or (identity.linked_vault if identity else None)

    try:
        resp = redeem_connect_code(args.code, bound_did, sk, base_url=base_url)
    except VaultError as exc:
        _die(
            f"connect-code redeem failed (status={exc.status}): {exc.body or exc}",
            code=1,
        )

    account_id = resp.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        _die(
            "vault accepted the redeem but the response did not include "
            f"an account_id: {resp!r}",
        )

    # Persist the account binding into the ceremony's sync state so
    # subsequent CLI verbs (sync --pull, absorb -> /received-kits) can
    # find the bound account without re-reading the connect-code.
    mark_account_bound(yaml_path, account_id)

    # Also remember the account globally in identity.json so a later
    # `tn init` of a *different* project can auto-attach to this same
    # account (warm path) instead of minting a browser claim URL. Only
    # when a machine identity exists (headless tier-3 connects have none).
    if identity is not None and identity.linked_account_id != account_id:
        identity.linked_account_id = account_id
        identity.ensure_written(identity_path)

    print(f"Connected to vault account {account_id}")

    # Cache the account AWK so warm-attach / sync can back up the body
    # non-interactively from here on (connect once, logged in for good). The
    # passphrase is presented once; only the derived AWK is persisted.
    passphrase = getattr(args, "passphrase", None)
    cache_vault = base_url or (identity.linked_vault if identity else None)
    if passphrase and identity is not None and cache_vault:
        try:
            cache_account_awk(identity, cache_vault, passphrase, account_id)
            print("  cached account credential (body backup runs unattended)")
        except Exception as e:  # noqa: BLE001 — caching is best-effort
            print(f"  WARN could not cache account credential: {e}")

    project_id = resp.get("project_id")
    project_name = resp.get("project_name")
    if project_id:
        print(f"  project_id:   {project_id}")
    if project_name:
        print(f"  project_name: {project_name}")
    print(f"  did:          {bound_did}")
    return 0


def _print_auth_state(st: AuthState) -> None:
    """Render an AuthState block. The CLI is the only place auth does I/O."""
    enrolled = "yes" if st.enrolled is True else "no" if st.enrolled is False else "unknown"
    print(f"device:   {st.device_did or '(none)'}")
    print(f"account:  {st.account_id or '(none - not logged in to an account)'}")
    print(f"vault:    {st.vault_url}")
    print("layers:")
    print(f"  linked (local file):  {'yes' if st.linked else 'no'}")
    print(f"  enrolled (vault):     {enrolled}")
    print(f"  backup key (cached):  {'yes' if st.key_cached else 'no'}")
    print(f"=> {st.message}")


def cmd_auth_status(args: argparse.Namespace) -> int:
    """`tn auth status` - thin printer over tn.auth.status()."""
    _print_auth_state(_auth_ns.status(vault=args.vault))
    return 0


def _device_login(vault: str | None, cache_key: bool | None = None) -> int:
    """Browser device-authorization login (RFC 8628): open the verification URL,
    ALWAYS print the short code + URL fallback, poll until the user signs in,
    then stamp the account onto the machine identity. The device key stays the
    principal — no token is stored. Mirrors ts-sdk cli/auth.ts `deviceLogin`."""
    identity = _load_or_mint_identity()
    vault_url = vault or identity.linked_vault or resolve_vault_url(None)
    sk = Ed25519PrivateKey.from_private_bytes(identity.device_private_key_bytes())
    try:
        dc = request_device_code(vault_url, sk, identity.did)
    except DeviceFlowError as exc:
        _die(f"could not start device login: {exc}", code=1)

    # Auto-open AND always print — a non-opening browser is then a non-event.
    print()
    print("To connect this device, open:")
    print(f"  {dc.verification_uri_complete}")
    print()
    print(f"If your browser didn't open, go to  {dc.verification_uri}")
    print(f"and enter the code:                 {dc.user_code}")
    print()
    open_browser(dc.verification_uri_complete)
    print("Waiting for you to sign in...  (Ctrl-C to cancel)")

    try:
        res = poll_device_token(vault_url, dc)
    except DeviceFlowError as exc:
        _die(str(exc), code=1)

    identity.linked_account_id = res["account_id"]
    identity.linked_vault = vault_url
    identity.ensure_written(_default_identity_path())

    cached = False
    key_id = res.get("awk_pickup_key_id")
    if key_id and should_cache_key(cache_key):
        seed = identity.device_private_key_bytes()
        if redeem_awk_pickup(vault_url=vault_url, device_seed=seed,
                             account_id=res["account_id"], key_id_b64=key_id):
            cached = True
            print("  cached account credential (backups run unattended)")
    # Fallback: the device-approve didn't hand us a key_id (e.g. the AWK
    # pickup was minted by a separate browser claim, not this device flow).
    # Drain the inbox for any pickup sealed to this DID so login still ends
    # with a cached AWK. Best-effort — never blocks, never raises.
    if not cached and should_cache_key(cache_key):
        if drain_pending_awk(vault_url=vault_url,
                             device_seed=identity.device_private_key_bytes()):
            print("  cached account credential (backups run unattended)")

    print()
    print(f"Connected as account {res['account_id']}")
    _print_auth_state(_auth_ns.status(vault=vault_url))
    return 0


def cmd_auth_login(args: argparse.Namespace) -> int:
    """`tn auth login` - sign in to your account and connect this device.

    With NO credential it runs the interactive browser device-flow (RFC 8628):
    opens the browser AND prints a short code to type as the fallback, polls
    until you sign in. An explicit `--code` (connect code) or
    `--account-passphrase` are the headless paths, delegated to the library;
    `tn auth connect <code>` is the pure-CI sibling.
    """
    code = getattr(args, "code", None)
    passphrase = getattr(args, "account_passphrase", None)
    if not code and not passphrase:
        return _device_login(getattr(args, "vault", None), cache_key=getattr(args, "cache_key", None))

    try:
        st = _auth_ns.login(
            vault=getattr(args, "vault", None),
            code=code,
            account_passphrase=passphrase,
        )
    except AuthError as exc:
        _die(str(exc), code=1)
    print("[tn auth] Connected.")
    _print_auth_state(st)
    return 0


def cmd_auth_logout(args: argparse.Namespace) -> int:
    """`tn auth logout` - thin printer over tn.auth.logout()."""
    st = _auth_ns.logout()
    print("Logged out on this machine.")
    print(f"  device key kept: {st.device_did or '(none)'}")
    print("  your account and backups in the vault are untouched.")
    return 0


def cmd_auth_whoami(args: argparse.Namespace) -> int:
    """`tn auth whoami` - thin printer over tn.auth.whoami()."""
    st = _auth_ns.whoami()
    if st.device_did is None:
        print("not logged in (no identity on this machine)")
        return 0
    acct = st.account_id or "(no account)"
    print(f"{st.device_did}  ->  account {acct} @ {st.vault_url}")
    return 0


def cmd_auth_use(args: argparse.Namespace) -> int:
    """`tn auth use <vault>` - thin printer over tn.auth.use()."""
    st = _auth_ns.use(args.vault)
    print(f"vault set to {st.vault_url}")
    print("  run `tn auth login` to connect this device to an account there.")
    return 0


def cmd_auth_connect(args: argparse.Namespace) -> int:
    """`tn auth connect <code>` - thin printer over tn.auth.connect().

    Canonical home for connect-code redemption; `tn account connect` is the
    legacy alias.
    """
    try:
        st = _auth_ns.connect(
            args.code,
            account_passphrase=getattr(args, "account_passphrase", None),
            vault=getattr(args, "vault", None),
        )
    except AuthError as exc:
        _die(str(exc))
    print(f"Connected to vault account {st.account_id}")
    _print_auth_state(st)
    return 0
