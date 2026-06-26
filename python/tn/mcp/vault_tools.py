"""Vault connector tools for the TN MCP server (ported from Know-Your-Exhaust).

The simple model (local agent, keys on the machine):
  - BIND a new package to your vault account with the COLD-CLAIM flow: mint a
    fresh local ceremony, upload an encrypted full_keystore as a pending claim,
    and hand back a CLAIM URL. You open that URL in a browser signed in to your
    vault account and approve the passkey - that binds the project to YOUR
    account (a real, account-scoped backup; never an orphan).
  - GET your entitled packages from the vault and ABSORB them into the local
    package. Decryption then happens locally with that keystore - no hosted
    sealed-service, no key escrow.
  - Start a NEW local package per project / workstream.

Why cold-claim, always: the warm "attach silently over the device JWT" path
binds only when the device's account already exists on the TARGET vault. Point
it at a vault the identity does not belong to and it creates orphan project rows
with no account binding (and still reports success). The cold claim cannot
orphan: nothing is bound until you accept the claim in the browser, and an
unaccepted claim simply expires.

These are thin wrappers over the tn SDK: tn.init mints the ceremony,
tn.handlers.vault_push.init_upload mints the cold claim, and the ceremony handle
exposes vault_pull_inbox / vault_sync / absorb for the read side.

All vault calls need a reachable vault + a local identity; when absent they
return a clear status rather than raising, so the agent can report cleanly.
"""
from __future__ import annotations

import json
import logging
import webbrowser
from typing import Any

from .. import current_config, init, list_ceremonies, use
from ..handlers.vault_push import _default_client_factory, init_upload
from ..identity import Identity, _default_identity_path
from ..vault_client import VaultClient, resolve_vault_url

_log = logging.getLogger("tn.mcp.vault")

DEFAULT_VAULT = "https://vault.tn-proto.org"


def _identity() -> Any:
    """Load the local device identity, minting one if none exists."""
    p = _default_identity_path()
    if p.exists():
        return Identity.load(p)
    ident = Identity.create_new(word_count=12)
    ident.ensure_written(p)
    return ident


def _client(identity: Any, vault_url: str | None) -> Any:
    """Authenticated VaultClient (DID-challenge handshake on construction).

    Used for the READ side (pull inbox + sync sealed files). The cold-claim
    write side uses the unauthenticated pending-claim client instead.
    """
    return VaultClient.for_identity(identity, vault_url)


def _resolve_vault(identity: Any, vault_url: str | None) -> str:
    """Pick the vault URL: explicit arg > identity's linked vault > default."""
    if vault_url:
        return vault_url.rstrip("/")
    lv = getattr(identity, "linked_vault", None)
    if lv:
        return str(lv).rstrip("/")
    try:
        return str(resolve_vault_url(None)).rstrip("/")
    except Exception:  # noqa: BLE001
        return DEFAULT_VAULT


def _cold_claim(cfg: Any, identity: Any, vault_url: str,
                open_browser: bool = True) -> dict:
    """Mint a COLD pending-claim for `cfg` and return everything the user needs.

    This is the same path the CLI takes when a device has no account on the
    target vault: build an encrypted full_keystore tnpkg, POST it to
    /api/v1/pending-claims (unauthenticated), and return a claim URL whose
    ``#k=`` fragment carries the backup key (the server never sees it).

    Returns a dict with: vault_id, claim_url, expires_at, reused, browser_opened.
    Never raises for the browser open; a failed open just sets browser_opened
    False (the URL is always returned so the agent can surface it).
    """
    client = _default_client_factory(vault_url, identity)
    try:
        result = init_upload(cfg, client, vault_base=vault_url)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            _log.debug("vault client close failed after init_upload", exc_info=True)

    claim_url = result["claim_url"]
    opened = False
    if open_browser:
        try:
            opened = bool(webbrowser.open(claim_url))
        except Exception:  # noqa: BLE001
            _log.debug("browser open failed for claim URL", exc_info=True)
            opened = False

    return {
        "vault_id": result["vault_id"],
        "claim_url": claim_url,
        "expires_at": result["expires_at"],
        "reused": bool(result.get("reused", False)),
        "browser_opened": opened,
    }


def _claim_steps(claim_url: str, vault_url: str) -> list[str]:
    return [
        f"1. Open the claim URL in a browser SIGNED IN to your vault account "
        f"({vault_url}/account). It may already be open in your browser.",
        "2. Approve the passkey / Windows Hello prompt - that binds this "
        "project to your account.",
        "3. It then shows as 'backed up' on your vault dashboard. Run "
        "vault_sync(name=...) afterwards to pull + absorb your entitled kits.",
        f"   (If the browser did not open, paste this URL manually: {claim_url})",
    ]


def new_workstream(name: str, project_dir: str | None = None,
                   vault_url: str | None = None, open_browser: bool = True,
                   bind: bool = True) -> dict:
    """Start a NEW local TN package (ceremony) and COLD-CLAIM it to your vault.

    1. `tn.init(name, link=False)` mints `.tn/<name>/` - a fresh, UNLINKED local
       ceremony (link=False so the SDK never silently warm-attaches/orphans).
    2. If `bind` (default), immediately mint a cold pending-claim and try to open
       the claim URL in your browser. You finish the bind by signing in +
       approving the passkey; nothing is bound to your account until you do.

    Absorbed kits and emitted rows live under this workstream, isolated from
    others. After claiming, call vault_sync(name=...) to fill it from the vault.
    """
    out: dict[str, Any] = {"workstream": name}
    try:
        h = (init(name, project_dir=project_dir, link=False)
             if project_dir else init(name, link=False))
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"could not create ceremony: {exc}"}
    out["yaml"] = str(getattr(h, "yaml_path", ""))
    out["ceremonies"] = list_ceremonies()
    if not bind:
        out["note"] = (f"Local package '{name}' created (unlinked). Bind it later "
                       f"with new_workstream(name='{name}') or claim(name='{name}').")
        return out

    try:
        ident = _identity()
        vault = _resolve_vault(ident, vault_url)
        cfg = getattr(h, "cfg", None) or current_config()
        claim_res = _cold_claim(cfg, ident, vault, open_browser=open_browser)
    except Exception as exc:  # noqa: BLE001
        out["claim_error"] = (f"could not mint claim (need a reachable vault): "
                              f"{exc}")
        out["note"] = (f"Ceremony '{name}' exists locally; vault claim deferred. "
                       f"Retry with claim(name='{name}') once the vault is "
                       f"reachable.")
        return out

    out["vault"] = vault
    out.update(claim_res)
    out["next_steps"] = _claim_steps(claim_res["claim_url"], vault)
    out["note"] = ("Cold-claim flow - no orphaned projects. The claim URL's #k= "
                   "fragment carries the backup key and never reaches the server. "
                   "Unaccepted claims expire on their own. Tell the user the claim "
                   "URL and the passkey step; they own sign-in + passkey.")
    return out


def claim(name: str | None = None, vault_url: str | None = None,
          open_browser: bool = True) -> dict:
    """(Re)mint a COLD claim URL for an existing local ceremony and open it.

    Use to bind a ceremony that was created unlinked, or to re-open a still-live
    claim (idempotent within the claim TTL - it reuses the live pending claim
    rather than minting a duplicate). This is the 'autoclaim' helper: it does
    everything except the parts only the user can do (sign in + passkey).
    """
    out: dict[str, Any] = {"workstream": name or "default"}
    try:
        h = use(name) if name else init(link=False)
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"could not open ceremony: {exc}"}
    try:
        ident = _identity()
        vault = _resolve_vault(ident, vault_url)
        cfg = getattr(h, "cfg", None) or current_config()
        res = _cold_claim(cfg, ident, vault, open_browser=open_browser)
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"could not mint claim (need a reachable vault): "
                                f"{exc}"}
    out["vault"] = vault
    out.update(res)
    out["next_steps"] = _claim_steps(res["claim_url"], vault)
    return out


def vault_sync(name: str | None = None, vault_url: str | None = None) -> dict:
    """READ side: GET the vault contents into the local package - pull the inbox
    of received kits and absorb them, and sync sealed files - so the local
    keystore holds everything this user is entitled to decrypt.

    Binding a NEW project to your account is a separate, consent-gated step:
    use new_workstream(...) / claim(...) (cold-claim), NOT a warm link. This
    function never warm-links (that path can orphan); it only pulls + absorbs.

    name : which local ceremony to sync into (default: the active/default one).
    """
    out: dict[str, Any] = {"workstream": name or "default"}
    try:
        h = use(name) if name else init(link=False)
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"could not open ceremony: {exc}"}

    client = None
    try:
        ident = _identity()
        vault = _resolve_vault(ident, vault_url)
        client = _client(ident, vault)
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"vault auth failed (need a reachable vault + "
                                f"identity): {exc}"}

    try:
        out["vault"] = vault
        out["pulled_inbox"] = str(h.vault_pull_inbox(client))   # pull + absorb received kits
        out["synced"] = str(h.vault_sync(client))               # sealed files
        out["ceremonies"] = list_ceremonies()
        out["note"] = ("Read-side pull complete: the local package holds your "
                       "entitled kits. Decrypt locally with "
                       "tn.read(as_recipient=<keystore>, group=...); obey each "
                       "row's spliced agents.md policy. To BIND a new project to "
                       "your account use new_workstream(...)/claim(...).")
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"vault sync failed: {exc}"
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:  # noqa: BLE001
            _log.debug("vault client close failed after sync", exc_info=True)
    return out


def vault_status(vault_url: str | None = None) -> dict:
    """What is the local package + vault link state? Safe to call anytime."""
    status: dict[str, Any] = {}
    try:
        status["ceremonies"] = list_ceremonies()
    except Exception as exc:  # noqa: BLE001
        status["ceremonies_error"] = str(exc)
    try:
        p = _default_identity_path()
        if p.exists():
            ident = Identity.load(p)
            status["identity"] = "present"
            status["linked_vault"] = getattr(ident, "linked_vault", None)
            status["linked_account"] = getattr(ident, "linked_account_id", None)
        else:
            status["identity"] = "none (a fresh one is minted on first claim)"
    except Exception as exc:  # noqa: BLE001
        status["identity_error"] = str(exc)
    return status


# --- recognizer: "does this look like TN ciphertext?" (for the ambient skill) ---

_ENVELOPE_KEYS = {"device_identity", "row_hash", "signature", "event_type", "sequence"}


def is_tn_envelope(obj: Any) -> bool:
    """True if a dict (or json line) looks like a TN attested row: the envelope
    header fields plus at least one {ciphertext, ...} group block. Used by the
    always-on skill to recognize encrypted exhaust wherever it appears."""
    if isinstance(obj, str):
        try:
            obj = json.loads(obj.strip().splitlines()[0])
        except Exception:  # noqa: BLE001
            return False
    if not isinstance(obj, dict):
        return False
    header_hits = len(_ENVELOPE_KEYS & set(obj))
    has_group_cipher = any(
        isinstance(v, dict) and "ciphertext" in v for v in obj.values()
    )
    return header_hits >= 3 and has_group_cipher
