"""Contact-book reducer for ``contact_update`` tnpkgs (Session 8).

See ``docs/superpowers/plans/2026-04-29-contact-update-tnpkg.md`` and
spec §4.10 / §4.6 / D-10 / D-11. The publisher's ``tn sync`` pulls
``contact_update`` tnpkgs from its inbox and runs ``tn.absorb`` on
each. The absorb dispatcher (``tn/absorb.py``) calls into this module
to validate the body and merge it into ``contacts.yaml``.

Contacts.yaml lives at ``<yaml_dir>/.tn/<stem>/contacts.yaml`` (per
``tn.conventions._stem_dir``). Schema for Session 8 is the simple flat
form documented in the plan §"Phase 3"::

    contacts:
      - account_id: <id>
        label: <label>
        package_did: <did or null>
        x25519_pub_b64: <key or null>
        claimed_at: <ts>
        source_link_id: <id or null>

Idempotency: a row matches incoming on the ``(account_id, package_did)``
pair (treating ``None`` as a valid value — i.e. an OAuth-only account
with no package yet matches another OAuth-only entry for the same
account). Match → replace in place. No match → append. **D-25**.

The richer per-local-label grouping in spec §4.10 is a derived view
deferred to a later session; we keep this file flat so concurrent
absorbs reduce predictably.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml as _yaml

from .conventions import tn_dir

# ---------------------------------------------------------------------------
# Body schema
# ---------------------------------------------------------------------------

# Required keys every ``contact_update`` body must carry. ``package_did``,
# ``x25519_pub_b64`` and ``source_link_id`` are required-present-but-may-be-
# null per the plan; we still demand the keys so downstream code can rely
# on key existence without `.get(...)` everywhere.
_REQUIRED_KEYS: tuple[str, ...] = (
    "account_id",
    "label",
    "package_did",
    "x25519_pub_b64",
    "claimed_at",
    "source_link_id",
)

# Subset that must be non-null strings. The other three may be None.
_NON_NULL_STRING_KEYS: tuple[str, ...] = ("account_id", "label", "claimed_at")


def _validate_contact_update_body(doc: Any) -> list[str]:
    """Validate a ``contact_update`` body dict.

    Returns a list of error strings; ``[]`` means valid. Used by both
    the absorb reducer (rejects malformed packages) and the vault
    emitter (asserts shape before signing).
    """
    errors: list[str] = []
    if not isinstance(doc, dict):
        return [f"contact_update body must be a JSON object; got {type(doc).__name__}"]

    for key in _REQUIRED_KEYS:
        if key not in doc:
            errors.append(f"missing required key {key!r}")

    for key in _NON_NULL_STRING_KEYS:
        v = doc.get(key)
        if v is None:
            errors.append(f"required key {key!r} must not be null")
        elif not isinstance(v, str) or not v:
            errors.append(f"required key {key!r} must be a non-empty string")

    # Nullable string fields — None is allowed; if present, must be str.
    for key in ("package_did", "x25519_pub_b64", "source_link_id"):
        v = doc.get(key, ...)  # sentinel: missing handled above
        if v is ... or v is None:
            continue
        if not isinstance(v, str):
            errors.append(f"key {key!r} must be a string or null")

    return errors


# ---------------------------------------------------------------------------
# YAML reducer
# ---------------------------------------------------------------------------


def _contacts_yaml_path(yaml_path: Path) -> Path:
    """Return the canonical contacts.yaml path for the given ceremony.

    Mirrors the per-stem layout used by ``tn.conventions``: lives at
    ``<yaml_dir>/.tn/<stem>/contacts.yaml`` so two ceremonies in the
    same directory don't collide.
    """
    return tn_dir(yaml_path) / "contacts.yaml"


def _load_contacts(yaml_path: Path) -> dict[str, Any]:
    """Read contacts.yaml or return an empty document.

    Empty means ``{"contacts": []}`` so callers can append unconditionally.
    """
    target = _contacts_yaml_path(yaml_path)
    if not target.exists():
        return {"contacts": []}
    raw = target.read_text(encoding="utf-8")
    if not raw.strip():
        return {"contacts": []}
    doc = _yaml.safe_load(raw)
    if not isinstance(doc, dict):
        return {"contacts": []}
    contacts = doc.get("contacts")
    if not isinstance(contacts, list):
        doc["contacts"] = []
    return doc


def _save_contacts(yaml_path: Path, doc: dict[str, Any]) -> None:
    target = _contacts_yaml_path(yaml_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        _yaml.safe_dump(doc, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


def _matches(existing: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Idempotency key per the plan: ``(account_id, package_did)``."""
    return (
        existing.get("account_id") == incoming.get("account_id")
        and existing.get("package_did") == incoming.get("package_did")
    )


def _apply_contact_update(yaml_path: Path, body: dict[str, Any]) -> dict[str, Any]:
    """Merge a validated ``contact_update`` body into contacts.yaml.

    Idempotency rule (plan §"Phase 3", D-25): match on
    ``(account_id, package_did)``; replace in place if matched, else
    append. Returns the new doc as written.
    """
    errors = _validate_contact_update_body(body)
    if errors:
        raise ValueError(
            "_apply_contact_update: invalid body — " + "; ".join(errors)
        )

    # Project to the canonical row shape so downstream readers get a
    # stable schema regardless of caller-supplied extras.
    row = {
        "account_id": body["account_id"],
        "label": body["label"],
        "package_did": body.get("package_did"),
        "x25519_pub_b64": body.get("x25519_pub_b64"),
        "claimed_at": body["claimed_at"],
        "source_link_id": body.get("source_link_id"),
    }

    doc = _load_contacts(yaml_path)
    contacts: list[dict[str, Any]] = doc["contacts"]

    replaced = False
    for i, existing in enumerate(contacts):
        if not isinstance(existing, dict):
            continue
        if _matches(existing, row):
            contacts[i] = row
            replaced = True
            break
    if not replaced:
        contacts.append(row)

    doc["contacts"] = contacts
    _save_contacts(yaml_path, doc)
    return doc


# ---------------------------------------------------------------------------
# Bulk address resolver (federation work, decisions log
# 2026-05-04-federation-and-management-decisions.md D-7)
# ---------------------------------------------------------------------------
#
# Alice's runtime resolves a list of recipient addresses (DID, handle,
# email) into the active-key set per recipient before sealing a
# kit_bundle. The vault's bulk POST /api/v1/contacts/resolve endpoint
# does the lookup; the helpers below wrap it.
#
# Caching: per-process, 5 minute TTL. A revoked DID propagates to
# publishers within the cache window. Override via ``cache_ttl_s`` on
# ``resolve()``.

import re as _re
import threading as _threading
import time as _time
from dataclasses import dataclass as _dataclass, field as _field
from typing import Literal as _Literal


AddressKind = _Literal["did", "handle", "email"]
ResolveStatus = _Literal["found", "not_found"]


_DID_PREFIX = "did:key:z"
_HANDLE_RE = _re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
_EMAIL_RE = _re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def parse_address(s: str) -> tuple[AddressKind, str]:
    """Detect the kind of recipient address and return (kind, normalized_value).

    Detection order:
      1. Starts with ``did:key:z`` -> ``("did", value)`` (verbatim).
      2. Looks like an email -> ``("email", value.lower())``.
      3. Matches the handle regex -> ``("handle", value.lower())``.

    Raises ``ValueError`` when the input doesn't fit any recognized
    shape so callers can branch (log, skip, hard-fail) rather than
    silently mis-classify.
    """
    if not isinstance(s, str):
        raise ValueError(f"parse_address: expected str, got {type(s).__name__}")
    raw = s.strip()
    if not raw:
        raise ValueError("parse_address: empty string")
    if raw.startswith(_DID_PREFIX):
        return ("did", raw)
    if "@" in raw and _EMAIL_RE.match(raw):
        return ("email", raw.lower())
    lowered = raw.lower()
    if _HANDLE_RE.match(lowered):
        return ("handle", lowered)
    raise ValueError(
        f"parse_address: {raw!r} doesn't match did:key, email, or handle shape"
    )


@_dataclass(frozen=True)
class AddressInput:
    kind: AddressKind
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@_dataclass
class ResolveResult:
    """One row of the resolver response."""

    input: AddressInput
    status: ResolveStatus
    account_handle: str | None = None
    active_dids: list[str] = _field(default_factory=list)
    invitable: bool = False

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> ResolveResult:
        inp = doc.get("input") or {}
        return cls(
            input=AddressInput(
                kind=inp.get("kind", "did"),
                value=inp.get("value", ""),
            ),
            status=doc.get("status", "not_found"),
            account_handle=doc.get("account_handle"),
            active_dids=list(doc.get("active_dids") or []),
            invitable=bool(doc.get("invitable", False)),
        )


_CACHE_LOCK = _threading.Lock()
_CACHE: dict[tuple[str, str], tuple[float, "ResolveResult"]] = {}
_DEFAULT_TTL_S = 300.0


def _cache_get(kind: str, value: str, *, ttl_s: float) -> "ResolveResult | None":
    key = (kind, value)
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        ts, result = entry
        if (_time.monotonic() - ts) > ttl_s:
            _CACHE.pop(key, None)
            return None
        return result


def _cache_put(kind: str, value: str, result: "ResolveResult") -> None:
    key = (kind, value)
    with _CACHE_LOCK:
        _CACHE[key] = (_time.monotonic(), result)


def clear_cache() -> None:
    """Drop the entire process-local resolver cache. Useful in tests
    and when an operator wants to force a fresh fetch after a known
    key revocation."""
    with _CACHE_LOCK:
        _CACHE.clear()


def resolve(
    addresses: "list[str | AddressInput]",
    *,
    vault_base: str,
    bearer_jwt: str,
    timeout_s: float = 5.0,
    cache_ttl_s: float = _DEFAULT_TTL_S,
    use_cache: bool = True,
    http_client: "Any | None" = None,
) -> "list[ResolveResult]":
    """Resolve a list of mixed-kind addresses to their active-key sets.

    Each input may be a raw string (auto-classified via
    ``parse_address``) or a pre-built ``AddressInput``. Returns one
    ``ResolveResult`` per input in matching order.

    Calls ``POST {vault_base}/api/v1/contacts/resolve`` with the
    provided bearer JWT. Cached per ``(kind, value)`` for
    ``cache_ttl_s`` seconds (5 min default). Pass ``use_cache=False``
    to force a network call.

    Caller owns the HTTP client lifecycle when one is provided.
    """
    import httpx as _httpx

    parsed: list[AddressInput] = []
    for a in addresses:
        if isinstance(a, AddressInput):
            parsed.append(a)
        else:
            kind, value = parse_address(a)
            parsed.append(AddressInput(kind=kind, value=value))

    cached: dict[int, ResolveResult] = {}
    to_fetch: list[AddressInput] = []
    fetch_index_for_pos: dict[int, int] = {}
    for i, addr in enumerate(parsed):
        if use_cache:
            hit = _cache_get(addr.kind, addr.value, ttl_s=cache_ttl_s)
            if hit is not None:
                cached[i] = hit
                continue
        fetch_index_for_pos[i] = len(to_fetch)
        to_fetch.append(addr)

    fetched: list[ResolveResult] = []
    if to_fetch:
        body = {"addresses": [a.to_dict() for a in to_fetch]}
        url = vault_base.rstrip("/") + "/api/v1/contacts/resolve"
        headers = {
            "Authorization": f"Bearer {bearer_jwt}",
            "Content-Type": "application/json",
        }
        if http_client is None:
            with _httpx.Client(timeout=timeout_s) as c:
                resp = c.post(url, json=body, headers=headers)
        else:
            resp = http_client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        doc = resp.json()
        for row in doc.get("results", []):
            fetched.append(ResolveResult.from_dict(row))
        # Update cache for what came back.
        for addr, result in zip(to_fetch, fetched):
            _cache_put(addr.kind, addr.value, result)

    out: list[ResolveResult] = []
    for i, addr in enumerate(parsed):
        if i in cached:
            out.append(cached[i])
            continue
        idx = fetch_index_for_pos.get(i)
        if idx is not None and idx < len(fetched):
            out.append(fetched[idx])
        else:
            # Server gave fewer rows than we asked for. Defensive
            # fallback so callers iterating in lockstep don't crash.
            out.append(
                ResolveResult(
                    input=addr,
                    status="not_found",
                    active_dids=[],
                    invitable=False,
                )
            )
    return out


def flatten_active_dids(results: "list[ResolveResult]") -> list[str]:
    """Convenience: union of every ``active_dids`` across results,
    deduped, preserving first-seen order. The natural input for
    ``tn.export(seal_for_recipient=True, to_dids=[...])``.
    """
    out: list[str] = []
    for r in results:
        if r.status != "found":
            continue
        for d in r.active_dids:
            if d not in out:
                out.append(d)
    return out


__all__ = [
    "AddressInput",
    "AddressKind",
    "ResolveResult",
    "ResolveStatus",
    "_apply_contact_update",
    "_contacts_yaml_path",
    "_load_contacts",
    "_validate_contact_update_body",
    "clear_cache",
    "flatten_active_dids",
    "parse_address",
    "resolve",
]
