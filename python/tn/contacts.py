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


__all__ = [
    "_apply_contact_update",
    "_contacts_yaml_path",
    "_load_contacts",
    "_validate_contact_update_body",
]
