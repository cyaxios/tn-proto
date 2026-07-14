"""Core verb tool implementations: tn_status, tn_read, tn_decrypt.

Each ``*_impl`` function is the body of one MCP tool. The server module
wraps them with the FastMCP decorator; keeping the logic here means the
tools can be exercised directly (no transport) in tests and smoke runs.

Containment: these functions never let a raw traceback reach the agent.
Failures either come back as a clear ``{"error": ...}`` payload (status,
decrypt) or are re-raised as a one-line ``RuntimeError`` built via
``errors.map_exception`` (read, where the caller explicitly asked for
``verify="raise"`` semantics).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import current_config, using_rust
from .._autoinit import maybe_autoinit_load_only
from .._entry import Entry as _SdkEntry
from ..config import LoadedConfig
from ..config import load as _load_config
from ..read import read as _tn_read
from ..reader import _lines_with_keybag
from .errors import map_exception
from .schemas import (
    DecryptedRow,
    DecryptFailure,
    DecryptInput,
    DecryptOutput,
    Entry,
    GroupSummary,
    ReadInput,
    ReadOutput,
    StatusOutput,
)

logger = logging.getLogger("tn.mcp.tools")

_NO_CEREMONY_MESSAGE = (
    "No ceremony found. Run `tn init` in the project directory (or set "
    "TN_YAML to an existing tn.yaml), then retry."
)

# Envelope keys _lines_with_keybag dereferences unconditionally; a JSON
# object missing any of them is not a TN envelope and is surfaced as a
# per-line failure instead of being fed to the decryptor.
_REQUIRED_ENVELOPE_KEYS = ("event_type", "prev_hash", "row_hash")


# --------------------------------------------------------------------- #
#  Shared helpers                                                       #
# --------------------------------------------------------------------- #


def _resolve_active_config() -> LoadedConfig:
    """Return the active ceremony's LoadedConfig, auto-initializing from an
    EXISTING on-disk ceremony if the runtime isn't bound yet (mirrors the
    tn.read path: never mints a fresh ceremony). Raises RuntimeError with
    a friendly hint when nothing is found.
    """
    try:
        return current_config()
    except RuntimeError:
        maybe_autoinit_load_only()
        return current_config()


def _serialize_entry(entry: _SdkEntry) -> Entry:
    """Convert an SDK Entry into the wire-shaped schemas.Entry.

    ``model_dump(mode="json")`` first, so non-JSON field values (datetime,
    Decimal, bytes) come out JSON-safe. The SDK's ``did`` attribute maps to
    the envelope-spec name ``device_identity``.
    """
    d = entry.model_dump(mode="json")
    return Entry(
        event_type=d["event_type"],
        timestamp=d["timestamp"],
        level=d["level"],
        message=d.get("message"),
        device_identity=d["did"],
        sequence=d["sequence"],
        event_id=d["event_id"],
        fields=d["fields"],
        hidden_groups=d["hidden_groups"],
    )


def _parse_iso(value: str | None, param: str) -> datetime | None:
    """Parse an ISO-8601 string; naive values are interpreted as UTC."""
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"tn_read: `{param}` is not a valid ISO-8601 timestamp: {value!r}"
        ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _entry_matches(
    entry: _SdkEntry,
    *,
    since: datetime | None,
    until: datetime | None,
    fields_equal: dict[str, str] | None,
) -> bool:
    """Apply the tool-level structured filters to one SDK entry."""
    if since is not None and entry.timestamp < since:
        return False
    if until is not None and entry.timestamp > until:
        return False
    if fields_equal:
        for name, want in fields_equal.items():
            if name not in entry.fields:
                return False
            if str(entry.fields[name]) != want:
                return False
    return True


# --------------------------------------------------------------------- #
#  tn_status                                                            #
# --------------------------------------------------------------------- #


def tn_status_impl() -> dict[str, Any]:
    """One-shot summary of the active ceremony.

    Never raises: when no ceremony is resolvable the payload carries a
    clear ``error`` message instead.
    """
    try:
        cfg = _resolve_active_config()
    except Exception as exc:  # noqa: BLE001 - containment: surface as error payload
        _code, message, _data = map_exception(exc)
        logger.info("tn_status: no ceremony resolvable (%s)", message)
        return {"error": _NO_CEREMONY_MESSAGE, "detail": message}

    fields_by_group: dict[str, list[str]] = {name: [] for name in cfg.groups}
    for field_name, group_names in cfg.field_to_groups.items():
        for group_name in group_names:
            fields_by_group.setdefault(group_name, []).append(field_name)
    groups = [
        GroupSummary(name=name, fields=sorted(fields))
        for name, fields in sorted(fields_by_group.items())
    ]

    out = StatusOutput(
        did=cfg.device.device_identity,
        yaml_path=str(cfg.yaml_path),
        ceremony_id=cfg.ceremony_id,
        cipher=cfg.cipher_name,
        mode=cfg.mode,
        linked_vault=cfg.linked_vault,
        linked_project_id=cfg.linked_project_id,
        project_name=cfg.project_name,
        sign=cfg.sign,
        chain=cfg.chain,
        rust_path=using_rust(),
        groups=groups,
    )
    logger.debug("tn_status: ceremony=%s mode=%s", cfg.ceremony_id, cfg.mode)
    return out.model_dump(mode="json")


# --------------------------------------------------------------------- #
#  tn_read                                                              #
# --------------------------------------------------------------------- #


def tn_read_impl(inp: ReadInput) -> dict[str, Any]:
    """Read the ceremony's log through ``tn.read`` with structured filters.

    Every trust-policy option passes through to ``tn.read`` unchanged. Under
    the default ``verify="auto"`` (or ``True`` / ``"raise"``) a failing row
    surfaces as a one-line RuntimeError (built from ``errors.map_exception``),
    never a raw traceback.
    """
    since = _parse_iso(inp.since, "since")
    until = _parse_iso(inp.until, "until")

    selector: str | None = None
    read_filter: dict[str, Any] | None = None
    if inp.event_type:
        if inp.event_type.endswith("*"):
            # Prefix match pushes down via the declarative filter dict.
            read_filter = {"event_type_prefix": inp.event_type[:-1]}
        else:
            selector = inp.event_type

    entries: list[Entry] = []
    total_scanned = 0
    matched = 0
    try:
        for e in _tn_read(
            selector,
            filter=read_filter,
            verify=inp.verify,
            require_signature=inp.require_signature,
            allow_unauthenticated=inp.allow_unauthenticated,
            trusted_writers=inp.trusted_writers,
            allow_unknown_writers=inp.allow_unknown_writers,
            log=inp.log,
        ):
            total_scanned += 1
            if not _entry_matches(
                e, since=since, until=until, fields_equal=inp.fields_equal
            ):
                continue
            matched += 1
            if matched <= inp.limit:
                entries.append(_serialize_entry(e))
    except Exception as exc:  # noqa: BLE001 - containment: re-raise as one-line RuntimeError
        code, message, _data = map_exception(exc)
        logger.info("tn_read failed (%s): %s", code, message)
        raise RuntimeError(f"tn_read failed ({code}): {message}") from None

    out = ReadOutput(
        entries=entries,
        total_scanned=total_scanned,
        returned=len(entries),
        truncated=matched > len(entries),
    )
    logger.debug(
        "tn_read: scanned=%d matched=%d returned=%d",
        total_scanned, matched, len(entries),
    )
    return out.model_dump(mode="json")


# --------------------------------------------------------------------- #
#  tn_decrypt                                                           #
# --------------------------------------------------------------------- #


def tn_decrypt_impl(inp: DecryptInput) -> dict[str, Any]:
    """Decrypt pasted TN ndjson lines against the local keystore.

    Contained: bad input comes back as a clear ``{"error": ...}`` payload
    or as per-line entries in ``failures``; this function never crashes
    the host.
    """
    # Resolve the keystore: explicit yaml wins, else the active ceremony.
    try:
        if inp.yaml:
            cfg = _load_config(Path(inp.yaml).expanduser())
        else:
            cfg = _resolve_active_config()
    except Exception as exc:  # noqa: BLE001 - containment: surface as error payload
        _code, message, _data = map_exception(exc)
        logger.info("tn_decrypt: keystore resolution failed (%s)", message)
        if inp.yaml:
            return {
                "error": (
                    f"Could not load ceremony yaml {inp.yaml!r}: {message}"
                ),
            }
        return {"error": _NO_CEREMONY_MESSAGE, "detail": message}

    keystore_path = Path(cfg.keystore)
    if not keystore_path.is_dir():
        return {
            "error": (
                f"Keystore directory not found: {keystore_path}. Nothing "
                "can be decrypted without recipient kits."
            ),
        }
    has_kits = any(
        p.name.endswith((".btn.mykit", ".jwe.mykey"))
        for p in keystore_path.iterdir()
    )
    if not has_kits:
        return {
            "error": (
                f"No recipient kits (*.btn.mykit / *.jwe.mykey) found in "
                f"keystore {keystore_path}; nothing can be decrypted."
            ),
        }

    # Pre-validate every line so one bad line becomes a per-line failure
    # instead of aborting the whole stream inside the decryptor.
    failures: list[DecryptFailure] = []
    valid_pairs: list[tuple[int, str]] = []
    total_lines = 0
    for lineno, raw in enumerate(inp.content.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        total_lines += 1
        try:
            env = json.loads(line)
        except json.JSONDecodeError as exc:
            failures.append(
                DecryptFailure(line=lineno, error=f"invalid JSON: {exc}")
            )
            continue
        if not isinstance(env, dict):
            failures.append(
                DecryptFailure(
                    line=lineno,
                    error="not a TN envelope: JSON value is not an object",
                )
            )
            continue
        missing = [k for k in _REQUIRED_ENVELOPE_KEYS if k not in env]
        if missing:
            failures.append(
                DecryptFailure(
                    line=lineno,
                    error=(
                        "not a TN envelope: missing "
                        + ", ".join(missing)
                    ),
                )
            )
            continue
        valid_pairs.append((lineno, line))

    signatures_checked = bool(cfg.sign)
    rows: list[DecryptedRow] = []
    try:
        triples = _lines_with_keybag(
            ((f"inline:{n}", line) for n, line in valid_pairs),
            keystore_path,
            verify_signatures=signatures_checked,
        )
        for (lineno, _line), triple in zip(valid_pairs, triples, strict=True):
            if inp.group:
                plaintext = triple.get("plaintext") or {}
                triple = {
                    **triple,
                    "plaintext": {
                        k: v for k, v in plaintext.items() if k == inp.group
                    },
                }
            entry = _SdkEntry.from_raw(triple)
            rows.append(
                DecryptedRow(
                    line=lineno,
                    entry=_serialize_entry(entry),
                    signature_valid=triple["valid"]["signature"],
                    chain_valid=triple["valid"]["chain"],
                )
            )
    except Exception as exc:  # noqa: BLE001 - containment: surface as error payload
        _code, message, _data = map_exception(exc)
        logger.info("tn_decrypt failed: %s", message)
        return {
            "error": f"Decrypt failed: {message}",
            "failures": [f.model_dump() for f in failures],
        }

    out = DecryptOutput(
        entries=rows,
        total_lines=total_lines,
        returned=len(rows),
        signatures_checked=signatures_checked,
        failures=failures,
    )
    logger.debug(
        "tn_decrypt: lines=%d decrypted=%d failures=%d",
        total_lines, len(rows), len(failures),
    )
    return out.model_dump(mode="json")


__all__ = ["tn_decrypt_impl", "tn_read_impl", "tn_status_impl"]
