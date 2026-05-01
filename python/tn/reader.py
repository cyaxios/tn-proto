"""Read back a TN log file and decrypt the groups we hold keys for (PRD §7.2).

Signatures are verified against each entry's `did` using the device's
self-contained did:key public key — no network lookup required.

This module exposes both the raw reader (``read()``/``_read()`` —
``{envelope, plaintext, valid}`` per entry) and the flat-shape projector
(``flatten_raw_entry()``) used by ``tn.read()``'s default + ``verify=True``
return shapes (per ``docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md``).

Migration flag:

    ``_READ_FLAT_DEFAULT`` (module-level constant) — when ``True`` (the
    default), ``tn.read()`` yields flat dicts. Set to ``False`` (or set
    the ``TN_READER_LEGACY=1`` environment variable) to revert to the
    legacy ``{envelope, plaintext, valid}`` shape during the migration
    period. Removed in a future release.
"""

from __future__ import annotations

import base64
import json
import os
import re as _re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import cipher as _cipher
from .chain import _compute_row_hash
from .config import LoadedConfig
from .signing import DeviceKey, _signature_from_b64

# --------------------------------------------------------------------------
# Migration flag — see module docstring.
# --------------------------------------------------------------------------

# Default: True. Override via ``TN_READER_LEGACY=1`` env var (read at
# import time, but ``tn.read()`` re-checks the env var on each call so
# tests can flip it mid-process via ``monkeypatch.setenv``).
_READ_FLAT_DEFAULT: bool = os.environ.get("TN_READER_LEGACY", "") not in ("1", "true", "True")


def _flat_default_active() -> bool:
    """Module + env-var combined: True means new flat shape, False means legacy."""
    if os.environ.get("TN_READER_LEGACY", "") in ("1", "true", "True"):
        return False
    return _READ_FLAT_DEFAULT


# Public envelope keys that always surface flat in the new shape.
_FLAT_ENVELOPE_KEYS: tuple[str, ...] = (
    "timestamp",
    "event_type",
    "level",
    "did",
    "sequence",
    "event_id",
)

# Crypto-plumbing envelope keys that NEVER surface flat (only via raw=True).
_CRYPTO_ENVELOPE_KEYS: frozenset[str] = frozenset(
    {"prev_hash", "row_hash", "signature"}
)

# Reserved envelope keys (used to identify "what's a public field" vs
# "what's an envelope basic" vs "what's a group payload").
_RESERVED_ENVELOPE_KEYS: frozenset[str] = frozenset(
    set(_FLAT_ENVELOPE_KEYS) | _CRYPTO_ENVELOPE_KEYS
)


def _is_group_payload(v: Any) -> bool:
    """Group payloads are dicts with ciphertext (and usually field_hashes)."""
    return isinstance(v, dict) and "ciphertext" in v


def flatten_raw_entry(raw: dict[str, Any], *, include_valid: bool = False) -> dict[str, Any]:
    """Project a raw ``{envelope, plaintext, valid}`` entry to the flat shape.

    Per spec §1.1 / §1.3:
      - The six envelope basics surface as top-level keys.
      - Public fields beyond envelope basics surface flat.
      - Decrypted fields from every group the caller could read surface flat,
        merged in alphabetical group order (last-write-wins on collision).
      - Crypto plumbing (``prev_hash``, ``row_hash``, ``signature``,
        ciphertext, field_hashes) is excluded.
      - ``_hidden_groups`` lists groups present in the envelope but absent
        from plaintext (caller has no kit). Omitted when empty.
      - ``_decrypt_errors`` lists groups whose plaintext came back as a
        decrypt-error sentinel. Omitted when empty.
      - When ``include_valid`` is True, a ``_valid`` block is added with
        ``{signature, row_hash, chain}`` booleans (§1.3).

    Field-name collisions across groups: dict last-write-wins. We iterate
    groups in alphabetical order so the result is deterministic across
    runs (§4.1). Callers who need group provenance should use ``raw=True``.
    """
    env = raw["envelope"]
    plaintext = raw.get("plaintext") or {}

    out: dict[str, Any] = {}

    # 1. Envelope basics.
    for k in _FLAT_ENVELOPE_KEYS:
        if k in env:
            out[k] = env[k]

    # 2. Public fields beyond envelope basics: anything in env that isn't
    #    an envelope basic, isn't crypto plumbing, and isn't a group payload.
    for k, v in env.items():
        if k in _RESERVED_ENVELOPE_KEYS:
            continue
        if _is_group_payload(v):
            continue
        out[k] = v

    # 3. Decrypted group fields, merged in alphabetical group order so
    #    last-write-wins on collision is deterministic across runs.
    decrypt_errors: list[str] = []
    for gname in sorted(plaintext.keys()):
        body = plaintext[gname]
        if not isinstance(body, dict):
            continue
        # Sentinel shapes used by the legacy reader for "no key" / "decrypt error":
        if body.get("$decrypt_error") is True:
            decrypt_errors.append(gname)
            continue
        if body.get("$no_read_key") is True:
            # Caller had no kit at decrypt time — surface as hidden, not error.
            continue
        out.update(body)

    # 4. _hidden_groups: groups with ciphertext in env that we couldn't
    #    decrypt (plaintext absent, or marked $no_read_key).
    hidden: list[str] = []
    for k, v in env.items():
        if k in _RESERVED_ENVELOPE_KEYS:
            continue
        if not _is_group_payload(v):
            continue
        body = plaintext.get(k)
        if body is None or (isinstance(body, dict) and body.get("$no_read_key") is True):
            hidden.append(k)
    if hidden:
        out["_hidden_groups"] = sorted(hidden)

    # 5. _decrypt_errors: groups where decrypt threw.
    if decrypt_errors:
        out["_decrypt_errors"] = sorted(decrypt_errors)

    # 6. _valid block (verify=True path).
    if include_valid:
        v = raw.get("valid") or {}
        out["_valid"] = {
            "signature": bool(v.get("signature", False)),
            "row_hash": bool(v.get("row_hash", False)),
            "chain": bool(v.get("chain", False)),
        }

    return out


def read(
    log_path: str | Path | None = None, cfg: LoadedConfig | None = None
) -> Iterator[dict[str, Any]]:
    """Iterate + decrypt entries from a newline-delimited-JSON log file.

    Both args are optional when `tn.init()` has been called:
      - `cfg` defaults to the runtime loaded by `tn.init()`.
      - `log_path` defaults to cfg.resolve_log_path() (yaml `logs.path`,
        e.g. `<yaml-dir>/.tn/logs/tn.ndjson`).

    Pass `log_path` explicitly for custom handler paths. Pass `cfg`
    explicitly for the legacy two-arg form or when reading a foreign log.
    """
    if cfg is None:
        from . import logger as _lg

        if _lg._runtime is None:
            raise RuntimeError("tn.init(yaml_path) must be called before tn.read()")
        cfg = _lg._runtime.cfg
    if log_path is None:
        log_path = cfg.resolve_log_path()
    return _read(log_path, cfg)


def _pel_glob_files(cfg: LoadedConfig) -> list[Path]:
    template = cfg.protocol_events_location
    if template == "main_log":
        return []
    yaml_dir = cfg.yaml_path.parent
    pat = template.replace("{yaml_dir}", str(yaml_dir))
    pat = _re.sub(r"\{[^}]+\}", "*", pat)
    p = Path(pat)
    if p.is_absolute():
        if "*" not in pat and "?" not in pat:
            return [p] if p.is_file() else []
        parts = p.parts
        i = next((j for j, part in enumerate(parts) if "*" in part or "?" in part), len(parts))
        base = Path(*parts[:i]) if i > 0 else p.parent
        rel = str(Path(*parts[i:]))
        return list(base.glob(rel)) if base.exists() else []
    else:
        rel_parts = Path(pat).parts
        rel = str(Path(*rel_parts[1:])) if rel_parts and rel_parts[0] == "." else str(Path(pat))
        return list(yaml_dir.glob(rel)) if rel and yaml_dir.exists() else []


def read_all(
    log_path: str | Path | None = None, cfg: LoadedConfig | None = None
) -> Iterator[dict[str, Any]]:
    """Yield entries from the main log + protocol event files, merged by timestamp.

    If protocol_events_location is main_log, this is equivalent to read().
    """
    if cfg is None:
        from . import logger as _lg

        if _lg._runtime is None:
            raise RuntimeError("tn.init(yaml_path) must be called before tn.read_all()")
        cfg = _lg._runtime.cfg
    if log_path is None:
        log_path = cfg.resolve_log_path()
    log_path = Path(log_path)

    all_entries: list[dict[str, Any]] = []
    if log_path.exists():
        all_entries.extend(_read(log_path, cfg))

    seen = {log_path.resolve()}
    for pel_file in _pel_glob_files(cfg):
        if not pel_file.is_file() or pel_file.resolve() in seen:
            continue
        seen.add(pel_file.resolve())
        all_entries.extend(_read(pel_file, cfg))

    all_entries.sort(key=lambda e: e["envelope"]["timestamp"])
    yield from all_entries


def read_as_recipient(
    log_path: str | Path,
    keystore_dir: str | Path,
    *,
    group: str = "default",
    verify_signatures: bool = True,
) -> Iterator[dict[str, Any]]:
    """Read a foreign log that is NOT part of this workspace's yaml.

    Use this when you hold raw key material for `group` (e.g. you absorbed
    a kit_bundle from the log's publisher) but no `tn.yaml` of your own
    describes your enrolment. The verb dispatches on which kit file is
    present in ``keystore_dir``:

    * ``<group>.btn.mykit``  → btn cipher (subset-difference broadcast)
    * ``<group>.jwe.mykey``  → JWE cipher (per-recipient X25519)

    If both are present, btn wins — kit_bundle absorbs always include the
    btn kit on btn ceremonies. If neither is present, raises ``FileNotFoundError``
    with the candidate paths it looked for.

    For btn ceremonies on the **publisher's own** log, use ``tn.read()``
    after ``tn.init(your_yaml)`` — your runtime is already bound to your
    own ceremony's btn state. ``read_as_recipient`` is the right verb
    when you want to decrypt a **foreign** publisher's log using a kit
    you absorbed (FINDINGS #7) — point its ``keystore_dir`` at the
    directory holding the foreign publisher's ``<group>.btn.mykit``,
    typically your own ceremony's ``cfg.keystore`` after ``tn.absorb()``
    placed the kit there.

    Yields the same shape as ``tn.read_raw()`` — ``envelope``,
    ``plaintext[group]``, ``valid.signature``, ``valid.chain``. Chain
    validation runs per-event-type.

    Decryption happens only for ``group``. Other groups the publisher
    used show up in ``envelope`` but not ``plaintext``.

    Use cases: Bob receiving Alice's log, Carol reading pre-revoke
    entries, any out-of-band share.
    """
    keystore_path = Path(keystore_dir)
    btn_kit = keystore_path / f"{group}.btn.mykit"
    jwe_key = keystore_path / f"{group}.jwe.mykey"
    if btn_kit.exists():
        cipher = _cipher.BtnGroupCipher.load(keystore_path, group)
    elif jwe_key.exists():
        cipher = _cipher.JWEGroupCipher.load(keystore_path, group)
    else:
        raise FileNotFoundError(
            f"read_as_recipient: no recipient key found for group={group!r} in "
            f"{keystore_path}. Looked for {btn_kit.name} (btn) and "
            f"{jwe_key.name} (jwe). If you absorbed a kit_bundle, the kit lands "
            f"in your ceremony's keystore (./.tn/keys/ by default) — point "
            f"keystore_dir there."
        )
    prev_hash_by_event: dict[str, str] = {}

    with open(log_path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{log_path}:{lineno}: invalid JSON: {e}") from e

            event_type = env["event_type"]
            last = prev_hash_by_event.get(event_type)
            chain_ok = (last is None) or (env["prev_hash"] == last)
            prev_hash_by_event[event_type] = env["row_hash"]

            plaintext: dict[str, dict[str, Any]] = {}
            g_block = env.get(group)
            if isinstance(g_block, dict) and "ciphertext" in g_block:
                ct_bytes = base64.b64decode(g_block["ciphertext"])
                try:
                    pt = cipher.decrypt(ct_bytes)
                    plaintext[group] = json.loads(pt.decode("utf-8"))
                except _cipher.NotARecipientError:
                    plaintext[group] = {"$no_read_key": True}
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    plaintext[group] = {"$decrypt_error": True}

            sig_ok = True
            if verify_signatures:
                try:
                    sig_ok = DeviceKey.verify(
                        env["did"],
                        env["row_hash"].encode("ascii"),
                        _signature_from_b64(env["signature"]),
                    )
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    sig_ok = False

            yield {
                "envelope": env,
                "plaintext": plaintext,
                "valid": {
                    "signature": sig_ok,
                    "chain": chain_ok,
                },
            }


def _read(log_path: str | Path, cfg: LoadedConfig) -> Iterator[dict[str, Any]]:
    """Yield one dict per log entry.

    Each yielded dict carries:
        envelope:    the raw on-disk JSON
        plaintext:   {group_name: {field: value, ...}}  (only for groups we
                     have a read key for)
        valid:       {"signature": bool, "chain": bool}

    Returns an empty iterator if ``log_path`` does not exist. With the
    2026-04-24 admin-log default flip, a fresh ceremony that emits only
    ``tn.*`` admin events lands them in ``.tn/admin/admin.ndjson`` and
    leaves the main log uncreated; ``tn.read()`` should not raise on a
    bare ceremony.
    """
    prev_hash_by_event: dict[str, str] = {}

    log_path = Path(log_path)
    if not log_path.exists():
        return

    with open(log_path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{log_path}:{lineno}: invalid JSON: {e}") from e

            event_type = env["event_type"]

            # chain integrity: compare prev_hash against last row_hash
            last = prev_hash_by_event.get(event_type)
            chain_ok = (last is None) or (env["prev_hash"] == last)
            prev_hash_by_event[event_type] = env["row_hash"]

            # row_hash recomputation
            groups_from_env: dict[str, dict[str, Any]] = {}
            plaintext: dict[str, dict[str, Any]] = {}
            # Row_hash recomputation needs EVERY group from the envelope
            # (even ones we can't decrypt). Start by collecting raw bytes.
            for gname in env:
                if isinstance(env[gname], dict) and "ciphertext" in env[gname]:
                    ct_bytes = base64.b64decode(env[gname]["ciphertext"])
                    groups_from_env[gname] = {
                        "ciphertext": ct_bytes,
                        "field_hashes": env[gname].get("field_hashes", {}),
                    }
            # Then decrypt the ones we have keys for.
            for gname, gcfg in cfg.groups.items():
                if gname not in groups_from_env:
                    continue
                ct_bytes = groups_from_env[gname]["ciphertext"]
                try:
                    pt = gcfg.cipher.decrypt(ct_bytes)
                    plaintext[gname] = json.loads(pt.decode("utf-8"))
                except _cipher.NotARecipientError:
                    plaintext[gname] = {"$no_read_key": True}
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    plaintext[gname] = {"$decrypt_error": True}

            # public_out must mirror what the writer put in: envelope fields
            # handled separately by _compute_row_hash (did/timestamp/event_id/
            # event_type/level/prev_hash/row_hash/signature/sequence) plus
            # group names MUST NOT appear in public_out.
            _envelope_reserved = {
                "did",
                "timestamp",
                "event_id",
                "event_type",
                "level",
                "prev_hash",
                "row_hash",
                "signature",
                "sequence",
            }
            public_out = {
                k: v
                for k, v in env.items()
                if k in cfg.public_fields and k not in _envelope_reserved and k not in cfg.groups
            }
            expected_row_hash = _compute_row_hash(
                did=env["did"],
                timestamp=env["timestamp"],
                event_id=env["event_id"],
                event_type=event_type,
                level=env["level"],
                prev_hash=env["prev_hash"],
                public_fields=public_out,
                groups=groups_from_env,
            )
            row_hash_ok = expected_row_hash == env["row_hash"]

            sig_ok = DeviceKey.verify(
                env["did"],
                env["row_hash"].encode("ascii"),
                _signature_from_b64(env["signature"]),
            )

            yield {
                "envelope": env,
                "plaintext": plaintext,
                "valid": {
                    "signature": sig_ok,
                    "row_hash": row_hash_ok,
                    "chain": chain_ok,
                },
            }
