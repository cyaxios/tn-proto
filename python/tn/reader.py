"""Read back a TN log file and decrypt the groups we hold keys for (PRD §7.2).

Signatures are verified against each entry's `did` using the device's
self-contained did:key public key — no network lookup required.

This module exposes both the raw reader (``read()``/``_read()`` —
``{envelope, plaintext, valid}`` per entry) and the flat-shape projector
(``flatten_raw_entry()``) used by ``tn.read()``'s default + ``verify=True``
return shapes.

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
from .chain import _compute_row_hash, verify_chain_link
from .config import LoadedConfig
from .canonical import _canonical_bytes
from .signing import DeviceKey, _signature_from_b64


def _aad_bytes_for(env: dict[str, Any], group_name: str) -> bytes:
    """Reconstruct a group's additional-authenticated-data bytes from a
    record's public ``tn_aad`` echo.

    The writer bound ``_canonical_bytes(effective_aad_dict)`` to the group's
    seal and echoed the ``{group: dict}`` map as a CANONICAL JSON STRING into
    ``env["tn_aad"]``. Parse it and re-canonicalize this group's dict so
    ``cipher.decrypt`` can verify the AEAD; an absent / empty / malformed
    entry yields ``b""`` (the writer bound nothing). Tampering the echo
    changes these bytes and the AEAD fails — the group opens to a
    decrypt-error marker, never plaintext.
    """
    raw = env.get("tn_aad")
    if not isinstance(raw, str) or not raw:
        return b""
    try:
        binding = json.loads(raw)
    except (ValueError, TypeError):
        return b""
    if not isinstance(binding, dict):
        return b""
    group_aad = binding.get(group_name)
    if not isinstance(group_aad, dict) or not group_aad:
        return b""
    return _canonical_bytes(group_aad)


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


# Public envelope keys that surface flat. As of 0.4.0a1 this includes the
# crypto plumbing (prev_hash, row_hash, signature) since Entry exposes
# them as typed attributes. Callers who want bytes-on-disk should use
# tn.read(raw=True) which yields the envelope dict directly.
_FLAT_ENVELOPE_KEYS: tuple[str, ...] = (
    "timestamp",
    "event_type",
    "level",
    "device_identity",
    "sequence",
    "event_id",
    "prev_hash",
    "row_hash",
    "signature",
)

# Reserved for backward compat with code that still imports it; no
# envelope keys are reserved-out of the flat shape now.
_CRYPTO_ENVELOPE_KEYS: frozenset[str] = frozenset()

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
    #
    # Only surface keys the upstream raw dict actually carried. The regular
    # `tn.read(verify=True)` path always sets all three (signature, row_hash,
    # chain) so its surface is unchanged. `read_as_recipient` only computes
    # signature + chain — surfacing a hardcoded `row_hash: False` there
    # would lie about a check that never ran.
    if include_valid:
        v = raw.get("valid") or {}
        valid_out: dict[str, Any] = {}
        for k in ("signature", "row_hash", "chain"):
            if k in v:
                valid_out[k] = bool(v[k])
        out["_valid"] = valid_out

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


def _discover_keybag_ciphers(
    keystore_path: Path,
) -> dict[str, "_cipher.GroupCipher"]:
    """Load every kit in ``keystore_path`` as ``{group_name: cipher}``.

    Used by :func:`read_with_keybag` so a reader holding kits from one
    or more groups (e.g. ``default.btn.mykit`` + ``tn.agents.btn.mykit``
    + an absorbed ``payments.btn.mykit``) gets ALL those groups
    decrypted on a single ``tn.read`` call. Missing kits are silently
    omitted — the read pass just yields ``$no_read_key`` for any group
    we don't have a kit for, matching the single-group behaviour.
    """
    bag: dict[str, _cipher.GroupCipher] = {}
    if not keystore_path.is_dir():
        return bag
    for entry in keystore_path.iterdir():
        name = entry.name
        if name.endswith(".btn.mykit"):
            group = name[: -len(".btn.mykit")]
            try:
                bag[group] = _cipher.BtnGroupCipher.load(keystore_path, group)
            except Exception:  # noqa: BLE001 — best-effort load; bad kit just doesn't join the bag
                continue
        elif name.endswith(".jwe.mykey"):
            group = name[: -len(".jwe.mykey")]
            # JWE: ``mykey`` is the recipient's private key; the sender's
            # pub-key sidecar must also be present for ``as_recipient``
            # construction. Fall back silently if not.
            try:
                bag[group] = _cipher.JWEGroupCipher.load(keystore_path, group)
            except Exception:  # noqa: BLE001
                continue
    return bag


def read_with_keybag(
    log_path: str | Path,
    keystore_dir: str | Path,
    *,
    verify_signatures: bool = True,
    expect_genesis: bool = False,
) -> Iterator[dict[str, Any]]:
    """Read a log decrypting every group whose kit lives in
    ``keystore_dir``.

    "Key bag" semantics: the SDK walks every ``*.btn.mykit`` and
    ``*.jwe.mykey`` in ``keystore_dir``, builds one cipher per group,
    and on each envelope tries every group block against its matching
    kit. The reader gets back the union of what any kit can decrypt.

    This is the default path for ``tn.read(log=...)`` after PR (#57):
    after ``tn.absorb(bundle)`` the bundle's kits land in
    ``cfg.keystore``, so a subsequent ``tn.read(log=publisher_log)``
    decrypts via those kits without the caller having to name any.

    Single-group :func:`read_as_recipient` remains the explicit
    "use only this kit" override (the ``as_recipient=`` kwarg on
    ``tn.read``).
    """
    with open(log_path, encoding="utf-8") as f:
        # `enumerate` lines so the source label in errors keeps the path.
        def _labelled() -> Iterator[tuple[str, str]]:
            for lineno, line in enumerate(f, 1):
                yield (f"{log_path}:{lineno}", line)
        yield from _lines_with_keybag(
            _labelled(),
            keystore_dir,
            verify_signatures=verify_signatures,
            expect_genesis=expect_genesis,
        )


def _lines_with_keybag(
    lines: Iterator[tuple[str, str]],
    keystore_dir: str | Path,
    *,
    verify_signatures: bool = True,
    expect_genesis: bool = False,
) -> Iterator[dict[str, Any]]:
    """Decrypt an iterator of ``(source_label, raw_line)`` pairs against the
    key bag in ``keystore_dir``, yielding ``{envelope, plaintext, valid}``
    triples — the exact per-line core of :func:`read_with_keybag`.

    Source-agnostic: a file reader feeds ``(path:lineno, line)`` pairs; a
    Kafka handler feeds ``(kafka://…@offset, line)`` pairs. The decrypt,
    chain check, and signature verify are identical regardless of where the
    bytes came from.

    ``expect_genesis`` (default ``False``) is the opt-in genesis anchor:
    when ``True``, the first entry of each ``event_type`` chain must anchor
    at :data:`~tn.chain.ZERO_HASH`, so a front-truncated log is flagged.
    Leave it off for ordinary logging and partial/tailed reads — see
    :func:`tn.chain.verify_chain_link`.
    """
    keystore_path = Path(keystore_dir)
    bag = _discover_keybag_ciphers(keystore_path)
    prev_hash_by_event: dict[str, str] = {}

    for label, raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            env = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{label}: invalid JSON: {e}") from e

        event_type = env["event_type"]
        chain_ok = verify_chain_link(
            prev_hash_by_event,
            event_type,
            env["prev_hash"],
            env["row_hash"],
            expect_genesis=expect_genesis,
        )

        # Walk every group block in the envelope; try the matching
        # cipher from the bag. Groups we don't have a kit for stay
        # silent (no $no_read_key entry — matches what an outside
        # observer would see).
        plaintext: dict[str, dict[str, Any]] = {}
        for key, block in env.items():
            if not isinstance(block, dict) or "ciphertext" not in block:
                continue
            cipher = bag.get(key)
            if cipher is None:
                continue
            try:
                ct_bytes = base64.b64decode(block["ciphertext"])
                pt = cipher.decrypt(ct_bytes, _aad_bytes_for(env, key))
                plaintext[key] = json.loads(pt.decode("utf-8"))
            except _cipher.NotARecipientError:
                plaintext[key] = {"$no_read_key": True}
            except Exception:  # noqa: BLE001 — bad ciphertext doesn't abort the stream
                plaintext[key] = {"$decrypt_error": True}

        sig_ok = True
        if verify_signatures:
            try:
                sig_ok = DeviceKey.verify(
                    env["device_identity"],
                    env["row_hash"].encode("ascii"),
                    _signature_from_b64(env["signature"]),
                )
            except Exception:  # noqa: BLE001
                sig_ok = False

        yield {
            "envelope": env,
            "plaintext": plaintext,
            "valid": {
                "signature": sig_ok,
                "chain": chain_ok,
            },
        }


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
    hibe_key = keystore_path / f"{group}.hibe.sk"
    # The keystore can hold keys for the SAME group name under several
    # ciphers at once (e.g. the reader's own btn ceremony plus an absorbed
    # hibe grant). The log line doesn't say which cipher sealed it, so try
    # every candidate at decrypt time — same posture as JWE trying each
    # wrapped key — and remember the first one that opens.
    ciphers: list[Any] = []
    if btn_kit.exists():
        ciphers.append(_cipher.BtnGroupCipher.load(keystore_path, group))
    if jwe_key.exists():
        ciphers.append(_cipher.JWEGroupCipher.load(keystore_path, group))
    if hibe_key.exists():
        ciphers.append(_cipher.HibeGroupCipher.load(keystore_path, group))
    if not ciphers:
        raise FileNotFoundError(
            f"read_as_recipient: no recipient key found for group={group!r} in "
            f"{keystore_path}. Looked for {btn_kit.name} (btn), "
            f"{jwe_key.name} (jwe), and {hibe_key.name} (hibe). If you "
            f"absorbed a kit_bundle, the kit lands in your ceremony's "
            f"keystore (./.tn/keys/ by default) — point keystore_dir there."
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
            chain_ok = verify_chain_link(
                prev_hash_by_event, event_type, env["prev_hash"], env["row_hash"]
            )

            plaintext: dict[str, dict[str, Any]] = {}
            g_block = env.get(group)
            if isinstance(g_block, dict) and "ciphertext" in g_block:
                ct_bytes = base64.b64decode(g_block["ciphertext"])
                saw_no_key = False
                aad_bytes = _aad_bytes_for(env, group)
                for candidate in ciphers:
                    try:
                        pt = candidate.decrypt(ct_bytes, aad_bytes)
                        plaintext[group] = json.loads(pt.decode("utf-8"))
                        # Promote the winner so later lines try it first.
                        if ciphers[0] is not candidate:
                            ciphers.remove(candidate)
                            ciphers.insert(0, candidate)
                        break
                    except _cipher.NotARecipientError:
                        saw_no_key = True
                    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                        pass
                if group not in plaintext:
                    plaintext[group] = (
                        {"$no_read_key": True} if saw_no_key else {"$decrypt_error": True}
                    )

            sig_ok = True
            if verify_signatures:
                try:
                    sig_ok = DeviceKey.verify(
                        env["device_identity"],
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


def parse_envelope_line(
    line: str,
    cfg: LoadedConfig,
    *,
    verify: bool = False,
    prev_hash_by_event: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Parse a single NDJSON line into the raw ``{envelope, plaintext, valid}`` shape.

    Returns ``None`` on empty / whitespace-only lines or JSON parse errors.

    ``prev_hash_by_event`` is an optional dict tracking chain state across
    successive calls (keyed by ``event_type``). Pass the same dict on every
    call from the same tailing session to get correct ``valid.chain`` values.
    If ``None``, chain checking is skipped (chain=False for that entry).

    ``verify`` controls whether row_hash recomputation and signature
    verification are performed. When ``False``, ``valid.signature`` and
    ``valid.row_hash`` are ``False`` (not computed), and ``valid.chain`` is
    set based on ``prev_hash_by_event`` if supplied.
    """
    line = line.strip()
    if not line:
        return None
    try:
        env = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = env.get("event_type", "")

    # Chain integrity. Without a carried `prev_hash_by_event` there is no
    # state to chain against, so chain is reported unverified (False).
    if prev_hash_by_event is not None:
        chain_ok: bool = verify_chain_link(
            prev_hash_by_event,
            event_type,
            env.get("prev_hash", ""),
            env.get("row_hash", ""),
        )
    else:
        chain_ok = False

    # Decrypt groups.
    groups_from_env: dict[str, dict[str, Any]] = {}
    plaintext: dict[str, dict[str, Any]] = {}
    for gname in env:
        if isinstance(env[gname], dict) and "ciphertext" in env[gname]:
            ct_bytes = base64.b64decode(env[gname]["ciphertext"])
            groups_from_env[gname] = {
                "ciphertext": ct_bytes,
                "field_hashes": env[gname].get("field_hashes", {}),
            }
    for gname, gcfg in cfg.groups.items():
        if gname not in groups_from_env:
            continue
        ct_bytes = groups_from_env[gname]["ciphertext"]
        try:
            pt = gcfg.cipher.decrypt(ct_bytes, _aad_bytes_for(env, gname))
            plaintext[gname] = json.loads(pt.decode("utf-8"))
        except _cipher.NotARecipientError:
            plaintext[gname] = {"$no_read_key": True}
        except Exception:  # noqa: BLE001
            plaintext[gname] = {"$decrypt_error": True}

    if verify:
        _envelope_reserved = {
            "device_identity", "timestamp", "event_id", "event_type", "level",
            "prev_hash", "row_hash", "signature", "sequence",
        }
        public_out = {
            k: v
            for k, v in env.items()
            if k in cfg.public_fields
            and k not in _envelope_reserved
            and k not in cfg.groups
        }
        # The ``tn_aad`` echo is an authenticated public field the writer
        # folded into the row_hash even though it is not a user-declared
        # public field. Fold it back so recompute matches — and so tampering
        # the echo flips row_hash to invalid (alongside the AEAD failure).
        if "tn_aad" in env:
            public_out["tn_aad"] = env["tn_aad"]
        expected_row_hash = _compute_row_hash(
            device_identity=env.get("device_identity", ""),
            timestamp=env.get("timestamp", ""),
            event_id=env.get("event_id", ""),
            event_type=event_type,
            level=env.get("level", ""),
            prev_hash=env.get("prev_hash", ""),
            public_fields=public_out,
            groups=groups_from_env,
        )
        row_hash_ok: bool = expected_row_hash == env.get("row_hash", "")
        try:
            sig_ok: bool = DeviceKey.verify(
                env["device_identity"],
                env["row_hash"].encode("ascii"),
                _signature_from_b64(env["signature"]),
            )
        except Exception:  # noqa: BLE001
            sig_ok = False
    else:
        row_hash_ok = False
        sig_ok = False

    return {
        "envelope": env,
        "plaintext": plaintext,
        "valid": {
            "signature": sig_ok,
            "row_hash": row_hash_ok,
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

    Returns an empty iterator if ``log_path`` does not exist. Because
    ``tn.*`` admin events default to the admin log, a fresh ceremony that
    writes only admin events leaves the main log uncreated; ``tn.read()``
    should not raise on a bare ceremony.
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
            chain_ok = verify_chain_link(
                prev_hash_by_event, event_type, env["prev_hash"], env["row_hash"]
            )

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
                    pt = gcfg.cipher.decrypt(ct_bytes, _aad_bytes_for(env, gname))
                    plaintext[gname] = json.loads(pt.decode("utf-8"))
                except _cipher.NotARecipientError:
                    plaintext[gname] = {"$no_read_key": True}
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    plaintext[gname] = {"$decrypt_error": True}

            # public_out must mirror what the writer put in: envelope fields
            # handled separately by _compute_row_hash (device_identity/
            # timestamp/event_id/event_type/level/prev_hash/row_hash/
            # signature/sequence) plus group names MUST NOT appear in
            # public_out.
            _envelope_reserved = {
                "device_identity",
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
            # ``tn_aad`` is an authenticated public echo folded into the
            # writer's row_hash; fold it back so recompute matches and so a
            # tampered echo flips row_hash to invalid.
            if "tn_aad" in env:
                public_out["tn_aad"] = env["tn_aad"]
            expected_row_hash = _compute_row_hash(
                device_identity=env["device_identity"],
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
                env["device_identity"],
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
