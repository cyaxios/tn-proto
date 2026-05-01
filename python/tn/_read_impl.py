"""Read verbs: read, read_raw, read_all, read_as_recipient, secure_read.

The implementations read the runtime singleton from the ``tn`` module via
late imports.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_logger = logging.getLogger("tn")
_surface = logging.getLogger("tn.surface")


class VerificationError(Exception):
    """Raised by ``tn.secure_read(on_invalid='raise')`` when an entry fails
    one or more of (signature, row_hash, chain) checks."""

    def __init__(self, *, envelope: dict[str, Any], invalid_reasons: list[str]):
        self.envelope = envelope
        self.invalid_reasons = list(invalid_reasons)
        et = envelope.get("event_type")
        eid = envelope.get("event_id")
        super().__init__(
            f"tn.secure_read: envelope event_type={et!r} event_id={eid!r} "
            f"failed verification: {self.invalid_reasons}"
        )


def _invalid_reasons_from_valid(valid: dict[str, Any]) -> list[str]:
    """Map the ``valid`` dict to the public ``invalid_reasons`` shape."""
    out: list[str] = []
    if not valid.get("signature", False):
        out.append("signature")
    if not valid.get("row_hash", False):
        out.append("row_hash")
    if not valid.get("chain", False):
        out.append("chain")
    return out


def _secure_read_impl(
    *,
    on_invalid: str = "skip",
    log_path: Any = None,
    cfg: Any = None,
    all_runs: bool = False,
    where=None,
):
    """Iterate verified log entries — fail-closed on any (sig, row_hash,
    chain) failure.

    Returns flat dicts in the same default shape as ``tn.read()``, plus
    an ``instructions`` block when the caller holds the ``tn.agents`` kit
    and the entry carries a populated ``tn.agents`` group.

    ``on_invalid`` modes (per spec section 3):

    * ``"skip"`` (default) — silently drop non-verifying entries. Best
      for production agentic flows. A ``tn.read.tampered_row_skipped``
      event is appended to the local admin log so monitoring can surface
      tampering without exposing the bad row's payload.
    * ``"raise"`` — raise :class:`VerificationError` on the first failure.
      Best for compliance pipelines that should halt on any anomaly.
    * ``"forensic"`` — yield the entry with ``_valid`` and
      ``_invalid_reasons`` keys exposed. The yielded dict still carries
      decrypted fields (when keys are held); use this only for auditor
      investigations.
    """
    import tn
    _surface.info(
        "tn.secure_read() ENTER on_invalid=%r log_path=%r cfg=%s all_runs=%s "
        "current_run_id=%s",
        on_invalid, log_path,
        "set" if cfg is not None else "None",
        all_runs, tn._run_id,
    )
    tn._maybe_autoinit_load_only()
    if on_invalid not in ("skip", "raise", "forensic"):
        raise ValueError(
            f"tn.secure_read: unknown on_invalid={on_invalid!r}; "
            f"expected 'skip' | 'raise' | 'forensic'"
        )

    from . import reader as _reader

    raw_iter = tn.read_raw(log_path, cfg, all_runs=all_runs, where=where)
    for r in raw_iter:
        valid = r.get("valid") or {}
        all_valid = (
            bool(valid.get("signature", False))
            and bool(valid.get("row_hash", False))
            and bool(valid.get("chain", False))
        )
        if not all_valid:
            reasons = _invalid_reasons_from_valid(valid)
            env = r.get("envelope") or {}
            if on_invalid == "raise":
                raise VerificationError(envelope=env, invalid_reasons=reasons)
            if on_invalid == "skip":
                # Don't loop our own tampered-row event back through
                # secure_read — that would emit an event for the very
                # event we're verifying. Skip silently in that case.
                if str(env.get("event_type", "")) == "tn.read.tampered_row_skipped":
                    continue
                try:
                    _emit_tampered_row_skipped(env, reasons)
                except Exception:
                    _logger.exception(
                        "tn.read.tampered_row_skipped emit failed; continuing"
                    )
                continue
            # forensic — fall through and yield the entry, augmented.
            flat = _reader.flatten_raw_entry(r, include_valid=True)
            flat["_invalid_reasons"] = sorted(set(reasons))
            _attach_instructions(flat, r)
            yield flat
            continue

        flat = _reader.flatten_raw_entry(r, include_valid=False)
        _attach_instructions(flat, r)
        yield flat


def _attach_instructions(flat: dict[str, Any], raw: dict[str, Any]) -> None:
    """If the raw entry's plaintext carries a ``tn.agents`` block AND
    the caller holds the kit (decrypt succeeded), surface those six
    fields as a dedicated ``instructions`` block per spec section 3.1.

    Side effect: REMOVES the six tn.agents field names from the top-level
    flat dict (``flatten_raw_entry`` flattens every readable group's fields
    by default). Instructions are conceptually a separate concern from
    data, so we keep them out of the top level. This is the one place
    the flat-dict pattern bends.
    """
    plaintext = raw.get("plaintext") or {}
    body = plaintext.get("tn.agents")
    if not isinstance(body, dict):
        return
    # ``$no_read_key`` / ``$decrypt_error`` sentinels: don't surface; the
    # group is in ``_hidden_groups`` / ``_decrypt_errors`` already.
    if body.get("$no_read_key") is True or body.get("$decrypt_error") is True:
        return

    instructions: dict[str, Any] = {}
    for f in (
        "instruction",
        "use_for",
        "do_not_use_for",
        "consequences",
        "on_violation_or_error",
        "policy",
    ):
        if f in body:
            instructions[f] = body[f]
        # Also remove from the flat top level — instructions are a
        # separate concern.
        flat.pop(f, None)

    if instructions:
        flat["instructions"] = instructions


def _emit_tampered_row_skipped(envelope: dict[str, Any], reasons: list[str]) -> None:
    """Append a ``tn.read.tampered_row_skipped`` admin event with public
    fields only — the bad row's payload is NOT exposed."""
    import tn
    rt = tn._dispatch_rt
    if rt is None:
        return
    rt.emit(
        "warning",
        "tn.read.tampered_row_skipped",
        {
            "envelope_event_id": envelope.get("event_id"),
            "envelope_did": envelope.get("did"),
            "envelope_event_type": envelope.get("event_type"),
            "envelope_sequence": envelope.get("sequence"),
            "invalid_reasons": sorted(set(reasons)),
        },
    )


def _is_foreign_log(log_path, cfg=None) -> bool:
    """Peek at the first JSON line of ``log_path``; return True iff the
    envelope's publisher ``did`` differs from the current runtime's
    device DID. Used by ``tn.read()`` to auto-route cross-publisher
    reads through ``read_as_recipient`` (FINDINGS S6.2).

    Conservative on failure — if the file is unreadable, has no
    parseable line, or our keystore has no default kit, return False so
    the regular read path runs and surfaces the underlying error itself.
    The kit-existence guard prevents false positives when ``tn.read()``
    is given an explicit log_path that's actually our own log but the
    auto-discovery chain landed on a different yaml than the one that
    wrote it (e.g. concurrent-emit tests that flush + re-init).
    """
    import json as _json
    from pathlib import Path as _Path

    from . import current_config

    try:
        active_cfg = cfg if cfg is not None else current_config()
    except RuntimeError:
        return False
    own_did = getattr(getattr(active_cfg, "device", None), "did", None)
    if not own_did:
        return False

    p = _Path(log_path)
    if not p.exists():
        return False

    keystore = getattr(active_cfg, "keystore", None)
    if keystore is None:
        return False
    kit_path = _Path(keystore) / "default.btn.mykit"
    if not kit_path.exists():
        return False

    # Don't auto-route when log_path is *exactly* our own log file.
    # That's the post-flush + re-init "reading my own log" case
    # (auto-discovery may have landed on a different yaml whose device
    # differs from the log's writer, but the log is conceptually own).
    own_log: _Path | None = None
    try:
        resolve_log = getattr(active_cfg, "resolve_log_path", None)
        if callable(resolve_log):
            resolved = resolve_log()
            own_log = _Path(str(resolved)).resolve()
    except Exception:  # noqa: BLE001 — defensive: stale cfg.resolve_log_path fallback
        own_log = None
    if own_log is not None:
        try:
            if _Path(log_path).resolve() == own_log:
                return False
        except OSError:
            pass

    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    env = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                env_did = env.get("did")
                if isinstance(env_did, str) and env_did:
                    return env_did != own_did
                # First non-empty line had no did — give up; let the
                # regular path do its thing.
                return False
    except OSError:
        return False
    return False


def _read_impl(
    log_path=None,
    cfg=None,
    *,
    verify: bool = False,
    raw: bool = False,
    all_runs: bool = False,
    where=None,
):
    """Iterate log entries. See ``tn.read`` for the full keyword contract."""
    import tn
    from . import current_config
    _surface.info(
        "tn.read() ENTER log_path=%r cfg=%s verify=%s raw=%s all_runs=%s "
        "current_run_id=%s dispatch=%s",
        log_path,
        "set" if cfg is not None else "None",
        verify, raw, all_runs, tn._run_id,
        "set" if tn._dispatch_rt is not None else "None",
    )
    tn._maybe_autoinit_load_only()
    from . import reader as _reader
    from .reader import read_as_recipient as _raw_read_as_recipient

    if log_path is not None and _is_foreign_log(log_path, cfg):
        active_cfg = cfg if cfg is not None else current_config()
        for raw_entry in _raw_read_as_recipient(
            log_path,
            active_cfg.keystore,
            group="default",
            verify_signatures=verify,
        ):
            valid = raw_entry.get("valid") or {}
            if "row_hash" not in valid:
                valid = dict(valid)
                valid["row_hash"] = bool(valid.get("signature", False))
                raw_entry["valid"] = valid
            if raw:
                if where is not None and not where(raw_entry):
                    continue
                yield raw_entry
                continue
            flat = _reader.flatten_raw_entry(raw_entry, include_valid=verify)
            if where is not None and not where(flat):
                continue
            yield flat
        return

    raw_iter = tn.read_raw(log_path, cfg, all_runs=all_runs)

    if raw:
        for r in raw_iter:
            if where is not None and not where(r):
                continue
            yield r
        return

    if not _reader._flat_default_active():
        for r in raw_iter:
            if where is not None and not where(r):
                continue
            yield r
        return

    for r in raw_iter:
        flat = _reader.flatten_raw_entry(r, include_valid=verify)
        if where is not None and not where(flat):
            continue
        yield flat


def _is_protocol_admin_event(event_type: str | None) -> bool:
    """Protocol-level admin events (``tn.*``) are emitted by the SDK itself,
    not by user code, and don't carry a ``run_id`` field — they are part
    of the ceremony's append-only history regardless of which process
    wrote them. They MUST bypass the run_id filter, otherwise reading
    the admin log returns nothing.
    """
    return isinstance(event_type, str) and event_type.startswith("tn.")


def _entry_in_current_run_flat(entry: dict[str, Any]) -> bool:
    """True iff a flat entry's `run_id` matches this process's run_id.

    Bypassed for protocol admin events (``tn.*``).
    """
    import tn
    if tn._run_id is None:
        return True
    if _is_protocol_admin_event(entry.get("event_type")):
        return True
    return entry.get("run_id") == tn._run_id


def _entry_in_current_run_raw(raw: dict[str, Any]) -> bool:
    """Same predicate for the raw {envelope, plaintext, valid} shape."""
    import tn
    if tn._run_id is None:
        return True
    env = raw.get("envelope") or {}
    if _is_protocol_admin_event(env.get("event_type")):
        return True
    plaintext = raw.get("plaintext") or {}
    for grp_fields in plaintext.values():
        if isinstance(grp_fields, dict):
            rid = grp_fields.get("run_id")
            if rid is not None:
                return rid == tn._run_id
    return False  # no run_id anywhere -> exclude (use all_runs=True to see)


def _read_raw_impl(log_path=None, cfg=None, *, all_runs: bool = False, where=None):
    """Iterate log entries as raw `{envelope, plaintext, valid}` dicts."""
    import tn
    _surface.info(
        "tn.read_raw() ENTER log_path=%r cfg=%s all_runs=%s run_id=%s",
        log_path, "set" if cfg is not None else "None", all_runs, tn._run_id,
    )
    return _read_raw_inner(log_path, cfg, all_runs=all_runs, where=where)


def _read_raw_inner(log_path=None, cfg=None, *, all_runs: bool = False, where=None):
    """Internal implementation of read_raw without surface-log entry."""
    import tn
    from . import current_config
    tn._maybe_autoinit_load_only()

    if all_runs and tn._dispatch_rt is not None and tn._dispatch_rt.using_rust:
        try:
            active_cfg = cfg if cfg is not None else current_config()
        except RuntimeError:
            active_cfg = None
        own_log = None
        if active_cfg is not None:
            try:
                own_log = active_cfg.resolve_log_path()
            except Exception:  # noqa: BLE001 — defensive on partially-loaded cfg
                own_log = None
        target_path = log_path if log_path is not None else own_log
        if target_path is not None and own_log is not None and Path(target_path).resolve() == Path(own_log).resolve():
            for backup_path in _rotated_backup_paths(Path(target_path)):
                try:
                    for r in tn._dispatch_rt.read(backup_path):
                        if where is not None and not where(r):
                            continue
                        yield r
                except Exception:  # noqa: BLE001 — best-effort: skip unreadable backups
                    continue

    if tn._dispatch_rt is not None and tn._dispatch_rt.using_rust:
        for r in tn._dispatch_rt.read(log_path):
            if not all_runs and not _entry_in_current_run_raw(r):
                continue
            if where is not None and not where(r):
                continue
            yield r
        return
    # Legacy reader path — pure-Python, unchanged behavior for JWE.
    from .reader import read as _legacy_read_fn

    if cfg is None:
        cfg = current_config()
    for r in _legacy_read_fn(log_path, cfg):
        if not all_runs and not _entry_in_current_run_raw(r):
            continue
        if where is not None and not where(r):
            continue
        yield r


def _rotated_backup_paths(log_path: Path) -> list[str]:
    """Return paths of rotation backups (`<log>.N` ... `<log>.1`) that
    exist on disk, **oldest first**."""
    parent = log_path.parent
    base = log_path.name
    found: list[tuple[int, str]] = []
    for n in range(1, 100):
        candidate = parent / f"{base}.{n}"
        if candidate.exists():
            found.append((n, str(candidate)))
    # Sort by N descending so oldest comes first — rotation shifts
    # `.N -> .N+1`, so the highest N is the oldest.
    found.sort(key=lambda t: -t[0])
    return [p for _, p in found]


def _read_raw_admin_aware(cfg=None):
    """Iterate raw entries across the main log AND the admin log."""
    import tn
    from . import current_config
    if cfg is None:
        cfg = current_config()

    main_path = cfg.resolve_log_path()
    seen: set = set()
    if main_path.exists():
        seen.add(main_path.resolve())
        yield from tn.read_raw(main_path, cfg, all_runs=True)

    # Admin log (and any other PEL files materialized so far).
    from .reader import _pel_glob_files

    for pel_file in _pel_glob_files(cfg):
        if not pel_file.is_file():
            continue
        rp = pel_file.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        yield from tn.read_raw(pel_file, cfg, all_runs=True)


def _read_all_impl(log_path=None, cfg=None, *, all_runs: bool = False, where=None):
    """User-facing wrapper: load-only auto-init, then delegate to
    ``tn.reader.read_all``."""
    import tn
    from .reader import read_all as _raw_read_all
    tn._maybe_autoinit_load_only()
    for r in _raw_read_all(log_path, cfg):
        if not all_runs and not _entry_in_current_run_raw(r):
            continue
        if where is not None and not where(r):
            continue
        yield r


def _read_as_recipient_impl(log_path, keystore_dir, *, group: str = "default",
                            verify_signatures: bool = True):
    """User-facing wrapper: delegates straight to
    ``tn.reader.read_as_recipient``."""
    from .reader import read_as_recipient as _raw_read_as_recipient
    yield from _raw_read_as_recipient(
        log_path, keystore_dir, group=group, verify_signatures=verify_signatures,
    )
