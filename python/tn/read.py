"""Read & watch verbs.

The single ``tn.read`` + ``tn.watch`` surface, both yielding
:class:`Entry` instances by default and on-disk envelope dicts when
``raw=True``.

Kwargs (both verbs):
  - ``where``        — predicate ``(Entry) -> bool``; entries that don't
                       match are skipped.
  - ``verify``       — reads use ``"auto"`` by default, resolving a secure
                       receiver-local policy. ``True`` / ``"raise"`` raises
                       :class:`VerifyError` on the first rejected row,
                       ``"skip"`` drops rejected rows with observability, and
                       ``False`` explicitly disables the security gate.
  - ``raw``          — yield the envelope dict plus ``_valid`` audit metadata
                       instead of an Entry.
  - ``log``          — alternate log address. Defaults to the current
                       ceremony's main log. Accepts a literal path, a
                       template with ``{event_type}`` / ``{date}`` /
                       etc. tokens (glob expanded), or the ``"admin"``
                       alias (resolves to ``cfg.admin_log_location``).
                       The default surface NEVER merges the admin log
                       in — address it explicitly.
  - ``as_recipient`` — keystore directory to decrypt with. Defaults to
                       the current ceremony's keystore.
  - ``group``        — group whose plaintext to surface (only meaningful
                       with ``as_recipient``).

Read-only kwargs:
  - ``all_runs``     — default ``True``: scan every entry on disk.
                       Pass ``False`` to restrict to this process's
                       current run.

Watch-only kwargs:
  - ``since``        — ``"now"`` | ``"start"`` | int | iso-string.
  - ``poll_interval``— seconds between stat polls.
"""
from __future__ import annotations

import json
import logging as _logging
from collections.abc import AsyncIterator, Callable, Collection, Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, overload

from ._entry import Entry, VerifyError
from ._watch_impl import ReadCursorV1
from .read_policy import (
    ReadContext,
    ReadDecision,
    ReadRecordState,
    ReadTrustPolicy,
    VerifyMode,
)
from .read_trust import InMemoryReadTrustProvider, LocalReadTrustProvider
from .security_audit import (
    UnsafeOperation,
    UnsafeOperationNotice,
    UnsafeRelaxation,
    record_unsafe_operation,
)

# ---------------------------------------------------------------------
# Public read-side observability primitives (DX review #11)
# ---------------------------------------------------------------------


@dataclass
class ReadStats:
    """Per-call accounting of what ``tn.read`` yielded vs dropped.

    Attached as ``.stats`` to the iterator that ``tn.read`` returns so
    callers can introspect post-iteration:

        result = tn.read(verify="skip")
        for e in result:
            ...
        if result.stats.skipped_verify > 0:
            log.warning("%d entries failed integrity", result.stats.skipped_verify)

    Counters tick incrementally during iteration, so partial consumption
    (break out of the loop early) shows partial counts. Rejections in
    ``verify="skip"`` mode populate the relevant ``skipped_*`` counters.
    """

    yielded: int = 0
    skipped_parse: int = 0
    skipped_verify: int = 0
    # 0.4.2a10: decrypt failures get their own bucket so callers can
    # distinguish "the bytes parsed and verified but I don't hold the
    # right kit for this row's groups" from parse / verify failures.
    # Bumped each time a yielded entry has hidden_groups != [] (i.e.
    # we couldn't decrypt at least one group's payload).
    skipped_decrypt: int = 0
    skipped_reasons: list[str] = field(default_factory=list)


class _ReadIterator:
    """Iterator wrapper that exposes ``.stats`` alongside the
    generator protocol. Returned by ``tn.read``; transparent to
    ``for e in tn.read(): ...``.
    """

    def __init__(
        self,
        gen: Iterator[Any],
        stats: ReadStats,
    ) -> None:
        self._gen = gen
        self.stats = stats

    def __iter__(self) -> _ReadIterator:
        return self

    def __next__(self) -> Any:
        return next(self._gen)

    # Generator-style close so callers using ``yield from`` or
    # itertools-style cleanup paths continue to work.
    def close(self) -> None:
        close = getattr(self._gen, "close", None)
        if close is not None:
            close()


class _WatchIterator:
    """Async-iterator-compatible watch result with a live resumable cursor."""

    def __init__(self, gen: Any, progress: Any) -> None:
        self._gen = gen
        self._progress = progress

    @property
    def cursor(self) -> ReadCursorV1:
        return self._progress.cursor

    def __aiter__(self) -> _WatchIterator:
        return self

    def __anext__(self) -> Any:
        return self._gen.__anext__()

    async def aclose(self) -> None:
        close = getattr(self._gen, "aclose", None)
        if close is not None:
            await close()

    def asend(self, value: Any) -> Any:
        return self._gen.asend(value)

    def athrow(self, *args: Any) -> Any:
        return self._gen.athrow(*args)


@dataclass
class _RuntimeAuditContext:
    """Adapt a bound read runtime to the shared unsafe-operation sink."""

    runtime: Any | None
    writable: bool
    emitted_event_id: str | None = None

    def emit_admin(self, event_type: str, fields: dict[str, object]) -> Any:
        if self.runtime is None:
            return None
        emitted = self.runtime.emit("warning", event_type, fields)
        if isinstance(emitted, dict):
            event_id = emitted.get("event_id")
            if isinstance(event_id, str) and event_id:
                self.emitted_event_id = event_id
        return emitted


def record_policy_weakening(
    operation: Literal["read", "watch"],
    policy: ReadTrustPolicy,
    context: ReadContext,
    *,
    runtime: Any | None = None,
) -> str | None:
    """Emit one common warning/audit notice for an actually weaker policy.

    Explicit unsigned settings are not weaker when the active local profile
    is already unsigned. Every other departure from the secure automatic
    policy is represented by the stable shared relaxation names.
    """

    automatic_unsigned = (
        context.active
        and context.local_log
        and not context.detached
        and context.profile_sign is False
    )
    relaxations: list[UnsafeRelaxation] = []
    if policy.mode == "disabled":
        relaxations.append(UnsafeRelaxation.VERIFICATION_DISABLED)
    if not automatic_unsigned and not policy.require_signature:
        relaxations.append(UnsafeRelaxation.SIGNATURE_NOT_REQUIRED)
    if not automatic_unsigned and policy.allow_unauthenticated:
        relaxations.append(UnsafeRelaxation.UNAUTHENTICATED_ALLOWED)
    if policy.allow_unknown_writers:
        relaxations.append(UnsafeRelaxation.UNKNOWN_WRITER_ALLOWED)
    if not relaxations:
        return None

    notice = UnsafeOperationNotice(
        operation=UnsafeOperation(operation),
        relaxations=tuple(relaxations),
        group=context.required_group,
        subject_did=None,
        artifact_digest=None,
    )
    audit_context = _RuntimeAuditContext(
        runtime=runtime,
        writable=context.writable and runtime is not None,
    )
    record_unsafe_operation(notice, audit_context)
    return audit_context.emitted_event_id

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _all_valid(valid: dict[str, Any]) -> bool:
    return (
        bool(valid.get("signature", True))
        and bool(valid.get("row_hash", True))
        and bool(valid.get("chain", True))
    )


def _local_device_did(cfg: Any | None) -> str | None:
    device = getattr(cfg, "device", None)
    return getattr(device, "device_identity", None) or getattr(device, "did", None)


def _same_path(left: Any, right: Any) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve()
    except (OSError, TypeError, ValueError):
        return False


def _build_read_context(
    cfg: Any | None,
    *,
    log: str | Path | None,
    log_targets: list[Path],
    as_recipient: str | Path | None,
    group: str,
) -> ReadContext:
    active = cfg is not None
    local_log = log is None
    if cfg is not None and log_targets:
        local_targets: list[Path] = []
        try:
            local_targets.append(Path(cfg.resolve_log_path()))
        except Exception:  # noqa: BLE001 - an unresolved path is not local
            pass
        try:
            from ._log_targets import resolve_log_target

            local_targets.extend(resolve_log_target(getattr(cfg, "log_path", ""), cfg))
            local_targets.extend(resolve_log_target("admin", cfg))
        except Exception:  # noqa: BLE001 - trust only sources we can resolve exactly
            pass
        local_log = bool(local_targets) and all(
            any(_same_path(path, local) for local in local_targets)
            for path in log_targets
        )
    detached = as_recipient is not None or not active
    if cfg is None:
        provider = InMemoryReadTrustProvider({})
    else:
        state_root = getattr(cfg, "read_state_root", Path(cfg.keystore).parent)
        provider = LocalReadTrustProvider(cfg, Path(state_root))
    return ReadContext(
        active=active,
        local_log=local_log,
        detached=detached,
        writable=active and local_log and not detached,
        profile_sign=getattr(cfg, "sign", None) if cfg is not None else None,
        profile_chain=getattr(cfg, "chain", None) if cfg is not None else None,
        local_device_did=_local_device_did(cfg),
        required_group=group if as_recipient is not None else None,
        trust_provider=provider,
    )


def _record_state(raw_entry: dict[str, Any]) -> ReadRecordState:
    envelope = raw_entry.get("envelope") or {}
    valid = raw_entry.get("valid") or {}
    plaintext = raw_entry.get("plaintext") or {}
    decrypt_failed = any(
        isinstance(body, dict) and body.get("$decrypt_error") is True
        for body in plaintext.values()
    )
    recipient_groups = frozenset(
        name
        for name, body in plaintext.items()
        if isinstance(body, dict)
        and body.get("$decrypt_error") is not True
        and body.get("$no_read_key") is not True
    )
    return ReadRecordState(
        record_valid=bool(valid.get("record", True)),
        row_hash_present=bool(envelope.get("row_hash")),
        row_hash_valid=valid.get("row_hash") is True,
        chain_valid=valid.get("chain") is True,
        signature_present=bool(envelope.get("signature")),
        signature_valid=valid.get("signature") is True,
        writer_did=envelope.get("device_identity")
        if isinstance(envelope.get("device_identity"), str)
        else None,
        aad_valid=valid.get("aad", not decrypt_failed) is True,
        recipient_groups=recipient_groups,
    )


def _valid_metadata(raw_entry: dict[str, Any], decision: ReadDecision) -> dict[str, Any]:
    valid = raw_entry.get("valid") or {}
    return {
        "signature": valid.get("signature") is True,
        "row_hash": valid.get("row_hash") is True,
        "chain": valid.get("chain") is True,
        "writer_authenticated": decision.writer_authenticated,
        "writer_authorized": decision.writer_authorized,
        "reasons": [reason.value for reason in decision.reasons],
    }


def _raw_envelope_with_validity(
    raw_entry: dict[str, Any],
    decision: ReadDecision,
) -> dict[str, Any]:
    envelope = dict(raw_entry.get("envelope") or {})
    envelope["_valid"] = _valid_metadata(raw_entry, decision)
    return envelope


def _emit_tampered_row(envelope: dict[str, Any], reasons: list[str]) -> None:
    """Emit ``tn.read.tampered_row_skipped`` admin event. Best-effort."""
    import tn
    rt = tn._dispatch_rt
    if rt is None:
        return
    if str(envelope.get("event_type", "")) == "tn.read.tampered_row_skipped":
        return
    try:
        rt.emit(
            "warning",
            "tn.read.tampered_row_skipped",
            {
                "envelope_event_id": envelope.get("event_id"),
                "envelope_device_identity": envelope.get("device_identity"),
                "envelope_event_type": envelope.get("event_type"),
                "envelope_sequence": envelope.get("sequence"),
                "invalid_reasons": sorted(set(reasons)),
            },
        )
    except Exception:  # noqa: BLE001 — best-effort surface
        pass


def _check_verify_kwarg(verify: VerifyMode) -> None:
    """Validate the ``verify`` kwarg.

    Legal values:
      * ``"auto"`` (default) — resolve the secure receiver-local policy.
      * ``False`` — don't verify; parse errors raise.
      * ``True`` / ``'raise'`` — verify; raise on first failure
        (synonyms — ``True`` is the idiomatic Python form,
        ``'raise'`` is the explicit string form).
      * ``'skip'`` — verify; drop failures; populate ``.stats`` /
        fire ``on_skip``.

    The shared ``VerifyMode`` type keeps IDE autocomplete and runtime
    validation aligned across read and watch.
    """
    if verify in (False, True, "auto", "skip", "raise"):
        return
    raise ValueError(
        f"verify must be 'auto' | False | True | 'skip' | 'raise'; got {verify!r}"
    )


def _wrap_parse_errors(
    triple_iter,
    verify,
    *,
    on_skip: Callable[[dict[str, Any], str], None] | None = None,
    stats: ReadStats | None = None,
):
    """Wrap a triple iterator so parser-level errors (malformed ciphertext,
    unparseable JSON, etc.) follow the same verify policy as
    integrity-check failures.

    Without this, a single tampered row raises out of the for-loop and
    the caller never gets to skip-and-continue under ``verify="skip"``.
    """
    while True:
        try:
            r = next(triple_iter)
        except StopIteration:
            return
        except Exception as exc:
            reason = "record_invalid"
            tampered_env = {
                "event_type": "<parse-error>",
                "_parse_error": f"{type(exc).__name__}: {exc}",
                "_valid": {
                    "signature": False,
                    "row_hash": False,
                    "chain": False,
                    "writer_authenticated": False,
                    "writer_authorized": False,
                    "reasons": [reason],
                },
            }
            # DX review #11: notify observer (logging hook / metric)
            # before any irreversible action (skip / raise).
            if on_skip is not None:
                try:
                    on_skip(tampered_env, reason)
                except Exception:  # noqa: BLE001 — observer must not break the read
                    _logging.getLogger("tn.read").warning(
                        "on_skip callback raised; continuing.",
                        exc_info=True,
                    )
            if stats is not None:
                stats.skipped_parse += 1
                stats.skipped_reasons.append(reason)
            if verify == "skip":
                _emit_tampered_row(tampered_env, [reason])
                continue
            if verify == "raise":
                raise VerifyError(
                    sequence=0,
                    event_type="<parse-error>",
                    reason=reason,
                    reasons=[reason],
                ) from exc
            # Disabled mode never returns malformed bytes as plaintext.
            raise
        yield r


# ---------------------------------------------------------------------
# Public verbs
# ---------------------------------------------------------------------


def _resolve_read_source(cfg: Any | None = None, runtime: Any | None = None) -> Any:
    """Pick the session's read source. File wins when the ceremony's main
    log exists on disk; otherwise the first handler that implements
    ``reader()`` (e.g. Kafka). Returns ``None`` to use the default file
    path — so existing file-backed ceremonies are entirely unaffected.
    """
    from pathlib import Path as _Path

    from .handlers.base import TNHandler

    # File wins when a real main log exists — preserves all current behavior.
    try:
        if cfg is None:
            from . import current_config

            cfg = current_config()
        lp = cfg.resolve_log_path()
        if lp and _Path(lp).exists() and _Path(lp).stat().st_size > 0:
            return None
    except Exception:  # noqa: BLE001
        pass

    from .handlers.file import (
        FileRotatingHandler,
        FileTemplatedRotatingHandler,
        FileTimedRotatingHandler,
    )
    _file_kinds = (
        FileRotatingHandler,
        FileTemplatedRotatingHandler,
        FileTimedRotatingHandler,
    )

    import tn.logger as _lg
    rt = getattr(runtime, "_py_rt", None) or getattr(_lg, "_runtime", None)
    for h in list(getattr(rt, "handlers", []) or []):
        # File handlers are the file path, already gated above by the
        # log-exists check — skip them here. A NETWORK handler is a read
        # source iff it overrides the base no-op reader().
        if isinstance(h, _file_kinds):
            continue
        if type(h).reader is not TNHandler.reader:
            return h
    return None


def _passes_selector_filter(
    env: dict[str, Any],
    selector: str | None,
    filter: dict[str, Any] | None,
) -> bool:
    """Authoritative client-side gate. event_type is a public field; this
    re-applies the selector + declarative filter regardless of whether the
    source pushed them down."""
    et = str(env.get("event_type", ""))
    if selector is not None and et != selector:
        return False
    if filter:
        lvl = str(env.get("level", ""))
        if "event_type_in" in filter and et not in filter["event_type_in"]:
            return False
        if "event_type_prefix" in filter and not et.startswith(filter["event_type_prefix"]):
            return False
        if "level_in" in filter and lvl not in filter["level_in"]:
            return False
    return True


@overload
def read(
    selector: str | None = ...,
    *,
    filter: dict[str, Any] | None = ...,
    reader_options: dict[str, Any] | None = ...,
    where: Callable[[Any], bool] | None = ...,
    verify: VerifyMode = ...,
    require_signature: bool | None = ...,
    allow_unauthenticated: bool | None = ...,
    trusted_writers: Collection[str] | None = ...,
    allow_unknown_writers: bool = ...,
    raw: Literal[False] = ...,
    log: str | Path | None = ...,
    as_recipient: str | Path | None = ...,
    group: str = ...,
    all_runs: bool = ...,
    on_skip: Callable[[dict[str, Any], str], None] | None = ...,
) -> _ReadIterator: ...
@overload
def read(
    selector: str | None = ...,
    *,
    filter: dict[str, Any] | None = ...,
    reader_options: dict[str, Any] | None = ...,
    where: Callable[[Any], bool] | None = ...,
    verify: VerifyMode = ...,
    require_signature: bool | None = ...,
    allow_unauthenticated: bool | None = ...,
    trusted_writers: Collection[str] | None = ...,
    allow_unknown_writers: bool = ...,
    raw: Literal[True],
    log: str | Path | None = ...,
    as_recipient: str | Path | None = ...,
    group: str = ...,
    all_runs: bool = ...,
    on_skip: Callable[[dict[str, Any], str], None] | None = ...,
) -> _ReadIterator: ...
def read(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    verify: Literal["auto", "raise", "skip"] | bool = "auto",
    require_signature: bool | None = None,
    allow_unauthenticated: bool | None = None,
    trusted_writers: Collection[str] | None = None,
    allow_unknown_writers: bool = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
    on_skip: Callable[[dict[str, Any], str], None] | None = None,
) -> _ReadIterator:
    """Read with receiver-local secure defaults; see :func:`_read_bound`."""

    return _read_bound(
        selector,
        filter=filter,
        reader_options=reader_options,
        where=where,
        verify=verify,
        require_signature=require_signature,
        allow_unauthenticated=allow_unauthenticated,
        trusted_writers=trusted_writers,
        allow_unknown_writers=allow_unknown_writers,
        raw=raw,
        log=log,
        as_recipient=as_recipient,
        group=group,
        all_runs=all_runs,
        on_skip=on_skip,
    )


def _read_bound(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    verify: VerifyMode = "auto",
    require_signature: bool | None = None,
    allow_unauthenticated: bool | None = None,
    trusted_writers: Collection[str] | None = None,
    allow_unknown_writers: bool = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
    on_skip: Callable[[dict[str, Any], str], None] | None = None,
    _cfg: Any | None = None,
    _runtime: Any | None = None,
) -> _ReadIterator:
    """Iterate attested log entries from the active ceremony.

    ``selector`` is the primary, positional selector: an exact
    ``event_type`` (no wildcards). ``None`` reads every event_type.

    ``filter`` is a declarative selector dict (``event_type_in`` /
    ``event_type_prefix`` / ``level_in``) applied as the authoritative
    gate AND offered to the source handler as a pushdown hint.

    ``reader_options`` is an opaque passthrough bag forwarded verbatim to
    the underlying read source (e.g. a Kafka consumer's ``group_id`` /
    ``offset`` / tuning). ``read`` never reads a key out of it. Ignored by
    file sources. Source is auto-resolved from the session handlers:
    a file source wins when present, else the first readable handler
    (e.g. Kafka).

    Default mode yields :class:`Entry` instances — flat-shaped dicts
    with the six envelope basics (``timestamp``, ``event_type``,
    ``level``, ``device_identity``, ``sequence``, ``event_id``) plus
    every readable group's decrypted fields hoisted to the top level.
    Pass ``raw=True`` to preserve the envelope-dict result shape and attach
    an ``_valid`` mapping with verification facts and rejection reasons.

    Args:
        where: Optional predicate ``(Entry|dict) -> bool``. Entries
            that return ``False`` are skipped. Applied AFTER decrypt
            and verify so the predicate sees the same shape callers
            iterate.
        verify: Read-policy mode. ``"auto"`` (default) resolves secure
            receiver-local requirements and raises on rejection.
            ``True`` is a compatibility alias for ``"raise"``;
            ``"skip"`` drops rejected rows with observability, and
            ``False`` explicitly disables policy enforcement.
        raw: ``False`` (default) yields :class:`Entry` instances.
            ``True`` yields envelope dicts with an added ``_valid`` mapping
            containing security facts and the full rejection-reason list.
        log: Source log address. ``None`` (default) reads the active
            ceremony's main log. Accepted forms:

            * ``"admin"`` — alias for ``cfg.admin_log_location``.
            * Absolute or relative path (``str`` or :class:`Path`).
            * Template with ``{event_type}`` / ``{event_class}`` /
              ``{date}`` / ``{yaml_dir}`` / ``{ceremony_id}`` /
              ``{did}`` tokens — every matching file is read in turn.
        as_recipient: Path to a single recipient kit (``*.btn.mykit``
            or ``*.jwe.mykey``). When set, decryption uses ONLY that
            kit — useful for offline cross-publisher audits. When
            unset and ``log`` is non-default, every kit in the active
            keystore is tried per envelope.
        group: Group name when ``as_recipient`` is set (selects which
            kit in that directory to load). Default ``"default"``.
        all_runs: ``True`` (default) yields entries from every run on
            disk. ``False`` filters to entries this process emitted
            in the current run only (per ``TN_RUN_ID``).
        on_skip: Optional callback invoked per dropped row when
            ``verify="skip"``. Receives ``(envelope_dict, reason)``.
            Useful for surfacing chain breaks without raising.

    Yields:
        :class:`Entry` (default) or ``dict`` (when ``raw=True``).
        The iterator exposes a ``.stats`` property after exhaustion
        with yielded and skip counters plus stable skip reasons.

    Raises:
        VerifyError: If ``verify="auto"``, ``True``, or ``"raise"`` and a
            row is rejected by the resolved read policy.
        RuntimeError: If :func:`tn.init` hasn't been called and
            ``TN_STRICT=1`` blocks auto-init.
        FileNotFoundError: If ``log`` resolves to a path that
            doesn't exist.

    Example:
        >>> import tn
        >>> tn.init()
        >>> tn.info("user.signed_in", user_id="u_123")

        >>> # Default: every entry from this ceremony's main log.
        >>> for e in tn.read():
        ...     print(e.sequence, e.event_type)

        >>> # Verified read; raise on tamper.
        >>> for e in tn.read(verify="raise"):
        ...     process(e)

        >>> # Audit-grade with full envelopes.
        >>> for row in tn.read(raw=True):
        ...     assert row["_valid"]["signature"] is True

        >>> # Read the admin log (tn.* protocol events).
        >>> for e in tn.read(log="admin"):
        ...     print(e.event_type)   # e.g. "tn.recipient.added"

    See Also:
        :func:`tn.watch`: Tail the log live (async generator).
        :func:`tn.info` / :func:`tn.log`: The producer side.
    """
    import tn
    if _cfg is None:
        tn._maybe_autoinit_load_only()
        try:
            _cfg = tn.current_config()
        except RuntimeError:
            _cfg = None
    if _runtime is None and _cfg is not None:
        _runtime = getattr(tn, "_dispatch_rt", None)

    # Resolve ``log`` to a concrete list of files. ``None`` keeps the
    # default (main log resolved by downstream readers). Anything else
    # — literal path, template, or ``"admin"`` sugar — goes through the
    # shared resolver so ``tn.read(log=cfg.admin_log_location)`` and
    # ``tn.read(log="admin")`` and ``tn.read(log=Path(...))`` all reach
    # the same code path. The default ``tn.read()`` deliberately does
    # NOT merge the admin log; admin events are addressed explicitly.
    log_targets: list[Path] = []
    if log is not None:
        from ._log_targets import resolve_log_target
        log_targets = resolve_log_target(log, _cfg)
    elif _cfg is not None and "{" in str(getattr(_cfg, "log_path", "")):
        from ._log_targets import resolve_log_target

        log_targets = resolve_log_target(_cfg.log_path, _cfg)

    context = _build_read_context(
        _cfg,
        log=log,
        log_targets=log_targets,
        as_recipient=as_recipient,
        group=group,
    )
    if (
        (not context.local_log or context.detached)
        and (require_signature is False or allow_unauthenticated is True)
        and not (require_signature is False and allow_unauthenticated is True)
    ):
        raise ValueError(
            "foreign or detached unsigned reads require both "
            "require_signature=False and allow_unauthenticated=True",
        )
    policy = ReadTrustPolicy.resolve(
        verify=verify,
        require_signature=require_signature,
        allow_unauthenticated=allow_unauthenticated,
        trusted_writers=trusted_writers,
        allow_unknown_writers=allow_unknown_writers,
        context=context,
    )
    unsafe_audit_event_id = record_policy_weakening(
        "read",
        policy,
        context,
        runtime=_runtime,
    )
    pre_decrypt_context = replace(context, required_group=None)

    def _pre_decrypt_gate(envelope: dict[str, Any], valid: dict[str, Any]) -> bool:
        state = _record_state(
            {"envelope": envelope, "plaintext": {}, "valid": valid},
        )
        state = replace(state, aad_valid=True, recipient_groups=frozenset())
        return policy.evaluate(state, pre_decrypt_context).accepted

    read_source = (
        _resolve_read_source(_cfg, _runtime)
        if log is None and as_recipient is None
        else None
    )

    # Source of {envelope, plaintext, valid} triples.
    #
    # Decryption strategy:
    #
    # * ``log=None`` (caller wants their own ceremony's main log):
    #   route through the runtime's read path — it uses the
    #   PublisherState which is the authoritative decryptor for
    #   events this ceremony emitted.
    #
    # * ``log=...`` + ``as_recipient=None``: key-bag read against
    #   the active ceremony's keystore. After ``tn.absorb(bundle)``
    #   the bundle's kits live in ``cfg.keystore``, so every
    #   ``*.btn.mykit`` / ``*.jwe.mykey`` is tried per envelope and
    #   anything that decrypts is yielded. Closes #57.
    #
    # * ``log=...`` + ``as_recipient=<path>``: explicit single-kit
    #   override (bring-your-own-kit; no merge into the keystore).
    #   ``group=`` selects which group's kit in that directory to
    #   load.
    if as_recipient is not None:
        from .reader import read_as_recipient as _raw_read_as_recipient
        if log is None:
            if _cfg is None:
                raise RuntimeError("as_recipient requires an active read context or explicit log")
            log_targets = [_cfg.resolve_log_path()]
        verify_sigs = policy.mode != "disabled"
        # Single-kit mode: one cipher per call, one group decrypted.
        def _triples_single_kit() -> Iterator[dict[str, Any]]:
            for one_log in log_targets:
                yield from _raw_read_as_recipient(
                    one_log,
                    Path(as_recipient),
                    group=group,
                    verify_signatures=verify_sigs,
                    pre_decrypt=_pre_decrypt_gate,
                )
        triples = _triples_single_kit()
    elif log is not None:
        from .reader import read_with_keybag as _raw_read_with_keybag
        try:
            _bag_keystore = _cfg.keystore if _cfg is not None else None
        except AttributeError:
            # No active ceremony; can't key-bag. Treat as the
            # foreign-without-keystore case: read raw envelopes only.
            _bag_keystore = None
        verify_sigs = policy.mode != "disabled"
        def _triples_keybag() -> Iterator[dict[str, Any]]:
            if _bag_keystore is None:
                # No keystore available — yield raw envelopes with
                # empty plaintext so the caller at least sees the
                # event_types / metadata. Better than silent empty.
                for one_log in log_targets:
                    try:
                        with open(one_log, encoding="utf-8") as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    env = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                yield {
                                    "envelope": env,
                                    "plaintext": {},
                                    "valid": {
                                        "record": True,
                                        "signature": False,
                                        "row_hash": False,
                                        "chain": False,
                                        "aad": True,
                                    },
                                }
                    except FileNotFoundError:
                        continue
                return
            for one_log in log_targets:
                yield from _raw_read_with_keybag(
                    one_log,
                    Path(_bag_keystore),
                    verify_signatures=verify_sigs,
                    pre_decrypt=_pre_decrypt_gate,
                )
        triples = _triples_keybag()
    elif log is None and log_targets:
        from ._read_impl import _read_raw_inner

        def _triples_local_templates() -> Iterator[dict[str, Any]]:
            for one_log in log_targets:
                yield from _read_raw_inner(
                    one_log,
                    _cfg,
                    all_runs=all_runs,
                    pre_decrypt=_pre_decrypt_gate,
                    runtime=_runtime,
                )

        triples = _triples_local_templates()
    elif read_source is not None:
        # No explicit log, no file source available, but a readable network
        # handler (e.g. Kafka) is configured. Pull sealed bytes from it and
        # run them through the SAME keybag decrypt path as a file read.
        from .reader import _lines_with_keybag
        src = read_source
        try:
            _ks = _cfg.keystore if _cfg is not None else None
        except AttributeError:
            _ks = None
        verify_sigs = policy.mode != "disabled"

        def _triples_handler() -> Iterator[dict[str, Any]]:
            lines = src.reader(reader_options, selection=selector, filter=filter)
            if lines is None:
                return
            if _ks is None:
                for _label, raw_line in lines:
                    s = raw_line.strip()
                    if not s:
                        continue
                    try:
                        env = json.loads(s)
                    except json.JSONDecodeError:
                        continue
                    yield {
                        "envelope": env,
                        "plaintext": {},
                        "valid": {
                            "record": True,
                            "signature": False,
                            "row_hash": False,
                            "chain": False,
                            "aad": True,
                        },
                    }
                return
            yield from _lines_with_keybag(
                lines,
                _ks,
                verify_signatures=verify_sigs,
                pre_decrypt=_pre_decrypt_gate,
            )
        triples = _triples_handler()
    else:
        from ._read_impl import _entry_in_current_run_raw, _read_raw_inner
        if log is None:
            triples = (
                r
                for r in _read_raw_inner(
                    None,
                    _cfg,
                    all_runs=all_runs,
                    pre_decrypt=_pre_decrypt_gate,
                    runtime=_runtime,
                )
                if all_runs or _entry_in_current_run_raw(r)
            )
        else:
            # Explicit target(s): iterate each resolved file in turn.
            # No run_id filter — when the caller named a specific log
            # they're asking for everything in it, not just this
            # process's emits.
            def _triples_explicit() -> Iterator[dict[str, Any]]:
                for one_log in log_targets:
                    yield from _read_raw_inner(
                        one_log,
                        _cfg,
                        all_runs=True,
                        pre_decrypt=_pre_decrypt_gate,
                        runtime=_runtime,
                    )
            triples = _triples_explicit()

    # DX review #11: build the public ReadStats accumulator (always
    # present on the returned iterator; cheap to maintain even when
    # unused). The inner generator updates ``stats.yielded`` /
    # ``skipped_*`` as it walks; callers introspect after iteration.
    stats = ReadStats()

    def _gen() -> Iterator[Any]:
        for r in _wrap_parse_errors(
            iter(triples), policy.mode, on_skip=on_skip, stats=stats,
        ):
            env_for_parse_check = r.get("envelope") or {}
            if env_for_parse_check.get("event_type") == "<parse-error>":
                decision = policy.evaluate(_record_state(r), context)
                observed = _raw_envelope_with_validity(r, decision)
                reason = "record_invalid"
                if on_skip is not None:
                    try:
                        on_skip(observed, reason)
                    except Exception:  # noqa: BLE001
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised; continuing.",
                            exc_info=True,
                        )
                stats.skipped_parse += 1
                stats.skipped_reasons.append(reason)
                if policy.mode == "raise":
                    raise VerifyError(
                        sequence=0,
                        event_type="<parse-error>",
                        reason=reason,
                        reasons=[reason],
                    )
                if policy.mode == "skip":
                    _emit_tampered_row(observed, [reason])
                continue

            decision = policy.evaluate(_record_state(r), context)
            observed_envelope = _raw_envelope_with_validity(r, decision)
            if not decision.accepted:
                reasons = [reason.value for reason in decision.reasons]
                reason = reasons[0] if reasons else "record_invalid"
                stats.skipped_verify += 1
                stats.skipped_reasons.append(reason)
                if on_skip is not None:
                    try:
                        on_skip(observed_envelope, reason)
                    except Exception:  # noqa: BLE001 - observers cannot alter read results
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised; continuing.",
                            exc_info=True,
                        )
                if policy.mode == "skip":
                    _emit_tampered_row(observed_envelope, reasons)
                    continue
                env = r.get("envelope") or {}
                raise VerifyError(
                    sequence=int(env.get("sequence", 0)),
                    event_type=str(env.get("event_type", "")),
                    reason=reason,
                    reasons=reasons,
                )

            envelope_event_id = (r.get("envelope") or {}).get("event_id")
            if (
                unsafe_audit_event_id is not None
                and envelope_event_id == unsafe_audit_event_id
            ):
                # The audit row still passed through scan/policy so chain state
                # advances, but this operation must not change its own result.
                continue

            # 0.4.2a10: surface decrypt failures.
            # When the dispatch returned a triple whose `plaintext` is
            # missing keys for at least one group present in the
            # envelope's ciphertext, the row's `hidden_groups` is
            # non-empty. This is distinct from a parse / verify
            # failure — the bytes parsed and the signature checked,
            # but the reader doesn't hold a kit that can decrypt
            # the payload. Today this would yield an Entry with
            # `fields = {}` silently; that's the audit-correctness
            # hole the 0.4.2a10 admin-verb-clarity spec calls out.
            #
            # Now: bump stats.skipped_decrypt, fire on_skip with a
            # reason starting "decrypt:<groups>", and yield the
            # entry as before (so chain integrity / sequence
            # continuity stay visible). The Entry exposes a new
            # `decryption_failed` property the caller can branch
            # on; existing call sites that don't check it see
            # exactly the same shape as before.
            hidden = list(r.get("envelope_hidden_groups", []) or [])
            if not hidden:
                # The Entry-construction path also derives this from
                # the raw triple; mirror its logic so we agree.
                env_for_hidden = r.get("envelope") or {}
                plaintext_for_hidden = r.get("plaintext") or {}
                hidden = [
                    g for g in env_for_hidden
                    if isinstance(env_for_hidden.get(g), dict)
                    and "ciphertext" in env_for_hidden[g]
                    and (
                        g not in plaintext_for_hidden
                        or (
                            isinstance(plaintext_for_hidden.get(g), dict)
                            and plaintext_for_hidden[g].get("$no_read_key") is True
                        )
                    )
                ]
            if hidden:
                env = r.get("envelope") or {}
                reason = "decrypt:" + ",".join(sorted(hidden))
                stats.skipped_decrypt += 1
                stats.skipped_reasons.append(reason)
                if on_skip is not None:
                    try:
                        on_skip(observed_envelope, reason)
                    except Exception:  # noqa: BLE001
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised on decrypt-fail; "
                            "continuing.",
                            exc_info=True,
                        )

            # Authoritative selector + filter gate (public-field match).
            if not _passes_selector_filter(r.get("envelope") or {}, selector, filter):
                continue

            if raw:
                envelope = observed_envelope
                if where is not None and not where(envelope):
                    continue
                stats.yielded += 1
                yield envelope
                continue

            try:
                entry = Entry.from_raw(r)
            except Exception as error:
                observed_envelope["_valid"]["reasons"] = ["record_invalid"]
                stats.skipped_parse += 1
                stats.skipped_reasons.append("record_invalid")
                if on_skip is not None:
                    try:
                        on_skip(observed_envelope, "record_invalid")
                    except Exception:  # noqa: BLE001 - observers cannot alter results
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised; continuing.",
                            exc_info=True,
                        )
                from ._watch_impl import _handle_parse_failure

                if _handle_parse_failure(
                    error,
                    policy,
                    envelope=r.get("envelope"),
                ):
                    continue
                raise
            if where is not None and not where(entry):
                continue
            stats.yielded += 1
            yield entry

    return _ReadIterator(_gen(), stats)


def secure_read(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    trusted_writers: Collection[str] | None = None,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
) -> _ReadIterator:
    """Strict convenience wrapper over the primary :func:`read` surface."""

    return _secure_read_bound(
        selector,
        filter=filter,
        reader_options=reader_options,
        where=where,
        trusted_writers=trusted_writers,
        raw=raw,
        log=log,
        as_recipient=as_recipient,
        group=group,
        all_runs=all_runs,
    )


def _secure_read_bound(
    selector: str | None = None,
    *,
    filter: dict[str, Any] | None = None,
    reader_options: dict[str, Any] | None = None,
    where: Callable[[Any], bool] | None = None,
    trusted_writers: Collection[str] | None = None,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
    _cfg: Any | None = None,
    _runtime: Any | None = None,
) -> _ReadIterator:
    return _read_bound(
        selector,
        filter=filter,
        reader_options=reader_options,
        where=where,
        verify="raise",
        require_signature=True,
        allow_unauthenticated=False,
        trusted_writers=trusted_writers,
        allow_unknown_writers=False,
        raw=raw,
        log=log,
        as_recipient=as_recipient,
        group=group,
        all_runs=all_runs,
        _cfg=_cfg,
        _runtime=_runtime,
    )


def watch(
    *,
    where: Callable[[Any], bool] | None = None,
    verify: VerifyMode = "auto",
    require_signature: bool | None = None,
    allow_unauthenticated: bool | None = None,
    trusted_writers: Collection[str] | None = None,
    allow_unknown_writers: bool = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    cursor: ReadCursorV1 | Mapping[str, Any] | None = None,
    since: str | int = "now",
    poll_interval: float = 0.3,
) -> _WatchIterator:
    """Tail with the same frozen receiver-local trust policy as :func:`read`.

    ``verify="auto"`` is secure by default. ``True`` / ``"raise"``,
    ``"skip"``, and explicit ``False`` retain the read-side meanings, and
    every complete source row advances the watch cursor exactly once even
    when skip mode rejects it. Verification and writer authorization happen
    before group decryption. ``raw=True`` preserves the on-disk envelope and
    adds the same ``_valid`` metadata as ``read(raw=True)``. The returned
    async iterator exposes a live ``.cursor``; pass that object or its
    ``to_dict()`` value back through ``cursor=`` to resume losslessly.
    """

    import tn

    tn._maybe_autoinit_load_only()
    cfg = tn.current_config()
    runtime = getattr(tn, "_dispatch_rt", None)

    from . import _watch_impl as _watch

    if cursor is not None and since != "now":
        raise ValueError("watch cursor cannot be combined with non-default since")

    paths = _watch._resolve_watch_sources(cfg, log)
    progress = _watch.build_watch_progress(
        cfg,
        paths,
        since=since,
        cursor=cursor,
    )
    context = _build_read_context(
        cfg,
        log=log,
        log_targets=paths,
        as_recipient=as_recipient,
        group=group,
    )
    if (
        (not context.local_log or context.detached)
        and (require_signature is False or allow_unauthenticated is True)
        and not (require_signature is False and allow_unauthenticated is True)
    ):
        raise ValueError(
            "foreign or detached unsigned reads require both "
            "require_signature=False and allow_unauthenticated=True",
        )
    policy = ReadTrustPolicy.resolve(
        verify=verify,
        require_signature=require_signature,
        allow_unauthenticated=allow_unauthenticated,
        trusted_writers=trusted_writers,
        allow_unknown_writers=allow_unknown_writers,
        context=context,
    )
    unsafe_audit_event_id = record_policy_weakening(
        "watch",
        policy,
        context,
        runtime=runtime,
    )

    async def _gen() -> AsyncIterator[Entry | dict[str, Any]]:
        async for record in _watch._watch_impl(
            since=since,
            poll_interval=poll_interval,
            log_path=log,
            policy=policy,
            context=context,
            cfg=cfg,
            paths=paths,
            progress=progress,
            as_recipient=as_recipient,
            group=group,
        ):
            envelope_event_id = (record.raw.get("envelope") or {}).get("event_id")
            if (
                unsafe_audit_event_id is not None
                and envelope_event_id == unsafe_audit_event_id
            ):
                # Scan/evaluate the self-audit row for chain continuity but do
                # not let observability change this operation's result.
                continue
            if raw:
                envelope = _raw_envelope_with_validity(record.raw, record.decision)
                if where is not None and not where(envelope):
                    continue
                yield envelope
                continue
            try:
                entry = Entry.from_raw(record.raw)
            except Exception as error:
                if _watch._handle_parse_failure(
                    error,
                    policy,
                    envelope=record.raw.get("envelope"),
                ):
                    continue
                raise
            if where is not None and not where(entry):
                continue
            yield entry

    return _WatchIterator(_gen(), progress)
