"""Read & watch verbs.

The single ``tn.read`` + ``tn.watch`` surface, both yielding
:class:`Entry` instances by default and on-disk envelope dicts when
``raw=True``.

Kwargs (both verbs):
  - ``where``        — predicate ``(Entry) -> bool``; entries that don't
                       match are skipped.
  - ``verify``       — ``False`` (default), ``True`` / ``"raise"`` (verify,
                       raise :class:`VerifyError` on first failure),
                       ``"skip"`` (verify, drop integrity-check failures
                       silently and emit a
                       ``tn.read.tampered_row_skipped`` admin event).
                       ``"skip"`` handles signature / row_hash / chain
                       failures gracefully; rows whose bytes won't even
                       parse (malformed ciphertext, truncated JSON) still
                       raise — those aren't "tampered" so much as
                       structurally broken, and the read path treats them
                       as bugs to surface, not events to skip.
  - ``raw``          — yield the on-disk envelope dict instead of an Entry.
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
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, overload

from ._entry import Entry, VerifyError


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
    (break out of the loop early) shows partial counts. The default
    ``verify=False`` mode never populates ``skipped_*`` — parse errors
    raise as today.
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

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _all_valid(valid: dict[str, Any]) -> bool:
    return (
        bool(valid.get("signature", True))
        and bool(valid.get("row_hash", True))
        and bool(valid.get("chain", True))
    )


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


def _check_verify_kwarg(verify: bool | Literal["skip", "raise"]) -> None:
    """Validate the ``verify`` kwarg.

    Legal values:
      * ``False`` (default) — don't verify; parse errors raise.
      * ``True`` / ``'raise'`` — verify; raise on first failure
        (synonyms — ``True`` is the idiomatic Python form,
        ``'raise'`` is the explicit string form).
      * ``'skip'`` — verify; drop failures; populate ``.stats`` /
        fire ``on_skip``.

    DX review #17: the type is ``bool | Literal["skip", "raise"]``
    so IDE autocomplete suggests the legal string values. The
    runtime check still accepts the same four values as before.
    """
    if verify in (False, True, "skip", "raise"):
        return
    raise ValueError(
        f"verify must be False | True | 'skip' | 'raise'; got {verify!r}"
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
            reason = f"parse: {type(exc).__name__}: {exc}"
            tampered_env = {"event_type": "<parse-error>"}
            # DX review #11: notify observer (logging hook / metric)
            # before any irreversible action (skip / raise).
            if on_skip is not None:
                try:
                    on_skip(tampered_env, reason)
                except Exception:  # noqa: BLE001 — observer must not break the read
                    import logging as _logging
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
            if verify in (True, "raise"):
                raise VerifyError(
                    sequence=0,
                    event_type="<parse-error>",
                    failed_checks=[reason],
                ) from exc
            # verify=False: malformed bytes are still bytes; let the
            # caller see the original exception so they can debug.
            raise
        yield r


# ---------------------------------------------------------------------
# Public verbs
# ---------------------------------------------------------------------


def _resolve_read_source() -> Any:
    """Pick the session's read source. File wins when the ceremony's main
    log exists on disk; otherwise the first handler that implements
    ``reader()`` (e.g. Kafka). Returns ``None`` to use the default file
    path — so existing file-backed ceremonies are entirely unaffected.
    """
    from pathlib import Path as _Path

    from . import current_config
    from .handlers.base import TNHandler

    # File wins when a real main log exists — preserves all current behavior.
    try:
        lp = current_config().resolve_log_path()
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
    rt = getattr(_lg, "_runtime", None)
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
    *,
    where: Callable[[Any], bool] | None = ...,
    verify: bool | Literal["skip", "raise"] = ...,
    raw: Literal[False] = ...,
    log: str | Path | None = ...,
    as_recipient: str | Path | None = ...,
    group: str = ...,
    all_runs: bool = ...,
    on_skip: Callable[[dict[str, Any], str], None] | None = ...,
) -> _ReadIterator: ...
@overload
def read(
    *,
    where: Callable[[Any], bool] | None = ...,
    verify: bool | Literal["skip", "raise"] = ...,
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
    verify: bool | Literal["skip", "raise"] = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = True,
    on_skip: Callable[[dict[str, Any], str], None] | None = None,
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
    Pass ``raw=True`` to yield ``{envelope, plaintext, valid}`` audit
    triples unchanged for forensics / chain inspection.

    Args:
        where: Optional predicate ``(Entry|dict) -> bool``. Entries
            that return ``False`` are skipped. Applied AFTER decrypt
            and verify so the predicate sees the same shape callers
            iterate.
        verify: Signature / row_hash / chain verification mode.
            ``False`` (default): no verification; yield every row.
            ``True`` / ``"skip"``: verify; silently drop bad rows.
            ``"raise"``: verify; raise :class:`VerifyError` on the
            first bad row.
        raw: ``False`` (default) yields :class:`Entry` instances.
            ``True`` yields ``{envelope, plaintext, valid}`` dicts —
            the on-disk envelope unchanged plus the decrypted
            per-group plaintext map and the per-row validity flags.
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
        with ``read`` / ``decrypted`` / ``skipped`` / ``invalid``
        counts.

    Raises:
        VerifyError: If ``verify="raise"`` and a row fails signature
            / row_hash / chain verification.
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
        ...     check_signature(row["envelope"]["signature"])

        >>> # Read the admin log (tn.* protocol events).
        >>> for e in tn.read(log="admin"):
        ...     print(e.event_type)   # e.g. "tn.recipient.added"

    See Also:
        :func:`tn.watch`: Tail the log live (async generator).
        :func:`tn.info` / :func:`tn.log`: The producer side.
        `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_:
            The wire shape this returns.
        `docs/spec/row-hash.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/row-hash.md>`_:
            The chain-link hash ``verify`` checks.
    """
    _check_verify_kwarg(verify)

    import tn
    tn._maybe_autoinit_load_only()

    # Resolve ``log`` to a concrete list of files. ``None`` keeps the
    # default (main log resolved by downstream readers). Anything else
    # — literal path, template, or ``"admin"`` sugar — goes through the
    # shared resolver so ``tn.read(log=cfg.admin_log_location)`` and
    # ``tn.read(log="admin")`` and ``tn.read(log=Path(...))`` all reach
    # the same code path. The default ``tn.read()`` deliberately does
    # NOT merge the admin log; admin events are addressed explicitly.
    log_targets: list[Path] = []
    if log is not None:
        from . import current_config
        from ._log_targets import resolve_log_target
        try:
            _cfg_for_targets = current_config()
        except RuntimeError:
            _cfg_for_targets = None
        log_targets = resolve_log_target(log, _cfg_for_targets)

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
            from . import current_config
            log_targets = [current_config().resolve_log_path()]
        verify_sigs = verify is not False
        # Single-kit mode: one cipher per call, one group decrypted.
        def _triples_single_kit() -> "Iterator[dict[str, Any]]":
            for one_log in log_targets:
                yield from _raw_read_as_recipient(
                    one_log,
                    Path(as_recipient),
                    group=group,
                    verify_signatures=verify_sigs,
                )
        triples = _triples_single_kit()
    elif log is not None:
        from . import current_config
        from .reader import read_with_keybag as _raw_read_with_keybag
        try:
            _bag_keystore = current_config().keystore
        except RuntimeError:
            # No active ceremony; can't key-bag. Treat as the
            # foreign-without-keystore case: read raw envelopes only.
            _bag_keystore = None
        verify_sigs = verify is not False
        def _triples_keybag() -> "Iterator[dict[str, Any]]":
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
                                    "valid": {"signature": True, "chain": True},
                                }
                    except FileNotFoundError:
                        continue
                return
            for one_log in log_targets:
                yield from _raw_read_with_keybag(
                    one_log,
                    Path(_bag_keystore),
                    verify_signatures=verify_sigs,
                )
        triples = _triples_keybag()
    elif log is None and _resolve_read_source() is not None:
        # No explicit log, no file source available, but a readable network
        # handler (e.g. Kafka) is configured. Pull sealed bytes from it and
        # run them through the SAME keybag decrypt path as a file read.
        from . import current_config
        from .reader import _lines_with_keybag
        src = _resolve_read_source()
        try:
            _ks = current_config().keystore
        except RuntimeError:
            _ks = None
        verify_sigs = verify is not False

        def _triples_handler() -> "Iterator[dict[str, Any]]":
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
                    yield {"envelope": env, "plaintext": {},
                           "valid": {"signature": True, "chain": True}}
                return
            yield from _lines_with_keybag(lines, _ks, verify_signatures=verify_sigs)
        triples = _triples_handler()
    else:
        from ._read_impl import _entry_in_current_run_raw, _read_raw_inner
        if log is None:
            triples = (
                r for r in _read_raw_inner(None, None, all_runs=all_runs)
                if all_runs or _entry_in_current_run_raw(r)
            )
        else:
            # Explicit target(s): iterate each resolved file in turn.
            # No run_id filter — when the caller named a specific log
            # they're asking for everything in it, not just this
            # process's emits.
            def _triples_explicit() -> "Iterator[dict[str, Any]]":
                for one_log in log_targets:
                    yield from _read_raw_inner(one_log, None, all_runs=True)
            triples = _triples_explicit()

    # DX review #6: when the writer ceremony chose ``sign: false`` the
    # on-disk entries carry empty ``signature`` values by design — the
    # signature validator can't be expected to succeed there, and
    # raising ``VerifyError: signature`` on every entry makes the
    # combination "unverifiable by design." Drop signature from the
    # reasons list (under all verify modes) when the active ceremony
    # is configured for unsigned emit. Other checks (chain, row_hash,
    # decrypt) still run and still fail loudly.
    try:
        from . import current_config
        _verify_skip_signature = current_config().sign is False
    except Exception:
        _verify_skip_signature = False

    # DX review #11: build the public ReadStats accumulator (always
    # present on the returned iterator; cheap to maintain even when
    # unused). The inner generator updates ``stats.yielded`` /
    # ``skipped_*`` as it walks; callers introspect after iteration.
    stats = ReadStats()

    def _gen() -> Iterator[Any]:
        for r in _wrap_parse_errors(
            iter(triples), verify, on_skip=on_skip, stats=stats,
        ):
            # DX review 0.4.2a3 follow-up: the Rust read iterator now
            # yields a sentinel triple ({"event_type": "<parse-error>",
            # "_parse_error": "..."}) for rows that fail per-row
            # parse/decrypt instead of raising. Route those through the
            # ``skipped_parse`` counter (not ``skipped_verify``) so the
            # caller can distinguish "the bytes are malformed" from
            # "the bytes parse but verify failed."
            env_for_parse_check = r.get("envelope") or {}
            if env_for_parse_check.get("event_type") == "<parse-error>":
                reason = (
                    "parse: " +
                    str(env_for_parse_check.get("_parse_error", "unknown"))
                )
                if on_skip is not None:
                    try:
                        on_skip(env_for_parse_check, reason)
                    except Exception:  # noqa: BLE001
                        import logging as _logging
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised; continuing.",
                            exc_info=True,
                        )
                if verify in (True, "raise"):
                    stats.skipped_parse += 1
                    stats.skipped_reasons.append(reason)
                    raise VerifyError(
                        sequence=0,
                        event_type="<parse-error>",
                        failed_checks=[reason],
                    )
                if verify == "skip":
                    stats.skipped_parse += 1
                    stats.skipped_reasons.append(reason)
                    _emit_tampered_row(env_for_parse_check, [reason])
                    continue
                # verify=False (0.4.2a4): silently skip the bad row and
                # keep iterating so clean entries before and after a
                # corrupt one both surface. Stats still tick so callers
                # who care can read ``result.stats.skipped_parse`` after
                # iteration; an ``on_skip`` callback (if supplied) still
                # fires above. Previously this branch raised
                # ``ValueError(reason)``, which killed the generator
                # mid-stream and discarded every clean entry after the
                # first bad one. ``verify=True`` still raises (after the
                # observer call); ``verify='skip'`` is unchanged.
                stats.skipped_parse += 1
                stats.skipped_reasons.append(reason)
                continue

            valid = r.get("valid") or {}
            if not _all_valid(valid):
                reasons = [k for k, v in valid.items() if not v]
                if _verify_skip_signature and "signature" in reasons:
                    reasons = [r for r in reasons if r != "signature"]
                if not reasons:
                    # Only the signature check failed and we're configured
                    # to skip it — entry is valid for this ceremony.
                    pass
                else:
                    env = r.get("envelope") or {}
                    reason_str = ",".join(reasons)
                    # DX review #11: notify observer before any
                    # irreversible action (raise or skip). Catch
                    # exceptions in the callback so a buggy observer
                    # can't tank the read loop.
                    if on_skip is not None:
                        try:
                            on_skip(env, reason_str)
                        except Exception:  # noqa: BLE001
                            import logging as _logging
                            _logging.getLogger("tn.read").warning(
                                "on_skip callback raised; continuing.",
                                exc_info=True,
                            )
                    if verify in (True, "raise"):
                        stats.skipped_verify += 1
                        stats.skipped_reasons.append(reason_str)
                        raise VerifyError(
                            sequence=int(env.get("sequence", 0)),
                            event_type=str(env.get("event_type", "")),
                            failed_checks=reasons,
                        )
                    elif verify == "skip":
                        stats.skipped_verify += 1
                        stats.skipped_reasons.append(reason_str)
                        _emit_tampered_row(env, reasons)
                        continue
                    # verify=False: yield the entry anyway

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
                    and g not in plaintext_for_hidden
                ]
            if hidden:
                env = r.get("envelope") or {}
                reason = "decrypt:" + ",".join(sorted(hidden))
                stats.skipped_decrypt += 1
                stats.skipped_reasons.append(reason)
                if on_skip is not None:
                    try:
                        on_skip(env, reason)
                    except Exception:  # noqa: BLE001
                        import logging as _logging
                        _logging.getLogger("tn.read").warning(
                            "on_skip callback raised on decrypt-fail; "
                            "continuing.",
                            exc_info=True,
                        )

            # Authoritative selector + filter gate (public-field match).
            if not _passes_selector_filter(r.get("envelope") or {}, selector, filter):
                continue

            if raw:
                envelope = r.get("envelope") or {}
                if where is not None and not where(envelope):
                    continue
                stats.yielded += 1
                yield envelope
                continue

            try:
                entry = Entry.from_raw(r)
            except Exception:  # noqa: BLE001 — malformed entry, skip rather than abort
                continue
            if where is not None and not where(entry):
                continue
            stats.yielded += 1
            yield entry

    return _ReadIterator(_gen(), stats)


async def watch(
    *,
    where: Callable[[Any], bool] | None = None,
    verify: bool | Literal["skip", "raise"] = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    since: str | int = "now",
    poll_interval: float = 0.3,
) -> AsyncIterator[Entry] | AsyncIterator[dict[str, Any]]:
    """Tail the active ceremony's log live, yielding entries as they arrive.

    Async generator — use ``async for entry in tn.watch(...)``. Polls
    the underlying ndjson file(s) every ``poll_interval`` seconds;
    decrypted, optionally verified entries flow out as they're
    appended. Cancel by breaking out of the loop or letting the
    coroutine be garbage-collected.

    Args:
        where: Optional predicate ``(Entry|dict) -> bool``. Entries
            that return ``False`` are skipped. Applied AFTER decrypt
            so the predicate sees the iterator's yield shape.
        verify: Signature / row_hash / chain verification mode. Same
            three values as :func:`tn.read` (``False`` /
            ``"skip"`` / ``"raise"``). Today watch is best-effort
            here: malformed rows are silently skipped regardless of
            mode (see ``docs/sdk-parity.md`` for the rationale).
        raw: ``False`` (default) yields :class:`Entry` instances.
            ``True`` yields flat-dict envelopes — same shape as
            :func:`tn.read` (raw=True) modulo signature: watch
            doesn't expose the per-row ``valid`` block today.
        log: Source log address. ``None`` (default) tails the active
            ceremony's main log. Same forms as :func:`tn.read`:
            ``"admin"`` alias, absolute / relative path, or a
            template with ``{event_type}`` / ``{event_class}`` /
            ``{date}`` / ``{yaml_dir}`` / ``{ceremony_id}`` /
            ``{did}`` tokens (every matching file tailed in parallel).
        as_recipient: NOT SUPPORTED on watch (raises
            :class:`NotImplementedError`). For one-shot foreign reads
            use :func:`tn.read` with ``as_recipient=``.
        group: Reserved for future ``as_recipient`` support.
        since: Starting cursor. ``"now"`` (default) yields only
            entries appended AFTER the call. ``"start"`` replays
            from the beginning of the log. An ``int`` is a sequence
            number (resume after that seq). A string in ISO-8601
            form is a timestamp (resume from the first entry whose
            timestamp >= the cursor).
        poll_interval: Seconds between file-tail polls. Default
            ``0.3``. Lower = lower latency, higher CPU. The
            underlying watcher uses ``inotify`` / ``FSEvents`` /
            ``ReadDirectoryChangesW`` where available; poll-interval
            is the fallback ceiling.

    Yields:
        :class:`Entry` (default) or ``dict`` (when ``raw=True``).
        The generator never completes on its own — it tails forever
        until cancelled.

    Raises:
        NotImplementedError: If ``as_recipient`` is set (use
            :func:`tn.read` for foreign reads).
        RuntimeError: If :func:`tn.init` hasn't been called and
            ``TN_STRICT=1`` blocks auto-init.
        FileNotFoundError: If ``log`` resolves to a path that
            doesn't exist (and isn't a template that produces zero
            files — which is allowed; watch waits for the first
            match).

    Example:
        >>> import asyncio
        >>> import tn
        >>>
        >>> async def main():
        ...     tn.init()
        ...     async for entry in tn.watch():
        ...         print(entry.sequence, entry.event_type)
        ...         if entry.event_type == "scan.done":
        ...             break
        >>> # asyncio.run(main())  # would block forever otherwise

        >>> # Tail admin events (tn.* protocol bookkeeping).
        >>> async def admin_watcher():
        ...     async for e in tn.watch(log="admin"):
        ...         if e.event_type == "tn.recipient.added":
        ...             notify(e)

        >>> # Resume from a specific sequence after a crash.
        >>> async def resume(last_seq):
        ...     async for e in tn.watch(since=last_seq):
        ...         process(e)

    See Also:
        :func:`tn.read`: Synchronous one-shot read of every entry.
        :func:`tn.info` / :func:`tn.log`: The producer side.
        `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_:
            The wire shape this yields.
    """
    _check_verify_kwarg(verify)

    if as_recipient is not None:
        # Recipient-mode tail isn't wired yet — clear error rather than
        # silently wrong behavior. Use ``tn.read`` for one-shot foreign
        # reads.
        del group  # acknowledge unused
        raise NotImplementedError(
            "tn.watch(as_recipient=...) is not yet supported. "
            "Use tn.read(as_recipient=..., log=...) for foreign reads."
        )

    from ._watch_impl import _watch_impl as _impl

    # _watch_impl yields flat dicts (post-flatten_raw_entry). With the
    # 0.4.0a1 envelope-key expansion the flat dict carries every field
    # Entry.from_flat needs.
    async for flat in _impl(
        since=since,
        verify=False,  # we re-implement verify gate below
        poll_interval=poll_interval,
        log_path=log,
    ):
        # _watch_impl currently does its own per-row signature check
        # when verify=True; we asked it for verify=False so we can apply
        # our own three-mode gate here. Without raw triples accessible
        # post-watch, "verify" on the watch path is best-effort: we can
        # only detect failures the writer caught (none in the flat
        # output today). For 0.4.0a1, treat watch's verify modes the
        # same as ``False`` and document this in the parity doc.
        if raw:
            # Flat dict from watch — best we can do without a triple
            # source. Document under sdk-parity.
            if where is not None and not where(flat):
                continue
            yield flat
            continue
        try:
            entry = Entry.from_flat(flat)
        except Exception:  # noqa: BLE001 — skip malformed
            continue
        if where is not None and not where(entry):
            continue
        yield entry
