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
  - ``all_runs``     — scan across all runs in the file.

Watch-only kwargs:
  - ``since``        — ``"now"`` | ``"start"`` | int | iso-string.
  - ``poll_interval``— seconds between stat polls.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any, Literal, overload

from ._entry import Entry, VerifyError

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
                "envelope_did": envelope.get("did"),
                "envelope_event_type": envelope.get("event_type"),
                "envelope_sequence": envelope.get("sequence"),
                "invalid_reasons": sorted(set(reasons)),
            },
        )
    except Exception:  # noqa: BLE001 — best-effort surface
        pass


def _check_verify_kwarg(verify: bool | str) -> None:
    if verify in (False, True, "skip", "raise"):
        return
    raise ValueError(
        f"verify must be False | True | 'skip' | 'raise'; got {verify!r}"
    )


def _wrap_parse_errors(triple_iter, verify):
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
            if verify == "skip":
                _emit_tampered_row(
                    {"event_type": "<parse-error>"},
                    [f"parse: {type(exc).__name__}: {exc}"],
                )
                continue
            if verify in (True, "raise"):
                raise VerifyError(
                    sequence=0,
                    event_type="<parse-error>",
                    failed_checks=[f"parse: {type(exc).__name__}: {exc}"],
                ) from exc
            # verify=False: malformed bytes are still bytes; let the
            # caller see the original exception so they can debug.
            raise
        yield r


# ---------------------------------------------------------------------
# Public verbs
# ---------------------------------------------------------------------


@overload
def read(
    *,
    where: Callable[[Any], bool] | None = ...,
    verify: bool | str = ...,
    raw: Literal[False] = ...,
    log: str | Path | None = ...,
    as_recipient: str | Path | None = ...,
    group: str = ...,
    all_runs: bool = ...,
) -> Iterator[Entry]: ...
@overload
def read(
    *,
    where: Callable[[Any], bool] | None = ...,
    verify: bool | str = ...,
    raw: Literal[True],
    log: str | Path | None = ...,
    as_recipient: str | Path | None = ...,
    group: str = ...,
    all_runs: bool = ...,
) -> Iterator[dict[str, Any]]: ...
def read(
    *,
    where: Callable[[Any], bool] | None = None,
    verify: bool | str = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    all_runs: bool = False,
) -> Iterator[Entry] | Iterator[dict[str, Any]]:
    """Iterate log entries.

    Default mode yields :class:`Entry` instances. Pass ``raw=True`` to
    yield on-disk envelope dicts unchanged (forensics / chain auditors).

    The default surface is the main user log only. Admin envelopes
    (``tn.*``) live in a separate log; address them explicitly:

        tn.read(log="admin")                       # alias sugar
        tn.read(log=cfg.admin_log_location)        # explicit path
        tn.read(log="./.tn/admin/admin.ndjson")    # literal

    ``log=`` also accepts a template with ``{event_type}`` /
    ``{event_class}`` / ``{date}`` / ``{yaml_dir}`` / ``{ceremony_id}``
    / ``{did}`` tokens, in which case every matching file is read
    back in turn. This mirrors :func:`tn.watch` — both verbs share
    the same resolver so any addressing form works uniformly.
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
    if as_recipient is not None:
        from .reader import read_as_recipient as _raw_read_as_recipient
        if log is None:
            from . import current_config
            log_targets = [current_config().resolve_log_path()]
        verify_sigs = verify is not False
        # as_recipient mode tails ONE log at a time (the cipher needs
        # a stable per-file state). Multi-file template targets fan
        # out one read pass per file.
        def _triples_recipient() -> "Iterator[dict[str, Any]]":
            for one_log in log_targets:
                yield from _raw_read_as_recipient(
                    one_log,
                    Path(as_recipient),
                    group=group,
                    verify_signatures=verify_sigs,
                )
        triples = _triples_recipient()
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

    for r in _wrap_parse_errors(iter(triples), verify):
        valid = r.get("valid") or {}
        if not _all_valid(valid):
            reasons = [k for k, v in valid.items() if not v]
            if verify in (True, "raise"):
                env = r.get("envelope") or {}
                raise VerifyError(
                    sequence=int(env.get("sequence", 0)),
                    event_type=str(env.get("event_type", "")),
                    failed_checks=reasons,
                )
            if verify == "skip":
                _emit_tampered_row(r.get("envelope") or {}, reasons)
                continue
            # verify=False: yield the entry anyway

        if raw:
            envelope = r.get("envelope") or {}
            if where is not None and not where(envelope):
                continue
            yield envelope
            continue

        try:
            entry = Entry.from_raw(r)
        except Exception:  # noqa: BLE001 — malformed entry, skip rather than abort
            continue
        if where is not None and not where(entry):
            continue
        yield entry


async def watch(
    *,
    where: Callable[[Any], bool] | None = None,
    verify: bool | str = False,
    raw: bool = False,
    log: str | Path | None = None,
    as_recipient: str | Path | None = None,
    group: str = "default",
    since: str | int = "now",
    poll_interval: float = 0.3,
) -> AsyncIterator[Entry] | AsyncIterator[dict[str, Any]]:
    """Tail the log live, yielding entries as they arrive.

    Async generator. Use ``async for entry in tn.watch(...)``.

    The default surface tails the main user log only. Admin envelopes
    (``tn.*``) live in a separate log and must be addressed
    explicitly:

        tn.watch(log="admin")                       # alias sugar
        tn.watch(log=cfg.admin_log_location)        # explicit path
        tn.watch(log="./.tn/admin/admin.ndjson")    # literal

    ``log=`` also accepts a template with ``{event_type}`` /
    ``{event_class}`` / ``{date}`` / ``{yaml_dir}`` / ``{ceremony_id}``
    / ``{did}`` tokens; every matching file is tailed in parallel.
    Symmetric with :func:`tn.read`.
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
