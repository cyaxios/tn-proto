"""Tail-aware async generator over the local TN ndjson log(s).

Tracks byte offset per source file so we never re-read prior bytes on
append. Survives rotation (inode change) by reopening at offset 0 of
the new file. On unexpected truncation (file shorter than tracked
offset, no inode change), we resume from the new end and emit a
tamper-class admin event (``tn.watch.truncation_observed``).

By default ``tn.watch`` tails **only the main user log**. Admin events
(``tn.*``) live in a separate log and must be addressed explicitly:

    tn.watch(log="admin")                       # sugar (use this)
    tn.watch(log=cfg.admin_log_location)        # explicit config address
    tn.watch(log="./logs/payments.ndjson")      # literal path to any log

This is intentionally symmetric with ``tn.read`` — the two verbs share
the resolver in ``tn._log_targets`` so any addressing form works
uniformly. The previous always-include-admin default was a regression
fix; the new default rule is "admin events are addressed, never
merged implicitly."

Cross-language counterpart: ts-sdk/src/watch.ts. Both implementations
must yield the same entries in the same order for the same log file.

Stat-poll based — no watchdog / native fs-event dependency. The
default 0.3s poll interval matches the TS default.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

from ._entry import VerifyError
from .read_policy import ReadContext, ReadDecision, ReadTrustPolicy


@dataclass(frozen=True)
class SourceCursorV1:
    """Lossless position for one canonical watch source."""

    kind: Literal["byte_offset", "sequence", "opaque"]
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in {
            "byte_offset",
            "sequence",
            "opaque",
        }:
            raise ValueError(f"invalid cursor kind: {self.kind!r}")
        if not isinstance(self.value, str):
            raise ValueError("cursor value must be a lossless string")
        if self.kind in {"byte_offset", "sequence"} and not self.value.isdecimal():
            raise ValueError(f"{self.kind} cursor value must be a non-negative decimal string")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class ReadCursorV1:
    """Versioned multi-source cursor serialized in canonical key order."""

    sources: Mapping[str, SourceCursorV1] = field(default_factory=dict)
    version: Literal[1] = 1

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("watch cursor version must be exactly 1")
        if not isinstance(self.sources, Mapping):
            raise ValueError("watch cursor sources must be a mapping")
        normalized: dict[str, SourceCursorV1] = {}
        for source_id, source in self.sources.items():
            if not _valid_source_id(source_id):
                raise ValueError(f"invalid canonical watch source ID: {source_id!r}")
            if not isinstance(source, SourceCursorV1):
                raise ValueError(f"invalid source cursor for {source_id!r}")
            normalized[source_id] = source
        object.__setattr__(self, "sources", dict(sorted(normalized.items())))

    @classmethod
    def from_value(cls, value: ReadCursorV1 | Mapping[str, Any]) -> ReadCursorV1:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping) or set(value) != {"version", "sources"}:
            raise ValueError("watch cursor must contain exactly version and sources")
        raw_sources = value["sources"]
        if not isinstance(raw_sources, Mapping):
            raise ValueError("watch cursor sources must be a mapping")
        sources: dict[str, SourceCursorV1] = {}
        for source_id, raw_source in raw_sources.items():
            if not isinstance(raw_source, Mapping) or set(raw_source) != {"kind", "value"}:
                raise ValueError(
                    f"source cursor {source_id!r} must contain exactly kind and value",
                )
            sources[source_id] = SourceCursorV1(
                kind=raw_source["kind"],
                value=raw_source["value"],
            )
        return cls(version=value["version"], sources=sources)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "sources": {
                source_id: self.sources[source_id].to_dict()
                for source_id in sorted(self.sources)
            },
        }


def canonical_source_id(descriptor: bytes) -> str:
    """Hash one NUL-delimited source descriptor into its stable ID."""

    return f"source:sha256:{hashlib.sha256(descriptor).hexdigest()}"


def _valid_source_id(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("source:sha256:"):
        return False
    digest = value.removeprefix("source:sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def _normalize_file_source_path(path: str) -> str:
    slashed = path.replace("\\", "/")
    if slashed.startswith("//?/"):
        slashed = slashed[4:]
    prefix = ""
    remainder = slashed
    if (
        len(slashed) >= 3
        and slashed[0].isalpha()
        and slashed[1:3] == ":/"
    ):
        prefix = slashed[0].lower() + ":/"
        remainder = slashed[3:]
    elif slashed.startswith("//"):
        prefix = "//"
        remainder = slashed[2:]
    elif slashed.startswith("/"):
        prefix = "/"
        remainder = slashed[1:]

    components: list[str] = []
    for component in remainder.split("/"):
        if component == ".." and components and components[-1] != "..":
            components.pop()
        elif component == ".." and not prefix:
            components.append(component)
        elif component in {"", ".", ".."}:
            continue
        else:
            components.append(component)
    return prefix + "/".join(components)


def canonical_file_source_id(path: str | os.PathLike[str]) -> str:
    """Return the host-independent lexical ID for an already joined path."""

    normalized = _normalize_file_source_path(os.fspath(path))
    return canonical_source_id(b"file\0" + normalized.encode("utf-8"))


@dataclass
class _SourceState:
    """Per-source-file tail state. One instance per file being watched."""
    path: Path
    offset: int = 0
    inode: int | None = None
    source_id: str | None = None
    scanned: int = 0
    prev_hash_by_event: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source_id is None:
            self.source_id = canonical_file_source_id(self.path)

    @property
    def cursor(self) -> SourceCursorV1:
        return SourceCursorV1(kind="byte_offset", value=str(self.offset))


@dataclass(frozen=True)
class _WatchRecord:
    raw: dict[str, Any]
    decision: ReadDecision


@dataclass
class _WatchProgress:
    sources: list[_SourceState]
    retained_sources: dict[str, SourceCursorV1] = field(default_factory=dict)

    @property
    def cursor(self) -> ReadCursorV1:
        current = dict(self.retained_sources)
        current.update(
            {
                source.source_id: source.cursor
                for source in self.sources
                if source.source_id is not None
            },
        )
        return ReadCursorV1(sources=current)


def build_watch_progress(
    cfg: Any,
    paths: list[Path],
    *,
    since: str | int,
    cursor: ReadCursorV1 | Mapping[str, Any] | None,
) -> _WatchProgress:
    parsed_cursor = ReadCursorV1.from_value(cursor) if cursor is not None else None
    yaml_path = Path(getattr(cfg, "yaml_path", Path.cwd() / "tn.yaml"))
    if not yaml_path.is_absolute():
        yaml_path = Path.cwd() / yaml_path
    yaml_dir = yaml_path.parent
    retained = dict(parsed_cursor.sources) if parsed_cursor is not None else {}
    sources: list[_SourceState] = []
    for path in paths:
        joined = path if path.is_absolute() else yaml_dir / path
        source_id = canonical_file_source_id(joined)
        resumed = retained.get(source_id)
        if resumed is not None:
            if resumed.kind != "byte_offset":
                raise ValueError(
                    f"file watch source {source_id} requires a byte_offset cursor",
                )
            offset = int(resumed.value)
        else:
            offset = _initial_offset_for(path, since)
        sources.append(
            _SourceState(
                path=path,
                offset=offset,
                inode=(path.stat().st_ino if path.exists() else None),
                source_id=source_id,
            ),
        )
    return _WatchProgress(sources=sources, retained_sources=retained)


def _resolve_watch_sources(
    cfg, log_path: Any
) -> list[Path]:
    """Decide which files ``tn.watch`` should tail.

    Symmetric with ``tn.read``: routes the public ``log=`` argument
    through :func:`tn._log_targets.resolve_log_target` so any form a
    caller might pass — literal path, template with ``{event_type}``
    style tokens, or the ``"admin"`` alias — yields the same file set
    here and in ``tn.read``.

    With ``log_path is None`` we tail **only the main log**. Admin
    envelopes (``tn.*``) live in their own log since the
    runtime-correctness work split them off; merging them into the
    default watch surface was a regression-period workaround. Callers
    that actually want to see admin events in their tail say so:

        tn.watch(log="admin")                       # sugar (use this)
        tn.watch(log=cfg.admin_log_location)        # explicit config address
    """
    if log_path is None:
        return [cfg.resolve_log_path()]
    from ._log_targets import resolve_log_target

    return resolve_log_target(log_path, cfg)


def _initial_offset_for(
    path: Path, since: str | int
) -> int:
    """Compute the starting byte offset for one source given ``since``."""
    if since == "start":
        return 0
    if since == "now":
        return path.stat().st_size if path.exists() else 0
    if isinstance(since, int):
        return _find_offset_for_sequence(path, since)
    return _find_offset_for_timestamp(path, since)


async def _watch_impl(
    *,
    since: str | int = "now",
    poll_interval: float = 0.3,
    log_path: str | os.PathLike | None = None,
    policy: ReadTrustPolicy,
    context: ReadContext,
    cfg: Any | None = None,
    paths: list[Path] | None = None,
    progress: _WatchProgress | None = None,
    as_recipient: str | os.PathLike | None = None,
    group: str = "default",
) -> AsyncIterator[_WatchRecord]:
    # Bug W5 (0.4.2a4 follow-up): match ``tn.read``'s autoinit path so
    # a fresh process without a bound runtime gets the same friendly
    # "no ceremony found" error (with discovery-chain hint) instead
    # of the bare ``no active runtime`` raise that ``current_config``
    # would otherwise produce. read.py:191 does this for the same
    # reason; the asymmetry made watch's empty-result mode confusing.
    if cfg is None:
        import tn as _tn

        _tn._maybe_autoinit_load_only()
        from . import current_config

        cfg = current_config()
    if paths is None:
        paths = _resolve_watch_sources(cfg, log_path)

    recipient_ciphers = (
        _load_recipient_ciphers(Path(as_recipient), group)
        if as_recipient is not None
        else None
    )

    if progress is None:
        progress = build_watch_progress(
            cfg,
            paths,
            since=since,
            cursor=None,
        )
    sources = progress.sources

    while True:
        any_yielded = False
        for src in sources:
            async for entry in _drain_one_source(
                src,
                cfg,
                policy=policy,
                context=context,
                recipient_ciphers=recipient_ciphers,
                group=group,
            ):
                any_yielded = True
                yield entry
        # Sleep once per full tick. If nothing was yielded this tick
        # it's a clean wait; if something was, the caller saw it via
        # the yields above and we still sleep before the next stat.
        del any_yielded
        await asyncio.sleep(poll_interval)


async def _drain_one_source(
    src: _SourceState,
    cfg,
    *,
    policy: ReadTrustPolicy,
    context: ReadContext,
    recipient_ciphers: list[Any] | None,
    group: str,
) -> AsyncIterator[_WatchRecord]:
    """Drain a single source file's new lines since the last tick.

    Updates ``src`` in place (offset, inode, prev_hash chain). Yields
    one raw triple plus its policy decision per accepted envelope. Every
    complete line advances the byte cursor before evaluation, including a
    rejected line, so skip mode cannot loop or conceal later appends.
    """
    p = src.path
    if not p.exists():
        return

    st = p.stat()
    current_inode = st.st_ino

    if src.inode is not None and current_inode != src.inode:
        # Rotation — file replaced. Reset to offset 0 of the new file.
        src.offset = 0
        src.inode = current_inode
        src.prev_hash_by_event.clear()
    elif st.st_size < src.offset:
        # Truncation — file shorter than tracked offset, same inode.
        _emit_truncation_warning(p, src.offset, st.st_size)
        src.offset = st.st_size
    else:
        src.inode = current_inode

    if st.st_size <= src.offset:
        return

    with p.open("rb") as f:
        f.seek(src.offset)
        while True:
            line = f.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                # Partial line; rewind so the next tick re-reads it whole.
                src.offset = f.tell() - len(line)
                break
            # Advance progress before any yield or rejection. If the caller
            # stops after this record, resumption still starts after exactly
            # the bytes already scanned.
            src.offset = f.tell()
            if not line.strip():
                continue
            src.scanned += 1
            try:
                line_str = line.decode("utf-8").rstrip("\r\n")
                raw, decision = _evaluate_line(
                    line_str,
                    cfg,
                    policy=policy,
                    context=context,
                    prev_hash_by_event=src.prev_hash_by_event,
                    recipient_ciphers=recipient_ciphers,
                    group=group,
                )
            except Exception as error:
                if _handle_parse_failure(error, policy):
                    continue
                raise
            if not decision.accepted:
                if _handle_rejection(raw, decision, policy):
                    continue
                raise AssertionError("unreachable watch rejection state")
            yield _WatchRecord(raw=raw, decision=decision)


def _evaluate_line(
    line: str,
    cfg: Any,
    *,
    policy: ReadTrustPolicy,
    context: ReadContext,
    prev_hash_by_event: dict[str, str],
    recipient_ciphers: list[Any] | None,
    group: str,
) -> tuple[dict[str, Any], ReadDecision]:
    """Scan, gate, decrypt, and fully evaluate one complete source row."""

    from .read import _record_state
    from .reader import _scan_envelope_before_decrypt

    parsed = json.loads(line)
    if not isinstance(parsed, dict):
        raise ValueError("TN envelope must be a JSON object")
    valid, groups_from_env = _scan_envelope_before_decrypt(
        parsed,
        prev_hash_by_event,
    )
    pre_context = replace(context, required_group=None)
    pre_raw = {"envelope": parsed, "plaintext": {}, "valid": valid}
    pre_decision = policy.evaluate(_record_state(pre_raw), pre_context)
    if not pre_decision.accepted:
        return pre_raw, pre_decision

    plaintext = _decrypt_groups(
        parsed,
        groups_from_env,
        cfg,
        recipient_ciphers=recipient_ciphers,
        group=group,
    )
    valid["aad"] = not any(
        body.get("$decrypt_error") is True
        for body in plaintext.values()
        if isinstance(body, dict)
    )
    raw = {"envelope": parsed, "plaintext": plaintext, "valid": valid}
    return raw, policy.evaluate(_record_state(raw), context)


def _decrypt_groups(
    envelope: dict[str, Any],
    groups_from_env: dict[str, dict[str, Any]],
    cfg: Any,
    *,
    recipient_ciphers: list[Any] | None,
    group: str,
) -> dict[str, dict[str, Any]]:
    from . import cipher as _cipher
    from .reader import _aad_bytes_for, _decode_plaintext_object

    plaintext: dict[str, dict[str, Any]] = {}
    if recipient_ciphers is not None:
        group_input = groups_from_env.get(group)
        if group_input is None:
            return plaintext
        saw_no_key = False
        saw_open_failure = False
        for candidate in list(recipient_ciphers):
            try:
                payload = candidate.decrypt(
                    group_input["ciphertext"],
                    _aad_bytes_for(envelope, group),
                )
            except _cipher.NotARecipientError:
                saw_no_key = True
                continue
            except Exception:  # noqa: BLE001 - authenticated open failed
                saw_open_failure = True
                continue
            plaintext[group] = _decode_plaintext_object(payload, group)
            if recipient_ciphers[0] is not candidate:
                recipient_ciphers.remove(candidate)
                recipient_ciphers.insert(0, candidate)
            break
        if group not in plaintext:
            plaintext[group] = (
                {"$decrypt_error": True}
                if saw_open_failure or not saw_no_key
                else {"$no_read_key": True}
            )
        return plaintext

    for group_name, group_cfg in cfg.groups.items():
        group_input = groups_from_env.get(group_name)
        if group_input is None:
            continue
        try:
            payload = group_cfg.cipher.decrypt(
                group_input["ciphertext"],
                _aad_bytes_for(envelope, group_name),
            )
        except _cipher.NotARecipientError:
            plaintext[group_name] = {"$no_read_key": True}
            continue
        except Exception:  # noqa: BLE001 - authenticated open failed
            plaintext[group_name] = {"$decrypt_error": True}
            continue
        plaintext[group_name] = _decode_plaintext_object(payload, group_name)
    return plaintext


def _load_recipient_ciphers(keystore: Path, group: str) -> list[Any]:
    from . import cipher as _cipher

    candidates: list[Any] = []
    btn_kit = keystore / f"{group}.btn.mykit"
    jwe_key = keystore / f"{group}.jwe.mykey"
    hibe_key = keystore / f"{group}.hibe.sk"
    if btn_kit.exists():
        candidates.append(_cipher.BtnGroupCipher.load(keystore, group))
    if jwe_key.exists():
        candidates.append(_cipher.JWEGroupCipher.load(keystore, group))
    if hibe_key.exists():
        candidates.append(_cipher.HibeGroupCipher.load(keystore, group))
    if not candidates:
        raise FileNotFoundError(
            f"tn.watch: no recipient key found for group={group!r} in {keystore}. "
            f"Looked for {btn_kit.name}, {jwe_key.name}, and {hibe_key.name}.",
        )
    return candidates


def _handle_parse_failure(
    error: Exception,
    policy: ReadTrustPolicy,
    *,
    envelope: dict[str, Any] | None = None,
) -> bool:
    """Return true when skip mode consumed the malformed source row."""

    observed = envelope or {
        "event_type": "<parse-error>",
        "_parse_error": str(error),
    }
    event_type = str(observed.get("event_type", "<parse-error>"))
    try:
        sequence = int(observed.get("sequence", 0))
    except (TypeError, ValueError):
        sequence = 0
    if policy.mode == "skip":
        from .read import _emit_tampered_row

        _emit_tampered_row(observed, ["record_invalid"])
        return True
    if policy.mode == "raise":
        raise VerifyError(
            sequence=sequence,
            event_type=event_type,
            reason="record_invalid",
            reasons=["record_invalid"],
        ) from error
    # Verification-disabled mode still requires canonical parsing.
    return False


def _handle_rejection(
    raw: dict[str, Any],
    decision: ReadDecision,
    policy: ReadTrustPolicy,
) -> bool:
    reasons = [reason.value for reason in decision.reasons]
    reason = reasons[0] if reasons else "record_invalid"
    envelope = raw.get("envelope") or {}
    if policy.mode == "skip":
        from .read import _emit_tampered_row

        _emit_tampered_row(envelope, reasons)
        return True
    raise VerifyError(
        sequence=int(envelope.get("sequence", 0)),
        event_type=str(envelope.get("event_type", "")),
        reason=reason,
        reasons=reasons,
    )


def _emit_truncation_warning(
    path: Path, prior_offset: int, new_size: int
) -> None:
    """Best-effort emit of ``tn.watch.truncation_observed`` admin event.

    Truncation under a stable inode signals tampering or surprising
    operator action (manual file edit, log-rotation tool that didn't
    rename, etc.). We surface it as a warning-level admin event so it
    rides the attested log and survives forensics. Swallowed if the
    dispatch isn't ready yet.
    """
    try:
        from . import _require_dispatch
        rt = _require_dispatch()
        rt.emit("warning", "tn.watch.truncation_observed", {
            "log_path": str(path),
            "prior_offset": prior_offset,
            "new_size": new_size,
        })
    except Exception:  # noqa: BLE001 — best-effort: swallow if dispatch isn't ready
        pass


def _find_offset_for_sequence(path: Path, target_seq: int) -> int:
    """Linear scan from byte 0; return offset of first envelope with sequence >= target_seq.

    Note: per-event-type sequence semantics — the comparison is on the
    envelope's ``sequence`` field as-is. Cross-language tests use a single
    event_type so ``tn.watch(since=N)`` and an N-th absolute entry coincide.
    """
    if not path.exists():
        return 0
    pos = 0
    with path.open("rb") as f:
        while True:
            start = f.tell()
            line = f.readline()
            if not line:
                return pos
            if not line.endswith(b"\n"):
                return start
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                pos = f.tell()
                continue
            seq = env.get("sequence")
            if isinstance(seq, int) and seq >= target_seq:
                return start
            pos = f.tell()


def _find_offset_for_timestamp(path: Path, target_ts: str) -> int:
    """Linear scan; return offset of first envelope with timestamp >= target_ts.

    Timestamps are ISO-8601 strings in TN envelopes (RFC 3339 / lexicographic
    ordering); we do a string compare rather than parsing each one.
    """
    if not path.exists():
        return 0
    pos = 0
    with path.open("rb") as f:
        while True:
            start = f.tell()
            line = f.readline()
            if not line:
                return pos
            if not line.endswith(b"\n"):
                return start
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                pos = f.tell()
                continue
            ts = env.get("timestamp")
            if isinstance(ts, str) and ts >= target_ts:
                return start
            pos = f.tell()
