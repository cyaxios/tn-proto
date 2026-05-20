"""Stdout handler — write envelope info to a stream.

Default-on per `tn.init()` so that out-of-the-box `tn.info(...)` lands a
line on stdout, matching the stdlib `logging.basicConfig()` mental model.
Opt-out via the `TN_NO_STDOUT=1` env var or `tn.init(stdout=False)`.

Two output formats:

  * ``pretty`` (default) — terse human-readable single line:
    ``HH:MM:SS.mmm LEVEL  seq=N  event_type``. No DID, no hashes, no
    signatures, no ciphertext: those live in the on-disk attestation
    file for audit, not on a developer's terminal.
  * ``json`` — the canonical newline-terminated NDJSON envelope (the
    same bytes the file handler writes to disk). Use this when piping
    stdout to a log shipper, ``jq``, etc.

Format selection (precedence high -> low):

  1. ``TN_STDOUT_FORMAT`` env var (``pretty`` | ``json``)
  2. ``format:`` field on the yaml ``handlers:`` entry
  3. ``format=`` constructor kwarg
  4. default: ``pretty``

For declarative use the same handler is registered as ``kind: "stdout"``
in :mod:`tn.handlers.registry`, so a yaml ``handlers: [{kind: stdout}]``
list also works.

Admin-event filtering (DX review #23):

By default the stdout handler suppresses ``tn.*`` protocol admin
events (``tn.ceremony.init``, ``tn.group.added``, etc.) so a fresh
``tn.init()`` + ``tn.info(...)`` prints exactly what the user wrote
— one line per emit, no bookkeeping noise. This matches what
``tn.read()`` already does (admin events live in a separate log
addressed via ``tn.read(log='admin')``).

Opt back in via either:

  * ``TN_STDOUT_INCLUDE_ADMIN=1`` env var (process-wide), or
  * ``include_admin=True`` constructor kwarg.
"""

from __future__ import annotations

import os
import sys
from typing import IO, Any

from .base import SyncHandler

VALID_FORMATS = ("pretty", "json")


def _resolve_format(explicit: str | None) -> str:
    """Pick stdout format with env-var override.

    Env wins over the explicit kwarg so an operator can globally flip
    every stdout sink in a process to JSON (for log shipping) without
    editing every yaml.
    """
    env = os.environ.get("TN_STDOUT_FORMAT", "").strip().lower()
    if env in VALID_FORMATS:
        return env
    if explicit and explicit.lower() in VALID_FORMATS:
        return explicit.lower()
    return "pretty"


# Envelope keys that are *crypto* and never belong on stdout. The
# pretty format suppresses these by name; everything else is fair
# game (modulo ciphertext-object values, see below).
_CRYPTO_KEYS = frozenset(
    {
        "prev_hash",
        "row_hash",
        "signature",
        # ``did`` is the publisher's full DID — shown truncated only.
        "did",
        # Already rendered into the line header.
        "timestamp",
        "level",
        "event_type",
        "sequence",
        "event_id",
    }
)


def _is_group_ciphertext(value: Any) -> bool:
    """True iff a value looks like a group ciphertext block (a dict
    with a ``ciphertext`` key). These are the encrypted payloads;
    they don't belong on stdout."""
    return isinstance(value, dict) and "ciphertext" in value


def _short(s: str, n: int = 12) -> str:
    """Truncate a long identifier (DID, event_id) for compact display."""
    if not s or len(s) <= n:
        return s
    return s[:n] + "…"


def _format_pretty(envelope: dict[str, Any]) -> bytes:
    """Render an envelope as a terse human-readable line.

    Header: ``HH:MM:SS.mmm LEVEL  seq=N  event_type``.

    Trailer: every public envelope field rendered as ``key=value``,
    sorted by key. Crypto fields (signatures, hashes, full DID) and
    group ciphertext blocks are suppressed — those live on disk for
    audit, not on a developer's terminal. ``event_id`` and ``did``
    (when present) are shown truncated as ``id=<short>`` /
    ``did=<short>`` so the operator can correlate without seeing
    the whole opaque string.

    ``level=""`` (severity-less ``tn.log``) renders as ``LOG``.
    Bytes output for parity with the ``json`` format.
    """
    ts = str(envelope.get("timestamp", ""))
    if "T" in ts:
        ts = ts.split("T", 1)[1]
    if ts.endswith("Z"):
        ts = ts[:-1]
    if "." in ts:
        head, frac = ts.split(".", 1)
        ts = f"{head}.{frac[:3]}"
    level = str(envelope.get("level") or "log").upper()
    seq = envelope.get("sequence", "")
    event_type = str(envelope.get("event_type", ""))

    parts = [f"{ts:<12} {level:<5}  seq={seq}  {event_type}"]

    # Truncated correlation identifiers (operator-useful, terminal-safe).
    eid = envelope.get("event_id")
    if isinstance(eid, str) and eid:
        parts.append(f"id={_short(eid, 8)}")
    did = envelope.get("did")
    if isinstance(did, str) and did:
        parts.append(f"did={_short(did, 16)}")

    # Public fields: anything not crypto, not ciphertext-shaped.
    extras: list[str] = []
    for k, v in sorted(envelope.items()):
        if k in _CRYPTO_KEYS:
            continue
        if _is_group_ciphertext(v):
            continue
        extras.append(f"{k}={v!r}")
    if extras:
        parts.append(" ".join(extras))

    line = "  ".join(parts) + "\n"
    return line.encode("utf-8")


class StdoutHandler(SyncHandler):
    """Synchronous handler that writes envelope info to a stream.

    Parameters
    ----------
    name:
        Handler name (used for logging / debug). Defaults to ``"stdout"``.
    stream:
        Binary stream to write to. Defaults to ``sys.stdout.buffer`` so
        output is emitted as bytes. Tests inject ``io.BytesIO()``.
    filter_spec:
        Optional filter (same shape as every other handler). When set,
        non-matching events are dropped.
    format:
        ``"pretty"`` (default) for terse human lines, ``"json"`` for
        the canonical NDJSON envelope. Overridden at emit-time by the
        ``TN_STDOUT_FORMAT`` env var if set.
    """

    def __init__(
        self,
        name: str = "stdout",
        *,
        stream: IO[bytes] | None = None,
        filter_spec: dict[str, Any] | None = None,
        format: str | None = None,
        include_admin: bool | None = None,
    ):
        super().__init__(name, filter_spec)
        # Resolve at emit-time, not import-time, so test capsys redirection
        # (which replaces sys.stdout) is honored even if the handler was
        # constructed before capsys took effect.
        self._stream_override = stream
        self._format_kwarg = format
        # DX review #23: by default ``tn.*`` admin events are filtered
        # out of stdout so the user sees only what they emitted. ``None``
        # means "consult ``TN_STDOUT_INCLUDE_ADMIN``"; ``True`` / ``False``
        # force the behaviour and bypass the env var. Useful when a
        # specific stream + filter combo is wanted programmatically.
        self._include_admin = include_admin

    def resolved_address(self) -> str:
        """Stdout handlers dedup by a single sentinel — every
        StdoutHandler instance writes to the same process stdout
        (or to whatever stream override was injected, in which
        case dedup happens by the override's ``id``)."""
        if self._stream_override is not None:
            return f"<stream:{id(self._stream_override)}>"
        return "<stdout>"

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        # DX review #23: filter ``tn.*`` admin events by default so a
        # fresh ``tn.init()`` + ``tn.info('hello')`` prints one line,
        # not four. ``TN_STDOUT_INCLUDE_ADMIN=1`` (or
        # ``include_admin=True``) restores the previous behaviour for
        # operators who want the protocol bookkeeping on stdout.
        event_type = str(envelope.get("event_type", ""))
        if event_type.startswith("tn."):
            if self._include_admin is True:
                # Explicit per-handler opt-in wins over env.
                pass
            elif self._include_admin is False:
                return
            elif os.environ.get("TN_STDOUT_INCLUDE_ADMIN", "").strip() != "1":
                return
        if self._stream_override is not None:
            stream = self._stream_override
            text_mode = False
        else:
            # capsys-friendly: read sys.stdout fresh on every emit.
            #
            # In an IPython/Jupyter/Databricks kernel ``sys.stdout`` is
            # an ``ipykernel.iostream.OutStream`` whose ``.buffer`` is
            # the underlying file descriptor — writes there bypass the
            # kernel's cell-output capture and end up in the driver log
            # rather than the originating cell. Force text-mode writes
            # through ``sys.stdout`` itself so the kernel sees them.
            if _in_ipython_kernel():
                stream = sys.stdout
                text_mode = True
            elif hasattr(sys.stdout, "buffer"):
                stream = sys.stdout.buffer  # type: ignore[assignment]
                text_mode = False
            else:
                stream = sys.stdout  # type: ignore[assignment]
                text_mode = True
        # Resolve format every emit so mid-process env-var flips are
        # honored — same pattern stdlib logging uses for level checks.
        fmt = _resolve_format(self._format_kwarg)
        if fmt == "json":
            payload = raw_line if raw_line.endswith(b"\n") else raw_line + b"\n"
        else:
            payload = _format_pretty(envelope)
        # 0.4.2a9: handle Windows-console encoding gracefully. On
        # Windows the default cp1252 codec cannot encode many common
        # characters (em-dash, arrows, emoji, CJK, …). A bare
        # `stream.write(text)` raises UnicodeEncodeError on those
        # bytes and would kill the emit. We already decode with
        # `errors="replace"` going from bytes → str; mirror that on
        # the str → console encode step by replacing un-encodable
        # codepoints with `?` rather than raising.
        text_payload = payload.decode("utf-8", errors="replace")
        if text_mode:
            try:
                stream.write(text_payload)  # type: ignore[arg-type]
            except TypeError:
                stream.write(payload)  # type: ignore[arg-type]
            except UnicodeEncodeError:
                # Resort to the stream's own encoding, replacing
                # anything it can't render with a "?". Keeps the log
                # line visible (with lossy chars) instead of taking
                # the whole emit down.
                enc = getattr(stream, "encoding", None) or "ascii"
                stream.write(
                    text_payload.encode(enc, errors="replace").decode(enc)
                )  # type: ignore[arg-type]
        else:
            try:
                stream.write(payload)
            except TypeError:
                # capsys's captured stdout may be text-mode, not bytes-mode
                try:
                    stream.write(text_payload)  # type: ignore[arg-type]
                except UnicodeEncodeError:
                    enc = getattr(stream, "encoding", None) or "ascii"
                    stream.write(
                        text_payload.encode(enc, errors="replace").decode(enc)
                    )  # type: ignore[arg-type]
        try:
            stream.flush()
        except Exception:  # noqa: BLE001 — flush is best-effort; underlying stream may be unflushable in test capture
            pass


def _in_ipython_kernel() -> bool:
    """True iff running inside an IPython kernel (Jupyter, Databricks).

    Conservative detection: only returns True when IPython is importable
    AND ``get_ipython()`` returns a non-None instance. Plain CPython,
    pytest runs, and tn CLI invocations all return False.
    """
    try:
        from IPython import get_ipython  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        return get_ipython() is not None
    except Exception:
        return False
