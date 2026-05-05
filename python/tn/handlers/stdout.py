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


def _format_pretty(envelope: dict[str, Any]) -> bytes:
    """Render an envelope as a terse human-readable line.

    Format: ``HH:MM:SS.mmm LEVEL  seq=N  event_type\\n``.

    ``level=""`` (severity-less ``tn.log``) renders as ``LOG`` to match
    the public verb name. Fields are intentionally absent — they are
    encrypted in the envelope at this layer and recoverable via
    ``tn.read()``. Bytes output (not str) for parity with the
    ``json`` format and the file sinks.
    """
    ts = str(envelope.get("timestamp", ""))
    # Trim "2026-05-05T22:27:23.712506Z" -> "22:27:23.712"
    if "T" in ts:
        ts = ts.split("T", 1)[1]
    if ts.endswith("Z"):
        ts = ts[:-1]
    # Truncate fractional to milliseconds for readability.
    if "." in ts:
        head, frac = ts.split(".", 1)
        ts = f"{head}.{frac[:3]}"
    level = str(envelope.get("level") or "log").upper()
    seq = envelope.get("sequence", "")
    event_type = str(envelope.get("event_type", ""))
    line = f"{ts:<12} {level:<5}  seq={seq}  {event_type}\n"
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
    ):
        super().__init__(name, filter_spec)
        # Resolve at emit-time, not import-time, so test capsys redirection
        # (which replaces sys.stdout) is honored even if the handler was
        # constructed before capsys took effect.
        self._stream_override = stream
        self._format_kwarg = format

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        if self._stream_override is not None:
            stream = self._stream_override
        else:
            # capsys-friendly: read sys.stdout fresh on every emit
            stream = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout  # type: ignore[assignment]
        # Resolve format every emit so mid-process env-var flips are
        # honored — same pattern stdlib logging uses for level checks.
        fmt = _resolve_format(self._format_kwarg)
        if fmt == "json":
            payload = raw_line if raw_line.endswith(b"\n") else raw_line + b"\n"
        else:
            payload = _format_pretty(envelope)
        try:
            stream.write(payload)
        except TypeError:
            # capsys's captured stdout may be text-mode, not bytes-mode
            stream.write(payload.decode("utf-8", errors="replace"))  # type: ignore[arg-type]
        try:
            stream.flush()
        except Exception:  # noqa: BLE001 — flush is best-effort; underlying stream may be unflushable in test capture
            pass
