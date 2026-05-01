"""Stdout handler — write canonical envelope JSON lines to a stream.

Default-on per `tn.init()` so that out-of-the-box `tn.info(...)` lands a
JSON line on stdout, matching the stdlib `logging.basicConfig()` mental
model. Opt-out via the `TN_NO_STDOUT=1` env var or `tn.init(stdout=False)`.

For declarative use the same handler is registered as ``kind: "stdout"``
in :mod:`tn.handlers.registry`, so a yaml ``handlers: [{kind: stdout}]``
list also works.
"""

from __future__ import annotations

import sys
from typing import IO, Any

from .base import SyncHandler


class StdoutHandler(SyncHandler):
    """Synchronous handler that writes the raw envelope JSON line to a stream.

    Parameters
    ----------
    name:
        Handler name (used for logging / debug). Defaults to ``"stdout"``.
    stream:
        Binary stream to write to. Defaults to ``sys.stdout.buffer`` so the
        line is emitted as bytes (matches what the file handler writes to
        disk, byte-for-byte). Tests inject ``io.BytesIO()``.
    filter_spec:
        Optional filter (same shape as every other handler). When set,
        non-matching events are dropped.
    """

    def __init__(
        self,
        name: str = "stdout",
        *,
        stream: IO[bytes] | None = None,
        filter_spec: dict[str, Any] | None = None,
    ):
        super().__init__(name, filter_spec)
        # Resolve at emit-time, not import-time, so test capsys redirection
        # (which replaces sys.stdout) is honored even if the handler was
        # constructed before capsys took effect.
        self._stream_override = stream

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        if self._stream_override is not None:
            stream = self._stream_override
        else:
            # capsys-friendly: read sys.stdout fresh on every emit
            stream = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout  # type: ignore[assignment]
        if not raw_line.endswith(b"\n"):
            raw_line = raw_line + b"\n"
        try:
            stream.write(raw_line)
        except TypeError:
            # capsys's captured stdout may be text-mode, not bytes-mode
            stream.write(raw_line.decode("utf-8", errors="replace"))  # type: ignore[arg-type]
        try:
            stream.flush()
        except Exception:  # noqa: BLE001 — flush is best-effort; underlying stream may be unflushable in test capture
            pass
