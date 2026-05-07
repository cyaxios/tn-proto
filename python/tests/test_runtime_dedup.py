"""Tests for the per-emit address dedup in TNRuntime.

Contract (see directory-layout.md):

> Per emit, each unique resolved sink address is written at most
> once. If a handler tries to write an envelope that already landed
> at that address during this emit's fanout, the write is a no-op.

Two-handler scenarios across the file_rotating + stdout sinks
(the two shipping sinks). Every other handler is out of scope
until they implement ``resolved_address()``.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))


class _CountingHandler:
    """Minimal handler stub for runtime-level dedup testing.

    Doesn't subclass TNHandler — we only call into the dedup
    logic via the runtime's fanout loop, which uses ``accepts``,
    ``resolved_address``, and ``emit``.
    """

    def __init__(self, name: str, address: str | None):
        self.name = name
        self._address = address
        self.calls = 0

    def accepts(self, envelope) -> bool:
        return True

    def resolved_address(self) -> str | None:
        return self._address

    def emit(self, envelope, raw_line) -> None:
        self.calls += 1


class TestResolvedAddressOnHandlers:
    def test_file_rotating_address_is_resolved_path(self, tmp_path):
        from tn.handlers.file import FileRotatingHandler

        h = FileRotatingHandler("h1", tmp_path / "log.ndjson")
        # Address is the absolute, resolved path.
        addr = h.resolved_address()
        assert Path(addr).is_absolute()
        assert Path(addr) == (tmp_path / "log.ndjson").resolve()

    def test_two_file_handlers_at_same_path_share_address(self, tmp_path):
        from tn.handlers.file import FileRotatingHandler

        h1 = FileRotatingHandler("a", tmp_path / "shared.ndjson")
        h2 = FileRotatingHandler("b", tmp_path / "shared.ndjson")
        assert h1.resolved_address() == h2.resolved_address()

    def test_two_file_handlers_at_different_paths_have_different_addresses(
        self, tmp_path
    ):
        from tn.handlers.file import FileRotatingHandler

        h1 = FileRotatingHandler("a", tmp_path / "x.ndjson")
        h2 = FileRotatingHandler("b", tmp_path / "y.ndjson")
        assert h1.resolved_address() != h2.resolved_address()

    def test_stdout_sentinel(self):
        from tn.handlers.stdout import StdoutHandler

        h = StdoutHandler("stdout")
        # Default stdout (no override) has the bare sentinel.
        assert h.resolved_address() == "<stdout>"

    def test_stdout_with_override_uses_id(self):
        from tn.handlers.stdout import StdoutHandler

        buf = io.BytesIO()
        h = StdoutHandler("stdout", stream=buf)
        # Override gets a stream-id-keyed sentinel.
        assert h.resolved_address().startswith("<stream:")
        assert str(id(buf)) in h.resolved_address()


class TestRuntimeDedupBehavior:
    """Walk the runtime's emit loop directly with stub handlers to
    verify the dedup contract independent of the rest of the runtime."""

    def _emit_via_loop(self, handlers):
        """Mimic the runtime's emit-side fanout loop (logger.py:344)
        using stub handlers, then return the per-handler call counts."""
        envelope = {"event_id": "e1", "event_type": "x", "level": "info"}
        raw = b'{"event_id":"e1"}\n'
        seen: set[str] = set()
        for h in handlers:
            if not h.accepts(envelope):
                continue
            try:
                addr = h.resolved_address()
            except Exception:
                addr = None
            if addr is not None:
                if addr in seen:
                    continue
                seen.add(addr)
            h.emit(envelope, raw)
        return [h.calls for h in handlers]

    def test_two_handlers_same_address_only_first_writes(self):
        a = _CountingHandler("a", "/tmp/log")
        b = _CountingHandler("b", "/tmp/log")
        counts = self._emit_via_loop([a, b])
        assert counts == [1, 0]

    def test_two_handlers_different_addresses_both_write(self):
        a = _CountingHandler("a", "/tmp/log_a")
        b = _CountingHandler("b", "/tmp/log_b")
        counts = self._emit_via_loop([a, b])
        assert counts == [1, 1]

    def test_three_handlers_two_at_same_address(self):
        a = _CountingHandler("a", "/tmp/x")
        b = _CountingHandler("b", "/tmp/y")
        c = _CountingHandler("c", "/tmp/x")  # dupe of a
        counts = self._emit_via_loop([a, b, c])
        assert counts == [1, 1, 0]

    def test_handler_with_none_address_always_writes(self):
        # None opts out of dedup. Even if another handler has the
        # same conceptual sink, None-address handler always fires.
        a = _CountingHandler("a", "/tmp/x")
        b = _CountingHandler("b", None)
        c = _CountingHandler("c", None)
        d = _CountingHandler("d", "/tmp/x")  # dupe of a
        counts = self._emit_via_loop([a, b, c, d])
        assert counts == [1, 1, 1, 0]

    def test_dedup_resets_per_emit(self):
        # Two emits on the same handler list — each emit's dedup
        # state is independent. Same handlers fire once per emit.
        a = _CountingHandler("a", "/tmp/x")
        b = _CountingHandler("b", "/tmp/x")
        # Emit 1
        self._emit_via_loop([a, b])
        # Emit 2 — pretend we restart the dedup state. The contract
        # is per-emit, so calling _emit_via_loop again resets the
        # set internally.
        self._emit_via_loop([a, b])
        # Each (envelope, address) pair had only one write per emit.
        # ``a`` fires twice (once per emit). ``b`` is deduped both
        # times.
        assert a.calls == 2
        assert b.calls == 0


class TestStdoutBackboneDedup:
    """Functional: when default has stdout and a stream extends
    default, the stream's effective handler set has stdout once
    (because it inherits from default + name-dedup at config-merge).
    Address dedup is a backstop for cases where two stdout handlers
    slipped through with different names."""

    def test_two_stdout_handlers_dedup_to_one_write(self):
        from tn.handlers.stdout import StdoutHandler

        buf = io.BytesIO()
        # Both handlers use the same stream override → same address.
        h1 = StdoutHandler("a", stream=buf)
        h2 = StdoutHandler("b", stream=buf)
        envelope = {
            "event_id": "e1",
            "event_type": "x",
            "level": "info",
            "timestamp": "2026-05-06T00:00:00.000Z",
            "sequence": 1,
        }
        raw = b'{"x":1}\n'
        seen: set[str] = set()
        for h in [h1, h2]:
            addr = h.resolved_address()
            if addr in seen:
                continue
            seen.add(addr)
            h.emit(envelope, raw)
        # Only one write landed in buf.
        text = buf.getvalue().decode("utf-8")
        assert text.count("\n") == 1
