"""``fs.scan`` handler — pick up ``.tnpkg`` files from a watched directory.

Per the 2026-04-24 admin log architecture plan §5.2: polls a local
directory for new ``.tnpkg`` files. Calls ``tn.absorb()`` for each.
Moves processed files to ``<dir>/.processed/`` (or deletes them, if
configured). Bad-signature files are moved to ``<dir>/.rejected/`` so
operators can inspect them without re-processing on every tick.

Config shape (tn.yaml)::

    - kind: fs.scan
      in_dir: ./inbox
      poll_interval: 30s
      on_processed: archive | delete       # default: archive
      archive_dir: ./inbox/.processed      # only when on_processed=archive

The pull side mirrors ``vault.pull`` in spirit but skips the auth
dance — the filesystem is the trust boundary. Concurrency: a single
scheduler thread; ``flush_and_close()`` drains the in-flight tick
cleanly.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .base import TNHandler

_log = logging.getLogger("tn.handlers.fs_scan")

_DEFAULT_POLL_INTERVAL_SEC = 30.0


class FsScanHandler(TNHandler):
    """Poll a directory for ``.tnpkg`` files and absorb them.

    Constructor parameters
    ----------------------

    name
        Handler name.
    in_dir
        Directory to scan for ``.tnpkg`` files. Created on demand.
    poll_interval
        Seconds between scans.
    on_processed
        ``"archive"`` (default) — move to ``archive_dir`` after absorb.
        ``"delete"`` — remove the file. Bad-signature files always
        go to ``<in_dir>/.rejected/`` regardless.
    archive_dir
        Override the archive directory. Default is ``<in_dir>/.processed/``.
    rejected_dir
        Override the rejected directory. Default is ``<in_dir>/.rejected/``.
    cfg_provider
        Test seam for the active LoadedConfig.
    filter_spec
        Standard handler filter dict (unused on the scan path; kept for
        symmetry).
    autostart
        Start scheduler thread immediately. Tests set False.
    """

    def __init__(
        self,
        name: str,
        *,
        in_dir: Path,
        poll_interval: float = _DEFAULT_POLL_INTERVAL_SEC,
        on_processed: str = "archive",
        archive_dir: Path | None = None,
        rejected_dir: Path | None = None,
        cfg_provider: Callable[[], Any] | None = None,
        filter_spec: dict[str, Any] | None = None,
        autostart: bool = True,
    ) -> None:
        super().__init__(name, filter_spec)
        if on_processed not in ("archive", "delete"):
            raise ValueError(
                f"fs.scan: on_processed must be 'archive' or 'delete', got {on_processed!r}"
            )
        self._in_dir = Path(in_dir)
        self._poll_interval = float(poll_interval)
        self._on_processed = on_processed
        self._archive_dir = (
            Path(archive_dir) if archive_dir else self._in_dir / ".processed"
        )
        self._rejected_dir = (
            Path(rejected_dir) if rejected_dir else self._in_dir / ".rejected"
        )
        self._cfg_provider = cfg_provider or _default_cfg_provider

        self._stop_ev = threading.Event()
        self._tick_lock = threading.Lock()
        self._closed = False

        self._scheduler: threading.Thread | None = None
        if autostart:
            self._scheduler = threading.Thread(
                target=self._schedule_loop,
                name=f"tn-fs-scan-{name}",
                daemon=True,
            )
            self._scheduler.start()

    # ------------------------------------------------------------------
    # TNHandler contract
    # ------------------------------------------------------------------

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        return  # scan handlers don't react to local emits

    def close(self, *, timeout: float = 30.0) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_ev.set()
        if self._scheduler is not None:
            self._scheduler.join(timeout=min(timeout, 5.0))
        with self._tick_lock:
            pass

    # ------------------------------------------------------------------
    # Scheduler
    # ------------------------------------------------------------------

    def _schedule_loop(self) -> None:
        try:
            self.tick_once()
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.exception("[%s] fs.scan initial tick failed", self.name)
        while not self._stop_ev.wait(self._poll_interval):
            try:
                self.tick_once()
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception("[%s] fs.scan tick failed", self.name)

    def tick_once(self) -> int:
        """Run one scan/absorb cycle. Returns the count of newly absorbed
        snapshots. Public so tests can drive it deterministically."""
        with self._tick_lock:
            return self._tick_locked()

    def _tick_locked(self) -> int:
        cfg = self._cfg_provider()
        if cfg is None:
            _log.debug("[%s] fs.scan: no active cfg, skipping", self.name)
            return 0

        if not self._in_dir.exists():
            return 0

        from ..absorb import absorb as _absorb

        absorbed = 0
        # Sort so processing order is deterministic — useful for tests
        # and reasoning about cursor advance order.
        for entry in sorted(self._in_dir.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix != ".tnpkg":
                continue
            try:
                receipt = _absorb(cfg, entry)
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception(
                    "[%s] fs.scan: absorb crashed for %s", self.name, entry.name
                )
                self._move_to(entry, self._rejected_dir)
                continue
            status = getattr(receipt, "status", None) or getattr(
                receipt, "legacy_status", ""
            )
            if status == "rejected":
                _log.warning(
                    "[%s] fs.scan: rejecting %s — %s",
                    self.name,
                    entry.name,
                    getattr(receipt, "reason", ""),
                )
                self._move_to(entry, self._rejected_dir)
                continue
            absorbed += 1
            self._dispose(entry)
        return absorbed

    # ------------------------------------------------------------------
    # File move helpers
    # ------------------------------------------------------------------

    def _dispose(self, path: Path) -> None:
        if self._on_processed == "delete":
            try:
                path.unlink()
            except OSError:
                _log.exception("[%s] fs.scan: failed to delete %s", self.name, path)
            return
        self._move_to(path, self._archive_dir)

    def _move_to(self, path: Path, dest_dir: Path) -> None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / path.name
        if target.exists():
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            target = target.with_name(f"{target.stem}__{ts}{target.suffix}")
        try:
            path.rename(target)
        except OSError:
            _log.exception(
                "[%s] fs.scan: failed to move %s -> %s", self.name, path, target
            )


def _default_cfg_provider() -> Any:
    try:
        from .. import current_config

        return current_config()
    except RuntimeError:
        return None


__all__ = ["FsScanHandler"]
