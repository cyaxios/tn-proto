"""``fs.drop`` handler — write admin-log snapshots to a watched directory.

Per the 2026-04-24 admin log architecture plan §5.2: useful for offline
or air-gap scenarios. The handler subscribes to admin events. On each
emit (after filtering) it composes ``tn.export(out_path, kind=
"admin_log_snapshot")`` and the resulting ``.tnpkg`` is dropped into a
local outbox directory. A peer's ``FsScanHandler`` (or any other
process) picks the file up and absorbs it.

Config shape (tn.yaml)::

    - kind: fs.drop
      out_dir: ./outbox
      on: ["tn.recipient.added", "tn.recipient.revoked"]
      scope: admin
      trigger: on_emit                    # default: on_emit
      filename_template: "snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg"

Defaults:
* ``out_dir`` -> ``<yaml_dir>/.tn/outbox``
* ``trigger`` -> ``on_emit`` (FS dump on every accepted event)
* ``filename_template`` -> ``"snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg"``

The ``on:`` knob is a per-event-type allowlist (an inclusive filter on
top of the ``filter:`` block). When set, only listed event types
trigger a drop. When unset, every admin event (``tn.*``) triggers.

Idempotency: the handler tracks the last-shipped ``head_row_hash`` in
memory and skips writing a duplicate file when nothing has advanced.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import TNHandler

_log = logging.getLogger("tn.handlers.fs_drop")

DEFAULT_FILENAME_TEMPLATE = "snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg"


class FsDropHandler(TNHandler):
    """Drop ``.tnpkg`` admin snapshots into a local watched directory.

    Constructor parameters
    ----------------------

    name
        Handler name.
    out_dir
        Destination directory. Created on demand.
    on
        Optional list of event types to drop on (allowlist). When None,
        every admin event triggers (subject to the ``filter`` block).
    scope
        ``scope`` field passed to ``tn.export``.
    trigger
        ``"on_emit"`` (default) — drop on each accepted emit.
        ``"on_schedule"`` reserved; not implemented yet (would mirror
        ``vault.push`` scheduler).
    filename_template
        Python ``str.format`` template. Available placeholders:

        * ``{ceremony_id}``: the producer ceremony id
        * ``{date}``: ISO timestamp ``YYYYMMDDTHHMMSSZ``
        * ``{head_row_hash}``: full row_hash (or empty string)
        * ``{head_row_hash:short}``: first 12 chars after the
          ``sha256:`` prefix (or first 12 of the raw hash). Falls
          back to "noop" when the snapshot has no head.
        * ``{from_did}``: the writer's DID

    cfg_provider
        Test seam for the active LoadedConfig.
    filter_spec
        Standard handler filter dict.
    """

    def __init__(
        self,
        name: str,
        *,
        out_dir: Path,
        on: list[str] | None = None,
        scope: str = "admin",
        trigger: str = "on_emit",
        filename_template: str = DEFAULT_FILENAME_TEMPLATE,
        cfg_provider: Callable[[], Any] | None = None,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, filter_spec)
        if trigger != "on_emit":
            # Reserved value — keep the API stable for the future.
            raise ValueError(
                f"fs.drop: trigger={trigger!r} not supported yet; only 'on_emit' is implemented."
            )
        self._out_dir = Path(out_dir)
        self._on_types: set[str] | None = set(on) if on else None
        self._scope = scope
        self._trigger = trigger
        self._filename_template = filename_template
        self._cfg_provider = cfg_provider or _default_cfg_provider

        self._last_shipped_head: str | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # TNHandler contract
    # ------------------------------------------------------------------

    def accepts(self, envelope: dict[str, Any]) -> bool:
        if not super().accepts(envelope):
            return False
        et = envelope.get("event_type")
        if not isinstance(et, str) or not et.startswith("tn."):
            return False
        if self._on_types is not None and et not in self._on_types:
            return False
        return True

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        try:
            self._drop_snapshot(envelope)
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.exception("[%s] fs.drop emit failed", self.name)

    # ------------------------------------------------------------------
    # Snapshot writer
    # ------------------------------------------------------------------

    def _drop_snapshot(self, envelope: dict[str, Any]) -> Path | None:
        cfg = self._cfg_provider()
        if cfg is None:
            _log.debug("[%s] fs.drop: no active cfg, skipping", self.name)
            return None

        from ..export import export
        from ..tnpkg import _read_manifest

        self._out_dir.mkdir(parents=True, exist_ok=True)

        # Use a temp filename first; rename only after we know head_row_hash.
        tmp_name = f"snapshot_inflight_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.tnpkg"
        tmp_path = self._out_dir / tmp_name
        try:
            export(tmp_path, kind="admin_log_snapshot", cfg=cfg, scope=self._scope)
        except Exception:
            _log.exception("[%s] fs.drop: export failed", self.name)
            raise

        try:
            manifest, _body = _read_manifest(tmp_path)
        except Exception:
            _log.exception("[%s] fs.drop: failed to read back manifest", self.name)
            tmp_path.unlink(missing_ok=True)
            raise

        head = manifest.head_row_hash
        with self._lock:
            if head and head == self._last_shipped_head:
                tmp_path.unlink(missing_ok=True)
                _log.debug(
                    "[%s] fs.drop: head %s unchanged; skip", self.name, head
                )
                return None

        final_name = self._format_filename(manifest)
        final_path = self._out_dir / final_name
        if final_path.exists():
            # If the templated filename collides (e.g. two events share a
            # head_row_hash), append a microsecond suffix to keep it
            # unique. Idempotent dedupe lives in absorb on the receiver.
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            final_path = final_path.with_name(
                f"{final_path.stem}__{ts}{final_path.suffix}"
            )
        tmp_path.rename(final_path)

        with self._lock:
            self._last_shipped_head = head

        _log.info(
            "[%s] fs.drop: wrote snapshot %s (head=%s, trigger=%s)",
            self.name,
            final_path.name,
            head,
            envelope.get("event_type"),
        )
        return final_path

    def _format_filename(self, manifest: Any) -> str:
        head = manifest.head_row_hash or ""
        head_short = _short_hash(head)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # Manual placeholder substitution because Python's str.format does
        # not support the custom ``:short`` modifier idiom we exposed in
        # the config. Keep it explicit; smaller surface than a custom
        # Formatter subclass.
        out = self._filename_template
        replacements = {
            "{ceremony_id}": manifest.ceremony_id,
            "{date}": ts,
            "{head_row_hash}": head,
            "{head_row_hash:short}": head_short,
            "{from_did}": manifest.from_did,
        }
        for needle, value in replacements.items():
            out = out.replace(needle, str(value))
        return _sanitize_filename(out)


def _short_hash(rh: str) -> str:
    if not rh:
        return "noop"
    if rh.startswith("sha256:"):
        return rh[len("sha256:") : len("sha256:") + 12]
    return rh[:12]


_DISALLOWED = '<>:"/\\|?*'


def _sanitize_filename(name: str) -> str:
    """Strip path separators and other Windows-illegal characters from
    a filename. Defensive — production uses templates that already avoid
    these, but tests sometimes feed colon-bearing DIDs through.
    """
    out = name
    for ch in _DISALLOWED:
        out = out.replace(ch, "_")
    return out


def _default_cfg_provider() -> Any:
    try:
        from .. import current_config

        return current_config()
    except RuntimeError:
        return None


__all__ = ["DEFAULT_FILENAME_TEMPLATE", "FsDropHandler"]
