"""Runtime dispatch: Rust tn_core for btn-only ceremonies, pure-Python otherwise.

Import-time safe: if the tn_core extension is unavailable, we silently fall back
to the pure-Python implementation (current behavior unchanged).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

try:
    from tn_core import Runtime as _RustRuntime  # PyO3 extension

    _RUST_OK = True
except ImportError:
    _RustRuntime = None
    _RUST_OK = False


def _ceremony_is_btn_only(yaml_path: Path) -> bool:
    """True iff every group in the yaml uses `cipher: btn`."""
    import yaml as _yaml

    try:
        doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, _yaml.YAMLError):
        return False
    if not isinstance(doc, dict):
        return False
    groups = doc.get("groups") or {}
    if not groups:
        return False
    for g in groups.values():
        if not isinstance(g, dict) or g.get("cipher") != "btn":
            return False
    return True


def should_use_rust(yaml_path: Path) -> bool:
    if os.environ.get("TN_FORCE_PYTHON"):
        return False
    return _RUST_OK and _ceremony_is_btn_only(yaml_path)


def _rust_entries_with_valid(entries: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Add `valid` dict to each Rust-produced read entry.

    Signature, row_hash, and chain are all verified here. The Rust
    runtime's decrypt success proves the ciphertext is authentic for the
    holder of the reader kit, but does NOT prove the envelope hasn't been
    tampered with on disk — someone with write access to the log file
    could splice a fake row with a bogus signature. So we re-verify:

      signature : Ed25519 verify over row_hash, against the envelope's DID
      row_hash  : recompute SHA-256 over envelope fields and compare
      chain     : prev_hash matches previous entry's row_hash (per event_type)
    """
    import base64

    from tn.chain import _compute_row_hash
    from tn.signing import DeviceKey, _signature_from_b64

    _reserved = {
        "did",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
    }

    prev_hash_by_event: dict[str, str] = {}
    for entry in entries:
        env = entry["envelope"]
        event_type = env.get("event_type", "")
        prev_hash = env.get("prev_hash", "")
        row_hash = env.get("row_hash", "")
        did = env.get("did", "")
        sig_b64 = env.get("signature", "")

        # Chain linkage ------------------------------------------------
        last = prev_hash_by_event.get(event_type)
        chain_ok = (last is None) or (prev_hash == last)
        prev_hash_by_event[event_type] = row_hash

        # Row hash recompute ------------------------------------------
        public_fields: dict[str, Any] = {}
        groups: dict[str, dict[str, Any]] = {}
        for k, v in env.items():
            if k in _reserved:
                continue
            if isinstance(v, dict) and "ciphertext" in v and "field_hashes" in v:
                groups[k] = {
                    "ciphertext": base64.standard_b64decode(v["ciphertext"]),
                    "field_hashes": dict(v["field_hashes"]),
                }
            else:
                public_fields[k] = v
        try:
            recomputed = _compute_row_hash(
                did=did,
                timestamp=env.get("timestamp", ""),
                event_id=env.get("event_id", ""),
                event_type=event_type,
                level=env.get("level", ""),
                prev_hash=prev_hash,
                public_fields=public_fields,
                groups=groups,
            )
            row_hash_ok = recomputed == row_hash
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            row_hash_ok = False

        # Signature verify --------------------------------------------
        try:
            sig_bytes = _signature_from_b64(sig_b64)
            sig_ok = bool(DeviceKey.verify(did, row_hash.encode("ascii"), sig_bytes))
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            sig_ok = False

        yield {
            "envelope": env,
            "plaintext": entry["plaintext"],
            "valid": {
                "signature": sig_ok,
                "row_hash": row_hash_ok,
                "chain": chain_ok,
            },
        }


class DispatchRuntime:
    """Uniform facade — routes to either Rust or the legacy Python runtime."""

    def __init__(self, yaml_path: Path, _logger_runtime=None):
        """Construct a DispatchRuntime.

        If _logger_runtime is provided it is used as the Python runtime
        directly (avoids a double-init when called from tn/logger.py where
        the TNRuntime has already been built).

        Rust is used for emit only when no Python handlers are registered.
        Handlers require the full sealed envelope at emit time; the Rust
        runtime returns only a receipt (event_id, row_hash, sequence), so
        the Python path is used when handlers are present.
        """
        self._yaml = Path(yaml_path)
        self._py_rt = _logger_runtime  # always kept — used for handlers + config

        # Use Rust iff available AND no user-registered Python handlers need
        # the sealed envelope. The zero-config default file handler is
        # excluded: the Rust runtime writes to the same log file itself, so
        # routing through Python for that handler would double-write.
        user_handlers = (
            [h for h in _logger_runtime.handlers if not getattr(h, "_tn_default", False)]
            if _logger_runtime is not None and hasattr(_logger_runtime, "handlers")
            else []
        )
        self._use_rust = should_use_rust(self._yaml) and not user_handlers
        if self._use_rust:
            self._rt = _RustRuntime.init(str(self._yaml))
        else:
            self._rt = None

    def emit(
        self,
        level: str,
        event_type: str,
        fields: dict[str, Any],
        *,
        sign: bool | None = None,
    ) -> dict[str, Any]:
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            # sign=None → Rust uses ceremony.sign default; True/False overrides.
            return self._rt.emit(level, event_type, fields, None, None, sign)
        if self._py_rt is None:
            raise RuntimeError("DispatchRuntime: Python runtime not set")
        # Python path doesn't support per-call sign override yet (JWE path
        # always signs). The yaml ceremony.sign flag is a Rust-only feature
        # until the legacy logger gains it. Ignore sign on the Python path
        # for now; document in set_signing() docstring.
        return self._py_rt.emit(level, event_type, fields)

    def read(self, log_path=None) -> Iterator[dict[str, Any]]:
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            # If the resolved log path doesn't exist (e.g. a fresh
            # ceremony emitted only admin events that landed in the
            # `.tn/admin/admin.ndjson` file under the new default), the
            # Rust runtime would raise. Short-circuit on the Python side.
            if log_path is None:
                resolved = Path(self._rt.log_path()) if hasattr(self._rt, "log_path") else None
                if resolved is not None and not resolved.exists():
                    return
            elif not Path(log_path).exists():
                return
            # Use read_raw — dispatch's `read()` is the audit-grade
            # `{envelope, plaintext}` shape that ``_rust_entries_with_valid``
            # consumes (and that ``tn.read_raw()`` exposes to callers). The
            # Rust runtime's flat `read()` is for the read-ergonomics path,
            # which goes through ``secure_read`` instead.
            entries = (
                self._rt.read_raw(str(log_path))
                if log_path is not None
                else self._rt.read_raw()
            )
            yield from _rust_entries_with_valid(entries)
            return
        if self._py_rt is None:
            raise RuntimeError("DispatchRuntime: Python runtime not set")
        from tn.reader import read as _legacy_read

        cfg = self._py_rt.cfg
        if log_path is None:
            log_path = cfg.resolve_log_path()
        yield from _legacy_read(log_path, cfg)

    def close(self, *, timeout: float = 30.0) -> None:
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            self._rt.close()
        else:
            if self._py_rt is not None:
                close_fn = getattr(self._py_rt, "flush_and_close", None) or getattr(
                    self._py_rt, "close", None
                )
                if callable(close_fn):
                    try:
                        close_fn(timeout=timeout)
                    except TypeError:
                        close_fn()

    # ------------------------------------------------------------------
    # Admin verbs (Task 39): btn recipient management via Rust path
    # ------------------------------------------------------------------

    def add_recipient_btn(
        self,
        group: str,
        out_path: str,
        recipient_did: str | None = None,
    ) -> int:
        """Mint a new btn reader kit for `group`, write it to `out_path`.

        Returns the leaf index (int) of the newly minted kit.
        Only available when using_rust is True (btn ceremony).

        If `recipient_did` is provided, a `tn.recipient.added` attested event
        is appended to the log so readers can reconstruct the recipient map
        by replay. Leaving it `None` still mints the kit but records no
        recipient identity (useful for test code or bulk pre-mints).
        """
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            return self._rt.add_recipient(group, str(out_path), recipient_did)
        raise NotImplementedError(
            "add_recipient_btn via DispatchRuntime requires the Rust path "
            "(btn ceremony + tn_core extension). For non-btn ceremonies use "
            "tn.admin.issue_key / tn.admin.issue_coupon directly."
        )

    def revoke_recipient_btn(self, group: str, leaf_index: int) -> None:
        """Revoke the btn reader at `leaf_index` in `group`.

        Only available when using_rust is True (btn ceremony).
        """
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            self._rt.revoke_recipient(group, leaf_index)
            return
        raise NotImplementedError(
            "revoke_recipient_btn via DispatchRuntime requires the Rust path."
        )

    def revoked_count_btn(self, group: str) -> int:
        """Return the number of revoked recipients in `group`'s btn state.

        Only available when using_rust is True (btn ceremony).
        """
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            return self._rt.revoked_count(group)
        raise NotImplementedError("revoked_count_btn via DispatchRuntime requires the Rust path.")

    @property
    def using_rust(self) -> bool:
        return self._use_rust
