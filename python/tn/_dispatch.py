"""Runtime dispatch: Rust tn_core for btn-only ceremonies, pure-Python otherwise.

Import-time safe: if the tn_core extension is unavailable, we silently fall back
to the pure-Python implementation (current behavior unchanged).
"""

from __future__ import annotations

import json
import logging
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
    import warnings

    warnings.warn(
        "tn_core extension not found. The pure-Python runtime fallback is "
        "deprecated and will be removed in tn-protocol 0.5.0. "
        "Install tn-core: pip install tn-core (or `pip install tn-protocol` "
        "which now requires it).",
        DeprecationWarning,
        stacklevel=2,
    )

_log = logging.getLogger("tn._dispatch")


def _ceremony_is_btn_only(yaml_path: Path) -> bool:
    """True iff every group in the yaml uses ``cipher: btn``.

    Resolves ``extends:`` first so streams that inherit groups from
    a parent yaml are correctly detected as btn-only based on the
    parent's groups.
    """
    from . import config as _config

    try:
        doc = _config._read_yaml_doc(yaml_path)
    except (OSError, ValueError):
        return False
    try:
        doc = _config._resolve_extends(yaml_path, doc)
    except ValueError:
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


def _logs_path_is_templated(yaml_path: Path) -> bool:
    """True iff the ceremony's ``logs.path`` contains template tokens.

    The Rust runtime opens a single log file at init; per-event-type
    fan-out via templated paths is currently Python-only. When a
    ceremony asks for templated routing, we route emit/read through
    the Python path so the feature works without breaking the Rust
    acceleration for non-templated ceremonies.

    A follow-up issue tracks adding a writer pool to the Rust runtime
    so this check can be dropped.
    """
    from . import config as _config

    try:
        doc = _config._read_yaml_doc(yaml_path)
    except (OSError, ValueError):
        return False
    try:
        doc = _config._resolve_extends(yaml_path, doc)
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    logs = doc.get("logs") or {}
    path = logs.get("path") if isinstance(logs, dict) else None
    return isinstance(path, str) and "{" in path


def should_use_rust(yaml_path: Path) -> bool:
    if os.environ.get("TN_FORCE_PYTHON"):
        return False
    if not _RUST_OK:
        import warnings

        warnings.warn(
            f"Ceremony {yaml_path}: falling back to pure-Python runtime "
            "because tn_core is not installed. This fallback is deprecated; "
            "install tn_core to remove this warning. See tn-protocol 0.5.0 "
            "release notes for details.",
            DeprecationWarning,
            stacklevel=3,
        )
        return False
    if not _ceremony_is_btn_only(yaml_path):
        return False
    # Templated main-log paths route per-envelope to N files. The Rust
    # runtime doesn't support that yet (it opens one log file at init),
    # so a templated ceremony runs through the Python emit path. See
    # _logs_path_is_templated for the rationale.
    if _logs_path_is_templated(yaml_path):
        return False
    return True


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

        Rust is used for emit on every btn-only ceremony when the tn_core
        extension is available — even when the operator has registered
        custom Python handlers (kafka, S3, vault.sync, etc.). The Rust
        runtime hands back the canonical envelope NDJSON line on each
        emit so this dispatcher can fan out to those Python handlers
        after the Rust path has already written, signed, and chained the
        entry.

        During the post-Rust Python fan-out, handlers whose write target
        Rust has already covered are skipped to prevent double-writes /
        double-stdout. See ``_fan_out_python_handlers`` for the precise
        rule (path-equality for file handlers, class-match for stdout).
        """
        self._yaml = Path(yaml_path)
        self._py_rt = _logger_runtime  # always kept — used for handlers + config

        self._use_rust = should_use_rust(self._yaml)
        if self._use_rust:
            # The Rust runtime reads yaml directly and doesn't know
            # about ``extends:``. If the source yaml uses extends,
            # resolve it in Python and hand the resolved view to Rust
            # via a sibling ``.resolved.yaml`` file. The source stays
            # minimal; the resolved file is regenerated on every
            # init so it can't drift.
            self._rt = _RustRuntime.init(str(self._yaml_for_rust()))
        else:
            self._rt = None

    def reload(self) -> None:
        """Re-init the Rust runtime against the current yaml on disk.

        DX review #8: ``tn.admin.ensure_group`` mutates the yaml at
        runtime to add a new group. The Rust runtime caches its view
        of groups + routing at init time, so without an explicit
        reload, post-ensure_group emits would route only through the
        groups the runtime saw originally. This method re-reads the
        yaml (resolving ``extends`` if present) and rebinds
        ``self._rt`` so subsequent emits see the new group.

        Cheap to call: the Rust runtime's init path loads existing
        keystore material (does NOT mint fresh keys when the yaml's
        ceremony already exists on disk). Pre-existing chain state
        is preserved.
        """
        if not self._use_rust:
            return
        self._rt = _RustRuntime.init(str(self._yaml_for_rust()))

    def _yaml_for_rust(self) -> Path:
        """Return a yaml path the Rust runtime can load.

        For sources without ``extends:``, returns the source path
        unchanged. For sources with extends, resolves the chain in
        Python and writes the merged doc to a sibling
        ``.resolved.yaml`` file, returning that path.
        """
        from . import config as _config
        import yaml as _yaml

        try:
            doc = _config._read_yaml_doc(self._yaml)
        except (OSError, ValueError):
            return self._yaml
        if not doc.get("extends"):
            return self._yaml
        try:
            resolved = _config._resolve_extends(self._yaml, doc)
        except ValueError:
            return self._yaml
        # Drop the ``extends`` marker — Rust doesn't need it and
        # would not recognize it.
        resolved.pop("extends", None)
        out_path = self._yaml.parent / ".resolved.yaml"
        try:
            with out_path.open("w", encoding="utf-8") as fh:
                _yaml.safe_dump(resolved, fh, sort_keys=False)
        except OSError:
            return self._yaml
        return out_path

    def emit(
        self,
        level: str,
        event_type: str,
        fields: dict[str, Any],
        *,
        sign: bool | None = None,
    ) -> None:
        if self._use_rust:
            if self._rt is None:
                raise RuntimeError("DispatchRuntime: Rust runtime not initialized")
            # sign=None → Rust uses ceremony.sign default; True/False overrides.
            # Returns the canonical NDJSON line as bytes (or None if filtered
            # by Rust's level threshold).
            raw_line = self._rt.emit(level, event_type, fields, None, None, sign)
            if raw_line is not None:
                self._fan_out_python_handlers(raw_line)
            return None
        if self._py_rt is None:
            raise RuntimeError("DispatchRuntime: Python runtime not set")
        # Python path doesn't support per-call sign override yet (JWE path
        # always signs). The yaml ceremony.sign flag is a Rust-only feature
        # until the legacy logger gains it. Ignore sign on the Python path
        # for now; document in set_signing() docstring.
        return self._py_rt.emit(level, event_type, fields)

    def _fan_out_python_handlers(self, raw_line: bytes) -> None:
        """Run user-registered Python handlers on a Rust-produced envelope.

        Mirrors Rust's ``fan_out_to_handlers`` behaviour: per-handler
        ``accepts()`` filter, errors logged + swallowed so a downstream
        handler issue never aborts a publish that is already on disk.

        Skips handlers whose target Rust has already covered:

          * Any ``StdoutHandler``-class instance — Rust's
            ``Runtime::init`` auto-registers its own native
            ``StdoutHandler`` (gated on ``TN_NO_STDOUT`` and
            yaml-silences-stdout) that writes to fd 1 directly. Running
            the Python copy would print every envelope twice. Python's
            registry / auto-add only puts a ``StdoutHandler`` in the
            handler list under the same conditions Rust does, so the
            two are in lockstep — unconditionally skip on the Python
            side when the Rust path is active.
          * Any file handler whose ``path`` resolves to the same file
            Rust's internal ``log_writer`` is appending to (i.e.
            ``cfg.logs.path``). Running the Python copy would
            double-write that file. Other file handlers — including a
            second ``file.rotating`` at a different path, or
            ``file.timed_rotating`` for an audit split — run as
            expected.

        Everything else (kafka, S3, vault.sync, fs.drop, etc.) runs.
        """
        if self._py_rt is None or not getattr(self._py_rt, "handlers", None):
            return
        # Snapshot handlers so a handler that re-enters emit doesn't
        # observe a half-mutated list mid-iteration.
        handlers = list(self._py_rt.handlers)

        # Compute what Rust covers exactly once per emit. The PyO3
        # ``log_path()`` returns the resolved string path; we re-resolve
        # to normalise drive-letter case + separators on Windows so the
        # path-equality check below is robust.
        rust_log_path: Path | None = None
        if self._rt is not None:
            try:
                rust_log_path = Path(self._rt.log_path()).resolve()
            except Exception:  # noqa: BLE001 — best-effort; older bindings may lack log_path
                rust_log_path = None

        envelope: dict[str, Any] | None = None
        # Lazy import to avoid a circular dependency with tn.handlers.*.
        from tn.handlers.stdout import StdoutHandler as _StdoutHandler  # noqa: PLC0415

        # IPython/Jupyter/Databricks capture sys.stdout at the Python
        # object level. Rust's native StdoutHandler writes to fd 1
        # directly, which bypasses that capture — emits never land in
        # cell output, only get flushed to the kernel's underlying
        # stdout (visible in the driver log, not the notebook).
        #
        # When a kernel is detected we DO NOT skip Python's
        # StdoutHandler: it writes through sys.stdout (text mode, see
        # handlers/stdout.py) which the kernel captures and renders in
        # the originating cell. The Rust handler's fd-1 writes still
        # happen but are invisible to the user — no perceived double-print.
        from . import _in_ipython as _detect_ipython  # noqa: PLC0415
        _stdout_in_notebook = _detect_ipython()

        for h in handlers:
            # Skip Python's StdoutHandler — Rust's native one already wrote.
            # Exception: in a notebook kernel, run the Python handler so
            # emits land in cell output (see comment above).
            if isinstance(h, _StdoutHandler) and not _stdout_in_notebook:
                continue

            # Skip file handler whose path matches Rust's log_writer target.
            h_path = getattr(h, "path", None)
            if h_path is not None and rust_log_path is not None:
                try:
                    if Path(h_path).resolve() == rust_log_path:
                        continue
                except (OSError, ValueError):
                    pass

            if envelope is None:
                # Lazy-parse: only pay the JSON-load cost when at least
                # one user handler is going to look at the envelope.
                try:
                    envelope = json.loads(raw_line)
                except (ValueError, TypeError) as e:
                    _log.warning(
                        "DispatchRuntime: failed to parse Rust-produced "
                        "envelope line for fan-out: %s; skipping handlers.",
                        e,
                    )
                    return
            try:
                if not h.accepts(envelope):
                    continue
                h.emit(envelope, raw_line)
            except Exception:  # noqa: BLE001 — swallow per handler-fanout contract
                _log.exception(
                    "DispatchRuntime: handler %r raised during fan-out; swallowed.",
                    getattr(h, "name", type(h).__name__),
                )

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
