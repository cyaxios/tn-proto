"""tn-protocol: TN protocol Python SDK.

Public API:
    tn.init(yaml_path)          # load or create ceremony + open log file
    tn.debug/info/warning/error # emit attested log entries
    tn.set_context(**kwargs)    # per-request context (PRD §13)
    tn.update_context / clear_context / get_context
    tn.read(log_path, cfg)      # iterate + decrypt entries (flat dicts;
                                # raw=True for the {envelope, plaintext,
                                # valid} audit shape)

Ciphers: "jwe" (pure-Python static-ECDH + AES-KW + AES-GCM) and "btn"
(NNL subset-difference broadcast, via the Rust tn_core extension).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from . import _agents_policy, _autoinit, classifier, identity, sealing, vault_client, wallet
from ._agents_policy import PolicyDocument, PolicyTemplate
from ._autoinit import set_strict
from ._dispatch import (  # should_use_rust re-exported for diagnostics
    DispatchRuntime,
    should_use_rust,
)
from ._entry import Audit, Entry, VerifyError
from .absorb import AbsorbReceipt, AbsorbResult, LeafReuseAttempt
from .absorb import absorb as _raw_absorb
from .admin import (
    ensure_group,
    set_link_state,
)
from . import admin  # noqa: F401
from . import pkg  # noqa: F401
from . import vault  # noqa: F401
from .admin.cache import (
    AdminStateCache,
    ChainConflict,
    RotationConflict,
    SameCoordinateFork,
)
from .admin.cache import LeafReuseAttempt as CacheLeafReuseAttempt  # noqa: F401
from .compile import compile_enrolment
from .context import (
    clear_context,
    get_context,
    scope,
    set_context,
    update_context,
)
from .export import export as _raw_export
from .offer import offer
from .reader import read_all as _raw_read_all
from .reader import read_as_recipient as _raw_read_as_recipient
from .reconcile import _reconcile

# --------------------------------------------------------------------------
# Module-level dispatch runtime — set by tn.init(), cleared by flush_and_close()
# --------------------------------------------------------------------------

_logger = logging.getLogger("tn")
# Dedicated diagnostic surface logger. We emit at INFO so a developer can
# trace every public entry-point with `--log-cli-level=INFO` (pytest) or
# `logging.getLogger("tn.surface").setLevel(logging.INFO)`. Off-by-default
# at the root logger so libraries don't spam users; on-demand visibility
# is what we want.
_surface = logging.getLogger("tn.surface")

# `TN_SURFACE_LOG=<path>` writes every public-surface ENTER/EXIT to the
# given file, bypassing pytest's log-capture quirks and the root logger
# config. Useful for diagnosing test-ordering bugs in the bulk pytest
# run where stdout/stderr are captured per test.
#
# Default fallback: when the env var is unset we still tee to a process-
# scoped file under TEMP so a developer running pytest casually sees the
# trace. Path is printed to stderr at module import.
import os as _os_for_surface
import tempfile as _tempfile_for_surface
_surface_log_path = (
    _os_for_surface.environ.get("TN_SURFACE_LOG")
    or str(_os_for_surface.path.join(
        _tempfile_for_surface.gettempdir(),
        f"tn_surface_pid{_os_for_surface.getpid()}.log",
    ))
)
try:
    _surface_fh = logging.FileHandler(_surface_log_path, encoding="utf-8", delay=False)
    _surface_fh.setFormatter(
        logging.Formatter("%(asctime)s [pid=%(process)d] %(name)s | %(message)s")
    )
    _surface.addHandler(_surface_fh)
    _surface.setLevel(logging.INFO)
    _surface.propagate = False  # don't double-emit through root
    _surface.info(
        "=== tn module imported, surface log opened at %s (pid=%d) ===",
        _surface_log_path, _os_for_surface.getpid(),
    )
except Exception:
    # Best-effort: never let logging bootstrap failure break import.
    pass

_dispatch_rt: DispatchRuntime | None = None

# Lock around the _dispatch_rt swap during init() / flush_and_close().
# Without this, two threads both calling tn.init() on a fresh process can
# both pass the `_dispatch_rt is None` check and race to construct two
# runtimes for the same yaml. Plain Lock (not RLock) — init() itself does
# not recurse into init(). See Workstream D7.
_init_lock = threading.Lock()

# Per-process run identifier — minted once at first init, embedded as a
# public ``run_id`` field on every emit. Lets ``tn.read()`` filter to
# "this process's events only" by default, so naive filters don't pull
# in entries from prior runs (FINDINGS.md #12).
_run_id: str | None = None

# Module-level lazy LKV cache singleton — created on first call to
# ``tn.cached_admin_state()`` / ``tn.cached_recipients()``. Bound to the
# ``LoadedConfig`` active at that moment; reset on ``flush_and_close()``
# so a re-init re-creates it. See plan section 4.
_cached_admin_state: AdminStateCache | None = None

# Module-level ``tn.agents`` policy document for the active ceremony.
# Populated by ``tn.init()`` after loading ``.tn/config/agents.md``;
# cleared by ``flush_and_close()``. ``None`` means "no policy file present"
# — the splice path no-ops.
_agent_policy_doc: PolicyDocument | None = None

# Note on _sign_override (defined later): a single-attribute read on each
# emit. Python's GIL makes the load atomic, and the operation is "newest
# winner" by design — adding a lock is overkill for a session-level toggle.


def _init_impl(
    yaml_path=None,
    *,
    log_path=None,
    pool_size: int = 4,
    cipher: str = "btn",
    identity=None,
    extra_handlers=None,
    stdout: bool | None = None,
) -> None:
    """Initialize TN for this process.

    ``yaml_path`` is optional. With no argument, ``tn.init()`` walks the
    same discovery chain that auto-init uses:

      1. ``$TN_YAML`` env var
      2. ``./tn.yaml`` in the current working directory
      3. ``$TN_HOME/tn.yaml`` (default ``~/.tn/tn.yaml``)
      4. None of the above → mint a fresh ceremony at ``$TN_HOME``

    With an explicit path, that path is used verbatim and the discovery
    chain is skipped. ``TN_STRICT=1`` blocks the no-arg form (raises
    ``RuntimeError``) so production callers can't accidentally land on
    the auto-discovery path.

    If the ceremony uses cipher: btn on every group AND the tn_core Rust
    extension is available AND TN_FORCE_PYTHON is not set, emit/read are
    transparently routed through the Rust runtime. All other public symbols
    (current_config, admin verbs, read_as_recipient, etc.) remain on the
    Python path.

    All kwargs are forwarded to the underlying logger.init() so existing
    call sites continue to work without changes.
    """
    global _dispatch_rt, _run_id

    _surface.info(
        "tn.init() ENTER yaml_path=%r cipher=%r identity=%r log_path=%r "
        "stdout=%r prior_dispatch=%s prior_run_id=%s pid=%s",
        yaml_path, cipher, identity, log_path, stdout,
        "set" if _dispatch_rt is not None else "None",
        _run_id,
        __import__("os").getpid(),
    )

    if yaml_path is None:
        from ._autoinit import _resolve_discovery_yaml

        resolved = _resolve_discovery_yaml()
        if resolved is None:
            raise RuntimeError(
                "tn.init(): TN_STRICT=1 disables ceremony auto-discovery. "
                "Pass an explicit yaml_path or unset TN_STRICT."
            )
        yaml_path, _was_created = resolved

    # Mint a run_id once per process. Auto-injected on every emit so
    # tn.read() can default-filter to "this run only" (FINDINGS.md #12).
    # Shared with the Rust runtime via $TN_RUN_ID so both code paths
    # stamp the SAME run_id on entries — otherwise the read filter
    # would silently drop everything emitted via the Rust path.
    #
    # We always mint fresh and overwrite the env var: a child process
    # that inherits a stale TN_RUN_ID from its parent must NOT silently
    # join the parent's "current run", or the student's "fresh" hello.py
    # picks up entries from the prior shell session and reports them
    # as if they belonged to this run.
    if _run_id is None:
        import os as _os
        import uuid as _uuid
        _run_id = _uuid.uuid4().hex
        _os.environ["TN_RUN_ID"] = _run_id

    # Serialize init() across threads so two callers on a fresh process
    # don't both build their own runtime (and then leak one). The second
    # caller waits, sees the now-bound _dispatch_rt, and short-circuits
    # via logger.init's own _runtime swap (which also re-uses the same
    # _runtime_lock). See Workstream D7.
    with _init_lock:
        # Always call logger.init() first — it handles:
        #   - fresh ceremony creation (keystore, yaml)
        #   - absorb + _reconcile of inbox packages
        #   - building the Python TNRuntime (cfg, handlers, chain)
        from .logger import init as _logger_init

        _logger_init(
            yaml_path,
            log_path=log_path,
            pool_size=pool_size,
            cipher=cipher,
            identity=identity,
            extra_handlers=extra_handlers,
            stdout=stdout,
        )

        # After logger.init() completes, read back the singleton it created.
        from . import logger as _lg

        py_rt = _lg._runtime  # TNRuntime instance

        yaml_p = Path(yaml_path).resolve()

        if should_use_rust(yaml_p) and py_rt is not None:
            # Build the Rust-backed dispatch runtime; pass the Python TNRuntime
            # so close() / current_config() can still reach Python-side state.
            _dispatch_rt = DispatchRuntime(yaml_p, _logger_runtime=py_rt)
        else:
            _dispatch_rt = DispatchRuntime(yaml_p, _logger_runtime=py_rt)

    # Honor an optional yaml ``ceremony.log_level`` so operators can
    # bake the threshold into the ceremony config rather than calling
    # ``tn.set_level()`` programmatically. The kwarg/programmatic API
    # takes precedence — once you've explicitly set a level via
    # ``tn.set_level()`` it stays put across re-inits in the same
    # process. Yaml is for the "fresh process picks up the right
    # default" case (AVL J3.2 ergonomic).
    if py_rt is not None:
        try:
            yaml_level = _yaml_log_level(py_rt)
            if yaml_level is not None and _session._log_level_threshold == 10:
                # Threshold still at the floor default — apply yaml.
                set_level(yaml_level)
        except Exception:
            _logger.exception("yaml ceremony.log_level apply failed; continuing")

    # Emit tn.group.added for every configured group that has no prior
    # group.added event in the log. Rust's Runtime::init already fires
    # tn.ceremony.init at fresh-create; Python's create_fresh mints the
    # default group (and ensure_group creates others) without emitting,
    # so without this their existence is invisible to the attested log.
    # Guard is log-based (idempotent): if the group's added event is
    # already there, skip. Runs once per ceremony per group on the
    # first init that lands on that state.
    if py_rt is not None:
        try:
            _emit_missing_group_added(py_rt)
        except Exception:
            # Best-effort post-init bootstrap; never block init.
            _logger.exception("_emit_missing_group_added failed; continuing")

    # Load ``.tn/config/agents.md`` if it exists; cache the parsed
    # PolicyDocument on the module so the emit-side splice can read it
    # without touching disk every call. Then check for a policy-content
    # change vs the last ``tn.agents.policy_published`` admin event and
    # emit a fresh one if the hash differs (or the event is missing).
    global _agent_policy_doc
    _agent_policy_doc = None
    if py_rt is not None:
        try:
            _agent_policy_doc = _agents_policy.load_policy_file(yaml_p.parent)
        except ValueError:
            # Malformed policy: re-raise so the init clearly fails. Caller
            # should fix or remove the file.
            raise
        except OSError:
            _logger.exception("agents policy load failed; continuing without")
            _agent_policy_doc = None
        try:
            _maybe_emit_policy_published(py_rt, _agent_policy_doc)
        except Exception:
            _logger.exception("tn.agents.policy_published emit failed; continuing")


def _iter_log_files(cfg) -> list:
    """Return every ndjson file where attested events for this ceremony
    could live: the main log plus every protocol_events_location (PEL)
    file materialized so far.

    Splitting tn.* events into a dedicated file is supported via the
    `ceremony.protocol_events_location` yaml setting (see config.py).
    Any reconciliation pass that only reads the main log would miss
    events written there and re-emit them forever. Anything that wants
    to know "did this event already land" should iterate this helper.
    """
    paths: list[Path] = []
    main = cfg.resolve_log_path()
    if main.exists():
        paths.append(main)
    pel = getattr(cfg, "protocol_events_location", "main_log")
    if pel and pel != "main_log":
        yaml_dir = cfg.yaml_path.parent
        # The template may contain {event_type}. List every file that
        # exists under the non-template prefix directory.
        base = pel.split("{", 1)[0]
        if base.startswith("./"):
            base = base[2:]
        base_path = yaml_dir / base
        # base_path might be a directory prefix ("./logs/admin/") or a
        # single file ("./logs/events.ndjson"). Either way, glob the
        # parent directory — an earlier branch on `"{" in pel` was a
        # no-op (both branches picked the parent) and has been collapsed.
        parent = base_path.parent
        if parent.exists():
            # Anything that looks like an ndjson file the PEL template
            # could have written. Keep the globbing loose; the scan is
            # defensive.
            for p in parent.rglob("*.ndjson"):
                if p not in paths:
                    paths.append(p)
    return paths


def _scan_attested_events(cfg, event_type: str, *, key: str = "group") -> set:
    """Walk every log file associated with `cfg` and return the set of
    values found at `envelope[key]` for envelopes whose `event_type`
    matches. Covers both the main log and every PEL file (see
    `_iter_log_files`). Used by the various _emit_missing_* helpers so
    init stays idempotent across split-log setups.

    `key` defaults to "group" for the common case (group.added). Pass
    e.g. `"recipient_did"` or a tuple-producing key.
    """
    import json as _json

    seen: set = set()
    for path in _iter_log_files(cfg):
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        env = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if env.get("event_type") != event_type:
                        continue
                    val = env.get(key)
                    if val is not None:
                        seen.add(val)
        except OSError:
            continue
    return seen


def _emit_missing_group_added(py_rt):
    """Scan every log (main + PEL) for tn.group.added events and emit
    one for any configured group that doesn't yet have an attestation.
    Idempotent."""
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    cfg = py_rt.cfg
    seen = _scan_attested_events(cfg, "tn.group.added", key="group")
    configured = list(cfg.groups.keys())
    if not configured:
        return
    rt = _require_dispatch()
    for group_name in configured:
        if group_name in seen:
            continue
        try:
            rt.emit(
                "info",
                "tn.group.added",
                {
                    "group": group_name,
                    "cipher": cfg.cipher_name,
                    "publisher_did": cfg.device.did,
                    "added_at": _dt.now(_tz.utc).isoformat(),
                },
            )
        except Exception:
            # Dashboard surfaces the gap if it matters.
            _logger.exception(
                "tn.group.added emit failed for group=%r; continuing", group_name
            )


def _splice_agent_policy(event_type: str, fields: dict[str, Any]) -> None:
    """Emit-side splice per spec §2.6.

    Looks up ``event_type`` in the cached policy doc; if a template exists,
    fills the six tn.agents fields via ``setdefault`` so per-emit overrides
    still win. The yaml-declared ``tn.agents`` group routes those six
    field names automatically — this just populates them.
    """
    doc = _agent_policy_doc
    if doc is None:
        return
    template = doc.templates.get(event_type)
    if template is None:
        return
    fields.setdefault("instruction", template.instruction)
    fields.setdefault("use_for", template.use_for)
    fields.setdefault("do_not_use_for", template.do_not_use_for)
    fields.setdefault("consequences", template.consequences)
    fields.setdefault("on_violation_or_error", template.on_violation_or_error)
    fields.setdefault(
        "policy",
        f"{template.path}#{template.event_type}@{template.version}#{template.content_hash}",
    )


def _last_policy_published_hash(cfg) -> str | None:
    """Return the ``content_hash`` of the most recent
    ``tn.agents.policy_published`` event in the local logs, or ``None``
    if no such event exists. Walks both main and admin logs.
    """
    import json as _json

    last_hash: str | None = None
    last_ts: str = ""
    for path in _iter_log_files(cfg):
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        env = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if env.get("event_type") != "tn.agents.policy_published":
                        continue
                    ts = str(env.get("timestamp") or "")
                    h = env.get("content_hash")
                    if h is None:
                        # tn.agents group payload may carry the hash if it
                        # got routed there; fall back to the public field.
                        continue
                    if ts >= last_ts:
                        last_ts = ts
                        last_hash = str(h)
        except OSError:
            continue
    return last_hash


def _maybe_emit_policy_published(py_rt, doc: PolicyDocument | None) -> None:
    """Emit ``tn.agents.policy_published`` iff the active policy file's
    content_hash differs from the last published one in the log (or the
    file is freshly present and no prior event exists). No-op when the
    file is absent.
    """
    if doc is None:
        return
    cfg = py_rt.cfg
    last_hash = _last_policy_published_hash(cfg)
    if last_hash == doc.content_hash:
        return  # already published this version
    rt = _require_dispatch()
    rt.emit(
        "info",
        "tn.agents.policy_published",
        {
            "policy_uri": doc.path,
            "version": doc.version,
            "content_hash": doc.content_hash,
            "event_types_covered": sorted(doc.templates.keys()),
            "policy_text": doc.body,
        },
    )


def _maybe_autoinit() -> None:
    """Discover or auto-create a ceremony if no explicit init has run.

    Cheap no-op once a runtime is bound. See ``tn/_autoinit.py`` for the
    discovery chain and the loud-notice contract.

    Used by EMIT paths (log/info/warning/error/debug) — they're allowed
    to mint a fresh ceremony when nothing is found, because the user is
    actively trying to record something.
    """
    if _dispatch_rt is not None:
        return
    _autoinit.maybe_autoinit()


def _maybe_autoinit_load_only() -> None:
    """Discover an EXISTING ceremony and bind it. Never mints fresh.

    Used by READ paths (read/read_raw/read_all/secure_read/read_as_recipient)
    and ADMIN verbs (add_recipient/revoke/admin_*/recipients/rotate/etc.).
    These need an existing ceremony to be meaningful — silently minting
    one would be a footgun. Raises ``RuntimeError`` with a friendly hint
    if no ceremony is found.
    """
    if _dispatch_rt is not None:
        return
    _autoinit.maybe_autoinit_load_only()


def _require_dispatch() -> DispatchRuntime:
    if _dispatch_rt is None:
        raise RuntimeError("tn.init(yaml_path) must be called before tn.log")
    return _dispatch_rt


# --------------------------------------------------------------------------
# Logging verbs — routed through DispatchRuntime
# --------------------------------------------------------------------------

# Session-level toggles + global state — implemented in tn/_session.py.
# `_log_level_threshold`, `_sign_override`, `_resolve_sign`, plus the public
# verbs (set_signing/set_level/get_level/is_enabled_for) all live there.
# Re-exported below the function bodies so existing call sites keep working.


def _coerce_for_wire(value: Any) -> Any:
    """Coerce values to a wire-safe shape before they cross the Python →
    Rust PyO3 boundary (or land in a json.dumps that doesn't have a
    ``default=`` callback).

    Currently:
    - ``Decimal`` → ``str`` (preserves precision; reader gets the
      string back and parses to Decimal as needed). Rust receives a
      string field rather than a float-coerced Decimal.

    Recurses into ``list``, ``tuple``, and ``dict`` so nested Decimals
    are handled too.
    """
    from decimal import Decimal as _Decimal
    if isinstance(value, _Decimal):
        if not value.is_finite():
            raise ValueError("Decimal NaN/Infinity not supported on the wire")
        return str(value)
    if isinstance(value, dict):
        return {k: _coerce_for_wire(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_coerce_for_wire(v) for v in value]
    return value


def _emit_with_splice(level: str, event_type: str, fields: dict[str, Any], sign: bool | None) -> dict[str, Any]:
    """Build the merged-fields dict, splice ``tn.agents`` policy text if
    a template applies, then dispatch the emit.

    Auto-injects ``run_id`` (a per-process UUID minted at first init) as
    a public field unless the caller already supplied one. Lets
    ``tn.read()`` default-filter to "this run only" so naive filters
    don't pull in entries from prior runs (FINDINGS.md #12).

    Coerces Decimal values to strings before dispatch so they survive
    the PyO3 boundary and the canonical hash with full precision
    (FINDINGS.md #9, #10, #13).
    """
    merged: dict[str, Any] = {**get_context(), **fields}
    if "run_id" not in merged and _run_id is not None:
        merged["run_id"] = _run_id
    merged = _coerce_for_wire(merged)
    _splice_agent_policy(event_type, merged)
    return _require_dispatch().emit(level, event_type, merged, sign=sign)


def _yaml_log_level(py_rt) -> str | None:
    """Pull ``ceremony.log_level`` straight from the on-disk yaml.
    Returns ``None`` when the field is absent or unparseable. Doesn't
    raise — yaml-load errors are swallowed and treated as "no opinion."
    """
    try:
        from pathlib import Path as _Path

        import yaml as _yaml

        yaml_path = _Path(py_rt.cfg.yaml_path)
        with yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh) or {}
        ceremony = doc.get("ceremony") or {}
        level = ceremony.get("log_level")
        if isinstance(level, str) and level:
            return level
    except Exception:  # noqa: BLE001 — best-effort read; never blocks init
        return None
    return None


# --------------------------------------------------------------------------
# Session toggles + module-global state — implemented in tn/_session.py.
# Re-exported here so existing call sites still see `tn._log_level_threshold`,
# `tn.set_level(...)`, etc. emit.py reads `_session._log_level_threshold` at
# call time, so `set_level()` updates propagate correctly.
# --------------------------------------------------------------------------
from . import _session  # noqa: E402
from ._session import (  # noqa: E402, F401
    _resolve_sign,
    get_level,
    is_enabled_for,
    set_level,
    set_signing,
)


# `_log_level_threshold` and `_sign_override` are read by callers via attribute
# access on the `tn` package (e.g. `tn._log_level_threshold`). They live in
# `_session.py` now; we expose them as module-level descriptors that re-read
# from `_session` on every access so callers can't see a stale snapshot.
def __getattr__(name: str):
    if name == "_log_level_threshold":
        return _session._log_level_threshold
    if name == "_sign_override":
        return _session._sign_override
    raise AttributeError(f"module 'tn' has no attribute {name!r}")


# --------------------------------------------------------------------------
# Emit verbs — implemented in tn/emit.py. Re-exported here so callers keep
# writing `tn.info(...)`. The dispatch state (run_id, _dispatch_rt) and
# the helpers (_emit_with_splice, _resolve_sign) still live in this
# package init; emit.py imports them back when called.
# --------------------------------------------------------------------------
from .emit import debug, error, info, log, warning  # noqa: E402, F401

# --------------------------------------------------------------------------
# Lifecycle verbs — public API lives in tn.lifecycle, re-exported here.
# The _impl bodies are private and used by lifecycle.py via the package init.
# --------------------------------------------------------------------------
from .lifecycle import (  # noqa: E402, F401
    current_config,
    flush_and_close,
    init,
    session,
    using_rust,
)

# --------------------------------------------------------------------------
# Read verbs — public API lives in tn.read.
# --------------------------------------------------------------------------
from .read import (  # noqa: E402, F401
    read,
    read_all,
    read_as_recipient,
    read_raw,
    secure_read,
    watch,
)


from ._read_impl import (  # noqa: F401, E402
    VerificationError,
    _attach_instructions,
    _emit_tampered_row_skipped,
    _entry_in_current_run_flat,
    _entry_in_current_run_raw,
    _invalid_reasons_from_valid,
    _is_foreign_log,
    _is_protocol_admin_event,
    _read_all_impl,
    _read_as_recipient_impl,
    _read_impl,
    _read_raw_admin_aware,
    _read_raw_impl,
    _read_raw_inner,
    _rotated_backup_paths,
    _secure_read_impl,
)



def _flush_and_close_impl(*, timeout: float = 30.0) -> None:
    """Close all handlers (drains async outboxes best-effort)."""
    global _dispatch_rt, _cached_admin_state, _agent_policy_doc
    _surface.info(
        "tn.flush_and_close() ENTER prior_dispatch=%s timeout=%s",
        "set" if _dispatch_rt is not None else "None",
        timeout,
    )
    # Lock around the swap so a concurrent init() doesn't see a half-torn-down
    # state. See Workstream D7.
    with _init_lock:
        if _dispatch_rt is not None:
            _dispatch_rt.close(timeout=timeout)
            _dispatch_rt = None
        # Reset the lazy admin cache singleton so a re-init() re-creates it
        # bound to the new ceremony's LoadedConfig.
        _cached_admin_state = None
        # Clear cached policy doc so a re-init reloads from disk.
        _agent_policy_doc = None
        # Also clear the logger singleton so re-init works correctly.
        from . import logger as _lg

        with _lg._runtime_lock:
            _lg._runtime = None
    _surface.info(
        "tn.flush_and_close() EXIT _run_id=%s (run_id intentionally NOT reset; "
        "TN_RUN_ID env still set so re-init keeps stamping consistent run_id)",
        _run_id,
    )


def _current_config_impl():
    """Return the LoadedConfig for the active ceremony."""
    from . import logger as _lg

    if _lg._runtime is None:
        raise RuntimeError("tn.init(yaml_path) must be called first")
    cfg = _lg._runtime.cfg
    _surface.info(
        "tn.current_config() yaml=%s log_path=%s keystore=%s",
        cfg.yaml_path, cfg.log_path, cfg.keystore,
    )
    return cfg


def _using_rust_impl() -> bool:
    """Diagnostic: True iff the current runtime is routed through tn_core (Rust)."""
    answer = bool(_dispatch_rt is not None and _dispatch_rt.using_rust)
    _surface.info("tn.using_rust() -> %s", answer)
    return answer


# --------------------------------------------------------------------------
# Admin verbs that route through Rust when available (btn ceremonies)
# --------------------------------------------------------------------------


def _get_or_create_cache() -> AdminStateCache:
    """Lazily build the module-level ``AdminStateCache`` singleton bound
    to the currently-active ``LoadedConfig``. Raises ``RuntimeError`` if
    ``tn.init()`` has not been called.
    """
    global _cached_admin_state
    if _cached_admin_state is None:
        cfg = current_config()  # raises if no init
        _cached_admin_state = AdminStateCache(cfg)
    return _cached_admin_state


from ._pkg_impl import _absorb_impl, _export_impl  # noqa: F401, E402


def _refresh_admin_cache_if_present() -> None:
    """Post-write hook used by emit + absorb paths. Best-effort: never
    raises. If the cache hasn't been instantiated yet (no caller has
    invoked ``cached_admin_state()`` this session), this is a no-op —
    the cache will pick up the new envelopes when first asked.
    """
    if _cached_admin_state is None:
        return
    try:
        _cached_admin_state.refresh()
    except Exception:
        _logger.exception("admin cache refresh failed; proceeding")


from ._pkg_impl import _bundle_for_recipient_impl  # noqa: F401, E402
from ._vault_impl import _vault_link_impl, _vault_unlink_impl  # noqa: F401, E402
from ._session_impl import _Session, _SessionHandle, _session_impl  # noqa: F401, E402


__all__ = [  # noqa: RUF022 — intentional category grouping (see inline comments)
    "AbsorbReceipt",
    "AbsorbResult",
    "AdminStateCache",
    "Audit",
    "ChainConflict",
    "Entry",
    "LeafReuseAttempt",
    "PolicyDocument",
    "PolicyTemplate",
    "RotationConflict",
    "SameCoordinateFork",
    "VerificationError",
    "VerifyError",
    # admin subpackage (cipher-agnostic verbs + cache accessors)
    "admin",
    # pkg subpackage (export, absorb, bundle_for_recipient)
    "pkg",
    # vault subpackage (link, unlink)
    "vault",
    # LLM classifier stub (PRD §6.4)
    "classifier",
    "clear_context",
    "compile_enrolment",
    "current_config",
    "debug",
    # ceremony admin (code-level equivalents of the CLI verbs)
    "ensure_group",
    "error",
    "flush_and_close",
    "get_context",
    # identity + sealing + wallet (link/backup/recovery story)
    "identity",
    "info",
    # high-level logging
    "init",
    "log",
    # Bilateral lifecycle (JWE + btn unified read)
    "offer",
    "read",
    "read_all",
    "read_as_recipient",
    "read_raw",
    "secure_read",
    "sealing",
    # context
    "scope",
    "session",
    "set_context",
    "set_level",
    "set_link_state",
    "set_signing",
    "set_strict",
    "get_level",
    "is_enabled_for",
    "update_context",
    # dispatch diagnostic
    "using_rust",
    "vault_client",
    "wallet",
    "warning",
    "watch",
]
