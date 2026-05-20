"""tn-protocol: TN protocol Python SDK.

Lifecycle (the four-line dirt-easy summary):

    1. tn.absorb('Agentic20.project.tnpkg')   # install layout from dashboard
    2. tn.info('hello.world', who='alice')    # emit an attested entry
    3. for e in tn.read(): print(e)           # iterate + decrypt
    4. tn.flush_and_close()                   # drain handlers (optional)

Step 1 is optional once a ceremony is on disk; ``tn.info`` will discover
``./tn.yaml`` (legacy) or ``./.tn/default/tn.yaml`` (multi-ceremony) on
first use. Step 4 is optional in short scripts but recommended in
long-running processes.

Public API:
    tn.init(yaml_path)          # load or create ceremony + open log file
    tn.absorb(source)           # install a .tnpkg (alias for tn.pkg.absorb)
    tn.export(...)              # produce a .tnpkg (alias for tn.pkg.export)
    tn.debug/info/warning/error # emit attested log entries
    tn.set_context(**kwargs)    # per-request context (PRD §13)
    tn.update_context / clear_context / get_context
    tn.read(log_path, cfg)      # iterate + decrypt entries (flat dicts;
                                # raw=True for the {envelope, plaintext,
                                # valid} audit shape)
    tn.flush_and_close()        # drain handlers, release runtime

Ciphers: "jwe" (pure-Python static-ECDH + AES-KW + AES-GCM) and "btn"
(NNL subset-difference broadcast, via the Rust tn_core extension).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from . import (
    _agents_policy,
    _autoinit,
    admin,
    classifier,
    identity,
    pkg,
    sealing,
    vault,
    vault_client,
    wallet,
)
from ._agents_policy import PolicyDocument, PolicyTemplate
from ._autoinit import set_strict
from ._dispatch import (  # should_use_rust re-exported for diagnostics
    DispatchRuntime,
    should_use_rust,
)
from ._entry import Entry, VerifyError
from .absorb import AbsorbReceipt, AbsorbResult, LeafReuseAttempt
from .absorb import absorb as _raw_absorb

# Re-export the Rust-bound runtime exception so callers can write a
# stable `except tn.KeystoreConflictError` instead of dipping into the
# private `tn_core._core` module. The class is shared across runtime
# failures, so check the message string when distinguishing
# divergence-retry from other faults: see `is_keystore_diverged()`.
from tn_core._core import TnRuntimeError as KeystoreConflictError


def is_keystore_diverged(exc: BaseException) -> bool:
    """Return True if ``exc`` is a keystore-state-divergence error from
    the Rust runtime (the retry-friendly case for concurrent admin
    writers), False otherwise.

    The Rust runtime raises ``KeystoreConflictError`` for many distinct
    failure modes that share the same exception class. This predicate
    looks for the specific divergence marker so deploy scripts can
    write::

        try:
            tn.admin.add_recipient(group="default", recipient_did=did)
        except tn.KeystoreConflictError as exc:
            if tn.is_keystore_diverged(exc):
                # safe to re-read + retry the admin verb
                ...
            else:
                raise
    """
    if not isinstance(exc, KeystoreConflictError):
        return False
    msg = str(exc)
    return "diverged" in msg
from .admin import (
    ensure_group,
    set_link_state,
)
from .admin.cache import (
    AdminStateCache,
    ChainConflict,
    RotationConflict,
    SameCoordinateFork,
)
from .admin.cache import LeafReuseAttempt as CacheLeafReuseAttempt  # noqa: F401
from .compile import compile_enrolment
from .context import (
    _context as _ctx_var,  # noqa: F401 — read by `_emit_via` hot path
    clear_context,
    get_context,
    scope,
    set_context,
    update_context,
)
from .export import (
    IDENTITY_SEED_CEREMONY_PLACEHOLDER,
    export_identity_seed,
)
from .export import (
    export as _raw_export,
)
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
    link: bool | None = None,
    device_private_bytes: bytes | None = None,
    keystore_dir: "str | Path | None" = None,
    admin_log_path: "str | Path | None" = None,
) -> None:
    """Initialize TN for this process.

    ``yaml_path`` is optional. With no argument, ``tn.init()`` walks the
    same discovery chain that auto-init uses:

      1. ``$TN_YAML`` env var
      2. ``./tn.yaml`` in the current working directory (legacy layout)
      3. ``./.tn/default/tn.yaml`` (multi-ceremony layout)
      4. ``$TN_HOME/tn.yaml`` (default ``~/.tn/tn.yaml``)
      5. None of the above → mint a fresh ceremony at ``./.tn/default/``

    With an explicit path, that path is used verbatim and the discovery
    chain is skipped. ``TN_STRICT=1`` blocks the no-arg form (raises
    ``RuntimeError``) so production callers can't accidentally land on
    the auto-discovery path.

    If the ceremony uses cipher: btn on every group AND the tn_core Rust
    extension is available AND TN_FORCE_PYTHON is not set, emit/read are
    transparently routed through the Rust runtime. All other public symbols
    (current_config, admin verbs, read_as_recipient, etc.) remain on the
    Python path.

    All kwargs are forwarded to the underlying logger.build_runtime()
    so existing call sites continue to work without changes.
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

    # Register the atexit drain hook on first init so handlers flush
    # on normal interpreter shutdown without the caller having to
    # remember tn.flush_and_close(). Idempotent — repeat inits don't
    # re-register. See _atexit_flush + _register_atexit_flush_once.
    _register_atexit_flush_once()

    # Serialize init() across threads so two callers on a fresh process
    # don't both build their own runtime (and then leak one). The second
    # caller waits, sees the now-bound _dispatch_rt, and short-circuits
    # via logger.build_runtime's own _runtime swap (which also re-uses
    # the same _runtime_lock). See Workstream D7.
    with _init_lock:
        # Always call logger.build_runtime() first — it handles:
        #   - fresh ceremony creation (keystore, yaml)
        #   - absorb + _reconcile of inbox packages
        #   - building the Python TNRuntime (cfg, handlers, chain)
        from .logger import build_runtime as _logger_build_runtime

        _logger_build_runtime(
            yaml_path,
            log_path=log_path,
            pool_size=pool_size,
            cipher=cipher,
            identity=identity,
            extra_handlers=extra_handlers,
            stdout=stdout,
            device_private_bytes=device_private_bytes,
            keystore_dir=keystore_dir,
            admin_log_path=admin_log_path,
        )

        # After logger.build_runtime() completes, read back the singleton it created.
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

    # ------------------------------------------------------------------
    # SDK auto-link — parity with the ``tn init`` CLI verb.
    #
    # The CLI's ``cmd_wallet_init`` block uploads the fresh ceremony to
    # the vault and prints a CLAIM URL. That block lived only in the
    # CLI, so notebook callers of ``tn.init()`` got no URL.
    #
    # Resolution of the ``link`` kwarg:
    #
    #   * ``True``  — force run (works in any context).
    #   * ``False`` — never run (CLI passes this to keep its own block).
    #   * ``None``  — auto: run iff inside an IPython/Jupyter/Databricks
    #                 kernel. Plain Python scripts, pytest runs,
    #                 examples, and library callers get a clean
    #                 ceremony with no surprise vault contact; the
    #                 notebook UX the change was written for still
    #                 fires automatically.
    #
    # ``TN_NO_LINK=1`` is a hard env-level opt-out checked by the
    # helper itself.
    # ------------------------------------------------------------------
    if link is True or (link is None and _in_ipython()):
        try:
            _auto_link_after_init(yaml_path=yaml_p, identity=identity)
        except Exception:
            _logger.exception("tn.init auto-link wrapper raised; continuing")


# Module-level latch so re-entrant ``tn.init()`` calls in the same
# process don't reprint the claim URL on every call.
_link_done_this_process: bool = False


def _in_ipython() -> bool:
    """True iff running inside an IPython/Jupyter/Databricks kernel.

    Used to (a) route the auto-link banner through ``IPython.display.HTML``
    so the claim URL renders as a clickable hyperlink in the cell, and
    (b) keep the stdout handler in the dispatch fan-out so emits land
    in cell output rather than the Rust-side fd-1 sink the kernel
    doesn't capture.
    """
    try:
        from IPython import get_ipython  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        return get_ipython() is not None
    except Exception:
        return False


def _display_claim_url(
    *,
    url: str,
    vault_id: str,
    expires_at: str,
    reused: bool,
) -> None:
    """Render the claim URL. HTML hyperlink in IPython, plain print elsewhere."""
    if _in_ipython():
        try:
            from IPython.display import HTML, display  # type: ignore[import-not-found]

            reuse_note = (
                '  <em>(reusing live pending claim within TTL)</em>'
                if reused
                else ''
            )
            display(HTML(
                '<div style="border-left:3px solid #2b7;padding:0.5em 0.75em;'
                'margin:0.5em 0;font-family:sans-serif;">'
                '<div style="font-weight:600;margin-bottom:0.25em;">'
                'TN — claim this project under your account</div>'
                f'<div><a href="{url}" target="_blank" rel="noopener">{url}</a></div>'
                '<div style="font-size:0.85em;color:#666;margin-top:0.25em;">'
                f'vault_id: <code>{vault_id}</code> · expires: '
                f'<code>{expires_at}</code>{reuse_note}'
                '</div></div>'
            ))
            return
        except Exception:
            pass  # fall through to plain print below
    print()
    print("[tn.init] Backed up to vault")
    print(f"[tn.init]   vault_id: {vault_id}")
    print(f"[tn.init]   expires:  {expires_at}")
    if reused:
        print("[tn.init]   (reusing live pending-claim within TTL)")
    print()
    print(
        "[tn.init] CLAIM URL — open this in your browser to attach the "
        "project to your account:"
    )
    print(f"  {url}")
    print()


def _auto_link_after_init(*, yaml_path: Path, identity: Any | None) -> None:
    """Best-effort vault upload + claim URL surfacing.

    Mirrors the link/print block from ``cli.cmd_wallet_init`` so plain
    Python callers (notebooks, scripts, REPL) get the same onboarding
    URL the CLI does. Failures are warned-but-not-raised: a vault that
    is unreachable does not invalidate the on-disk ceremony.

    Identity resolution:
      * Caller-supplied ``identity`` wins.
      * Else load from ``_default_identity_path()`` if it exists.
      * Else mint a fresh identity (mnemonic NOT stored — back up
        ``identity.json`` directly or run ``tn wallet backup`` later).

    Env opt-out: ``TN_NO_LINK=1`` skips entirely.
    """
    global _link_done_this_process
    if _link_done_this_process:
        return
    if __import__("os").environ.get("TN_NO_LINK", "").strip() == "1":
        return

    from .identity import Identity, _default_identity_path
    from .vault_client import resolve_vault_url

    identity_path = _default_identity_path()
    if identity is None:
        if identity_path.exists():
            try:
                identity = Identity.load(identity_path)
            except Exception as e:
                _logger.warning(
                    "auto-link: failed to load identity at %s: %s; skipping.",
                    identity_path, e,
                )
                return
        else:
            try:
                identity = Identity.create_new(word_count=12)
                identity.ensure_written(identity_path)
            except Exception as e:
                _logger.warning(
                    "auto-link: failed to mint identity at %s: %s; skipping.",
                    identity_path, e,
                )
                return

    vault_url = identity.linked_vault or resolve_vault_url(None)
    if identity.linked_vault is None:
        try:
            identity.linked_vault = vault_url
            identity.ensure_written(identity_path)
        except Exception:
            _logger.exception(
                "auto-link: failed to persist linked_vault; continuing"
            )

    client = None
    try:
        from .handlers.vault_push import _default_client_factory, init_upload

        client = _default_client_factory(vault_url, identity)
        cfg = _current_config_impl()
        result = init_upload(cfg, client, vault_base=vault_url)
        _display_claim_url(
            url=result["claim_url"],
            vault_id=result["vault_id"],
            expires_at=result["expires_at"],
            reused=bool(result.get("reused", False)),
        )
        _link_done_this_process = True
    except Exception as e:
        _logger.warning(
            "auto-link: vault upload failed: %s; ceremony is still valid "
            "locally. Retry with `tn wallet link %s --vault %s`.",
            e, yaml_path, vault_url,
        )
    finally:
        if client is not None:
            try:
                client._vc.close()
            except Exception:
                pass


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
        raise RuntimeError(
            "tn: no active runtime. Call one of:\n"
            "  - tn.init()                            # discover or auto-create a ceremony\n"
            "  - tn.init(yaml_path)                   # bind to an existing ceremony\n"
            "  - tn.absorb('Agentic20.project.tnpkg') # install + bind in one call\n"
            "Then retry."
        )
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


# Types that pass straight through ``_coerce_for_wire`` unchanged. JSON-native
# scalars plus None. When every top-level value in a fields dict is one of
# these, we can skip the recursive walk entirely.
#
# Containers (dict, list, tuple) are deliberately NOT in this set — they
# could contain a nested Decimal that needs coercion. The fast-path here
# only fires for "flat" emits, which is the overwhelming common case
# (``tn.info('order.created', user='alice', amount=4999)``).
_WIRE_SAFE_TYPES: tuple = (str, int, float, bool, bytes, type(None))


def _fields_already_wire_safe(fields: dict[str, Any]) -> bool:
    """Return True iff every value in ``fields`` is a JSON-native scalar.

    Used by ``_emit_via`` to skip the ``_coerce_for_wire`` walk for the
    common flat-emit case. Order-of-magnitude faster than the walk
    itself when the answer is True, and the walk is unchanged for
    fields that aren't.
    """
    # ``isinstance(v, _WIRE_SAFE_TYPES)`` is a C-level type-tuple check,
    # cheaper than the recursive _coerce_for_wire call on the same value.
    for v in fields.values():
        if not isinstance(v, _WIRE_SAFE_TYPES):
            return False
    return True


def _notify_config_changed() -> None:
    """Tell the dispatch runtime to re-build its per-emit invariant cache.

    Call this when state that the cache depends on has changed outside
    the package's own setters — for example, after directly mutating
    ``tn._dispatch_rt._py_rt.handlers`` from advanced/test code. The
    package's public setters (``set_level``, ``set_signing``,
    ``reload()``) already trigger this implicitly.

    No-op if no dispatch runtime is bound yet.

    See ``DispatchRuntime._invalidate_caches`` for the list of
    cache slots that get rebuilt (IPython detection, Rust log path,
    effective handler list).
    """
    rt = globals().get("_dispatch_rt")
    if rt is None:
        return
    invalidator = getattr(rt, "_invalidate_caches", None)
    if invalidator is not None:
        invalidator()


def _ensure_run_id() -> str:
    """Return the per-process ``_run_id``, minting it lazily on first
    use. Without this the per-instance dispatch path (TN.info on a
    named ceremony) emits entries with no run_id, which the default
    read filter ("this run only") then drops. Mirrors the run_id
    minting in ``_init_impl`` for the legacy / default ceremony path.
    """
    global _run_id
    if _run_id is None:
        import os as _os
        import uuid as _uuid
        _run_id = _uuid.uuid4().hex
        _os.environ["TN_RUN_ID"] = _run_id
    return _run_id


def _emit_via(
    rt: DispatchRuntime,
    level: str,
    event_type: str,
    fields: dict[str, Any],
    sign: bool | None,
) -> None:
    """Build the merged-fields dict, splice tn.agents policy text if a
    template applies, then dispatch the emit through the supplied
    runtime.

    Used by both the module-level ``tn.info`` (which passes the global
    singleton) and the per-TN ``payments.info`` (which passes its own
    runtime). Splitting the dispatch target out is what makes
    multi-ceremony non-default emits independent of the global
    singleton — the user's no-rebinding contract.

    Hot-path note (0.4.2a7): the common flow is "no scope context,
    flat fields, no agent policy template for this event_type". The
    branches below short-circuit each invariant so vanilla emits
    don't pay for capabilities they aren't using:
      - When ``_context.get()`` is None (no ``tn.scope(...)`` /
        ``set_context(...)`` active), the ``fields`` dict (which is
        the verb wrapper's ``**kwargs`` capture — private to this
        call) is mutated in place. Saves the ``dict(fields)`` copy.
      - When every field value is JSON-native, skip the recursive
        ``_coerce_for_wire`` walk.
      - When no agent-policy doc is loaded,
        ``_splice_agent_policy`` returns immediately.
    """
    ctx = _ctx_var.get()
    if ctx is None:
        # Common path: no scope active. ``fields`` is the freshly-
        # built ``**kwargs`` from the verb wrapper — private to this
        # call — so we can mutate it directly without bleeding into
        # the caller.
        merged: dict[str, Any] = fields
    else:
        merged = {**ctx, **fields}
    if "run_id" not in merged:
        merged["run_id"] = _ensure_run_id()
    # _coerce_for_wire is a recursive walk; for flat emits with
    # JSON-native scalars it returns the input unchanged. Skip it.
    if not _fields_already_wire_safe(merged):
        merged = _coerce_for_wire(merged)
    _splice_agent_policy(event_type, merged)
    return rt.emit(level, event_type, merged, sign=sign)


def _emit_with_splice(level: str, event_type: str, fields: dict[str, Any], sign: bool | None) -> None:
    """Module-level emit: routes through the singleton dispatch runtime.

    Used by the bare ``tn.info(...)`` / ``tn.log(...)`` API which is
    bound to whichever ceremony was most recently bound to the
    singleton (typically ``default``). Per-TN methods bypass this
    and call ``_emit_via`` with their own runtime — see
    ``tn._handle.TN``.
    """
    return _emit_via(_require_dispatch(), level, event_type, fields, sign)


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


def __dir__() -> list[str]:
    """Focused introspection surface for ``help(tn)`` and tab-completion.

    Returns the curated ``__all__`` list. Without this hook, Python's
    default ``dir(tn)`` enumerates every stdlib name we happened to
    import at module scope (``Path``, ``Any``, ``logging``,
    ``threading``, ``annotations``, ...) plus every submodule that got
    auto-imported (``canonical``, ``chain``, ``cipher``, ...). Those
    are all still reachable via attribute access — we just don't
    advertise them as part of the public API.

    The clean dir() also gives the TS SDK rebuild an unambiguous
    signal of which symbols are part of the wire contract and which
    are implementation detail.
    """
    return sorted(__all__)


# --------------------------------------------------------------------------
# Emit verbs — implemented in tn/emit.py. Re-exported here so callers keep
# writing `tn.info(...)`. The dispatch state (run_id, _dispatch_rt) and
# the helpers (_emit_with_splice, _resolve_sign) still live in this
# package init; emit.py imports them back when called.
# --------------------------------------------------------------------------
from ._handle import (  # noqa: E402
    TN,
    MultiCeremonyEmitNotImplemented,
)

# --------------------------------------------------------------------------
# Multi-ceremony module verbs — see tn._multi and docs/directory-layout.md.
# tn.init is sourced from _multi (which delegates legacy yaml-path calls
# through to tn._init_impl for backwards compat). tn.use and tn.list
# are new with the multi-ceremony work.
# --------------------------------------------------------------------------
from ._multi import (  # noqa: E402
    TNConfigConflict,
    TNCreateFailed,
    TNInvalidName,
    init,
    list_ceremonies,
    use,
)

# Internal helpers from the legacy read-impl module that other parts of
# the SDK still import. The user-facing read verbs (read/read_raw/...)
# are gone — there's now exactly one ``tn.read`` and one ``tn.watch``.
from ._read_impl import (  # noqa: F401, E402
    VerificationError,
    _entry_in_current_run_raw,
    _is_foreign_log,
    _is_protocol_admin_event,
    _read_raw_admin_aware,
    _read_raw_inner,
    _rotated_backup_paths,
)
from ._registry import TNNotFound  # noqa: E402
from . import emit as _emit_module  # noqa: E402
from .emit import debug, error, info, log, warning  # noqa: E402

# 0.4.2a7 hot-path lift: bind ``_emit_with_splice`` / ``_resolve_sign``
# / the ``tn`` module reference onto ``emit.py``'s module namespace
# once at package load. The verbs (``log`` / ``info`` / etc.) then
# call the bound names directly instead of paying for a late ``from .
# import ...`` on every emit. emit.py is imported earlier in this
# same __init__.py — at that point those names didn't exist yet, so
# we patch them in here at the tail.
_emit_module._bind_dependencies()

# --------------------------------------------------------------------------
# Lifecycle verbs — public API lives in tn.lifecycle, re-exported here.
# The _impl bodies are private and used by lifecycle.py via the package init.
# --------------------------------------------------------------------------
from .lifecycle import (  # noqa: E402
    current_config,
    flush_and_close,
    session,
    using_rust,
)

# --------------------------------------------------------------------------
# Read verbs — public API lives in tn.read.
# --------------------------------------------------------------------------
from .read import (  # noqa: E402
    read,
    watch,
)


# atexit registration: tn.init() registers _atexit_flush once per
# process so handlers drain on normal interpreter exit without the
# caller needing to remember tn.flush_and_close(). The flag prevents
# double-registration on subsequent init() calls.
_atexit_registered = False


def _atexit_flush() -> None:
    """Best-effort drain at process exit. Idempotent — safe to run after
    an explicit ``tn.flush_and_close()`` (it's a no-op when the
    runtime is already closed). Swallows exceptions so a flush failure
    can't taint the interpreter shutdown.
    """
    try:
        if _dispatch_rt is not None:
            _flush_and_close_impl()
    except Exception:
        # atexit must never raise — leftover state will be cleaned up
        # by the OS when the process exits anyway.
        pass


def _register_atexit_flush_once() -> None:
    """Register ``_atexit_flush`` exactly once for the lifetime of this
    process. Called from ``_init_impl`` on first init.
    """
    global _atexit_registered
    if _atexit_registered:
        return
    import atexit
    atexit.register(_atexit_flush)
    _atexit_registered = True


def _flush_and_close_impl(*, timeout: float = 30.0) -> None:
    """Close all handlers (drains async outboxes best-effort).

    You usually don't need to call ``tn.flush_and_close()`` explicitly
    — ``tn.init()`` registers an ``atexit`` hook that drains handlers
    on normal interpreter shutdown. Call this only when you need
    deterministic flush *before* the process exits (e.g., before
    forking, before assertion checks in tests, or in long-running
    services that re-init periodically). For deterministic scoping
    use ``with tn.session(): ...`` instead.
    """
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
        # Close per-TN runtimes (named ceremonies that own their own
        # dispatch runtime — Bug 1 fix). Their file handlers won't
        # flush otherwise.
        from ._handle import _close_per_tn_runtimes
        _close_per_tn_runtimes(timeout=timeout)

        # Reset the lazy admin cache singleton so a re-init() re-creates it
        # bound to the new ceremony's LoadedConfig.
        _cached_admin_state = None
        # Clear cached policy doc so a re-init reloads from disk.
        _agent_policy_doc = None
        # Also clear the logger singleton so re-init works correctly.
        from . import logger as _lg

        with _lg._runtime_lock:
            _lg._runtime = None
        # Clear the multi-ceremony registry so test isolation is
        # tight: a later ``tn.init('default', yaml=...)`` won't
        # collide with the prior handle. Disk state for named
        # ceremonies under ``.tn/<name>/`` is unaffected; a
        # subsequent ``tn.use(name)`` re-attaches to it.
        from ._registry import clear_registry_for_tests as _clear_reg
        _clear_reg()
    _surface.info(
        "tn.flush_and_close() EXIT _run_id=%s (run_id intentionally NOT reset; "
        "TN_RUN_ID env still set so re-init keeps stamping consistent run_id)",
        _run_id,
    )


# Note: tn.session() already exists as a context manager (see
# python/tn/_session_impl.py). It handles init + tmpdir + close +
# nested-session restore. For explicit lifecycle scoping, use:
#
#     with tn.session() as handle:
#         handle.log("evt", k=1)
#
# For most callers the atexit hook above means you never need to call
# flush_and_close() at all.


def _current_config_impl():
    """Return the LoadedConfig for the active ceremony."""
    from . import logger as _lg

    if _lg._runtime is None:
        raise RuntimeError(
            "tn: no active runtime. Call tn.init() (or tn.absorb(<bundle>) "
            "for a freshly-downloaded project_seed / identity_seed) first."
        )
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


from ._pkg_impl import _absorb_impl, _export_impl  # noqa: E402

absorb = _absorb_impl
export = _export_impl


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
from ._session_impl import _Session, _session_impl, _SessionHandle  # noqa: F401, E402
from ._vault_impl import _vault_link_impl, _vault_unlink_impl  # noqa: F401, E402

__all__ = [  # noqa: RUF022 — intentional category grouping (see inline comments)
    "AbsorbReceipt",
    "AbsorbResult",
    "absorb",
    "export",
    "AdminStateCache",
    "ChainConflict",
    "Entry",
    "KeystoreConflictError",
    "is_keystore_diverged",
    "LeafReuseAttempt",
    "MultiCeremonyEmitNotImplemented",
    "PolicyDocument",
    "PolicyTemplate",
    "RotationConflict",
    "SameCoordinateFork",
    "TN",
    "TNConfigConflict",
    "TNCreateFailed",
    "TNInvalidName",
    "TNNotFound",
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
    # multi-ceremony module verbs (see docs/directory-layout.md)
    "list_ceremonies",
    "log",
    # Bilateral lifecycle (JWE + btn unified read)
    "offer",
    "read",
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
    "use",
    # dispatch diagnostic
    "using_rust",
    "vault_client",
    "wallet",
    "warning",
    "watch",
]
