"""``TN``: the public ceremony handle.

A ``TN`` instance is the in-process representation of a single
ceremony. It owns the ceremony's registry name and yaml path; the
heavy lifting (chain, signing, vault, handlers) still routes through
the SDK's existing module-level singleton runtime.

Why singleton-routing during this sprint
----------------------------------------
The current SDK keeps the active ceremony's runtime in module-level
globals (``_dispatch_rt``, ``logger._runtime``, ``_run_id``,
``_agent_policy_doc``, ``_cached_admin_state``). Splitting that state
per-ceremony so two ``TN`` instances can emit in parallel is a deeper
refactor than this sprint targets.

Concretely, this sprint lands:

- the ``TN`` class and the registry, so multi-ceremony is *named* and
  *enumerable* in code;
- the ``.tn/<name>/`` directory layout, so multi-ceremony is *visible*
  on disk;
- the safe-defaults auto-create flow, so ``tn.use(name)`` is friendly;
- the legacy-layout migration.

It does *not* land:

- emit/read on a non-default named ceremony. A ``TN`` whose name is
  not ``"default"`` raises ``MultiCeremonyEmitNotImplemented`` from
  any verb that would route through the singleton. The ceremony's
  on-disk state and config are still real and inspectable.

The next sprint will replace the singleton-wrapping below with real
per-instance dispatch. The class surface here is the surface that
the new dispatch will plug into; callers updated to use ``TN`` today
will not need to change when that lands.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ._defaults import DEFAULT_CEREMONY_NAME

if TYPE_CHECKING:
    from typing import Iterator

__all__ = [
    "MultiCeremonyEmitNotImplemented",
    "TN",
    "_close_per_tn_runtimes",
]


# Module-level set of per-TN runtimes (named ceremonies only —
# default's runtime is the singleton, closed separately by
# ``tn.flush_and_close``). The set is consulted by flush_and_close
# so per-TN runtimes' file handlers flush on shutdown.
_per_tn_runtimes: list[Any] = []


def _track_per_tn_runtime(rt: Any) -> None:
    """Register a per-TN ``DispatchRuntime`` for shutdown. Called
    from ``TN._get_runtime`` when minting a runtime for a named
    ceremony.
    """
    _per_tn_runtimes.append(rt)


def _close_per_tn_runtimes(*, timeout: float = 30.0) -> None:
    """Close every tracked per-TN runtime. Invoked from
    ``tn.flush_and_close``. Best-effort: a failing close on one
    runtime does not prevent the others from running."""
    while _per_tn_runtimes:
        rt = _per_tn_runtimes.pop()
        try:
            rt.close(timeout=timeout)
        except Exception:
            pass


class MultiCeremonyEmitNotImplemented(NotImplementedError):
    """Raised when a non-default ``TN`` is asked to emit or read.

    The directory and config exist on disk; only the in-process
    singleton-routing for non-default ceremonies is staged.
    """

    def __init__(self, name: str, verb: str):
        self.name = name
        self.verb = verb
        super().__init__(
            f"TN(name={name!r}).{verb}(...) is not yet wired in this "
            "sprint. Multi-ceremony emit and read land in the next "
            "sprint, when the module-level dispatch singleton is "
            "factored per-instance. Until then, only the 'default' "
            f"ceremony can emit. The directory .tn/{name}/ and its "
            "tn.yaml are real and can be inspected."
        )


class TN:
    """Handle to a single TN ceremony.

    Construct via ``tn.init(name, ...)`` or ``tn.use(name)``; do not
    instantiate directly. The constructor is intentionally minimal so
    the registry can intern a single instance per (process, name).
    """

    __slots__ = ("_name", "_yaml_path", "_directory", "_cfg", "_rt")

    def __init__(self, name: str, *, yaml_path: Path, directory: Path):
        self._name = name
        self._yaml_path = yaml_path
        self._directory = directory
        # Lazy ``LoadedConfig`` — minted on first access to ``self.cfg``.
        self._cfg: object | None = None
        # Lazy per-instance ``DispatchRuntime``. Bug-1 fix: every TN
        # owns its own runtime instead of rebinding the module-level
        # singleton on each method call. ``payments.info(...)`` writes
        # to payments' runtime, ``default.info(...)`` writes to
        # default's, never crossing. The default ceremony's runtime
        # is wired to the module-level singleton (so the bare
        # ``tn.info(...)`` API and ``default.info(...)`` share state),
        # but named ceremonies are fully independent.
        self._rt: object | None = None

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Registry name (the ``.tn/<name>/`` directory name)."""
        return self._name

    @property
    def yaml_path(self) -> Path:
        """Absolute path to this ceremony's ``tn.yaml``."""
        return self._yaml_path

    @property
    def directory(self) -> Path:
        """Absolute path to this ceremony's ``.tn/<name>/`` directory."""
        return self._directory

    @property
    def is_default(self) -> bool:
        """True iff this is the default ceremony."""
        return self._name == DEFAULT_CEREMONY_NAME

    @property
    def cfg(self) -> Any:
        """Return the ``LoadedConfig`` for this ceremony, lazy-loaded.

        For ``default``, the cfg is the singleton's active config (so
        the live emit path and the tnpkg/vault path see the same
        state). For named ceremonies, the cfg is loaded directly from
        ``self.yaml_path`` without binding the singleton — that is
        what allows tnpkg/vault flows to operate on a non-default
        ceremony without the chain-emit infrastructure being involved.

        Cached after first load. Call ``invalidate_cfg()`` if the
        on-disk yaml has been mutated by something outside this
        process and you need to reread.
        """
        if self.is_default:
            # Always defer to the singleton's loaded cfg for default,
            # so tnpkg/vault verbs and live emit verbs agree on
            # ceremony state.
            from . import current_config as _current_config

            return _current_config()
        if self._cfg is None:
            from . import config as _config

            self._cfg = _config.load(self._yaml_path)
        return self._cfg

    def invalidate_cfg(self) -> None:
        """Drop the cached ``LoadedConfig`` so the next access re-reads
        ``self.yaml_path`` from disk. No-op for the default ceremony
        (which always defers to the singleton)."""
        self._cfg = None

    # ------------------------------------------------------------------
    # Per-instance dispatch runtime
    # ------------------------------------------------------------------

    def _get_runtime(self) -> Any:
        """Return this TN's ``DispatchRuntime``, building it on first
        access. Default ceremony's runtime is the module-level
        singleton (so ``tn.info(...)`` and ``default.info(...)`` share
        state). Named ceremonies build independent runtimes — calls
        on one TN never rebind another.

        Per-instance runtimes are tracked in a module-level set
        (``_per_tn_runtimes``) so ``tn.flush_and_close()`` can close
        them all alongside the singleton. Without that, per-TN
        runtimes' file handlers wouldn't flush on shutdown.
        """
        if self._rt is not None:
            return self._rt
        if self.is_default:
            # Default's runtime IS the module-level singleton.
            from . import _dispatch_rt as _global_rt
            from . import _init_impl as _legacy_init

            if _global_rt is None:
                _legacy_init(str(self._yaml_path))
            from . import _dispatch_rt as _global_rt2
            self._rt = _global_rt2
            return self._rt
        # Named ceremony: build an independent runtime + python-side
        # TNRuntime. No global state is touched.
        from . import config as _config
        from . import logger as _lg
        from ._dispatch import DispatchRuntime as _DR

        cfg = _config.load(self._yaml_path)
        default_log_dir = cfg.resolve_log_path().parent
        py_rt = _lg.TNRuntime(cfg, default_log_dir)
        rt = _DR(self._yaml_path, _logger_runtime=py_rt)
        self._rt = rt
        # Track for flush_and_close.
        _track_per_tn_runtime(rt)
        return rt

    def _activate(self) -> None:
        """Legacy singleton-binding helper. Used only by paths that
        still reach for ``_require_dispatch()`` — admin verbs and
        tnpkg/vault operations on non-default ceremonies. Live emit
        and read no longer call this; they use ``_get_runtime`` for
        per-instance dispatch (Bug 1 fix).
        """
        from . import current_config as _current_config
        from . import _init_impl as _legacy_init

        try:
            cfg = _current_config()
            existing = Path(getattr(cfg, "yaml_path", "")).resolve()
            if existing == self._yaml_path.resolve():
                return
        except Exception:
            pass
        _legacy_init(str(self._yaml_path))

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"TN(name={self._name!r}, yaml_path={str(self._yaml_path)!r})"

    # ------------------------------------------------------------------
    # Emit verbs
    #
    # The default ceremony delegates to the existing module-level
    # singleton (which already does the right thing). Named ceremonies
    # raise; see the module docstring for why.
    # ------------------------------------------------------------------

    # Emit verbs route through THIS TN's runtime, not the module-level
    # singleton. Two TNs in the same process emit to their own logs
    # without rebinding each other (Bug 1 fix). The default ceremony's
    # runtime is the singleton, so ``tn.info(...)`` and
    # ``default.info(...)`` continue to share state.

    def _emit(
        self,
        level: str,
        event_type: str,
        args: tuple,
        fields: dict[str, Any],
    ) -> None:
        from . import (
            _emit_via,
            _resolve_sign,
            _session,
        )
        # Apply the same level-threshold short-circuit as the
        # module-level emit verbs. Mirrors ``tn.emit``: drop if the
        # event's level is *below* the threshold. ``tn.log`` (level
        # ``""``) always emits regardless.
        thresholds = {"debug": 10, "info": 20, "warning": 30, "error": 40}
        if level in thresholds:
            if thresholds[level] < _session._log_level_threshold:
                return
        # Stdlib-style "absorb positional message" — same as
        # ``tn.emit._absorb_positional_message``.
        if args:
            if "message" in fields:
                fields["message"] = (
                    str(fields["message"]) + " " + " ".join(str(a) for a in args)
                )
            else:
                fields["message"] = " ".join(str(a) for a in args)
        _emit_via(self._get_runtime(), level, event_type, fields, _resolve_sign(None))

    def log(self, event_type: str, *args: Any, **fields: Any) -> None:
        """Severity-less event on this stream. Routes through this
        TN's per-instance runtime — no global-singleton rebinding."""
        self._emit("", event_type, args, fields)

    def debug(self, event_type: str, *args: Any, **fields: Any) -> None:
        self._emit("debug", event_type, args, fields)

    def info(self, event_type: str, *args: Any, **fields: Any) -> None:
        self._emit("info", event_type, args, fields)

    def warning(self, event_type: str, *args: Any, **fields: Any) -> None:
        self._emit("warning", event_type, args, fields)

    def error(self, event_type: str, *args: Any, **fields: Any) -> None:
        self._emit("error", event_type, args, fields)

    # ------------------------------------------------------------------
    # Read verbs
    # ------------------------------------------------------------------

    def read(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        """Read this stream's log file, decrypting with the project
        keystore.

        For streams whose profile has no replay surface (e.g.
        ``telemetry`` writes only to stdout), ``read()`` returns an
        empty iterator rather than raising. The semantics are
        "this stream has nothing to replay" — different shape, not
        an error. Callers iterating over read can write code that
        works uniformly across stream profiles.

        For streams with a file sink, this activates the ceremony
        (binds the singleton to its yaml so the legacy reader
        machinery has a runtime to read against) and delegates to
        the standard read function.
        """
        if not self._has_replay_surface():
            return iter(())
        self._activate()
        from .read import read as _read_fn
        return _read_fn(*args, **kwargs)

    def watch(self, *args: Any, **kwargs: Any) -> Any:
        """Tail this stream's log file. See ``read`` for replay-surface
        semantics — streams without a file sink yield an empty
        iterator (forward-only sinks have nothing to tail in the
        replay sense)."""
        if not self._has_replay_surface():
            return iter(())
        self._activate()
        from . import watch as _watch_fn
        return _watch_fn(*args, **kwargs)

    def _has_replay_surface(self) -> bool:
        """True iff this stream's profile (if any) has a readable
        backlog. Falls back to True for streams without a stamped
        profile, so legacy yamls (which preceded the profile field)
        keep working with read/watch.

        See ``tn._profiles.Profile.has_replay_surface``.
        """
        try:
            doc = self._load_yaml_dict()
            profile_name = (doc.get("ceremony") or {}).get("profile")
            if profile_name is None:
                return True
            from . import _profiles
            if not _profiles.is_known(profile_name):
                return True
            return _profiles.get(profile_name).has_replay_surface()
        except Exception:
            # Anything pathological — missing yaml, malformed yaml —
            # falls back to "treat as having a backlog" so the legacy
            # behavior of "raise on real read failure" still surfaces
            # to the caller in the read() body.
            return True

    def _load_yaml_dict(self) -> dict[str, Any]:
        """Load this stream's yaml as a plain dict. Cached per call;
        cheap for the small per-stream config files we produce."""
        import yaml as _yaml
        try:
            with self._yaml_path.open("r", encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh)
            return doc if isinstance(doc, dict) else {}
        except OSError:
            return {}

    # ------------------------------------------------------------------
    # Tnpkg verbs (export / absorb / bundle_for_recipient)
    #
    # Unlike emit/read, tnpkg flows are direct file I/O over the
    # ceremony's keystore, yaml, and admin log. They do not need the
    # chain-emit singleton. They DO need a ``LoadedConfig``, which
    # ``self.cfg`` provides per-ceremony — so these verbs work on
    # named (non-default) ceremonies as well.
    # ------------------------------------------------------------------

    def export(
        self,
        out_path: Any,
        *,
        kind: str,
        **kwargs: Any,
    ) -> Any:
        """Build a ``.tnpkg`` from this ceremony's state.

        Thin wrapper over ``tn.export.export`` with ``cfg=self.cfg``
        threaded through. ``kind`` and other kwargs match the
        underlying ``tn.export.export`` signature.
        """
        self._activate()
        from typing import cast
        from .export import export as _raw_export, ExportKind
        return _raw_export(
            out_path, kind=cast(ExportKind, kind), cfg=self.cfg, **kwargs
        )

    def absorb(self, source: Any, **kwargs: Any) -> Any:
        """Absorb a ``.tnpkg`` into this ceremony's state."""
        self._activate()
        from .absorb import absorb as _raw_absorb
        return _raw_absorb(self.cfg, source, **kwargs)

    def bundle_for_recipient(
        self,
        recipient_did: str,
        out_path: Any,
        *,
        groups: list[str] | None = None,
    ) -> Any:
        """Mint kits for ``recipient_did`` and bundle them into a
        ``.tnpkg`` at ``out_path``.

        For non-default ceremonies, this routes through a custom
        implementation that uses ``self.cfg`` instead of the singleton.
        For ``default``, defers to the existing module-level
        ``tn.bundle_for_recipient`` (which already handles the
        singleton path correctly).
        """
        self._activate()
        if self.is_default:
            from . import _bundle_for_recipient_impl
            return _bundle_for_recipient_impl(
                recipient_did, out_path, groups=groups
            )
        return self._bundle_for_recipient_per_ceremony(
            recipient_did, out_path, groups=groups
        )

    def _bundle_for_recipient_per_ceremony(
        self,
        recipient_did: str,
        out_path: Any,
        *,
        groups: list[str] | None,
    ) -> Any:
        """Per-ceremony version of ``bundle_for_recipient``.

        Mirrors the singleton-bound impl in ``_pkg_impl.py`` but reads
        from ``self.cfg`` instead of ``current_config()``. Splitting
        this out keeps the singleton path unchanged.
        """
        import tempfile
        from pathlib import Path as _Path

        from . import admin as _admin

        cfg = self.cfg
        if groups is None:
            requested = [g for g in cfg.groups if g != "tn.agents"]
        else:
            requested = list(dict.fromkeys(groups))

        if not requested:
            raise ValueError(
                "bundle_for_recipient: no groups to bundle. The ceremony "
                "has only the internal tn.agents group; declare a regular "
                "group via tn.ensure_group(...) first, or pass groups=[...]."
            )

        unknown = [g for g in requested if g not in cfg.groups]
        if unknown:
            raise ValueError(
                f"bundle_for_recipient: unknown groups {unknown!r}; this "
                f"ceremony declares {sorted(cfg.groups)}. Add them via "
                f"tn.ensure_group(cfg, name, fields=[...]) first."
            )

        with tempfile.TemporaryDirectory(prefix="tn-bundle-") as td:
            td_path = _Path(td)
            for gname in requested:
                kit_path = td_path / f"{gname}.btn.mykit"
                _admin.add_recipient(
                    gname,
                    recipient_did=recipient_did,
                    out_path=kit_path,
                    cfg=cfg,
                )

            from .export import export as _raw_export
            out = _raw_export(
                out_path,
                kind="kit_bundle",
                cfg=cfg,
                to_did=recipient_did,
                keystore=td_path,
                groups=requested,
            )
        return _Path(out)

    # ------------------------------------------------------------------
    # Vault verbs (link / unlink / push / pull)
    # ------------------------------------------------------------------

    def vault_link(self, client: Any, *, project_name: str | None = None) -> Any:
        """Link this ceremony to a vault project. See
        ``tn.wallet.link_ceremony`` for the underlying contract."""
        self._activate()
        from .wallet import link_ceremony as _link
        return _link(self.cfg, client, project_name=project_name)

    def vault_sync(self, client: Any) -> Any:
        """Push this ceremony's keystore + tn.yaml to its linked
        vault project. See ``tn.wallet.sync_ceremony``."""
        self._activate()
        from .wallet import sync_ceremony as _sync
        return _sync(self.cfg, client)

    def vault_push_snapshot(self, client: Any, **kwargs: Any) -> Any:
        """Push an admin-log snapshot to the vault.
        See ``tn.handlers.vault_push.push_snapshot``."""
        self._activate()
        from .handlers.vault_push import push_snapshot as _push
        return _push(cfg=self.cfg, client=client, **kwargs)

    def vault_pull_inbox(self, client: Any, **kwargs: Any) -> Any:
        """Pull this ceremony's inbox blobs from the vault and
        absorb them. See ``tn.handlers.vault_pull.pull_inbox``."""
        self._activate()
        from .handlers.vault_pull import pull_inbox as _pull
        return _pull(cfg=self.cfg, client=client, **kwargs)
