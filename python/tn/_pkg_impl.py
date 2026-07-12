"""Pkg verbs: export, absorb, bundle_for_recipient implementations."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, overload

if TYPE_CHECKING:
    from .absorb import AbsorbReceipt, AbsorbResult
    from .config import LoadedConfig

_logger = logging.getLogger("tn")
_surface = logging.getLogger("tn.surface")


def _export_impl(*args: Any, **kwargs: Any):
    """Build a ``.tnpkg`` from local ceremony state.

    Thin wrapper over ``tn.export.export``. Calls ``_maybe_autoinit()``
    so module-level use without an explicit ``tn.init()`` works the
    same way every other public verb does. If the caller didn't pass
    ``cfg=``, fill it in from the active runtime so the kind-specific
    branches that need a config (``admin_log_snapshot``, ``offer``,
    ``enrolment``, ``kit_bundle``) work transparently.
    """
    import tn

    from .export import export as _raw_export
    _surface.info(
        "tn.export(args=%d, kwargs=%s)", len(args), sorted(kwargs.keys()),
    )
    tn._maybe_autoinit_load_only()
    if "cfg" not in kwargs:
        try:
            kwargs["cfg"] = tn.current_config()
        except RuntimeError:
            # current_config raises only when no init has happened; the
            # autoinit_load_only above would already have raised if
            # discovery failed. Fall through and let raw_export raise
            # its own argument-shape error (some kinds don't need cfg).
            pass
    return _raw_export(*args, **kwargs)


@overload
def _absorb_impl(source: Path | str | bytes | bytearray, /) -> AbsorbReceipt: ...
@overload
def _absorb_impl(
    cfg: LoadedConfig, source: Path | str | bytes | bytearray, /
) -> AbsorbResult: ...
@overload
def _absorb_impl(*, source: Path | str | bytes | bytearray) -> AbsorbReceipt: ...
@overload
def _absorb_impl(
    *, cfg: LoadedConfig, source: Path | str | bytes | bytearray
) -> AbsorbResult: ...
def _absorb_impl(*args: Any, **kwargs: Any) -> AbsorbReceipt | AbsorbResult:
    """Absorb a `.tnpkg` and refresh the lazy admin LKV cache, if any.

    Thin wrapper over ``tn.absorb.absorb``: same call shapes, same return
    types, plus a best-effort post-write refresh so subsequent
    ``tn.admin.cache.cached_admin_state()`` calls observe the absorbed
    envelopes.

    Dirt-easy bootstrap (the headline UX, see brief):

      * If the bundle is a self-contained bootstrap kind
        (``identity_seed`` / ``project_seed``) and no runtime is bound
        to this process yet, the underlying ``absorb()`` synthesizes a
        minimal ``LoadedConfig`` from cwd + the bundle's body/tn.yaml
        so the layout lands on disk without a prior ``tn.init()``.

      * Once the bootstrap absorb succeeds, this wrapper *automatically
        binds the runtime* to the freshly-absorbed ``./tn.yaml``. The
        caller can immediately do ``tn.info(...)`` / ``tn.read()``
        without an explicit ``tn.init()`` step.

      * If a runtime is already bound (the user called ``tn.init()``
        first), absorb stays in the existing safety logic — refuse to
        overwrite a populated ceremony, accept on a fresh one.
    """
    import tn

    from .absorb import absorb as _raw_absorb
    _surface.info(
        "tn.absorb(args=%d, kwargs=%s)", len(args), sorted(kwargs.keys()),
    )
    # Track whether we're on the "no runtime yet, bundle is self-contained
    # bootstrap" path so we can auto-init after absorb completes. Capture
    # the decision *before* calling absorb because absorb writes ./tn.yaml
    # to disk, which would change the autoinit-load-only decision after.
    is_pre_init_bootstrap = (
        tn._dispatch_rt is None and _is_bootstrap_kind_source(args, kwargs)
    )
    # Skip the load-only autoinit when no runtime is bound and the
    # bundle is a self-contained bootstrap kind: the underlying
    # absorb() synthesizes a cfg from cwd + body/tn.yaml.
    if not is_pre_init_bootstrap:
        # Try load-only first (preferred: bind an existing ceremony).
        # If none exists, fall back to the emit-style autoinit so the
        # caller can absorb a kit_bundle as their very first verb. The
        # standard autoinit banner fires when a fresh ceremony gets
        # minted, so the caller knows a new identity was created.
        try:
            tn._maybe_autoinit_load_only()
        except RuntimeError:
            from ._autoinit import maybe_autoinit as _maybe_autoinit
            _maybe_autoinit()
    receipt = _raw_absorb(*args, **kwargs)
    tn._refresh_admin_cache_if_present()

    # Implicit init on bootstrap absorb. After the layout has been
    # written to disk, bind the runtime to the freshly-absorbed yaml so
    # the user can immediately call tn.info / tn.read without a separate
    # tn.init step. Only fires when:
    #   - We took the no-prior-init bootstrap path above, AND
    #   - The absorb actually succeeded (accepted_count > 0 OR a noop).
    # On rejection we leave the runtime unbound; the caller can inspect
    # receipt.legacy_reason and decide what to do.
    if is_pre_init_bootstrap and getattr(receipt, "kind", None) in (
        "identity_seed",
        "project_seed",
    ):
        rejected = getattr(receipt, "legacy_status", None) == "rejected"
        if not rejected:
            try:
                _bind_after_bootstrap_absorb(receipt.kind)
            except Exception:
                # Best-effort: a follow-up failure to bind shouldn't
                # silently swallow the absorb result. Surface in the
                # logs but leave the receipt intact for the caller.
                _logger.exception(
                    "implicit init after bootstrap absorb failed; "
                    "call tn.init() explicitly to investigate"
                )

    _surface.info(
        "tn.absorb returning kind=%r noop=%s accepted=%s deduped=%s",
        getattr(receipt, "kind", None),
        getattr(receipt, "noop", None),
        getattr(receipt, "accepted_count", None),
        getattr(receipt, "deduped_count", None),
    )
    return receipt


def _bind_after_bootstrap_absorb(kind: str) -> None:
    """Implicit-init helper: bind the SDK runtime to a freshly-absorbed
    bootstrap layout in cwd.

    Behavior depends on the bundle kind:

    * ``project_seed`` ships a complete ``tn.yaml`` — load it directly.
    * ``identity_seed`` ships a *stub* yaml (just ``identity.did:``)
      that's not a loadable ceremony. Replace the stub with a fresh
      real ceremony yaml that adopts the absorbed identity, then load.
      This is the moral equivalent of "running ``tn init`` against a
      pre-existing keystore" — the keys came from the absorbed bundle,
      everything else (groups, cipher, log paths) is minted with safe
      defaults.

    Called from ``_absorb_impl`` only on the implicit-init path; never
    on rejection or when a runtime is already bound.
    """
    import tn

    from . import config as _config

    yaml_path = (Path.cwd() / "tn.yaml").resolve()
    if not yaml_path.exists():
        return

    if kind == "identity_seed":
        # Stub yaml from export_identity_seed has only ``identity.did``
        # — not a loadable ceremony. Promote it to a real one bound to
        # the just-installed device key.
        keystore = (yaml_path.parent / ".tn" / "tn" / "keys").resolve()
        priv_path = keystore / "local.private"
        if not priv_path.exists():
            # Defensive: identity_seed absorb should always land
            # local.private here; if it didn't, fall through to a
            # plain init attempt and let it raise the real error.
            tn.init(str(yaml_path))
            return
        seed_bytes = priv_path.read_bytes()
        # create_fresh refuses if local.private is already present;
        # delete the stub yaml + the keystore's keypair, then mint a
        # real ceremony with the absorbed seed. The keypair is
        # re-written by create_fresh (deterministic from the seed).
        try:
            yaml_path.unlink()
        except OSError:
            pass
        try:
            priv_path.unlink()
        except OSError:
            pass
        pub_path = keystore / "local.public"
        try:
            pub_path.unlink()
        except OSError:
            pass
        _config.create_fresh(yaml_path, device_private_bytes=seed_bytes)
        tn.init(str(yaml_path))
        return

    # project_seed and any future complete-yaml bootstrap kinds:
    # the absorbed yaml is loadable as-is.
    tn.init(str(yaml_path))


def _is_bootstrap_kind_source(args: tuple, kwargs: dict) -> bool:
    """Best-effort, manifest-only peek at the absorb source's kind, returning
    True iff this is an ``identity_seed`` or ``project_seed`` bundle —
    the two kinds for which absorb is allowed to bootstrap a fresh
    directory without an active runtime.

    Returns False on any error (in which case the caller falls through
    to the standard load-only autoinit).
    """
    from .tnpkg import _peek_manifest_kind

    if len(args) == 1 and not kwargs:
        source = args[0]
    elif "source" in kwargs:
        source = kwargs.get("source")
    else:
        return False
    if source is None or not isinstance(source, (Path, str, bytes, bytearray)):
        return False
    try:
        return _peek_manifest_kind(source) in ("identity_seed", "project_seed")
    except Exception:  # noqa: BLE001 — defensive: unparseable source is simply "not bootstrappable"
        return False


def _bundle_for_recipient_impl(
    recipient_did: str,
    out_path: str | Path,
    *,
    groups: list[str] | None = None,
    seal_for_recipient: bool = False,
) -> Path:
    """Mint a fresh kit for ``recipient_did`` across one or more groups and
    bundle them into a single ``.tnpkg`` at ``out_path``.

    Closes FINDINGS #5: doing this by hand requires (a) minting each kit
    with the canonical ``<group>.btn.mykit`` filename — a non-canonical
    name silently makes the export skip your kit and ship the publisher's
    own self-kit, which would let the recipient impersonate the publisher
    — and (b) routing ``export(kind="kit_bundle")`` at a temp keystore
    holding only those kits, NOT at the publisher's live keystore. This
    verb does both internally so the caller can't get either step wrong.

    ``groups`` defaults to every NON-internal group declared in the active
    ceremony (i.e. excludes ``tn.agents`` — that group is for LLM runtime
    bundles via :func:`admin.add_agent_runtime`, which adds ``tn.agents``
    on top of the requested set). Pass an explicit list to scope the kit
    bundle to a subset.

    Each requested group MUST already be declared in the ceremony's yaml
    (use :func:`ensure_group` first if not). A name that isn't a known
    group is rejected up front so we don't half-mint.

    Returns the absolute ``Path`` to the written ``.tnpkg``. The recipient
    runs ``tn.pkg.absorb(out_path)`` to install the kits into their keystore;
    afterwards ``tn.read_as_recipient(<publisher's log>, <their keystore>)``
    decrypts the publisher's log per group.
    """
    import tempfile

    import tn

    from . import admin as _admin
    from . import current_config

    tn._maybe_autoinit_load_only()

    cfg = current_config()

    if groups is None:
        # Default: every group except tn.agents (an internal LLM-policy
        # channel that doesn't make sense to ship to a human reader).
        requested = [g for g in cfg.groups if g != "tn.agents"]
    else:
        requested = list(dict.fromkeys(groups))  # preserve order, drop dupes

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

    # Mint each kit into a temp dir with the canonical filename, then
    # export from that temp dir. The publisher's own keystore is never
    # the export source, which prevents the FINDINGS #5 trap (shipping
    # the publisher's self-kit by accident).
    with tempfile.TemporaryDirectory(prefix="tn-bundle-") as td:
        td_path = Path(td)
        for gname in requested:
            kit_path = td_path / f"{gname}.btn.mykit"
            _admin.add_recipient(
                gname,
                recipient_did=recipient_did,
                out_path=kit_path,
            )

        out = _export_impl(
            out_path,
            kind="kit_bundle",
            cfg=cfg,
            to_did=recipient_did,
            keystore=td_path,
            groups=requested,
            seal_for_recipient=seal_for_recipient,
        )
    return Path(out)
