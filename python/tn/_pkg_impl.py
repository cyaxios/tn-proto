"""Pkg verbs: export, absorb, bundle_for_recipient implementations."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_logger = logging.getLogger("tn")
_surface = logging.getLogger("tn.surface")


def _export_impl(*args: Any, **kwargs: Any):
    """Build a ``.tnpkg`` from local ceremony state.

    Thin wrapper over ``tn.export.export``. Calls ``_maybe_autoinit()``
    so module-level use without an explicit ``tn.init()`` works the
    same way every other public verb does.
    """
    import tn
    from .export import export as _raw_export
    _surface.info(
        "tn.export(args=%d, kwargs=%s)", len(args), sorted(kwargs.keys()),
    )
    tn._maybe_autoinit_load_only()
    return _raw_export(*args, **kwargs)


def _absorb_impl(*args: Any, **kwargs: Any):
    """Absorb a `.tnpkg` and refresh the lazy admin LKV cache, if any.

    Thin wrapper over ``tn.absorb.absorb``: same call shapes, same return
    types, plus a best-effort post-write refresh so subsequent
    ``tn.admin.cache.cached_admin_state()`` calls observe the absorbed
    envelopes.
    """
    import tn
    from .absorb import absorb as _raw_absorb
    _surface.info(
        "tn.absorb(args=%d, kwargs=%s)", len(args), sorted(kwargs.keys()),
    )
    tn._maybe_autoinit_load_only()
    receipt = _raw_absorb(*args, **kwargs)
    tn._refresh_admin_cache_if_present()
    _surface.info(
        "tn.absorb returning kind=%r noop=%s accepted=%s deduped=%s",
        getattr(receipt, "kind", None),
        getattr(receipt, "noop", None),
        getattr(receipt, "accepted_count", None),
        getattr(receipt, "deduped_count", None),
    )
    return receipt


def _bundle_for_recipient_impl(
    recipient_did: str,
    out_path: str | Path,
    *,
    groups: list[str] | None = None,
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
        )
    return Path(out)
