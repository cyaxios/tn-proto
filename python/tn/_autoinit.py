"""Auto-init for tn — discovery chain + loud notice on auto-create.

Public entry point: ``maybe_autoinit()``. Called from every public verb in
``tn.__init__`` before it dereferences ``_dispatch_rt``. If a runtime is
already bound (someone called ``tn.init()`` explicitly, or we're inside a
``tn.session()`` context), this is a cheap no-op.

Discovery order (cwd-scoped; no implicit user-home attach):

    1. ``$TN_YAML``                       (env var, absolute or relative)
    2. ``./tn.yaml``                      (cwd, single-ceremony layout)
    3. ``./.tn/default/tn.yaml``          (cwd, legacy multi-ceremony layout)
    4. exactly one ``./.tn/<project>/tn.yaml`` project-root layout
    5. CREATE FRESH at ``./.tn/<cwd-name>/tn.yaml`` and emit a loud notice.

``$TN_HOME/tn.yaml`` is intentionally NOT in the chain: a project's tn
calls must scope to that project. To opt in to a user-home ceremony
explicitly, set ``TN_YAML=$TN_HOME/tn.yaml`` or call ``tn.init(<that
path>)`` directly.

Strict mode disables steps 2-5: ``TN_STRICT=1`` (env) or
``tn.set_strict(True)`` (Python). When strict is on and no explicit init
has happened, ``tn.log()`` raises ``RuntimeError`` exactly like today.

The loud notice prints once per Python process and once per auto-create
ceremony — silenced by ``TN_AUTOINIT_QUIET=1``.

This module never imports ``tn`` directly. It relies on the caller (the
package ``__init__``) to do the dispatch-runtime swap. Keeping this
loose-coupled means ``tn.__init__`` is the only place that owns
``_dispatch_rt`` mutation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

__all__ = [
    "is_strict",
    "maybe_autoinit",
    "reset_state_for_tests",
    "set_strict",
]

# Module-level state. ``_notice_printed`` is intentionally process-wide:
# the loud banner exists to inform a human, not a test runner — once per
# process is the right cadence even across multiple ceremonies. The
# helper ``reset_state_for_tests`` exists for test code that needs to
# observe a re-fire.
_notice_printed: bool = False
_strict_override: bool | None = None


def set_strict(enabled: bool) -> None:
    """Toggle strict mode in Python (overrides ``TN_STRICT``).

    ``True`` disables auto-init for the rest of this process.
    ``False`` re-enables it (overrides a ``TN_STRICT=1`` env var).
    """
    global _strict_override
    _strict_override = bool(enabled)


def is_strict() -> bool:
    """True iff auto-init is disabled. Honors the Python override first,
    falls through to ``TN_STRICT`` env var. ``TN_STRICT`` is truthy when
    its lowercased value is in {"1", "true", "yes", "on"}."""
    if _strict_override is not None:
        return _strict_override
    raw = os.environ.get("TN_STRICT", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def reset_state_for_tests() -> None:
    """Clear the once-per-process notice flag and the strict override.

    Test-only helper; production code should never call this. Without it,
    a test that exercises auto-create twice would only see the notice on
    the first run and miss the second branch.
    """
    global _notice_printed, _strict_override
    _notice_printed = False
    _strict_override = None


def _tn_home() -> Path:
    """Resolve ``$TN_HOME`` to a directory. Default: ``~/.tn``.

    Used verbatim whether set by env var or defaulted — one canonical
    location for every project on this machine. Run from a different
    directory and you get the same ceremony.
    """
    env = os.environ.get("TN_HOME", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".tn"


def _quiet() -> bool:
    raw = os.environ.get("TN_AUTOINIT_QUIET", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _emit_autoinit_notice(yaml_path: Path, did: str, was_created: bool) -> None:
    """Print the loud banner. ``was_created`` distinguishes the
    "I just minted a new identity" case (loud, banner-y) from the
    "loaded an existing one" case (currently silent — kept as a
    parameter so callers don't have to special-case the call site).
    """
    global _notice_printed
    if _notice_printed:
        return
    if not was_created:
        # Loading an existing ceremony is the happy path — no notice.
        # We still flip the flag so subsequent loads don't reconsider.
        _notice_printed = True
        return
    if _quiet():
        _notice_printed = True
        return

    cwd = str(Path.cwd().resolve())
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    banner = (
        "\n"
        "================================================================\n"
        "  TN: A NEW CEREMONY HAS BEEN CREATED\n"
        "================================================================\n"
        f"  Location:  {yaml_path}\n"
        f"  Identity:  {did}\n"
        f"  Created:   {now} (auto, because no existing\n"
        "             ceremony was found in the discovery chain)\n"
        "\n"
        "  This identity is unique to your current working directory:\n"
        f"      {cwd}\n"
        "\n"
        "  If you intended to USE AN EXISTING ceremony, stop the process\n"
        "  now and do ONE of the following:\n"
        "\n"
        "    1. Set TN_YAML=/path/to/existing/tn.yaml  (env var)\n"
        "    2. Call tn.init('/path/to/existing/tn.yaml') before tn.log()\n"
        "    3. Place a tn.yaml in the current working directory\n"
        "\n"
        "  If you intended to create a fresh ceremony, you can silence\n"
        "  this notice by either:\n"
        "\n"
        "    - Calling tn.init() explicitly (with this same path or a\n"
        "      different one), OR\n"
        "    - Setting TN_AUTOINIT_QUIET=1 in your environment.\n"
        "\n"
        "  This notice prints once per Python process.\n"
        "================================================================\n"
    )
    try:
        sys.stderr.write(banner)
        sys.stderr.flush()
    except (OSError, ValueError):
        # OSError covers broken pipes; ValueError covers writes to a closed stream.
        # If stderr is closed (rare; embedded interpreters), fall back to stdout.
        # The notice is informational; a write failure should never abort auto-init.
        try:
            sys.stdout.write(banner)
            sys.stdout.flush()
        except (OSError, ValueError):
            pass

    _notice_printed = True


def _resolve_project_ceremony_yaml() -> Path | None:
    """Find a project-named ceremony under ``<cwd>/.tn/`` (0.5.0a2 layout).

    The ``tn init <project>`` flow names the ceremony after the project
    (``.tn/<project>/tn.yaml``) rather than the legacy ``.tn/default/``.
    This resolver supports that layout for discovery:

      * If a ``default`` ceremony exists, it is NOT handled here (the
        caller checks ``.tn/default/`` first for back-compat).
      * If exactly one project ceremony exists, return it.
      * If multiple exist, return ``None`` (ambiguous — the caller falls
        through and the user must disambiguate via ``$TN_YAML``).

    Returns ``None`` when ``.tn/`` is absent or holds zero/many ceremonies.
    """
    from ._layout import ceremony_yaml_path, list_ceremonies_on_disk

    names = [n for n in list_ceremonies_on_disk() if n != "default"]
    if len(names) == 1:
        p = ceremony_yaml_path(names[0]).resolve()
        return p if p.exists() else None
    return None


def _resolve_existing_yaml() -> Path | None:
    """Walk the discovery chain LOAD-ONLY: return a yaml path that
    already exists, or ``None`` if no ceremony is found.

    Never creates a fresh ceremony. Used by read paths and admin verbs
    via ``_maybe_autoinit_load_only()`` — those operations need an
    existing ceremony to be meaningful, so silently minting one would
    surprise the caller.
    """
    if is_strict():
        return None
    env_yaml = os.environ.get("TN_YAML", "").strip()
    if env_yaml:
        p = Path(env_yaml).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        else:
            p = p.resolve()
        if p.exists():
            return p
    cwd_yaml = (Path.cwd() / "tn.yaml").resolve()
    if cwd_yaml.exists():
        return cwd_yaml
    multi_yaml = (Path.cwd() / ".tn" / "default" / "tn.yaml").resolve()
    if multi_yaml.exists():
        return multi_yaml
    # 0.5.0a2: project-named ceremony (`.tn/<project>/tn.yaml`) when no
    # `default` exists and exactly one project ceremony is on disk.
    project_yaml = _resolve_project_ceremony_yaml()
    if project_yaml is not None:
        return project_yaml
    # NOTE: $TN_HOME/tn.yaml is intentionally NOT in the auto-discovery
    # chain. A project's tn calls must scope to that project; the old
    # behavior (silently attaching to ~/.tn/tn.yaml from prior work)
    # corrupted the attestation guarantee for new users. To opt in to
    # a user-home ceremony explicitly, set TN_YAML=$TN_HOME/tn.yaml or
    # call tn.init(<that path>) directly.
    return None


def _resolve_discovery_yaml() -> tuple[Path, bool] | None:
    """Walk the discovery chain. Returns ``(path, was_created)`` if a
    ceremony was found or auto-created, ``None`` if strict mode blocks
    everything.

    The caller is responsible for actually invoking ``tn.init(path)``;
    this helper only locates the yaml. Splitting locate-from-load keeps
    the auto-init module independent of ``tn.logger``.
    """
    if is_strict():
        return None

    # Step 2: $TN_YAML
    env_yaml = os.environ.get("TN_YAML", "").strip()
    if env_yaml:
        p = Path(env_yaml).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        else:
            p = p.resolve()
        if p.exists():
            return (p, False)
        # $TN_YAML pointed at something that doesn't exist. Treat that
        # as user intent: create at exactly that path. Fresh ceremonies
        # under TN_YAML get the notice (the user named the location, but
        # the absence of the file is still surprising).
        p.parent.mkdir(parents=True, exist_ok=True)
        return (p, True)

    # Step 3: ./tn.yaml (legacy single-ceremony layout).
    cwd_yaml = (Path.cwd() / "tn.yaml").resolve()
    if cwd_yaml.exists():
        return (cwd_yaml, False)

    # Step 4: ./.tn/default/tn.yaml (legacy multi-ceremony layout).
    multi_yaml = (Path.cwd() / ".tn" / "default" / "tn.yaml").resolve()
    if multi_yaml.exists():
        return (multi_yaml, False)

    # Step 4b (0.5.0a2): project-root ceremony `.tn/<project>/tn.yaml`
    # when there's no `default` and exactly one project ceremony exists.
    project_yaml = _resolve_project_ceremony_yaml()
    if project_yaml is not None:
        return (project_yaml, False)

    # NOTE: $TN_HOME/tn.yaml is intentionally NOT in this chain. A
    # fresh `python script.py` in a project directory must scope to
    # that project — the prior behavior (silent attach to
    # ~/.tn/tn.yaml left over from earlier work) corrupted the
    # attestation guarantee for new users. To opt in to a user-home
    # ceremony explicitly, set TN_YAML=$TN_HOME/tn.yaml or call
    # tn.init(<that path>) directly.

    # Step 5: create fresh at ./.tn/<cwd-name>/tn.yaml — the Project-root
    # layout is the default for fresh projects.
    from ._layout import project_layout

    project_yaml = project_layout(project_dir=Path.cwd()).project_yaml.resolve()
    project_yaml.parent.mkdir(parents=True, exist_ok=True)
    return (project_yaml, True)


def maybe_autoinit_load_only() -> None:
    """Load-only auto-init: walk the discovery chain and bind a runtime
    if an EXISTING ceremony is found, but never mint a fresh one.

    Used by read paths (``tn.read``, ``tn.read_raw``, ``tn.read_all``,
    ``tn.secure_read``, ``tn.read_as_recipient``) and admin verbs
    (``add_recipient``, ``revoke_recipient``, ``recipients``, ``rotate``,
    ``admin_*``, ``cached_*``). These operations need an existing ceremony
    to be meaningful — silently minting one would surprise the caller.

    If no ceremony is found, raise ``RuntimeError`` with a friendly hint.
    """
    import tn as _tn

    if _tn._dispatch_rt is not None:
        return

    yaml_path = _resolve_existing_yaml()
    if yaml_path is None:
        raise RuntimeError(
            "tn: no ceremony found. Looked at $TN_YAML, ./tn.yaml, "
            "and ~/.tn/tn.yaml. Run `tn.init()` (or `tn.info(...)` to "
            "auto-create one), then retry."
        )
    _tn.init(yaml_path)


def maybe_autoinit() -> None:
    """If no explicit ``tn.init()`` has happened, run discovery and bind
    a runtime via ``tn.init()``. Loud notice fires when a new ceremony
    is minted.

    Strict mode short-circuits and lets the caller's
    ``_require_dispatch()`` raise its standard error. That keeps the
    error message identical to pre-auto-init behavior so callers that
    branch on it don't have to retest.
    """
    # Late import: ``tn`` imports this module at import time, so we
    # cannot import ``tn`` at module-load. Import inside the function.
    import tn as _tn

    if _tn._dispatch_rt is not None:
        return

    if is_strict():
        # Caller's _require_dispatch() will raise the standard
        # "tn.init(yaml_path) must be called before tn.log" error.
        return

    resolved = _resolve_discovery_yaml()
    if resolved is None:
        return
    yaml_path, was_created = resolved

    # Hand off to the regular init() so all the absorb/_reconcile/handler
    # plumbing fires exactly as it does for explicit init.
    #
    # Fresh auto-create must route through no-arg init so explicit init and
    # auto-init produce the same Project-root layout. Existing YAMLs and
    # explicit TN_YAML paths are still honored literally.
    from ._layout import project_layout

    cwd_project_yaml = project_layout(project_dir=Path.cwd()).project_yaml.resolve()
    if was_created and yaml_path == cwd_project_yaml:
        _tn.init()
    else:
        _tn.init(yaml_path)

    # Now read back the device DID and emit the notice. ``current_config``
    # raises if init failed; in that case we don't print the banner —
    # the underlying error is already on its way out.
    try:
        cfg = _tn.current_config()
        did = getattr(cfg.device, "did", "<unknown>")
    except RuntimeError:
        did = "<unknown>"
    _emit_autoinit_notice(yaml_path, did, was_created)
