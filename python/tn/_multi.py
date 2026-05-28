"""Multi-ceremony module-level verbs: ``init``, ``use``, ``list_ceremonies``.

These are the public entry points for the multi-ceremony work. The
single-ceremony ``tn.init(yaml_path)`` form is preserved unchanged in
``tn.lifecycle`` for backwards compatibility; this module adds the
named-ceremony form on top.

Design rules (see ``docs/directory-layout.md``):

- ``init(name, ...)`` carries setup intent. Conflict-on-mismatch with
  on-disk YAML.
- ``use(name)`` carries usage intent. Get or create with safe defaults.
  Friendly: never raises ``TNNotFound`` for valid names.
- ``init()`` == ``init("default")``. ``use()`` == ``use("default")``.
- ``list_ceremonies()`` returns the in-process registry names.

The ``TN`` class itself lives in ``tn._handle``; the registry in
``tn._registry``; the layout helpers in ``tn._layout``; the safe
defaults in ``tn._defaults``.
"""

from __future__ import annotations

import contextlib
import difflib
import os
import time
from pathlib import Path
from typing import Any

import yaml as _yaml

from . import _profiles
from ._defaults import (
    DEFAULT_CEREMONY_NAME,
    safe_defaults_yaml,
)
from ._handle import TN
from ._layout import (
    TNInvalidName,
    ceremony_dir,
    ceremony_yaml_path,
    is_valid_ceremony_name,
    list_ceremonies_on_disk,
    migrate_legacy_layout,
    tn_root,
)
from ._registry import (
    TNNotFound as _TNNotFound,
    get as _registry_get,
    list_names as _registry_list_names,
    register as _registry_register,
    unregister as _registry_unregister,
)

__all__ = [
    "TNConfigConflict",
    "TNCreateFailed",
    "TNInvalidName",
    "init",
    "list_ceremonies",
    "use",
]


class TNConfigConflict(RuntimeError):
    """Raised when ``init`` kwargs contradict an on-disk ``tn.yaml``.

    The on-disk YAML is the durable evidence record. If your code
    disagrees with it, that is a bug, not a configuration knob.
    Resolve by updating the YAML by hand, or by re-creating the
    ceremony under a different name.
    """


class TNCreateFailed(RuntimeError):
    """Raised when on-disk creation of a ceremony directory fails."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _ceremony_create_lock(project_dir: Path | None, name: str):
    """Cross-process lock around ceremony creation.

    Mints a sentinel lock file at ``<project>/.tn/.init.<name>.lock``
    using ``O_CREAT | O_EXCL`` (atomic on POSIX and Windows). The first
    arrival wins and proceeds with creation; subsequent arrivals spin
    on a short sleep until either the yaml has appeared on disk
    (meaning the holder finished) or a 30s timeout fires.

    Stale-lock recovery: a lock file older than 60s is assumed to be
    abandoned (process crashed mid-init) and is reaped by the next
    arrival.

    Per-name scoping means concurrent inits of different ceremonies
    (e.g. ``default`` and ``billing`` from different workers) don't
    serialize on each other; only same-name races queue.

    DX review #1: closes the gunicorn/uvicorn-workers/celery race that
    silently corrupted ceremonies when multiple processes called
    ``tn.init()`` against an empty ``.tn/`` simultaneously. See
    DX_FIXES.md and tests/test_concurrent_init.py.
    """
    pdir = project_dir if project_dir is not None else Path.cwd()
    lock_dir = pdir / ".tn"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:  # pragma: no cover — surfaced by caller
        raise TNCreateFailed(
            f"could not create .tn/ for lock at {lock_dir}: {exc}"
        ) from exc
    lock_path = lock_dir / f".init.{name}.lock"
    yaml_path = ceremony_yaml_path(name, project_dir=project_dir)
    deadline = time.monotonic() + 30.0
    holding = False
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, f"pid={os.getpid()}\n".encode())
            finally:
                os.close(fd)
            holding = True
            break
        except FileExistsError:
            # Another process holds the lock. Three outcomes possible:
            #   1. They finished while we were spinning -> yaml present.
            #   2. They crashed -> stale lock; reap if older than 60s.
            #   3. They're still working -> sleep + retry.
            if yaml_path.is_file():
                # Race lost; the other process completed. Yield to
                # caller without holding the lock so they load.
                yield
                return
            try:
                age = time.time() - lock_path.stat().st_mtime
            except FileNotFoundError:
                # Lock vanished between FileExistsError and stat (the
                # other process just released). Retry immediately.
                continue
            if age > 60.0:
                # Stale; the holder probably crashed. Best-effort reap.
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() > deadline:
                raise TNCreateFailed(
                    f"timed out (30s) acquiring ceremony create lock at "
                    f"{lock_path}; another process appears stuck. If you "
                    f"are certain no other process is initialising this "
                    f"ceremony, delete {lock_path} and retry."
                )
            time.sleep(0.05)
    try:
        yield
    finally:
        if holding:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def _looks_like_yaml_path(arg: str) -> bool:
    """True iff ``arg`` looks like a legacy ``init(yaml_path)`` argument
    rather than a new-style registry name. Conservative: must end in
    ``.yaml`` or ``.yml``. A bare path-separator (``foo/bar``) is
    *not* enough: it could be a malformed ceremony name that should
    raise ``TNInvalidName``, and we want that error to surface rather
    than silently routing through the legacy yaml-path handler.
    """
    if not arg:
        return False
    return arg.endswith(".yaml") or arg.endswith(".yml")


def _ensure_ceremony_on_disk(
    name: str,
    *,
    project_dir: Path | None,
    device_did: str,
    cipher: str = "btn",
    profile: str | None = None,
    device_private_bytes: bytes | None = None,
    keystore_dir: Path | None = None,
    admin_log_path: Path | None = None,
    link: bool | None = None,
    as_root: bool = False,
) -> Path:
    """Create ``.tn/<name>/`` with a real, loadable ``tn.yaml`` if the
    directory does not already exist. Returns the yaml path.

    Two-mode behavior:

    * For the *default* ceremony, this calls ``config.create_fresh``
      to mint the project's identity + keystore. This is where the
      project's DID and signing key are born.

    * For *named streams*, this writes a lightweight yaml that
      references default's DID + keystore by relative path. No keys
      are minted, no per-stream device identity exists. Streams
      share project identity. If default does not yet exist, it is
      created first.

    Per-stream directories only contain ``logs/`` and ``admin/``
    (where the stream's own log and admin events are written). The
    ``keys/`` directory exists only at default; streams reference
    it via ``keystore.path: ../default/keys``.

    The ``device_did`` parameter is unused (kept for signature
    stability).
    """
    del device_did

    yaml_path = ceremony_yaml_path(name, project_dir=project_dir)
    if yaml_path.is_file():
        # 0.4.2a9: warn if the caller asked for a different profile
        # than the one stamped on the existing yaml. Profile is part
        # of a ceremony's identity — it controls signs / chains /
        # default_sink — and changing it after mint would invalidate
        # the on-disk log's verifiability. Silently honour the
        # original stamp; tell the operator (loudly) that their
        # second arg was a no-op.
        if profile is not None:
            import yaml as _yaml
            try:
                with yaml_path.open("r", encoding="utf-8") as fh:
                    existing = _yaml.safe_load(fh) or {}
                stamped = (existing.get("ceremony") or {}).get("profile")
                if stamped and stamped != profile:
                    import logging as _logging
                    _logging.getLogger("tn").warning(
                        "ceremony %r already minted with profile=%r; "
                        "requested profile=%r is ignored. Profile is "
                        "immutable per-ceremony; mint a new named "
                        "stream (`tn.init('<new_name>', profile=%r)`) "
                        "instead.",
                        name, stamped, profile, profile,
                    )
            except (_yaml.YAMLError, OSError):
                # Best-effort warning — don't block attach on a
                # transient read error.
                pass
        return yaml_path

    chosen_profile = profile or _profiles.DEFAULT_PROFILE
    if not _profiles.is_known(chosen_profile):
        raise TNCreateFailed(
            f"unknown profile {chosen_profile!r}; catalog: "
            f"{list(_profiles.all_profile_names())}"
        )

    # DX review #1: serialise concurrent creators of the same ceremony
    # across processes. Acquiring the lock and re-checking ``is_file``
    # closes the gunicorn/uvicorn-workers race that previously let
    # multiple workers each mint a fresh device DID, ending with an
    # on-disk yaml whose ``me.did`` did not match the keystore.
    with _ceremony_create_lock(project_dir, name):
        if yaml_path.is_file():
            # Another process finished while we waited; load that.
            return yaml_path
        if name == DEFAULT_CEREMONY_NAME or as_root:
            # `as_root` lets a project-named ceremony (0.5.0a2 layout,
            # `.tn/<project>/`) mint its own keystore instead of being a
            # stream that references `../default/keys`. The literal
            # "default" name keeps the same behaviour for back-compat.
            return _create_default_ceremony(
                name=name,
                yaml_path=yaml_path,
                project_dir=project_dir,
                cipher=cipher,
                profile=chosen_profile,
                device_private_bytes=device_private_bytes,
                keystore_dir_override=keystore_dir,
                admin_log_path_override=admin_log_path,
                link=link,
            )
        return _create_stream_yaml(
            name=name,
            yaml_path=yaml_path,
            project_dir=project_dir,
            profile=chosen_profile,
        )


def _create_default_ceremony(
    *,
    name: str,
    yaml_path: Path,
    project_dir: Path | None,
    cipher: str,
    profile: str,
    device_private_bytes: bytes | None = None,
    keystore_dir_override: Path | None = None,
    admin_log_path_override: Path | None = None,
    link: bool | None = None,
) -> Path:
    """Mint the project's default ceremony: identity, keystore,
    full yaml. The only place a TN device DID gets created.

    ``device_private_bytes`` seeds the device key from a known
    32-byte Ed25519 seed instead of generating a random one. Used by
    env-injected deploys (Lambda, k8s sealed-secrets).

    ``keystore_dir_override`` and ``admin_log_path_override`` let
    callers redirect those paths away from the default
    ``.tn/<name>/keys`` and ``.tn/<name>/admin/admin.ndjson``
    locations. Useful for shared volumes or encrypted filesystems.
    """
    ydir = ceremony_dir(name, project_dir=project_dir)
    try:
        ydir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TNCreateFailed(
            f"could not create ceremony directory {ydir}: {exc}"
        ) from exc

    for sub in ("keys", "logs", "admin", "vault"):
        (ydir / sub).mkdir(parents=True, exist_ok=True)

    keystore_dir_resolved = (
        keystore_dir_override
        if keystore_dir_override is not None
        else ydir / "keys"
    )
    admin_log_resolved = (
        admin_log_path_override
        if admin_log_path_override is not None
        else ydir / "admin" / "admin.ndjson"
    )

    try:
        from . import config as _config

        _config.create_fresh(
            yaml_path,
            cipher=cipher,
            device_private_bytes=device_private_bytes,
            keystore_dir=keystore_dir_resolved,
            log_path=ydir / "logs" / "tn.ndjson",
            admin_log_path=admin_log_resolved,
            link=link,
        )
    except Exception as exc:  # noqa: BLE001
        raise TNCreateFailed(
            f"could not create fresh ceremony at {yaml_path}: {exc}"
        ) from exc

    try:
        doc = _load_yaml_dict(yaml_path)
        ceremony_block = doc.setdefault("ceremony", {})
        ceremony_block["profile"] = profile
        # DX review #4 (signs) + profile audit (default_sink) +
        # 0.4.2a7 (chains): the profile catalog drives runtime
        # behaviour, not just yaml metadata. Axes wired here:
        #   * ``signs`` -> ``ceremony.sign`` (Rust runtime honours).
        #   * ``chains`` -> ``ceremony.chain`` (Rust runtime honours;
        #     when false skips the per-emit advisory lock + tail-scan
        #     + chain advance/commit, used by telemetry / secure_log).
        #   * ``default_sink`` -> handler list filter (stdout-sink
        #     profiles drop the file.rotating handler, matching what
        #     ``_create_stream_yaml`` already does for streams).
        # The last axis (``flush``) still needs Rust runtime support.
        try:
            prof = _profiles.get(profile)
        except KeyError:
            prof = None
        if prof is not None:
            ceremony_block["sign"] = prof.signs
            ceremony_block["chain"] = prof.chains
            if prof.default_sink == "stdout":
                # Drop the auto-declared file.rotating handler so this
                # ceremony is true stdout-only — matches the catalog
                # promise of "near-zero overhead vs Python's logging."
                doc["handlers"] = [
                    h for h in (doc.get("handlers") or [])
                    if not (isinstance(h, dict)
                            and h.get("kind") in ("file.rotating", "file"))
                ]
        with yaml_path.open("w", encoding="utf-8") as fh:
            _yaml.safe_dump(doc, fh, sort_keys=False)
    except OSError as exc:
        raise TNCreateFailed(
            f"could not stamp profile into {yaml_path}: {exc}"
        ) from exc
    return yaml_path


def _create_stream_yaml(
    *,
    name: str,
    yaml_path: Path,
    project_dir: Path | None,
    profile: str,
) -> Path:
    """Write a minimal per-stream yaml that references the default
    ceremony via ``extends:``.

    NOTE: Stream-yaml structure is also packed into ``full_keystore``
    (and vault-minted ``project_seed``) manifests by ``tn.export`` and
    restored verbatim by ``tn.absorb._restore_stream_yamls``. A schema
    change here needs to land in three places:
        1. this writer (for fresh local mints),
        2. the packer in ``export.py`` (still verbatim today),
        3. a migration step for older on-disk stream yamls.
    See ``docs/superpowers/specs/2026-05-12-cold-start-completeness-design.md``.

    Side effect: ensures the default ceremony exists first (creating
    it if absent), since named streams cannot exist without a project
    identity to anchor them to.

    The stream's yaml carries only what is *stream-specific*:

      * ``extends: ../default/tn.yaml`` — pulls in identity,
        keystore, groups, recipients from default at config-load time.
      * ``ceremony.id`` (per-stream chain identity)
      * ``ceremony.profile``
      * ``ceremony.sign`` (derived from profile)
      * ``ceremony.admin_log_location``
      * ``logs.path``
      * stream-specific ``handlers``

    Identity, keystore, groups, recipients, public_fields are NOT
    duplicated — they come from default via the loader's
    ``_resolve_extends`` pass. Operators editing default's groups
    automatically affect all streams; no drift, no manual sync.

    The stream directory contains only ``logs/`` and ``admin/`` —
    no ``keys/``.
    """
    default_yaml = ceremony_yaml_path(
        DEFAULT_CEREMONY_NAME, project_dir=project_dir
    )
    if not default_yaml.is_file():
        _ensure_ceremony_on_disk(
            DEFAULT_CEREMONY_NAME,
            project_dir=project_dir,
            device_did="",
            profile=_profiles.DEFAULT_PROFILE,
        )

    ydir = ceremony_dir(name, project_dir=project_dir)
    try:
        ydir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TNCreateFailed(
            f"could not create stream directory {ydir}: {exc}"
        ) from exc

    for sub in ("logs", "admin"):
        (ydir / sub).mkdir(parents=True, exist_ok=True)

    log_path = f"./logs/{name}.ndjson"
    admin_path = f"./admin/admin.ndjson"

    p = _profiles.get(profile)

    declared: list[dict[str, Any]] = []
    if p.default_sink == "file_rotating":
        declared.append(
            {
                "kind": "file.rotating",
                "name": "main",
                "path": log_path,
                "max_bytes": 5 * 1024 * 1024,
                "backup_count": 5,
                "rotate_on_init": False,
            }
        )
    # stdout is declared on every stream yaml so dev-time visibility
    # of emits matches the default ceremony's auto-stdout. Operators
    # silence per-stream by removing this entry; TN_NO_STDOUT=1 is
    # the env-level override. For telemetry (default_sink=stdout)
    # this is the only sink.
    declared.append({"kind": "stdout", "name": "stdout"})

    # Reference to default's yaml by relative path. ``extends:`` is
    # resolved at load time in ``config.load`` -> ``_resolve_extends``;
    # see directory-layout.md for the full merge semantics.
    extends_relpath = f"../{DEFAULT_CEREMONY_NAME}/tn.yaml"

    doc = {
        "extends": extends_relpath,
        "ceremony": {
            "id": _mint_stream_ceremony_id(name),
            "sign": p.signs,
            "chain": p.chains,
            "profile": profile,
            "admin_log_location": admin_path,
            "log_level": "debug",
        },
        "logs": {"path": log_path},
        "handlers": declared,
    }
    try:
        with yaml_path.open("w", encoding="utf-8") as fh:
            _yaml.safe_dump(doc, fh, sort_keys=False)
    except OSError as exc:
        raise TNCreateFailed(
            f"could not write stream yaml {yaml_path}: {exc}"
        ) from exc
    return yaml_path


def _merge_handlers_additive(
    declared: list[dict[str, Any]],
    inherited: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Strict-additive merge of handler lists.

    The stream's declared handlers come first; inherited handlers
    from the parent are appended unless their ``name`` (or, if
    name is missing, their ``kind``) collides with one already
    present. Strict-additive means no override: if the stream
    declared a ``stdout`` handler and the parent also has one,
    the stream's wins (it was declared first; the parent's is
    skipped at merge time, not subtracted from the parent's view
    of the world).

    Returns a fresh list; neither input is mutated.
    """
    out: list[dict[str, Any]] = list(declared)
    seen = {(h.get("name") or h.get("kind")) for h in out}
    for h in inherited:
        key = h.get("name") or h.get("kind")
        if key in seen:
            continue
        out.append(dict(h))
        seen.add(key)
    return out


def _mint_stream_ceremony_id(name: str) -> str:
    """Each stream has its own ceremony_id (which scopes its chain),
    even though it shares device identity with default. Format:
    ``stream_<name>_<short_hex>`` so it's recognizable at a glance.
    """
    import secrets
    return f"stream_{name}_{secrets.token_hex(3)}"


def _load_yaml_dict(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
    except OSError as exc:
        raise TNCreateFailed(f"could not read {path}: {exc}") from exc
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise TNConfigConflict(
            f"on-disk yaml at {path} is not a mapping; refusing to load."
        )
    return doc


def _check_no_conflict(
    yaml_path: Path,
    *,
    profile: str | None,
) -> None:
    """If the on-disk yaml exists and disagrees with code-supplied
    kwargs, log a warning and let the on-disk record win.

    Operator authority: the on-disk yaml is the source of truth — an
    operator who edited it has policy authority. If code says one
    thing and yaml says another, code yields. The warning surfaces
    the conflict so a developer running locally sees that their
    intent was overridden.

    The function validates that any code-supplied profile name is in
    the SDK catalog regardless of whether there's an on-disk conflict;
    a typo'd profile fails fast.
    """
    if profile is not None and not _profiles.is_known(profile):
        raise TNConfigConflict(
            f"unknown profile {profile!r}; catalog: "
            f"{list(_profiles.all_profile_names())}. "
            "Profiles are SDK-fixed; see tn._profiles for the catalog."
        )
    if not yaml_path.is_file():
        return
    if profile is None:
        return
    doc = _load_yaml_dict(yaml_path)
    on_disk = (doc.get("ceremony") or {}).get("profile")
    if on_disk is None:
        return
    if on_disk != profile:
        import logging as _log
        _log.getLogger("tn").warning(
            "profile conflict for %s: code requested %r, on-disk yaml "
            "specifies %r. Operator authority — yaml wins. To use the "
            "code-requested profile, edit the yaml or pick a different "
            "ceremony name.",
            yaml_path, profile, on_disk,
        )


def _device_did_for_create() -> str:
    """Best-effort device DID for stamping a fresh ceremony's
    safe-defaults. If a ceremony is already active in this process,
    reuse its device DID so all auto-created ceremonies share the
    process identity. Otherwise, fall back to a placeholder; the
    create-fresh path inside ``logger.create_fresh`` will replace it
    with the real DID at first init.

    Splitting this out keeps the safe-defaults template stamp-able
    without needing an active runtime — a property tests rely on.
    """
    try:
        from . import current_config as _current_config

        cfg = _current_config()
        did = getattr(cfg.device, "did", None)
        if isinstance(did, str) and did:
            return did
    except Exception:
        # current_config raises when no init has happened yet; that's
        # the normal first-create path. Fall through to placeholder.
        pass
    # Placeholder DID: clearly not a real key. Replaced on first init
    # via the existing fresh-ceremony pipeline. Using a recognisable
    # marker so an inspector who sees this in a yaml knows the
    # ceremony was not yet bound to a device.
    return "did:key:z6Mk_PENDING_DEVICE_BINDING"


def _new_handle(name: str, *, project_dir: Path | None) -> TN:
    return TN(
        name=name,
        yaml_path=ceremony_yaml_path(name, project_dir=project_dir),
        directory=ceremony_dir(name, project_dir=project_dir),
    )


def _maybe_migrate(project_dir: Path | None) -> None:
    """Migrate ``.tn/tn/`` -> ``.tn/default/`` if applicable.

    Best-effort: any failure here re-raises so the caller sees the
    ambiguous-state error rather than masking it. The migration itself
    is idempotent.
    """
    root = tn_root(project_dir)
    if not root.is_dir():
        return
    migrate_legacy_layout(project_dir=project_dir)


def _format_not_found(name: str, project_dir: Path | None) -> str:
    """Compose the friendly message body for a registry miss. Used
    when a strict lookup needs to fail loud (rare; ``use`` itself
    auto-creates instead)."""
    registered = _registry_list_names()
    on_disk = list_ceremonies_on_disk(project_dir)
    suggestions = difflib.get_close_matches(name, registered + on_disk, n=2, cutoff=0.6)
    bits = [
        f"no ceremony named {name!r} is registered in this process.",
        f"Registered ceremonies: {registered or '(none)'}.",
    ]
    if on_disk:
        bits.append(f"On disk under .tn/: {on_disk}.")
    if suggestions:
        bits.append(f"Did you mean: {suggestions}?")
    bits.append(
        f"To attach or create: tn.init({name!r}) or tn.use({name!r})."
    )
    return " ".join(bits)


# ---------------------------------------------------------------------------
# init() helpers — kept narrow and named so init() itself stays a
# coordinator. Each helper has one job and is independently testable.
# ---------------------------------------------------------------------------


def _resolve_init_aliases(
    *,
    name: str | Path | None,
    ceremony: str | None,
    yaml_path: str | Path | None,
    load: str | Path | None,
    device_private_bytes: bytes | None,
    device_seed: bytes | None,
    identity: Any,
) -> tuple[str | Path | None, str | Path | None, bytes | None]:
    """Resolve the three alias pairs the public signature exposes.

    Returns ``(name, yaml_path, device_private_bytes)`` after applying
    each alias and checking for mutual exclusion. Raises ``TypeError``
    if both names of a pair are passed, or if ``identity=`` and a raw
    seed are passed together (both seed the device key).
    """
    if ceremony is not None and name is not None:
        raise TypeError(
            "tn.init() got both 'name' and 'ceremony' — they're aliases; pass exactly one"
        )
    if ceremony is not None:
        name = ceremony

    if load is not None and yaml_path is not None:
        raise TypeError(
            "tn.init() got both 'yaml_path' and 'load' — they're aliases; pass exactly one"
        )
    if load is not None:
        yaml_path = load

    if device_seed is not None and device_private_bytes is not None:
        raise TypeError(
            "tn.init() got both 'device_private_bytes' and 'device_seed' — they're aliases; pass exactly one"
        )
    if device_seed is not None:
        device_private_bytes = device_seed

    if identity is not None and device_private_bytes is not None:
        raise TypeError(
            "tn.init() got both 'identity' and 'device_private_bytes' — pass exactly one (or neither)"
        )

    return name, yaml_path, device_private_bytes


def _store_project_tag(project: str | None) -> None:
    """Attach an informational project tag to the tn module.

    Stored as ``tn._current_project``. Future PR wires this to vault
    auto-attach + pending-claim. No-op when ``project`` is ``None``.
    """
    if project is None:
        return
    import tn as _tn_pkg
    _tn_pkg._current_project = project


def _stamp_project_labels(
    yaml_path: Path, project_name: str | None, version_name: str | None,
) -> None:
    """Stamp ``ceremony.project_name`` / ``ceremony.version_name`` into
    an existing yaml. No-op when both are None. Used by ``tn.init`` to
    record the operator-chosen vault label at mint time.

    Read-modify-write via PyYAML to preserve every other key as the
    init machinery left it.
    """
    if project_name is None and version_name is None:
        return
    import yaml as _yaml
    try:
        with yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh) or {}
    except OSError:
        return
    if not isinstance(doc, dict):
        return
    ceremony = doc.setdefault("ceremony", {})
    if not isinstance(ceremony, dict):
        return
    # Only set when missing — don't overwrite an existing operator
    # edit. Same shape as how ``_apply_profile_to_yaml`` treats the
    # profile field at re-init time.
    if project_name is not None and "project_name" not in ceremony:
        ceremony["project_name"] = project_name
    if version_name is not None and "version_name" not in ceremony:
        ceremony["version_name"] = version_name
    try:
        with yaml_path.open("w", encoding="utf-8") as fh:
            _yaml.safe_dump(doc, fh, sort_keys=False)
    except OSError:
        pass


def _build_legacy_kwargs(
    *,
    log_path: str | Path | None,
    pool_size: int,
    cipher: str,
    identity: Any,
    extra_handlers: Any,
    stdout: bool | None,
    link: bool | None,
    device_private_bytes: bytes | None,
    keystore_dir: str | Path | None,
    admin_log_path: str | Path | None,
) -> dict[str, Any]:
    """Collect the kwargs the legacy chain (``tn._init_impl`` →
    ``logger.build_runtime`` → ``config.create_fresh``) actually
    consumes. Only non-default values land in the dict so the legacy
    chain's own defaults still apply for omitted kwargs.
    """
    out: dict[str, Any] = {}
    if log_path is not None:
        out["log_path"] = log_path
    if pool_size != 4:
        out["pool_size"] = pool_size
    if cipher != "btn":
        out["cipher"] = cipher
    if identity is not None:
        out["identity"] = identity
    if extra_handlers is not None:
        out["extra_handlers"] = extra_handlers
    if stdout is not None:
        out["stdout"] = stdout
    if link is not None:
        out["link"] = link
    if device_private_bytes is not None:
        out["device_private_bytes"] = device_private_bytes
    if keystore_dir is not None:
        out["keystore_dir"] = keystore_dir
    if admin_log_path is not None:
        out["admin_log_path"] = admin_log_path
    return out


def _apply_stream(handle: TN, stream: str | None) -> TN:
    """If ``stream`` is set, open the named stream, rebind the module
    singleton to it, and return its handle; otherwise return ``handle``
    unchanged.

    Pattern used everywhere ``init`` returns: callers do
    ``return _apply_stream(handle, stream)``.

    The singleton rebind matters because ``tn.init(stream='foo')`` is
    documented as equivalent to "focus on foo for subsequent
    module-level calls." Without the rebind, ``tn.info(...)`` after
    init would still land in the default ceremony, contradicting the
    docstring and silently swallowing per-stream emits.
    """
    if stream is None:
        return handle
    # Route through the bind=True path so the module singleton
    # (_dispatch_rt) points at the stream's yaml. Subsequent
    # tn.info / tn.read at module level then address the stream.
    return _init_named_ceremony(
        name=stream,
        project_path=None,
        yaml_path=None,
        profile=None,
        legacy_kwargs={},
        bind=True,
    )


def _init_via_yaml_path(
    yaml_str: str, legacy_kwargs: dict[str, Any]
) -> TN:
    """Handle the legacy ``tn.init(yaml_path)`` shape.

    Routes through the single-ceremony legacy path. Binds the module
    singleton + registers a default handle pointing at the resolved
    yaml.
    """
    from . import _init_impl as _legacy_init

    _legacy_init(yaml_str, **legacy_kwargs)
    return _ensure_default_handle_for_legacy_init(yaml_path_arg=yaml_str)


def _init_via_discovery(
    *,
    project_path: Path | None,
    yaml_path: str | Path | None,
    profile: str | None,
    legacy_kwargs: dict[str, Any],
) -> TN:
    """Handle no-args ``tn.init()`` with the discovery chain.

    If the caller passed ``yaml_path=`` (or ``load=``), skip discovery
    entirely and use the default ceremony rooted at that yaml — same
    semantics as the original "explicit yaml override on the default
    ceremony" branch.

    Otherwise, if an existing yaml is found (``$TN_YAML`` /
    ``./tn.yaml`` / ``$TN_HOME/tn.yaml``) AND ``project_dir`` is not
    pinned, attach via the legacy path so the singleton binds.

    Falls back to minting ``.tn/default/`` under the right project
    root if nothing is on disk.
    """
    # Explicit yaml_path with no name → default ceremony rooted there.
    if yaml_path is not None:
        return _init_named_ceremony(
            name=DEFAULT_CEREMONY_NAME,
            project_path=project_path,
            yaml_path=yaml_path,
            profile=profile,
            legacy_kwargs=legacy_kwargs,
        )

    if project_path is None:
        from ._autoinit import _resolve_existing_yaml

        existing = _resolve_existing_yaml()
        if existing is not None:
            # 0.4.2a9: warn if the caller passed `profile=` but the
            # on-disk yaml has a different profile stamped. Profile
            # is immutable per-ceremony (see `tn.init` docstring);
            # the second-call profile arg is silently honored as a
            # no-op without this warning.
            _check_no_conflict(existing, profile=profile)
            return _init_via_yaml_path(str(existing), legacy_kwargs)

    # Nothing on disk yet (or project_dir is set) — mint the default
    # ceremony under the right project root.
    return _init_named_ceremony(
        name=DEFAULT_CEREMONY_NAME,
        project_path=project_path,
        yaml_path=None,
        profile=profile,
        legacy_kwargs=legacy_kwargs,
    )


def _init_named_ceremony(
    *,
    name: str,
    project_path: Path | None,
    yaml_path: str | Path | None,
    profile: str | None,
    legacy_kwargs: dict[str, Any],
    bind: bool = True,
) -> TN:
    """Handle the named-ceremony shape (``tn.init("payments")``).

    Validates the ceremony name, auto-migrates legacy layouts if any,
    honours an explicit ``yaml_path=`` override, otherwise mints
    ``.tn/<name>/`` via ``_ensure_ceremony_on_disk``.

    ``bind=True`` (the default and the ``tn.init(name=...)`` path)
    rebinds the module singleton onto this ceremony. ``bind=False``
    is for ``tn.use(name)`` which is the lazy attach-by-name flow:
    it returns a handle without disturbing whatever the module-level
    ``tn.info`` / ``tn.current_config`` are currently bound to.
    """
    if not isinstance(name, str) or not is_valid_ceremony_name(name):
        raise TNInvalidName(
            f"invalid ceremony name {name!r}: must match "
            "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved)."
        )

    _maybe_migrate(project_path)

    try:
        existing = _registry_get(name)
    except _TNNotFound:
        existing = None

    if yaml_path is not None:
        return _init_named_with_explicit_yaml(
            name=name,
            yaml_path=yaml_path,
            profile=profile,
            existing=existing,
            legacy_kwargs=legacy_kwargs,
            bind=bind,
        )

    return _init_named_default_layout(
        name=name,
        project_path=project_path,
        profile=profile,
        existing=existing,
        legacy_kwargs=legacy_kwargs,
        bind=bind,
    )


def _init_named_with_explicit_yaml(
    *,
    name: str,
    yaml_path: str | Path,
    profile: str | None,
    existing: TN | None,
    legacy_kwargs: dict[str, Any],
    bind: bool = True,
) -> TN:
    """Named ceremony with an explicit yaml-path override.

    The caller pinned a yaml location; we honour it and skip the
    default ``.tn/<name>/`` placement. Profile-conflict checks still
    apply against the on-disk yaml.

    ``bind`` controls whether the module singleton is rebound. ``True``
    on the ``tn.init(name=)`` path; ``False`` for ``tn.use(name)``.
    """
    explicit_yaml = Path(yaml_path).resolve()
    _check_no_conflict(explicit_yaml, profile=profile)

    if existing is not None:
        if bind:
            _bind_default_singleton(explicit_yaml, **legacy_kwargs)
        return existing

    handle = TN(
        name=name,
        yaml_path=explicit_yaml,
        directory=explicit_yaml.parent,
    )
    _registry_register(name, handle)
    if bind:
        # Last `tn.init(...)` call wins for module-level state.
        # Callers that want to keep an explicit handle to a non-
        # current ceremony retain the returned `TN` and use
        # `handle.info(...)`.
        _bind_default_singleton(explicit_yaml, **legacy_kwargs)
    return handle


def _init_named_default_layout(
    *,
    name: str,
    project_path: Path | None,
    profile: str | None,
    existing: TN | None,
    legacy_kwargs: dict[str, Any],
    bind: bool = True,
) -> TN:
    """Named ceremony mounted at the canonical ``.tn/<name>/`` location.

    Mints on disk if absent. With ``bind=True`` (the default, taken by
    the ``tn.init(name=...)`` path) the module singleton is rebound
    onto this ceremony so post-call ``tn.info(...)`` /
    ``tn.current_config()`` / ``tn.read(...)`` operate against it —
    last init wins, mirroring stdlib ``logging``. With ``bind=False``
    (the ``tn.use(name)`` path) the singleton is left alone; this
    is for the lazy attach-by-name flow that wants a handle without
    disturbing module-level state.
    """
    yaml_p = ceremony_yaml_path(name, project_dir=project_path)
    _check_no_conflict(yaml_p, profile=profile)

    if existing is not None:
        if bind:
            _bind_default_singleton(yaml_p, **legacy_kwargs)
        return existing

    if not yaml_p.is_file():
        # Single source of truth for on-disk layout.
        _ensure_ceremony_on_disk(
            name,
            project_dir=project_path,
            device_did=_device_did_for_create(),
            cipher=legacy_kwargs.get("cipher", "btn"),
            profile=profile,
            device_private_bytes=legacy_kwargs.get("device_private_bytes"),
            keystore_dir=(
                Path(legacy_kwargs["keystore_dir"])
                if "keystore_dir" in legacy_kwargs else None
            ),
            admin_log_path=(
                Path(legacy_kwargs["admin_log_path"])
                if "admin_log_path" in legacy_kwargs else None
            ),
            # DX review #5: ``link=False`` propagates all the way to
            # ``config.create_fresh`` which writes ``mode: local`` +
            # empty ``linked_vault`` into the yaml. The kwarg used to
            # be accepted silently and only suppress the post-init
            # auto-link prompt.
            link=legacy_kwargs.get("link"),
        )

    handle = _new_handle(name, project_dir=project_path)
    _registry_register(name, handle)
    if bind:
        _bind_default_singleton(yaml_p, **legacy_kwargs)
    return handle


# ---------------------------------------------------------------------------
# Public verbs
# ---------------------------------------------------------------------------


def init(
    name: str | Path | None = None,
    *,
    # ── existing public params (kept) ────────────────────────────
    yaml_path: str | Path | None = None,
    profile: str | None = None,
    project_dir: str | Path | None = None,
    # ── lifted out of **legacy_kwargs (now first-class) ──────────
    log_path: str | Path | None = None,
    pool_size: int = 4,
    cipher: str = "btn",
    identity: Any = None,
    extra_handlers: Any = None,
    stdout: bool | None = None,
    link: bool | None = None,
    # ── newly reachable from config.create_fresh ─────────────────
    device_private_bytes: bytes | None = None,
    keystore_dir: str | Path | None = None,
    admin_log_path: str | Path | None = None,
    # ── new name slots reserved for future behavior ──────────────
    project: str | None = None,
    version: str | None = None,
    stream: str | None = None,
    ceremony: str | None = None,
    load: str | Path | None = None,
    device_seed: bytes | None = None,
) -> TN:
    """Set up or attach to a TN ceremony and return its handle.

    The single public entry for building a TN runtime in this process.

    Common shapes
    -------------
    ``tn.init()``
        Walk the discovery chain (``$TN_YAML`` → ``./tn.yaml`` →
        ``./.tn/default/tn.yaml`` → ``$TN_HOME/tn.yaml``) and attach
        to whatever's found. If nothing is found, mint a fresh
        ``.tn/default/`` ceremony at the appropriate root.

    ``tn.init("payments")``
        Attach to the named ceremony at ``.tn/payments/``, minting
        if absent. **Side effect (DX review #14):** if no project
        default exists yet, this call ALSO mints
        ``.tn/default/`` to anchor the project identity. Named
        ceremonies are *streams* that share the project DID via
        ``extends: ../default/tn.yaml`` — they cannot exist
        without a default. See the "Project identity and named
        streams" section of the README for the architecture, and
        ``tn.init(yaml_path=...)`` if you want a truly
        self-contained ceremony at a custom location.

    ``tn.init("./tn.yaml")`` / ``tn.init(load="./tn.yaml")``
        Attach to the explicit yaml file (or mint it there).

    ``tn.init(name="my-app", stream="pod-1")``
        Attach to the default ceremony AND open a named stream in
        one call. Returns the stream's handle, not the default's.

    Parameters
    ----------
    name :
        Ceremony name (e.g. ``"payments"``) OR a yaml path (``Path``
        object, or a string ending in ``.yaml`` / ``.yml``). The
        only positional argument; everything else is keyword-only.
        See also ``ceremony=`` and ``load=`` for explicit keyword
        forms.

    yaml_path :
        Explicit yaml file location. Honored even when ``name`` is
        also passed. See also ``load=`` (alias).

    profile :
        Profile-defaults bundle stamped onto a fresh ceremony's yaml
        (``"transaction"`` / ``"audit"`` / ``"secure_log"`` /
        ``"telemetry"`` / ``"stdout"``).

        **Immutable per-ceremony.** Profile is part of a ceremony's
        identity: it controls ``sign`` / ``chain`` / ``default_sink``,
        all of which are stamped into the yaml and into every emit.
        Changing the profile after mint would invalidate the
        verifiability of the existing log. So when ``tn.init`` is
        called with a ``profile=`` arg against a ceremony that
        already exists, the new value is **ignored** — the original
        stamp wins. A warning is logged via ``logging.getLogger("tn")``
        when the requested profile differs from the stamped one.
        To run a different profile, mint a new named stream:
        ``tn.init("<new_name>", profile="<other>")``.

    project_dir :
        Explicit project root for the multi-ceremony layout. Pass to
        force ``.tn/<name>/`` placement under a non-cwd directory.

    log_path :
        Override the main log file location for a fresh ceremony,
        AND synthesize a single ``file.rotating`` handler at that
        path when the yaml has no ``handlers:`` block.

    pool_size :
        BTN broadcast tree pool size at fresh-mint time. Defaults to
        4. Btn-only; ignored for JWE ceremonies.

    cipher :
        Group-sealing cipher for a fresh ceremony: ``"btn"``
        (default) or ``"jwe"``. Ignored when loading an existing
        yaml (cipher comes from the yaml).

    identity :
        A ``tn.identity.Identity`` to seed the device key from. When
        minting fresh, the new ceremony binds to the identity's
        keypair; the DID written into ``tn.yaml`` matches. Ignored
        when loading. Mutually exclusive with ``device_seed=``.

    extra_handlers :
        Additional ``TNHandler`` instances to register on top of
        whatever the yaml declares. Used by tests and programmatic
        integrations.

    stdout :
        Force the stdout handler on/off. ``None`` (default) defers
        to ``TN_NO_STDOUT`` env (off when set).

    link :
        Post-init vault upload + claim URL surfacing.
        ``None`` (default) runs only inside an IPython/Jupyter/
        Databricks kernel. ``True`` forces; ``False`` blocks.
        Env opt-out: ``TN_NO_LINK=1``.

    device_private_bytes :
        Raw 32-byte Ed25519 seed for the device key at fresh-mint
        time. Useful for environments that inject the seed via secret
        manager (Lambda, k8s sealed-secrets, GitHub Actions) — read
        from env at startup and pass it here. Ignored when loading
        an existing yaml. Mutually exclusive with ``identity=`` and
        ``device_seed=``. See also ``device_seed=`` (alias).

    keystore_dir :
        Explicit keystore directory at fresh-mint time. Defaults to
        ``<yaml_dir>/.tn/<stem>/keys``. Override when the keystore
        needs to live outside the default ceremony layout (mounted
        volume, shared cache, encrypted filesystem). Ignored when
        loading.

    admin_log_path :
        Explicit admin log file location at fresh-mint time.
        Defaults to ``<yaml_dir>/.tn/<stem>/admin/admin.ndjson``.
        Override when admin events need to ship to a custom location
        (e.g., a shared audit volume). Ignored when loading.

    project :
        Vault project tag. Currently stored as informational metadata
        on the runtime; future releases will wire it to vault
        auto-attach + pending-claim flows. Pass to tag this runtime
        with a project name now so the future behavior picks it up
        without a code change.

    stream :
        Optional named stream. If set, after the ceremony runtime is
        up, run ``tn.use(stream)`` and return that handle instead of
        the default ceremony's. Equivalent to writing
        ``tn.init(...); return tn.use(stream)``.

    ceremony :
        Alias for ``name=``. If both are set, raises ``TypeError``.

    load :
        Alias for ``yaml_path=``. If both are set, raises
        ``TypeError``.

    device_seed :
        Alias for ``device_private_bytes=``. If both are set, raises
        ``TypeError``.

    Returns
    -------
    TN
        A handle to the ceremony (or stream, if ``stream=`` was
        passed). Subsequent calls in the same process are idempotent.

    Raises
    ------
    TypeError
        Unknown kwarg, or a duplicate-alias conflict.
    TNInvalidName
        ``name`` (or ``ceremony=``) is not a valid ceremony name.
    """
    # Resolve aliases + side effects + collect kwargs for the legacy chain.
    name, yaml_path, device_private_bytes = _resolve_init_aliases(
        name=name,
        ceremony=ceremony,
        yaml_path=yaml_path,
        load=load,
        device_private_bytes=device_private_bytes,
        device_seed=device_seed,
        identity=identity,
    )
    _store_project_tag(project)
    legacy_kwargs = _build_legacy_kwargs(
        log_path=log_path,
        pool_size=pool_size,
        cipher=cipher,
        identity=identity,
        extra_handlers=extra_handlers,
        stdout=stdout,
        link=link,
        device_private_bytes=device_private_bytes,
        keystore_dir=keystore_dir,
        admin_log_path=admin_log_path,
    )

    project_path = Path(project_dir) if project_dir is not None else None

    def _stamp_after_dispatch(handle: TN) -> TN:
        # 0.4.2a9: stamp project_name / version_name into the active
        # yaml after dispatch returns. Additive (no overwrite of an
        # existing field), idempotent on re-init. Re-loads the
        # singleton's cfg via a second init pass so the in-memory
        # LoadedConfig reflects the new fields immediately — required
        # for `wallet.link_ceremony` called in the same process to
        # pick up the operator-chosen label.
        if project is None and version is None:
            return handle
        try:
            from . import current_config
            cfg = current_config()
            yaml_p = Path(cfg.yaml_path)
        except Exception:  # noqa: BLE001
            return handle
        if not yaml_p.is_file():
            return handle
        before = (cfg.project_name, cfg.version_name)
        _stamp_project_labels(yaml_p, project, version)
        # Re-load only if the stamp actually changed something.
        # `_stamp_project_labels` is additive (no overwrite), so we
        # only reload when at least one field was previously None.
        if (project is not None and before[0] is None) or (
            version is not None and before[1] is None
        ):
            from . import _init_impl as _legacy_init  # noqa: PLC0415
            _legacy_init(str(yaml_p), **legacy_kwargs)
        return handle

    # Dispatch by call shape. Three shapes, each handled by a small helper.
    if isinstance(name, Path) or (
        isinstance(name, str) and _looks_like_yaml_path(name)
    ):
        # Legacy ``tn.init(yaml_path)`` style — Path or yaml-suffixed string.
        return _apply_stream(
            _stamp_after_dispatch(_init_via_yaml_path(str(name), legacy_kwargs)),
            stream,
        )

    if name is None:
        # No-args / discovery chain — find an existing yaml or mint default.
        # An explicit yaml_path= (or load=) overrides discovery.
        return _apply_stream(
            _stamp_after_dispatch(
                _init_via_discovery(
                    project_path=project_path,
                    yaml_path=yaml_path,
                    profile=profile,
                    legacy_kwargs=legacy_kwargs,
                ),
            ),
            stream,
        )

    # Named ceremony — ``tn.init("payments")`` or ``tn.init(name="x")``.
    #
    # DX review #14: the named-ceremony path ALSO mints ``.tn/default/``
    # if it doesn't exist yet. This is by design — named ceremonies
    # are *streams* that share the project's identity. The stream's
    # yaml carries ``extends: ../default/tn.yaml`` and the loader
    # pulls the device DID + signing key + groups + recipients from
    # default at config-load time. Removing the auto-create would
    # leave the stream unable to encrypt anything.
    #
    # If you want a truly self-contained ceremony with its own DID
    # (no shared identity, no .tn/default/), use the explicit
    # yaml_path= form instead:
    #
    #     tn.init(yaml_path="./standalone.yaml", cipher="btn")
    #
    # See the "Project identity and named streams" section of the
    # README for the architecture.
    return _apply_stream(
        _stamp_after_dispatch(
            _init_named_ceremony(
                name=name,
                project_path=project_path,
                yaml_path=yaml_path,
                profile=profile,
                legacy_kwargs=legacy_kwargs,
            ),
        ),
        stream,
    )



def use(
    name: str | None = None,
    *,
    profile: str | None = None,
    project_dir: str | Path | None = None,
) -> TN:
    """Get or create a TN handle by registry name.

    Looks up the in-process registry first; returns the handle if
    found. Falls through to disk attach (``.tn/<name>/`` exists with a
    yaml) and finally to safe-defaults auto-create.

    ``profile`` selects a ceremony profile (``transaction`` / ``audit``
    / ``secure_log`` / ``telemetry`` — see ``tn._profiles``). The
    profile is honored ONLY at creation time. If the named ceremony
    already exists on disk, the on-disk profile wins (operator
    authority); a code-supplied profile that disagrees is logged as a
    conflict warning. Registry-cached handles ignore ``profile``
    entirely — restart the process to re-bind under different
    settings.

    Friendly: for valid names, never raises ``TNNotFound``. The only
    failure modes are ``TNInvalidName`` (bad name) and
    ``TNCreateFailed`` (filesystem).
    """
    if name is None:
        name = DEFAULT_CEREMONY_NAME

    if not is_valid_ceremony_name(name):
        raise TNInvalidName(
            f"invalid ceremony name {name!r}: must match "
            "[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved)."
        )

    # Registry hit: nothing else to do. A code-supplied profile here
    # would have no effect (the handle is already bound), so we don't
    # surface a warning — common pattern is "use everywhere, pin the
    # profile once at the first call site or via the yaml."
    try:
        return _registry_get(name)
    except _TNNotFound:
        pass

    # Registry miss: defer to the same disk-attach-or-create code path
    # as ``init`` but with ``bind=False``. ``tn.use`` is the lazy
    # registry-attach verb; it returns a handle without disturbing
    # the module-level singleton. Callers that explicitly want their
    # named ceremony to BE the module-level singleton call
    # ``tn.init(name=...)`` instead.
    project_path = Path(project_dir).resolve() if project_dir is not None else None
    return _init_named_ceremony(
        name=name,
        project_path=project_path,
        yaml_path=None,
        profile=profile,
        legacy_kwargs={},
        bind=False,
    )


def list_ceremonies() -> list[str]:
    """Return the names of ceremonies registered in this process."""
    return _registry_list_names()


# ---------------------------------------------------------------------------
# Default-ceremony singleton bridge
#
# During this sprint, the default ceremony's emit/read still goes
# through the existing module-level singleton runtime (built by
# ``tn._init_impl``). The bridge below ensures that calling
# ``tn.init()`` (no args) or ``tn.init("default")`` also binds the
# singleton, so ``tn.info(...)`` keeps working without anyone having
# to know about both APIs.
# ---------------------------------------------------------------------------


def _bind_default_singleton(yaml_p: Path, **legacy_kwargs: Any) -> None:
    """Bind the legacy singleton to the supplied yaml. Idempotent if
    the singleton is already pointing at this yaml; otherwise this is
    a re-init (which the legacy code path supports).
    """
    from . import _init_impl as _legacy_init
    from . import current_config as _current_config

    try:
        cfg = _current_config()
        existing_yaml = Path(getattr(cfg, "yaml_path", "")).resolve()
        if existing_yaml == yaml_p.resolve():
            return  # already bound to this yaml
    except Exception:
        # No active runtime; fall through to init.
        pass
    _legacy_init(str(yaml_p), **legacy_kwargs)


def _ensure_default_handle_for_legacy_init(*, yaml_path_arg: str) -> TN:
    """Helper for the legacy-shim path in ``init``.

    The legacy ``tn.init(yaml_path)`` is a "fresh init" — repeated
    calls in the same process (typical test pattern) explicitly
    intend to replace prior state. If a prior default handle exists
    pointing at a different yaml, swap it out: unregister the old
    handle and register a new one that reflects the new yaml. The
    singleton itself was already swapped by ``_init_impl``; the
    registry just has to follow.

    Idempotent if the yaml hasn't changed: returns the existing
    handle as-is.
    """
    yp = Path(yaml_path_arg).resolve()
    try:
        existing = _registry_get(DEFAULT_CEREMONY_NAME)
    except _TNNotFound:
        existing = None
    if existing is not None and existing.yaml_path == yp:
        return existing
    if existing is not None:
        _registry_unregister(DEFAULT_CEREMONY_NAME)
    handle = TN(
        name=DEFAULT_CEREMONY_NAME,
        yaml_path=yp,
        directory=yp.parent,
    )
    _registry_register(DEFAULT_CEREMONY_NAME, handle)
    return handle
