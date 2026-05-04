"""Config loader for tn.lint.

Loads a project's ``tn.yaml``, resolves any ``extends:`` entries against
on-disk industry packs, merges groups and fields, and returns an immutable
:class:`LintConfig` for the rule engine to consume.

Resolution rules for an ``extends:`` entry::

    1. If the string contains '/' or ends in '.yaml', treat it as a path
       relative to the directory of tn.yaml.
    2. Otherwise treat it as a pack id and probe, in order:
         - <tn.yaml dir>/industry-agents/<id>.yaml
         - <tn.yaml dir>/packs/<id>.yaml
         - sibling repo: walks upward from tn.yaml (and from this source
           file as a final fallback) looking for either
           ``tn_proto_web/static/industry-agents/<id>.yaml`` or
           ``tn-proto-org/static/industry-agents/<id>.yaml``

Merge order: pack groups/fields are applied first, then the project's own
groups/fields override them. A project may NOT override the group of a
field marked ``forbidden_post_auth: true`` to a public-policy group --
that's a config error and surfaces as exit code 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class ConfigError(Exception):
    """Raised for any tn.yaml problem that warrants exit code 2."""


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #


# kwargs that the protocol reserves for itself; rules should not flag them.
RESERVED_KWARGS: frozenset[str] = frozenset(
    {
        "correlation_id",
        "request_id",
        "event_id",
        "level",
        "timestamp",
        "event_type",
    }
)

# tn.* method names that count as a "log call" for rule purposes.
TN_METHODS: frozenset[str] = frozenset(
    {"info", "warning", "error", "attest", "log"}
)


# --------------------------------------------------------------------------- #
# LintConfig
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LintConfig:
    """Immutable, fully-merged view of tn.yaml + extended packs.

    ``groups``: name -> {policy, rationale, ...}
    ``fields``: field name -> {group, spec_ref, forbidden_post_auth, ...}
    ``public_fields``: names that are always-public (project only).
    ``forbidden_post_auth``: union of field names flagged in any pack.
    ``known_field_names``: union of project + pack field names + public_fields,
        used by R2 to decide if a kwarg is "declared".
    """

    config_path: Path
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    public_fields: frozenset[str] = field(default_factory=frozenset)
    forbidden_post_auth: frozenset[str] = field(default_factory=frozenset)
    known_field_names: frozenset[str] = field(default_factory=frozenset)
    extends_loaded: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level YAML must be a mapping")
    return data


def find_config(start: Path) -> Path:
    """Search for tn.yaml from *start* upward to filesystem root."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while True:
        candidate = cur / "tn.yaml"
        if candidate.is_file():
            return candidate
        if cur.parent == cur:
            raise ConfigError(
                "no tn.yaml found searching upward from "
                f"{start}; pass --config to point at one"
            )
        cur = cur.parent


_SIBLING_PACK_DIRS: tuple[tuple[str, ...], ...] = (
    ("tn_proto_web", "static", "industry-agents"),
    ("tn-proto-org", "static", "industry-agents"),
)


def _iter_sibling_industry_dirs(base_dir: Path) -> list[Path]:
    """Walk up from ``base_dir`` (and from this source file) looking for
    a sibling repo's published industry-agents dir.

    The packs live in the sibling ``tn_proto_web`` / ``tn-proto-org``
    repo (https://github.com/cyaxios/tn-proto-org). Local clones may
    use either directory name. Returns every existing candidate.
    """
    candidates: list[Path] = []
    seen: set[Path] = set()

    starts: list[Path] = []
    try:
        starts.append(base_dir.resolve())
    except OSError:
        pass
    starts.append(Path(__file__).resolve().parent)

    for start in starts:
        cur = start
        while True:
            for parts in _SIBLING_PACK_DIRS:
                cand = cur.joinpath(*parts)
                rcand = cand if cand.exists() else None
                if rcand is None:
                    continue
                if rcand in seen:
                    continue
                seen.add(rcand)
                candidates.append(rcand)
            if cur.parent == cur:
                break
            cur = cur.parent
    return candidates


def _resolve_extends_entry(entry: str, base_dir: Path) -> Path:
    """Resolve one entry from ``extends:`` to a YAML file on disk."""
    if "/" in entry or "\\" in entry or entry.endswith(".yaml"):
        candidate = (base_dir / entry).resolve()
        if not candidate.is_file():
            raise ConfigError(f"extends path not found: {entry} (looked at {candidate})")
        return candidate

    probes: list[Path] = [
        base_dir / "industry-agents" / f"{entry}.yaml",
        base_dir / "packs" / f"{entry}.yaml",
    ]
    for sibling_dir in _iter_sibling_industry_dirs(base_dir):
        probes.append(sibling_dir / f"{entry}.yaml")
    for p in probes:
        if p.is_file():
            return p.resolve()
    paths = "\n  ".join(str(p) for p in probes)
    raise ConfigError(
        f"extends pack id '{entry}' not found; looked at:\n  {paths}"
    )


def _merge_pack(
    pack_data: dict[str, Any],
    *,
    groups: dict[str, dict[str, Any]],
    fields: dict[str, dict[str, Any]],
    forbidden: set[str],
    source: str,
) -> None:
    """Merge a single pack's groups/fields into the running maps."""
    pack_groups = pack_data.get("groups") or {}
    if not isinstance(pack_groups, dict):
        raise ConfigError(f"{source}: 'groups' must be a mapping")
    for gname, gdata in pack_groups.items():
        if not isinstance(gdata, dict):
            raise ConfigError(f"{source}: group '{gname}' must be a mapping")
        # First writer wins for groups; project will override after.
        groups.setdefault(gname, dict(gdata))

    pack_fields = pack_data.get("fields") or {}
    if not isinstance(pack_fields, dict):
        raise ConfigError(f"{source}: 'fields' must be a mapping")
    for fname, fdata in pack_fields.items():
        if not isinstance(fdata, dict):
            raise ConfigError(f"{source}: field '{fname}' must be a mapping")
        fields.setdefault(fname, dict(fdata))
        if fdata.get("forbidden_post_auth") is True:
            forbidden.add(fname)


def _public_policy_groups(groups: dict[str, dict[str, Any]]) -> set[str]:
    return {
        name
        for name, gdata in groups.items()
        if isinstance(gdata, dict) and gdata.get("policy") == "public"
    }


def load_config(
    config_path: Path | None,
    *,
    cwd: Path | None = None,
    use_extends: bool = True,
) -> LintConfig:
    """Load and merge tn.yaml + its extended packs."""
    if config_path is None:
        config_path = find_config(cwd or Path.cwd())
    config_path = config_path.resolve()
    if not config_path.is_file():
        raise ConfigError(f"config file does not exist: {config_path}")

    project = _read_yaml(config_path)
    base_dir = config_path.parent

    groups: dict[str, dict[str, Any]] = {}
    fields: dict[str, dict[str, Any]] = {}
    forbidden: set[str] = set()
    extends_loaded: list[str] = []

    extends_raw = project.get("extends") or []
    if use_extends and extends_raw:
        if not isinstance(extends_raw, list):
            raise ConfigError("extends: must be a list of pack ids or paths")
        for entry in extends_raw:
            if not isinstance(entry, str):
                raise ConfigError(f"extends entry must be a string: {entry!r}")
            pack_path = _resolve_extends_entry(entry, base_dir)
            pack_yaml = _read_yaml(pack_path)
            _merge_pack(
                pack_yaml,
                groups=groups,
                fields=fields,
                forbidden=forbidden,
                source=str(pack_path),
            )
            extends_loaded.append(entry)

    # Apply project groups (override pack-defined ones).
    proj_groups = project.get("groups") or {}
    if not isinstance(proj_groups, dict):
        raise ConfigError(f"{config_path}: 'groups' must be a mapping")
    for gname, gdata in proj_groups.items():
        if not isinstance(gdata, dict):
            raise ConfigError(
                f"{config_path}: group '{gname}' must be a mapping"
            )
        groups[gname] = dict(gdata)

    # Apply project fields. Enforce: cannot move a forbidden_post_auth field
    # into a group whose policy is public.
    proj_fields = project.get("fields") or {}
    if not isinstance(proj_fields, dict):
        raise ConfigError(f"{config_path}: 'fields' must be a mapping")
    for fname, fdata in proj_fields.items():
        if not isinstance(fdata, dict):
            raise ConfigError(
                f"{config_path}: field '{fname}' must be a mapping"
            )
        fields[fname] = {**fields.get(fname, {}), **dict(fdata)}

    public_groups = _public_policy_groups(groups)
    for fname in forbidden:
        spec = fields.get(fname, {})
        if spec.get("group") in public_groups:
            raise ConfigError(
                f"{config_path}: field '{fname}' is marked "
                "forbidden_post_auth in an extended pack but the project "
                f"reassigns it to a public-policy group "
                f"'{spec.get('group')}' -- this is not allowed"
            )

    # Public fields list (project-only).
    pf_list: Iterable[Any] = project.get("public_fields") or []
    if not isinstance(pf_list, list):
        raise ConfigError(f"{config_path}: 'public_fields' must be a list")
    public_fields = frozenset(str(x) for x in pf_list)

    known = set(fields.keys()) | set(public_fields) | RESERVED_KWARGS
    return LintConfig(
        config_path=config_path,
        groups=groups,
        fields=fields,
        public_fields=public_fields,
        forbidden_post_auth=frozenset(forbidden),
        known_field_names=frozenset(known),
        extends_loaded=tuple(extends_loaded),
    )
