"""``tn show`` — reflective inspection verbs (env catalog + profile catalog).

`tn show env` reflects the canonical TN_* environment surface (the _ENV_SCHEMA
inventory below); `tn show profiles` renders the SDK profile catalog. Read-only:
these verbs never install env-var behavior, they report what is already wired.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import _autoinit, _profiles
from . import config as _config
from .cli_common import _die

# ---------------------------------------------------------------------
# `tn show env` — reflective env-var inventory
# ---------------------------------------------------------------------
#
# Source of truth is ``_ENV_SCHEMA`` below — what the CLI reflects at
# runtime. Adding a new env-var read in ``tn/`` means adding a row here.
# The ``read_today`` field controls whether a row shows up as a
# live environment knob or a *(proposed)* future binding.
#
# Reflective-only by design: this verb does NOT install any new env-var
# behavior. It reads what's already wired and prints. YAML-sourced rows
# (``yaml_field`` set) are best-effort: the verb tries to load the
# auto-discovered ceremony to fill in current values, but a missing /
# unparseable yaml is non-fatal — those cells just render ``(unset)``.

# Categories used for the human table. Order matters — we render in
# this sequence.
_ENV_CATEGORIES: tuple[str, ...] = (
    "identity",
    "vault",
    "ceremony",
    "runtime",
    "logging",
    "deployment",
    "handlers",
)


# Each entry: name, category, purpose, read_today flag, default-string,
# secret flag, precedence string, and an optional yaml_field for rows
# whose authoritative value lives in tn.yaml today.
#
# ``read_today`` carries the file:line of the first authoritative read
# when wired, or ``None`` when this is a *(proposed)* future binding.
_ENV_SCHEMA: tuple[dict[str, Any], ...] = (
    # -- identity -----------------------------------------------------
    {
        "name": "TN_IDENTITY_DIR",
        "category": "identity",
        "purpose": "Override the directory holding identity.json.",
        "read_today": "tn/identity.py:97",
        "default": "OS data dir + /tn",
        "secret": False,
        "precedence": "env > XDG_DATA_HOME > APPDATA > home",
    },
    {
        "name": "XDG_DATA_HOME",
        "category": "identity",
        "purpose": "POSIX user-data root; TN appends /tn.",
        "read_today": "tn/identity.py:100",
        "default": "~/.local/share",
        "secret": False,
        "precedence": "TN_IDENTITY_DIR > env > home",
    },
    {
        "name": "APPDATA",
        "category": "identity",
        "purpose": "Windows roaming profile root; TN appends \\tn.",
        "read_today": "tn/identity.py:104",
        "default": "~/AppData/Roaming",
        "secret": False,
        "precedence": "TN_IDENTITY_DIR > XDG_DATA_HOME > env > home",
    },
    {
        "name": "TN_IDENTITY_DID",
        "category": "identity",
        "purpose": "Pin which DID this process uses when multiple identities are on disk.",
        "read_today": None,
        "default": "first identity in TN_IDENTITY_DIR",
        "secret": False,
        "precedence": "env > implicit-single-identity",
    },
    # -- vault --------------------------------------------------------
    {
        "name": "TN_VAULT_URL",
        "category": "vault",
        "purpose": "Base URL for the cloud vault (auth, sealed blobs, projects).",
        "read_today": "tn/vault_client.py:49",
        "default": "https://vault.tn-proto.org",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_VAULT_DEFAULT_BASE",
        "category": "vault",
        "purpose": "Base for did:web identity vault discovery.",
        "read_today": "tn/identity.py:410",
        "default": "https://vault.tn-proto.org",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_VAULT_PROJECT_ID",
        "category": "vault",
        "purpose": "Pin the linked vault project id.",
        "read_today": None,
        "default": "from yaml: linked_project_id",
        "secret": False,
        "precedence": "env > yaml > unset",
        "yaml_field": "linked_project_id",
    },
    {
        "name": "TN_VAULT_SESSION_TOKEN",
        "category": "vault",
        "purpose": "Pre-auth session token for non-interactive vault calls "
        "(legacy alias: TN_VAULT_JWT).",
        "read_today": "tn/vault_client.py:for_identity",
        "default": "challenge/verify on demand",
        "secret": True,
        "precedence": "arg > TN_VAULT_SESSION_TOKEN > TN_VAULT_JWT > challenge",
    },
    {
        "name": "TN_API_KEY",
        "category": "vault",
        "purpose": "Cold-start bootstrap bearer (tn_apikey_<seed>_<key_id>): on "
        "a fresh node, provisions the keystore from the sealed bundle.",
        "read_today": "tn/bootstrap.py:228",
        "default": "unset",
        "secret": True,
        "precedence": "env (handler-builder cold-start)",
    },
    {
        "name": "TN_ACCOUNT_PASSPHRASE",
        "category": "vault",
        "purpose": "Account recovery passphrase; derives the backup key (AWK) "
        "that wraps the keystore backup.",
        "read_today": "tn/cli.py (wallet sync / account connect / auth)",
        "default": "unset (else --account-passphrase or prompt)",
        "secret": True,
        "precedence": "flag (--account-passphrase) > env",
    },
    {
        "name": "TN_VAULT_TIMEOUT",
        "category": "vault",
        "purpose": "HTTP timeout (seconds) for the vault client.",
        "read_today": None,
        "default": "30.0",
        "secret": False,
        "precedence": "env > default",
    },
    # -- ceremony / config -------------------------------------------
    {
        "name": "TN_YAML",
        "category": "ceremony",
        "purpose": "Explicit path to tn.yaml for autoinit / discovery.",
        "read_today": "tn/_autoinit.py:180",
        "default": "discovery chain",
        "secret": False,
        "precedence": "env > ./tn.yaml > $TN_HOME/tn.yaml > mint-fresh",
    },
    {
        "name": "TN_HOME",
        "category": "ceremony",
        "purpose": "Root for shared TN state; holds tn.yaml when minted fresh.",
        "read_today": "tn/_autoinit.py:89",
        "default": "~/.tn",
        "secret": False,
        "precedence": "env > home fallback",
    },
    {
        "name": "TN_STRICT",
        "category": "ceremony",
        "purpose": "Block ceremony auto-discovery; init() needs an explicit yaml.",
        "read_today": "tn/_autoinit.py:66",
        "default": "unset (autodiscover allowed)",
        "secret": False,
        "precedence": "python override > env > default",
    },
    {
        "name": "TN_RUN_ID",
        "category": "ceremony",
        "purpose": "Run id shared between Python and Rust runtimes; stamped on envelopes.",
        "read_today": "tn/__init__.py:209 (write)",
        "default": "minted per tn.init()",
        "secret": False,
        "precedence": "parent env > minted",
    },
    {
        "name": "TN_AUTOINIT_QUIET",
        "category": "ceremony",
        "purpose": "Silence the loud autoinit / fresh-ceremony banner.",
        "read_today": "tn/_autoinit.py:96",
        "default": "unset (banner on)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_CEREMONY_ID",
        "category": "ceremony",
        "purpose": "Pin the ceremony id without round-tripping through tn.yaml.",
        "read_today": None,
        "default": "from yaml: ceremony.id",
        "secret": False,
        "precedence": "env > yaml",
        "yaml_field": "ceremony_id",
    },
    # -- runtime / dispatch ------------------------------------------
    {
        "name": "TN_FORCE_PYTHON",
        "category": "runtime",
        "purpose": "Disable the Rust extension; pure-Python emit/read paths.",
        "read_today": "tn/_dispatch.py:43",
        "default": "unset (Rust if available)",
        "secret": False,
        "precedence": "env > available-extension",
    },
    {
        "name": "TN_READER_LEGACY",
        "category": "runtime",
        "purpose": "Revert tn.read to legacy flat-tuple shape (pre-WS-G).",
        "read_today": "tn/reader.py:42",
        "default": "unset (new shape)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_CLAIM_ON_MISSING_IDENTITY",
        "category": "runtime",
        "purpose": "Auto-claim a fresh identity if init's yaml DID isn't on disk.",
        "read_today": "tn/logger.py:430",
        "default": "unset (raise IdentityError)",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_WALLET_AUTOSYNC",
        "category": "runtime",
        "purpose": "After every emit, push the new envelope to the linked vault.",
        "read_today": "tn/admin/__init__.py:537",
        "default": "unset (manual sync)",
        "secret": False,
        "precedence": "env > default",
    },
    # -- logging / observability -------------------------------------
    {
        "name": "TN_NO_STDOUT",
        "category": "logging",
        "purpose": "Suppress the default-on stdout JSON envelope mirror.",
        "read_today": "tn/logger.py:542",
        "default": "unset (stdout handler attached)",
        "secret": False,
        "precedence": "explicit arg > env > default",
    },
    {
        "name": "TN_SURFACE_LOG",
        "category": "logging",
        "purpose": "File path: append every public-API ENTER/EXIT to this file.",
        "read_today": "tn/__init__.py:88",
        "default": "unset (no surface log)",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_LOG_PATH",
        "category": "logging",
        "purpose": "Override logs.path (main log file destination).",
        "read_today": None,
        "default": "from yaml: logs.path",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "log_path",
    },
    {
        "name": "TN_ADMIN_LOG_PATH",
        "category": "logging",
        "purpose": "Override admin.log path (admin / state ndjson).",
        "read_today": None,
        "default": "./.tn/<stem>/admin/default.ndjson",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "admin_log_location",
    },
    {
        "name": "TN_LOG_LEVEL",
        "category": "logging",
        "purpose": "Surface logger verbosity (info / debug / trace).",
        "read_today": None,
        "default": "info",
        "secret": False,
        "precedence": "env > default",
    },
    {
        "name": "TN_DEBUG",
        "category": "logging",
        "purpose": "Master debug switch — enable verbose internal traces.",
        "read_today": None,
        "default": "unset",
        "secret": False,
        "precedence": "env > default",
    },
    # -- deployment / storage ---------------------------------------
    {
        "name": "TN_STATE_DIR",
        "category": "deployment",
        "purpose": "Override the per-user state dir (sync-failure queue, etc.).",
        "read_today": "tn/admin/__init__.py:570",
        "default": "XDG_STATE_HOME/tn or %APPDATA%/tn",
        "secret": False,
        "precedence": "env > XDG_STATE_HOME > APPDATA > home",
    },
    {
        "name": "XDG_STATE_HOME",
        "category": "deployment",
        "purpose": "POSIX user-state root; TN appends /tn.",
        "read_today": "tn/admin/__init__.py:574",
        "default": "~/.local/state",
        "secret": False,
        "precedence": "TN_STATE_DIR > env > home",
    },
    {
        "name": "TN_CACHE_DIR",
        "category": "deployment",
        "purpose": "Override cache root (admin state cache, manifest cache).",
        "read_today": None,
        "default": "derived from yaml dir",
        "secret": False,
        "precedence": "env > yaml > default",
    },
    {
        "name": "TN_KEYS_DIR",
        "category": "deployment",
        "purpose": "Override keys/ path (per-group keys).",
        "read_today": None,
        "default": "from yaml: ./keys/",
        "secret": False,
        "precedence": "env > yaml > default",
        "yaml_field": "keystore",
    },
    {
        "name": "TN_OUTBOX_DIR",
        "category": "deployment",
        "purpose": "Override durable outbox root (durable handler queue).",
        "read_today": None,
        "default": "./.tn/outbox/durable",
        "secret": False,
        "precedence": "env > yaml > default",
    },
    # -- handlers (env:NAME indirection) -----------------------------
    {
        "name": "TN_KAFKA_BOOTSTRAP",
        "category": "handlers",
        "purpose": "Kafka handler bootstrap.servers.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_KAFKA_USERNAME",
        "category": "handlers",
        "purpose": "SASL username for Kafka handler.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_KAFKA_PASSWORD",
        "category": "handlers",
        "purpose": "SASL password for Kafka handler.",
        "read_today": "tn/handlers/kafka.py:26 (indirect)",
        "default": "none",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_ENDPOINT",
        "category": "handlers",
        "purpose": "S3 handler endpoint URL (e.g. MinIO / R2).",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_BUCKET",
        "category": "handlers",
        "purpose": "Destination bucket for the S3 handler.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_ACCESS_KEY_ID",
        "category": "handlers",
        "purpose": "S3 access key id.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default chain",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_S3_SECRET_ACCESS_KEY",
        "category": "handlers",
        "purpose": "S3 secret access key.",
        "read_today": "tn/handlers/s3.py:46 (indirect)",
        "default": "AWS default chain",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_DELTA_TOKEN",
        "category": "handlers",
        "purpose": "Databricks Delta personal access token.",
        "read_today": "tn/handlers/delta.py:63 (indirect)",
        "default": "none",
        "secret": True,
        "precedence": "yaml > env-indirect",
    },
    {
        "name": "TN_DELTA_HOST",
        "category": "handlers",
        "purpose": "Databricks workspace host.",
        "read_today": "tn/handlers/delta.py:63 (indirect)",
        "default": "none",
        "secret": False,
        "precedence": "yaml > env-indirect",
    },
)


def _resolve_yaml_values() -> dict[str, str]:
    """Best-effort: load the auto-discovered ceremony and pull yaml-sourced
    fields so ``tn show env`` can render them as ``(from yaml: ...)``.

    Returns an empty dict when no ceremony is reachable. Never raises —
    a malformed yaml or missing keystore must not break the inventory
    output.
    """
    out: dict[str, str] = {}
    try:
        path = _autoinit._resolve_existing_yaml()
        if path is None:
            return out
        # Load yaml without env substitution failures masking the call:
        # if any required env-var ref is missing, _substitute_env_vars
        # raises ValueError. Treat that as "yaml unavailable".
        try:
            cfg = _config.load(path)
        except Exception:  # noqa: BLE001 — any config-load error => yaml unavailable
            return out
        out["ceremony_id"] = cfg.ceremony_id
        out["log_path"] = str(cfg.resolve_log_path())
        out["admin_log_location"] = cfg.admin_log_location
        out["keystore"] = str(cfg.keystore)
        if cfg.linked_project_id:
            out["linked_project_id"] = cfg.linked_project_id
        if cfg.linked_vault:
            out["linked_vault"] = cfg.linked_vault
    except Exception:  # noqa: BLE001 — defensive: discovery error must not break the verb
        return out
    return out


def _redact(value: str) -> str:
    """Render a secret value as ``*** (length: N)`` for human display."""
    return f"*** (length: {len(value)})"


def _resolve_entry_value(
    entry: dict[str, Any],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> tuple[str, str]:
    """Return ``(value, source)`` for one schema row.

    ``source`` is one of ``"env"``, ``"yaml"``, ``"unset"``. ``"unset"`` carries
    the row's documented default in parentheses for human display.
    """
    name = entry["name"]
    if name in env and env[name] != "":
        return env[name], "env"
    yaml_field = entry.get("yaml_field")
    if yaml_field and yaml_field in yaml_vals:
        return yaml_vals[yaml_field], "yaml"
    return "", "unset"


def _render_human(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> str:
    lines: list[str] = []
    lines.append("# tn show env — canonical TN_* environment surface")
    lines.append("# Reflective only. Secrets are redacted; use --format=env to paste.")
    lines.append("")
    by_cat: dict[str, list[dict[str, Any]]] = {c: [] for c in _ENV_CATEGORIES}
    for entry in schema:
        by_cat.setdefault(entry["category"], []).append(entry)

    name_w = max(len(e["name"]) for e in schema)
    val_w = 28

    for cat in _ENV_CATEGORIES:
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        lines.append(f"## {cat}")
        lines.append("")
        for entry in rows:
            value, source = _resolve_entry_value(entry, env, yaml_vals)
            proposed = entry.get("read_today") is None
            if source == "unset":
                shown = "(unset)"
                tail = f"  default: {entry['default']}"
            else:
                if entry.get("secret") and value:
                    shown = _redact(value)
                else:
                    shown = value if value else "(empty)"
                if source == "yaml":
                    tail = f"  (from yaml: {entry.get('yaml_field')})"
                else:
                    tail = ""
            tags = " (proposed)" if proposed else ""
            lines.append(
                f"  {entry['name']:<{name_w}}  {shown:<{val_w}}{tail}"
            )
            lines.append(
                f"  {'':<{name_w}}  {entry['purpose']}{tags}"
            )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_env_format(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
) -> str:
    """Bash-style block: ``TN_FOO=value`` per line, secrets fully present.

    Only emits rows with a resolvable value (env or yaml). Unset rows are
    skipped so the output is paste-able straight into a shell or .env file.
    """
    out_lines: list[str] = []
    for entry in schema:
        value, source = _resolve_entry_value(entry, env, yaml_vals)
        if source == "unset":
            continue
        out_lines.append(f"{entry['name']}={value}")
    return "\n".join(out_lines) + ("\n" if out_lines else "")


def _render_json(
    schema: tuple[dict[str, Any], ...],
    env: dict[str, str],
    yaml_vals: dict[str, str],
    *,
    redact_secrets: bool,
) -> str:
    rows: list[dict[str, Any]] = []
    for entry in schema:
        value, source = _resolve_entry_value(entry, env, yaml_vals)
        rendered: str | None
        if source == "unset":
            rendered = None
        elif entry.get("secret") and redact_secrets and value:
            rendered = _redact(value)
        else:
            rendered = value
        rows.append(
            {
                "name": entry["name"],
                "category": entry["category"],
                "purpose": entry["purpose"],
                "value": rendered,
                "source": source,
                "secret": bool(entry.get("secret")),
                "read_today": entry.get("read_today"),
                "default": entry["default"],
                "precedence": entry.get("precedence"),
                "yaml_field": entry.get("yaml_field"),
                "proposed": entry.get("read_today") is None,
            }
        )
    return json.dumps({"entries": rows}, indent=2, sort_keys=False) + "\n"


def cmd_show_env(args: argparse.Namespace) -> int:
    env = dict(os.environ)
    yaml_vals = _resolve_yaml_values()

    fmt = getattr(args, "format", "human") or "human"
    if fmt == "human":
        sys.stdout.write(_render_human(_ENV_SCHEMA, env, yaml_vals))
    elif fmt == "env":
        # Deploy-paste form: secrets fully present.
        sys.stdout.write(_render_env_format(_ENV_SCHEMA, env, yaml_vals))
    elif fmt == "json":
        sys.stdout.write(
            _render_json(_ENV_SCHEMA, env, yaml_vals, redact_secrets=True)
        )
    else:
        _die(f"unknown --format: {fmt!r}. Use human / env / json.")
    return 0


def cmd_show_profiles(args: argparse.Namespace) -> int:
    """Print the profile catalog.

    DX review #22: the curated profile bundle (encrypts / signs /
    chains / flush / default_sink / intended_use) is the right
    metadata to expose for "what should I init with?" decisions.
    The data has lived in ``tn._profiles._CATALOG`` since 0.3.0 but
    had no CLI surface — users were reaching into the private module
    to discover the bundles. This verb is the proper public reflection.
    """
    fmt = getattr(args, "format", "human") or "human"
    names = list(_profiles.all_profile_names())
    profiles = [_profiles.get(n) for n in names]

    if fmt == "json":
        payload = [
            {
                "name": p.name,
                "encrypts": p.encrypts,
                "signs": p.signs,
                "chains": p.chains,
                "flush": p.flush,
                "default_sink": p.default_sink,
                "intended_use": p.intended_use,
                "default": p.name == _profiles.DEFAULT_PROFILE,
            }
            for p in profiles
        ]
        sys.stdout.write(json.dumps({"profiles": payload}, indent=2) + "\n")
        return 0

    # human table
    cols = [
        ("NAME", 12),
        ("ENCRYPTS", 8),
        ("SIGNS", 5),
        ("CHAINS", 6),
        ("FLUSH", 8),
        ("SINK", 14),
    ]
    header = "  ".join(f"{name:<{w}}" for name, w in cols)
    sys.stdout.write(header + "\n")
    sys.stdout.write(
        "  ".join("-" * w for _name, w in cols) + "\n"
    )
    for p in profiles:
        marker = "*" if p.name == _profiles.DEFAULT_PROFILE else " "
        sys.stdout.write(
            f"{p.name + marker:<12}  "
            f"{'yes' if p.encrypts else 'no':<8}  "
            f"{'yes' if p.signs else 'no':<5}  "
            f"{'yes' if p.chains else 'no':<6}  "
            f"{p.flush:<8}  "
            f"{p.default_sink:<14}\n"
        )
    sys.stdout.write("\n* = catalog default (used when tn.init() is called with no profile=).\n\n")
    # Intended-use details below the table.
    for p in profiles:
        sys.stdout.write(f"{p.name}: {p.intended_use}\n\n")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """DX review #21: ``tn show`` with no subverb dispatches to the
    most-useful default rather than spitting an argparse usage error.
    Today that default is ``env``; if a future ``show`` verb becomes
    the obvious entrypoint, repoint here. Explicit subverbs
    (``tn show env``, ``tn show profiles``) take precedence.
    """
    return cmd_show_env(args)
