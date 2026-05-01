"""YAML configuration: load, validate, create fresh ceremony (PRD §4).

`tn.init()` calls `load_or_create()`. If the YAML exists and is valid, we
use it. Otherwise we generate a fresh ceremony: device keypair, default
group cipher, and the supporting key files.

Keystore layout on disk:
    <keystore>/local.private         # Ed25519 private-key seed, raw 32 bytes
    <keystore>/local.public          # did:key string, utf-8 text
    <keystore>/index_master.key      # 32-byte HKDF master secret

BGW groups additionally write:
    <keystore>/<group>.write         # BGW write key, binary with magic header
    <keystore>/<group>.read          # this party's slot key, binary w/ magic
    <keystore>/<group>.read.a|b|c    # unissued pool slots

JWE groups write:
    <keystore>/<group>.jwe.sender    # X25519 private (publisher)
    <keystore>/<group>.jwe.recipients# JSON [{did, pub_b64}, ...]
    <keystore>/<group>.jwe.mykey     # X25519 private (recipient, may be self)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import cipher as _cipher
from . import classifier as _classifier
from . import indexing as _indexing
from .signing import DeviceKey

_KNOWN_PEL_TOKENS = frozenset(
    {"event_type", "event_class", "date", "yaml_dir", "ceremony_id", "did"}
)


# Compose-style env-var substitution applied to the raw yaml *string* before
# yaml.safe_load runs. Matches `${VAR}` and `${VAR:-default}`. The negative
# lookbehind on `\$` lets us escape a literal `${...}` by writing `$${...}`
# (the doubled `$$` collapses to a single `$` after substitution, exactly
# like docker-compose). Variable names follow the POSIX shell rule
# `[A-Za-z_][A-Za-z0-9_]*`. Defaults may contain anything except `}`.
_ENV_VAR_RE = re.compile(
    r"""
    (?<!\$)\$\{                   # ${  — but not preceded by another $
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    (?: : - (?P<default>[^}]*) )? # optional :-default (default may be empty)
    \}
    """,
    re.VERBOSE,
)
# Catches malformed `${...}` constructs that the main regex skipped (e.g.
# `${1FOO}` or `${FOO BAR}`). Used only to produce a friendly error.
_BAD_ENV_VAR_RE = re.compile(r"(?<!\$)\$\{([^}]*)\}")


def _substitute_env_vars(text: str, source_path: Path) -> str:
    """Expand ``${VAR}`` and ``${VAR:-default}`` in raw yaml text.

    Substitution happens on the file content as a string, *before*
    yaml parsing — same model as docker-compose. This is simpler and
    safer than walking the parsed dict and avoids surprises with yaml
    types (an env var landing inside a list, a quoted scalar, etc.).

    Syntax::

        ${VAR}             # required; raises ValueError if VAR is unset
        ${VAR:-default}    # falls back to ``default`` (may be empty)
        $${literal}        # escape: emits the literal ``${literal}``

    Variable names must match ``[A-Za-z_][A-Za-z0-9_]*`` (Compose rule).
    No recursive expansion: a value pulled from the environment is
    inserted verbatim and not re-scanned for further ``${...}``.

    Errors include the source path, the offending variable name, and
    the line number, so a malformed yaml is easy to track down.

    Examples::

        >>> os.environ["TN_X"] = "hello"
        >>> _substitute_env_vars("a: ${TN_X}", Path("/tmp/x.yaml"))
        'a: hello'
        >>> _substitute_env_vars("a: ${TN_MISSING:-fallback}", Path("/tmp/x.yaml"))
        'a: fallback'
        >>> _substitute_env_vars("a: $${LITERAL}", Path("/tmp/x.yaml"))
        'a: ${LITERAL}'
    """

    def _line_of(offset: int) -> int:
        # Offsets are 0-indexed; line numbers are 1-indexed.
        return text.count("\n", 0, offset) + 1

    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        default = match.group("default")
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        raise ValueError(
            f"{source_path}:{_line_of(match.start())}: "
            f"required environment variable ${{{name}}} is not set "
            f"(use ${{{name}:-default}} to provide a fallback)"
        )

    # Validate first against the *original* text: anything that looks
    # like `${...}` but isn't a strictly-valid `${NAME}` /
    # `${NAME:-default}` is malformed. The escape `$${...}` is fine
    # (the negative lookbehind on `\$` skips it).
    for bad in _BAD_ENV_VAR_RE.finditer(text):
        token = bad.group(0)
        if not _ENV_VAR_RE.fullmatch(token):
            raise ValueError(
                f"{source_path}:{_line_of(bad.start())}: "
                f"malformed env-var reference {token!r} "
                f"(expected ${{NAME}} or ${{NAME:-default}} where "
                f"NAME matches [A-Za-z_][A-Za-z0-9_]*)"
            )

    substituted = _ENV_VAR_RE.sub(_replace, text)
    # Collapse the `$$` escape to a single `$` last, so escaped tokens
    # survive the substitution pass untouched.
    return substituted.replace("$$", "$")


def _validate_pel_template(template: str, yaml_dir: Path) -> None:
    for m in re.findall(r"\{(\w+)\}", template):
        if m not in _KNOWN_PEL_TOKENS:
            raise ValueError(f"unknown substitution {{{m}}} in protocol_events_location")
    dummy = template
    dummy = dummy.replace("{event_type}", "tn.test")
    dummy = dummy.replace("{event_class}", "tn")
    dummy = dummy.replace("{date}", "2026-01-01")
    dummy = dummy.replace("{yaml_dir}", str(yaml_dir))
    dummy = dummy.replace("{ceremony_id}", "local_test1234")
    dummy = dummy.replace("{did}", "z6MkTestAAAAAAAA")
    resolved = Path(dummy).resolve() if Path(dummy).is_absolute() else (yaml_dir / dummy).resolve()
    try:
        resolved.relative_to(yaml_dir.resolve())
    except ValueError as err:
        raise ValueError("protocol_events_location resolves outside ceremony directory") from err


DEFAULT_POOL_SIZE = 4
DEFAULT_PUBLIC_FIELDS = [
    # Envelope-routing fields every request handler sets.
    "timestamp",
    "event_id",
    "event_type",
    "level",
    "server_did",
    "user_did",
    "request_id",
    "method",
    "path",
    # Admin-catalog fields (tn.ceremony.init, tn.group.added, tn.recipient.*,
    # tn.coupon.issued, tn.rotation.completed, tn.enrolment.*, tn.vault.*).
    # These must stay at envelope root so the vault's reducer can read them
    # without a reader kit; treating them as non-public would route them
    # into the default group ciphertext and break the dashboard's /state
    # projection (see tnproto-org routes_invite._resync_publisher_log_to_state).
    "ceremony_id",
    "cipher",
    "device_did",
    "created_at",
    "group",
    "publisher_did",
    "added_at",
    "leaf_index",
    "recipient_did",
    "kit_sha256",
    "slot",
    "to_did",
    "issued_to",
    "generation",
    "previous_kit_sha256",
    "old_pool_size",
    "new_pool_size",
    "rotated_at",
    "peer_did",
    "package_sha256",
    "compiled_at",
    "from_did",
    "absorbed_at",
    "vault_did",
    "project_id",
    "linked_at",
    "reason",
    "unlinked_at",
    # Agents-policy + tampered-row admin events (per 2026-04-25 spec §2.7,
    # §3.3). These fields must stay public on the envelope so the policy
    # published / tampered-row events are auditor-replayable without any
    # reader kit.
    "policy_uri",
    "content_hash",
    "event_types_covered",
    "policy_text",
    "envelope_event_id",
    "envelope_did",
    "envelope_event_type",
    "envelope_sequence",
    "invalid_reasons",
]


@dataclass
class GroupConfig:
    """Per-group runtime state.

    `cipher` is the GroupCipher instance for this group. BGW or JWE —
    the ceremony picks one at create_fresh() time and it's stored in
    the YAML at `ceremony.cipher`. `pool_size` is BGW-specific and only
    meaningful when `cipher.name == "bgw"`.

    `index_key` is the HKDF-derived HMAC key for this group's equality
    index tokens. Derived from the ceremony master secret bound to
    (ceremony_id, group_name) — see tn/indexing.py.
    """

    name: str
    cipher: _cipher.GroupCipher
    pool_size: int = 4
    unissued_slots: list[int] = field(default_factory=list)
    index_key: bytes = b""
    index_epoch: int = 0


@dataclass
class LoadedConfig:
    yaml_path: Path
    keystore: Path
    device: DeviceKey
    ceremony_id: str
    master_index_key: bytes  # 32-byte secret; scopes all group index keys
    cipher_name: str  # "bgw" or "jwe"
    public_fields: list[str]
    default_policy: str
    groups: dict[str, GroupConfig]
    # Multi-group field routing: a field listed under N groups in yaml is
    # encrypted into all N groups' payloads. The list is sorted alphabetically
    # at load time so canonical envelope encoding stays deterministic.
    field_to_groups: dict[str, list[str]]  # field_name -> [group_name, ...]
    handler_specs: list[dict[str, Any]] | None = None  # raw YAML; built lazily
    # Wallet-link fields (spec 2026-04-20-tn-identity-wallet-link §7):
    mode: str = "local"  # "local" | "linked"
    linked_vault: str | None = None  # e.g. "https://api.cyaxios.com"
    linked_project_id: str | None = None  # vault-side project id
    sync_logs: bool = False  # §9.4 option B: also sync ndjson logs
    # Where ``tn.*`` admin envelopes are written. The canonical attribute is
    # ``admin_log_location``; ``protocol_events_location`` is kept as a
    # read-only property (below) for callers that haven't migrated yet.
    #
    # Default: ``./.tn/admin/admin.ndjson`` — every admin event lands in a
    # single dedicated file under the yaml directory. Override paths can
    # still be a path template (with ``{event_type}``, etc.) or the legacy
    # literal ``"main_log"`` to fold admin events back into the main log.
    admin_log_location: str = "./.tn/admin/admin.ndjson"
    # Main log path. Relative paths resolve against yaml_path.parent.
    # Default matches historical implicit behavior.
    log_path: str = "./.tn/logs/tn.ndjson"

    @property
    def protocol_events_location(self) -> str:
        """Legacy alias for ``admin_log_location``.

        Pre-2026-04-24 the field was named ``protocol_events_location`` and
        defaulted to ``"main_log"``. The default flipped to a dedicated
        ``./.tn/admin/admin.ndjson`` file as part of the admin-log
        architecture work; new code should read ``admin_log_location``.
        This property is kept so downstream callers (reader.py, logger.py,
        admin_log.py, the various test fixtures) keep working without a
        coordinated rename.
        """
        return self.admin_log_location

    def resolve_log_path(self) -> Path:
        """Absolute path to the main ndjson log file for this ceremony."""
        p = Path(self.log_path)
        if not p.is_absolute():
            p = (self.yaml_path.parent / p).resolve()
        return p

    def group_for(self, field_name: str) -> str:
        """Return the first group a field routes into, or "default".

        Back-compat shim: callers that only need a single group (e.g. the
        legacy single-route admin path) should migrate to reading
        ``field_to_groups`` directly. Multi-group fields collapse to their
        first sorted entry here, which is *not* what the emit path does.
        """
        groups = self.field_to_groups.get(field_name)
        return groups[0] if groups else "default"

    @property
    def field_to_group(self) -> dict[str, str]:
        """Legacy single-group view of ``field_to_groups``.

        Returns the first (alphabetically smallest) group for each field.
        Provided for back-compat with admin/test code that hasn't migrated
        to the multi-group shape yet. Mutating the returned dict does NOT
        write back into the config — use ``ensure_field_route`` for that.
        """
        return {k: v[0] for k, v in self.field_to_groups.items() if v}

    def is_linked(self) -> bool:
        return self.mode == "linked" and bool(self.linked_vault)

    @property
    def ciphers_minted(self) -> list[str]:
        """User-facing cipher labels used by any group in this ceremony.

        Derived from self.groups; order of first appearance.
        """
        seen: list[str] = []
        for g in self.groups.values():
            if g.cipher.name not in seen:
                seen.append(g.cipher.name)
        return seen

    def resolve_protocol_events_path(self, event_type: str) -> Path:
        from datetime import datetime, timezone

        template = self.protocol_events_location
        yaml_dir = self.yaml_path.parent
        result = template
        result = result.replace("{event_type}", event_type)
        result = result.replace("{event_class}", event_type.split(".")[0])
        result = result.replace("{date}", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        result = result.replace("{yaml_dir}", str(yaml_dir))
        result = result.replace("{ceremony_id}", self.ceremony_id)
        did_parts = self.device.did.split(":")
        did_short = (did_parts[-1] if len(did_parts) > 1 else self.device.did)[:16]
        result = result.replace("{did}", did_short)
        if Path(result).is_absolute():
            return Path(result)
        return (yaml_dir / result).resolve()


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _read_bytes(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _create_group(
    keystore: Path,
    name: str,
    *,
    master_index_key: bytes,
    ceremony_id: str,
    cipher_name: str,
    pool_size: int = 4,
    epoch: int = 0,
    recipient_dids: list[str] | None = None,
    recipient_pubs: dict[str, bytes] | None = None,
) -> GroupConfig:
    """Mint a fresh group's cipher + derive its index key."""
    inst: _cipher.GroupCipher
    if cipher_name == "jwe":
        # Solo-ceremony default: publisher is also the sole recipient.
        # Callers that want a multi-party ceremony must pass recipient_dids
        # plus recipient_pubs (every non-self recipient's public key).
        dids = recipient_dids or ["self"]
        inst = _cipher.JWEGroupCipher.create(
            keystore,
            name,
            recipient_dids=dids,
            recipient_pubs=recipient_pubs,
        )
    elif cipher_name == "btn":
        inst = _cipher.BtnGroupCipher.create(keystore, name)
    else:
        raise ValueError(f"unknown cipher: {cipher_name!r}; expected 'jwe' or 'btn'")
    unissued: list[int] = []

    return GroupConfig(
        name=name,
        cipher=inst,
        pool_size=pool_size,
        unissued_slots=unissued,
        index_key=_indexing._derive_group_index_key(master_index_key, ceremony_id, name, epoch),
        index_epoch=epoch,
    )


def create_fresh(
    yaml_path: Path,
    *,
    pool_size: int = DEFAULT_POOL_SIZE,
    cipher: str = "btn",
    device_private_bytes: bytes | None = None,
) -> LoadedConfig:
    """Generate a fresh ceremony: device key + default group.

    `cipher` selects the group-sealing primitive for this ceremony:
    "btn" (NNL subset-difference broadcast — default; uses the Rust
    tn_core extension when available, with a Python fallback for emit)
    or "jwe" (static-ECDH + AES-KW; pure Python alternative for
    ceremonies that need no Rust dependency at all).
    Once chosen, the whole ceremony uses that cipher. Change it by
    creating a new ceremony.

    `device_private_bytes` — optional 32-byte Ed25519 seed. If provided,
    the ceremony binds to that key (so the DID written into tn.yaml
    matches the caller's Identity). If omitted, a fresh random key is
    generated (legacy behavior).
    """
    if cipher not in ("jwe", "btn"):
        raise ValueError(f"unknown cipher {cipher!r}; expected 'jwe' or 'btn'")
    yaml_path = yaml_path.resolve()
    # Namespace the .tn/ subdir by yaml stem so two yamls in the same
    # directory don't collide on the same keys/logs/admin paths
    # (FINDINGS #2). The yaml stem is "_register" for _register.yaml,
    # "tn" for ~/.tn/tn.yaml, etc. Existing yamls untouched: they encode
    # whatever path they were created with, and load_config resolves
    # whatever the yaml literally says.
    yaml_stem = yaml_path.stem
    keystore = yaml_path.parent / ".tn" / yaml_stem / "keys"
    # Single source of truth for the main log path; reused below for
    # both ``logs.path`` and the file.rotating handler so an operator
    # editing one place stays in sync with the other automatically.
    _log_path_default = f"./.tn/{yaml_stem}/logs/tn.ndjson"

    # Refuse to clobber an existing keystore. If .tn/keys/local.private
    # already exists but tn.yaml does not, the caller is either
    # (a) pointing at the wrong directory, or
    # (b) restoring a ceremony whose yaml was lost, which needs a
    #     reconstruction step, not a fresh generate.
    # Generating a new device key here would silently orphan every
    # previous log entry (wrong DID) and discard the old index master
    # so HMAC tokens stop matching. That class of corruption is
    # irrecoverable, so we stop here instead.
    existing_private = keystore / "local.private"
    if existing_private.exists():
        raise RuntimeError(
            f"refusing to create a fresh ceremony at {yaml_path}: "
            f"{existing_private} already exists. Either delete the keystore "
            f"directory ({keystore}) to start over, or restore the yaml from "
            f"the existing material (local.public holds the DID; match "
            f"cipher + ceremony_id to what the log expects)."
        )

    if device_private_bytes is not None:
        device = DeviceKey.from_private_bytes(device_private_bytes)
    else:
        device = DeviceKey.generate()
    _write_bytes(keystore / "local.private", device.private_bytes)
    (keystore / "local.public").write_text(device.did, encoding="utf-8")

    # Master index secret lives for the life of the ceremony. Rotation
    # re-runs create_fresh() into a new ceremony dir; there is no
    # in-place rotation of this key.
    master_index_key = _indexing._new_master_key()
    _write_bytes(keystore / "index_master.key", master_index_key)

    ceremony_id = _mint_ceremony_id()
    default = _create_group(
        keystore,
        "default",
        master_index_key=master_index_key,
        ceremony_id=ceremony_id,
        cipher_name=cipher,
        pool_size=pool_size,
    )

    # JWE records the DID only (the publisher's pub lives in
    # <group>.jwe.recipients). btn records the DID only (the self-kit is
    # in <group>.btn.mykit).
    group_block: dict[str, Any] = {
        "policy": "private",
        "cipher": cipher,
        "recipients": [{"did": device.did}],
    }

    # ``tn.agents`` reserved group — auto-inject for every fresh ceremony
    # per the 2026-04-25 read-ergonomics spec §2.3. Carries the six policy
    # fields the markdown loader splices into emit when ``.tn/config/agents.md``
    # is present. Always ``cipher: btn`` so kits can be bundled via
    # ``tn.export(kind="kit_bundle")`` for LLM-runtime onboarding.
    #
    # Pure-logging users pay nothing: with no policy file, the group's
    # plaintext is empty for every emit (zero-length ciphertext).
    agents_group = _create_group(
        keystore,
        "tn.agents",
        master_index_key=master_index_key,
        ceremony_id=ceremony_id,
        cipher_name="btn",
        pool_size=pool_size,
    )
    agents_block: dict[str, Any] = {
        "policy": "private",
        "cipher": "btn",
        "recipients": [{"did": device.did}],
        "fields": [
            "instruction",
            "use_for",
            "do_not_use_for",
            "consequences",
            "on_violation_or_error",
            "policy",
        ],
        "auto_populated_by_policy": True,
    }

    doc = {
        # All ceremony defaults are written explicitly so the yaml is a
        # complete, auditable contract — every behavior the runtime
        # consults can be inspected (and edited) here, with no hidden
        # in-code defaults. Closes FINDINGS #10.
        "ceremony": {
            "id": ceremony_id,
            "mode": "local",
            "cipher": cipher,
            # Sign every entry's row_hash with the device's Ed25519 key.
            # ``sign: false`` flips chain-only mode (still tamper-evident
            # via prev_hash + row_hash, but no signature). The Rust runtime
            # honors this flag; legacy Python emit always signs.
            "sign": True,
            # Where ``tn.*`` admin envelopes are written. The default
            # routes admin events to a dedicated file under the yaml dir,
            # namespaced by yaml stem so two yamls in the same folder
            # don't share the same admin file. Set to ``"main_log"`` to
            # fold them back into the main log (pre-2026-04-24 behavior).
            "admin_log_location": f"./.tn/{yaml_stem}/admin/admin.ndjson",
            # Active log-level threshold. ``debug`` (the floor) lets
            # every emit through; ``info`` drops debug-level emits;
            # ``warning`` drops debug+info; ``error`` drops everything
            # below error. Mirrors stdlib ``logging.Logger.setLevel``
            # and is honored at init unless the caller already set a
            # threshold programmatically via ``tn.set_level()``.
            "log_level": "debug",
        },
        # Where `tn.info` writes and `tn.read` reads. Single path, no template
        # substitution. For event-type-based file splitting use a `handlers:`
        # block or `protocol_events_location` (see advanced docs).
        "logs": {"path": _log_path_default},
        "keystore": {"path": f"./.tn/{yaml_stem}/keys"},
        "me": {"did": device.did},
        # Output sinks. Both sinks are declared explicitly so they're
        # auditable + editable from the yaml — no hidden in-code defaults
        # (FINDINGS #1, #10). To silence stdout, remove the second entry
        # (or set ``TN_NO_STDOUT=1`` for a temporary override). The
        # file.rotating ``path`` is derived from ``logs.path`` above so
        # the two stay in sync without operator coordination.
        "handlers": [
            {
                "kind": "file.rotating",
                "name": "main",
                "path": _log_path_default,
                "max_bytes": 5 * 1024 * 1024,
                "backup_count": 5,
                # Session-start rotation: OFF by default. TN logs are an
                # attestation chain — `prev_hash`/`row_hash` tie every
                # row to its predecessor — so rotating at session start
                # breaks chain verification across the rotation boundary
                # and surfaces as "tn.read() returns nothing after
                # re-init". Operators who want a fresh file per session
                # (e.g. for size management) can flip this to true; the
                # chain is then auditable per-file but not across files.
                "rotate_on_init": False,
            },
            {"kind": "stdout"},
        ],
        "public_fields": DEFAULT_PUBLIC_FIELDS,
        "default_policy": "private",
        "groups": {"default": group_block, "tn.agents": agents_block},
        "fields": {},
        # LLM field classifier — STUBBED out per PRD §6.4. When an unknown
        # field appears the SDK currently puts it in `default`. Flip
        # `enabled: true` and call `tn.classifier._register(fn)` to wire a
        # real model once that feature is built.
        "llm_classifier": {
            "enabled": False,
            "provider": "",
            "model": "",
        },
    }
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False)

    return LoadedConfig(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        ceremony_id=ceremony_id,
        master_index_key=master_index_key,
        cipher_name=cipher,
        public_fields=DEFAULT_PUBLIC_FIELDS,
        default_policy="private",
        groups={"default": default, "tn.agents": agents_group},
        # The six tn.agents fields all route exclusively to that group.
        field_to_groups={
            "consequences": ["tn.agents"],
            "do_not_use_for": ["tn.agents"],
            "instruction": ["tn.agents"],
            "on_violation_or_error": ["tn.agents"],
            "policy": ["tn.agents"],
            "use_for": ["tn.agents"],
        },
    )


def _build_field_to_groups(doc: dict[str, Any], yaml_path: Path) -> dict[str, list[str]]:
    """Invert the canonical ``groups[<name>].fields`` block into ``field -> [groups]``.

    The new canonical source of truth is each group's own ``fields:`` list.
    A field listed under multiple groups gets encrypted into all of them.
    For deterministic envelope encoding, each field's group list is sorted
    alphabetically.

    Back-compat: when no group declares ``fields:`` we fall back to the
    legacy flat ``fields:`` block (each field maps to one group). A
    ``DeprecationWarning`` is emitted in that case so callers migrate.

    Validation:
      * A field listed under a group that doesn't exist is an error.
      * A field listed in zero groups (and not ``public_fields``) is an
        error — this catches typos that today silently fall through to
        ``default_policy``.
      * A field listed in both ``public_fields`` and a group is ambiguous
        and rejected.
    """
    import warnings

    groups_block = doc.get("groups") or {}
    # public_fields override is ADDITIVE, not replacement: the 37 defaults
    # are always public; the yaml's `public_fields:` block adds to that
    # set. Documented in README §"public_fields override path" and
    # docs/yaml-config-reference.md §1.5. So a yaml saying
    # `public_fields: [my_field]` yields a 38-field public set (37
    # defaults plus my_field).
    public_fields = set(DEFAULT_PUBLIC_FIELDS) | set(doc.get("public_fields") or [])

    # Walk per-group fields. New canonical shape.
    per_group_fields: dict[str, list[str]] = {}
    any_group_declares_fields = False
    for gname, gspec in groups_block.items():
        if not isinstance(gspec, dict):
            continue
        gfields = gspec.get("fields")
        if gfields is None:
            continue
        any_group_declares_fields = True
        if not isinstance(gfields, list):
            raise ValueError(
                f"{yaml_path}: groups.{gname}.fields must be a list of field names "
                f"(got {type(gfields).__name__})"
            )
        for fname in gfields:
            if not isinstance(fname, str):
                raise ValueError(
                    f"{yaml_path}: groups.{gname}.fields entries must be strings "
                    f"(got {type(fname).__name__})"
                )
            per_group_fields.setdefault(gname, []).append(fname)

    field_to_groups: dict[str, list[str]] = {}

    if any_group_declares_fields:
        # New canonical path. Build inverted map directly.
        for gname, fnames in per_group_fields.items():
            for fname in fnames:
                field_to_groups.setdefault(fname, []).append(gname)
    else:
        # Back-compat: legacy flat `fields:` block. Each field → 1 group.
        legacy = doc.get("fields") or {}
        if legacy:
            warnings.warn(
                f"{yaml_path}: the flat top-level `fields:` block is "
                "deprecated; declare field membership inside each group "
                "as `groups[<name>].fields: [...]`. The flat form "
                "supports only one group per field and will be removed "
                "in a future release.",
                DeprecationWarning,
                stacklevel=4,
            )
        for fname, fspec in legacy.items():
            if isinstance(fspec, dict):
                gname = str(fspec.get("group", "default"))
            elif isinstance(fspec, str):
                gname = fspec
            else:
                raise ValueError(
                    f"{yaml_path}: fields.{fname!r} must be a string group name "
                    f"or {{group: <name>}} (got {type(fspec).__name__})"
                )
            field_to_groups.setdefault(fname, []).append(gname)

    # Validate: every routed group must exist.
    known_groups = set(groups_block.keys())
    for fname, gnames in field_to_groups.items():
        for gname in gnames:
            if gname not in known_groups:
                raise ValueError(
                    f"{yaml_path}: field {fname!r} routed to unknown group "
                    f"{gname!r} (known groups: {sorted(known_groups)})"
                )

    # Validate: a field cannot be both public and group-routed.
    overlap = sorted(public_fields & set(field_to_groups))
    if overlap:
        raise ValueError(
            f"{yaml_path}: fields {overlap!r} appear in both public_fields "
            f"and a group's fields: list. A field is either public "
            f"(plaintext on the envelope) or encrypted into one or more "
            f"groups, never both."
        )

    # Sort each list deterministically so canonical envelope encoding is
    # stable across loaders (Python/TS/Rust must agree).
    for fname in field_to_groups:
        field_to_groups[fname] = sorted(set(field_to_groups[fname]))

    # Validate: any field declared under groups[*].fields ends up routed.
    # (Already true by construction; the loop above adds it.) The remaining
    # error case — a field that arrives at emit time but is in zero groups
    # and not public — is caught at emit time, not load time. Reason: yaml
    # cannot list every possible field name a publisher might emit, so a
    # field appearing in *zero groups* at load time is fine — it just means
    # nothing has declared a route for it yet.

    return field_to_groups


def load(yaml_path: Path) -> LoadedConfig:
    yaml_path = yaml_path.resolve()
    raw_text = yaml_path.read_text(encoding="utf-8")
    expanded = _substitute_env_vars(raw_text, yaml_path)
    doc = yaml.safe_load(expanded)

    if not isinstance(doc, dict):
        raise ValueError(f"{yaml_path}: expected top-level mapping")
    for required in ("me", "groups"):
        if required not in doc:
            raise ValueError(f"{yaml_path}: missing required key {required!r}")

    # Reserved namespace check: ``tn.*`` group names are reserved for
    # protocol-level conventions (per the 2026-04-25 read-ergonomics spec
    # §2.2). The only allowed name in the reserved namespace is the
    # auto-injected ``tn.agents`` group. Anything else is rejected at
    # load time so the failure surfaces at ``tn.init()`` not at first
    # emit.
    user_groups = doc.get("groups") or {}
    if isinstance(user_groups, dict):
        for gname in user_groups:
            if not isinstance(gname, str):
                continue
            if gname.startswith("tn.") and gname != "tn.agents":
                raise ValueError(
                    f"{yaml_path}: group name {gname!r} is reserved "
                    f"(the ``tn.*`` namespace is for protocol-level conventions; "
                    f"only ``tn.agents`` is allowed). Rename your group."
                )

    # `ceremony` block may be absent in very old YAMLs. Default the cipher
    # to "jwe" when unset — the pre-cipher-field era predated BGW removal
    # and JWE is the closest portable equivalent (pure-Python, no extras).
    ceremony_block = doc.get("ceremony") or {}
    ceremony_id = str(ceremony_block.get("id") or "")
    if not ceremony_id:
        raise ValueError(f"{yaml_path}: ceremony.id must be set")
    cipher_name = str(ceremony_block.get("cipher") or "btn")
    if cipher_name not in ("jwe", "btn"):
        raise ValueError(
            f"{yaml_path}: unknown ceremony.cipher {cipher_name!r}; "
            f"expected 'jwe' or 'btn' (legacy 'bgw' was removed in Workstream G)"
        )

    # Wallet-link fields (optional, default to unlinked)
    mode = str(ceremony_block.get("mode") or "local")
    if mode not in ("local", "linked"):
        raise ValueError(f"{yaml_path}: unknown ceremony.mode {mode!r}")
    linked_vault = ceremony_block.get("linked_vault") or None
    linked_project_id = ceremony_block.get("linked_project_id") or None
    sync_logs = bool(ceremony_block.get("sync_logs", False))
    if mode == "linked" and not linked_vault:
        raise ValueError(
            f"{yaml_path}: ceremony.mode=linked requires ceremony.linked_vault",
        )

    # The yaml key is renamed from `protocol_events_location` to
    # `admin_log_location` for clarity (per docs/.../2026-04-24-tn-admin-log
    # -architecture.md §1.2). Accept both for now; emit a DeprecationWarning
    # when the legacy name is the only one supplied. Drop the alias next
    # release.
    raw_admin_log = ceremony_block.get("admin_log_location")
    raw_pel_legacy = ceremony_block.get("protocol_events_location")
    if raw_admin_log is None and raw_pel_legacy is not None:
        import warnings as _warnings

        _warnings.warn(
            "ceremony.protocol_events_location is deprecated; "
            "rename it to ceremony.admin_log_location.",
            DeprecationWarning,
            stacklevel=2,
        )
        pel = str(raw_pel_legacy or "main_log")
    elif raw_admin_log is not None:
        pel = str(raw_admin_log)
    else:
        # Default: dedicated admin log under yaml_dir (per
        # docs/.../2026-04-24-tn-admin-log-architecture.md §1).
        pel = "./.tn/admin/admin.ndjson"
    if pel != "main_log":
        _validate_pel_template(pel, yaml_path.parent)

    logs_block = doc.get("logs") or {}
    log_path = str(logs_block.get("path") or "./.tn/logs/tn.ndjson")

    keystore = (yaml_path.parent / doc.get("keystore", {}).get("path", "./.tn/keys")).resolve()
    device = DeviceKey.from_private_bytes(_read_bytes(keystore / "local.private"))
    # Only the publisher (ceremony creator) holds the master index
    # secret. Recipients load without it; they can decrypt via their
    # cipher keys but cannot write index tokens or search by default.
    master_path = keystore / "index_master.key"
    master_index_key = _read_bytes(master_path) if master_path.exists() else b""

    groups: dict[str, GroupConfig] = {}
    for name, spec in doc["groups"].items():
        pool = int(spec.get("pool_size", DEFAULT_POOL_SIZE))
        epoch = int(spec.get("index_epoch", 0))

        # Per-group cipher with ceremony-level fallback for backcompat.
        raw_cipher = spec.get("cipher") or cipher_name
        group_cipher = raw_cipher
        if group_cipher not in ("jwe", "btn"):
            raise ValueError(
                f"{yaml_path}: groups.{name}.cipher is {raw_cipher!r}; "
                f"expected 'jwe' or 'btn' (legacy 'bgw'/'bearer' removed)"
            )

        inst: _cipher.GroupCipher
        unissued: list[int] = []
        if group_cipher == "btn":
            inst = _cipher.BtnGroupCipher.load(keystore, name)
        else:  # jwe
            # Recipient view: if we have a sender_pub sidecar + mykey but no
            # sender key, we're a recipient (not publisher). Construct the
            # cipher via as_recipient so decrypt works.
            sender_pub_sidecar = keystore / f"{name}.jwe.sender_pub"
            mykey_path = keystore / f"{name}.jwe.mykey"
            sender_path = keystore / f"{name}.jwe.sender"
            if sender_pub_sidecar.exists() and mykey_path.exists() and not sender_path.exists():
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

                my_sk = X25519PrivateKey.from_private_bytes(mykey_path.read_bytes())
                inst = _cipher.JWEGroupCipher.as_recipient(
                    sender_pub_sidecar.read_bytes(),
                    my_sk,
                )
            else:
                inst = _cipher.JWEGroupCipher.load(keystore, name)
            unissued = []

        derived_index_key = (
            _indexing._derive_group_index_key(master_index_key, ceremony_id, name, epoch)
            if master_index_key
            else b""
        )
        groups[name] = GroupConfig(
            name=name,
            cipher=inst,
            pool_size=pool,
            unissued_slots=unissued,
            index_key=derived_index_key,
            index_epoch=epoch,
        )

    field_to_groups = _build_field_to_groups(doc, yaml_path)

    # Hand the LLM classifier its config so the stub knows if it's
    # "enabled" (it currently does nothing either way).
    _classifier._configure(doc.get("llm_classifier"))

    return LoadedConfig(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        ceremony_id=ceremony_id,
        master_index_key=master_index_key,
        cipher_name=cipher_name,
        # ADDITIVE merge: defaults always present, yaml extras appended.
        # Order is preserved (defaults first, then yaml extras in order),
        # de-duped via dict.fromkeys to keep deterministic envelope shape.
        public_fields=list(
            dict.fromkeys(
                list(DEFAULT_PUBLIC_FIELDS) + list(doc.get("public_fields") or [])
            )
        ),
        default_policy=doc.get("default_policy", "private"),
        groups=groups,
        field_to_groups=field_to_groups,
        handler_specs=doc.get("handlers"),  # None if absent; [] if empty-list
        mode=mode,
        linked_vault=linked_vault,
        linked_project_id=linked_project_id,
        sync_logs=sync_logs,
        admin_log_location=pel,
        log_path=log_path,
    )


def load_or_create(yaml_path: str | os.PathLike[str], **create_kwargs: Any) -> LoadedConfig:
    p = Path(yaml_path)
    if p.exists():
        return load(p)
    return create_fresh(p, **create_kwargs)


def _mint_ceremony_id() -> str:
    import secrets

    return "local_" + secrets.token_hex(4)
