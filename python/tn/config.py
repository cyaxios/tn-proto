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
    {"event_type", "event_class", "event_id", "date", "yaml_dir", "ceremony_id", "did"}
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


def _validate_path_template(
    template: str, yaml_dir: Path, *, key_name: str
) -> None:
    """Validate a path template against the known TN tokens.

    Used for both ``ceremony.admin_log_location`` and ``logs.path`` so
    the substitution rules and the safety check (must resolve under
    the ceremony directory) stay identical for any templated path the
    runtime renders per-envelope.

    ``key_name`` is the human-readable yaml key for the error message
    so an operator sees ``unknown substitution {foo} in logs.path``
    rather than the generic ``protocol_events_location`` text.
    """
    for m in re.findall(r"\{(\w+)\}", template):
        if m not in _KNOWN_PEL_TOKENS:
            raise ValueError(f"unknown substitution {{{m}}} in {key_name}")
    dummy = template
    dummy = dummy.replace("{event_type}", "tn.test")
    dummy = dummy.replace("{event_class}", "tn")
    dummy = dummy.replace("{event_id}", "0190aaaa-0000-7000-8000-000000000000")
    dummy = dummy.replace("{date}", "2026-01-01")
    dummy = dummy.replace("{yaml_dir}", str(yaml_dir))
    dummy = dummy.replace("{ceremony_id}", "local_test1234")
    dummy = dummy.replace("{did}", "z6MkTestAAAAAAAA")
    resolved = Path(dummy).resolve() if Path(dummy).is_absolute() else (yaml_dir / dummy).resolve()
    allowed_root = yaml_dir.parent if yaml_dir.name == "streams" else yaml_dir
    try:
        resolved.relative_to(allowed_root.resolve())
    except ValueError as err:
        raise ValueError(f"{key_name} resolves outside ceremony directory") from err


def _validate_pel_template(template: str, yaml_dir: Path) -> None:
    """Back-compat wrapper. New code should call
    :func:`_validate_path_template` directly with an explicit
    ``key_name``.
    """
    _validate_path_template(template, yaml_dir, key_name="protocol_events_location")


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
    "device_identity",
    "created_at",
    "group",
    "publisher_identity",
    "added_at",
    "leaf_index",
    "recipient_identity",
    "kit_sha256",
    "slot",
    "issued_to",
    "generation",
    "previous_kit_sha256",
    "old_pool_size",
    "new_pool_size",
    "rotated_at",
    "peer_identity",
    "package_sha256",
    "compiled_at",
    "absorbed_at",
    "vault_identity",
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
    "envelope_device_identity",
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
    linked_vault: str | None = None  # e.g. "https://vault.tn-proto.org"
    linked_project_id: str | None = None  # vault-side project id
    # Project-level vault block normalized from `vault:` (preferred) or
    # legacy `ceremony.linked_*` fields. Vault sync never includes app logs.
    vault_enabled: bool = False
    vault_declared: bool = False
    vault_url: str | None = None
    vault_linked_project_id: str | None = None
    vault_autosync: bool = False
    vault_sync_interval_seconds: int = 600
    # Legacy parsed field. Vault sync never includes application logs.
    sync_logs: bool = False
    # DX review #6: ``ceremony.sign`` mirrored on the loaded config so
    # readers can decide whether to verify signatures. False means the
    # writer chose to skip Ed25519 signing (profile=telemetry/stdout);
    # signature-check on read is then meaningless and would always fail.
    sign: bool = True
    # 0.4.2a7: ``ceremony.chain`` mirrored alongside ``sign``. False
    # means the Rust runtime skips the per-emit advisory lock + tail
    # scan + chain advance/commit; rows carry sequence=1 and
    # prev_hash="" (unchained sentinels). Used by telemetry /
    # secure_log profiles where per-row chain integrity isn't part of
    # the audit story.
    chain: bool = True
    # 0.4.2a9: operator-chosen project label. Persisted in the yaml as
    # ``ceremony.project_name``. Passed to the vault on link so the
    # web UI shows a human name ("mycompany_payments") instead of the
    # random ceremony_id. Two TN installs that share a project_name
    # AND belong to the same vault account merge into one
    # ``account_projects`` row (laptop-dev, ci, prod become three
    # publishers on one project). When ``None`` (legacy ceremonies),
    # ``wallet.link_ceremony`` falls back to ``ceremony_id`` so old
    # data keeps working.
    project_name: str | None = None
    # 0.4.2a9: per-instance version label inside ``project_name``.
    # The vault stores it as ``account_projects.publishers[].nickname``.
    # Typical values: "laptop-dev", "ci", "prod". Defaults to
    # ``project_name`` when None (single-version projects).
    version_name: str | None = None
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

    def resolve_protocol_events_path(
        self, event_type: str, *, event_id: str = ""
    ) -> Path:
        """Render the admin-log path template for a single event.

        ``event_id`` is only consumed by templates that contain the
        ``{event_id}`` token; callers that don't have an id handy can
        omit it (an admin template without ``{event_id}`` renders the
        same regardless).
        """
        return self._render_path_template(
            self.protocol_events_location,
            event_type=event_type,
            event_id=event_id,
        )

    def resolve_log_path_for(self, event_type: str, *, event_id: str = "") -> Path:
        """Render the main-log path template for a single event_type.

        Mirrors :meth:`resolve_protocol_events_path` but for ``logs.path``.
        Lets a ceremony declare e.g.
        ``logs: {path: ./.tn/logs/{event_class}/{date}.ndjson}`` and have
        ``tn.info(...)`` route per-envelope to the rendered file. When
        ``log_path`` has no template tokens, the result is equivalent to
        :meth:`resolve_log_path` (the literal path).

        Read side: ``tn.read(log=cfg.log_path)`` already glob-expands
        the same tokens via ``_log_targets.resolve_log_target``, so
        the round-trip is symmetric without further changes.

        ``event_id`` is consumed only by ``{event_id}`` templates (one
        file per event). The Rust runtime renders that token itself on
        the accelerated path; this method backs the pure-Python
        fallback (``FileTemplatedRotatingHandler``) and the read-side
        resolver.
        """
        return self._render_path_template(
            self.log_path, event_type=event_type, event_id=event_id
        )

    def _render_path_template(
        self, template: str, *, event_type: str, event_id: str = ""
    ) -> Path:
        """Substitute the TN path tokens against ``event_type`` /
        ``event_id`` / the cermony's static identity, then resolve
        relative paths against the yaml directory.

        Tokens recognised (matches ``_KNOWN_PEL_TOKENS`` in this file):
        ``{event_type}``, ``{event_class}``, ``{event_id}``, ``{date}``,
        ``{yaml_dir}``, ``{ceremony_id}``, ``{did}``.

        Single source of truth for both ``resolve_protocol_events_path``
        and ``resolve_log_path_for`` so the substitution rules stay
        identical across the admin log and the main log.
        """
        from datetime import datetime, timezone

        yaml_dir = self.yaml_path.parent
        result = template
        result = result.replace("{event_type}", event_type)
        result = result.replace("{event_class}", event_type.split(".")[0])
        result = result.replace("{event_id}", event_id)
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
    keystore_dir: Path | None = None,
    log_path: Path | None = None,
    admin_log_path: Path | None = None,
    link: bool | None = None,
) -> LoadedConfig:
    """Generate a fresh ceremony: device key + default group.

    `cipher` selects the group-sealing primitive for this ceremony:
    "btn" (NNL subset-difference broadcast — default; uses the Rust
    tn_core extension when available, with a Python fallback for emit)
    or "jwe" (static-ECDH + AES-KW; pure Python alternative for
    ceremonies that need no Rust dependency at all).
    Once chosen, the whole ceremony uses that cipher. Change it by
    creating a new ceremony.

    `keystore_dir`, `log_path`, `admin_log_path` — optional explicit
    directories that override the stem-derived ``.tn/<stem>/...``
    defaults. Used by the multi-ceremony layout (``.tn/<name>/keys``
    instead of ``.tn/<name>/.tn/tn/keys``). All three should be passed
    together when overriding; mixing leaves you with paths that don't
    line up.

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
    if keystore_dir is not None:
        keystore = Path(keystore_dir).resolve()
    else:
        keystore = yaml_path.parent / ".tn" / yaml_stem / "keys"
    # Single source of truth for the main log path; reused below for
    # both ``logs.path`` and the file.rotating handler so an operator
    # editing one place stays in sync with the other automatically.
    if log_path is not None:
        # Yaml stores log path relative to the yaml's parent for
        # portability. Fall back to absolute if not under that parent.
        _log_path_resolved = Path(log_path).resolve()
        try:
            _log_path_default = "./" + str(
                _log_path_resolved.relative_to(yaml_path.parent)
            ).replace("\\", "/")
        except ValueError:
            _log_path_default = str(_log_path_resolved)
    else:
        _log_path_default = f"./.tn/{yaml_stem}/logs/tn.ndjson"
    if admin_log_path is not None:
        _admin_log_resolved = Path(admin_log_path).resolve()
        try:
            _admin_log_default = "./" + str(
                _admin_log_resolved.relative_to(yaml_path.parent)
            ).replace("\\", "/")
        except ValueError:
            _admin_log_default = str(_admin_log_resolved)
    else:
        _admin_log_default = f"./.tn/{yaml_stem}/admin/admin.ndjson"
    if keystore_dir is not None:
        try:
            _keystore_path_str = "./" + str(
                Path(keystore_dir).resolve().relative_to(yaml_path.parent)
            ).replace("\\", "/")
        except ValueError:
            _keystore_path_str = str(Path(keystore_dir).resolve())
    else:
        _keystore_path_str = f"./.tn/{yaml_stem}/keys"

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
        "recipients": [{"recipient_identity": device.device_identity}],
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
        "recipients": [{"recipient_identity": device.device_identity}],
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

    from .vault_client import DEFAULT_VAULT_URL

    # DX review #5: ``link=False`` produces an unlinked (offline)
    # ceremony — no ``linked_vault`` URL, ``mode: local``. ``link=True``
    # or ``link=None`` (the legacy default) preserves the linked
    # behaviour. Callers that want an air-gap deploy now have a
    # documented init-time knob; the kwarg used to silently no-op.
    _is_unlinked = link is False
    _yaml_mode = "local" if _is_unlinked else "linked"
    _yaml_vault_url = "" if _is_unlinked else DEFAULT_VAULT_URL

    doc = {
        # All ceremony defaults are written explicitly so the yaml is a
        # complete, auditable contract — every behavior the runtime
        # consults can be inspected (and edited) here, with no hidden
        # in-code defaults. Closes FINDINGS #10.
        "ceremony": {
            "id": ceremony_id,
            # Default ceremonies are vault-linked at mint time. The
            # ``linked_vault`` URL points at the hosted cyaxios vault;
            # ``linked_project_id`` is empty until ``tn.vault.link()``
            # claims one. Nothing reaches the network until an explicit
            # vault verb runs — ``mode: linked`` only gates which
            # operations are permitted, not whether they fire. Set
            # ``mode: local`` to opt out and operate fully offline.
            "mode": _yaml_mode,
            "linked_vault": _yaml_vault_url,
            "linked_project_id": "",
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
            "admin_log_location": _admin_log_default,
            # Active log-level threshold. ``debug`` (the floor) lets
            # every emit through; ``info`` drops debug-level emits;
            # ``warning`` drops debug+info; ``error`` drops everything
            # below error. Mirrors stdlib ``logging.Logger.setLevel``
            # and is honored at init unless the caller already set a
            # threshold programmatically via ``tn.set_level()``.
            "log_level": "debug",
        },
        "vault": {
            "enabled": not _is_unlinked,
            "url": _yaml_vault_url,
            "linked_project_id": "",
            "autosync": not _is_unlinked,
            "sync_interval_seconds": 600,
        },
        # Where `tn.info` writes and `tn.read` reads. Single path, no template
        # substitution. For event-type-based file splitting use a `handlers:`
        # block or `protocol_events_location` (see advanced docs).
        "logs": {"path": _log_path_default},
        "keystore": {"path": _keystore_path_str},
        "device": {"device_identity": device.device_identity},
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


def _read_yaml_doc(yaml_path: Path) -> dict[str, Any]:
    """Read + env-var-expand + yaml-parse a single tn.yaml file.

    Used by both ``load`` and the extends resolver. Does not validate;
    returns the raw doc dict (or raises ValueError on bad shape)."""
    yaml_path = yaml_path.resolve()
    raw_text = yaml_path.read_text(encoding="utf-8")
    expanded = _substitute_env_vars(raw_text, yaml_path)
    doc = yaml.safe_load(expanded)
    if not isinstance(doc, dict):
        raise ValueError(f"{yaml_path}: expected top-level mapping")
    return doc


# Fields that come from the parent (default) ceremony and cannot be
# overridden by an extending stream. If a child yaml sets one of
# these, a warning is logged and the parent's value is used.
# Identity, groups, recipient relationships are project-scoped.
_PARENT_OWNED_KEYS = (
    "device",
    "keystore",
    "groups",
    "fields",
    "public_fields",
    "default_policy",
    "llm_classifier",
)

# Fields that the child can fully override (no merge with parent's value).
_CHILD_OWNED_KEYS = ("logs",)


def _absolutize_path(p: str, base: Path) -> str:
    """Resolve a possibly-relative path string against ``base`` and
    return an absolute path string. Pass-through if already absolute.

    Used during extends merging: a parent yaml's ``keystore.path``
    is recorded relative to the parent's own directory, but the
    merged result will be loaded against the child's directory.
    Absolutizing at merge time makes the final paths location-
    independent and consistent regardless of which yaml in the
    chain triggered the load.
    """
    pp = Path(p)
    if pp.is_absolute():
        return str(pp)
    return str((base / pp).resolve())


def _absolutize_parent_doc(parent_doc: dict[str, Any], parent_path: Path) -> dict[str, Any]:
    """Walk parent_doc and convert relative paths to absolute paths
    rooted at ``parent_path.parent``. Mutates and returns a fresh
    copy. Conservative: only paths in known fields are touched.
    """
    out = dict(parent_doc)
    base = parent_path.parent

    if isinstance(out.get("keystore"), dict) and "path" in out["keystore"]:
        ks = dict(out["keystore"])
        ks["path"] = _absolutize_path(str(ks["path"]), base)
        out["keystore"] = ks

    if isinstance(out.get("logs"), dict) and "path" in out["logs"]:
        lg = dict(out["logs"])
        lg["path"] = _absolutize_path(str(lg["path"]), base)
        out["logs"] = lg

    cer = out.get("ceremony")
    if isinstance(cer, dict) and "admin_log_location" in cer:
        cer = dict(cer)
        loc = cer["admin_log_location"]
        if isinstance(loc, str) and loc != "main_log":
            cer["admin_log_location"] = _absolutize_path(loc, base)
        out["ceremony"] = cer

    if isinstance(out.get("handlers"), list):
        new_handlers = []
        for h in out["handlers"]:
            if isinstance(h, dict) and "path" in h:
                hh = dict(h)
                hh["path"] = _absolutize_path(str(hh["path"]), base)
                new_handlers.append(hh)
            else:
                new_handlers.append(h)
        out["handlers"] = new_handlers

    return out


def _resolve_extends(yaml_path: Path, doc: dict[str, Any], _seen: set[Path] | None = None) -> dict[str, Any]:
    """If ``doc`` declares ``extends: <path>``, recursively load the
    parent yaml and return a merged dict.

    Merge rules (see directory-layout.md):
      - parent-owned keys (identity, groups, recipients): parent wins.
        Child values logged + ignored.
      - child-owned keys (logs.path): child wins outright.
      - ``ceremony``: shallow-merged per subfield, child wins.
      - ``handlers``: child REPLACES if declared (including empty list).
        Inherits from parent only when the child omits the key entirely.
        0.4.2a8 used an additive merge that surprised users whose child
        yaml declared a stdout-only handler — they ended up dual-writing
        to the parent's file.rotating sink.
      - all other top-level keys: child wins if set, else parent's.

    Path absolutization: parent's relative paths (keystore.path,
    logs.path, handler.path, admin_log_location) are converted to
    absolute paths rooted at the parent's directory before merge.
    The child's relative paths remain relative to its own directory.
    This keeps load semantics correct regardless of which yaml in
    the chain triggers the load.

    Cycles are detected (via the ``_seen`` set) and raise ValueError.
    """
    extends = doc.get("extends")
    if not extends:
        return doc

    if _seen is None:
        _seen = set()
    if yaml_path in _seen:
        raise ValueError(
            f"{yaml_path}: extends cycle detected. "
            "extends: chains cannot loop back on themselves."
        )
    _seen = _seen | {yaml_path}

    if not isinstance(extends, str):
        raise ValueError(
            f"{yaml_path}: extends must be a string path, got {type(extends).__name__}"
        )
    parent_path = (yaml_path.parent / extends).resolve()
    if not parent_path.is_file():
        raise ValueError(
            f"{yaml_path}: extends target {parent_path} does not exist"
        )

    parent_doc = _read_yaml_doc(parent_path)
    parent_resolved = _resolve_extends(parent_path, parent_doc, _seen)
    # Absolutize parent's relative paths so they survive the merge
    # into the child's coordinate system.
    parent_resolved = _absolutize_parent_doc(parent_resolved, parent_path)

    # Start from parent's view, then apply child's overrides.
    merged: dict[str, Any] = dict(parent_resolved)

    import logging as _log
    log = _log.getLogger("tn")

    for key, child_val in doc.items():
        if key == "extends":
            continue
        if key in _PARENT_OWNED_KEYS:
            if key in parent_resolved:
                if child_val != parent_resolved[key]:
                    log.warning(
                        "%s: child sets parent-owned key %r; parent wins. "
                        "Identity / groups / recipients live at the project "
                        "root only. Remove the override from the stream yaml.",
                        yaml_path, key,
                    )
                continue
            # Parent didn't set it; child's value can stand.
            merged[key] = child_val
            continue
        if key == "ceremony":
            base = dict(parent_resolved.get("ceremony") or {})
            if isinstance(child_val, dict):
                base.update(child_val)
            merged["ceremony"] = base
            continue
        if key == "handlers":
            # Child-declared `handlers:` REPLACES the parent's list
            # outright. Standard yaml-inheritance semantics, and the
            # only one that matches user intent: a child stream
            # declaring `handlers: [stdout]` means "I want stdout
            # only," not "I want stdout PLUS whatever the parent
            # had." The prior additive-with-dedupe behaviour caused
            # silent dual-writes into the parent's file sink.
            #
            # Keep declared as-is, including the empty-list case
            # `handlers: []` which means "no handlers at all" — an
            # explicit child opt-out of parent inheritance.
            merged["handlers"] = (
                list(child_val) if isinstance(child_val, list) else []
            )
            continue
        # Default: child wins.
        merged[key] = child_val

    return merged


def authoritative_yaml_for(yaml_path: Path, key: str) -> Path:
    """Return the yaml in ``yaml_path``'s ``extends:`` chain that owns ``key``.

    Parent-owned keys (``groups``, ``fields``, ``device``, ``keystore``,
    ``recipients`` nested under ``groups``, ...) are authoritative only at
    the head of the ``extends:`` chain. A named *stream* yaml that
    ``extends: ../default/tn.yaml`` must NOT write them into itself:
    :func:`_resolve_extends` discards a child's copy of a parent-owned key
    on the next load ("child sets parent-owned key 'groups'; parent
    wins"), so the write is silently lost.

    This walks from ``yaml_path`` toward the chain root and returns the
    path of the yaml *closest to the root* that declares ``key`` — that
    is the one whose value actually survives the merge. If no yaml in the
    chain declares ``key`` yet, the chain root is returned so a
    first-time write lands authoritatively. For a yaml with no
    ``extends:`` the chain is a single node and the result is
    ``yaml_path`` itself, so the legacy single-file layout is unaffected.

    Raises ``ValueError`` on an ``extends:`` cycle or a missing /
    malformed ``extends:`` target (mirrors :func:`_resolve_extends`).
    """
    yaml_path = yaml_path.resolve()
    chain: list[Path] = []  # [leaf, ..., root]
    declarers: list[Path] = []  # subset of chain that declares `key`, same order
    seen: set[Path] = set()
    cur = yaml_path
    while True:
        if cur in seen:
            raise ValueError(
                f"{cur}: extends cycle detected while resolving the "
                f"authoritative yaml for key {key!r}."
            )
        seen.add(cur)
        doc = _read_yaml_doc(cur)
        chain.append(cur)
        if key in doc:
            declarers.append(cur)
        extends = doc.get("extends")
        if not extends:
            break
        if not isinstance(extends, str):
            raise ValueError(
                f"{cur}: extends must be a string path, got {type(extends).__name__}"
            )
        parent = (cur.parent / extends).resolve()
        if not parent.is_file():
            raise ValueError(f"{cur}: extends target {parent} does not exist")
        cur = parent
    # `declarers` is in leaf->root order; the entry closest to the root is
    # the one the merge keeps (parent wins). Fall back to the chain root
    # when nothing declares the key yet.
    return declarers[-1] if declarers else chain[-1]


@dataclass(frozen=True)
class _VaultSettings:
    present: bool
    enabled: bool
    url: str | None
    linked_project_id: str | None
    autosync: bool
    sync_interval_seconds: int


@dataclass(frozen=True)
class _CeremonySettings:
    """Validated ceremony-block scalars resolved from yaml.

    Bundled into one return value so ``load()`` doesn't have to juggle a
    7-tuple of unrelated strings.
    """

    ceremony_id: str
    cipher_name: str  # "btn" | "jwe"
    mode: str  # "local" | "linked"
    linked_vault: str | None
    linked_project_id: str | None
    sync_logs: bool  # legacy/ignored; vault sync never includes app logs
    # DX review #6: surface ``ceremony.sign`` on the loaded config so
    # ``tn.read(verify=True)`` can consult it. Yamls written with
    # ``sign: false`` ship empty signatures; the reader skips the
    # signature check rather than raising a guaranteed VerifyError.
    sign: bool
    # 0.4.2a7: surface ``ceremony.chain``. False means rows are
    # unchained (sequence=1, prev_hash=""); mirror it onto
    # LoadedConfig so a reader can decide whether chain verification
    # makes sense.
    chain: bool
    # 0.4.2a9: operator-chosen project label (vault-side
    # `account_projects.name`). None for legacy ceremonies.
    project_name: str | None
    # 0.4.2a9: per-instance label inside the project (vault-side
    # `account_projects.publishers[].nickname`). None when omitted —
    # the link path falls back to `project_name`.
    version_name: str | None


def _validate_load_doc_structure(yaml_path: Path, doc: Any) -> None:
    """Top-level structural validation: dict shape, required keys,
    reserved-namespace check on group names.

    Raises ``ValueError`` with the yaml path prefixed so the operator
    can locate the offending file at ``tn.init()`` time rather than at
    first emit.
    """
    if not isinstance(doc, dict):
        raise ValueError(f"{yaml_path}: expected top-level mapping")
    if "me" in doc and "device" not in doc:
        raise ValueError(
            f"{yaml_path}: legacy `me:` top-level block is no longer supported "
            f"(0.4.3a1 renamed it to `device:`). Replace `me: {{did: ...}}` with "
            f"`device: {{device_identity: ...}}`. See "
            f"docs/superpowers/specs/2026-05-20-identity-and-key-naming.md."
        )
    for required in ("device", "groups"):
        if required not in doc:
            raise ValueError(f"{yaml_path}: missing required key {required!r}")

    # Reserved namespace check: ``tn.*`` group names are reserved for
    # protocol-level conventions (per the 2026-04-25 read-ergonomics
    # spec §2.2). The only allowed name in the reserved namespace is
    # the auto-injected ``tn.agents`` group.
    user_groups = doc.get("groups") or {}
    if not isinstance(user_groups, dict):
        return
    for gname in user_groups:
        if not isinstance(gname, str):
            continue
        if gname.startswith("tn.") and gname != "tn.agents":
            raise ValueError(
                f"{yaml_path}: group name {gname!r} is reserved "
                f"(the ``tn.*`` namespace is for protocol-level conventions; "
                f"only ``tn.agents`` is allowed). Rename your group."
            )


def _resolve_vault_settings(
    yaml_path: Path,
    vault_block: Any,
    ceremony_block: dict[str, Any],
) -> _VaultSettings:
    """Normalize the project-level ``vault:`` block with legacy fallback."""
    legacy_url = _str_or_none(ceremony_block.get("linked_vault"))
    legacy_project_id = _str_or_none(ceremony_block.get("linked_project_id"))
    if vault_block is None:
        return _VaultSettings(
            present=False,
            enabled=bool(legacy_url),
            url=legacy_url,
            linked_project_id=legacy_project_id,
            autosync=bool(legacy_url),
            sync_interval_seconds=600,
        )
    if not isinstance(vault_block, dict):
        raise ValueError(f"{yaml_path}: vault must be a mapping when present")

    enabled = bool(vault_block.get("enabled", True))
    url = _str_or_none(vault_block.get("url"))
    linked_project_id = _str_or_none(vault_block.get("linked_project_id"))
    autosync = bool(vault_block.get("autosync", enabled))
    raw_interval = vault_block.get("sync_interval_seconds", 600)
    try:
        interval = int(raw_interval)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{yaml_path}: vault.sync_interval_seconds must be an integer"
        ) from exc
    if interval <= 0:
        raise ValueError(f"{yaml_path}: vault.sync_interval_seconds must be positive")
    if enabled and not url:
        raise ValueError(f"{yaml_path}: vault.enabled=true requires vault.url")
    return _VaultSettings(
        present=True,
        enabled=enabled,
        url=url if enabled else None,
        linked_project_id=linked_project_id if enabled else None,
        autosync=autosync if enabled else False,
        sync_interval_seconds=interval,
    )


def _rust_config_summary(yaml_path: Path) -> dict[str, Any]:
    """Load and normalize YAML through ``tn_core``.

    This is the shared control-plane check for the Python SDK. Python still
    materializes ``LoadedConfig`` because it owns Python cipher/handler objects,
    but the YAML grammar, extends merge, reserved-name rule, field routing, and
    normalized vault view are validated by Rust first.
    """
    from tn_core import _core as _tn_core

    return dict(_tn_core.config_load_summary(str(yaml_path)))


def _vault_settings_from_rust(yaml_path: Path, summary: dict[str, Any]) -> _VaultSettings:
    vault = summary.get("vault")
    if not isinstance(vault, dict):
        raise ValueError(f"{yaml_path}: tn_core returned malformed vault summary")
    return _VaultSettings(
        present=bool(vault.get("declared", False)),
        enabled=bool(vault.get("enabled", False)),
        url=_str_or_none(vault.get("url")),
        linked_project_id=_str_or_none(vault.get("linked_project_id")),
        autosync=bool(vault.get("autosync", False)),
        sync_interval_seconds=int(vault.get("sync_interval_seconds", 600)),
    )


def _resolve_ceremony_settings(
    yaml_path: Path, ceremony_block: dict[str, Any], vault_settings: _VaultSettings
) -> _CeremonySettings:
    """Validate and pack the ``ceremony:`` block scalars.

    ``ceremony`` may be absent in very old yamls — callers pass ``{}``
    in that case and we default cipher to ``"btn"``. ``mode`` defaults
    to ``"local"``; ``mode=linked`` requires ``linked_vault``.
    """
    ceremony_id = str(ceremony_block.get("id") or "")
    if not ceremony_id:
        raise ValueError(f"{yaml_path}: ceremony.id must be set")
    cipher_name = str(ceremony_block.get("cipher") or "btn")
    if cipher_name not in ("jwe", "btn"):
        raise ValueError(
            f"{yaml_path}: unknown ceremony.cipher {cipher_name!r}; "
            f"expected 'jwe' or 'btn' (legacy 'bgw' was removed in Workstream G)"
        )
    mode = str(ceremony_block.get("mode") or "local")
    if mode not in ("local", "linked"):
        raise ValueError(f"{yaml_path}: unknown ceremony.mode {mode!r}")
    linked_vault = (
        vault_settings.url
        if vault_settings.present
        else _str_or_none(ceremony_block.get("linked_vault"))
    )
    linked_project_id = (
        vault_settings.linked_project_id
        if vault_settings.present
        else _str_or_none(ceremony_block.get("linked_project_id"))
    )
    if mode == "linked" and not linked_vault:
        raise ValueError(
            f"{yaml_path}: ceremony.mode=linked requires ceremony.linked_vault",
        )
    return _CeremonySettings(
        ceremony_id=ceremony_id,
        cipher_name=cipher_name,
        mode=mode,
        linked_vault=linked_vault,
        linked_project_id=linked_project_id,
        sync_logs=bool(ceremony_block.get("sync_logs", False)),
        # Default ``sign: True`` keeps pre-DX-fix yamls (which never
        # carried this key) verifying as before.
        sign=bool(ceremony_block.get("sign", True)),
        # Default ``chain: True`` keeps pre-0.4.2a7 yamls (no key)
        # chaining as before. False is opt-in for telemetry /
        # secure_log profiles.
        chain=bool(ceremony_block.get("chain", True)),
        # 0.4.2a9: vault-link labels. Pulled as-typed (yaml-quoted
        # strings only); operator-managed, not derived.
        project_name=_str_or_none(ceremony_block.get("project_name")),
        version_name=_str_or_none(ceremony_block.get("version_name")),
    )


def _str_or_none(v: Any) -> str | None:
    """Return a stripped string if ``v`` is a non-empty string, else None.
    Centralises the "yaml field optional string" pattern."""
    if isinstance(v, str):
        stripped = v.strip()
        if stripped:
            return stripped
    return None


def _resolve_admin_log_location(yaml_path: Path, ceremony_block: dict[str, Any]) -> str:
    """Resolve where ``tn.*`` admin envelopes get written.

    Precedence (per 2026-04-24-tn-admin-log-architecture.md §1.2):

    1. ``ceremony.admin_log_location`` — canonical key.
    2. ``ceremony.protocol_events_location`` — legacy alias; emits a
       ``DeprecationWarning`` and will be dropped next release.
    3. Default: ``./.tn/admin/admin.ndjson`` under the yaml dir.

    The literal ``"main_log"`` is preserved as an escape hatch that
    folds admin events back into the main log. Anything else is
    validated as a path template via :func:`_validate_pel_template`.
    """
    raw_admin_log = ceremony_block.get("admin_log_location")
    raw_pel_legacy = ceremony_block.get("protocol_events_location")
    if raw_admin_log is not None:
        pel = str(raw_admin_log)
    elif raw_pel_legacy is not None:
        import warnings as _warnings

        _warnings.warn(
            "ceremony.protocol_events_location is deprecated; "
            "rename it to ceremony.admin_log_location.",
            DeprecationWarning,
            stacklevel=2,
        )
        pel = str(raw_pel_legacy or "main_log")
    else:
        pel = "./.tn/admin/admin.ndjson"
    if pel != "main_log":
        _validate_pel_template(pel, yaml_path.parent)
    return pel


def _load_keystore_and_keys(
    yaml_path: Path, doc: dict[str, Any]
) -> tuple[Path, DeviceKey, bytes]:
    """Resolve ``keystore`` dir, load the device private key, and read
    the optional ``index_master.key``.

    Recipients (kits that absorb someone else's ceremony) only have the
    cipher key material and the device key — no master index secret —
    so the master key is best-effort: an empty bytes sentinel disables
    index-token emission downstream.
    """
    keystore = (yaml_path.parent / doc.get("keystore", {}).get("path", "./.tn/keys")).resolve()
    device = DeviceKey.from_private_bytes(_read_bytes(keystore / "local.private"))
    master_path = keystore / "index_master.key"
    master_index_key = _read_bytes(master_path) if master_path.exists() else b""
    return keystore, device, master_index_key


def _instantiate_group_cipher(
    name: str, group_cipher: str, keystore: Path
) -> _cipher.GroupCipher:
    """Build the ``GroupCipher`` instance for a single group.

    For JWE, detect "recipient view" (we have a sender_pub sidecar + my
    private key but not the sender key itself) and route through
    ``as_recipient`` so decrypt works in absorbed kits.
    """
    if group_cipher == "btn":
        return _cipher.BtnGroupCipher.load(keystore, name)
    # jwe
    sender_pub_sidecar = keystore / f"{name}.jwe.sender_pub"
    mykey_path = keystore / f"{name}.jwe.mykey"
    sender_path = keystore / f"{name}.jwe.sender"
    if sender_pub_sidecar.exists() and mykey_path.exists() and not sender_path.exists():
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        my_sk = X25519PrivateKey.from_private_bytes(mykey_path.read_bytes())
        return _cipher.JWEGroupCipher.as_recipient(
            sender_pub_sidecar.read_bytes(),
            my_sk,
        )
    return _cipher.JWEGroupCipher.load(keystore, name)


def _load_group(
    name: str,
    spec: dict[str, Any],
    *,
    ceremony_cipher: str,
    ceremony_id: str,
    keystore: Path,
    master_index_key: bytes,
    yaml_path: Path,
) -> GroupConfig:
    """Materialise a single ``GroupConfig`` from its yaml spec.

    Validates the per-group cipher (falling back to ceremony cipher),
    derives the equality-index key (only when this kit holds the master
    secret), and returns the assembled record.
    """
    pool = int(spec.get("pool_size", DEFAULT_POOL_SIZE))
    epoch = int(spec.get("index_epoch", 0))
    raw_cipher = spec.get("cipher") or ceremony_cipher
    if raw_cipher not in ("jwe", "btn"):
        raise ValueError(
            f"{yaml_path}: groups.{name}.cipher is {raw_cipher!r}; "
            f"expected 'jwe' or 'btn' (legacy 'bgw'/'bearer' removed)"
        )
    inst = _instantiate_group_cipher(name, raw_cipher, keystore)
    derived_index_key = (
        _indexing._derive_group_index_key(master_index_key, ceremony_id, name, epoch)
        if master_index_key
        else b""
    )
    return GroupConfig(
        name=name,
        cipher=inst,
        pool_size=pool,
        unissued_slots=[],
        index_key=derived_index_key,
        index_epoch=epoch,
    )


def load(yaml_path: Path) -> LoadedConfig:
    """Read, validate, and assemble a :class:`LoadedConfig` from yaml.

    High-level shape (each step is its own helper above):

    1. Read raw yaml and resolve the ``extends:`` chain.
    2. Validate top-level structure + reserved group namespace.
    3. Pack the ceremony scalars (id, cipher, mode, linked_*).
    4. Resolve the admin-log location with legacy-key migration.
    5. Resolve keystore dir + device key + optional master index key.
    6. Instantiate every group's cipher and derive its index key.
    7. Build the field→groups routing table and configure the LLM
       classifier stub.
    """
    yaml_path = yaml_path.resolve()
    doc = _read_yaml_doc(yaml_path)

    # Resolve extends: chain *before* validation. After this point the
    # merged doc carries identity, groups, recipients from the root
    # of the chain; the per-stream child supplied only its overrides.
    doc = _resolve_extends(yaml_path, doc)

    _validate_load_doc_structure(yaml_path, doc)
    field_to_groups = _build_field_to_groups(doc, yaml_path)
    rust_summary = _rust_config_summary(yaml_path)
    ceremony_block = doc.get("ceremony") or {}
    vault_settings = _vault_settings_from_rust(yaml_path, rust_summary)
    settings = _resolve_ceremony_settings(yaml_path, ceremony_block, vault_settings)
    pel = _resolve_admin_log_location(yaml_path, ceremony_block)

    logs_block = doc.get("logs") or {}
    log_path = str(logs_block.get("path") or "./.tn/logs/tn.ndjson")
    # Validate the main-log path template (if any). Same tokens
    # the admin log accepts; the runtime writer renders per-envelope.
    # See LoadedConfig.resolve_log_path_for / FileTemplatedRotatingHandler.
    if "{" in log_path:
        _validate_path_template(log_path, yaml_path.parent, key_name="logs.path")

    keystore, device, master_index_key = _load_keystore_and_keys(yaml_path, doc)

    groups: dict[str, GroupConfig] = {
        name: _load_group(
            name,
            spec,
            ceremony_cipher=settings.cipher_name,
            ceremony_id=settings.ceremony_id,
            keystore=keystore,
            master_index_key=master_index_key,
            yaml_path=yaml_path,
        )
        for name, spec in doc["groups"].items()
    }

    # Hand the LLM classifier its config so the stub knows if it's
    # "enabled" (it currently does nothing either way).
    _classifier._configure(doc.get("llm_classifier"))

    return LoadedConfig(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        ceremony_id=settings.ceremony_id,
        master_index_key=master_index_key,
        cipher_name=settings.cipher_name,
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
        mode=settings.mode,
        linked_vault=settings.linked_vault,
        linked_project_id=settings.linked_project_id,
        vault_enabled=vault_settings.enabled,
        vault_declared=vault_settings.present,
        vault_url=vault_settings.url,
        vault_linked_project_id=vault_settings.linked_project_id,
        vault_autosync=vault_settings.autosync,
        vault_sync_interval_seconds=vault_settings.sync_interval_seconds,
        sync_logs=settings.sync_logs,
        sign=settings.sign,
        chain=settings.chain,
        project_name=settings.project_name,
        version_name=settings.version_name,
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
