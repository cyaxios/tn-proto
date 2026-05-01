"""The tn.log public API: init + debug/info/warning/error (PRD §6).

Steps of `_emit` (PRD §6.3):
  1. Merge context (contextvars) with kwargs.
  2. Classify each field: public (per YAML) vs group-routed.
  3. Hash every field value (SHA-256 over canonical serialization).
  4. Encrypt each group's field dict with BGW (one ciphertext per group).
  5. Build chain: prev_hash from last entry in this event_type's chain.
  6. Sign row_hash with the device Ed25519 key.
  7. Append the JSON envelope to the log file.

Step 8 ("publish firehose") from the PRD is deferred — requires wallet
+ Kafka integration that is out of scope for the MVP wrapper.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import cipher as _cipher
from . import classifier as _classifier
from .canonical import _canonical_bytes
from .chain import ChainState, _compute_row_hash
from .config import LoadedConfig, load_or_create
from .context import get_context
from .handlers import TNHandler, build_handlers
from .indexing import _index_token
from .signing import _signature_b64

_log = logging.getLogger("tn.logger")

# event_type is user-controlled. It's used in filename / topic templates
# downstream, so whitelist ruthlessly at the entry point.
_EVENT_TYPE_RE = re.compile(r"^[a-z0-9._-]{1,64}$", re.IGNORECASE)


def _validate_event_type(event_type: str) -> str:
    if not isinstance(event_type, str) or not _EVENT_TYPE_RE.match(event_type):
        raise ValueError(
            f"event_type {event_type!r} invalid — allowed charset [A-Za-z0-9._-], 1..64 chars"
        )
    return event_type


def _pel_glob(cfg: LoadedConfig) -> list[Path]:
    """Return all existing files matching the protocol_events_location template."""
    import re as _re

    pel = cfg.protocol_events_location
    if pel == "main_log":
        return []
    yaml_dir = cfg.yaml_path.parent
    pat = pel.replace("{yaml_dir}", str(yaml_dir))
    pat = _re.sub(r"\{[^}]+\}", "*", pat)
    p = Path(pat)
    if p.is_absolute():
        if "*" not in pat and "?" not in pat:
            return [p] if p.is_file() else []
        parts = p.parts
        i = next((j for j, part in enumerate(parts) if "*" in part or "?" in part), len(parts))
        base = Path(*parts[:i]) if i > 0 else p.parent
        rel = str(Path(*parts[i:]))
        return list(base.glob(rel)) if base.exists() else []
    else:
        rel_parts = Path(pat).parts
        rel = str(Path(*rel_parts[1:])) if rel_parts and rel_parts[0] == "." else str(Path(pat))
        return list(yaml_dir.glob(rel)) if rel and yaml_dir.exists() else []


def _seed_chain_from_pel(chain: ChainState, cfg: LoadedConfig) -> None:
    last_by_type: dict[str, tuple[int, str]] = {}
    for path in sorted(_pel_glob(cfg)):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as f:
                for raw_line in f:
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    try:
                        env = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    et = env.get("event_type")
                    seq = env.get("sequence")
                    row = env.get("row_hash")
                    if not (isinstance(et, str) and isinstance(seq, int) and isinstance(row, str)):
                        continue
                    prior = last_by_type.get(et)
                    if prior is None or seq > prior[0]:
                        last_by_type[et] = (seq, row)
        except OSError:
            continue
    if last_by_type:
        chain.seed(last_by_type)


def _seed_chain_from_logs(chain: ChainState, log_dir: Path) -> None:
    """Scan ndjson files in `log_dir` and seed `chain` with the last
    (sequence, row_hash) observed per event_type.

    Reads public envelope fields only (event_type, sequence, row_hash);
    no decryption, no signature verification. Malformed lines are
    skipped quietly so a partially-written tail during an earlier crash
    does not block restart.
    """
    if not log_dir.exists() or not log_dir.is_dir():
        return
    last_by_type: dict[str, tuple[int, str]] = {}
    for path in sorted(log_dir.iterdir()):
        if not path.is_file() or not path.name.endswith(".ndjson"):
            continue
        try:
            with open(path, "rb") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        env = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    et = env.get("event_type")
                    seq = env.get("sequence")
                    row = env.get("row_hash")
                    if not (isinstance(et, str) and isinstance(seq, int) and isinstance(row, str)):
                        continue
                    prior = last_by_type.get(et)
                    if prior is None or seq > prior[0]:
                        last_by_type[et] = (seq, row)
        except OSError:
            continue
    if last_by_type:
        chain.seed(last_by_type)


# --------------------------------------------------------------------
# Module-level singleton: one running TN instance per process.
# --------------------------------------------------------------------

_runtime: TNRuntime | None = None
_runtime_lock = threading.Lock()
_last_claim_session = None  # populated by tn.init(...) when the V2 claim URL fires


class TNRuntime:
    def __init__(
        self,
        cfg: LoadedConfig,
        default_log_dir: Path,
        *,
        extra_handlers: list[TNHandler] | None = None,
    ):
        self.cfg = cfg
        self.default_log_dir = default_log_dir
        self.chain = ChainState()
        # Reentrant lock around the emit critical section
        # (_classify -> encrypt -> chain.advance -> _compute_row_hash -> sign ->
        #  write -> handler fan-out -> chain.commit). Reentrant because a
        # handler invoked under this lock may call back into tn.log() to
        # emit a derived event; without RLock that re-entry would deadlock.
        # See Workstream D7 in 2026-04-24-tn-protocol-review-remediation.md.
        self._emit_lock = threading.RLock()
        default_log_dir.mkdir(parents=True, exist_ok=True)

        # Seed the per-event-type chain state from any existing ndjson logs
        # in the directory. Without this, restarting the process and then
        # logging an event_type that already appears in the log breaks the
        # reader's chain continuity check (every restart would start a new
        # sequence 1 with prev_hash = ZERO_HASH).
        _seed_chain_from_logs(self.chain, default_log_dir)
        _seed_chain_from_pel(self.chain, cfg)

        self.handlers: list[TNHandler] = build_handlers(
            cfg.handler_specs,
            yaml_dir=cfg.yaml_path.parent,
            default_log_dir=default_log_dir,
        )
        if extra_handlers:
            self.handlers.extend(extra_handlers)

    def emit(self, level: str, event_type: str, fields: dict[str, Any]) -> dict[str, Any]:
        _validate_event_type(event_type)
        # The whole pipeline below — _classify, encrypt, chain.advance,
        # _compute_row_hash, sign, write, handler fan-out, chain.commit —
        # is one critical section. Two threads racing here would otherwise
        # both read the same prev_hash from chain.advance() and emit two
        # envelopes claiming the same (event_type, sequence) slot,
        # corrupting the on-disk chain. RLock so handlers calling back
        # into tn.log() don't deadlock. See Workstream D7.
        with self._emit_lock:
            return self._emit_locked(level, event_type, fields)

    def _emit_locked(
        self, level: str, event_type: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        # 1. merge context
        merged = {**get_context(), **fields}

        # 2. _classify public vs group buckets
        #
        # Multi-group routing: a field declared under N groups in yaml
        # (`groups[<g>].fields: [...]`) gets encrypted into all N groups'
        # payloads. Each group's reader sees the same plaintext value
        # independently. The `field_to_groups` map is built at yaml-load
        # time and sorted alphabetically per field so envelope encoding
        # stays canonical across SDK implementations.
        public_keys = set(self.cfg.public_fields)
        public_out: dict[str, Any] = {}
        per_group: dict[str, dict[str, Any]] = {}
        for k, v in merged.items():
            if k in public_keys:
                public_out[k] = v
                continue
            gnames = self.cfg.field_to_groups.get(k)
            if not gnames:
                # Field has no declared route. Try the LLM classifier (which
                # is a stub today and returns "default"). If that yields a
                # known group, use it. Otherwise fall back to the default
                # group when one exists. As a last resort raise — the silent
                # fall-through that hid typos is exactly what multi-group
                # routing was meant to fix.
                guess = _classifier._classify(k, v, list(self.cfg.groups))
                if guess in self.cfg.groups:
                    gnames = [guess]
                elif "default" in self.cfg.groups:
                    gnames = ["default"]
                else:
                    raise ValueError(
                        f"field {k!r} has no group route and is not in "
                        f"public_fields. Add it to `groups[<g>].fields` in "
                        f"tn.yaml, list it under public_fields, or define a "
                        f"`default` group to absorb unknowns."
                    )
            for gname in gnames:
                if gname not in self.cfg.groups:
                    # Should be unreachable: load-time validation rejects
                    # routes to unknown groups. Defensive raise here so a
                    # mutated cfg doesn't silently drop fields.
                    raise ValueError(
                        f"field {k!r} routed to unknown group {gname!r} "
                        f"(known groups: {sorted(self.cfg.groups)})"
                    )
                per_group.setdefault(gname, {})[k] = v

        # 3. index token per private field (keyed HMAC under the group's
        #    HKDF-derived index key; see tn/indexing.py). Tokens are
        #    emitted per-group only for private fields — public fields
        #    need no index token since their value is already in the
        #    clear.
        group_payloads: dict[str, dict[str, Any]] = {}
        for gname, plain_fields in per_group.items():
            group_cfg = self.cfg.groups[gname]
            field_hashes: dict[str, str] = {}
            for fname, fval in plain_fields.items():
                field_hashes[fname] = _index_token(group_cfg.index_key, fname, fval)

            # 4. encrypt group plaintext via the ceremony's cipher (BGW
            #    or JWE — see tn/cipher.py). If this party isn't a
            #    publisher for the group, the cipher raises and we skip.
            plaintext_bytes = _canonical_bytes(plain_fields)
            try:
                ct_bytes = group_cfg.cipher.encrypt(plaintext_bytes)
            except _cipher.NotAPublisherError as e:
                _log.warning(
                    "skipping group %r for %s: %s",
                    gname,
                    event_type,
                    e,
                )
                continue
            group_payloads[gname] = {
                "ciphertext": ct_bytes,  # raw bytes — we'll b64 in envelope
                "field_hashes": field_hashes,
            }

        # 5. chain
        seq, prev_hash = self.chain.advance(event_type)
        timestamp = (
            datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
        event_id = str(uuid.uuid4())
        level_norm = level.lower()

        row_hash = _compute_row_hash(
            did=self.cfg.device.did,
            timestamp=timestamp,
            event_id=event_id,
            event_type=event_type,
            level=level_norm,
            prev_hash=prev_hash,
            public_fields=public_out,
            groups=group_payloads,
        )

        # 6. sign
        sig = self.cfg.device.sign(row_hash.encode("ascii"))

        # 7. append envelope as JSON line
        envelope: dict[str, Any] = {
            "did": self.cfg.device.did,
            "timestamp": timestamp,
            "event_id": event_id,
            "event_type": event_type,
            "level": level_norm,
            "sequence": seq,
            "prev_hash": prev_hash,
            "row_hash": row_hash,
            "signature": _signature_b64(sig),
        }
        for k, v in public_out.items():
            envelope.setdefault(k, v)
        for gname, g in group_payloads.items():
            envelope[gname] = {
                "ciphertext": base64.b64encode(g["ciphertext"]).decode("ascii"),
                "field_hashes": g["field_hashes"],
            }

        from ._entry import _json_default
        line = json.dumps(envelope, separators=(",", ":"), default=_json_default) + "\n"
        raw = line.encode("utf-8")

        # Route protocol events (tn.*) to separate file if configured
        if event_type.startswith("tn.") and self.cfg.protocol_events_location != "main_log":
            pel_path = self.cfg.resolve_protocol_events_path(event_type)
            pel_path.parent.mkdir(parents=True, exist_ok=True)
            with open(pel_path, "a", encoding="utf-8") as _pel_f:
                _pel_f.write(line)
            self.chain.commit(event_type, row_hash)
            return envelope

        # Fan out to every handler whose filter accepts this envelope.
        delivered = 0
        for h in self.handlers:
            if not h.accepts(envelope):
                continue
            try:
                h.emit(envelope, raw)
                delivered += 1
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                # A failing sync handler must not take down the caller.
                # Async handlers already swallow + retry internally.
                _log.exception(
                    "handler %r raised on %s/%s; entry already sealed",
                    h.name,
                    event_type,
                    envelope["event_id"],
                )
        if delivered == 0:
            _log.warning(
                "no handler accepted event %s/%s — envelope computed but not written",
                event_type,
                envelope["event_id"],
            )

        self.chain.commit(event_type, row_hash)
        return envelope

    def close(self, *, timeout: float = 30.0) -> None:
        for h in self.handlers:
            try:
                h.close(timeout=timeout)
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception("handler %r close failed", h.name)


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------


def init(
    yaml_path: str | os.PathLike[str],
    *,
    log_path: str | os.PathLike[str] | None = None,  # back-compat: forces
    # default_file handler
    # at this exact path
    pool_size: int = 4,
    cipher: str = "btn",  # only affects fresh ceremonies
    identity=None,  # tn.identity.Identity or None
    extra_handlers: list[TNHandler] | None = None,  # for tests / programmatic
    stdout: bool | None = None,  # None = default-on unless TN_NO_STDOUT=1
) -> None:
    """Load or create the ceremony at `yaml_path`.

    Handler resolution:
      1. If tn.yaml has a `handlers:` section, use that.
      2. Else if `log_path` is passed explicitly, synthesize a single
         rotating-file handler at that path (back-compat for callers that
         predate the handlers YAML).
      3. Else default to `<yaml-dir>/.tn/logs/tn.ndjson` (5 MB x 5 backups).

    `cipher` selects the group-sealing primitive when the YAML doesn't
    exist yet and a fresh ceremony is created ("jwe" or "bgw"). Has no
    effect when the YAML already exists — the cipher is read from the YAML.

    `identity` — optional tn.identity.Identity. If passed AND the yaml
    doesn't exist yet (fresh ceremony path), the ceremony's device key
    binds to identity.device_private_key_bytes() so the DID written
    into tn.yaml matches the Identity. Has no effect when loading an
    existing yaml (device key comes from the keystore on disk).

    Idempotent: re-initializing with the same args returns without error.
    """
    global _runtime
    with _runtime_lock:
        if _runtime is not None:
            _runtime.close()
            _runtime = None

        # V2 claim-on-missing-identity path (spec §13.5):
        # When TN_CLAIM_ON_MISSING_IDENTITY=1 is set AND no explicit
        # identity was passed AND no identity.json exists AND the yaml
        # is about to be auto-created, spin up a loopback claim URL.
        # The mnemonic is accessible via the URL (with fragment key +
        # confirm code); the caller gets a ClaimSession via the
        # `_last_claim_session` module global.
        if (
            identity is None
            and os.environ.get("TN_CLAIM_ON_MISSING_IDENTITY") == "1"
            and not Path(yaml_path).exists()
        ):
            from . import claim as _claim
            from .identity import _default_identity_path

            if not _default_identity_path().exists():
                session = _claim.start_claim()
                identity = session.identity
                global _last_claim_session
                _last_claim_session = session
                print(
                    f"[tn.init] identity.json not found -- claim URL:\n"
                    f"    {session.url}\n"
                    f"    Confirmation code: {session.confirmation_code}\n"
                    f"    (TTL: {int(session.expires_at - __import__('time').time())}s)",
                    flush=True,
                )

        create_kwargs: dict = {"pool_size": pool_size, "cipher": cipher}
        if identity is not None:
            create_kwargs["device_private_bytes"] = identity.device_private_key_bytes()
        cfg = load_or_create(yaml_path, **create_kwargs)

        # --- auto-absorb inbox + _reconcile (unified-read Plan 1) ---
        from .absorb import absorb as _absorb
        from .conventions import inbox_dir
        from .reconcile import _reconcile

        # Inbox is at ``<yaml_dir>/.tn/<stem>/inbox/`` per the per-stem
        # namespacing (FINDINGS #2). No more eager-create-everything;
        # ghost dirs from the pre-namespacing layout (S0.2) stay gone.
        resolved_yaml = Path(yaml_path).resolve()
        inbox = inbox_dir(resolved_yaml)
        if not inbox.exists():
            # Nothing to drain — skip the absorb loop. Fresh ceremony
            # with no operator-dropped packages: don't create the dir
            # just to scan an empty glob.
            inbox = None

        # Absorb any .tnpkg packages waiting in inbox. Delete on success;
        # leave on failure for inspection.
        for pkg_path in sorted(inbox.glob("*.tnpkg")) if inbox is not None else []:
            try:
                result = _absorb(cfg, pkg_path)
                if result.status in (
                    "offer_stashed",
                    "enrolment_applied",
                    "coupon_applied",
                    "no_op",
                ):
                    pkg_path.unlink()
                else:
                    _log.warning(
                        "absorb did not accept %s: %s (%s); file left in inbox for inspection.",
                        pkg_path,
                        result.status,
                        result.reason,
                    )
            except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.warning(
                    "absorb raised on %s: %s; file left in inbox.",
                    pkg_path,
                    e,
                )

        # Reload cfg if absorb mutated yaml or keystore. Reconcile may
        # mutate again (promotions, auto-coupons).
        cfg = load_or_create(yaml_path)
        try:
            _reconcile(cfg)
        except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.warning("_reconcile raised: %s; init continuing.", e)
        # Reload once more if _reconcile mutated.
        cfg = load_or_create(yaml_path)
        # ------------------------------------------------------------

        synthesized_default = False
        if log_path is not None and cfg.handler_specs is None:
            # Back-compat path: synthesize spec matching the legacy default.
            cfg.handler_specs = [
                {
                    "kind": "file.rotating",
                    "name": "main",
                    "path": str(log_path),
                    "max_bytes": 5 * 1024 * 1024,
                    "backup_count": 5,
                }
            ]
            # Track that this handler list is a back-compat synthesis, not a
            # user-declared one. DispatchRuntime checks ``_tn_default`` on
            # each handler to decide whether the Rust runtime is safe — a
            # synthesized handler is morally equivalent to the zero-config
            # default and must NOT disable the Rust path. (Bug fixed:
            # ``tn.init(yaml, log_path=...)`` was kicking btn ceremonies to
            # the Python fallback, breaking ``admin_add_recipient``.)
            synthesized_default = True

        # Default-on stdout handler: matches stdlib logging mental model
        # (logs land on stdout unless explicitly silenced). Opt-out via:
        #
        #   * ``TN_NO_STDOUT=1`` env var
        #   * ``stdout=False`` kwarg (wins over env)
        #   * yaml ``handlers: [...]`` declared with no ``kind: stdout``
        #     entry — yaml-as-contract per FINDINGS S0.4: removing the
        #     stdout entry silences stdout for both admin and user emits.
        #
        # When the yaml has no ``handlers:`` block at all, the legacy
        # default-on behavior applies (auto-add stdout). When the yaml
        # DOES declare handlers, the list is authoritative — auto-add
        # only fires if stdout is explicitly listed.
        if stdout is None:
            stdout = os.environ.get("TN_NO_STDOUT", "").strip() != "1"
        handler_specs = cfg.handler_specs
        yaml_declares_handlers = handler_specs is not None and len(handler_specs) > 0
        # When the yaml declares a ``handlers:`` block, that list is
        # authoritative — the registry builds whatever's in it. Skip the
        # auto-added stdout entirely so the operator's edits are honored
        # (silencing stdout means removing the entry; double-add would
        # ignore that intent). Legacy yamls with no handlers block fall
        # through to the default-on auto-stdout for back-compat.
        if stdout and not yaml_declares_handlers:
            from .handlers.stdout import StdoutHandler

            stdout_handler = StdoutHandler()
            # Mark as a "default" handler so DispatchRuntime does NOT switch
            # to the Python emit path on its account — the btn admin verbs
            # require the Rust path, and dropping back to Python would break
            # them (NotImplementedError on add_recipient_btn etc.). Side effect:
            # on btn ceremonies that activate the Rust runtime, stdout output
            # is currently silent because Rust writes only to the file and
            # doesn't fan out to Python handlers. The cross-language port will
            # close this gap by adding stdout to the Rust runtime directly.
            stdout_handler._tn_default = True  # type: ignore[attr-defined]
            extra_handlers = [stdout_handler, *(extra_handlers or [])]

        # Use cfg.log_path (from yaml `logs.path`, default `./.tn/logs/tn.ndjson`)
        # to discover the main log location; TNRuntime wants the directory.
        default_log_path = cfg.resolve_log_path()
        default_log_dir = default_log_path.parent
        _runtime = TNRuntime(cfg, default_log_dir, extra_handlers=extra_handlers)
        if synthesized_default:
            for h in _runtime.handlers:
                # Mark every handler in the synthesized list as default so
                # DispatchRuntime treats them like the zero-config defaults.
                h._tn_default = True  # type: ignore[attr-defined]


def _require_init() -> TNRuntime:
    if _runtime is None:
        raise RuntimeError("tn.init(yaml_path) must be called before tn.log")
    return _runtime


def log(event_type: str, **fields: Any) -> dict[str, Any]:
    """Severity-less log. Use this when the event isn't fundamentally
    debug/info/warning/error — it's just a fact to attest."""
    return _require_init().emit("", event_type, fields)


def debug(event_type: str, **fields: Any) -> dict[str, Any]:
    return _require_init().emit("debug", event_type, fields)


def info(event_type: str, **fields: Any) -> dict[str, Any]:
    return _require_init().emit("info", event_type, fields)


def warning(event_type: str, **fields: Any) -> dict[str, Any]:
    return _require_init().emit("warning", event_type, fields)


def error(event_type: str, **fields: Any) -> dict[str, Any]:
    return _require_init().emit("error", event_type, fields)


def current_config() -> LoadedConfig:
    return _require_init().cfg


def flush_and_close(*, timeout: float = 30.0) -> None:
    """Close all handlers (drains async outboxes best-effort)."""
    global _runtime
    with _runtime_lock:
        if _runtime is not None:
            _runtime.close(timeout=timeout)
            _runtime = None
