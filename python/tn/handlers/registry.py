"""Build handler instances from the YAML ``handlers:`` list.

Supported ``kind`` values:

=========================================  =======
Kind                                       Notes
=========================================  =======
``file.rotating`` / ``file``               Size-based rotation (default)
``file.timed_rotating``                    Time-based rotation
``kafka``                                  Confluent / self-hosted Kafka
``s3`` / ``aws.s3``                        AWS S3 (or compatible)
``delta`` / ``delta_table`` / ``databricks`` Databricks Delta tables
``vault.sync``                             tnproto-org cloud vault (RFC §4)
``vault.push``                             admin snapshot push (plan §5.2)
``vault.pull``                             admin snapshot pull (plan §5.2)
``fs.drop``                                local outbox drop (plan §5.2)
``fs.scan``                                local inbox scan (plan §5.2)
``stdout``                                 write JSON envelope lines to stdout
=========================================  =======

Filter specs are parsed by :func:`tn.filters._compile_filter` which
handles both the classic field/op dict shape and the RFC §3.2 shorthand
keys (``event_type_prefix``, ``not_event_type_prefix``, ``event_type_in``,
``level_in``, ``sync``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .base import TNHandler
from .file import FileRotatingHandler, FileTimedRotatingHandler

_log = logging.getLogger("tn.handlers")


def default_file_handler(log_dir: Path) -> TNHandler:
    """The zero-config default: 5 MB rotating at <log_dir>/tn.ndjson."""
    h = FileRotatingHandler(
        name="default",
        path=log_dir / "tn.ndjson",
        max_bytes=5 * 1024 * 1024,
        backup_count=5,
    )
    # Sentinel so DispatchRuntime can distinguish the zero-config default
    # (which the Rust runtime replaces, not duplicates) from user-registered
    # handlers (Kafka, Delta, etc.) that need the Python fan-out path.
    h._tn_default = True  # type: ignore[attr-defined]
    return h


def build_handlers(
    specs: list[dict[str, Any]] | None,
    *,
    yaml_dir: Path,
    default_log_dir: Path,
) -> list[TNHandler]:
    """Instantiate handlers from YAML. If `specs` is None, synthesize the
    default. Empty list means user explicitly opted out — honor it."""
    if specs is None:
        return [default_file_handler(default_log_dir)]
    if not specs:
        _log.warning(
            "tn.yaml: handlers: is present but empty — no log output will be "
            "written. Remove the key or add at least one handler."
        )
        return []

    out: list[TNHandler] = []
    for raw in specs:
        kind = raw.get("kind", "").lower()
        name = raw.get("name") or kind or "handler"
        filter_spec = raw.get("filter")

        if kind in ("file.rotating", "file"):
            path = _resolve_path(raw["path"], yaml_dir)
            handler = FileRotatingHandler(
                name=name,
                path=path,
                max_bytes=int(raw.get("max_bytes", 5 * 1024 * 1024)),
                backup_count=int(raw.get("backup_count", 5)),
                # Default off: TN log is an attestation chain;
                # rotation at session start breaks chain verification
                # across the rotation boundary. Yaml
                # `rotate_on_init: true` opts in for operators who
                # want a separate file per session.
                rotate_on_init=bool(raw.get("rotate_on_init", False)),
                filter_spec=filter_spec,
            )
            # The yaml-declared file handler is the canonical default sink
            # for ceremonies — Rust writes to the same log file itself, so
            # this handler must be marked as a "default" so the dispatch
            # layer can keep using the Rust path. The Python emit path
            # also writes via this handler (same as before); only the Rust
            # path treats it as "already covered, skip the Python copy".
            handler._tn_default = True  # type: ignore[attr-defined]
            out.append(handler)
        elif kind == "file.timed_rotating":
            path = _resolve_path(raw["path"], yaml_dir)
            out.append(
                FileTimedRotatingHandler(
                    name=name,
                    path=path,
                    when=raw.get("when", "midnight"),
                    backup_count=int(raw.get("backup_count", 30)),
                    filter_spec=filter_spec,
                )
            )
        elif kind == "kafka":
            from .kafka import KafkaHandler

            out.append(
                KafkaHandler(
                    name=name,
                    outbox_path=_outbox_path(yaml_dir, name),
                    bootstrap=raw["bootstrap"],
                    topic=raw["topic"],
                    sasl=raw.get("sasl"),
                    client_id=raw.get("client_id", "tn-protocol"),
                    compression_type=raw.get("compression_type", "zstd"),
                    acks=raw.get("acks", "all"),
                    filter_spec=filter_spec,
                )
            )
        elif kind in ("s3", "aws.s3"):
            from .s3 import S3Handler

            out.append(
                S3Handler(
                    name=name,
                    outbox_path=_outbox_path(yaml_dir, name),
                    bucket=raw["bucket"],
                    prefix=raw.get("prefix", "tn"),
                    region=raw.get("region"),
                    access_key=raw.get("access_key"),
                    secret_key=raw.get("secret_key"),
                    session_token=raw.get("session_token"),
                    endpoint_url=raw.get("endpoint_url"),
                    sse=raw.get("sse"),
                    sse_kms_key_id=raw.get("sse_kms_key_id"),
                    batch_max_rows=int(raw.get("batch_max_rows", 500)),
                    batch_max_bytes=int(raw.get("batch_max_bytes", 10 * 1024 * 1024)),
                    batch_window_sec=float(raw.get("batch_window_sec", 60.0)),
                    filter_spec=filter_spec,
                )
            )
        elif kind in ("delta", "delta_table", "databricks"):
            from .delta import DeltaTableHandler

            out.append(
                DeltaTableHandler(
                    name=name,
                    outbox_path=_outbox_path(yaml_dir, name),
                    host=raw["host"],
                    token=raw["token"],
                    warehouse_id=raw.get("warehouse_id", "auto"),
                    catalog=raw.get("catalog", "workspace"),
                    schema=raw.get("schema", "bronze"),
                    table=raw.get("table", "tn_events_bronze"),
                    partition_by=raw.get("partition_by"),
                    batch_max_rows=int(raw.get("batch_max_rows", 500)),
                    batch_max_bytes=int(raw.get("batch_max_bytes", 10 * 1024 * 1024)),
                    batch_window_sec=float(raw.get("batch_window_sec", 60.0)),
                    one_table_per_event_type=bool(raw.get("one_table_per_event_type", False)),
                    filter_spec=filter_spec,
                )
            )
        elif kind in ("vault.sync", "vault"):
            from .vault_sync import VaultSyncHandler

            # Resolve the alice DID and private key from the keystore so
            # the handler can authenticate against the vault. The keystore
            # path is expected to contain ``local.private`` (raw 32-byte
            # Ed25519 seed) and ``local.public`` (did:key string).
            keystore_path = _resolve_keystore(raw, yaml_dir)
            alice_did, alice_priv = _load_device_key(keystore_path)
            out.append(
                VaultSyncHandler(
                    name=name,
                    outbox_path=_outbox_path(yaml_dir, name),
                    vault_did=raw["vault_did"],
                    project_id=raw["project_id"],
                    alice_did=alice_did,
                    alice_private_key_bytes=alice_priv,
                    batch_interval_sec=float(raw.get("batch_interval_ms", 5000)) / 1000.0,
                    batch_max_events=int(raw.get("batch_max_events", 100)),
                    filter_spec=filter_spec,
                )
            )
        elif kind == "vault.push":
            from .vault_push import VaultPushHandler

            poll = _parse_duration(raw.get("poll_interval", 60.0))
            out.append(
                VaultPushHandler(
                    name=name,
                    endpoint=raw["endpoint"],
                    project_id=raw["project_id"],
                    trigger=str(raw.get("trigger", "on_schedule")),
                    poll_interval=poll,
                    scope=str(raw.get("scope", "admin")),
                    filter_spec=filter_spec,
                )
            )
        elif kind == "vault.pull":
            from .vault_pull import VaultPullHandler

            poll = _parse_duration(raw.get("poll_interval", 60.0))
            out.append(
                VaultPullHandler(
                    name=name,
                    endpoint=raw["endpoint"],
                    project_id=raw["project_id"],
                    poll_interval=poll,
                    on_absorb_error=str(raw.get("on_absorb_error", "log")),
                    filter_spec=filter_spec,
                )
            )
        elif kind == "fs.drop":
            from .fs_drop import DEFAULT_FILENAME_TEMPLATE, FsDropHandler

            out_dir_raw = raw.get("out_dir") or "./.tn/outbox"
            out_dir = _resolve_path(out_dir_raw, yaml_dir)
            out.append(
                FsDropHandler(
                    name=name,
                    out_dir=out_dir,
                    on=raw.get("on"),
                    scope=str(raw.get("scope", "admin")),
                    trigger=str(raw.get("trigger", "on_emit")),
                    filename_template=str(
                        raw.get("filename_template", DEFAULT_FILENAME_TEMPLATE)
                    ),
                    filter_spec=filter_spec,
                )
            )
        elif kind == "fs.scan":
            from .fs_scan import FsScanHandler

            in_dir = _resolve_path(raw["in_dir"], yaml_dir)
            archive = (
                _resolve_path(raw["archive_dir"], yaml_dir)
                if raw.get("archive_dir")
                else None
            )
            poll = _parse_duration(raw.get("poll_interval", 30.0))
            out.append(
                FsScanHandler(
                    name=name,
                    in_dir=in_dir,
                    poll_interval=poll,
                    on_processed=str(raw.get("on_processed", "archive")),
                    archive_dir=archive,
                    filter_spec=filter_spec,
                )
            )
        elif kind == "stdout":
            from .stdout import StdoutHandler

            handler = StdoutHandler(name=name, filter_spec=filter_spec)
            # Same rationale as file.rotating above — declarative stdout is
            # the canonical default sink, so it does NOT preclude the Rust
            # dispatch path. (Rust currently doesn't fan to stdout itself,
            # so on btn ceremonies stdout is silent — pre-existing gap
            # tracked separately; doesn't change with this flag.)
            handler._tn_default = True  # type: ignore[attr-defined]
            out.append(handler)
        elif kind in ("otel", "opentelemetry"):
            from .otel import NullOtelLogger, OpenTelemetryHandler

            # The OTel logger must be wired programmatically after init
            # (pass it via tn.init(extra_handlers=[...])). When declared in
            # YAML only, we use the no-op logger and log a warning so the
            # operator knows they need to wire up the provider themselves.
            _log.warning(
                "handler %r: kind=%r in YAML uses NullOtelLogger. "
                "For real export, pass an OpenTelemetryHandler via extra_handlers=.",
                name,
                kind,
            )
            out.append(
                OpenTelemetryHandler(
                    name=name,
                    otel_logger=NullOtelLogger(),
                    filter_spec=filter_spec,
                )
            )
        else:
            raise ValueError(f"tn.yaml: unknown handler kind {kind!r} on handler {name!r}")
    return out


def _parse_duration(raw: Any) -> float:
    """Parse a duration as seconds. Accepts plain numbers, or strings
    like ``"60s"``, ``"5m"``, ``"1h"``. Used by the new pull / scan
    handlers so YAML can stay readable.
    """
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str):
        raise ValueError(f"poll_interval must be a number or string, got {type(raw).__name__}")
    s = raw.strip().lower()
    multiplier = 1.0
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        s = s[:-1]
    elif s.endswith("m"):
        multiplier = 60.0
        s = s[:-1]
    elif s.endswith("h"):
        multiplier = 3600.0
        s = s[:-1]
    return float(s) * multiplier


def _resolve_path(path: str, yaml_dir: Path) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (yaml_dir / p).resolve()


def _outbox_path(yaml_dir: Path, handler_name: str) -> Path:
    """Resolve the per-handler durable retry queue directory.

    Per session-11 outbox-layout-migration plan (2026-04-29): writes go to
    the new per-stem layout (``.tn/<stem>/handlers/<name>/outbox``). Reads
    fall back to the legacy ``.tn/outbox/durable/<name>`` path if the new
    one is empty / absent and the legacy one has on-disk SQLite state, so
    a queued-but-not-yet-drained item from before the migration isn't
    orphaned. The fallback is best-effort and silent.
    """
    from ..conventions import handler_outbox_dir, legacy_handler_outbox_dir

    new_path = handler_outbox_dir(yaml_dir, handler_name).resolve()
    legacy = legacy_handler_outbox_dir(yaml_dir, handler_name).resolve()

    # Prefer legacy only if it has stored state and the new path doesn't
    # already exist. Once the queue drains, future runs migrate naturally.
    legacy_db = legacy / "data.db"
    if legacy_db.exists() and not new_path.exists():
        return legacy
    return new_path


def _resolve_keystore(raw: dict[str, Any], yaml_dir: Path) -> Path:
    """Return the keystore directory for a vault.sync handler spec.

    Looks for ``keystore_path`` in the handler spec, then falls back to
    ``./.tn/keys`` relative to the yaml directory. Used by the vault.sync
    kind to locate the device private key that authenticates against the
    vault.
    """
    ks = raw.get("keystore_path")
    if ks:
        return _resolve_path(ks, yaml_dir)
    # Default: <yaml_dir>/.tn/keys (matches tn config layout).
    return (yaml_dir / ".tn" / "keys").resolve()


def _load_device_key(keystore_path: Path) -> tuple[str, bytes]:
    """Load (did, private_key_bytes) from the keystore directory.

    Reads:
      ``local.public``  -- the did:key string (UTF-8 text).
      ``local.private`` -- raw 32-byte Ed25519 seed.

    Raises ``FileNotFoundError`` when the files are missing (keystore not
    initialised yet) and ``ValueError`` when the key has an unexpected
    size.
    """
    pub_path = keystore_path / "local.public"
    priv_path = keystore_path / "local.private"

    if not pub_path.exists() or not priv_path.exists():
        raise FileNotFoundError(
            f"vault.sync: keystore at {keystore_path} is missing "
            f"local.public or local.private -- run `tn init` first."
        )

    alice_did = pub_path.read_text(encoding="utf-8").strip()
    raw_bytes = priv_path.read_bytes()
    if len(raw_bytes) != 32:
        raise ValueError(
            f"vault.sync: expected 32-byte Ed25519 seed in {priv_path}, got {len(raw_bytes)} bytes"
        )
    return alice_did, raw_bytes
