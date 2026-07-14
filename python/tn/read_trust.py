"""Receiver-local trust sources used by secure read policy resolution.

Trust is deliberately loaded once when a provider is constructed. Read policy
evaluation therefore performs exact-key lookups against an immutable snapshot;
it never consults process-global configuration or mutable files mid-iteration.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, cast, runtime_checkable

import yaml

from ._keystore_backend import AdvisoryFileLock, atomic_write_bytes
from .config import LoadedConfig
from .signing import _ED25519_MULTICODEC, _b58decode, _b58encode

if TYPE_CHECKING:
    from .read_policy import ReadContext


ReadTrustSource: TypeAlias = Literal[
    "local-device",
    "verified-package",
    "explicit-config",
]

_TRUST_SOURCES = frozenset(
    {
        "local-device",
        "verified-package",
        "explicit-config",
    },
)


def validate_ed25519_did(did: object) -> str:
    """Return an exact canonical Ed25519 ``did:key`` or raise ``ValueError``."""

    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError(f"trusted writer must be a canonical Ed25519 did:key; got {did!r}")
    encoded = did.removeprefix("did:key:z")
    if not encoded:
        raise ValueError(f"trusted writer must be a canonical Ed25519 did:key; got {did!r}")
    try:
        decoded = _b58decode(encoded)
    except (ValueError, TypeError) as error:
        raise ValueError(
            f"trusted writer must be a canonical Ed25519 did:key; got {did!r}",
        ) from error
    if len(decoded) != 34 or decoded[:2] != _ED25519_MULTICODEC or _b58encode(decoded) != encoded:
        raise ValueError(f"trusted writer must be a canonical Ed25519 did:key; got {did!r}")
    return did


@runtime_checkable
class ReadTrustProvider(Protocol):
    """Supplies the exact writer allowlist for one receiver's read context."""

    def trusted_writer_dids(self, context: ReadContext) -> frozenset[str]: ...

    def source_for(self, did: str) -> ReadTrustSource | None: ...


class InMemoryReadTrustProvider:
    """Immutable exact-key trust provider, useful for injection and tests."""

    def __init__(self, entries: Mapping[str, ReadTrustSource]) -> None:
        exact_entries: dict[str, ReadTrustSource] = {}
        for did, source in entries.items():
            exact_did = validate_ed25519_did(did)
            if source not in _TRUST_SOURCES:
                raise ValueError(f"invalid read trust source for {did!r}: {source!r}")
            exact_entries[exact_did] = cast(ReadTrustSource, source)
        self._entries: Mapping[str, ReadTrustSource] = MappingProxyType(exact_entries)
        self._trusted_writer_dids = frozenset(exact_entries)

    def trusted_writer_dids(self, context: ReadContext) -> frozenset[str]:
        del context
        return self._trusted_writer_dids

    def source_for(self, did: str) -> ReadTrustSource | None:
        return self._entries.get(did)


class LocalReadTrustProvider(InMemoryReadTrustProvider):
    """Snapshot receiver-local device, package, and explicit configuration trust."""

    def __init__(self, cfg: LoadedConfig, state_root: Path) -> None:
        self.state_root = Path(state_root)
        self.private_record_path = Path(cfg.keystore) / "trust" / "verified_publishers.v1.json"

        entries: dict[str, ReadTrustSource] = {
            did: "explicit-config" for did in _configured_writer_dids(Path(cfg.yaml_path))
        }
        entries.update(
            {did: "verified-package" for did in _verified_publisher_dids(self.private_record_path)},
        )
        local_did = getattr(cfg.device, "device_identity", None)
        if local_did is None:
            local_did = getattr(cfg.device, "did", None)
        entries[validate_ed25519_did(local_did)] = "local-device"
        super().__init__(entries)


def _configured_writer_dids(yaml_path: Path) -> frozenset[str]:
    try:
        document = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError(f"invalid trust configuration in {yaml_path}") from error
    if not isinstance(document, Mapping):
        raise ValueError(f"invalid trust configuration in {yaml_path}: root must be a mapping")
    if "trust" not in document:
        return frozenset()
    trust = document["trust"]
    if not isinstance(trust, Mapping):
        raise ValueError(f"invalid trust configuration in {yaml_path}: trust must be a mapping")
    if "writers" not in trust:
        return frozenset()
    writers = trust["writers"]
    if not isinstance(writers, list):
        raise ValueError(
            f"invalid trust configuration in {yaml_path}: trust.writers must be a list"
        )
    return frozenset(validate_ed25519_did(did) for did in writers)


def _verified_publisher_dids(path: Path) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid verified publisher record in {path}") from error
    if not isinstance(document, Mapping):
        raise ValueError(f"invalid verified publisher record in {path}: expected an object")

    publishers = document.get("publishers", document)
    if not isinstance(publishers, Mapping):
        raise ValueError(
            f"invalid verified publisher record in {path}: publishers must be an object",
        )
    dids: set[str] = set()
    for did, metadata in publishers.items():
        if not isinstance(metadata, Mapping):
            raise ValueError(
                f"invalid verified publisher record in {path}: {did!r} metadata must be an object",
            )
        try:
            dids.add(validate_ed25519_did(did))
        except ValueError as error:
            raise ValueError(f"invalid verified publisher record in {path}: {error}") from error
    return frozenset(dids)


def _record_verified_publisher(
    cfg: LoadedConfig,
    publisher_did: str,
    *,
    source: str,
    evidence: Mapping[str, object],
) -> Path:
    """Atomically merge one authenticated publisher into private read trust."""
    exact_did = validate_ed25519_did(publisher_did)
    path = Path(cfg.keystore) / "trust" / "verified_publishers.v1.json"
    with AdvisoryFileLock(path.with_suffix(".lock")):
        if path.exists():
            _verified_publisher_dids(path)
            document = json.loads(path.read_text(encoding="utf-8"))
            if "publishers" not in document:
                document = {"version": 1, "publishers": document}
        else:
            document = {"version": 1, "publishers": {}}
        publishers = dict(document["publishers"])
        prior = dict(publishers.get(exact_did, {}))
        prior.setdefault("source", source)
        prior["verified_package"] = dict(evidence)
        publishers[exact_did] = prior
        document["publishers"] = publishers
        atomic_write_bytes(
            path,
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
    return path


__all__ = [
    "InMemoryReadTrustProvider",
    "LocalReadTrustProvider",
    "ReadTrustProvider",
    "ReadTrustSource",
    "validate_ed25519_did",
]
