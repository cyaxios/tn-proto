"""Universal ``.tnpkg`` wrapper — signed manifest + kind-specific body.

Every ``.tnpkg`` is a STORED zip archive with this structure::

    foo.tnpkg/                    # zip archive (STORED, no compression)
      manifest.json               # signed JSON; the index
      body/...                    # kind-specific contents

The manifest is signed with Ed25519 by ``publisher_identity``'s device
key, over the RFC 8785-style canonical bytes of the manifest minus the
``manifest_signature_b64`` field. This module owns the wire-format
invariants (manifest schema, signature domain, zip layout). Producer /
consumer dispatch lives in :mod:`tn.export` and :mod:`tn.absorb`.

Kinds shipped in v1:

    admin_log_snapshot     ``body/admin.ndjson`` — every admin
                           envelope this writer has emitted, in chain
                           order.
    offer                  ``body/package.json`` — JWE bootstrap offer.
    enrolment              ``body/package.json`` — JWE enrolment.
    kit_bundle             ``body/<group>.btn.mykit`` files —
                           readers-only, no publisher state.
    full_keystore          ``body/keys/*`` — every keystore file,
                           including private material. Producer must
                           opt in via ``confirm_includes_secrets=True``.
    identity_seed          ``body/local.private`` + ``body/local.public``
                           + ``body/tn.yaml`` — minimal "this is who I am"
                           bundle a fresh recipient absorbs to bootstrap
                           a TN identity. Self-signed (from_did == to_did).
    contact_update         Contact-record sync from the vault inbox.

See `docs/spec/discrepancies.md#manifest-kinds <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/discrepancies.md#manifest-kinds>`_
for the cross-implementation kind-recognition state — Rust + TS lag on
``identity_seed`` and ``project_seed`` at the type level even though
all three implementations handle both kinds at runtime.

See Also:
    `docs/spec/manifest.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/manifest.md>`_:
        Authoritative wire spec — manifest schema + signature.
    `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
        Sealed body frame for bundles whose body is encrypted.
    `docs/spec/recipient-wraps.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/recipient-wraps.md>`_:
        Per-recipient BEK seal inside ``state.body_encryption``.
    `docs/spec/signing.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/signing.md>`_:
        Manifest signatures use standard base64 with padding (distinct
        from envelope signatures' URL-safe-no-pad encoding).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from tn_core import _core as _tn_core

from .signing import DeviceKey, _b58decode

# Manifest schema version. Bump if the manifest's required fields change in
# a backwards-incompatible way.
MANIFEST_VERSION = 1

# v1 dispatch discriminators. Adding a new kind requires an absorb handler
# in ``tn.absorb`` and (for snapshots) a producer in ``tn.export``.
KNOWN_KINDS = frozenset(_tn_core.manifest_known_kinds())


@dataclass
class TnpkgManifest:
    """Decoded `.tnpkg` manifest. Mirrors the JSON on the wire.

    Use ``to_dict()`` to serialize and ``sign(sk)`` to populate
    ``manifest_signature_b64`` after every other field is final. Calling
    ``sign()`` mutates the dataclass in place and also returns it.
    """

    kind: str
    publisher_identity: str
    ceremony_id: str
    as_of: str
    scope: str = "admin"
    recipient_identity: str | None = None
    version: int = MANIFEST_VERSION
    clock: dict[str, dict[str, int]] = field(default_factory=dict)
    event_count: int = 0
    head_row_hash: str | None = None
    state: dict[str, Any] | None = None
    manifest_signature_b64: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for ``json.dump``. Omits ``None`` /
        unset optional fields so the canonical form is stable across tiny
        variations in caller code."""
        return dict(_tn_core.manifest_to_dict(_manifest_doc_from_dataclass(self)))

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> TnpkgManifest:
        if not isinstance(doc, dict):
            raise ValueError(f"manifest must be a JSON object; got {type(doc).__name__}")
        missing = [
            k
            for k in ("kind", "version", "publisher_identity", "ceremony_id", "as_of")
            if k not in doc
        ]
        if missing:
            raise ValueError(f"manifest missing required keys: {missing}")
        normalized = dict(_tn_core.manifest_to_dict(doc))
        return cls(
            kind=str(normalized["kind"]),
            version=int(normalized["version"]),
            publisher_identity=str(normalized["publisher_identity"]),
            ceremony_id=str(normalized["ceremony_id"]),
            as_of=str(normalized["as_of"]),
            scope=str(normalized.get("scope", "admin")),
            recipient_identity=(
                str(normalized["recipient_identity"])
                if normalized.get("recipient_identity") is not None
                else None
            ),
            clock=dict(normalized.get("clock") or {}),
            event_count=int(normalized.get("event_count", 0)),
            head_row_hash=(
                str(normalized["head_row_hash"])
                if normalized.get("head_row_hash") is not None
                else None
            ),
            state=(normalized["state"] if normalized.get("state") is not None else None),
            manifest_signature_b64=(
                str(normalized["manifest_signature_b64"])
                if normalized.get("manifest_signature_b64") is not None
                else None
            ),
        )

    def signing_bytes(self) -> bytes:
        """Canonical bytes of the manifest with ``manifest_signature_b64`` removed.

        The exact byte sequence the producer signs. Receivers
        recompute this domain by stripping the same field from the
        on-wire manifest and re-canonicalising. Both sides MUST
        produce identical bytes for verification to succeed.

        Returns:
            UTF-8 canonical-bytes of the manifest minus the signature
            field. See
            `docs/spec/canonical-bytes.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/canonical-bytes.md>`_
            for the encoding rule.

        See Also:
            :meth:`sign`: Produces ``manifest_signature_b64`` over
                these bytes.
            `docs/spec/manifest.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/manifest.md>`_:
                Manifest signature spec.
        """
        return bytes(_tn_core.manifest_signing_bytes(_manifest_doc_from_dataclass(self)))

    def sign(self, sk: Ed25519PrivateKey) -> TnpkgManifest:
        """Sign the manifest in place and return self.

        Computes ``sk.sign(self.signing_bytes())`` and writes the
        result into ``manifest_signature_b64`` as **standard base64
        with padding** (distinct from envelope signatures' URL-safe-
        no-pad encoding — see
        `docs/spec/signing.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/signing.md>`_).

        Caller is responsible for ensuring ``publisher_identity``
        already names the device whose key is ``sk``. We do NOT
        cross-check here — receivers verify the signature against
        ``publisher_identity``'s did:key public bytes, which is the
        load-bearing check.

        Idempotent in shape — calling twice produces the same
        signature bytes for the same ``sk`` (Ed25519 is deterministic).

        Args:
            sk: The Ed25519 private key. Typically obtained via
                :meth:`tn.signing.DeviceKey.signing_key` from the
                publisher's keystore.

        Returns:
            ``self``, with ``manifest_signature_b64`` populated.
            Returned for fluent-API convenience: ``m.sign(sk).to_dict()``.

        Example:
            >>> from tn.tnpkg import TnpkgManifest
            >>> from tn.signing import DeviceKey
            >>> dk = DeviceKey.generate()
            >>> m = TnpkgManifest(
            ...     kind="offer",
            ...     publisher_identity=dk.device_identity,
            ...     ceremony_id="demo",
            ...     as_of="2026-05-22T00:00:00.000000+00:00",
            ... )
            >>> m.sign(dk.signing_key())  # doctest: +ELLIPSIS
            TnpkgManifest(...)
            >>> m.manifest_signature_b64 is not None
            True

        See Also:
            :meth:`signing_bytes`: The exact bytes this signs.
            :func:`tn.tnpkg._verify_manifest_signature`: The verify
                side.
            `docs/spec/manifest.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/manifest.md>`_:
                Manifest signature spec.
        """
        sig = sk.sign(self.signing_bytes())
        self.manifest_signature_b64 = base64.b64encode(sig).decode("ascii")
        return self


def _verify_manifest_signature(manifest: TnpkgManifest) -> bool:
    """True iff ``manifest_signature_b64`` verifies against ``from_did``'s
    Ed25519 public key. Returns False on any decode / verify error.
    """
    return bool(_tn_core.manifest_verify_signature(_manifest_doc_from_dataclass(manifest)))


def _did_key_pub(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key identifier.

    Kept for tests and browser interop helpers that need public-key bytes
    directly. Manifest verification itself is delegated to ``tn_core``.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID form for manifest signature: {did!r}")
    multicodec = _b58decode(did[len("did:key:z") :])
    prefix, pub_bytes = multicodec[:2], multicodec[2:]
    if prefix != b"\xed\x01":
        raise ValueError(
            f"manifest signing key must be Ed25519 (multicodec 0xed); "
            f"DID {did!r} carries {prefix!r}"
        )
    if len(pub_bytes) != 32:
        raise ValueError(f"DID {did!r} pub bytes are not 32-byte Ed25519")
    return pub_bytes


def _manifest_doc_from_dataclass(manifest: TnpkgManifest) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": manifest.kind,
        "version": manifest.version,
        "publisher_identity": manifest.publisher_identity,
        "ceremony_id": manifest.ceremony_id,
        "as_of": manifest.as_of,
        "scope": manifest.scope,
        "clock": manifest.clock,
        "event_count": manifest.event_count,
    }
    if manifest.recipient_identity is not None:
        out["recipient_identity"] = manifest.recipient_identity
    if manifest.head_row_hash is not None:
        out["head_row_hash"] = manifest.head_row_hash
    if manifest.state is not None:
        out["state"] = manifest.state
    if manifest.manifest_signature_b64 is not None:
        out["manifest_signature_b64"] = manifest.manifest_signature_b64
    return out


# --------------------------------------------------------------------------
# Zip writer / reader
# --------------------------------------------------------------------------


def _write_tnpkg(
    out_path: Path,
    manifest: TnpkgManifest,
    body_files: dict[str, bytes],
) -> Path:
    """Write a `.tnpkg` zip to ``out_path``.

    ``body_files`` maps a logical body path (e.g. ``"body/admin.ndjson"``)
    to its raw bytes. The caller is responsible for prefixing entries with
    ``body/`` per the format. ``manifest.json`` is written automatically
    from ``manifest.to_dict()``; the manifest must already be signed.
    """
    if manifest.manifest_signature_b64 is None:
        raise ValueError(
            "_write_tnpkg: manifest is unsigned. Call manifest.sign(sk) before "
            "writing — the wire format requires manifest_signature_b64 to be "
            "present."
        )
    out_path = Path(out_path).resolve()
    _tn_core.tnpkg_write(str(out_path), manifest.to_dict(), body_files)
    return out_path


def _validate_tnpkg_body_name(name: str) -> None:
    """Validate a non-manifest member name in the `.tnpkg` container."""
    if not name.startswith("body/") or name == "body/":
        raise ValueError(
            f"tnpkg: invalid package member {name!r}; expected manifest.json or body/..."
        )
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"tnpkg: invalid package member {name!r}; path traversal is forbidden")
    if name.startswith("/") or "\\" in name:
        raise ValueError(
            f"tnpkg: invalid package member {name!r}; only POSIX relative paths are allowed"
        )


def _read_manifest(source: Path | str | bytes | bytearray) -> tuple[TnpkgManifest, dict[str, bytes]]:
    """Open a `.tnpkg` and return ``(manifest, body_files)``.

    ``body_files`` maps every non-manifest entry name to its raw bytes.
    Does not verify the signature — the caller is expected to.
    """
    rust_source: bytes | str
    if isinstance(source, (bytes, bytearray)):
        rust_source = bytes(source)
    else:
        rust_source = str(source)
    manifest_doc, body = _tn_core.tnpkg_read(rust_source)
    return TnpkgManifest.from_dict(dict(manifest_doc)), dict(body)


# --------------------------------------------------------------------------
# Vector clock helpers
# --------------------------------------------------------------------------


def _clock_dominates(a: dict[str, dict[str, int]], b: dict[str, dict[str, int]]) -> bool:
    """True iff vector clock ``a`` is greater-than-or-equal to ``b`` on every
    ``(did, event_type)`` coordinate, i.e. ``a`` already covers everything
    ``b`` claims to know.

    Empty / missing coordinates count as 0. ``a`` may have strictly more
    coordinates than ``b`` (it's still a dominator). Equal clocks
    dominate each other (so the receiver's noop fast-path triggers when
    they are exactly in sync).
    """
    for did, et_map in b.items():
        a_map = a.get(did, {})
        for event_type, seq in et_map.items():
            if int(a_map.get(event_type, 0)) < int(seq):
                return False
    return True


def _clock_merge(
    a: dict[str, dict[str, int]],
    b: dict[str, dict[str, int]],
) -> dict[str, dict[str, int]]:
    """Pointwise max of two vector clocks. Pure; does not mutate inputs."""
    out: dict[str, dict[str, int]] = {}
    for src in (a, b):
        for did, et_map in src.items():
            slot = out.setdefault(did, {})
            for event_type, seq in et_map.items():
                cur = slot.get(event_type, 0)
                if int(seq) > int(cur):
                    slot[event_type] = int(seq)
    return out


def _device_signing_key_from_keystore(keystore: Path) -> Ed25519PrivateKey:
    """Load the device's Ed25519 private key from ``<keystore>/local.private``.

    Convenience wrapper for export paths that have a keystore but no
    fully-loaded ``LoadedConfig``.
    """
    priv = (Path(keystore) / "local.private").read_bytes()
    return DeviceKey.from_private_bytes(priv).signing_key()
