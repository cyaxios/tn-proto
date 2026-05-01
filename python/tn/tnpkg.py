"""Universal `.tnpkg` wrapper — signed manifest + kind-specific body.

Per docs/superpowers/plans/2026-04-24-tn-admin-log-architecture.md (Section 2),
every `.tnpkg` is a zip archive with this structure::

    foo.tnpkg/                    # zip archive
      manifest.json               # signed JSON; the index
      body/...                    # kind-specific contents

The manifest is signed with Ed25519 by ``from_did``'s device key, over the
RFC 8785-style canonical bytes of the manifest minus the signature field.
This module owns the wire-format invariants (manifest schema, signature
domain, zip layout). Producer / consumer dispatch lives in ``tn.export``
and ``tn.absorb``.

Kinds shipped in v1:
    admin_log_snapshot     body/admin.ndjson — every admin envelope this
                           writer has emitted, in chain order.
    offer                  body/package.json — JWE bootstrap offer
                           (existing ``Package`` shape).
    enrolment              body/package.json — JWE enrolment package.
    kit_bundle             body/<group>.btn.mykit files — readers-only,
                           no publisher state.
    full_keystore          body/keys/* — every keystore file, including
                           private material. Producer must opt in via
                           ``confirm_includes_secrets=True``.

The legacy three-format ``.tnpkg`` situation (pretty JSON, kit-bundle zip,
raw kit body inside ``tn-invite-*.zip``) is replaced. Old callers like
``packaging.dump_tnpkg`` / ``packaging.load_tnpkg`` are wrapped on top of
the new manifest header.
"""

from __future__ import annotations

import base64
import json
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import _canonical_bytes as _canonical_bytes
from .signing import DeviceKey, _b58decode

# Manifest schema version. Bump if the manifest's required fields change in
# a backwards-incompatible way.
MANIFEST_VERSION = 1

# v1 dispatch discriminators. Adding a new kind requires an absorb handler
# in ``tn.absorb`` and (for snapshots) a producer in ``tn.export``.
KNOWN_KINDS = frozenset(
    {
        "admin_log_snapshot",
        "offer",
        "enrolment",
        "recipient_invite",
        "kit_bundle",
        "full_keystore",
        # contact_update (Session 8, plan
        # docs/superpowers/plans/2026-04-29-contact-update-tnpkg.md, spec
        # §4.6 / D-11): the vault emits this kind into a publisher's inbox
        # after a counterparty claims a share-link or backup-link. Body
        # schema lives in tn.contacts._validate_contact_update_body.
        "contact_update",
    }
)


@dataclass
class TnpkgManifest:
    """Decoded `.tnpkg` manifest. Mirrors the JSON on the wire.

    Use ``to_dict()`` to serialize and ``sign(sk)`` to populate
    ``manifest_signature_b64`` after every other field is final. Calling
    ``sign()`` mutates the dataclass in place and also returns it.
    """

    kind: str
    from_did: str
    ceremony_id: str
    as_of: str
    scope: str = "admin"
    to_did: str | None = None
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
        out: dict[str, Any] = {
            "kind": self.kind,
            "version": self.version,
            "from_did": self.from_did,
            "ceremony_id": self.ceremony_id,
            "as_of": self.as_of,
            "scope": self.scope,
            "clock": self.clock,
            "event_count": self.event_count,
        }
        if self.to_did is not None:
            out["to_did"] = self.to_did
        if self.head_row_hash is not None:
            out["head_row_hash"] = self.head_row_hash
        if self.state is not None:
            out["state"] = self.state
        if self.manifest_signature_b64 is not None:
            out["manifest_signature_b64"] = self.manifest_signature_b64
        return out

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> TnpkgManifest:
        if not isinstance(doc, dict):
            raise ValueError(f"manifest must be a JSON object; got {type(doc).__name__}")
        # Required keys; reject loudly if missing.
        missing = [
            k for k in ("kind", "version", "from_did", "ceremony_id", "as_of") if k not in doc
        ]
        if missing:
            raise ValueError(f"manifest missing required keys: {missing}")
        return cls(
            kind=str(doc["kind"]),
            version=int(doc["version"]),
            from_did=str(doc["from_did"]),
            ceremony_id=str(doc["ceremony_id"]),
            as_of=str(doc["as_of"]),
            scope=str(doc.get("scope", "admin")),
            to_did=(str(doc["to_did"]) if doc.get("to_did") is not None else None),
            clock=dict(doc.get("clock") or {}),
            event_count=int(doc.get("event_count", 0)),
            head_row_hash=(
                str(doc["head_row_hash"]) if doc.get("head_row_hash") is not None else None
            ),
            state=(doc["state"] if doc.get("state") is not None else None),
            manifest_signature_b64=(
                str(doc["manifest_signature_b64"])
                if doc.get("manifest_signature_b64") is not None
                else None
            ),
        )

    def signing_bytes(self) -> bytes:
        """Canonical bytes of the manifest with ``manifest_signature_b64``
        excluded — the exact domain over which the producer signs."""
        d = self.to_dict()
        d.pop("manifest_signature_b64", None)
        return _canonical_bytes(d)

    def sign(self, sk: Ed25519PrivateKey) -> TnpkgManifest:
        """Populate ``manifest_signature_b64`` in-place and return self.

        Caller is responsible for ensuring ``from_did`` already names the
        device whose key is ``sk``. We do not cross-check here — the
        receiver verifies the signature against ``from_did``'s did:key
        public bytes, which is the load-bearing check.
        """
        sig = sk.sign(self.signing_bytes())
        self.manifest_signature_b64 = base64.b64encode(sig).decode("ascii")
        return self


def _did_key_pub(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key: identifier.

    Mirrors ``signing.DeviceKey.verify`` decoding for the Ed25519 case so
    we can verify a manifest without instantiating a ``DeviceKey``.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID form for manifest signature: {did!r}")
    multicodec = _b58decode(did[len("did:key:z") :])
    prefix, pub_bytes = multicodec[:2], multicodec[2:]
    # Ed25519 multicodec varint = b"\xed\x01"; we only sign with Ed25519.
    if prefix != b"\xed\x01":
        raise ValueError(
            f"manifest signing key must be Ed25519 (multicodec 0xed); "
            f"DID {did!r} carries {prefix!r}"
        )
    if len(pub_bytes) != 32:
        raise ValueError(f"DID {did!r} pub bytes are not 32-byte Ed25519")
    return pub_bytes


def _verify_manifest_signature(manifest: TnpkgManifest) -> bool:
    """True iff ``manifest_signature_b64`` verifies against ``from_did``'s
    Ed25519 public key. Returns False on any decode / verify error.
    """
    if not manifest.manifest_signature_b64:
        return False
    try:
        pub_bytes = _did_key_pub(manifest.from_did)
        sig = base64.b64decode(manifest.manifest_signature_b64)
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, manifest.signing_bytes())
        return True
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        return False


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
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n",
        )
        for name, data in body_files.items():
            zf.writestr(name, data)
    return out_path


def _open_zip(source: Path | bytes | bytearray) -> zipfile.ZipFile:
    """Open a `.tnpkg` zip from a path or in-memory bytes. Raises
    ValueError with a friendly message on a non-zip input.
    """
    if isinstance(source, (bytes, bytearray)):
        try:
            return zipfile.ZipFile(BytesIO(bytes(source)), "r")
        except zipfile.BadZipFile as exc:
            raise ValueError(f"absorb: input bytes are not a valid `.tnpkg` zip: {exc}") from exc
    p = Path(source)
    if not p.exists():
        raise FileNotFoundError(f"absorb: source path does not exist: {p}")
    try:
        return zipfile.ZipFile(p, "r")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"absorb: {p} is not a valid `.tnpkg` zip: {exc}") from exc


def _read_manifest(source: Path | bytes | bytearray) -> tuple[TnpkgManifest, dict[str, bytes]]:
    """Open a `.tnpkg` and return ``(manifest, body_files)``.

    ``body_files`` maps every non-manifest entry name to its raw bytes.
    Does not verify the signature — the caller is expected to.
    """
    with _open_zip(source) as zf:
        names = zf.namelist()
        if "manifest.json" not in names:
            raise ValueError(
                "absorb: zip is missing `manifest.json`. The `.tnpkg` format "
                "requires a top-level signed manifest; this archive does not "
                "have one. Was it produced by an old / external tool?"
            )
        manifest_doc = json.loads(zf.read("manifest.json").decode("utf-8"))
        manifest = TnpkgManifest.from_dict(manifest_doc)
        body: dict[str, bytes] = {}
        for name in names:
            if name == "manifest.json":
                continue
            body[name] = zf.read(name)
        return manifest, body


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
