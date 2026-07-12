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

Cross-implementation kind-recognition state: Rust + TS lag on
``identity_seed`` and ``project_seed`` at the type level even though
all three implementations handle both kinds at runtime.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from tn._native import core as _tn_core

from .canonical import _canonical_bytes
from .signing import DeviceKey, _b58decode
from .trust import TrustError, TrustReason, verify_ed25519_did_signature

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
    body_sha256: dict[str, str] = field(default_factory=dict)
    manifest_signature_b64: str | None = None
    # A parsed legacy manifest can have an empty body index because the field
    # was absent on the wire. Keep that distinction so low-level inspection
    # can still verify the legacy signature domain when explicitly requested.
    _body_sha256_present: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for ``json.dump``. Omits ``None`` /
        unset optional fields so the canonical form is stable across tiny
        variations in caller code."""
        candidate = _manifest_doc_from_dataclass(self)
        normalized = dict(_tn_core.manifest_to_dict(candidate))
        if "body_sha256" in candidate:
            normalized["body_sha256"] = dict(self.body_sha256)
        return normalized

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
        body_sha256_raw = doc.get("body_sha256")
        if "body_sha256" in doc and not isinstance(body_sha256_raw, dict):
            raise ValueError("manifest body_sha256 must be a JSON object")
        normalized = dict(_tn_core.manifest_to_dict(doc))
        body_sha256: dict[str, str] = {}
        if isinstance(body_sha256_raw, dict):
            for name, digest in body_sha256_raw.items():
                if not isinstance(name, str) or not isinstance(digest, str):
                    raise ValueError("manifest body_sha256 keys and values must be strings")
                body_sha256[name] = digest
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
            body_sha256=body_sha256,
            manifest_signature_b64=(
                str(normalized["manifest_signature_b64"])
                if normalized.get("manifest_signature_b64") is not None
                else None
            ),
            _body_sha256_present="body_sha256" in doc,
        )

    def signing_bytes(self) -> bytes:
        """Canonical bytes of the manifest with ``manifest_signature_b64`` removed.

        The exact byte sequence the producer signs. Receivers
        recompute this domain by stripping the same field from the
        on-wire manifest and re-canonicalising. Both sides MUST
        produce identical bytes for verification to succeed.

        Returns:
            UTF-8 canonical-bytes of the manifest minus the signature
            field.

        See Also:
            :meth:`sign`: Produces ``manifest_signature_b64`` over
                these bytes.
        """
        doc = _manifest_doc_from_dataclass(self)
        doc.pop("manifest_signature_b64", None)
        return _canonical_bytes(doc)

    def sign(self, sk: Ed25519PrivateKey) -> TnpkgManifest:
        """Sign the manifest in place and return self.

        Computes ``sk.sign(self.signing_bytes())`` and writes the
        result into ``manifest_signature_b64`` as **standard base64
        with padding** (distinct from envelope signatures' URL-safe-
        no-pad encoding).

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
        """
        sig = sk.sign(self.signing_bytes())
        self.manifest_signature_b64 = base64.b64encode(sig).decode("ascii")
        return self


def _verify_manifest_signature(manifest: TnpkgManifest) -> bool:
    """True iff ``manifest_signature_b64`` verifies against ``from_did``'s
    Ed25519 public key. Returns False on any decode / verify error.
    """
    if manifest.manifest_signature_b64 is None:
        return False
    try:
        signature = base64.b64decode(manifest.manifest_signature_b64, validate=True)
        verify_ed25519_did_signature(
            manifest.publisher_identity,
            manifest.signing_bytes(),
            signature,
        )
    except (TrustError, TypeError, ValueError):
        return False
    return True


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
    if manifest._body_sha256_present:
        out["body_sha256"] = dict(manifest.body_sha256)
    if manifest.manifest_signature_b64 is not None:
        out["manifest_signature_b64"] = manifest.manifest_signature_b64
    return out


def compute_body_sha256(body_files: Mapping[str, bytes]) -> dict[str, str]:
    """Return the canonical digest index for final stored body bytes.

    Keys must already be exact, normalized ``body/...`` archive member names.
    Digests use the lowercase ``sha256:<64 hex>`` wire spelling.
    """
    out: dict[str, str] = {}
    for name in sorted(body_files):
        _validate_tnpkg_body_name(name)
        data = body_files[name]
        if not isinstance(data, bytes):
            raise TypeError(f"tnpkg body member {name!r} must be bytes")
        out[name] = f"sha256:{hashlib.sha256(data).hexdigest()}"
    return out


def prepare_manifest_body_index(
    manifest: TnpkgManifest,
    body_files: Mapping[str, bytes],
) -> TnpkgManifest:
    """Index ``body_files`` on ``manifest`` and invalidate any old signature."""
    manifest.body_sha256 = compute_body_sha256(body_files)
    manifest._body_sha256_present = True
    manifest.manifest_signature_b64 = None
    return manifest


def sign_manifest_with_body(
    manifest: TnpkgManifest,
    body_files: Mapping[str, bytes],
    signing_key: Ed25519PrivateKey,
) -> TnpkgManifest:
    """Index final body bytes, then sign the complete manifest domain."""
    return prepare_manifest_body_index(manifest, body_files).sign(signing_key)


def verify_manifest_body_index(
    manifest: TnpkgManifest,
    body_files: Mapping[str, bytes],
    require_index: bool,
) -> None:
    """Verify exact body member names and digests against ``manifest``.

    A missing index is tolerated only for an explicitly selected legacy
    inspection boundary. A present index is always validated, even when
    ``require_index`` is false.
    """
    if not manifest._body_sha256_present:
        if require_index:
            raise TrustError(
                TrustReason.BODY_DIGEST_MISMATCH,
                "manifest body_sha256 index is missing",
            )
        return

    for name, digest in manifest.body_sha256.items():
        try:
            _validate_tnpkg_body_name(name)
        except ValueError as exc:
            raise TrustError(
                TrustReason.BODY_DIGEST_MISMATCH,
                f"invalid indexed body member {name!r}",
            ) from exc
        if (
            len(digest) != len("sha256:") + 64
            or not digest.startswith("sha256:")
            or any(ch not in "0123456789abcdef" for ch in digest[len("sha256:") :])
        ):
            raise TrustError(
                TrustReason.BODY_DIGEST_MISMATCH,
                f"malformed digest for {name!r}",
            )

    try:
        actual = compute_body_sha256(body_files)
    except (TypeError, ValueError) as exc:
        raise TrustError(
            TrustReason.BODY_DIGEST_MISMATCH,
            "body member set contains an invalid path or value",
        ) from exc
    if manifest.body_sha256 != actual:
        raise TrustError(TrustReason.BODY_DIGEST_MISMATCH, "body index mismatch")


# --------------------------------------------------------------------------
# Resource limits — bound a malicious / malformed `.tnpkg` (P0-5)
# --------------------------------------------------------------------------
#
# A `.tnpkg` is just a zip. An attacker (or a corrupt producer) can craft one
# that, when fully read into memory, exhausts the host: a zip bomb (tiny
# compressed size that inflates to gigabytes), one enormous entry, or tens of
# thousands of small entries. The reader MUST bound the archive using zip
# CENTRAL-DIRECTORY METADATA (``ZipInfo.file_size`` / ``ZipInfo.compress_size``,
# both available WITHOUT decompressing) BEFORE any entry's bytes are read, and
# the manifest signature MUST be verified before any body member is read on the
# absorb path. The limits below are deliberately generous relative to real
# packages — a full_keystore backup is a handful of small key files plus a
# manifest, and on-disk fixtures top out around 15 KiB with 2 entries — so they
# stop bombs without rejecting any legitimate bundle. Raise them if a real
# fixture ever exceeds one; the point is to cap blast radius, not to be tight.

# Max number of zip entries. A real `.tnpkg` has a manifest plus a small
# handful of body members; thousands of entries is an attack, not a backup.
MAX_PKG_ENTRY_COUNT = 2000

# Max uncompressed size of ``manifest.json``. Real manifests are a few KiB even
# with a per-recipient ``recipient_wraps`` array; 2 MiB is far past any honest
# manifest while still cheap to parse.
MAX_MANIFEST_BYTES = 2 * 1024 * 1024  # 2 MiB

# Max uncompressed size of any single entry. Bounds the largest single
# allocation a body read can trigger.
MAX_PKG_ENTRY_BYTES = 128 * 1024 * 1024  # 128 MiB

# Max total uncompressed size across all entries. Bounds the aggregate memory a
# full read of the archive can consume.
MAX_PKG_TOTAL_BYTES = 512 * 1024 * 1024  # 512 MiB

# Max per-entry compression ratio (uncompressed / compressed). `.tnpkg` is
# written ZIP_STORED, so legitimate packages have a ratio of ~1.0. A high ratio
# is the signature of a zip bomb: a few KiB on disk inflating to gigabytes.
MAX_PKG_COMPRESSION_RATIO = 200


class PackageError(ValueError):
    """A `.tnpkg` archive breached a structural / resource limit, or is
    otherwise unreadable as a package.

    Subclasses :class:`ValueError` so existing call sites that already
    treat a malformed `.tnpkg` as a ``ValueError`` (e.g. the absorb
    dispatcher's legacy-JSON fallback, ``_try_bootstrap_cfg``) keep
    working unchanged. The message names the limit that was hit and the
    offending value so an operator can tell a bomb from a genuine large
    backup.
    """


class ManifestSignatureError(PackageError):
    """The manifest signature did not verify. Raised by
    :func:`_read_manifest` only when ``verify_signature=True`` — so the
    absorb path can refuse to read body members into memory until the
    manifest is proven authentic.
    """


def _enforce_zip_limits(zf: zipfile.ZipFile) -> None:
    """Bound a `.tnpkg` using zip central-directory metadata ONLY.

    Reads no entry bytes — every check is against ``ZipInfo.file_size``
    (uncompressed) and ``ZipInfo.compress_size`` (on-disk), both of
    which the stdlib populates from the central directory without
    decompressing. Raises :class:`PackageError` naming the breached
    limit and the offending value on the first violation. Returns
    normally for a within-bounds archive.

    This is the cheap pre-flight that stops zip bombs / huge entries /
    entry floods before any read allocates memory.
    """
    infos = zf.infolist()
    if len(infos) > MAX_PKG_ENTRY_COUNT:
        raise PackageError(
            f"`.tnpkg` has {len(infos)} entries, exceeding the limit of "
            f"{MAX_PKG_ENTRY_COUNT}. Refusing to read a package with this "
            f"many members (possible zip bomb / malformed archive)."
        )
    total = 0
    for info in infos:
        size = info.file_size
        if size > MAX_PKG_ENTRY_BYTES:
            raise PackageError(
                f"`.tnpkg` entry {info.filename!r} declares an uncompressed "
                f"size of {size} bytes, exceeding the per-entry limit of "
                f"{MAX_PKG_ENTRY_BYTES} bytes ({MAX_PKG_ENTRY_BYTES // (1024 * 1024)} "
                f"MiB). Refusing to read it (possible zip bomb)."
            )
        # Compression-ratio guard. file_size / max(compress_size, 1) catches a
        # tiny compressed blob that inflates to a huge buffer — the classic
        # zip-bomb shape. Legitimate `.tnpkg` files are STORED (ratio ~1).
        ratio = size / max(info.compress_size, 1)
        if ratio > MAX_PKG_COMPRESSION_RATIO:
            raise PackageError(
                f"`.tnpkg` entry {info.filename!r} has a compression ratio of "
                f"{ratio:.1f}x ({size} bytes uncompressed from "
                f"{info.compress_size} bytes), exceeding the limit of "
                f"{MAX_PKG_COMPRESSION_RATIO}x. Refusing to inflate it "
                f"(possible zip bomb)."
            )
        total += size
        if total > MAX_PKG_TOTAL_BYTES:
            raise PackageError(
                f"`.tnpkg` total uncompressed size exceeds the limit of "
                f"{MAX_PKG_TOTAL_BYTES} bytes "
                f"({MAX_PKG_TOTAL_BYTES // (1024 * 1024)} MiB) at entry "
                f"{info.filename!r}. Refusing to read the remaining members "
                f"(possible zip bomb)."
            )


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
    from ``manifest.to_dict()``; the manifest must already be indexed and
    signed with :func:`sign_manifest_with_body`.
    """
    for name in body_files:
        _validate_tnpkg_body_name(name)
    if manifest.manifest_signature_b64 is None:
        raise ValueError(
            "_write_tnpkg: manifest is unsigned. Call "
            "sign_manifest_with_body(manifest, body_files, sk) before writing — "
            "the wire format requires manifest_signature_b64 to be present."
        )
    verify_manifest_body_index(manifest, body_files, require_index=True)
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_bytes = (json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        for name in sorted(body_files):
            zf.writestr(name, body_files[name])
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


def _open_zip(source: Path | str | bytes | bytearray) -> zipfile.ZipFile:
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


def _inspect_tnpkg_archive(
    zf: zipfile.ZipFile,
    *,
    validate_body_names: bool = True,
) -> list[str]:
    """Validate bounded container metadata without reading any member bytes."""
    _enforce_zip_limits(zf)

    names = zf.namelist()
    manifest_count = names.count("manifest.json")
    if manifest_count == 0:
        raise PackageError(
            "absorb: zip is missing `manifest.json`. The `.tnpkg` format "
            "requires a top-level signed manifest; this archive does not "
            "have one. Was it produced by an old / external tool?"
        )
    if manifest_count != 1:
        raise ValueError(
            f"tnpkg: a package must carry exactly one manifest.json (found {manifest_count})"
        )

    if validate_body_names:
        seen_body_names: set[str] = set()
        for name in names:
            if name == "manifest.json":
                continue
            if name in seen_body_names:
                raise ValueError(f"tnpkg: duplicate package member {name!r}")
            seen_body_names.add(name)
            _validate_tnpkg_body_name(name)

    manifest_info = zf.getinfo("manifest.json")
    if manifest_info.file_size > MAX_MANIFEST_BYTES:
        raise PackageError(
            f"`.tnpkg` manifest.json declares an uncompressed size of "
            f"{manifest_info.file_size} bytes, exceeding the manifest limit "
            f"of {MAX_MANIFEST_BYTES} bytes "
            f"({MAX_MANIFEST_BYTES // (1024 * 1024)} MiB). Refusing to parse "
            f"it (possible zip bomb / malformed archive)."
        )
    return names


def _read_manifest_document(zf: zipfile.ZipFile) -> dict[str, Any]:
    """Read and JSON-decode only the already-bounded manifest member."""
    doc = json.loads(zf.read("manifest.json").decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"manifest must be a JSON object; got {type(doc).__name__}")
    return doc


def _peek_manifest_kind(source: Path | str | bytes | bytearray) -> str:
    """Return a bounded manifest's raw kind without loading any body member.

    This is an inspection-only routing primitive. It deliberately does not
    verify the signature or validate the complete manifest schema; callers
    that recognize a security-sensitive kind must follow with one verified
    package read before consuming body state.
    """
    with _open_zip(source) as zf:
        # Inspect enough metadata to bound and locate the manifest, while
        # deferring body-name validation to the recognized kind's verified
        # read. That lets malformed bootstrap containers fail closed instead
        # of falling through to auto-initialization.
        _inspect_tnpkg_archive(zf, validate_body_names=False)
        doc = _read_manifest_document(zf)
    kind = doc.get("kind")
    if not isinstance(kind, str):
        raise ValueError("manifest kind must be a string")
    return kind


def _read_manifest(
    source: Path | str | bytes | bytearray,
    *,
    verify_signature: bool = False,
) -> tuple[TnpkgManifest, dict[str, bytes]]:
    """Open a `.tnpkg` and return ``(manifest, body_files)``.

    ``body_files`` maps every non-manifest entry name to its raw bytes.

    Read order (so a malicious / malformed package can't exhaust memory —
    P0-5):

    1. Enforce :func:`_enforce_zip_limits` on the archive using zip
       metadata ONLY — no entry bytes are read yet. A zip bomb / huge
       entry / entry flood is rejected here with a :class:`PackageError`.
    2. Read and parse ``manifest.json`` (its own size is capped at
       :data:`MAX_MANIFEST_BYTES` via the zip metadata before the read).
    3. If ``verify_signature`` is set, verify the manifest signature and
       require the body-index field BEFORE any body member is read. On a bad
       signature raise :class:`ManifestSignatureError`; a missing index raises
       :class:`TrustError`. Neither path reads body bytes.
    4. Only then read the body members into memory and check exact digest-map
       equality before returning them.

    ``verify_signature`` defaults to False to preserve the long-standing
    contract for callers that legitimately unwrap self-produced or
    already-trusted packages (``tn.packaging.Package.from_tnpkg``, the
    fs-drop / vault-push handlers, the cli_compile inspector). The absorb
    dispatcher passes ``verify_signature=True``.
    """
    with _open_zip(source) as zf:
        # (1) Metadata-only resource guard — must run before any read.
        names = _inspect_tnpkg_archive(zf)

        # (2) Manifest first. Its uncompressed size is bounded separately
        # (and more tightly) than a body member — a multi-MiB "manifest"
        # is an attack, not an honest index.
        manifest_doc = _read_manifest_document(zf)
        manifest = TnpkgManifest.from_dict(manifest_doc)

        # (3) Verify the manifest signature BEFORE reading any body member.
        if verify_signature and not _verify_manifest_signature(manifest):
            raise ManifestSignatureError(
                f"manifest signature does not verify against from_did "
                f"{manifest.publisher_identity!r}. The package is corrupt, "
                f"truncated, or tampered with. Ask the sender to re-export and "
                f"re-send."
            )

        # A required but absent index can be rejected from authenticated
        # manifest state alone. Do this before loading even one body member.
        if verify_signature and not manifest._body_sha256_present:
            verify_manifest_body_index(manifest, {}, require_index=True)

        # (4) Bodies last — only now do we pull entry bytes into memory.
        body: dict[str, bytes] = {}
        for name in names:
            if name == "manifest.json":
                continue
            body[name] = zf.read(name)
        if verify_signature:
            verify_manifest_body_index(manifest, body, require_index=True)
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
