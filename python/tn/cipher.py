"""Pluggable group-cipher abstraction.

A GroupCipher is what a ceremony uses to seal the plaintext fields of a
single group into an opaque `ciphertext` bytes blob, and to recover
them on the read side. Everything outside this file — canonical
serialization, HMAC index tokens, chain, signature — is cipher-agnostic.

Two implementations ship:

  * JWEGroupCipher — RFC 7516 JWE General JSON Serialization via a
    production JOSE library (Authlib/joserfc): ECDH-ES+A256KW per
    recipient over X25519, A256GCM body. Per-recipient revocation is
    O(1): drop the recipient from the list, next seal omits them.
  * BtnGroupCipher — NNL subset-difference broadcast encryption (see
    the `btn` Rust crate / PyO3 binding). Entitlement + revocation
    without per-recipient headers. Implementation at the bottom of
    this file routes to the `btn` module.

A ceremony picks one cipher at `create_fresh()` time; the choice is
stored in the YAML at `ceremony.cipher` and never changes for that
ceremony. Rotation creates a fresh cipher of the same kind.
"""

from __future__ import annotations

import base64
import json
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class CipherError(RuntimeError):
    """Base error for cipher operations."""


class NotAPublisherError(CipherError):
    """Raised when encrypt() is called without publisher key material."""


class NotARecipientError(CipherError):
    """Raised when decrypt() is called without recipient key material."""


@contextmanager
def _perf_stage(stage: str) -> Iterator[None]:
    try:
        from . import _perf
    except Exception:  # pragma: no cover - standalone cipher import fallback
        yield
        return

    with _perf.time_stage(stage):
        yield


@runtime_checkable
class GroupCipher(Protocol):
    """One cipher instance per (ceremony, group). Stateful: holds key
    material on disk under `keystore/`."""

    name: str  # "jwe", "btn", or "hibe"

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Seal `plaintext` into an opaque blob. Raises NotAPublisherError
        if this party doesn't hold the write key.

        ``aad`` is optional additional-authenticated-data bound to the body
        AEAD — authenticated, not encrypted. Storage is cipher-specific:
        JWE serializes it in the RFC 7516 ``aad`` member inside the
        ciphertext; btn and HIBE do not store it. A reader must supply
        byte-identical ``aad`` to open. Empty (the default) binds nothing and
        uses the same wire shape as a plain seal."""
        ...

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Open `ciphertext` to recover plaintext. Raises
        NotARecipientError if this party can't read this group.

        ``aad`` must byte-match whatever was bound at seal time."""
        ...


# ---------------------------------------------------------------------------
# JWE cipher — RFC 7516 JWE General JSON (ECDH-ES+A256KW / A256GCM / X25519) via joserfc
# ---------------------------------------------------------------------------

_JWE_ALGS = ["ECDH-ES+A256KW", "A256GCM"]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _validate_x25519_public_key(pub_bytes: bytes, *, what: str = "pub_bytes") -> bytes:
    """Return raw X25519 public bytes or raise ``ValueError`` with context."""
    raw = bytes(pub_bytes)
    if len(raw) != 32:
        raise ValueError(f"{what} must be 32 raw X25519 bytes, got {len(raw)}")
    return raw


def _okp_public_jwk(pub_raw: bytes) -> dict[str, str]:
    """A raw 32-byte X25519 public key as an RFC 8037 OKP JWK."""
    return {"kty": "OKP", "crv": "X25519", "x": _b64u(_validate_x25519_public_key(pub_raw))}


def _okp_private_jwk(my_sk: X25519PrivateKey) -> dict[str, str]:
    """A cryptography X25519 private key as an RFC 8037 OKP private JWK."""
    pub = my_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "X25519", "x": _b64u(pub), "d": _b64u(my_sk.private_bytes_raw())}


def _jwe_seal(recipient_pubs: list[bytes], plaintext: bytes, aad: bytes) -> bytes:
    """Seal to N X25519 recipients as an RFC 7516 General JSON JWE.

    Returns the UTF-8 JSON bytes (sorted keys, tight separators) that become
    the group's opaque ``ciphertext``. Per recipient: ECDH-ES+A256KW wraps one
    shared A256GCM CEK. An empty ``aad`` omits the JWE ``aad`` member so the
    no-marker path stays a plain seal.
    """
    from joserfc import jwe as _jwe
    from joserfc.jwk import OKPKey

    enc = _jwe.GeneralJSONEncryption({"enc": "A256GCM"}, plaintext, aad=aad or None)
    for pub in recipient_pubs:
        enc.add_recipient({"alg": "ECDH-ES+A256KW"}, OKPKey.import_key(_okp_public_jwk(pub)))
    obj = _jwe.encrypt_json(enc, None, algorithms=_JWE_ALGS)
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _jwe_open(blob: bytes, my_sk: X25519PrivateKey, aad: bytes) -> bytes:
    """Open a General JSON JWE by trial-decrypting each recipient block.

    joserfc's multi-recipient ``decrypt_json`` needs a ``kid`` to match a key
    to a block; our blocks are anonymous, so we view each recipient as a
    flattened JWE and try the reader's key against it (the AEAD tag rejects a
    wrong key with no false-plaintext risk). The embedded ``aad`` member must
    byte-match ``aad`` — the marker reconstructed from the record's public
    ``tn_aad`` echo — so a tampered echo fails to open.
    """
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise NotARecipientError(f"JWE: ciphertext is not a JWE JSON object ({exc})") from exc
    _validate_jwe_general_json_shape(obj)

    from joserfc import jwe as _jwe
    from joserfc.jwk import OKPKey

    key = OKPKey.import_key(_okp_private_jwk(my_sk))
    base = {k: obj[k] for k in ("protected", "iv", "ciphertext", "tag") if k in obj}
    if "aad" in obj:
        base["aad"] = obj["aad"]
    expected = aad or b""
    for rcpt in obj.get("recipients", []):
        flat = dict(base)
        flat["encrypted_key"] = rcpt.get("encrypted_key", "")
        if "header" in rcpt:
            flat["header"] = rcpt["header"]
        try:
            got = _jwe.decrypt_json(flat, key, algorithms=_JWE_ALGS)
        except Exception:  # noqa: BLE001 - try every anonymous recipient block
            continue
        if (got.aad or b"") != expected:
            raise NotARecipientError("JWE: aad marker mismatch")
        return got.plaintext
    raise NotARecipientError("JWE: no recipient block in this envelope opens under this key")


def _validate_jwe_general_json_shape(obj: Any) -> None:
    """Validate the JWE General JSON shape expected by this cipher.

    Shape errors are reported as ``NotARecipientError`` so callers see a
    malformed ciphertext as an unopened envelope, not as an incidental
    ``TypeError``/``KeyError`` from inside the JOSE library.
    """
    if not isinstance(obj, dict):
        raise NotARecipientError("JWE: ciphertext is not a JWE JSON object")
    for field_name in ("protected", "iv", "ciphertext", "tag"):
        if not isinstance(obj.get(field_name), str):
            raise NotARecipientError(f"JWE: field {field_name!r} must be present as a string")
    if "aad" in obj and not isinstance(obj["aad"], str):
        raise NotARecipientError("JWE: field 'aad' must be a string when present")
    recipients = obj.get("recipients")
    if not isinstance(recipients, list):
        raise NotARecipientError("JWE: field 'recipients' must be a list")
    for idx, rcpt in enumerate(recipients):
        if not isinstance(rcpt, dict):
            raise NotARecipientError(f"JWE: recipient {idx} must be an object")
        if not isinstance(rcpt.get("encrypted_key"), str):
            raise NotARecipientError(f"JWE: recipient {idx} must include string 'encrypted_key'")
        if "header" in rcpt and not isinstance(rcpt["header"], dict):
            raise NotARecipientError(f"JWE: recipient {idx} header must be an object")


def _atomic_write_text(path: Path, content: str) -> None:
    """Write `content` to `path` via write-to-temp-then-rename.

    Path.replace is atomic on POSIX; on Windows it's not guaranteed atomic
    but is far safer than a truncating write. Acceptable for a local
    keystore file, where corruption is the only concern we guard against.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _atomic_write_secret_bytes(path: Path, data: bytes) -> None:
    """Owner-only (0600) atomic write for secret key material — HIBE msk/sk,
    the X25519 private halves of a JWE group.

    Routes through the keystore backend so these land with the same posture
    as ``local.private`` / ``index_master.key``: a same-dir temp opened 0600,
    fsync, atomic replace. A plain ``Path.write_bytes`` inherits the process
    umask and leaves the file world-readable (0644) — fine for the mpk, wrong
    for a master secret. On Windows the mode is a no-op; the user-profile ACL
    is the protection there, same as every other keystore secret.
    """
    from ._keystore_backend import atomic_write_bytes

    atomic_write_bytes(path, data)


@dataclass
class JWEGroupCipher:
    """RFC 7516 JWE cipher: one cipher per (ceremony, group).

    Seals the group body as a JWE General JSON Serialization via a production
    JOSE library (Authlib/joserfc): one fresh A256GCM CEK for the body, wrapped
    per recipient with ECDH-ES+A256KW over the recipient's X25519 key. The
    ephemeral ECDH-ES sender key travels in each recipient header, so there is
    no long-lived sender secret in the decrypt path (sender authenticity comes
    from the record's Ed25519 signature, not the cipher). Revoking a recipient
    is an O(1) recipient-list edit; the next seal omits their block.

    The ``<group>.jwe.sender`` keypair below is retained only as a stable group
    identity anchor for the ceremony / compile / absorb surface — ECDH-ES does
    not use it to seal or open.

    Keystore layout::

        <keystore>/<group>.jwe.sender       32B X25519 private (identity anchor)
        <keystore>/<group>.jwe.recipients   JSON list [{recipient_identity, pub_b64}, ...]
        <keystore>/<group>.jwe.mykey        32B X25519 private (recipient)
    """

    name: str = "jwe"
    _sender_sk: X25519PrivateKey | None = field(default=None, repr=False)
    _sender_pub: bytes = b""
    _my_sk: X25519PrivateKey | None = field(default=None, repr=False)
    _recipients_path: Path | None = field(default=None, repr=False)

    @classmethod
    def create(
        cls,
        keystore: Path,
        group_name: str,
        *,
        recipient_dids: list[str],
        recipient_pubs: dict[str, bytes] | None = None,
    ) -> JWEGroupCipher:
        """Mint a fresh ceremony/group as publisher.

        If ``recipient_pubs`` omits a DID, a fresh X25519 keypair is minted
        for that DID and its private stashed in the keystore. This is
        the solo-ceremony case where the creator is both publisher and
        sole reader.

        Supplied public keys must be exactly 32 raw X25519 bytes. When all
        recipients have supplied public keys, any stale ``.jwe.mykey`` from a
        previous local create is removed so this publisher does not keep a
        misleading private key for an external-only recipient set.

        WARNING: Overwrites any existing JWE keystore files for this
        group. Use rotate() at the ceremony layer for key cycling.
        """
        keystore.mkdir(parents=True, exist_ok=True)
        sender_sk = X25519PrivateKey.generate()
        _atomic_write_secret_bytes(
            keystore / f"{group_name}.jwe.sender", sender_sk.private_bytes_raw()
        )
        sender_pub = sender_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        pubs = dict(recipient_pubs or {})
        for did in recipient_dids:
            if did in pubs:
                pubs[did] = _validate_x25519_public_key(
                    pubs[did],
                    what=f"recipient_pubs[{did!r}]",
                )
        missing = [d for d in recipient_dids if d not in pubs]
        if len(missing) > 1:
            raise ValueError(
                f"JWE.create: {len(missing)} recipient DIDs lack a supplied "
                f"public key ({missing!r}). At most one may be auto-generated "
                f"(the publisher's self-recipient slot); callers must supply "
                f"public keys for every other recipient out-of-band."
            )
        if missing:
            my_sk_new = X25519PrivateKey.generate()
            _atomic_write_secret_bytes(
                keystore / f"{group_name}.jwe.mykey", my_sk_new.private_bytes_raw()
            )
            pubs[missing[0]] = my_sk_new.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            stale_mykey = keystore / f"{group_name}.jwe.mykey"
            if stale_mykey.exists():
                stale_mykey.unlink()

        recipients_doc = [
            {
                "recipient_identity": d,
                "pub_b64": base64.b64encode(pubs[d]).decode("ascii"),
            }
            for d in recipient_dids
        ]
        recipients_path = keystore / f"{group_name}.jwe.recipients"
        _atomic_write_text(recipients_path, json.dumps(recipients_doc, indent=2))

        my_sk_path = keystore / f"{group_name}.jwe.mykey"
        my_sk = (
            X25519PrivateKey.from_private_bytes(my_sk_path.read_bytes())
            if my_sk_path.exists()
            else None
        )

        return cls(
            _sender_sk=sender_sk,
            _sender_pub=sender_pub,
            _my_sk=my_sk,
            _recipients_path=recipients_path,
        )

    @classmethod
    def load(cls, keystore: Path, group_name: str) -> JWEGroupCipher:
        """Load an existing JWE group from its keystore files."""
        sender_path = keystore / f"{group_name}.jwe.sender"
        my_path = keystore / f"{group_name}.jwe.mykey"
        recipients_path = keystore / f"{group_name}.jwe.recipients"

        sender_sk = (
            X25519PrivateKey.from_private_bytes(sender_path.read_bytes())
            if sender_path.exists()
            else None
        )
        sender_pub = (
            sender_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            if sender_sk
            else b""
        )
        my_sk = (
            X25519PrivateKey.from_private_bytes(my_path.read_bytes()) if my_path.exists() else None
        )

        return cls(
            _sender_sk=sender_sk,
            _sender_pub=sender_pub,
            _my_sk=my_sk,
            _recipients_path=recipients_path if recipients_path.exists() else None,
        )

    @classmethod
    def as_recipient(cls, sender_pub: bytes, my_sk: X25519PrivateKey) -> JWEGroupCipher:
        """Construct a read-only view from a recipient's sk + sender's pub.

        Used by readers that received their X25519 private out-of-band
        and know the sender's pub from the ceremony metadata.
        """
        return cls(_sender_pub=sender_pub, _my_sk=my_sk)

    def sender_pub(self) -> bytes:
        """Return the sender's X25519 public key bytes (32 bytes, raw)."""
        return self._sender_pub

    def revoke_recipient(self, did: str) -> None:
        """Drop ``did`` from the recipient list. Subsequent encrypts exclude
        them. O(1) — no coordination with other recipients."""
        if self._sender_sk is None or self._recipients_path is None:
            raise NotAPublisherError("JWE: only the publisher can revoke")
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        before = len(doc)
        doc = [e for e in doc if e["recipient_identity"] != did]
        if len(doc) == before:
            return  # already absent — idempotent
        _atomic_write_text(self._recipients_path, json.dumps(doc, indent=2))

    def add_recipient(self, did: str, pub_bytes: bytes) -> None:
        """Append ``did`` with raw 32-byte X25519 pub to the recipient list.

        Subsequent encrypts include a wrapped CEK for this recipient.
        Idempotent: re-adding the same DID (even with a different pub)
        replaces the existing entry rather than duplicating it.
        """
        if self._sender_sk is None or self._recipients_path is None:
            raise NotAPublisherError("JWE: only the publisher can add recipients")
        pub_bytes = _validate_x25519_public_key(pub_bytes)
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        doc = [e for e in doc if e.get("recipient_identity") != did]
        doc.append(
            {
                "recipient_identity": did,
                "pub_b64": base64.b64encode(pub_bytes).decode("ascii"),
            }
        )
        _atomic_write_text(self._recipients_path, json.dumps(doc, indent=2))

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if self._recipients_path is None:
            raise NotAPublisherError("JWE: no recipient list in this keystore")
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        if not doc:
            raise NotAPublisherError(
                "JWE: cannot encrypt with zero recipients. Add a recipient "
                "before calling encrypt()."
            )
        pubs = [
            _validate_x25519_public_key(
                base64.b64decode(e["pub_b64"]),
                what=f"recipient {e.get('recipient_identity', '<unknown>')!r} pub_b64",
            )
            for e in doc
        ]
        with _perf_stage("emit:group_encrypt.cipher"):
            return _jwe_seal(pubs, plaintext, aad)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if self._my_sk is None:
            raise NotARecipientError("JWE: no recipient X25519 key in this keystore")
        with _perf_stage("read:group_decrypt.cipher"):
            return _jwe_open(ciphertext, self._my_sk, aad)


# ---------------------------------------------------------------------------
# HIBE cipher — BBG hierarchical identity-based encryption via the tn-hibe
# Rust extension. Encrypt to an identity path under an authority's master
# public key; readers hold delegated identity keys.
# ---------------------------------------------------------------------------

_HIBE_HISTORY_ROOT_SENTINEL = "\troot"


def _native_hibe() -> Any:
    """Deferred HIBE import, with a clear runtime error when unavailable."""
    from . import _hibe as hibe

    return hibe


def _validate_hibe_label(label: str, *, what: str) -> str:
    """Validate one non-root HIBE label without lossy normalization."""
    if not isinstance(label, str):
        raise ValueError(f"HIBE: {what} must be a string")
    if label == "":
        raise ValueError(f"HIBE: {what} must not be empty")
    if "/" in label:
        raise ValueError(f"HIBE: {what} must be one path segment, not contain '/'")
    if label != label.strip():
        raise ValueError(f"HIBE: {what} must not have leading or trailing whitespace")
    if any(ch in label for ch in "\r\n"):
        raise ValueError(f"HIBE: {what} must not contain line breaks")
    return label


def _normalize_hibe_path(
    id_path: str | None,
    *,
    what: str = "id_path",
    allow_root: bool = False,
) -> str:
    """Return a canonical slash-separated HIBE path or raise ``ValueError``.

    The Python boundary does not trim, collapse slashes, or skip blank
    segments because those transformations create ambiguous authorization
    paths. The HIBE root path is the empty string and is accepted only when
    ``allow_root`` is explicitly true.
    """
    if id_path is None:
        raise ValueError(f"HIBE: {what} is required")
    if not isinstance(id_path, str):
        raise ValueError(f"HIBE: {what} must be a string")
    if id_path == "":
        if allow_root:
            return ""
        raise ValueError(
            f"HIBE: {what} must not be blank; pass allow_root_path=True "
            "to use the root identity path explicitly"
        )
    if id_path != id_path.strip():
        raise ValueError(f"HIBE: {what} must not have leading or trailing whitespace")
    if any(ch in id_path for ch in "\r\n"):
        raise ValueError(f"HIBE: {what} must not contain line breaks")
    labels = id_path.split("/")
    if any(label == "" for label in labels):
        raise ValueError(f"HIBE: {what} must not contain empty path segments")
    return "/".join(
        _validate_hibe_label(label, what=f"{what} segment {idx}")
        for idx, label in enumerate(labels)
    )


def _previous_hibe_sk_path(keystore: Path, group_name: str) -> Path:
    """Return an unused archive path for a superseded HIBE identity key."""
    base = keystore / f"{group_name}.hibe.sk.previous.{time.time_ns()}"
    candidate = base
    counter = 1
    while candidate.exists():
        candidate = keystore / f"{base.name}.{counter}"
        counter += 1
    return candidate


def _hibe_root_marker_path(keystore: Path, group_name: str) -> Path:
    """Marker showing an empty active idpath is intentional root use."""
    return keystore / f"{group_name}.hibe.idpath.root"


def _encode_hibe_history_path(path: str) -> str:
    """Encode one validated path for the line-oriented idpath history file."""
    return _HIBE_HISTORY_ROOT_SENTINEL if path == "" else path


def _decode_hibe_history_line(line: str, *, what: str) -> str:
    """Decode one idpath history line, including explicit prior root paths."""
    if line == _HIBE_HISTORY_ROOT_SENTINEL:
        return ""
    return _normalize_hibe_path(line, what=what)


@dataclass
class HibeGroupCipher:
    """Ceremony/group cipher backed by BBG HIBE (constant-size ciphertext).

    Writing needs only the authority's master public key plus the group's
    identity path — no per-recipient key exchange at write time. Reading
    needs a delegated key on that exact path; a key for an ancestor path
    derives down locally (no msk, no re-keying). Delegated keys are
    permanent: no forward revocation of an admitted reader — groups that
    need that use btn (the default cipher).

    Keystore layout::

        <keystore>/<group>.hibe.mpk     authority PublicParams (public)
        <keystore>/<group>.hibe.idpath  identity path this group seals to (public)
        <keystore>/<group>.hibe.sk      delegated identity key (SECRET)
        <keystore>/<group>.hibe.msk     master secret (SECRET; present only
                                        when this keystore IS the authority)
    """

    name: str = "hibe"
    _mpk: bytes = b""
    _id_path: str = ""
    _sk: bytes | None = field(default=None, repr=False)
    _msk: bytes | None = field(default=None, repr=False)
    _keystore: Path | None = field(default=None, repr=False)
    _group_name: str = ""
    _allow_root_path: bool = field(default=False, repr=False)
    # Paths this group sealed to before rotations, newest first. Lets the
    # authority (msk holder) open pre-rotation entries; persisted in
    # ``<group>.hibe.idpath.history``, one path per line.
    _prior_paths: list[str] = field(default_factory=list, repr=False)
    # Superseded identity keys, newest first. When a re-issued kit lands,
    # absorb renames the old ``<group>.hibe.sk`` to ``.previous.<ts>``;
    # loading them back keeps a surviving reader's pre-rotation entries
    # readable without any special ceremony.
    _prior_sks: list[bytes] = field(default_factory=list, repr=False)

    @classmethod
    def create(
        cls,
        keystore: Path,
        group_name: str,
        *,
        authority_mpk: bytes | None = None,
        id_path: str | None = None,
        max_depth: int = 2,
        allow_root_path: bool = False,
    ) -> HibeGroupCipher:
        """Mint a fresh hibe group.

        With ``authority_mpk`` (and ``id_path``): seal to an EXTERNAL
        authority's path. No read key is written — this keystore can write
        but cannot read until a delegated key arrives via grant/absorb.

        Without ``authority_mpk`` (the solo-ceremony default, matching
        jwe/btn create semantics): this keystore becomes its own authority
        (per-authority trust root) — runs Setup, keeps the msk, and
        self-delegates a reader key for ``id_path`` (default ``"self"``).

        ``id_path`` is validated as slash-separated labels with no empty
        segments and no lossy whitespace trimming. The root identity path is
        the empty string and is accepted only with ``allow_root_path=True``.
        """
        hibe = _native_hibe()
        keystore.mkdir(parents=True, exist_ok=True)
        sk: bytes | None = None
        msk: bytes | None = None
        if authority_mpk is None:
            path = (
                "self"
                if id_path is None
                else _normalize_hibe_path(
                    id_path,
                    allow_root=allow_root_path,
                )
            )
            mpk_new, msk_new = hibe.setup(max_depth)
            sk_new = hibe.keygen(mpk_new, msk_new, path)
            _atomic_write_secret_bytes(keystore / f"{group_name}.hibe.msk", msk_new)
            _atomic_write_secret_bytes(keystore / f"{group_name}.hibe.sk", sk_new)
            mpk, msk, sk = mpk_new, msk_new, sk_new
        else:
            path = _normalize_hibe_path(id_path, allow_root=allow_root_path)
            mpk = authority_mpk
            hibe.mpk_fingerprint(mpk)  # parse now: reject malformed mpk at mint
        (keystore / f"{group_name}.hibe.mpk").write_bytes(mpk)
        _atomic_write_text(keystore / f"{group_name}.hibe.idpath", path)
        root_marker = _hibe_root_marker_path(keystore, group_name)
        if path == "":
            _atomic_write_text(root_marker, "root\n")
        elif root_marker.exists():
            root_marker.unlink()
        return cls(
            _mpk=mpk,
            _id_path=path,
            _sk=sk,
            _msk=msk,
            _keystore=keystore,
            _group_name=group_name,
            _allow_root_path=allow_root_path and path == "",
        )

    @classmethod
    def load(cls, keystore: Path, group_name: str) -> HibeGroupCipher:
        """Load an existing hibe group from its keystore files."""
        mpk_path = keystore / f"{group_name}.hibe.mpk"
        idpath_path = keystore / f"{group_name}.hibe.idpath"
        sk_path = keystore / f"{group_name}.hibe.sk"
        msk_path = keystore / f"{group_name}.hibe.msk"
        if not mpk_path.exists() or not idpath_path.exists():
            raise CipherError(
                f"HIBE: keystore is missing {group_name}.hibe.mpk/.idpath; "
                f"was this group minted (or its kit absorbed) here?"
            )
        history_path = keystore / f"{group_name}.hibe.idpath.history"
        prior = []
        if history_path.exists():
            for idx, line in enumerate(history_path.read_text(encoding="utf-8").splitlines()):
                prior.append(
                    _decode_hibe_history_line(
                        line,
                        what=f"{group_name}.hibe.idpath.history line {idx + 1}",
                    )
                )
        allow_root_path = _hibe_root_marker_path(keystore, group_name).exists()
        id_path = _normalize_hibe_path(
            idpath_path.read_text(encoding="utf-8"),
            what=f"{group_name}.hibe.idpath",
            allow_root=allow_root_path,
        )
        prior_sks = [
            p.read_bytes()
            for p in sorted(keystore.glob(f"{group_name}.hibe.sk.previous.*"), reverse=True)
        ]
        return cls(
            _mpk=mpk_path.read_bytes(),
            _id_path=id_path,
            _sk=sk_path.read_bytes() if sk_path.exists() else None,
            _msk=msk_path.read_bytes() if msk_path.exists() else None,
            _keystore=keystore,
            _group_name=group_name,
            _allow_root_path=allow_root_path and id_path == "",
            _prior_paths=prior,
            _prior_sks=prior_sks,
        )

    def id_path(self) -> str:
        """The identity path this group seals to."""
        return self._id_path

    def mpk(self) -> bytes:
        """The authority's master public key bytes."""
        return self._mpk

    def mpk_fingerprint(self) -> bytes:
        """SHA-256 fingerprint of the authority mpk (manifest ``mpk_fp``)."""
        return _native_hibe().mpk_fingerprint(self._mpk)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if not self._mpk:
            raise NotAPublisherError("HIBE: no authority mpk in this keystore")
        self._id_path = _normalize_hibe_path(
            self._id_path,
            what="id_path",
            allow_root=self._allow_root_path,
        )
        with _perf_stage("emit:group_encrypt.cipher"):
            return _native_hibe().seal(self._mpk, self._id_path, plaintext, aad or None)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Open a group blob.

        A blob does not carry the path it was sealed to, and after a path
        rotation a log mixes epochs, so try every key this keystore can
        legitimately produce: the held key as-is, the held key derived down
        to the current path, and — for the authority — msk-minted keys for
        the current path and every prior path recorded by rotations.

        ``aad`` must byte-match whatever was bound at seal time (empty when
        the group binds no marker); a mismatch fails every candidate.
        """
        hibe = _native_hibe()
        tried = False
        for sk in self._candidate_keys():
            tried = True
            try:
                with _perf_stage("read:group_decrypt.cipher"):
                    return hibe.open(self._mpk, sk, ciphertext, aad or None)
            except hibe.HibeCryptoError:
                continue
        if not tried:
            raise NotARecipientError(
                "HIBE: no delegated identity key for this group's path in this keystore"
            )
        raise NotARecipientError(
            "HIBE: no identity key in this keystore opens this group's "
            "ciphertext (sealed to a different path, or tampered bytes)"
        )

    def _candidate_keys(self):
        """Yield decryption-key candidates, most likely first, without
        minting the same path twice."""
        hibe = _native_hibe()
        seen: set[str] = set()
        target_paths = [
            _normalize_hibe_path(
                path,
                what="id_path",
                allow_root=True,
            )
            for path in [self._id_path, *self._prior_paths]
        ]

        def emit(sk: bytes):
            path = _normalize_hibe_path(
                hibe.key_id_path(sk),
                what="identity key path",
                allow_root=True,
            )
            if path not in seen:
                seen.add(path)
                yield sk
            for target_path in target_paths:
                if target_path in seen:
                    continue
                derived = self._derive_from_key(sk, target_path)
                if derived is not None:
                    seen.add(target_path)
                    yield derived

        if self._sk is not None:
            yield from emit(self._sk)
        for old_sk in self._prior_sks:
            yield from emit(old_sk)
        if self._msk is not None:
            for path in target_paths:
                if path in seen:
                    continue
                seen.add(path)
                yield hibe.keygen(self._mpk, self._msk, path)

    def _derive_from_held(self, target_path: str) -> bytes | None:
        """The held key if it sits on ``target_path``, derived down from an
        ancestor when needed (BBG opens only with an exact-path key)."""
        if self._sk is None:
            return None
        return self._derive_from_key(self._sk, target_path)

    def _derive_from_key(self, source_sk: bytes, target_path: str) -> bytes | None:
        """Derive ``source_sk`` to ``target_path`` when it is an ancestor."""
        hibe = _native_hibe()
        target_path = _normalize_hibe_path(target_path, what="target_path")
        held = _normalize_hibe_path(
            hibe.key_id_path(source_sk),
            what="identity key path",
            allow_root=True,
        )
        if held == target_path:
            return source_sk
        target_labels = target_path.split("/")
        held_labels = held.split("/") if held else []
        if held_labels != target_labels[: len(held_labels)]:
            return None
        sk = source_sk
        for label in target_labels[len(held_labels) :]:
            sk = hibe.delegate(self._mpk, sk, label)
        return sk

    def mint_reader_key(self, id_path: str, *, allow_root_path: bool = False) -> bytes:
        """Authority-side grant: generate the identity key for ``id_path``
        from the msk.

        ``id_path`` follows the same validated, slash-separated rules as
        group seal paths. The root path is allowed only when
        ``allow_root_path=True`` is passed explicitly. The admin layer
        packages the result into a ``hibe-id-key`` kit; the cipher only mints
        the material.
        """
        if self._msk is None:
            raise NotAPublisherError("HIBE: only the authority (msk holder) can mint reader keys")
        path = _normalize_hibe_path(id_path, allow_root=allow_root_path)
        return _native_hibe().keygen(self._mpk, self._msk, path)

    def delegate_reader_key(self, child_label: str) -> bytes:
        """Parent-side grant: derive the key one level below this
        keystore's own identity key. ``child_label`` must be one label, not a
        slash-separated path. No msk involved."""
        if self._sk is None:
            raise NotARecipientError("HIBE: no identity key to delegate from in this keystore")
        label = _validate_hibe_label(child_label, what="child_label")
        return _native_hibe().delegate(self._mpk, self._sk, label)

    def rotate_id_path(self, new_path: str, *, allow_root_path: bool = False) -> None:
        """Point future seals at ``new_path`` (the policy-path rotation).

        This is admission rotation, not revocation: pre-rotation seals stay
        open forever for whoever held a key on the old path (delegated keys
        are permanent), and a grantee holding a key for an ANCESTOR of the
        new path keeps access to new seals too. Pick a sibling path (e.g.
        bump the policy-hash leaf) to cut off exact-path grantees going
        forward. Authority-only: the msk mints this keystore's own fresh
        key for the new path. ``new_path`` is validated without trimming or
        collapsing labels; the root path requires ``allow_root_path=True``.
        """
        if self._msk is None:
            raise NotAPublisherError(
                "HIBE: only the authority (msk holder) can rotate the identity path"
            )
        if self._keystore is None:
            raise CipherError(
                "HIBE: this cipher instance is not bound to a keystore "
                "(recipient view); rotate from the authority's ceremony"
            )
        new_path = _normalize_hibe_path(new_path, allow_root=allow_root_path)
        if new_path == self._id_path:
            raise ValueError(f"HIBE: new path equals the current path {new_path!r}")
        sk = _native_hibe().keygen(self._mpk, self._msk, new_path)
        outgoing_path = _normalize_hibe_path(
            self._id_path,
            what="current id_path",
            allow_root=self._allow_root_path,
        )
        prior_paths = [outgoing_path, *self._prior_paths]
        _atomic_write_text(
            self._keystore / f"{self._group_name}.hibe.idpath.history",
            "\n".join(_encode_hibe_history_path(path) for path in prior_paths) + "\n",
        )
        if self._sk is not None:
            _atomic_write_secret_bytes(
                _previous_hibe_sk_path(self._keystore, self._group_name),
                self._sk,
            )
        _atomic_write_secret_bytes(self._keystore / f"{self._group_name}.hibe.sk", sk)
        _atomic_write_text(self._keystore / f"{self._group_name}.hibe.idpath", new_path)
        root_marker = _hibe_root_marker_path(self._keystore, self._group_name)
        if new_path == "":
            _atomic_write_text(root_marker, "root\n")
        elif root_marker.exists():
            root_marker.unlink()
        # Record the outgoing path so the authority keeps opening the
        # entries sealed under it (newest first).
        if self._sk is not None:
            self._prior_sks.insert(0, self._sk)
        self._prior_paths = prior_paths
        self._sk = sk
        self._id_path = new_path
        self._allow_root_path = allow_root_path and new_path == ""


# ---------------------------------------------------------------------------
# Btn cipher — NNL subset-difference broadcast encryption via the `btn` Rust
# extension. Pluggable under this Protocol the same way BGW and JWE are.
# ---------------------------------------------------------------------------


@dataclass
class BtnGroupCipher:
    """Ceremony/group cipher backed by the ``btn`` Rust extension
    (NNL subset-difference broadcast encryption).

    Keystore layout::

        <keystore>/<group>.btn.state  # serialized PublisherState (SECRET)
        <keystore>/<group>.btn.mykit  # self-kit bytes (for decrypt)

    One kit is minted for the publisher at create() time so the same
    party can both write and read. Additional recipients get kits via
    ``btn.PublisherState.mint()`` through an admin surface outside
    this class (analogous to JWE ``add_recipient``).
    """

    name: str = "btn"
    # `Any`-typed because the btn PyO3 module has no stubs; see mypy overrides.
    # Runtime concrete type is `btn.PublisherState` (reassigned in create/load).
    _state: Any = field(default=None, repr=False)
    _self_kit: bytes = b""
    _keystore: Path | None = field(default=None, repr=False)
    _group_name: str = ""
    # Snapshot of the last bytes we successfully persisted to disk.
    # Used as the CAS `prior` on the next ``_persist_state`` call so a
    # concurrent writer can't silently overwrite our mutation. Updated
    # in ``create`` / ``load`` / ``_persist_state`` and is the cipher's
    # private "view of the world." See _keystore_backend.py.
    _last_persisted_bytes: bytes | None = field(default=None, repr=False)
    # Retired states keyed by the epoch they served as active. Populated
    # at load time from `<group>.btn.state.retired.<epoch>` files, and
    # appended-to by `rotate()`. Used by future feature surface for
    # historical-kit re-minting; the active decrypt path doesn't need
    # them today (runtime kit-glob already picks up retired kit files).
    _retired_states: dict[int, Any] = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------
    # rotation properties
    # ---------------------------------------------------------------

    @property
    def retired_state_count(self) -> int:
        """How many retired PublisherState snapshots are loaded for
        this group. Each represents one prior rotation epoch."""
        return len(self._retired_states)

    @property
    def active_epoch(self) -> int:
        """Cipher-level epoch of the active state. Starts at 0; bumps
        on every successful `rotate()`. Distinct from yaml's
        `index_epoch` (HMAC search-key counter) which also bumps on
        rotate but is governed by the admin layer."""
        if self._state is None:
            return 0
        return self._state.epoch

    @classmethod
    def create(cls, keystore: Path, group_name: str) -> BtnGroupCipher:
        """Mint a fresh btn ceremony and write its key files.

        No CAS against a prior snapshot here — by construction the
        keystore is fresh, the state file does not exist yet, and no
        other writer should be contending. We still go through the
        keystore backend so the write picks up its OS-level lock and
        atomic-rename guarantees.
        """
        from tn._native import btn as _btn

        from ._keystore_backend import LocalFileKeystoreBackend, atomic_write_bytes

        state = _btn.PublisherState()
        self_kit = state.mint()
        keystore.mkdir(parents=True, exist_ok=True)
        state_bytes = state.to_bytes()
        # prior=None means "the file must not exist." If it does
        # exist, somebody minted into the same group before us and
        # our caller (admin add_group, fresh ceremony bootstrap) made
        # an invariant mistake; surfacing the conflict is correct.
        LocalFileKeystoreBackend(keystore).write_state(group_name, prior=None, new=state_bytes)
        atomic_write_bytes(keystore / f"{group_name}.btn.mykit", self_kit)
        return cls(
            _state=state,
            _self_kit=self_kit,
            _keystore=keystore,
            _group_name=group_name,
            _last_persisted_bytes=state_bytes,
        )

    @classmethod
    def load(cls, keystore: Path, group_name: str) -> BtnGroupCipher:
        """Load an existing btn group from its keystore files.

        0.4.3a1: also picks up the retired-state archive
        (`<group>.btn.state.retired.<epoch>` siblings written by a
        prior `rotate()`) and runs `recover_interrupted_promote()` so a
        prior rotation crash is rolled forward (or back) into a
        consistent, writable state rather than leaving stale `.pending`
        files — or, worse, deleting the only surviving copy."""
        from tn._native import btn as _btn

        from .btn_keystore import BtnKeystore

        ks = BtnKeystore(keystore)
        # Crash recovery: a prior rotation may have crashed during the
        # promote dance. Roll the surviving pending pair forward to active
        # (or discard it if the active pair is still intact) so the next
        # rotation starts from a consistent, writable point.
        ks.recover_interrupted_promote(group_name)

        state_path = keystore / f"{group_name}.btn.state"
        kit_path = keystore / f"{group_name}.btn.mykit"
        state = None
        last_persisted: bytes | None = None
        if state_path.exists():
            state_bytes = state_path.read_bytes()
            state = _btn.PublisherState.from_bytes(state_bytes)
            last_persisted = state_bytes
        kit_exists = kit_path.exists()
        self_kit = kit_path.read_bytes() if kit_exists else b""

        # 0.4.2a9: integrity check at load time, not per-emit. If the
        # publisher state exists but the self-kit is missing or
        # empty, the publisher would encrypt-and-write but be unable
        # to decrypt-and-read its own emits — "silent data loss" on
        # any subsequent `tn.read()`. We can't cheaply regenerate the
        # kit from state (`state.mint()` advances state, producing a
        # NEW kit, not the original), so fail loudly at init. The
        # operator can recover by absorbing a fresh kit bundle, or by
        # re-initing the ceremony (which wipes state too).
        #
        # We check at load — once per process — instead of per-emit
        # so the hot path stays free.
        if state is not None and (not kit_exists or len(self_kit) == 0):
            kind = "missing" if not kit_exists else "empty"
            raise CipherError(
                f"btn group {group_name!r} kit is {kind}: {kit_path}. "
                f"The publisher state at {state_path} expects a "
                f"matching self-kit; without it, emits would be "
                f"unreadable by this publisher. Recover by absorbing "
                f"a fresh kit bundle for this group, or by "
                f"re-initing the ceremony from scratch (which wipes "
                f"the existing publisher state)."
            )

        # 0.4.3a1: parse retired-state archive into an epoch-keyed dict
        # on the cipher. The retired *kit* files (`.btn.mykit.retired.<N>`)
        # are picked up separately by the Rust runtime's multi-kit
        # decrypt path; cipher.py only owns the state side.
        retired_states: dict[int, Any] = {}
        try:
            retired_cls = _btn.RetiredPublisherState
        except AttributeError:
            # tn_btn wheel older than 0.4.3a1 doesn't expose
            # RetiredPublisherState. Fail-soft: cipher loads but the
            # historical-mint surface is unavailable until the wheel is
            # rebuilt. Matches the rest of the soft-fallback pattern in
            # this module.
            retired_cls = None
        if retired_cls is not None:
            for epoch, files in ks.load_retired_states(group_name).items():
                try:
                    retired_states[epoch] = retired_cls.from_bytes(files.state_bytes)
                except (_btn.BtnRuntimeError, ValueError) as exc:
                    # Backward-compat: a keystore written by a pre-fix
                    # synced-rotation path archived the wrong wire form (a
                    # raw PublisherState) into this .retired.<epoch> slot.
                    # That archive only powers the historical-mint surface;
                    # reads still work via the retired *kit*. Skip the
                    # unreadable epoch with a warning rather than failing the
                    # whole config load (SDK must not crash on legacy data).
                    warnings.warn(
                        f"btn group {group_name!r}: skipping unreadable retired "
                        f"state for epoch {epoch} ({exc}). Historical re-mint for "
                        f"that epoch is unavailable; reads are unaffected.",
                        stacklevel=2,
                    )

        return cls(
            _state=state,
            _self_kit=self_kit,
            _keystore=keystore,
            _group_name=group_name,
            _last_persisted_bytes=last_persisted,
            _retired_states=retired_states,
        )

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if self._state is None:
            raise NotAPublisherError("btn: no state file in this keystore")
        return self._state.encrypt(plaintext, aad or None)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        from tn._native import btn as _btn

        if not self._self_kit:
            raise NotARecipientError("btn: no self-kit in this keystore")
        try:
            return _btn.decrypt(self._self_kit, ciphertext, aad or None)
        except _btn.NotEntitled as e:
            raise NotARecipientError(f"btn: kit not entitled: {e}") from e

    def _persist_state(self) -> None:
        """Persist the cipher's mutated state to disk under CAS.

        Called by admin verbs after mutating state (add / revoke /
        mint). The cipher's ``_last_persisted_bytes`` is the CAS
        ``prior`` — under the keystore's exclusive lock,
        :class:`LocalFileKeystoreBackend.write_state` re-reads the
        on-disk bytes and verifies they still match. A mismatch means
        a concurrent process committed a write between our last
        ``_persist_state`` (or ``load``) and now; the
        :class:`KeystoreConflictError` propagates so the caller can
        re-load and re-apply.

        Mirrors the Rust runtime's ``admin_add_recipient`` /
        ``admin_revoke_recipient`` pattern so Python and Rust writers
        contending on the same keystore directory are mutually safe.
        """
        if self._state is None or self._keystore is None:
            return
        from ._keystore_backend import LocalFileKeystoreBackend

        new_bytes = self._state.to_bytes()
        LocalFileKeystoreBackend(self._keystore).write_state(
            self._group_name,
            prior=self._last_persisted_bytes,
            new=new_bytes,
        )
        # CAS write succeeded — refresh our private snapshot so the
        # next _persist_state has a fresh prior to compare against.
        self._last_persisted_bytes = new_bytes

    # ---------------------------------------------------------------
    # rotate() — section 3.1 of the btn cipher rotation spec
    # ---------------------------------------------------------------

    def rotate(self) -> BtnRotationResult:
        """Rotate this group's cipher state.

        Sequence:
          1. Drive `tn_btn.PublisherState.rotate()` to get a
             RotationOutcome (new active + retired snapshot).
          2. Mint a fresh self-kit on the new active state.
          3. Write the new state + self-kit to ``.pending`` files.
          4. Persist the retired (state, self-kit) pair to
             ``.retired.<prior_epoch>`` files.
          5. Atomically promote pending → active (rename dance).
          6. Refresh in-memory ``_state`` / ``_self_kit`` /
             ``_last_persisted_bytes`` / ``_retired_states``.

        Returns a :class:`BtnRotationResult` carrying the prior +
        new publisher_id, prior + new epoch, and the retired
        timestamp. The admin layer uses these to populate the
        truth-telling fields on ``tn.rotation.completed``.

        Does NOT mint per-recipient kits — that's the admin layer's
        job (it needs the yaml's recipient list, which the cipher
        class doesn't see). See ``tn.admin._btn_rotate_impl``.

        Raises :class:`NotAPublisherError` if this cipher has no
        publisher state (read-only recipient). Raises ``RuntimeError``
        with a recovery hint if a partial-prior-rotation left a
        retired-pair collision on disk.
        """
        if self._state is None or self._keystore is None:
            raise NotAPublisherError("btn: cannot rotate a cipher with no publisher state on disk")

        from .btn_keystore import BtnKeystore

        ks = BtnKeystore(self._keystore)
        prior_publisher_id = bytes(self._state.publisher_id)
        prior_epoch = int(self._state.epoch)

        # Defense in depth: if a previous rotation got partway through
        # (write_retired_pair committed but promote_pending didn't),
        # the retired pair already exists for our current prior_epoch.
        # promote_pending would later raise FileExistsError, but by
        # then we've already consumed self._state via .rotate(). Catch
        # it up-front so the wrapper is still usable.
        retired_state_path = self._keystore / f"{self._group_name}.btn.state.retired.{prior_epoch}"
        if retired_state_path.exists():
            raise RuntimeError(
                f"btn.rotate({self._group_name!r}): retired state for epoch "
                f"{prior_epoch} already exists on disk at {retired_state_path}. "
                f"A previous rotation may have crashed between write_retired_pair "
                f"and promote_pending. Manual recovery: verify the .retired.{prior_epoch} "
                f"pair against the current active state (they should be the SAME prior "
                f"state if the active didn't change), then remove the duplicate pair "
                f"and re-run rotate."
            )

        outcome = self._state.rotate()  # consumes the PyO3 wrapper's inner
        new_active = outcome.active
        retired_snapshot = outcome.retired
        new_self_kit = new_active.mint()
        new_publisher_id = bytes(new_active.publisher_id)
        new_epoch = int(new_active.epoch)

        # Step 3+4 of the promote dance: write pending state + kit,
        # then archive the retired pair under .retired.<prior_epoch>.
        ks.write_pending(
            self._group_name,
            state_bytes=new_active.to_bytes(),
            self_kit=new_self_kit,
        )
        ks.write_retired_pair(
            self._group_name,
            epoch=prior_epoch,
            state_bytes=retired_snapshot.to_bytes(),
            self_kit=self._self_kit,
        )
        # Step 5: atomic rename swap.
        ks.promote_pending(self._group_name, retiring_epoch=prior_epoch)

        # Step 6: refresh in-memory view to match disk.
        self._state = new_active
        self._self_kit = new_self_kit
        self._last_persisted_bytes = new_active.to_bytes()
        self._retired_states[prior_epoch] = retired_snapshot

        return BtnRotationResult(
            prior_publisher_id=prior_publisher_id,
            new_publisher_id=new_publisher_id,
            prior_epoch=prior_epoch,
            new_epoch=new_epoch,
            retired_at_unix_secs=int(retired_snapshot.retired_at_unix_secs),
        )


@dataclass(frozen=True)
class BtnRotationResult:
    """Structured return from :meth:`BtnGroupCipher.rotate`.

    The admin layer uses these fields to populate the truth-telling
    payload on ``tn.rotation.completed`` and the public
    ``RotateGroupResult`` returned to callers."""

    prior_publisher_id: bytes
    new_publisher_id: bytes
    prior_epoch: int
    new_epoch: int
    retired_at_unix_secs: int
