"""Pluggable group-cipher abstraction.

A GroupCipher is what a ceremony uses to seal the plaintext fields of a
single group into an opaque `ciphertext` bytes blob, and to recover
them on the read side. Everything outside this file — canonical
serialization, HMAC index tokens, chain, signature — is cipher-agnostic.

Two implementations ship:

  * JWEGroupCipher — static ECDH (X25519) + HKDF-SHA256 + AES-256-KW
    per recipient + AES-256-GCM body. Per-recipient revocation is O(1):
    drop the recipient from the list, next seal omits them.
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
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class CipherError(RuntimeError):
    """Base error for cipher operations."""


class NotAPublisherError(CipherError):
    """Raised when encrypt() is called without publisher key material."""


class NotARecipientError(CipherError):
    """Raised when decrypt() is called without recipient key material."""


@runtime_checkable
class GroupCipher(Protocol):
    """One cipher instance per (ceremony, group). Stateful: holds key
    material on disk under `keystore/`."""

    name: str  # "jwe" or "btn"

    def encrypt(self, plaintext: bytes) -> bytes:
        """Seal `plaintext` into an opaque blob. Raises NotAPublisherError
        if this party doesn't hold the write key."""
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Open `ciphertext` to recover plaintext. Raises
        NotARecipientError if this party can't read this group."""
        ...


# ---------------------------------------------------------------------------
# JWE cipher — static ECDH (X25519) + HKDF-SHA256 + AES-256-KW + AES-256-GCM
# ---------------------------------------------------------------------------

_HKDF_INFO = b"tn-jwe:v1:A256KW"


def _derive_kek(peer_pub: bytes, my_sk: X25519PrivateKey) -> bytes:
    shared = my_sk.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(shared)


# Wire format v1 fixed sizes. A future version byte changes these wholesale.
_V1_IV_LEN = 12  # AES-GCM 96-bit nonce
_V1_SENDER_PUB_LEN = 32  # X25519 raw encoding
_V1_WRAPPED_LEN = 40  # AES-KW output for a 32-byte key
_V1_MIN_LEN = 1 + _V1_IV_LEN + _V1_SENDER_PUB_LEN + 2 + 4  # + 0 wrapped keys + 0 ct


def _pack_ciphertext(iv: bytes, ct: bytes, sender_pub: bytes, wrapped_keys: list[bytes]) -> bytes:
    """Pack JWE components into a single opaque blob so the envelope
    schema stays ``{ciphertext: b64, field_hashes}`` regardless of cipher.

    Wire format v1 (big-endian integers):

        version_byte (1B) = 0x01
        iv (12B)
        sender_pub (32B)
        n_recipients (2B)
        wrapped_keys (40 * n_recipients)
        ct_len (4B)
        ciphertext (ct_len bytes)

    Sizes are fixed per version. A change of primitives allocates a new
    version byte (0x02, ...) with its own fixed sizes.
    """
    if len(iv) != _V1_IV_LEN:
        raise CipherError(f"JWE v1 iv must be {_V1_IV_LEN} bytes, got {len(iv)}")
    if len(sender_pub) != _V1_SENDER_PUB_LEN:
        raise CipherError(
            f"JWE v1 sender_pub must be {_V1_SENDER_PUB_LEN} bytes, got {len(sender_pub)}"
        )
    for w in wrapped_keys:
        if len(w) != _V1_WRAPPED_LEN:
            raise CipherError(f"JWE v1 wrapped key must be {_V1_WRAPPED_LEN} bytes, got {len(w)}")

    out = bytearray([0x01])
    out += iv
    out += sender_pub
    out += len(wrapped_keys).to_bytes(2, "big")
    for w in wrapped_keys:
        out += w
    out += len(ct).to_bytes(4, "big") + ct
    return bytes(out)


def _unpack_ciphertext(blob: bytes) -> tuple[bytes, bytes, list[bytes], bytes]:
    """Inverse of ``_pack_ciphertext`` for version 0x01.

    Returns (iv, sender_pub, wrapped_keys, ct). Raises CipherError on
    malformed input: wrong version, insufficient length, or trailing bytes.
    """
    if len(blob) < 1:
        raise CipherError("JWE: packed ciphertext is empty")
    if blob[0] != 0x01:
        raise CipherError(f"JWE: unknown packed version {blob[0]:#x}")
    if len(blob) < _V1_MIN_LEN:
        raise CipherError(
            f"JWE v1 packed ciphertext shorter than minimum {_V1_MIN_LEN} bytes (got {len(blob)})"
        )
    p = 1
    iv = blob[p : p + _V1_IV_LEN]
    p += _V1_IV_LEN
    sender_pub = blob[p : p + _V1_SENDER_PUB_LEN]
    p += _V1_SENDER_PUB_LEN
    n = int.from_bytes(blob[p : p + 2], "big")
    p += 2

    expected_end = p + n * _V1_WRAPPED_LEN + 4  # wrapped_keys + ct_len
    if len(blob) < expected_end:
        raise CipherError(
            f"JWE v1 packed ciphertext truncated at wrapped-key array "
            f"(n={n}, expected at least {expected_end} bytes, got {len(blob)})"
        )
    wrapped: list[bytes] = []
    for _ in range(n):
        wrapped.append(blob[p : p + _V1_WRAPPED_LEN])
        p += _V1_WRAPPED_LEN
    ct_len = int.from_bytes(blob[p : p + 4], "big")
    p += 4
    ct = blob[p : p + ct_len]
    p += ct_len
    if p != len(blob):
        raise CipherError(
            f"JWE v1 packed ciphertext malformed: parsed {p} bytes of "
            f"{len(blob)} ({len(blob) - p} trailing bytes)"
        )
    return iv, sender_pub, wrapped, ct


def _atomic_write_text(path: Path, content: str) -> None:
    """Write `content` to `path` via write-to-temp-then-rename.

    Path.replace is atomic on POSIX; on Windows it's not guaranteed atomic
    but is far safer than a truncating write. Acceptable for a local
    keystore file, where corruption is the only concern we guard against.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


@dataclass
class JWEGroupCipher:
    """Static-DH JWE cipher: one cipher per (ceremony, group).

    Threat model: sender's long-lived X25519 private is the root of all
    per-recipient KEKs. Compromise that key and past envelopes are
    readable. (Same posture as BGW master — no per-envelope forward
    secrecy.) In exchange: every per-seal cost is in-place AES-KW,
    microseconds per recipient. Revoking a recipient is an O(1)
    recipient-list edit with no coordination.

    Keystore layout::

        <keystore>/<group>.jwe.sender       32B X25519 private (publisher)
        <keystore>/<group>.jwe.recipients   JSON list [{did, pub_b64}, ...]
        <keystore>/<group>.jwe.mykey        32B X25519 private (recipient)
    """

    name: str = "jwe"
    _sender_sk: X25519PrivateKey | None = field(default=None, repr=False)
    _sender_pub: bytes = b""
    _my_sk: X25519PrivateKey | None = field(default=None, repr=False)
    _recipients_path: Path | None = field(default=None, repr=False)
    _kek_cache: dict[str, bytes] | None = field(default=None, repr=False)

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

        WARNING: Overwrites any existing JWE keystore files for this
        group. Use rotate() at the ceremony layer for key cycling.
        """
        keystore.mkdir(parents=True, exist_ok=True)
        sender_sk = X25519PrivateKey.generate()
        (keystore / f"{group_name}.jwe.sender").write_bytes(sender_sk.private_bytes_raw())
        sender_pub = sender_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        pubs = dict(recipient_pubs or {})
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
            (keystore / f"{group_name}.jwe.mykey").write_bytes(my_sk_new.private_bytes_raw())
            pubs[missing[0]] = my_sk_new.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        recipients_doc = [
            {"did": d, "pub_b64": base64.b64encode(pubs[d]).decode("ascii")} for d in recipient_dids
        ]
        recipients_path = keystore / f"{group_name}.jwe.recipients"
        _atomic_write_text(recipients_path, json.dumps(recipients_doc, indent=2))

        my_sk_path = keystore / f"{group_name}.jwe.mykey"
        my_sk = (
            X25519PrivateKey.from_private_bytes(my_sk_path.read_bytes())
            if my_sk_path.exists()
            else None
        )

        inst = cls(
            _sender_sk=sender_sk,
            _sender_pub=sender_pub,
            _my_sk=my_sk,
            _recipients_path=recipients_path,
            _kek_cache={},
        )
        inst._recompute_kek_cache()
        return inst

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

        inst = cls(
            _sender_sk=sender_sk,
            _sender_pub=sender_pub,
            _my_sk=my_sk,
            _recipients_path=recipients_path if recipients_path.exists() else None,
            _kek_cache={} if sender_sk else None,
        )
        if sender_sk and recipients_path.exists():
            inst._recompute_kek_cache()
        return inst

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

    def _recompute_kek_cache(self) -> None:
        """Re-derive the per-recipient KEKs. Called at create() and after
        revoke_recipient()."""
        if self._sender_sk is None:
            raise RuntimeError(
                "_recompute_kek_cache called without sender secret key bound"
            )
        if self._recipients_path is None:
            raise RuntimeError(
                "_recompute_kek_cache called without recipients_path bound"
            )
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        cache: dict[str, bytes] = {}
        for entry in doc:
            pub = base64.b64decode(entry["pub_b64"])
            kek = _derive_kek(pub, self._sender_sk)
            cache[entry["did"]] = kek
        self._kek_cache = cache

    def revoke_recipient(self, did: str) -> None:
        """Drop ``did`` from the recipient list. Subsequent encrypts exclude
        them. O(1) — no coordination with other recipients."""
        if self._sender_sk is None or self._recipients_path is None:
            raise NotAPublisherError("JWE: only the publisher can revoke")
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        before = len(doc)
        doc = [e for e in doc if e["did"] != did]
        if len(doc) == before:
            return  # already absent — idempotent
        _atomic_write_text(self._recipients_path, json.dumps(doc, indent=2))
        self._recompute_kek_cache()

    def add_recipient(self, did: str, pub_bytes: bytes) -> None:
        """Append ``did`` with raw 32-byte X25519 pub to the recipient list.

        Subsequent encrypts include a wrapped CEK for this recipient.
        Idempotent: re-adding the same DID (even with a different pub)
        replaces the existing entry rather than duplicating it.
        """
        if self._sender_sk is None or self._recipients_path is None:
            raise NotAPublisherError("JWE: only the publisher can add recipients")
        if len(pub_bytes) != 32:
            raise ValueError(f"pub_bytes must be 32 raw X25519 bytes, got {len(pub_bytes)}")
        doc = json.loads(self._recipients_path.read_text(encoding="utf-8"))
        doc = [e for e in doc if e.get("did") != did]
        doc.append(
            {
                "did": did,
                "pub_b64": base64.b64encode(pub_bytes).decode("ascii"),
            }
        )
        _atomic_write_text(self._recipients_path, json.dumps(doc, indent=2))
        self._recompute_kek_cache()

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._sender_sk is None or self._kek_cache is None:
            raise NotAPublisherError("JWE: no sender X25519 key in this keystore")
        if not self._kek_cache:
            raise NotAPublisherError(
                "JWE: cannot encrypt with zero recipients. Add a recipient "
                "before calling encrypt()."
            )
        cek = secrets.token_bytes(32)
        iv = os.urandom(12)
        ct = AESGCM(cek).encrypt(iv, plaintext, None)
        wrapped = [aes_key_wrap(kek, cek) for kek in self._kek_cache.values()]
        return _pack_ciphertext(iv, ct, self._sender_pub, wrapped)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._my_sk is None:
            raise NotARecipientError("JWE: no recipient X25519 key in this keystore")
        iv, sender_pub, wrapped, ct = _unpack_ciphertext(ciphertext)
        # Recipient doesn't know which wrapped_key is theirs — try each.
        # At N<=10 that's at most ~50µs of wasted unwrap work; the AEAD
        # tag catches a mismatch without risk of silent false plaintext.
        kek = _derive_kek(sender_pub, self._my_sk)
        from cryptography.exceptions import InvalidTag

        for w in wrapped:
            try:
                cek = aes_key_unwrap(kek, w)
            except (InvalidUnwrap, ValueError):
                continue
            try:
                return AESGCM(cek).decrypt(iv, ct, None)
            except InvalidTag:
                continue
        raise NotARecipientError("JWE: no wrapped key in this envelope decrypts under my KEK")


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

    @classmethod
    def create(cls, keystore: Path, group_name: str) -> BtnGroupCipher:
        """Mint a fresh btn ceremony and write its key files."""
        import tn_btn as _btn

        state = _btn.PublisherState()
        self_kit = state.mint()
        keystore.mkdir(parents=True, exist_ok=True)
        (keystore / f"{group_name}.btn.state").write_bytes(state.to_bytes())
        (keystore / f"{group_name}.btn.mykit").write_bytes(self_kit)
        return cls(
            _state=state,
            _self_kit=self_kit,
            _keystore=keystore,
            _group_name=group_name,
        )

    @classmethod
    def load(cls, keystore: Path, group_name: str) -> BtnGroupCipher:
        """Load an existing btn group from its keystore files."""
        import tn_btn as _btn

        state_path = keystore / f"{group_name}.btn.state"
        kit_path = keystore / f"{group_name}.btn.mykit"
        state = None
        if state_path.exists():
            state = _btn.PublisherState.from_bytes(state_path.read_bytes())
        self_kit = kit_path.read_bytes() if kit_path.exists() else b""
        return cls(
            _state=state,
            _self_kit=self_kit,
            _keystore=keystore,
            _group_name=group_name,
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._state is None:
            raise NotAPublisherError("btn: no state file in this keystore")
        return self._state.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        import tn_btn as _btn

        if not self._self_kit:
            raise NotARecipientError("btn: no self-kit in this keystore")
        try:
            return _btn.decrypt(self._self_kit, ciphertext)
        except _btn.NotEntitled as e:
            raise NotARecipientError(f"btn: kit not entitled: {e}") from e

    def _persist_state(self) -> None:
        """Called by admin verbs after mutating state (add/revoke/mint)."""
        if self._state is not None and self._keystore is not None:
            p = self._keystore / f"{self._group_name}.btn.state"
            p.write_bytes(self._state.to_bytes())
