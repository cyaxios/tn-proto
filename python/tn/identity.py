"""TN per-user identity: XDG-based identity.json, BIP-39 bedrock, HKDF chain.

This is the module every verb in the wallet story funnels through:

    tn init <project>        -> Identity.create_new() + ensure_written()
    tn wallet restore        -> Identity.from_mnemonic(words) + ensure_written()
    tn.init(yaml_path)       -> Identity.load_or_ephemeral(...)
    tn wallet link           -> Identity.load() -> link a ceremony -> write

The HKDF ``info`` strings below are part of the stable ABI. Changing them
breaks every existing user's recovery. Don't touch them unless you
understand that.

Public helpers
--------------
``_resolve_did_endpoint(did_str)``
    Derive the HTTP base URL for a vault handler from a DID string.
    Supports ``did:key`` (falls back to ``TN_VAULT_DEFAULT_BASE`` env var)
    and ``did:web`` (fetches the DID document once and pins the endpoint).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mnemonic import Mnemonic

_log = logging.getLogger("tn.identity")

IDENTITY_SCHEMA_VERSION = 1

# --- HKDF info strings: stable ABI, never change -------------------------

HKDF_SALT = b"tn:v1"
HKDF_INFO_ROOT = b"tn:root:v1"
HKDF_INFO_DEVICE = b"tn:device:v1"
HKDF_INFO_VAULT_WRAP = b"tn:vault:wrap:v1"
HKDF_INFO_PASSKEY_SEED_WRAP = b"tn:passkey:seed-wrap:v1"


def _hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes = HKDF_SALT) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _did_key_from_ed25519_pub(pub_bytes: bytes) -> str:
    """Format the Ed25519 public key as a did:key string.

    Uses the standard multicodec prefix 0xED 0x01 for ed25519-pub then
    multibase base58btc 'z' encoding. Mirrors what tn/signing.py does
    so the resulting DIDs interop with the rest of the SDK.
    """
    # 0xed01 = ed25519-pub multicodec
    prefixed = b"\xed\x01" + pub_bytes
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # base58 encode
    n = int.from_bytes(prefixed, "big")
    out = b""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r : r + 1] + out
    # preserve leading zero bytes as '1' chars
    pad = 0
    for b in prefixed:
        if b == 0:
            pad += 1
        else:
            break
    return "did:key:z" + ("1" * pad + out.decode("ascii"))


# --- Paths ----------------------------------------------------------------


def _default_identity_dir() -> Path:
    """Return the XDG (or Windows equivalent) identity directory.

    Order:
      1. TN_IDENTITY_DIR if set (explicit override, cross-platform)
      2. XDG_DATA_HOME if set (POSIX + explicit on Windows)
      3. Platform default: ~/.local/share/tn on POSIX,
         %APPDATA%\\tn on Windows
    """
    override = os.environ.get("TN_IDENTITY_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "tn"
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "tn"
    return Path.home() / ".local" / "share" / "tn"


def _default_identity_path() -> Path:
    return _default_identity_dir() / "identity.json"


# --- Identity -------------------------------------------------------------


@dataclass
class IdentityPrefs:
    default_new_ceremony_mode: str = "local"  # "local" | "linked"

    @classmethod
    def from_dict(cls, d: dict | None) -> IdentityPrefs:
        d = d or {}
        return cls(
            default_new_ceremony_mode=d.get(
                "default_new_ceremony_mode",
                "local",
            ),
        )


class IdentityError(RuntimeError):
    """Raised when identity.json is missing, corrupt, or incompatible."""


@dataclass
class Identity:
    """The user's per-machine identity.

    Loaded from or written to `$XDG_DATA_HOME/tn/identity.json` (or the
    Windows equivalent). Contains the DID, the device private key in
    the form tn/signing.py expects, the BIP-39 seed (so vault_wrap_key
    is derivable without re-typing the mnemonic every CLI call),
    optional mnemonic words (held in memory only for display), the
    linked vault URL if any, and a local cache of account-wide prefs.
    """

    did: str
    device_pub_b64: str
    device_priv_b64_enc: str
    device_priv_enc_method: str = "none"  # "none" | "passkey-prf" | "mnemonic-sealed"
    seed_b64: str | None = None  # BIP-39 seed bytes; None for ephemeral
    # Mnemonic words persisted ONLY when the user passes `tn init
    # --keep-mnemonic` — opt-in because storing the recovery phrase on
    # disk increases blast radius on a filesystem compromise. Off by
    # default. When present, `tn wallet export-mnemonic` can re-display.
    mnemonic_stored: str | None = None
    linked_vault: str | None = None
    prefs_version: int = 0
    prefs: IdentityPrefs = field(default_factory=IdentityPrefs)
    version: int = IDENTITY_SCHEMA_VERSION

    # Mnemonic words are shown ONCE at generation and never written.
    _mnemonic: str | None = field(default=None, repr=False, compare=False)
    _ephemeral: bool = field(default=False, repr=False, compare=False)
    _source_path: Path | None = field(default=None, repr=False, compare=False)

    @property
    def _seed(self) -> bytes | None:
        """In-memory seed for vault_wrap_key derivation.

        Sourced from seed_b64 (persisted) when loaded from disk. Old
        callers that set `ident._seed = ...` directly still work via
        the setter.
        """
        if self.seed_b64 is None:
            return None
        pad = "=" * (-len(self.seed_b64) % 4)
        return base64.urlsafe_b64decode(self.seed_b64 + pad)

    @_seed.setter
    def _seed(self, value: bytes | None) -> None:
        if value is None:
            self.seed_b64 = None
        else:
            self.seed_b64 = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    # -- Factory: create fresh from a new mnemonic ------------------------

    @classmethod
    def create_new(cls, word_count: int = 12) -> Identity:
        """Generate a fresh mnemonic + derive everything from it.

        The returned Identity has `_mnemonic` populated; the caller is
        responsible for showing it to the user exactly once, then
        calling `ensure_written()` to persist everything except the
        mnemonic itself.
        """
        strength_bits = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
        if word_count not in strength_bits:
            raise ValueError(f"word_count must be one of {list(strength_bits)}")
        m = Mnemonic("english")
        words = m.generate(strength=strength_bits[word_count])
        ident = cls.from_mnemonic(words)
        ident._mnemonic = words
        return ident

    # -- Factory: derive from a known mnemonic ---------------------------

    @classmethod
    def from_mnemonic(cls, words: str, *, passphrase: str = "") -> Identity:
        """Deterministically derive identity from a BIP-39 mnemonic.

        Same words + same passphrase → same DID. This is the recovery path.
        """
        m = Mnemonic("english")
        if not m.check(words):
            raise IdentityError("invalid BIP-39 mnemonic (bad checksum)")
        seed = m.to_seed(words, passphrase=passphrase)
        root = _hkdf(seed, HKDF_INFO_ROOT)
        device_priv_raw = _hkdf(root, HKDF_INFO_DEVICE)
        priv = Ed25519PrivateKey.from_private_bytes(device_priv_raw)
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ident = cls(
            did=_did_key_from_ed25519_pub(pub),
            device_pub_b64=base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii"),
            device_priv_b64_enc=base64.urlsafe_b64encode(device_priv_raw)
            .rstrip(b"=")
            .decode("ascii"),
            device_priv_enc_method="none",
        )
        ident._seed = seed
        return ident

    # -- Factory: derive the vault wrap key --------------------------------

    def vault_wrap_key(self) -> bytes:
        """32 bytes of AES-256 key for client-side sealing."""
        if self._seed is None:
            raise IdentityError(
                "vault_wrap_key requires seed (rederive via from_mnemonic or from_passkey_prf)",
            )
        root = _hkdf(self._seed, HKDF_INFO_ROOT)
        return _hkdf(root, HKDF_INFO_VAULT_WRAP)

    # -- Factory: ephemeral (no persistence) -------------------------------

    @classmethod
    def create_ephemeral(cls) -> Identity:
        """Random device key, no mnemonic, no persistence.

        Used when tn.init(yaml) runs with no identity.json present and
        the caller just wants a working DID for the current process.
        The key never touches disk; lives only in this Identity instance.
        """
        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ident = cls(
            did=_did_key_from_ed25519_pub(pub),
            device_pub_b64=base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii"),
            device_priv_b64_enc=base64.urlsafe_b64encode(priv_raw).rstrip(b"=").decode("ascii"),
            device_priv_enc_method="none",
        )
        ident._ephemeral = True
        return ident

    # -- Device private key accessor ---------------------------------------

    def device_private_key_bytes(self) -> bytes:
        """Raw Ed25519 private key bytes."""
        if self.device_priv_enc_method != "none":
            raise IdentityError(
                f"device_priv stored with encryption "
                f"{self.device_priv_enc_method!r} — unwrap before use",
            )
        pad = "=" * (-len(self.device_priv_b64_enc) % 4)
        return base64.urlsafe_b64decode(self.device_priv_b64_enc + pad)

    # -- Persistence -------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> Identity:
        """Read identity.json. Raises IdentityError if missing/corrupt."""
        p = path or _default_identity_path()
        if not p.is_file():
            raise IdentityError(f"identity not found at {p}")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IdentityError(f"identity.json parse error at {p}: {e}") from e
        if doc.get("version") != IDENTITY_SCHEMA_VERSION:
            raise IdentityError(
                f"identity schema version {doc.get('version')} != "
                f"{IDENTITY_SCHEMA_VERSION}; run `tn wallet restore` or "
                f"upgrade your identity.json manually",
            )
        ident = cls(
            did=doc["did"],
            device_pub_b64=doc["device_pub_b64"],
            device_priv_b64_enc=doc["device_priv_b64_enc"],
            device_priv_enc_method=doc.get("device_priv_enc_method", "none"),
            seed_b64=doc.get("seed_b64"),
            mnemonic_stored=doc.get("mnemonic_stored"),
            linked_vault=doc.get("linked_vault"),
            prefs_version=int(doc.get("prefs_version", 0)),
            prefs=IdentityPrefs.from_dict(doc.get("prefs")),
            version=int(doc.get("version", IDENTITY_SCHEMA_VERSION)),
        )
        ident._source_path = p
        if ident.mnemonic_stored:
            ident._mnemonic = ident.mnemonic_stored
        return ident

    @classmethod
    def load_or_ephemeral(cls, path: Path | None = None) -> Identity:
        """Load identity.json if present; otherwise return an ephemeral one.

        Used by `tn.init(yaml_path)` for dev-ergonomic scenarios where
        no identity has been set up yet.
        """
        p = path or _default_identity_path()
        if p.is_file():
            try:
                return cls.load(p)
            except IdentityError:
                raise
        return cls.create_ephemeral()

    def ensure_written(self, path: Path | None = None) -> Path:
        """Persist identity.json. Mkdir parents, chmod 0600."""
        if self._ephemeral:
            raise IdentityError(
                "refusing to persist an ephemeral identity; generate via "
                "Identity.create_new() instead",
            )
        p = path or _default_identity_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": self.version,
            "did": self.did,
            "device_pub_b64": self.device_pub_b64,
            "device_priv_b64_enc": self.device_priv_b64_enc,
            "device_priv_enc_method": self.device_priv_enc_method,
            "seed_b64": self.seed_b64,
            "mnemonic_stored": self.mnemonic_stored,
            "linked_vault": self.linked_vault,
            "prefs_version": self.prefs_version,
            "prefs": asdict(self.prefs),
        }
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(doc, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        # Atomic rename on POSIX; Windows needs explicit replace.
        if p.exists():
            p.unlink()
        tmp.rename(p)
        # 0600 on POSIX. On Windows the XDG home is user-scoped anyway.
        if sys.platform != "win32":
            os.chmod(p, 0o600)
        self._source_path = p
        return p


# ---------------------------------------------------------------------------
# DID endpoint resolution
# ---------------------------------------------------------------------------

# In-process cache: did_str -> base URL string.
_did_endpoint_cache: dict[str, str] = {}


def _resolve_did_endpoint(did_str: str) -> str:
    """Derive the HTTP base URL for a vault service from a DID string.

    Supported DID methods:

    ``did:key:z...``
        The key is self-describing; no document to fetch. Transport URL
        comes from the ``TN_VAULT_DEFAULT_BASE`` environment variable
        (default ``http://localhost:8790``). Useful for local dev and
        tests that point at a local tnproto-org instance.

    ``did:web:<host>`` or ``did:web:<host>:<path:segments>``
        Fetch ``https://<host>/.well-known/did.json`` once per process,
        look for a ``service`` entry with ``type == "TnVaultEndpoint"``
        and use its ``serviceEndpoint``. Falls back to
        ``https://<host>`` when no matching service is found.
        The result is pinned in memory for the lifetime of the process
        so further calls are free.

    Raises ``ValueError`` for unsupported DID methods.
    """
    if did_str in _did_endpoint_cache:
        return _did_endpoint_cache[did_str]

    if did_str.startswith("did:key:"):
        base = os.environ.get("TN_VAULT_DEFAULT_BASE", "http://localhost:8790").rstrip("/")
        _did_endpoint_cache[did_str] = base
        return base

    if did_str.startswith("did:web:"):
        # did:web:host  or  did:web:host:path:segments
        # per the did:web spec, colons after the host encode path separators.
        parts = did_str[len("did:web:") :].split(":")
        host = parts[0]
        parts[1:] if len(parts) > 1 else [".well-known", "did.json"]

        # Well-known URL is always at /.well-known/did.json for the host.
        well_known = f"https://{host}/.well-known/did.json"

        try:
            import urllib.request

            with urllib.request.urlopen(well_known, timeout=5) as resp:
                doc = json.loads(resp.read())
            for svc in doc.get("service", []):
                if svc.get("type") == "TnVaultEndpoint":
                    endpoint = svc["serviceEndpoint"].rstrip("/")
                    _did_endpoint_cache[did_str] = endpoint
                    _log.info(
                        "_resolve_did_endpoint: did:web %s -> %s (from DID doc)",
                        host,
                        endpoint,
                    )
                    return endpoint
        except Exception as exc:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.warning(
                "_resolve_did_endpoint: could not fetch DID doc for %s (%s) "
                "-- falling back to https://%s",
                did_str,
                exc,
                host,
            )

        # Fallback: assume the host itself is the vault base.
        fallback = f"https://{host}"
        _did_endpoint_cache[did_str] = fallback
        return fallback

    raise ValueError(
        f"_resolve_did_endpoint: unsupported DID method in {did_str!r}. Supported: did:key, did:web"
    )
