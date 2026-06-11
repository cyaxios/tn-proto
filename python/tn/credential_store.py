"""Machine credential store — cache a derived key, never the master secret.

The same shape ``gh`` and the ``claude`` CLI use: after a one-time unlock,
a derived credential is cached so later commands run non-interactively. The
cached value is the account **AWK** (the account-scoped wrapping key), never
the passphrase — "token, not password." See ``_init_attach`` for how it's
used at init.

Two backends behind one interface so wallet code is storage-agnostic:

  * ``KeyringCredentialStore`` — the OS secret store (Windows Credential
    Manager / macOS Keychain / Linux Secret Service) via the ``keyring``
    package. Preferred when available.
  * ``FileCredentialStore`` — a single ``0600`` JSON file next to
    ``identity.json``. The graceful fallback for headless / CI / container
    contexts with no keychain (exactly ``gh``'s ``hosts.yml`` fallback).

``default_credential_store()`` returns the keychain backend when ``keyring``
is importable and a round-trip probe succeeds, else the file backend. Wallet
code calls the interface (``get`` / ``set`` / ``delete``) and never learns
which backend it got.

Security posture: the file backend is the SAME posture as the device key
that already sits in ``identity.json`` (plaintext-at-rest, an unencrypted
SSH-key equivalent). Moving BOTH behind the keychain is the single hardening
that lifts the whole machine, tracked separately.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

try:  # module-level optional dependency probe (no inline imports)
    import keyring as _keyring
except Exception:  # noqa: BLE001 — any import/backend error → file fallback
    _keyring = None

#: Keyring "service" namespace so TN secrets don't collide with other apps.
_SERVICE = "tn-proto"


@runtime_checkable
class CredentialStore(Protocol):
    """Get / set / delete a named secret. Implementations never raise on a
    missing key (``get`` returns ``None``); they may raise on a backend I/O
    fault, which callers in ``_init_attach`` catch and contain."""

    def get(self, name: str) -> bytes | None: ...
    def set(self, name: str, value: bytes) -> None: ...
    def delete(self, name: str) -> None: ...


class FileCredentialStore:
    """A single ``0600`` JSON file mapping name → base64(value).

    Atomic writes (temp + ``os.replace``) and POSIX ``0600`` so the file is
    owner-only. On Windows the user-profile ACL is the protection (chmod is
    a POSIX no-op); the path lives under the user's home regardless.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def _load(self) -> dict[str, str]:
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (ValueError, OSError):
            # Corrupt / unreadable store reads as empty — a fresh unlock
            # rewrites it. Never raise on a read.
            return {}

    def _save(self, doc: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(doc, sort_keys=True, indent=2).encode("utf-8")
        tmp = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
        # os.open with 0o600 so the secret is owner-only from creation, not
        # after a chmod race. Same hardened pattern as the keystore backend.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)

    def get(self, name: str) -> bytes | None:
        enc = self._load().get(name)
        if enc is None:
            return None
        try:
            return base64.b64decode(enc)
        except (ValueError, TypeError):
            return None

    def set(self, name: str, value: bytes) -> None:
        doc = self._load()
        doc[name] = base64.b64encode(value).decode("ascii")
        self._save(doc)

    def delete(self, name: str) -> None:
        doc = self._load()
        if doc.pop(name, None) is not None:
            self._save(doc)


class _KeyringLike(Protocol):
    """The slice of the ``keyring`` module surface we use."""

    def get_password(self, service: str, name: str, /) -> str | None: ...
    def set_password(self, service: str, name: str, value: str, /) -> None: ...
    def delete_password(self, service: str, name: str, /) -> None: ...


class KeyringCredentialStore:
    """OS secret store via ``keyring``. Values are base64 (keyring stores
    strings). Construct via :func:`default_credential_store`, which injects
    the imported keyring module after a usability probe."""

    def __init__(self, keyring_module: _KeyringLike) -> None:
        self._kr = keyring_module

    def get(self, name: str) -> bytes | None:
        enc = self._kr.get_password(_SERVICE, name)
        if enc is None:
            return None
        try:
            return base64.b64decode(enc)
        except (ValueError, TypeError):
            return None

    def set(self, name: str, value: bytes) -> None:
        self._kr.set_password(
            _SERVICE, name, base64.b64encode(value).decode("ascii")
        )

    def delete(self, name: str) -> None:
        try:
            self._kr.delete_password(_SERVICE, name)
        except Exception:  # noqa: BLE001 — keyring raises if the entry is absent
            pass


def _keyring_usable() -> bool:
    """True iff ``keyring`` imported AND a set/get/delete round-trip works.
    A keyring can import but have no working backend (the common Linux/CI
    case) — probe before trusting it."""
    if _keyring is None:
        return False
    probe = "tn-proto-probe"
    try:
        _keyring.set_password(_SERVICE, probe, "ok")
        got = _keyring.get_password(_SERVICE, probe)
        _keyring.delete_password(_SERVICE, probe)
        return got == "ok"
    except Exception:  # noqa: BLE001 — any backend fault → not usable
        return False


def default_credential_store(file_path: Path | None = None) -> CredentialStore:
    """Return the best available store: OS keychain when usable, else a
    ``0600`` file. ``file_path`` overrides the fallback file location
    (defaults to ``<identity dir>/credentials.json``)."""
    if _keyring is not None and _keyring_usable():
        return KeyringCredentialStore(_keyring)
    if file_path is None:
        from .identity import _default_identity_path

        file_path = _default_identity_path().parent / "credentials.json"
    return FileCredentialStore(file_path)


def awk_key_name(account_id: str) -> str:
    """Stable CredentialStore key under which an account's AWK is cached."""
    return f"awk:{account_id}"


__all__ = [
    "CredentialStore",
    "FileCredentialStore",
    "KeyringCredentialStore",
    "awk_key_name",
    "default_credential_store",
]
