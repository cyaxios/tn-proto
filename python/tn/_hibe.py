"""Thin, stable import surface over the native BBG HIBE cipher core.

Everything here is bytes-in/bytes-out against the canonical tn-hibe
encodings (the same bytes the cross-impl golden vectors pin):

    setup(max_depth)                 -> (mpk, msk)
    keygen(mpk, msk, id_path)        -> sk
    delegate(mpk, parent_sk, label)  -> sk          # parent -> child, no msk
    key_id_path(sk)                  -> str         # slash-separated path
    kem_wrap(mpk, id_path, cek)      -> wrapped     # 32-byte CEK
    kem_unwrap(mpk, sk, wrapped)     -> cek
    seal(mpk, id_path, plaintext)    -> blob        # full group ciphertext
    open(mpk, sk, blob)              -> plaintext
    mpk_fingerprint(mpk)             -> 32 bytes    # manifest mpk_fp
    mpk_max_depth(mpk)               -> int         # also a parse check

Raw BBG encrypt/decrypt over GT elements and the GT byte codecs are
deliberately NOT exposed here: the wire rule is KEM-not-direct (a GT
element never leaves the process), and the golden-vector fixtures own
the only legitimate use of GT bytes.

``HibeCryptoError`` means "wrong identity key or tampered bytes"; the
cipher layer maps it to ``NotARecipientError``. Identity paths are
slash-separated labels, root-first (``<reader>[/<policy-hash>]`` under
the per-authority trust model).
"""

from __future__ import annotations

from typing import Any

_HIBE_IMPORT_ERROR: BaseException | None = None

try:
    # ``tn._native`` is a single PyO3 extension module, not a Python package;
    # HIBE is exposed as its ``hibe`` attribute/submodule.
    from tn._native import hibe as _native_hibe
except (AttributeError, ImportError) as exc:  # pragma: no cover - platform build matrix
    _native_hibe = None
    _HIBE_IMPORT_ERROR = exc


def _missing_hibe(*_args: Any, **_kwargs: Any) -> Any:
    """Raise when this wheel/runtime was built without the HIBE submodule."""
    hint = (
        "HIBE native extension is unavailable: tn._native does not expose "
        "the hibe submodule. Rebuild or install tn-proto with tn-hibe support."
    )
    if _HIBE_IMPORT_ERROR is None:
        raise RuntimeError(hint)
    raise RuntimeError(hint) from _HIBE_IMPORT_ERROR


if _native_hibe is None:

    class HibeCryptoError(RuntimeError):
        """Placeholder error type used when the native HIBE module is absent."""

    delegate = _missing_hibe
    kem_unwrap = _missing_hibe
    kem_wrap = _missing_hibe
    key_id_path = _missing_hibe
    keygen = _missing_hibe
    mpk_fingerprint = _missing_hibe
    mpk_max_depth = _missing_hibe
    open = _missing_hibe
    seal = _missing_hibe
    setup = _missing_hibe
else:
    HibeCryptoError = _native_hibe.HibeCryptoError
    delegate = _native_hibe.delegate
    kem_unwrap = _native_hibe.kem_unwrap
    kem_wrap = _native_hibe.kem_wrap
    key_id_path = _native_hibe.key_id_path
    keygen = _native_hibe.keygen
    mpk_fingerprint = _native_hibe.mpk_fingerprint
    mpk_max_depth = _native_hibe.mpk_max_depth
    open = _native_hibe.open
    seal = _native_hibe.seal
    setup = _native_hibe.setup

__all__ = [
    "HibeCryptoError",
    "delegate",
    "kem_unwrap",
    "kem_wrap",
    "key_id_path",
    "keygen",
    "mpk_fingerprint",
    "mpk_max_depth",
    "open",
    "seal",
    "setup",
]
