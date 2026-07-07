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

from tn._native.hibe import (  # noqa: A004  (`open` mirrors the native verb)
    HibeCryptoError,
    delegate,
    kem_unwrap,
    kem_wrap,
    key_id_path,
    keygen,
    mpk_fingerprint,
    mpk_max_depth,
    open,
    seal,
    setup,
)

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
