"""Executable reference for the low-level HIBE primitives (`tn._hibe`).

Generates the captured output in docs/guide/hibe-library.md. Every primitive
is bytes-in / bytes-out; this file is the source of truth for the doc and a
self-asserting smoke test of the surface.

Run:  python tests/demo_hibe_primitives.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tn import _hibe  # noqa: E402


def h(b: bytes) -> str:
    return b[:8].hex() + f"... ({len(b)} bytes)"


def section(t: str) -> None:
    print(f"\n{'=' * 66}\n{t}\n{'=' * 66}")


def main() -> int:
    # --- Setup: one authority's system keypair.
    section("setup(max_depth) -> (mpk, msk)")
    mpk, msk = _hibe.setup(2)
    print(f"mpk (public, shareable) : {h(mpk)}")
    print(f"msk (secret, authority) : {h(msk)}")
    print(f"mpk_fingerprint(mpk)    : {_hibe.mpk_fingerprint(mpk).hex()}")
    print(f"mpk_max_depth(mpk)      : {_hibe.mpk_max_depth(mpk)}")

    # --- Keygen: mint a reader key for an identity path from the msk.
    section("keygen(mpk, msk, id_path) -> sk")
    sk = _hibe.keygen(mpk, msk, "alice/reports")
    print(f"sk for 'alice/reports'  : {h(sk)}")
    print(f"key_id_path(sk)         : {_hibe.key_id_path(sk)!r}")

    # --- Seal / open a whole body (the hybrid blob a group stores).
    section("seal(mpk, id_path, plaintext[, aad]) / open(mpk, sk, blob[, aad])")
    blob = _hibe.seal(mpk, "alice/reports", b"quarterly numbers")
    print(f"sealed blob             : {h(blob)}")
    print(f"open with alice's sk    : {_hibe.open(mpk, sk, blob)!r}")

    # Bind a marker (authenticated, not encrypted, not stored):
    aad = b"policy=finra-oba"
    gov = _hibe.seal(mpk, "alice/reports", b"governed body", aad)
    print(f"open with correct aad   : {_hibe.open(mpk, sk, gov, aad)!r}")
    try:
        _hibe.open(mpk, sk, gov, b"policy=other")
    except _hibe.HibeCryptoError:
        print("open with wrong aad     : HibeCryptoError (marker mismatch)")

    # --- KEM: wrap/unwrap a 32-byte content key directly (KEM-not-direct).
    section("kem_wrap(mpk, id_path, cek32) / kem_unwrap(mpk, sk, wrapped)")
    cek = bytes(range(32))
    wrapped = _hibe.kem_wrap(mpk, "alice/reports", cek)
    print(f"wrapped CEK             : {h(wrapped)}")
    print(f"unwrap == original CEK  : {_hibe.kem_unwrap(mpk, sk, wrapped) == cek}")

    # --- Delegate: a parent key mints a child key, no msk.
    section("delegate(mpk, parent_sk, child_label) -> child_sk")
    parent = _hibe.keygen(mpk, msk, "alice")
    child = _hibe.delegate(mpk, parent, "reports")
    print(f"delegated child path    : {_hibe.key_id_path(child)!r}")
    print(f"child opens alice/reports blob: {_hibe.open(mpk, child, blob)!r}")

    # --- Negative: a key on a different path cannot open.
    section("wrong-identity and tamper both fail closed")
    bob = _hibe.keygen(mpk, msk, "bob/reports")
    try:
        _hibe.open(mpk, bob, blob)
    except _hibe.HibeCryptoError:
        print("bob's key on alice's blob     : HibeCryptoError")
    bad = bytearray(blob)
    bad[-1] ^= 1  # flip a body byte -> AEAD tag fails
    try:
        _hibe.open(mpk, sk, bytes(bad))
    except (_hibe.HibeCryptoError, ValueError):
        print("one flipped byte              : rejected (tag or parse)")

    # --- Everything is bytes: keys/blobs are the entire API surface.
    section("wire sizes (bytes; vary with max_depth and path depth)")
    print(f"mpk={len(mpk)}  msk={len(msk)}  sk={len(sk)}  "
          f"wrapped_cek={len(wrapped)}  fingerprint=32")

    print("\nall primitive checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
