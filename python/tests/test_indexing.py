"""Unit tests for tn.indexing — the keyed equality-token module.

No native-crypto dependency: exercises HKDF derivation + HMAC tokens
directly, independent of BGW.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# Side-step `tn/__init__.py` — it eagerly loads the native crypto lib,
# which is a separate build artifact. Load `tn.indexing` (and its sole
# sibling dependency `tn.canonical`) directly by file path so these
# tests stay runnable without the compiled .dll/.so.
def _load_module(name: str, relpath: str):
    path = HERE.parent / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_load_module("tn_canonical_standalone", "tn/canonical.py")
# `tn.indexing` does `from .canonical import canonical_bytes`, so we have
# to stage canonical under the expected dotted name.
sys.modules.setdefault("tn", type(sys)("tn"))  # empty stub package
sys.modules["tn.canonical"] = sys.modules["tn_canonical_standalone"]
indexing = _load_module("tn.indexing", "tn/indexing.py")


def test_derivation_is_deterministic():
    master = b"\x01" * 32
    k1 = indexing._derive_group_index_key(master, "ceremony_A", "default")
    k2 = indexing._derive_group_index_key(master, "ceremony_A", "default")
    assert k1 == k2
    assert len(k1) == 32


def test_derivation_is_scoped_by_ceremony_and_group():
    master = b"\x01" * 32
    k_base = indexing._derive_group_index_key(master, "ceremony_A", "default")
    assert k_base != indexing._derive_group_index_key(master, "ceremony_B", "default")
    assert k_base != indexing._derive_group_index_key(master, "ceremony_A", "other")
    assert k_base != indexing._derive_group_index_key(b"\x02" * 32, "ceremony_A", "default")
    # Bumping the epoch must produce a fresh key (rotation invalidates
    # the old index).
    assert k_base != indexing._derive_group_index_key(master, "ceremony_A", "default", epoch=1)


def test_token_stable_under_equality():
    master = b"\x01" * 32
    key = indexing._derive_group_index_key(master, "c", "g")
    t1 = indexing._index_token(key, "amount", 100)
    t2 = indexing._index_token(key, "amount", 100)
    assert t1 == t2
    assert t1.startswith("hmac-sha256:v1:")


def test_token_differs_on_value_change():
    master = b"\x01" * 32
    key = indexing._derive_group_index_key(master, "c", "g")
    assert indexing._index_token(key, "amount", 100) != indexing._index_token(key, "amount", 101)


def test_token_differs_on_field_name_change():
    """Field name is bound into the HMAC input, so reassigning the same
    value to a different field produces a different token. This is the
    fix for the pre-existing field-name-not-in-hash bug."""
    master = b"\x01" * 32
    key = indexing._derive_group_index_key(master, "c", "g")
    assert indexing._index_token(key, "amount", 100) != indexing._index_token(key, "tip", 100)


def test_token_differs_across_groups():
    """Two groups under the same ceremony cannot cross-search even when
    both hold the same (field, value) — their derived keys differ."""
    master = b"\x01" * 32
    k_g1 = indexing._derive_group_index_key(master, "c", "g1")
    k_g2 = indexing._derive_group_index_key(master, "c", "g2")
    assert indexing._index_token(k_g1, "amount", 100) != indexing._index_token(k_g2, "amount", 100)


def test_rejects_wrong_sized_master():
    try:
        indexing._derive_group_index_key(b"\x00" * 16, "c", "g")
    except ValueError:
        return
    raise AssertionError("short master key should have raised")


def test_rejects_wrong_sized_group_key():
    try:
        indexing._index_token(b"\x00" * 16, "f", "v")
    except ValueError:
        return
    raise AssertionError("short group key should have raised")


def main() -> int:
    tests = [
        test_derivation_is_deterministic,
        test_derivation_is_scoped_by_ceremony_and_group,
        test_token_stable_under_equality,
        test_token_differs_on_value_change,
        test_token_differs_on_field_name_change,
        test_token_differs_across_groups,
        test_rejects_wrong_sized_master,
        test_rejects_wrong_sized_group_key,
    ]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"all {len(tests)} indexing tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
