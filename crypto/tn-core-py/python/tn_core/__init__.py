"""tn_core — Rust-backed TN runtime.

Import is via maturin as the `_core` extension. This file re-exports the
PyO3-generated classes so `from tn_core import Runtime` works.
"""
# The `_core` extension is produced by maturin and isn't visible to static
# type checkers without a built artifact — suppress the import-resolution
# warning and the "unused re-export" false positive.
from tn_core._core import Runtime  # type: ignore[import-not-found]  # noqa: F401
from tn_core._core import admin  # type: ignore[import-not-found]  # noqa: F401

# Register the submodule so that `import tn_core.admin` and
# `from tn_core.admin import reduce` resolve to the same object as
# `tn_core.admin.kinds()`.  PyO3 only populates attribute access; the
# Python import machinery needs an explicit sys.modules entry.
import sys as _sys
_sys.modules.setdefault("tn_core.admin", admin)

__all__ = ["Runtime", "admin"]
