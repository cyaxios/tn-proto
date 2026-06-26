"""Single source of truth for 'cache the AWK?'. ON by default; opt out with
cache_key=False or TN_NO_KEY_CACHE=1 (env wins). Mirrors link/TN_NO_LINK."""
from __future__ import annotations
import os


def should_cache_key(cache_key: bool | None) -> bool:
    if os.environ.get("TN_NO_KEY_CACHE", "").strip() == "1":
        return False
    if cache_key is False:
        return False
    return True


__all__ = ["should_cache_key"]
