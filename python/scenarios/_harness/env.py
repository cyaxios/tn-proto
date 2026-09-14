"""Load optional scenario credentials from the repository's .env file."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ENV_PATH = Path(__file__).resolve().parents[3] / ".env"


def load_repo_env() -> None:
    """Populate os.environ from the repository's .env file, when present.

    Uses setdefault: pre-existing env vars win.
    """
    if not REPO_ENV_PATH.is_file():
        return
    for raw in REPO_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


def get_optional(name: str) -> str | None:
    """Return env var value or None; empty strings also return None."""
    return os.environ.get(name) or None
