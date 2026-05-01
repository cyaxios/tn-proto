"""Load credentials from repo-root .env.

Reuses the path-candidates pattern from tests/test_kafka_live_confluent.py.
Never raises on missing file — scenarios that depend on a specific var
skip gracefully.
"""

from __future__ import annotations

import os
from pathlib import Path

CANDIDATE_ENV_PATHS = [
    Path("C:/codex/content_platform/.env"),
    Path("/mnt/c/codex/content_platform/.env"),
    Path(__file__).resolve().parents[4] / ".env",
]


def load_repo_env() -> None:
    """Populate os.environ from the first .env file that exists.

    Uses setdefault: pre-existing env vars win.
    """
    for p in CANDIDATE_ENV_PATHS:
        if not p.is_file():
            continue
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)
        return


def get_optional(name: str) -> str | None:
    """Return env var value or None; empty strings also return None."""
    return os.environ.get(name) or None
