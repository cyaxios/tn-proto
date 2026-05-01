"""Real tnproto-org subprocess fixture for persona scenarios.

Spawns the tnproto-org FastAPI app against a per-run test Mongo DB
and a tmp blob dir, waits for health, yields a VaultHandle, tears
down cleanly (kill subprocess, drop DB, rm blobs, save transcript).

Per-scenario isolation: each call gets a unique DB name so tests
don't interfere with each other or with anything in the "real"
`tn_vault` database.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
TNPROTO_ORG = REPO_ROOT / "tnproto-org"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except Exception as e:
            last_err = e
            time.sleep(0.4)
    raise RuntimeError(f"vault did not come up at {url}: {last_err!r}")


@dataclass
class VaultHandle:
    base_url: str
    db_name: str
    blob_dir: Path
    transcript_path: Path
    transcript: list[dict[str, Any]] = field(default_factory=list)

    def _save_transcript(self) -> None:
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with self.transcript_path.open("w", encoding="utf-8") as f:
            for entry in self.transcript:
                f.write(json.dumps(entry, default=str) + "\n")


@contextmanager
def vault_fixture(tmp_root: Path) -> Iterator[VaultHandle]:
    """Spawn tnproto-org, yield a VaultHandle, tear down cleanly.

    Test isolation: each fixture run gets its own Mongo DB name,
    blob dir, JWT secret, and port. Nothing shared between tests.
    """
    if not (TNPROTO_ORG / "src" / "__main__.py").exists():
        raise RuntimeError(f"tnproto-org not found at {TNPROTO_ORG}")

    port = _find_free_port()
    db_name = f"tn_vault_test_{uuid.uuid4().hex[:8]}"
    blob_dir = Path(tmp_root) / "vault_blobs"
    blob_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = Path(tmp_root) / "transcript.jsonl"

    env = {
        **os.environ,
        "VAULT_MONGO_DB": db_name,
        "VAULT_BLOB_DIR": str(blob_dir),
        "VAULT_HOST": "127.0.0.1",
        "VAULT_PORT": str(port),
        "VAULT_JWT_SECRET": "test-" + secrets.token_hex(8),
    }

    proc = subprocess.Popen(
        [sys.executable, "-m", "src"],
        cwd=str(TNPROTO_ORG),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    handle: VaultHandle | None = None
    try:
        _wait_http(f"http://127.0.0.1:{port}/docs", timeout=30.0)
        handle = VaultHandle(
            base_url=f"http://127.0.0.1:{port}",
            db_name=db_name,
            blob_dir=blob_dir,
            transcript_path=transcript_path,
        )
        yield handle
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            from pymongo import MongoClient

            uri = env.get(
                "VAULT_MONGO_URI",
                os.environ.get(
                    "VAULT_MONGO_URI",
                    "mongodb://localhost:27017",
                ),
            )
            MongoClient(uri).drop_database(db_name)
        except Exception:
            pass
        shutil.rmtree(blob_dir, ignore_errors=True)
        if handle is not None and handle.transcript:
            try:
                handle._save_transcript()
            except Exception:
                pass
