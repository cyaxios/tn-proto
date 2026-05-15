"""Boot a real tn_proto_web vault subprocess for hermetic silo tests.

Two silos need a live vault: C7 (key custody — init-time backup-link
flow) and C8 (restore on new machine). Both go end-to-end through the
real wire format: a real HTTP POST to `/api/v1/pending-claims`, a real
dev-auth bearer JWT, a real GET that returns the encrypted .tnpkg bytes,
and real `decrypt_body_blob(...)` against the BEK pulled from the URL
fragment. No mocks below the HTTP boundary — that's the whole point of
the silo.

What this module owns:

* `vault_server` fixture (session-scoped): spawns `python -m src` from
  `tn_proto_web/` on a free port with `TN_DEV_AUTH_BYPASS=1`, an
  ephemeral mongo DB, an ephemeral blob dir, and a unique
  `VAULT_JWT_SECRET`. Yields a `VaultServer` dataclass with the base URL
  and metadata the silo's helpers need. Teardown kills the subprocess
  and drops the test DB so we don't accumulate junk in mongo across
  runs.

* Skip-conditions: if `tn_proto_web/` isn't found, or mongo isn't
  reachable, the fixture pytest.skip's with a clear message. CI's c7/c8
  jobs run mongo as a service, so they always satisfy the skip. Locally
  a developer needs mongo running on `localhost:27017` (or
  `$VAULT_MONGO_URI`).

Why subprocess + real mongo and not in-process ASGI + mongomock-motor:
the SDK's `tn.init(link=True)` triggers an INIT-UPLOAD POST from a
thread inside the runtime, not from the test thread. In-process ASGI
plus mongomock would require monkey-patching every place the SDK uses
`requests` to instead hit the in-memory app, and that's the kind of
plumbing that hides real wire bugs. Subprocess + real HTTP is the same
shape a user's machine sees.

Lift note: mirrors the pattern from
`tn_proto_web/tests/e2e/conftest.py:vault_server` but drops the
publisher-mirror logic (silos C7/C8 don't need vault_state/publishers/).
"""
from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------
#
# regression/ lives under tn_proto/. tn_proto_web/ is a SIBLING of
# tn_proto/ under content_platform/'s parent dir (the C:\codex\tn root).
# Walk up to find it, since the absolute path differs per developer.

_REGRESSION_DIR = Path(__file__).resolve().parent.parent  # regression/
_TN_PROTO = _REGRESSION_DIR.parent  # tn_proto/
_TN_ROOT = _TN_PROTO.parent  # C:\codex\tn or whatever
_TN_PROTO_WEB = _TN_ROOT / "tn_proto_web"


def _resolve_vault_python() -> str:
    """Pick the python interpreter to spawn `python -m src` with.

    Order of preference:
      1. `$TN_VAULT_PYTHON` env var (explicit override for CI / odd setups).
      2. `tn_proto_web/.venv/Scripts/python.exe` or `.venv/bin/python`
         (per-OS Windows / posix layouts).
      3. `tn_proto_web/.venv-041a0check/...` (the current local checkpoint
         venv; tn_proto_web doesn't always have a plain `.venv`).
      4. `sys.executable` — only correct on CI where pip install ran in
         the same env that satisfies tn_proto_web's deps.

    Returns the absolute path as a string (subprocess.Popen accepts both).
    """
    override = os.environ.get("TN_VAULT_PYTHON")
    if override and Path(override).exists():
        return override

    candidates = [
        _TN_PROTO_WEB / ".venv" / "Scripts" / "python.exe",
        _TN_PROTO_WEB / ".venv" / "bin" / "python",
        _TN_PROTO_WEB / ".venv-041a0check" / "Scripts" / "python.exe",
        _TN_PROTO_WEB / ".venv-041a0check" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return sys.executable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Bind to port 0 and return the assigned port. Race window is small
    (kernel reserves the port until we close the socket); subprocess
    boots within seconds so a parallel binder is unlikely."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 45.0) -> None:
    """Poll an HTTP URL until it returns a non-5xx response (or timeout).

    The vault's `/docs` endpoint comes up after the FastAPI app has
    finished its startup hooks (mongo connection, etc.), so we use it as
    the readiness signal.
    """
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.5)
    raise RuntimeError(f"vault did not come up at {url}: {last_err!r}")


def _mongo_reachable(uri: str, timeout_ms: int = 1500) -> bool:
    """Best-effort connectivity check against the configured mongo URI.

    Returns True if the server responds to an `ismaster` (or
    equivalent) ping within `timeout_ms`. Caller pytest.skip's on False.
    """
    try:
        from pymongo import MongoClient  # type: ignore[import-not-found]

        client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        try:
            client.admin.command("ping")
            return True
        finally:
            client.close()
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Server dataclass + fixture
# ---------------------------------------------------------------------------


@dataclass
class VaultServer:
    """Handle returned to tests by the `vault_server` fixture.

    Attributes:
      base_url: e.g. "http://127.0.0.1:54123" (ephemeral) or
        "http://127.0.0.1:8790" (live). Used as `TN_VAULT_URL`.
      db_name: name of the ephemeral mongo DB; "<live>" when running
        against an already-running vault we don't own.
      blob_dir: directory where pending-claim ciphertexts are stored;
        meaningless ("<live>") when running against a live vault.
      jwt_secret: the `VAULT_JWT_SECRET` env passed to the subprocess.
        "<unknown>" in live-vault mode — we don't need to mint tokens
        manually because dev-auth login produces them.
      mode: "ephemeral" (subprocess we spawned + dropped) or "live"
        (an already-running vault on a port we did not bind). Tests
        and cleanup paths branch on this.
    """
    base_url: str
    db_name: str
    blob_dir: Path
    jwt_secret: str
    mode: str = "ephemeral"

    @property
    def is_live(self) -> bool:
        return self.mode == "live"


@pytest.fixture(scope="session")
def vault_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[VaultServer]:
    """Provide a vault for the session. Two modes:

    1. **Live mode (default)**: point at the already-running vault at
       `$TN_VAULT_URL` (defaults to `http://127.0.0.1:8790`). The
       fixture does NOT spawn a subprocess, does NOT touch the mongo
       DB on teardown, and trusts the developer that the live vault
       has `TN_DEV_AUTH_BYPASS=1` enabled. Tests that create
       pending_claims register them with the `vault_cleanup` fixture so
       they DELETE on test exit — the live DB stays at the same count
       before and after a run.

       Tests that DON'T want to talk to the vault (C1's module-level
       logging, for instance) simply leave `TN_NO_LINK=1` in place
       (the hermetic_machine fixture's default) and / or skip the
       vault handler in their yaml. No vault contact happens.

    2. **Ephemeral mode** (`TN_REGRESSION_USE_EPHEMERAL_VAULT=1`):
       spawn a fresh tn_proto_web subprocess against an ephemeral
       mongo DB + ephemeral blob dir. Teardown drops both. This mode
       is for CI runners that don't already have a vault running. Not
       used locally — see live mode above.

    Skips with a clear message if neither mode can satisfy:
      - Live mode (default): live vault must respond on `<base_url>/docs`.
        Start it with `python -m src` from tn_proto_web/ (env
        `TN_DEV_AUTH_BYPASS=1`).
      - Ephemeral mode: tn_proto_web/ must exist as a sibling of
        tn_proto/, and mongo must be reachable at $VAULT_MONGO_URI.
    """
    use_ephemeral = os.environ.get("TN_REGRESSION_USE_EPHEMERAL_VAULT") == "1"

    # ── Live mode (default) ─────────────────────────────────────────
    if not use_ephemeral:
        live_url = os.environ.get("TN_VAULT_URL", "http://127.0.0.1:8790")
        try:
            _wait_http(f"{live_url}/docs", timeout=5.0)
        except RuntimeError as exc:
            pytest.skip(
                f"Live vault at {live_url} not responding: {exc}. "
                f"Start it with `python -m src` from tn_proto_web/ "
                f"(env TN_DEV_AUTH_BYPASS=1) or set "
                f"TN_REGRESSION_USE_EPHEMERAL_VAULT=1 to spawn a "
                f"throwaway subprocess for this session."
            )
        yield VaultServer(
            base_url=live_url,
            db_name="<live>",
            blob_dir=Path("<live>"),
            jwt_secret="<unknown>",
            mode="live",
        )
        return  # no teardown — we don't own the live vault

    # ── Ephemeral mode (opt-in via TN_REGRESSION_USE_EPHEMERAL_VAULT=1) ─
    if not (_TN_PROTO_WEB / "src" / "__main__.py").exists():
        pytest.skip(
            f"tn_proto_web subprocess entry not found at "
            f"{_TN_PROTO_WEB / 'src' / '__main__.py'}. "
            f"This silo needs the vault repo as a sibling of tn_proto/."
        )

    mongo_uri = os.environ.get("VAULT_MONGO_URI", "mongodb://localhost:27017")
    if not _mongo_reachable(mongo_uri):
        pytest.skip(
            f"mongo not reachable at {mongo_uri}. This silo needs a live "
            f"mongo (run via `docker run -d -p 27017:27017 mongo:7` or "
            f"point $VAULT_MONGO_URI elsewhere). CI provides it as a "
            f"service."
        )

    port = _find_free_port()
    db_name = f"tn_vault_regression_{uuid.uuid4().hex[:8]}"
    blob_dir = tmp_path_factory.mktemp("vault_blobs")
    jwt_secret = "regression-" + secrets.token_hex(8)

    env = {
        **os.environ,
        "VAULT_MONGO_URI": mongo_uri,
        "VAULT_MONGO_DB": db_name,
        "VAULT_BLOB_DIR": str(blob_dir),
        "VAULT_HOST": "127.0.0.1",
        "VAULT_PORT": str(port),
        "VAULT_JWT_SECRET": jwt_secret,
        # Dev-auth bypass mounts /api/v1/dev/login. That's the ONE
        # automated encryption-exercising auth path (per the crawl
        # rule). Other paths (OAuth, WebAuthn, passphrase, mnemonic)
        # are covered via Playwright (walk tier) or manual scripts.
        "TN_DEV_AUTH_BYPASS": "1",
        # Bump caps so silos can create multiple ceremonies / kits
        # without hitting tier walls inherited from the parent env.
        "VAULT_MAX_PROJECTS": "20",
        "VAULT_MAX_FILES": "200",
        # Mute the FastAPI banner that drowns out test output.
        "PYTHONUNBUFFERED": "1",
    }

    vault_python = _resolve_vault_python()
    proc = subprocess.Popen(
        [vault_python, "-m", "src"],
        cwd=str(_TN_PROTO_WEB),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{port}"
    server = VaultServer(
        base_url=base_url,
        db_name=db_name,
        blob_dir=blob_dir,
        jwt_secret=jwt_secret,
    )

    try:
        _wait_http(f"{base_url}/docs", timeout=45.0)
        yield server
    finally:
        # Kill subprocess first so it isn't holding file handles.
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

        # Drop the ephemeral test DB so we don't accumulate state across
        # runs. Best-effort: if mongo went down between fixture start
        # and teardown we just leak the DB; the next run picks a fresh
        # uuid suffix anyway.
        try:
            from pymongo import MongoClient  # type: ignore[import-not-found]

            MongoClient(mongo_uri).drop_database(db_name)
        except Exception:  # noqa: BLE001
            pass

        shutil.rmtree(blob_dir, ignore_errors=True)
