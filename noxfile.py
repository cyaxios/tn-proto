"""Cross-platform build orchestration for tn-proto.

Mirrors the Makefile targets so contributors on Windows (without
make on PATH) get the same workflow as Linux/macOS users. Nox is the
Python ecosystem's standard task runner — same role as tox/just for
their respective communities.

Standard tooling, repeatable across machines:

  - ``maturin``  builds the Rust+PyO3 wheels (tn-core, tn-btn).
  - ``python -m build``  builds the pure-Python wheel + sdist.
  - ``twine check``  validates wheel metadata before upload.
  - ``twine upload``  publishes to TestPyPI / PyPI.

Output goes to ``./dist/`` (the Python packaging convention;
gitignored).

Common workflows::

  nox -s build          # build all three wheels into ./dist
  nox -s build_core     # subset
  nox -s build_btn      # subset
  nox -s build_protocol # subset
  nox -s clean          # rm ./dist and ./target/wheels
  nox -s check          # twine check on every wheel in ./dist
  nox -s test_install   # fresh venv + pip install + smoke import
  nox -s verify_version # check tn-protocol version isn't already on TestPyPI
  nox -s publish_test   # upload to TestPyPI
  nox -s publish        # upload to real PyPI (prompts for confirmation)
  nox -s tools          # install maturin + build + twine into the active env

Override the Python interpreter used::

  nox -s build -p 3.12

Dependencies:

  pip install nox  # one-time, then ``nox -s tools`` installs the rest
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

import nox  # type: ignore[import-not-found]

REPO_ROOT = Path(__file__).resolve().parent
DIST = REPO_ROOT / "dist"

TN_CORE_DIR = REPO_ROOT / "crypto" / "tn-core-py"
TN_BTN_DIR = REPO_ROOT / "crypto" / "tn-btn-py"
PY_DIR = REPO_ROOT / "python"

# Tools the build/publish targets assume are installed in the active
# nox session interpreter. ``nox -s tools`` installs them.
BUILD_TOOLS = ("maturin", "build", "twine")

# Don't auto-create a venv per session — these targets run against the
# active interpreter so contributors don't pay for venv creation on
# every invocation. ``test_install`` does its own venv internally.
nox.options.default_venv_backend = "none"
nox.options.sessions = ["build"]


def _ensure_dist() -> None:
    DIST.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Build sessions
# ---------------------------------------------------------------------------


@nox.session
def build_core(session: nox.Session) -> None:
    """Build the tn-core Rust+PyO3 wheel into ./dist."""
    _ensure_dist()
    session.log("Building tn-core (Rust + PyO3 via maturin)")
    session.chdir(TN_CORE_DIR)
    session.run(
        sys.executable,
        "-m",
        "maturin",
        "build",
        "--release",
        "--out",
        str(DIST),
        external=True,
    )


@nox.session
def build_btn(session: nox.Session) -> None:
    """Build the tn-btn Rust+PyO3 wheel into ./dist."""
    _ensure_dist()
    session.log("Building tn-btn (Rust + PyO3 via maturin)")
    session.chdir(TN_BTN_DIR)
    session.run(
        sys.executable,
        "-m",
        "maturin",
        "build",
        "--release",
        "--out",
        str(DIST),
        external=True,
    )


@nox.session
def build_protocol(session: nox.Session) -> None:
    """Build the tn-protocol pure-Python wheel + sdist into ./dist."""
    _ensure_dist()
    session.log("Building tn-protocol (pure Python via build)")
    session.chdir(PY_DIR)
    session.run(
        sys.executable, "-m", "build", "--outdir", str(DIST), external=True
    )


@nox.session
def build(session: nox.Session) -> None:
    """Build all three wheels (tn-core, tn-btn, tn-protocol)."""
    session.notify("build_core")
    session.notify("build_btn")
    session.notify("build_protocol")


# ---------------------------------------------------------------------------
# Hygiene + verification
# ---------------------------------------------------------------------------


@nox.session
def clean(session: nox.Session) -> None:
    """Remove ./dist and ./target/wheels."""
    for d in (DIST, REPO_ROOT / "target" / "wheels"):
        if d.exists():
            session.log(f"Removing {d}")
            shutil.rmtree(d)


@nox.session
def check(session: nox.Session) -> None:
    """Run ``twine check`` over every wheel in ./dist."""
    if not DIST.exists():
        session.error(f"{DIST} does not exist; run ``nox -s build`` first.")
    files = [str(p) for p in DIST.iterdir() if p.is_file()]
    if not files:
        session.error(f"{DIST} is empty; run ``nox -s build`` first.")
    session.run(
        sys.executable, "-m", "twine", "check", *files, external=True
    )


@nox.session
def test_install(session: nox.Session) -> None:
    """Build, then pip-install the wheels in a fresh venv and smoke-import.

    Catches "wheel built but unusable" cases before they reach
    TestPyPI. The venv lives at ``.venv-test/`` and is removed on
    success.
    """
    if not DIST.exists() or not any(DIST.iterdir()):
        session.error(
            f"{DIST} is empty; run ``nox -s build`` first."
        )
    venv_dir = REPO_ROOT / ".venv-test"
    if venv_dir.exists():
        shutil.rmtree(venv_dir)
    session.log(f"Creating fresh venv at {venv_dir}")
    session.run(sys.executable, "-m", "venv", str(venv_dir), external=True)
    if os.name == "nt":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"
    session.log("Installing wheels into venv")
    session.run(
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--upgrade",
        "pip",
        "--quiet",
        external=True,
    )
    session.run(
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--find-links",
        str(DIST),
        "tn-protocol",
        "--quiet",
        external=True,
    )
    session.log("Smoke import")
    session.run(
        str(venv_python),
        "-c",
        (
            "import tn, tn_core, tn_btn; "
            "print('smoke OK:', tn.__name__, '+', tn_core.__name__, '+', tn_btn.__name__)"
        ),
        external=True,
    )
    shutil.rmtree(venv_dir)
    session.log("test_install passed.")


# ---------------------------------------------------------------------------
# Publish targets
# ---------------------------------------------------------------------------


def _local_protocol_version() -> str:
    """Read tn-protocol's version from ``python/pyproject.toml``."""
    try:
        import tomllib  # py3.11+
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]
    with (PY_DIR / "pyproject.toml").open("rb") as fh:
        doc = tomllib.load(fh)
    return str(doc["project"]["version"])


@nox.session
def verify_version(session: nox.Session) -> None:
    """Pre-flight: ensure tn-protocol's local version isn't already on TestPyPI.

    Bumps to existing versions get rejected by PyPI; this catches
    the common "forgot to bump" case before tagging or uploading.
    """
    version = _local_protocol_version()
    session.log(f"Local tn-protocol version: {version}")
    url = f"https://test.pypi.org/pypi/tn-protocol/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            if resp.status == 200:
                json.load(resp)  # parse to confirm it's a real package page
                session.error(
                    f"Version {version} is already on TestPyPI. "
                    "Bump python/pyproject.toml before publishing."
                )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            session.log(f"OK — {version} is unused on TestPyPI.")
            return
        session.error(f"Could not check TestPyPI ({exc.code}): {exc.reason}")
    except Exception as exc:  # noqa: BLE001
        session.error(f"Could not check TestPyPI: {exc}")


@nox.session
def publish_test(session: nox.Session) -> None:
    """Upload ./dist to TestPyPI.

    Set ``TWINE_USERNAME=__token__`` and ``TWINE_PASSWORD=<test-token>``
    in your environment, or twine will prompt interactively.
    """
    session.notify("check")
    session.notify("verify_version")
    files = [str(p) for p in DIST.iterdir() if p.is_file()]
    session.log(f"Uploading {len(files)} files from {DIST} to TestPyPI")
    session.run(
        sys.executable,
        "-m",
        "twine",
        "upload",
        "--repository",
        "testpypi",
        *files,
        external=True,
    )


@nox.session
def publish(session: nox.Session) -> None:
    """Upload ./dist to real PyPI. Prompts for confirmation."""
    session.notify("check")
    answer = input("About to publish to real PyPI. Type 'yes' to continue: ")
    if answer.strip().lower() != "yes":
        session.error("Aborted.")
    files = [str(p) for p in DIST.iterdir() if p.is_file()]
    session.log(f"Uploading {len(files)} files from {DIST} to PyPI")
    session.run(
        sys.executable, "-m", "twine", "upload", *files, external=True
    )


# ---------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------


@nox.session
def tools(session: nox.Session) -> None:
    """Install maturin + build + twine into the active interpreter."""
    session.log(
        f"Installing build/publish tooling into {sys.executable}"
    )
    session.run(
        sys.executable, "-m", "pip", "install", "--upgrade", "pip", external=True
    )
    session.run(
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        *BUILD_TOOLS,
        external=True,
    )
