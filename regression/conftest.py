"""pytest plugin for the TN regression suite.

Provides:

- `--silo-report=<path>` CLI flag (Makefile passes this). Writes a
  structured JSON report at session end summarising every named
  assertion that ran.
- Per-test context: each test invocation sets the silo + test id on
  the `assertions` recorder so failure messages know where they are.

This file is auto-discovered by pytest because it lives at
`regression/_shared/conftest.py` — every pytest invocation that runs
under `regression/` picks it up.

Convention: every test in `regression/crawl/*/` should derive its silo
name from its parent directory. E.g. tests under
`regression/crawl/c7_key_custody_default/` get `silo=c7` automatically.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the regression package importable from inside tests
# (`from regression._shared.assertions import assert_named`).
_REGRESSION_ROOT = Path(__file__).resolve().parent.parent  # regression/
_REPO_ROOT = _REGRESSION_ROOT.parent                       # tn_proto/

# Insert at position 0 so we win over any conflicting installed package.
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Lazy import — avoid pulling assertions module at plugin load time if
# the rest of pytest hasn't initialized yet.
from regression._shared import assertions as _assertions  # noqa: E402


# ---------------------------------------------------------------------------
# CLI option
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--silo-report",
        action="store",
        default=None,
        help=(
            "Write a structured JSON report of every named assertion to this "
            "path at session end. Set by the regression Makefile; "
            "manual invocation can omit it."
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_silo(nodeid: str) -> str:
    """Pull the silo id out of a pytest nodeid.

    Examples:
        "regression/crawl/c7_key_custody_default/test_foo.py::test_bar"
            → "c7"
        "regression/walk/w3_recipient_flow/test_baz.py::test_qux"
            → "w3"
        "test_orphan.py::test_no_silo"
            → "unknown-silo"
    """
    parts = Path(nodeid.split("::")[0]).parts
    for part in parts:
        if len(part) >= 2 and part[0] in {"c", "w"} and part[1].isdigit():
            # Take just the numeric prefix segment (`c7_*` → `c7`).
            return part.split("_", 1)[0]
    return "unknown-silo"


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Reset the assertion recorder at session start so the report
    only reflects this run's assertions."""
    # `config` is unused but the pytest hook spec requires it.
    del config
    _assertions.reset_records()


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Stamp silo + test id onto the assertion recorder before each
    test runs. Failure messages and the JSON report will reference
    these values."""
    silo = _infer_silo(item.nodeid)
    _assertions.set_test_context(silo=silo, test=item.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write the structured report at session end if --silo-report
    was passed."""
    report_path = session.config.getoption("--silo-report")
    if not report_path:
        return

    # Infer silo from the first collected test if we have any.
    silo = "unknown-silo"
    if session.items:
        silo = _infer_silo(session.items[0].nodeid)

    _assertions.write_report(
        Path(report_path),
        silo=silo,
        exit_code=int(exitstatus),
    )
