"""Named-assertion sidecar for the TN regression suite.

Every check in a regression test MUST go through `assert_named()` (or
`LogQuery.assert_contains()` for TN-native log queries). The point is:

- **No bare `assert x == y`** — every check has a name, an expected
  value, an observed value, and a pointer to "where to look" on miss.
- **Identical failure shape** across Python, TS, and Playwright silos
  so a maintainer reading a report doesn't have to context-switch.
- **Recorded into the silo's structured report** at
  `.reports/<silo>/last.json` so CI can surface named failures as
  artifacts.

See `_shared/README.md` for the contract + examples.
"""
from __future__ import annotations

import dataclasses
import json
import sys
import threading
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Report shape — identical between Python and TS silos so consumers
# (CI artifact viewer, future dashboards) can treat them uniformly.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AssertionRecord:
    """One named assertion's outcome. Serialized to JSON."""

    name: str
    style: str  # "named" | "log-query"
    passed: bool
    expected: str
    observed: str
    on_miss: str  # only meaningful when passed=False
    silo: str
    test: str  # `<file>::<function>` for pytest, similar for TS

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# In-process recorder — pytest's conftest writes this out at session end
# ---------------------------------------------------------------------------


_RECORDER_LOCK = threading.Lock()
_RECORDS: list[AssertionRecord] = []
_CURRENT_SILO: str | None = None
_CURRENT_TEST: str | None = None


def set_test_context(*, silo: str, test: str) -> None:
    """Called from the pytest hook at the start of each test."""
    global _CURRENT_SILO, _CURRENT_TEST
    _CURRENT_SILO = silo
    _CURRENT_TEST = test


def _resolve_silo() -> str:
    if _CURRENT_SILO:
        return _CURRENT_SILO
    # Fallback: infer from cwd. Useful for ad-hoc invocations.
    cwd = Path.cwd().resolve()
    for part in cwd.parts:
        if part.startswith(("c", "w")) and len(part) >= 2 and part[1].isdigit():
            return part
    return "unknown-silo"


def _resolve_test() -> str:
    if _CURRENT_TEST:
        return _CURRENT_TEST
    # Try to identify a test function from the call stack.
    import inspect

    for frame_info in inspect.stack():
        fn = frame_info.function
        if fn.startswith("test_"):
            return f"{Path(frame_info.filename).name}::{fn}"
    return "unknown-test"


def _record(rec: AssertionRecord) -> None:
    with _RECORDER_LOCK:
        _RECORDS.append(rec)


def collected_records() -> list[dict[str, Any]]:
    """Conftest pulls this at session-finish to write the JSON report."""
    with _RECORDER_LOCK:
        return [r.to_dict() for r in _RECORDS]


def reset_records() -> None:
    """Test helper. Don't call in production tests."""
    global _RECORDS, _CURRENT_SILO, _CURRENT_TEST
    with _RECORDER_LOCK:
        _RECORDS = []
        _CURRENT_SILO = None
        _CURRENT_TEST = None


# ---------------------------------------------------------------------------
# The two assertion verbs
# ---------------------------------------------------------------------------


class NamedAssertionError(AssertionError):
    """Raised when a named assertion fails. The message is the full
    formatted failure block; pytest will print it as the test
    failure reason."""


def _format_failure(
    *,
    name: str,
    style: str,
    expected: Any,
    observed: Any,
    on_miss: str,
    silo: str,
    test: str,
) -> str:
    """One canonical failure format. Used by both styles. Identical
    shape on TS side via `assertions.ts`."""
    return (
        f"ASSERTION FAILED: {name}\n"
        f"  silo: {silo}\n"
        f"  test: {test}\n"
        f"  style: {style}\n"
        f"  expected: {expected!r}\n"
        f"  observed: {observed!r}\n"
        f"  look at: {on_miss}"
    )


def assert_named(
    *,
    name: str,
    expected: Any,
    observed: Any,
    on_miss: str,
    predicate: Callable[[Any, Any], bool] | None = None,
) -> None:
    """Style-2 named assertion. Use whenever the check is not against
    a TN envelope — HTTP responses, Mongo rows, DOM state, file
    existence, etc.

    Args:
        name: short kebab-case identifier; appears in failure output
            and in the JSON report. Must be unique within a test.
        expected: the value (or shape) you're looking for. Free-form;
            printed via `repr()` on miss.
        observed: the value actually observed. Same.
        on_miss: human-readable pointer to "where to look" on failure.
            **Must include a file:line or symbol reference.** Bad:
            "didn't work." Good: "expected row in pending_claims for
            vault_id={vid}; check routes_pending_claims.py:50 (insert
            path) and Mongo TTL index."
        predicate: optional custom equality. Default is `==`. Useful
            for fuzzy comparisons (subset-match, regex-match, …).

    Raises:
        NamedAssertionError: if the predicate returns False. The error
            message is the full formatted failure block.
    """
    silo = _resolve_silo()
    test = _resolve_test()

    if predicate is None:
        passed = expected == observed
    else:
        passed = bool(predicate(expected, observed))

    rec = AssertionRecord(
        name=name,
        style="named",
        passed=passed,
        expected=repr(expected),
        observed=repr(observed),
        on_miss=on_miss,
        silo=silo,
        test=test,
    )
    _record(rec)

    if not passed:
        raise NamedAssertionError(
            _format_failure(
                name=name,
                style="named",
                expected=expected,
                observed=observed,
                on_miss=on_miss,
                silo=silo,
                test=test,
            )
        )


def assert_named_match(
    *,
    name: str,
    pattern: str,
    observed: str,
    on_miss: str,
) -> None:
    """Convenience wrapper for regex-pattern assertions. Same contract
    as `assert_named` but uses `re.search`."""
    import re

    def _match(expected: str, actual: str) -> bool:
        return re.search(expected, actual) is not None

    assert_named(
        name=name,
        expected=pattern,
        observed=observed,
        on_miss=on_miss,
        predicate=_match,
    )


# ---------------------------------------------------------------------------
# Report writer — called by conftest at session end
# ---------------------------------------------------------------------------


def write_report(report_path: Path, *, silo: str, exit_code: int) -> None:
    """Write the silo's structured report to `report_path`. Called by
    the pytest hook in `_shared/conftest.py`.

    Schema:
        {
            "silo": str,
            "passed": bool,           # all assertions passed AND pytest exit 0
            "exit_code": int,
            "assertions": [
                AssertionRecord.to_dict(),
                ...
            ],
            "tests_with_failures": [...],   # convenience: test ids
        }
    """
    records = collected_records()
    all_passed = all(r["passed"] for r in records) and exit_code == 0
    failed_tests = sorted({r["test"] for r in records if not r["passed"]})

    report = {
        "silo": silo,
        "passed": all_passed,
        "exit_code": exit_code,
        "assertions": records,
        "tests_with_failures": failed_tests,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI: `python -m regression._shared.assertions <report-path>` prints
# a human-readable summary. Useful when poking around `.reports/`.
# ---------------------------------------------------------------------------


def _print_summary(report_path: Path) -> int:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"no report at {report_path}", file=sys.stderr)
        return 2

    status = "PASS" if report["passed"] else "FAIL"
    print(f"[{status}] silo={report['silo']} exit={report['exit_code']}")
    print(f"  assertions: {len(report['assertions'])}")
    fails = [r for r in report["assertions"] if not r["passed"]]
    if fails:
        print(f"  failed assertions: {len(fails)}")
        for f in fails:
            print(f"    - {f['name']} ({f['test']})")
            print(f"      look at: {f['on_miss']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m regression._shared.assertions <report.json>")
        sys.exit(2)
    sys.exit(_print_summary(Path(sys.argv[1])))
