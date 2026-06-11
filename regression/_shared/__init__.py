"""Shared utilities for every regression silo. See `_shared/README.md`."""

from regression._shared.assertions import (
    AssertionRecord,
    NamedAssertionError,
    assert_named,
    assert_named_match,
    collected_records,
    reset_records,
    set_test_context,
    write_report,
)

__all__ = [
    "AssertionRecord",
    "NamedAssertionError",
    "assert_named",
    "assert_named_match",
    "collected_records",
    "reset_records",
    "set_test_context",
    "write_report",
]
