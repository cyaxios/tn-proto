"""tn.* exceptions map cleanly onto MCP error codes.

The cookbook exposes only two raisable exception classes:
    - tn.VerificationError(*, envelope, invalid_reasons)
    - tn.VerifyError(sequence, event_type, failed_checks)

Other names that appear in tn.__all__ — ChainConflict (Union),
SameCoordinateFork, RotationConflict, LeafReuseAttempt — are conflict
descriptor dataclasses, not exceptions. The mapping covers what's
actually raised; the conflict shapes ride inside structured data, not
inside raised exceptions.
"""
from __future__ import annotations

import pytest  # noqa: F401  -- pytest is the runner; import for parity

import tn
from tn.mcp.errors import map_exception, TN_ERROR_CODES, INTERNAL_ERROR_CODE


def test_map_verification_error():
    """tn.VerificationError -> code -32000, with envelope details in data."""
    exc = tn.VerificationError(
        envelope={"event_type": "order.created", "row_hash": "h1"},
        invalid_reasons=["bad_signature"],
    )
    code, message, data = map_exception(exc)
    assert code == TN_ERROR_CODES["VerificationError"]
    assert "bad_signature" in message or "verification" in message.lower()
    assert data["exception_class"] == "VerificationError"
    # envelope details surfaced
    assert data["envelope_event_type"] == "order.created"
    assert data["envelope_hash"] == "h1"
    assert data["invalid_reasons"] == ["bad_signature"]


def test_map_verify_error():
    """tn.VerifyError -> code -32001."""
    exc = tn.VerifyError(sequence=42, event_type="payment.charged", failed_checks=["chain"])
    code, _, data = map_exception(exc)
    assert code == TN_ERROR_CODES["VerifyError"]
    assert data["exception_class"] == "VerifyError"


def test_map_runtime_error_to_runtime_code():
    """A RuntimeError (e.g. from strict-mode auto-init) maps to -32006."""
    exc = RuntimeError(
        "tn.info() called without prior tn.init(); set TN_STRICT=0 or call tn_init."
    )
    code, message, data = map_exception(exc)
    assert code == TN_ERROR_CODES["RuntimeError"]
    assert "tn_init" in message
    assert data["exception_class"] == "RuntimeError"


def test_map_unknown_exception_is_internal():
    """Unrecognized exceptions get the JSON-RPC INTERNAL code (-32603)."""
    exc = ValueError("oops")
    code, message, data = map_exception(exc)
    assert code == INTERNAL_ERROR_CODE
    assert "oops" in message
    assert data["exception_class"] == "ValueError"


def test_traceback_tail_present_on_real_exception():
    """When an exception has a traceback, the last frame is captured."""
    try:
        raise ValueError("inner")
    except ValueError as e:
        _, _, data = map_exception(e)
        assert data["traceback_tail"] is not None
        assert "test_errors.py" in data["traceback_tail"]


def test_traceback_tail_none_when_no_frame():
    """An exception without traceback (constructed but not raised) gets None."""
    exc = ValueError("never raised")
    _, _, data = map_exception(exc)
    assert data["traceback_tail"] is None
