"""Exception -> MCP error mapping.

The MCP protocol uses JSON-RPC 2.0 error codes. The reserved range
-32000..-32099 is for application-defined errors. We allocate:

    -32000  TN_VERIFICATION_ERROR  -- secure_read forensic / chain mismatch
    -32001  TN_VERIFY_ERROR        -- lower-level signature/chain failure
    -32006  TN_RUNTIME_ERROR       -- strict-mode + general tn runtime errors
    -32099  TN_UNKNOWN             -- reserved for future tn-specific

The standard JSON-RPC -32603 (Internal error) is used for non-tn
exceptions that escape the tool body.

Note: ``tn.ChainConflict`` is a Union[LeafReuseAttempt, SameCoordinateFork,
RotationConflict] — those are conflict *descriptor* dataclasses, not
exception classes. The cookbook surfaces them as data inside structured
returns from query verbs, never as raised exceptions. So the mapping only
covers what's actually raised: VerificationError, VerifyError, and the
generic RuntimeError.
"""
from __future__ import annotations

import traceback
from typing import Any

import tn


# Canonical mapping. Values are JSON-RPC error codes. Keep the dict
# explicit (no auto-derivation) so additions here force a code review.
TN_ERROR_CODES: dict[str, int] = {
    "VerificationError": -32000,
    "VerifyError": -32001,
    "RuntimeError": -32006,
}

# JSON-RPC standard "Internal error". Used as the fallback for anything
# we don't have a tn-specific code for.
INTERNAL_ERROR_CODE: int = -32603


def map_exception(exc: BaseException) -> tuple[int, str, dict[str, Any]]:
    """Map a Python exception onto an (code, message, data) MCP error triple.

    Returns:
        code: JSON-RPC error code (int).
        message: human-readable; includes the exception's str() unchanged.
        data: structured payload — exception_class, traceback (last frame
            only), plus any tn-specific attributes the exception carried.
    """
    cls_name = type(exc).__name__

    # Look up the tn-specific code. Falls back to INTERNAL_ERROR_CODE if
    # the exception isn't one we recognize.
    code = TN_ERROR_CODES.get(cls_name, INTERNAL_ERROR_CODE)

    message = str(exc) or cls_name

    # Last frame of the traceback is enough for diagnostics; full
    # traceback would balloon the response.
    tb = traceback.extract_tb(exc.__traceback__)
    last_frame = tb[-1] if tb else None
    data: dict[str, Any] = {
        "exception_class": cls_name,
        "traceback_tail": (
            f"{last_frame.filename}:{last_frame.lineno} in {last_frame.name}"
            if last_frame else None
        ),
    }

    # tn.VerificationError carries envelope + invalid_reasons. Surface them.
    if isinstance(exc, tn.VerificationError):
        envelope = getattr(exc, "envelope", None)
        if envelope is not None:
            data["envelope_event_type"] = envelope.get("event_type")
            data["envelope_hash"] = envelope.get("row_hash") or envelope.get("hash")
        invalid_reasons = getattr(exc, "invalid_reasons", None)
        if invalid_reasons:
            data["invalid_reasons"] = list(invalid_reasons)

    # tn.VerifyError carries sequence, event_type, failed_checks. Surface them.
    if isinstance(exc, tn.VerifyError):
        for attr in ("sequence", "event_type", "failed_checks"):
            value = getattr(exc, attr, None)
            if value is not None:
                data[attr] = value

    return code, message, data


__all__ = ["map_exception", "TN_ERROR_CODES", "INTERNAL_ERROR_CODE"]
