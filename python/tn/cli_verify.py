"""``tn verify`` — validate envelope ndjson read from stdin.

Python mirror of the TypeScript ``tn-js verify`` subcommand
(``ts-sdk/bin/tn-js.mjs`` ``verifyCmd``). It reads one envelope JSON
object per line from stdin and writes one result line per input to
stdout:

    {"ok": true,  "did": ..., "event_type": ..., "event_id": ...,
     "row_hash": ..., "sequence": ...}
    {"ok": false, "reason": "...", "event_id": ...}

This is the public-only verify path: it recomputes ``row_hash`` from
the envelope's public fields, checks it against the stored value, and
verifies the Ed25519 signature over the ``row_hash``. Encrypted group
payloads are rejected (``public-only verify``) rather than decrypted —
identical to the TS contract.

No crypto is reimplemented here: ``row_hash`` recomputation reuses
``tn.chain._compute_row_hash`` and signature verification reuses
``tn.signing.DeviceKey.verify`` / ``_signature_from_b64`` — the same
primitives the ``tn.read`` verification path uses.

Mirrors the cmd_* shape in ``tn/cli.py``: ``cmd_verify(args)`` returns
an ``int`` exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .chain import _compute_row_hash
from .signing import DeviceKey, _signature_from_b64

# The mandatory envelope scalars (Python wire naming). The TS verify
# path destructures `did`; the Python on-the-wire field is
# `device_identity` (see tn/reader.py), so we key on that and surface it
# as `did` in the result to match the TS output shape.
_REQUIRED = (
    "device_identity",
    "timestamp",
    "event_id",
    "event_type",
    "level",
    "sequence",
    "prev_hash",
    "row_hash",
    "signature",
)

# Envelope keys that are NOT public fields — handled by the row-hash
# layout directly, so they must not leak into the public-field map.
_ENVELOPE_RESERVED = frozenset(_REQUIRED)


def _emit(result: dict[str, Any]) -> None:
    """Write one compact result line to stdout."""
    sys.stdout.write(json.dumps(result) + "\n")


def _verify_envelope(env: dict[str, Any]) -> dict[str, Any]:
    """Verify a single decoded envelope; return its result dict.

    Mirrors the per-envelope checks in the TS ``verifyCmd``: required
    fields present, no encrypted group payloads, ``row_hash`` matches a
    fresh recompute, and the Ed25519 signature verifies.
    """
    event_id = env.get("event_id")

    # 1. Required scalar fields must all be present.
    for key in _REQUIRED:
        if env.get(key) is None:
            return {"ok": False, "reason": f"missing {key}", "event_id": event_id}

    # 2. Anything left over is either a public field or a group payload.
    #    A group payload (dict carrying `ciphertext`) is not handled on
    #    the public-only verify path.
    public_fields: dict[str, Any] = {}
    for key, value in env.items():
        if key in _ENVELOPE_RESERVED:
            continue
        if isinstance(value, dict) and "ciphertext" in value:
            return {
                "ok": False,
                "reason": f"group payload {key} present; public-only verify",
                "event_id": event_id,
            }
        public_fields[key] = value

    # 3. Recompute row_hash from the public-only envelope and compare.
    recomputed = _compute_row_hash(
        device_identity=env["device_identity"],
        timestamp=env["timestamp"],
        event_id=env["event_id"],
        event_type=env["event_type"],
        level=env["level"],
        prev_hash=env["prev_hash"],
        public_fields=public_fields,
        groups={},
    )
    if recomputed != env["row_hash"]:
        return {
            "ok": False,
            "reason": "row_hash mismatch",
            "expected": recomputed,
            "got": env["row_hash"],
            "event_id": event_id,
        }

    # 4. Verify the Ed25519 signature over the row_hash bytes.
    sig_ok = DeviceKey.verify(
        env["device_identity"],
        env["row_hash"].encode("ascii"),
        _signature_from_b64(env["signature"]),
    )
    if not sig_ok:
        return {"ok": False, "reason": "bad signature", "event_id": event_id}

    return {
        "ok": True,
        "did": env["device_identity"],
        "event_type": env["event_type"],
        "event_id": event_id,
        "row_hash": env["row_hash"],
        "sequence": env["sequence"],
    }


def cmd_verify(args: argparse.Namespace) -> int:
    """Read envelope ndjson from stdin; write one result line per input.

    Returns 0 once stdin is drained (per-envelope failures are reported
    inline, exactly like the TS contract). Invalid JSON on a stdin line
    is fatal: it prints to stderr and exits 2, mirroring the TS
    ``die`` path.
    """
    stream = getattr(args, "stdin", None) or sys.stdin
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            env = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"tn: error: invalid JSON on stdin: {e}", file=sys.stderr)
            return 2
        try:
            _emit(_verify_envelope(env))
        except Exception as e:  # noqa: BLE001 — mirror TS catch-all per envelope
            _emit({"ok": False, "reason": f"exception: {e}"})
    return 0
