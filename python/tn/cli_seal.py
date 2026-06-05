"""`tn seal` — attest one envelope per stdin JSON line.

The Python counterpart of the TypeScript ``tn-js seal`` subcommand
(``ts-sdk/bin/tn-js.mjs`` ``sealCmd``). It reads one JSON object per
stdin line and writes one attested envelope ndjson line per input.

Each input line has the shape::

    {
      "seed_b64": "<base64 32 bytes>",
      "event_type": "order.created",
      "level": "info",
      "sequence": 1,
      "prev_hash": "sha256:...",
      "timestamp": "2026-04-23T12:00:00Z",
      "event_id": "uuid-v4",
      "public_fields": { "amount": 100 }
    }

This is the public-only seal path (no btn/JWE group encryption) so the
wire bytes interop byte-for-byte with ``tn-js seal``: same row_hash
preimage (:func:`tn.chain._compute_row_hash`), same Ed25519 signature
over the row_hash (:class:`tn.signing.DeviceKey`), same compact-ndjson
envelope key order. Crypto + canonicalisation are reused from the SDK,
never reimplemented here.

Module entry point: ``python -m tn.cli seal`` once wired into the
top-level parser. The verb function mirrors the ``cmd_*`` shape of
``tn/cli.py``.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Any, NoReturn

from .chain import _compute_row_hash
from .signing import DeviceKey, _signature_b64

#: Fields every seal input line MUST carry. Mirrors the TS ``required``
#: list in ``sealCmd`` (``public_fields`` is optional, defaults to {}).
_REQUIRED = (
    "seed_b64",
    "event_type",
    "level",
    "sequence",
    "prev_hash",
    "timestamp",
    "event_id",
)


def _die(msg: str) -> NoReturn:
    """Print an error to stderr and exit 2.

    Mirrors the TS ``die`` helper (``tn-js: <msg>``, exit code 2) used
    by ``sealCmd`` for malformed stdin and missing fields.
    """
    print(f"tn seal: {msg}", file=sys.stderr)
    sys.exit(2)


def _seal_line(inp: dict[str, Any]) -> str:
    """Build one attested envelope ndjson line from a parsed input dict.

    Mirrors the body of the TS ``sealCmd`` per-line handler: validate
    required fields, derive the device key from the seed, compute the
    row_hash over the public fields, sign it, and render the envelope.
    """
    for k in _REQUIRED:
        if k not in inp:
            _die(f"missing field {k}")

    seed = base64.b64decode(inp["seed_b64"])
    dk = DeviceKey.from_private_bytes(seed)

    public_fields = inp.get("public_fields") or {}

    row_hash = _compute_row_hash(
        device_identity=dk.device_identity,
        timestamp=inp["timestamp"],
        event_id=inp["event_id"],
        event_type=inp["event_type"],
        level=inp["level"],
        prev_hash=inp["prev_hash"],
        public_fields=public_fields,
        groups={},
    )

    sig = dk.sign(row_hash.encode("utf-8"))

    # Envelope key order matches build_envelope (crypto/tn-core) and the
    # Python logger: the 9 mandatory scalars first, then public fields in
    # insertion order, skipping any that collide with a mandatory key.
    envelope: dict[str, Any] = {
        "device_identity": dk.device_identity,
        "timestamp": inp["timestamp"],
        "event_id": inp["event_id"],
        "event_type": inp["event_type"],
        "level": inp["level"],
        "sequence": inp["sequence"],
        "prev_hash": inp["prev_hash"],
        "row_hash": row_hash,
        "signature": _signature_b64(sig),
    }
    for k, v in public_fields.items():
        envelope.setdefault(k, v)

    return json.dumps(envelope, separators=(",", ":")) + "\n"


def cmd_seal(args: argparse.Namespace) -> int:
    """Read seal-input JSON line(s) from stdin; emit envelope ndjson.

    Mirrors the TS ``sealCmd`` stdin->stdout contract: skip blank
    lines, parse one JSON object per line (``die`` on invalid JSON),
    and write one envelope ndjson line per input to stdout. Returns 0
    on success; ``_die`` exits 2 on any malformed input.
    """
    del args  # No flags; the contract is pure stdin -> stdout.
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            inp = json.loads(line)
        except json.JSONDecodeError as e:
            _die(f"invalid JSON on stdin: {e}")
        sys.stdout.write(_seal_line(inp))
    return 0
