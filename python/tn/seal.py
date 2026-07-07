"""tn.seal / tn.unseal — portable sealed objects.

A sealed object is a standalone envelope: the same on-wire schema the
emit path writes, built and returned instead of appended to the log.
``seal`` routes fields into groups per the yaml and encrypts each
group; ``unseal`` verifies the envelope and opens every group block
the keys at hand can decrypt, walking own-ceremony ciphers first and
then every kit in the keystore.

Standalone conventions: ``sequence`` is 0, ``prev_hash`` is "", and
the reserved public field ``tn_sealed`` is 1 (a number, so the
row-hash preimage's str(value) renders identically across SDK
implementations). Sealing never touches the ceremony's chain state.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from . import cipher as _cipher
from . import classifier as _classifier
from ._entry import _json_default
from .canonical import _canonical_bytes
from .chain import _compute_row_hash
from .indexing import _index_token
from .logger import _validate_event_type, current_config
from .signing import _signature_b64

_log = logging.getLogger("tn.seal")

#: The nine mandatory envelope scalars. Everything else in a sealed
#: object is either a public field or a group block.
_ENVELOPE_RESERVED = frozenset({
    "device_identity", "timestamp", "event_id", "event_type", "level",
    "sequence", "prev_hash", "row_hash", "signature",
})


class SealedObject(dict):
    """Signed standalone envelope returned by :func:`tn.seal`.

    Behaves as the envelope ``dict``; ``str()`` renders canonical
    JSON so the object can be written to a file, posted over HTTP,
    or interpolated into a prompt without a serialization step.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return json.dumps(self, separators=(",", ":"), default=_json_default)


class UnsealError(RuntimeError):
    """Raised when unseal input is not a sealed-object envelope at all.

    Having no key that fits is NOT this error — that returns the
    public frame with the blocks left sealed.
    """


def seal(
    object_type: str,
    *,
    receipt: bool = True,
    aad: dict[str, Any] | None = None,
    **fields: Any,
) -> SealedObject:
    """Seal fields into a portable attested object (standalone envelope)."""
    _validate_event_type(object_type)
    if "tn_sealed" in fields:
        raise ValueError(
            "tn_sealed is a reserved sealed-object marker; rename the field"
        )
    cfg = current_config()

    # Same wire coercion the emit path applies before dispatch
    # (bytes -> $b64, Decimal -> str, datetime -> ISO). Deferred import:
    # tn/__init__.py imports this module during package init.
    from . import _coerce_for_wire
    merged = _coerce_for_wire(dict(fields))

    # -- classify public vs group buckets (mirrors logger.py's
    #    _emit_locked classification, minus the context merge) --
    public_keys = set(cfg.public_fields)
    public_out: dict[str, Any] = {}
    per_group: dict[str, dict[str, Any]] = {}
    for k, v in merged.items():
        if k in public_keys:
            public_out[k] = v
            continue
        gnames = cfg.field_to_groups.get(k)
        if not gnames:
            guess = _classifier._classify(k, v, list(cfg.groups))
            if guess in cfg.groups:
                gnames = [guess]
            elif "default" in cfg.groups:
                gnames = ["default"]
            else:
                raise ValueError(
                    f"field {k!r} has no group route and is not in "
                    f"public_fields. Add it to `groups[<g>].fields` in "
                    f"tn.yaml, list it under public_fields, or define a "
                    f"`default` group to absorb unknowns."
                )
        for gname in gnames:
            if gname not in cfg.groups:
                raise ValueError(
                    f"field {k!r} routed to unknown group {gname!r} "
                    f"(known groups: {sorted(cfg.groups)})"
                )
            per_group.setdefault(gname, {})[k] = v

    # -- index tokens + aad + encrypt (mirrors the emit path's
    #    per-group sort, token, aad-bind, and encrypt steps) --
    aad_echo: dict[str, dict[str, Any]] = {}
    group_payloads: dict[str, dict[str, Any]] = {}
    for gname, plain_fields in per_group.items():
        group_cfg = cfg.groups[gname]
        plain_fields = dict(sorted(plain_fields.items()))
        field_hashes = {
            fname: _index_token(group_cfg.index_key, fname, fval)
            for fname, fval in plain_fields.items()
        }
        effective_aad = {**group_cfg.aad_default, **(aad or {})}
        aad_bytes = _canonical_bytes(effective_aad) if effective_aad else b""
        plaintext_bytes = _canonical_bytes(plain_fields)
        try:
            ct_bytes = group_cfg.cipher.encrypt(plaintext_bytes, aad_bytes)
        except _cipher.NotAPublisherError as e:
            _log.warning("skipping group %r for %s: %s", gname, object_type, e)
            continue
        group_payloads[gname] = {
            "ciphertext": ct_bytes,
            "field_hashes": field_hashes,
        }
        if effective_aad:
            aad_echo[gname] = effective_aad

    if aad_echo:
        public_out["tn_aad"] = _canonical_bytes(aad_echo).decode("utf-8")
    # Detachment marker — a number so str(value) in the row-hash
    # preimage renders identically in every SDK implementation.
    public_out["tn_sealed"] = 1

    # -- standalone identity + hash + sign (mirrors the emit path's
    #    hash/sign steps, with sequence=0 / prev_hash="" and NO chain
    #    advance) --
    timestamp = (
        datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    event_id = str(uuid.uuid4())
    row_hash = _compute_row_hash(
        device_identity=cfg.device.device_identity,
        timestamp=timestamp,
        event_id=event_id,
        event_type=object_type,
        level="",
        prev_hash="",
        public_fields=public_out,
        groups=group_payloads,
    )
    sig = cfg.device.sign(row_hash.encode("ascii"))

    envelope: dict[str, Any] = {
        "device_identity": cfg.device.device_identity,
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": object_type,
        "level": "",
        "sequence": 0,
        "prev_hash": "",
        "row_hash": row_hash,
        "signature": _signature_b64(sig),
    }
    for k, v in public_out.items():
        envelope.setdefault(k, v)
    for gname, g in group_payloads.items():
        envelope[gname] = {
            "ciphertext": base64.b64encode(g["ciphertext"]).decode("ascii"),
            "field_hashes": g["field_hashes"],
        }

    if receipt:
        _emit_receipt(envelope, object_type, sorted(group_payloads))

    return SealedObject(envelope)


def _emit_receipt(envelope: dict[str, Any], object_type: str, groups: list[str]) -> None:
    """Chain one ordinary log row attesting the seal act.

    Same internal-event pattern as tn.enrolment.compiled
    (compile.py:80-95), but errors PROPAGATE: the caller asked for a
    receipt, so a silently missing one would break the guarantee.
    """
    from . import logger as _lg  # deferred: package init order
    _lg._require_init().emit(
        "info",
        "tn.object.sealed",
        {
            "object_id": envelope["row_hash"],
            "object_type": object_type,
            "groups": groups,
        },
    )
