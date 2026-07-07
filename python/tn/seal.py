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
from pathlib import Path
from typing import Any

from . import cipher as _cipher
from . import classifier as _classifier
from ._entry import Entry, VerifyError, _json_default
from .canonical import _canonical_bytes
from .chain import _compute_row_hash
from .indexing import _index_token
from .logger import _validate_event_type, current_config
from .reader import _aad_bytes_for, _discover_keybag_ciphers
from .signing import DeviceKey, _signature_b64, _signature_from_b64

_log = logging.getLogger("tn.seal")

#: The nine mandatory envelope scalars. Everything else in a sealed
#: object is either a public field or a group block.
_ENVELOPE_RESERVED = frozenset({
    "device_identity", "timestamp", "event_id", "event_type", "level",
    "sequence", "prev_hash", "row_hash", "signature",
})


class SealedObject(dict):
    """Signed standalone envelope returned by :func:`tn.seal`.

    Behaves as the envelope ``dict``; ``str()`` renders compact wire
    JSON (the same line format the log writes) so the object can be
    written to a file, posted over HTTP, or interpolated into a
    prompt without a serialization step.
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
            if isinstance(v, dict) and "ciphertext" in v:
                # The wire is self-describing: unseal treats any dict value
                # carrying a "ciphertext" key as an encrypted group block,
                # so a public field shaped like that could never round-trip.
                raise ValueError(
                    f"public field {k!r} is a dict containing a 'ciphertext' "
                    f"key; unseal would misread it as an encrypted group "
                    f"block. Rename the inner key or route the field into "
                    f"a group."
                )
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

    # -- index tokens + aad + encrypt (the emit path's token,
    #    aad-bind, and encrypt steps) --
    aad_echo: dict[str, dict[str, Any]] = {}
    group_payloads: dict[str, dict[str, Any]] = {}
    for gname, plain_fields in per_group.items():
        group_cfg = cfg.groups[gname]
        # Sort up front so a sealed envelope's field_hashes ordering is
        # deterministic across builds; the row_hash is unaffected either
        # way because _canonical_bytes sorts keys internally.
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

    # The preimage must commit to what the wire carries: verifiers
    # recompute the row hash from parsed JSON, so hash the public
    # values in their wire rendering (datetime -> ISO string, etc.),
    # not the in-memory Python objects _json_default would still have
    # to convert at str() time.
    public_out = json.loads(json.dumps(public_out, default=_json_default))

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


def unseal(
    source: SealedObject | dict[str, Any] | str | bytes | Path,
    *,
    verify: bool = True,
    raw: bool = False,
    as_recipient: str | Path | None = None,
    group: str = "default",
) -> Entry | dict[str, Any]:
    """Verify a sealed object and open every group block a held key fits.

    No key fitting is not an error: you get the verified public frame
    with the blocks left sealed. ``UnsealError`` is malformed input
    only; ``VerifyError`` is failed verification with ``verify=True``.
    """
    env = _normalize_source(source)

    # group blocks: {gname: {"ciphertext": bytes, "field_hashes": {...}}}
    groups_from_env: dict[str, dict[str, Any]] = {}
    for k, v in env.items():
        if isinstance(v, dict) and "ciphertext" in v:
            try:
                ct = base64.b64decode(v["ciphertext"])
            except Exception as e:  # malformed block = malformed source, re-raised typed
                raise UnsealError(f"group block {k!r} has undecodable ciphertext") from e
            groups_from_env[k] = {
                "ciphertext": ct,
                "field_hashes": v.get("field_hashes", {}),
            }

    valid = {"signature": False, "row_hash": False}
    if verify:
        # Self-describing recompute: every non-reserved, non-group-block
        # key is a public field. (The log reader filters through the
        # local yaml's public_fields — parse_envelope_line — which would
        # make foreign sealed objects unverifiable.)
        public_out = {
            k: v for k, v in env.items()
            if k not in _ENVELOPE_RESERVED and k not in groups_from_env
        }
        expected = _compute_row_hash(
            device_identity=env["device_identity"],
            timestamp=env.get("timestamp", ""),
            event_id=env.get("event_id", ""),
            event_type=env["event_type"],
            level=env.get("level", ""),
            prev_hash=env.get("prev_hash", ""),
            public_fields=public_out,
            groups=groups_from_env,
        )
        valid["row_hash"] = expected == env.get("row_hash", "")
        try:
            valid["signature"] = DeviceKey.verify(
                env["device_identity"],
                env["row_hash"].encode("ascii"),
                _signature_from_b64(env["signature"]),
            )
        except Exception:  # noqa: BLE001 — any failure shape means unverified
            valid["signature"] = False
        failed = [k for k, ok in valid.items() if not ok]
        if failed:
            raise VerifyError(
                sequence=int(env.get("sequence", 0) or 0),
                event_type=env.get("event_type", ""),
                failed_checks=failed,
            )

    plaintext = _decrypt_walk(env, groups_from_env, as_recipient, group)

    triple = {"envelope": env, "plaintext": plaintext, "valid": valid}
    if raw:
        return triple
    # Entry.from_raw copies non-reserved public extras into Entry.fields,
    # which would leak the tn_sealed marker into user fields — and make
    # tn.seal(**entry.fields) trip the reserved-name guard. Drop it from
    # the Entry-bound copy only; the raw triple above stays wire-faithful.
    entry_env = {k: v for k, v in env.items() if k != "tn_sealed"}
    return Entry.from_raw({**triple, "envelope": entry_env})


def _normalize_source(
    source: SealedObject | dict[str, Any] | str | bytes | Path,
) -> dict[str, Any]:
    """Any accepted source shape -> one envelope dict, or UnsealError."""
    if isinstance(source, Path):
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as e:
            raise UnsealError(f"cannot read sealed object file: {e}") from e
        return _parse_envelope_text(text)
    if isinstance(source, (str, bytes)):
        if isinstance(source, bytes):
            try:
                text = source.decode("utf-8")
            except UnicodeDecodeError as e:
                raise UnsealError(f"not a sealed object: invalid utf-8 ({e})") from e
        else:
            text = source
        return _parse_envelope_text(text)
    if isinstance(source, dict):
        return _require_envelope_shape(dict(source))
    raise UnsealError(f"unsupported sealed object source type: {type(source).__name__}")


def _parse_envelope_text(text: str) -> dict[str, Any]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise UnsealError(f"not a sealed object: invalid JSON ({e})") from e
    if not isinstance(obj, dict):
        raise UnsealError("not a sealed object: JSON is not an object")
    return _require_envelope_shape(obj)


def _require_envelope_shape(env: dict[str, Any]) -> dict[str, Any]:
    # seal always writes all nine envelope scalars; require the ones the
    # rest of unseal dereferences unconditionally (Entry.from_raw needs
    # timestamp/event_id/sequence even with verify=False) so malformed
    # input surfaces as UnsealError, never a bare KeyError.
    required = (
        "device_identity", "event_type", "row_hash", "signature",
        "timestamp", "event_id", "sequence",
    )
    missing = [k for k in required if k not in env]
    if missing:
        raise UnsealError(f"not a sealed object: missing {', '.join(missing)}")
    return env


def _load_recipient_candidates(keystore_dir: Path, group: str) -> list[Any]:
    """Every cipher candidate for ``group`` in ``keystore_dir``, btn first.

    Mirrors read_as_recipient's candidate loading: the keystore can hold
    keys for the SAME group name under several ciphers at once, and the
    envelope doesn't say which cipher sealed it, so the caller tries each
    candidate and keeps the first that opens.
    """
    btn_kit = keystore_dir / f"{group}.btn.mykit"
    jwe_key = keystore_dir / f"{group}.jwe.mykey"
    hibe_key = keystore_dir / f"{group}.hibe.sk"
    ciphers: list[Any] = []
    if btn_kit.exists():
        ciphers.append(_cipher.BtnGroupCipher.load(keystore_dir, group))
    if jwe_key.exists():
        ciphers.append(_cipher.JWEGroupCipher.load(keystore_dir, group))
    if hibe_key.exists():
        ciphers.append(_cipher.HibeGroupCipher.load(keystore_dir, group))
    if not ciphers:
        raise FileNotFoundError(
            f"unseal: no recipient key found for group={group!r} in "
            f"{keystore_dir}. Looked for {btn_kit.name} (btn), "
            f"{jwe_key.name} (jwe), and {hibe_key.name} (hibe). If you "
            f"absorbed a kit_bundle, the kit lands in your ceremony's "
            f"keystore — point as_recipient there."
        )
    return ciphers


def _decrypt_walk(
    env: dict[str, Any],
    groups_from_env: dict[str, dict[str, Any]],
    as_recipient: str | Path | None,
    group: str,
) -> dict[str, dict[str, Any]]:
    """Try every candidate key per group; first fit wins, failures skip.

    The default keybag walk (reader._discover_keybag_ciphers) holds one
    cipher per group and skips hibe kits, unlike the as_recipient
    candidate loading — known inherited reader behavior; the fix belongs
    in the reader later.
    """
    plaintext: dict[str, dict[str, Any]] = {}

    def _try(gname: str, cipher_obj: Any) -> bool:
        ct = groups_from_env[gname]["ciphertext"]
        try:
            pt = cipher_obj.decrypt(ct, _aad_bytes_for(env, gname))
            plaintext[gname] = json.loads(pt.decode("utf-8"))
            return True
        except Exception:  # noqa: BLE001 — a non-fitting key must not abort the walk
            return False

    if as_recipient is not None:
        # single-kit override: load every cipher candidate for `group`
        # from that directory and decrypt only `group`. Nothing to open
        # means nothing to load — return before touching the keystore.
        if group not in groups_from_env:
            return plaintext
        for cipher_obj in _load_recipient_candidates(Path(as_recipient), group):
            if _try(group, cipher_obj):
                break
        return plaintext

    try:
        cfg = current_config()
    except RuntimeError:
        cfg = None

    if cfg is not None:
        # pass 1: own-ceremony group ciphers (publisher side)
        for gname in groups_from_env:
            gcfg = cfg.groups.get(gname)
            if gcfg is not None:
                _try(gname, gcfg.cipher)
        # pass 2: keystore key-bag (own kits + everything absorbed)
        bag = _discover_keybag_ciphers(Path(cfg.keystore))
        for gname in groups_from_env:
            if gname in plaintext:
                continue
            cipher_obj = bag.get(gname)
            if cipher_obj is not None:
                _try(gname, cipher_obj)
    return plaintext


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
