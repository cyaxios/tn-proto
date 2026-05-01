"""Generate the Python-produced cross-language byte-compare fixtures
for the new ``tn.read()`` flat shape, ``tn.secure_read()`` output, and
``tn.agents`` group pre-encryption canonical bytes.

Spec: ``docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md``
section 5.4 (cross-language byte-identity).

Two fixtures are emitted:

    secure_read_canonical.json
        Canonical JSON of ``flatten_raw_entry(...) + attach_instructions(...)``
        applied to the canonical scenario raw entries. This is the dict shape
        ``tn.secure_read()`` hands to the LLM. The same on-disk envelope +
        plaintext input must produce byte-identical canonical-JSON output
        across Python / Rust / TS.

    tn_agents_pre_encryption.json
        Canonical bytes (RFC 8785-style sorted-keys / no-whitespace) of the
        six-field policy splice payload for ``payment.completed``. This is
        the cipher's input — random AEAD nonces make the post-encryption
        ciphertext diverge per row, but the canonical PRE-encryption bytes
        (what gets passed to ``cipher.encrypt(...)``) must agree across
        languages, byte for byte.

Run with the project venv:

    .venv/Scripts/python.exe \\
        tn-protocol/python/tests/fixtures/build_secure_read_fixtures.py

The fixtures are byte-deterministic: re-running on any platform produces
the same bytes. They are committed; consumer tests in Rust + TS load this
file and assert their locally-produced output is byte-identical.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parents[1]
sys.path.insert(0, str(PYDIR))

from tn._agents_policy import parse_policy_text
from tn.canonical import _canonical_bytes
from tn.reader import flatten_raw_entry

# --------------------------------------------------------------------------
# Canonical scenario inputs (mirrored byte-for-byte in the Rust + TS
# builders). Edit here = edit there.
# --------------------------------------------------------------------------

CANONICAL_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
CANONICAL_POLICY_PATH = ".tn/config/agents.md"
CANONICAL_POLICY_TEXT = """\
# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting on amount and currency.

### do_not_use_for
Credit decisions, loan underwriting, risk scoring.

### consequences
customer_id is PII; exposure violates GDPR.

### on_violation_or_error
POST https://merchant.example.com/controls/escalate
"""

# Two raw entries, hand-constructed with deterministic envelope values so
# the output is independent of clock + RNG. Group payloads use a literal
# placeholder ``ciphertext`` byte so ``flatten_raw_entry`` recognizes them
# as group blocks (the actual bytes don't matter for the projection — the
# pre-encryption canonical bytes assert is a separate fixture).
ORDER_CREATED_RAW = {
    "envelope": {
        "did": CANONICAL_DID,
        "timestamp": "2026-04-25T18:32:18.000000Z",
        "event_id": "01HXYZ0000000000000000ORD1",
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": "sha256:" + "1" * 64,
        "signature": "AAAA",
        # Public field beyond envelope basics.
        "request_id": "req_abc",
        # Two group payloads in the on-disk envelope. Caller holds the
        # ``default`` kit but NOT the ``pii`` kit, so ``pii`` lands in
        # ``_hidden_groups``.
        "default": {"ciphertext": "ZGVmYXVsdA==", "field_hashes": {}},
        "pii": {"ciphertext": "cGlp", "field_hashes": {}},
    },
    "plaintext": {
        # Caller decrypted ``default`` only.
        "default": {
            "order_id": "ord_2026_q2_a47b9",
            "amount": 4999,
            "currency": "USD",
        },
    },
    "valid": {"signature": True, "row_hash": True, "chain": True},
}

PAYMENT_COMPLETED_RAW = {
    "envelope": {
        "did": CANONICAL_DID,
        "timestamp": "2026-04-25T18:33:42.000000Z",
        "event_id": "01HXYZ0000000000000000PAY1",
        "event_type": "payment.completed",
        "level": "info",
        "sequence": 2,
        "prev_hash": "sha256:" + "1" * 64,
        "row_hash": "sha256:" + "2" * 64,
        "signature": "BBBB",
        "default": {"ciphertext": "ZGVmYXVsdA==", "field_hashes": {}},
        "tn.agents": {"ciphertext": "YWdlbnRz", "field_hashes": {}},
    },
    "plaintext": {
        "default": {
            "order_id": "ord_2026_q2_a47b9",
            "amount": 4999,
            "currency": "USD",
        },
        # The ``tn.agents`` plaintext as the cipher would have decrypted it.
        # Six fields, exactly the policy splice for ``payment.completed``.
        "tn.agents": {
            "instruction": "This row records a completed payment.",
            "use_for": "Aggregate reporting on amount and currency.",
            "do_not_use_for": "Credit decisions, loan underwriting, risk scoring.",
            "consequences": "customer_id is PII; exposure violates GDPR.",
            "on_violation_or_error": "POST https://merchant.example.com/controls/escalate",
            "policy": ".tn/config/agents.md#payment.completed@1#sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
        },
    },
    "valid": {"signature": True, "row_hash": True, "chain": True},
}


def _attach_instructions(flat: dict, raw: dict) -> None:
    """Mirror of ``tn.__init__._attach_instructions`` — kept duplicated here
    so the builder doesn't depend on ``tn.init()`` side effects.

    Lifts the six tn.agents fields from ``raw['plaintext']['tn.agents']``
    into a typed ``instructions`` block on ``flat``, and removes those
    field names from the flat top level.
    """
    plaintext = raw.get("plaintext") or {}
    body = plaintext.get("tn.agents")
    if not isinstance(body, dict):
        return
    if body.get("$no_read_key") is True or body.get("$decrypt_error") is True:
        return
    instructions: dict = {}
    for f in (
        "instruction",
        "use_for",
        "do_not_use_for",
        "consequences",
        "on_violation_or_error",
        "policy",
    ):
        if f in body:
            instructions[f] = body[f]
        flat.pop(f, None)
    if instructions:
        flat["instructions"] = instructions


def build_secure_read_canonical() -> dict:
    """Project both raw entries through the secure_read pipeline and return
    a top-level dict ``{order_created, payment_completed}`` for the fixture.
    """
    order = flatten_raw_entry(ORDER_CREATED_RAW, include_valid=False)
    _attach_instructions(order, ORDER_CREATED_RAW)
    payment = flatten_raw_entry(PAYMENT_COMPLETED_RAW, include_valid=False)
    _attach_instructions(payment, PAYMENT_COMPLETED_RAW)
    return {
        "order_created": order,
        "payment_completed": payment,
    }


# --------------------------------------------------------------------------
# Canonical scenarios per admin event_type. Each entry is the exact dict the
# emit-side runtime would feed to ``_canonical_bytes(...)`` for the event's
# row_hash. Values are intentionally fully populated (no nulls) so the
# canonical encoding exercises every shape the catalog accepts. Edits here
# are mirrored byte-for-byte in the Rust + TS builders.
# --------------------------------------------------------------------------

ADMIN_EVENT_SCENARIOS: dict[str, dict] = {
    "tn.ceremony.init": {
        "ceremony_id": "cer_byte_compare_canonical_2026",
        "cipher": "btn",
        "device_did": CANONICAL_DID,
        "created_at": "2026-04-25T18:00:00.000000Z",
    },
    "tn.group.added": {
        "group": "default",
        "cipher": "btn",
        "publisher_did": CANONICAL_DID,
        "added_at": "2026-04-25T18:00:01.000000Z",
    },
    "tn.recipient.added": {
        "group": "default",
        "leaf_index": 7,
        "recipient_did": "did:key:zRecipientCanonical",
        "kit_sha256": "sha256:" + "a" * 64,
        "cipher": "btn",
    },
    "tn.recipient.revoked": {
        "group": "default",
        "leaf_index": 7,
        "recipient_did": "did:key:zRecipientCanonical",
    },
    "tn.coupon.issued": {
        "group": "default",
        "slot": 3,
        "to_did": "did:key:zCouponHolder",
        "issued_to": "did:key:zCouponHolder",
    },
    "tn.rotation.completed": {
        "group": "default",
        "cipher": "btn",
        "generation": 2,
        "previous_kit_sha256": "sha256:" + "b" * 64,
        "old_pool_size": 12,
        "new_pool_size": 24,
        "rotated_at": "2026-04-25T18:00:02.000000Z",
    },
    "tn.enrolment.compiled": {
        "group": "default",
        "peer_did": "did:key:zPeerEnrolment",
        "package_sha256": "sha256:" + "c" * 64,
        "compiled_at": "2026-04-25T18:00:03.000000Z",
    },
    "tn.enrolment.absorbed": {
        "group": "default",
        "from_did": "did:key:zSenderEnrolment",
        "package_sha256": "sha256:" + "c" * 64,
        "absorbed_at": "2026-04-25T18:00:04.000000Z",
    },
    "tn.vault.linked": {
        "vault_did": "did:web:vault.example",
        "project_id": "proj_byte_compare",
        "linked_at": "2026-04-25T18:00:05.000000Z",
    },
    "tn.vault.unlinked": {
        "vault_did": "did:web:vault.example",
        "project_id": "proj_byte_compare",
        "reason": "operator_initiated",
        "unlinked_at": "2026-04-25T18:00:06.000000Z",
    },
    "tn.agents.policy_published": {
        "policy_uri": CANONICAL_POLICY_PATH,
        "version": "1",
        "content_hash": "sha256:79e0aefecfce8b26d2ea3be0026effee96c9c7aaa8f189d0236fa555eabbb36e",
        "event_types_covered": [
            "order.created",
            "payment.completed",
            "tn.recipient.added",
        ],
        "policy_text": CANONICAL_POLICY_TEXT,
    },
    "tn.read.tampered_row_skipped": {
        "envelope_event_id": "01HXYZ0000000000000000PAY1",
        "envelope_did": CANONICAL_DID,
        "envelope_event_type": "payment.completed",
        "envelope_sequence": 2,
    },
}


def build_admin_events_canonical() -> dict:
    """Compute canonical bytes for the canonical-scenario fields of every
    admin event_type in the catalog.

    Output shape::

        {
            "<event_type>": {
                "fields": {...},
                "canonical_bytes_hex": "...",
                "canonical_bytes_len": <int>,
            },
            ...
        }

    The ``fields`` dict is the exact emit-time payload feeds to
    ``_canonical_bytes(...)``; the hex is what every SDK must produce
    byte-for-byte. Adding an event_type here pins the shape across all
    three SDKs and would have caught the 2026-04-25 e2e splice gap on
    the protocol-spec side rather than the integration-test side.
    """
    out: dict = {}
    for event_type, fields in ADMIN_EVENT_SCENARIOS.items():
        cb = _canonical_bytes(fields)
        out[event_type] = {
            "fields": fields,
            "canonical_bytes_hex": cb.hex(),
            "canonical_bytes_len": len(cb),
        }
    return out


def build_tn_agents_pre_encryption() -> dict:
    """Compute the canonical pre-encryption bytes for the ``tn.agents``
    group's payload on the canonical ``payment.completed`` event.

    The runtime computes ``_canonical_bytes(plain_fields)`` and feeds the
    result to ``cipher.encrypt(...)``. Random AEAD nonces make the
    ciphertext diverge per row; the input bytes are deterministic and must
    agree across all three SDKs.
    """
    doc = parse_policy_text(CANONICAL_POLICY_TEXT, CANONICAL_POLICY_PATH)
    template = doc.templates["payment.completed"]
    splice = {
        "instruction": template.instruction,
        "use_for": template.use_for,
        "do_not_use_for": template.do_not_use_for,
        "consequences": template.consequences,
        "on_violation_or_error": template.on_violation_or_error,
        "policy": (
            f"{template.path}#{template.event_type}"
            f"@{template.version}#{template.content_hash}"
        ),
    }
    cb = _canonical_bytes(splice)
    return {
        "splice_dict": splice,
        "canonical_bytes_hex": cb.hex(),
        "canonical_bytes_len": len(cb),
        "policy_content_hash": doc.content_hash,
    }


def _write_canonical_json(path: Path, obj: dict) -> int:
    """Write ``obj`` to ``path`` as canonical JSON (sorted keys, compact
    separators, UTF-8). Returns the byte count.

    This is the wire form the byte-compare assertion compares — so all
    three languages must use the same encoding.
    """
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    raw = text.encode("utf-8")
    path.write_bytes(raw)
    return len(raw)


def main() -> None:
    secure = build_secure_read_canonical()
    sec_path = HERE / "secure_read_canonical.json"
    nbytes = _write_canonical_json(sec_path, secure)
    print(f"wrote {sec_path} ({nbytes} bytes)")

    pre = build_tn_agents_pre_encryption()
    pre_path = HERE / "tn_agents_pre_encryption.json"
    nbytes = _write_canonical_json(pre_path, pre)
    print(f"wrote {pre_path} ({nbytes} bytes)")

    admin = build_admin_events_canonical()
    admin_path = HERE / "admin_events_canonical.json"
    nbytes = _write_canonical_json(admin_path, admin)
    print(f"wrote {admin_path} ({nbytes} bytes)")


if __name__ == "__main__":
    main()
