"""Generate cross-implementation golden fixtures for tn-core.

Run from repo root:
    .venv/Scripts/python.exe tn-protocol/python/tools/generate_rust_fixtures.py

Outputs to tn-protocol/crypto/tn-core/tests/fixtures/*.json

Never hand-edit the output files. If an output changes, regenerate and commit
both the script change and the new fixtures in the same commit, with a commit
message that explains why the format changed.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# Allow imports from tn-protocol/python without install
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # tn-protocol/python
sys.path.insert(0, str(ROOT))

from tn.canonical import canonical_bytes
from tn.chain import ZERO_HASH, compute_row_hash
from tn.indexing import derive_group_index_key, index_token
from tn.signing import DeviceKey, signature_b64

FIX_DIR = HERE.parent.parent / "crypto" / "tn-core" / "tests" / "fixtures"
FIX_DIR.mkdir(parents=True, exist_ok=True)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _hex(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Fixture 1: canonical_bytes
# ---------------------------------------------------------------------------


def gen_canonical() -> None:
    """Each case: input_json (JSON-representable) + expected_output_hex.

    For the bytes-wrapping case we store a sentinel ``{"$b64": "..."}``
    value directly in ``input_json``.  The Rust side must reproduce this
    wrapping via a helper ``wrap_bytes(&[u8])`` that serialises bytes as
    ``{"$b64":"<base64>"}`` in canonical order — identical to what Python's
    ``canonical_bytes`` does.
    """
    cases = [
        {"name": "empty_object", "input": {}},
        {"name": "single_string", "input": {"a": "hello"}},
        {"name": "nested_sort", "input": {"b": 1, "a": {"z": 2, "y": 1}}},
        {"name": "utf8_unicode", "input": {"name": "café ☕"}},
        {
            "name": "bytes_wrap_via_sentinel",
            # Python canonical_bytes wraps bytes as {"$b64": "AAEC"}.
            # The dict below *is* that wrapped form; passing it directly
            # produces the same bytes as passing bytes([0, 1, 2]) wrapped
            # inside a parent dict.
            "input": {"k": {"$b64": "AAEC"}},
            "rust_builder_hint": "wrap_bytes(&[0u8, 1, 2])",
        },
        {"name": "list_of_mixed", "input": {"xs": [1, "two", None, True, 3.5]}},
        {"name": "bool_and_null", "input": {"a": True, "b": False, "c": None}},
    ]

    out = []
    for c in cases:
        bytes_out = canonical_bytes(c["input"])
        entry: dict = {
            "name": c["name"],
            "input_json": c["input"],
            "output_hex": _hex(bytes_out),
            "output_str": bytes_out.decode("utf-8", errors="replace"),
        }
        if "rust_builder_hint" in c:
            entry["rust_builder_hint"] = c["rust_builder_hint"]
        out.append(entry)

    (FIX_DIR / "canonical_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  canonical_vectors.json  ({len(out)} cases)")


# ---------------------------------------------------------------------------
# Fixture 2: compute_row_hash
# ---------------------------------------------------------------------------


def gen_row_hash() -> None:
    cases = [
        {
            "name": "empty_public_empty_groups",
            "did": "did:key:zABC",
            "timestamp": "2026-04-21T12:00:00.000000Z",
            "event_id": "00000000-0000-0000-0000-000000000001",
            "event_type": "order.created",
            "level": "info",
            "prev_hash": ZERO_HASH,
            "public_fields": {},
            "groups": {},
        },
        {
            "name": "with_public_and_one_group",
            "did": "did:key:zXYZ",
            "timestamp": "2026-04-21T12:00:01.000000Z",
            "event_id": "00000000-0000-0000-0000-000000000002",
            "event_type": "order.paid",
            "level": "info",
            "prev_hash": "sha256:" + "ab" * 32,
            "public_fields": {"method": "POST", "path": "/x"},
            "groups": {
                "default": {
                    "ciphertext": bytes(range(32)),
                    "field_hashes": {
                        "amount": "hmac-sha256:v1:" + "cd" * 32,
                        "currency": "hmac-sha256:v1:" + "ef" * 32,
                    },
                }
            },
        },
    ]

    out = []
    for c in cases:
        rh = compute_row_hash(
            did=c["did"],
            timestamp=c["timestamp"],
            event_id=c["event_id"],
            event_type=c["event_type"],
            level=c["level"],
            prev_hash=c["prev_hash"],
            public_fields=c["public_fields"],
            groups=c["groups"],
        )
        out.append(
            {
                "name": c["name"],
                "inputs": {
                    **{k: v for k, v in c.items() if k not in ("name", "groups")},
                    "groups": {
                        gn: {
                            "ciphertext_hex": _hex(g["ciphertext"]),
                            "field_hashes": g["field_hashes"],
                        }
                        for gn, g in c["groups"].items()
                    },
                },
                "expected_row_hash": rh,
            }
        )

    (FIX_DIR / "row_hash_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  row_hash_vectors.json   ({len(out)} cases)")


# ---------------------------------------------------------------------------
# Fixture 3: index tokens
# ---------------------------------------------------------------------------


def gen_index_tokens() -> None:
    master = bytes(range(32))
    cases = [
        {"ceremony": "cer_a", "group": "default", "epoch": 0, "field": "amount", "value": 123},
        {"ceremony": "cer_a", "group": "default", "epoch": 0, "field": "note", "value": "hello"},
        {
            "ceremony": "cer_a",
            "group": "billing",
            "epoch": 7,
            "field": "card_last4",
            "value": "4242",
        },
        {
            "ceremony": "cer_b",
            "group": "default",
            "epoch": 0,
            "field": "obj",
            "value": {"a": 1, "b": [2, 3]},
        },
    ]

    out = []
    for c in cases:
        gk = derive_group_index_key(master, c["ceremony"], c["group"], c["epoch"])
        tok = index_token(gk, c["field"], c["value"])
        out.append(
            {
                "master_hex": _hex(master),
                "ceremony": c["ceremony"],
                "group": c["group"],
                "epoch": c["epoch"],
                "field": c["field"],
                "value": c["value"],
                "derived_key_hex": _hex(gk),
                "expected_token": tok,
            }
        )

    (FIX_DIR / "index_token_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  index_token_vectors.json ({len(out)} cases)")


# ---------------------------------------------------------------------------
# Fixture 4: signing
# ---------------------------------------------------------------------------


def gen_signing() -> None:
    seeds = [bytes([i] * 32) for i in range(1, 4)]
    messages = [
        b"",
        b"sha256:" + b"0" * 64,
        "café ☕".encode(),
    ]

    out = []
    for seed in seeds:
        dk = DeviceKey.from_private_bytes(seed)
        entry = {
            "seed_hex": _hex(seed),
            "public_hex": _hex(dk.public_bytes),
            "did": dk.did,
            "cases": [],
        }
        for msg in messages:
            sig = dk.sign(msg)
            entry["cases"].append(
                {
                    "message_hex": _hex(msg),
                    "signature_b64url_nopad": signature_b64(sig),
                }
            )
        out.append(entry)

    (FIX_DIR / "signing_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  signing_vectors.json    ({len(out)} keys × {len(messages)} msgs)")


# ---------------------------------------------------------------------------
# Fixture 5: envelope (two chained entries, identity cipher)
# ---------------------------------------------------------------------------


def gen_envelope() -> None:
    """Two full envelopes with injected timestamp+event_id.

    Uses an 'identity cipher' (ciphertext == canonical_bytes(fields)) so
    the envelope assembly is verified independently of which cipher is in
    use.  The Rust test must reproduce every field including row_hash and
    signature.
    """
    seed = bytes([7] * 32)
    dk = DeviceKey.from_private_bytes(seed)
    master = bytes(range(32))
    ceremony = "cer_golden"
    group = "default"
    epoch = 0
    gk = derive_group_index_key(master, ceremony, group, epoch)

    out = []
    for i, (ts, eid, fields) in enumerate(
        [
            (
                "2026-04-21T12:00:00.000000Z",
                "00000000-0000-0000-0000-00000000000a",
                {"amount": 100, "note": "first"},
            ),
            (
                "2026-04-21T12:00:01.000000Z",
                "00000000-0000-0000-0000-00000000000b",
                {"amount": 200, "currency": "USD"},
            ),
        ]
    ):
        field_hashes = {k: index_token(gk, k, v) for k, v in sorted(fields.items())}
        plaintext = canonical_bytes(fields)
        ct = plaintext  # identity cipher: ciphertext IS the canonical encoding
        prev_hash = ZERO_HASH if i == 0 else out[-1]["expected_row_hash"]
        row_hash = compute_row_hash(
            did=dk.did,
            timestamp=ts,
            event_id=eid,
            event_type="order.created",
            level="info",
            prev_hash=prev_hash,
            public_fields={"method": "POST"},
            groups={group: {"ciphertext": ct, "field_hashes": field_hashes}},
        )
        sig = dk.sign(row_hash.encode("ascii"))

        # The NDJSON envelope line a conforming Rust writer must reproduce.
        envelope_obj = {
            "did": dk.did,
            "timestamp": ts,
            "event_id": eid,
            "event_type": "order.created",
            "level": "info",
            "sequence": i + 1,
            "prev_hash": prev_hash,
            "row_hash": row_hash,
            "signature": signature_b64(sig),
            "method": "POST",
            group: {
                "ciphertext": _b64(ct),
                "field_hashes": field_hashes,
            },
        }
        line = json.dumps(envelope_obj, separators=(",", ":")) + "\n"

        out.append(
            {
                "inputs": {
                    "seed_hex": _hex(seed),
                    "timestamp": ts,
                    "event_id": eid,
                    "event_type": "order.created",
                    "level": "info",
                    "sequence": i + 1,
                    "prev_hash": prev_hash,
                    "public_fields": {"method": "POST"},
                    "private_fields": fields,
                    "group": group,
                    "ceremony_id": ceremony,
                    "master_index_key_hex": _hex(master),
                    "epoch": epoch,
                    "cipher": "identity",
                },
                "expected_field_hashes": field_hashes,
                "expected_ciphertext_hex": _hex(ct),
                "expected_row_hash": row_hash,
                "expected_signature_b64url": signature_b64(sig),
                "expected_envelope_ndjson": line,
            }
        )

    (FIX_DIR / "envelope_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  envelope_vectors.json   ({len(out)} entries)")


# ---------------------------------------------------------------------------
# Fixture 6: btn (broadcast-transaction encryption)
# ---------------------------------------------------------------------------


def gen_btn() -> None:
    """Capture a btn ciphertext produced by btn-py so Rust can decrypt it.

    API summary (from btn-py/src/lib.rs and btn/__init__.py):
      - ``btn.PublisherState(seed=<32 bytes>)``  — deterministic constructor
      - ``pub.mint()``                            — returns kit bytes directly
      - ``pub.encrypt(plaintext)``                — returns ciphertext bytes
      - ``pub.to_bytes()``                        — serialise state
      - ``btn.decrypt(kit_bytes, ct_bytes)``      — module-level free function

    The btn module is re-exported from ``btn.__init__`` via ``btn._core``.
    """
    try:
        import btn  # type: ignore[import-not-found]  # PyO3 ext built via maturin develop
    except ImportError as exc:
        print(f"  btn_vectors.json        SKIPPED — import failed: {exc}")
        (FIX_DIR / "btn_vectors.json").write_text(
            json.dumps(
                {
                    "_skipped": (
                        "btn-py not importable in this environment; "
                        "build with `maturin develop` inside tn-protocol/crypto/btn-py "
                        "then re-run this script. See Task 37."
                    )
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return

    seed = bytes([42] * 32)
    pub = btn.PublisherState(seed=seed)

    # Mint a reader kit. Returns bytes directly (ReaderKit serialised via
    # kit.to_bytes() inside Rust; Python side receives plain bytes).
    kit_bytes: bytes = pub.mint()

    plaintext = b"hello btn"
    ct_bytes: bytes = pub.encrypt(plaintext)
    state_bytes: bytes = pub.to_bytes()

    # Verify round-trip: decrypt with the kit we just minted.
    recovered = btn.decrypt(kit_bytes, ct_bytes)
    assert recovered == plaintext, f"btn round-trip failed: {recovered!r} != {plaintext!r}"

    out = {
        "publisher_seed_hex": _hex(seed),
        "publisher_state_bytes_hex": _hex(state_bytes),
        "reader_leaf_index": 0,
        "reader_kit_bytes_hex": _hex(kit_bytes),
        "plaintext_hex": _hex(plaintext),
        "ciphertext_hex": _hex(ct_bytes),
    }
    (FIX_DIR / "btn_vectors.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("  btn_vectors.json        (1 encrypt/decrypt pair)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    print(f"Writing fixtures to:\n  {FIX_DIR}\n")
    gen_canonical()
    gen_row_hash()
    gen_index_tokens()
    gen_signing()
    gen_envelope()
    gen_btn()
    print(f"\nDone. {len(list(FIX_DIR.glob('*.json')))} JSON files in fixtures/")


if __name__ == "__main__":
    main()
