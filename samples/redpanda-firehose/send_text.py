"""Send a text message through the TN firehose to Redpanda.

    python send_text.py "Hello from TN"
    python send_text.py --bootstrap tn-redpanda.fly.dev:9092 "Hello from TN"
    python send_text.py --project-id YOUR-UUID "Hello from TN"
    echo "Hello from stdin" | python send_text.py -

Wraps the text in a TN envelope (device_identity, event_id, row_hash,
Ed25519 signature), encrypts the frame under the Phase-A stub BEK, and
produces it to the firehose topic. The consumer prints the plaintext back.

Device identity is ephemeral per-run unless --key-file is provided.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

sys.path.insert(0, str(Path(__file__).parent))
from handler import TnRedpandaHandler, topic_for

_DEMO_PROJECT = "00000000-0000-0000-0000-000000000001"

# Placeholder — swap for your Fly.io app name once deployed:
#   fly.toml app = "tn-redpanda"  →  tn-redpanda.fly.dev:9092
_DEFAULT_BOOTSTRAP = "localhost:9092"


# ---------------------------------------------------------------------------
# Minimal TN envelope construction
# ---------------------------------------------------------------------------

def _load_or_create_key(key_file: Path | None) -> Ed25519PrivateKey:
    """Load a persistent device key or generate an ephemeral one."""
    if key_file and key_file.exists():
        raw = base64.b64decode(key_file.read_text().strip())
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    if key_file:
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        key_file.write_text(base64.b64encode(raw).decode())
    return key


def _did_key(private_key: Ed25519PrivateKey) -> str:
    """Encode Ed25519 public key as did:key (multicodec 0xed01, base58btc z prefix)."""
    pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = bytes([0xed, 0x01]) + pub
    return "did:key:z" + _b58encode(payload)


def _b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = ""
    while n:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    for b in data:
        if b == 0:
            result = alphabet[0] + result
        else:
            break
    return result


def _sha256hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def make_envelope(
    text: str,
    private_key: Ed25519PrivateKey,
    project_id: str,
    prev_hash: str,
    sequence: int,
) -> tuple[dict, bytes]:
    """Build and sign a TN envelope carrying text in public_fields.content."""
    did = _did_key(private_key)
    now = datetime.now(timezone.utc).isoformat()
    event_id = str(uuid.uuid4())
    event_type = "text.message"

    # Canonical fields for row_hash (matches TN chain contract)
    row_input = f"{did}|{event_type}|{sequence}|{prev_hash}|{event_id}|{now}".encode()
    row_hash = _sha256hex(row_input)

    # Sign the row_hash with the device key
    sig_bytes = private_key.sign(row_hash.encode("ascii"))
    signature = "Ed25519:" + base64.b64encode(sig_bytes).decode()

    env = {
        "device_identity": did,
        "timestamp": now,
        "event_id": event_id,
        "event_type": event_type,
        "level": "info",
        "sequence": sequence,
        "prev_hash": prev_hash,
        "row_hash": row_hash,
        "signature": signature,
        "public_fields": {
            "project_id": project_id,
            "content": text,
            "byte_len": len(text.encode()),
        },
    }
    return env, (json.dumps(env) + "\n").encode()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Send text as a TN envelope to Redpanda")
    ap.add_argument("text", nargs="?", help="Text to send (or - for stdin)")
    ap.add_argument("--bootstrap", default=_DEFAULT_BOOTSTRAP)
    ap.add_argument("--project-id", default=_DEMO_PROJECT)
    ap.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Path to persist device key (base64 raw Ed25519). "
             "Omit for ephemeral key per run.",
    )
    ap.add_argument("--prev-hash", default="sha256:" + "0" * 64,
                    help="prev_hash for the chain (default: genesis)")
    ap.add_argument("--sequence", type=int, default=0)
    args = ap.parse_args()

    # Resolve text
    if args.text == "-" or args.text is None:
        text = sys.stdin.read().strip()
    else:
        text = args.text

    if not text:
        ap.error("No text provided.")

    encoded = text.encode()
    if len(encoded) > 65536:
        ap.error(f"Text too long ({len(encoded)} bytes). Keep it reasonable.")

    private_key = _load_or_create_key(args.key_file)
    did = _did_key(private_key)

    env, raw = make_envelope(
        text=text,
        private_key=private_key,
        project_id=args.project_id,
        prev_hash=args.prev_hash,
        sequence=args.sequence,
    )

    outbox = Path("/tmp/tn-send-text-outbox")
    outbox.mkdir(parents=True, exist_ok=True)

    username = os.environ.get("RP_USERNAME")
    password = os.environ.get("RP_PASSWORD")

    handler = TnRedpandaHandler(
        "send-text",
        outbox,
        bootstrap=args.bootstrap,
        project_id=args.project_id,
        sasl_username=username,
        sasl_password=password,
    )

    topic = topic_for(args.project_id)
    print(f"bootstrap : {args.bootstrap}")
    print(f"topic     : {topic}")
    print(f"did       : {did[:32]}…")
    print(f"event_id  : {env['event_id']}")
    print(f"text      : {text!r}  ({len(encoded)} bytes)")
    print()

    handler.emit(env, raw)
    handler.close(timeout=15)

    print("Sent.")
    print(f"\nConsume:  .venv/bin/python demo_consume.py --bootstrap {args.bootstrap}")


if __name__ == "__main__":
    main()
