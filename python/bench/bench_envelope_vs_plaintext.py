"""Envelope-vs-plaintext performance matrix.

Compares four ways of appending attested / encrypted / plain events to
an ndjson-style log, across a range of payload sizes. The point is to
quantify what TN's cryptographic guarantees cost on top of naive
line-appended JSON, and to put the current (BGW) SDK against the older
(per-column X25519) SDK head-to-head on the same hardware.

Variants (same hot loop, same event dicts, same output discipline):
  plaintext       json.dumps(event) + write line   (no crypto at all)
  plaintext+sign  plaintext + Ed25519 sign per entry (integrity only)
  tn_envelope     tn.info() from the NEW SDK at tn-protocol/python/tn —
                  BGW broadcast encrypt + AES-GCM body + signed
                  row_hash + per-event-type chain + HMAC index tokens
  old_sdk_ndjson  TNClient.log() from the OLD SDK at python/tn with
                  only NdjsonFileSink enabled (DeltaTable + Avro sinks
                  disabled). Ed25519 sign + per-column X25519/CEK
                  envelope encryption + Merkle chain.

Payload sizes (bytes, measured as the serialized event dict):
  ~256 B, ~1 KB, ~4 KB, ~16 KB, ~64 KB

Run (WSL; requires libtncrypto.so):
    cd tn-protocol/python
    TNCRYPTO_LIB=$(pwd)/../crypto/build/libtncrypto.so \\
        /usr/bin/python bench/bench_envelope_vs_plaintext.py
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# ----------------------------------------------------------------------
# Payload generation
# ----------------------------------------------------------------------

# Canned indexed fields. Values are small; the big cost driver is the
# padded `blob` field added to reach the target size.
_BASE_FIELDS = {
    "amount": 4200,
    "email": "alice@example.com",
    "ip": "10.0.0.17",
    "order_id": "A000123",
    "country": "ES",
    "method": "POST",
}


def _make_event(target_bytes: int, seq: int) -> dict:
    """Build an event whose json.dumps length lands ~target_bytes."""
    evt = dict(_BASE_FIELDS)
    evt["amount"] = 4200 + (seq % 100)
    evt["order_id"] = f"A{seq:09d}"

    # Measure base size, then top up with a `blob` field.
    base = json.dumps(evt, separators=(",", ":"))
    overhead = len(base) + len(',"blob":""')
    pad = max(0, target_bytes - overhead)
    evt["blob"] = "x" * pad
    return evt


# ----------------------------------------------------------------------
# Variants
# ----------------------------------------------------------------------


def _count_lines(path: Path) -> int:
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def bench_plaintext(events: int, size_bytes: int, ws: Path) -> dict:
    """json.dumps + line append. No crypto. Baseline for everything."""
    log = ws / "plain.ndjson"
    latencies_us: list[float] = []
    t0 = time.perf_counter()
    with open(log, "ab") as f:
        for i in range(events):
            evt = _make_event(size_bytes, i)
            t_entry = time.perf_counter()
            line = json.dumps(evt, separators=(",", ":")).encode("utf-8") + b"\n"
            f.write(line)
            latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    total = time.perf_counter() - t0

    # Open pass: json.loads each line. Floor for the read side.
    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    with open(log, "rb") as f:
        for line in f:
            t_entry = time.perf_counter()
            json.loads(line)
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    decrypt_total = time.perf_counter() - t_d0

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": log.stat().st_size,
        "lines_written": _count_lines(log),
    }


def bench_plaintext_signed(events: int, size_bytes: int, ws: Path) -> dict:
    """Plaintext plus a per-entry Ed25519 signature over SHA-256 of the
    serialized payload. Models the minimum attestation floor: integrity
    without confidentiality."""
    import base64
    import hashlib

    from tn.signing import DeviceKey, signature_b64

    device = DeviceKey.generate()
    log = ws / "plainsig.ndjson"
    latencies_us: list[float] = []
    t0 = time.perf_counter()
    with open(log, "ab") as f:
        for i in range(events):
            evt = _make_event(size_bytes, i)
            t_entry = time.perf_counter()
            payload = json.dumps(evt, separators=(",", ":"), sort_keys=True).encode("utf-8")
            digest = hashlib.sha256(payload).digest()
            sig = device.sign(digest)
            signed = {
                "did": device.did,
                "payload_b64": base64.b64encode(payload).decode("ascii"),
                "sig": signature_b64(sig),
            }
            f.write(json.dumps(signed, separators=(",", ":")).encode("utf-8") + b"\n")
            latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    total = time.perf_counter() - t0

    # Open pass: parse, base64-decode, Ed25519-verify.
    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    with open(log, "rb") as f:
        for line in f:
            t_entry = time.perf_counter()
            env = json.loads(line)
            payload = base64.b64decode(env["payload_b64"])
            digest = hashlib.sha256(payload).digest()
            from tn.signing import signature_from_b64 as _sfb

            assert DeviceKey.verify(env["did"], digest, _sfb(env["sig"]))
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    decrypt_total = time.perf_counter() - t_d0

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": log.stat().st_size,
        "lines_written": _count_lines(log),
    }


def bench_tn_envelope(events: int, size_bytes: int, ws: Path) -> dict:
    """Full tn.info() pipeline: BGW broadcast encrypt + AES-GCM body +
    Ed25519 signature over the chained row_hash + HMAC index tokens."""
    import tn  # deferred until env is ready

    yaml_path = ws / "tn.yaml"
    log = ws / "logs" / "tn.ndjson"
    tn.init(yaml_path, log_path=log, pool_size=4, cipher="bgw")

    latencies_us: list[float] = []
    t0 = time.perf_counter()
    for i in range(events):
        evt = _make_event(size_bytes, i)
        t_entry = time.perf_counter()
        tn.info("bench.event", **evt)
        latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    tn.flush_and_close()
    total = time.perf_counter() - t0
    # Find the actual file the handler wrote to. Default file handler
    # may rotate or use a sibling name; walk the logs dir to be safe.
    log_dir = log.parent
    log_files = [p for p in log_dir.iterdir() if p.is_file()]
    bytes_on_disk = sum(p.stat().st_size for p in log_files)
    lines_written = sum(_count_lines(p) for p in log_files)

    # Open pass: reopen under the same ceremony config and iterate
    # through tn.read(raw=True). Each entry: parse, BGW-decrypt, verify signature
    # + chain + row_hash. Represents what an authorised slot holder pays
    # to consume the log.
    tn.init(yaml_path, log_path=log, pool_size=4, cipher="bgw")
    cfg = tn.current_config()

    # File rotation may have split entries across several files; read
    # every one so the decrypt rate is against the full event set.
    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    for logfile in log_files:
        it = tn.read(logfile, cfg, raw=True)
        while True:
            # Time the iterator step — tn.read is a generator, so the
            # BGW decrypt + signature + chain verification happen inside
            # __next__() before control returns here. Timing after
            # next() would only see dict access and miss the real work.
            t_entry = time.perf_counter()
            try:
                entry = next(it)
            except StopIteration:
                break
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
            _ = entry["plaintext"]
            _ = entry["valid"]["signature"]
    decrypt_total = time.perf_counter() - t_d0
    tn.flush_and_close()

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": bytes_on_disk,
        "lines_written": lines_written,
    }


def bench_tn_envelope_jwe(events: int, size_bytes: int, ws: Path) -> dict:
    """Full tn.info() / tn.read(raw=True) pipeline under a JWE-configured ceremony.

    True like-for-like against `bench_tn_envelope` (BGW): same hot loop,
    same event dicts, same output discipline. The only difference is the
    group-sealing cipher.
    """
    import tn  # deferred until env is ready

    yaml_path = ws / "tn.yaml"
    log = ws / "logs" / "tn.ndjson"
    tn.init(yaml_path, log_path=log, cipher="jwe")

    latencies_us: list[float] = []
    t0 = time.perf_counter()
    for i in range(events):
        evt = _make_event(size_bytes, i)
        t_entry = time.perf_counter()
        tn.info("bench.event", **evt)
        latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    tn.flush_and_close()
    total = time.perf_counter() - t0

    log_dir = log.parent
    log_files = [p for p in log_dir.iterdir() if p.is_file()]
    bytes_on_disk = sum(p.stat().st_size for p in log_files)
    lines_written = sum(_count_lines(p) for p in log_files)

    # Reopen under the same ceremony and iterate tn.read(raw=True).
    tn.init(yaml_path, log_path=log, cipher="jwe")
    cfg = tn.current_config()

    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    for logfile in log_files:
        it = tn.read(logfile, cfg, raw=True)
        while True:
            t_entry = time.perf_counter()
            try:
                entry = next(it)
            except StopIteration:
                break
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
            _ = entry["plaintext"]
            _ = entry["valid"]["signature"]
    decrypt_total = time.perf_counter() - t_d0
    tn.flush_and_close()

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": bytes_on_disk,
        "lines_written": lines_written,
    }


def bench_jwe_envelope(events: int, size_bytes: int, ws: Path) -> dict:
    """JWE-style multi-recipient sealing (ECDH-ES + A256KW + A256GCM).

    Hand-rolled single-file implementation for a head-to-head against
    the BGW-based `tn_envelope` variant. Recipient count = 4, matching
    BGW pool_size=4.

    Per-entry flow:
      * Sample 32-byte CEK + 12-byte IV.
      * AES-256-GCM(CEK, IV) over canonical JSON of the private fields.
      * Generate an ephemeral X25519 keypair; for each recipient pub,
        ECDH → HKDF-SHA256 → 256-bit KEK → AES-KW-wrap CEK.
      * HMAC-SHA256 index tokens per private field under a per-group key
        (same tn.indexing module the BGW variant uses).
      * Canonical envelope hash → Ed25519 signature.
      * Append envelope as one JSON line.

    Comparable surrounding machinery to tn_envelope (chain prev_hash,
    signed row_hash, HMAC index tokens). Only the sealing primitive
    differs: BGW pairing encrypt vs N × ECDH key wrap.
    """
    import base64
    import hashlib
    import os as _os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    from tn import indexing
    from tn.canonical import canonical_bytes
    from tn.signing import DeviceKey, signature_b64

    def _b64(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    N_RECIPIENTS = 4

    # One-time ceremony setup: recipient X25519 keys, device Ed25519,
    # and an index key. Matches what tn.init does behind the scenes.
    recipients_sk = [X25519PrivateKey.generate() for _ in range(N_RECIPIENTS)]
    recipients_pub = [
        sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for sk in recipients_sk
    ]
    device = DeviceKey.generate()
    master = indexing.new_master_key()
    group_index_key = indexing.derive_group_index_key(master, "jwe-bench", "default")

    log = ws / "jwe.ndjson"
    prev_hash = "sha256:" + "0" * 64
    latencies_us: list[float] = []

    t0 = time.perf_counter()
    with open(log, "ab") as f:
        for i in range(events):
            evt = _make_event(size_bytes, i)
            t_entry = time.perf_counter()

            # 1. index tokens per field
            field_hashes = {k: indexing.index_token(group_index_key, k, v) for k, v in evt.items()}

            # 2. body AEAD
            cek = _os.urandom(32)
            iv = _os.urandom(12)
            plaintext = canonical_bytes(evt)
            ciphertext = AESGCM(cek).encrypt(iv, plaintext, None)

            # 3. per-recipient key wrap via ECDH-ES + HKDF + A256KW
            ephemeral = X25519PrivateKey.generate()
            eph_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            recipient_blocks = []
            for rpub in recipients_pub:
                shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(rpub))
                kek = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"jwe-bench:A256KW",
                ).derive(shared)
                wrapped = aes_key_wrap(kek, cek)
                recipient_blocks.append(_b64(wrapped))

            # 4. chain + signed row_hash
            envelope = {
                "did": device.did,
                "event_type": "bench.event",
                "prev_hash": prev_hash,
                "field_hashes": field_hashes,
                "default": {
                    "iv": _b64(iv),
                    "ciphertext": _b64(ciphertext),
                    "ephemeral_pub": _b64(eph_pub),
                    "recipients": recipient_blocks,
                },
            }
            env_canon = canonical_bytes(envelope)
            row_hash = "sha256:" + hashlib.sha256(env_canon).hexdigest()
            sig = device.sign(row_hash.encode("ascii"))
            envelope["row_hash"] = row_hash
            envelope["signature"] = signature_b64(sig)

            line = json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"
            f.write(line)

            prev_hash = row_hash
            latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    total = time.perf_counter() - t0

    # Open pass from recipient 0's perspective: parse, ECDH with
    # ephemeral_pub, unwrap CEK, AES-GCM decrypt, verify Ed25519 sig.
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

    from tn.signing import signature_from_b64 as _sfb

    recipient_0 = recipients_sk[0]
    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    with open(log, "rb") as fr:
        for line in fr:
            t_entry = time.perf_counter()
            env = json.loads(line)
            eph_pub = base64.b64decode(env["default"]["ephemeral_pub"])
            wrapped = base64.b64decode(env["default"]["recipients"][0])
            iv_bytes = base64.b64decode(env["default"]["iv"])
            ct = base64.b64decode(env["default"]["ciphertext"])
            shared = recipient_0.exchange(X25519PublicKey.from_public_bytes(eph_pub))
            kek = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"jwe-bench:A256KW",
            ).derive(shared)
            cek = aes_key_unwrap(kek, wrapped)
            _pt = AESGCM(cek).decrypt(iv_bytes, ct, None)
            assert DeviceKey.verify(
                env["did"], env["row_hash"].encode("ascii"), _sfb(env["signature"])
            )
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    decrypt_total = time.perf_counter() - t_d0

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": log.stat().st_size,
        "lines_written": _count_lines(log),
    }


def bench_jwe_static_dh(events: int, size_bytes: int, ws: Path) -> dict:
    """JWE with precomputed static Diffie-Hellman (no ephemeral per seal).

    Same threat model as BGW: keys are long-lived per ceremony. Compromise
    the sender's X25519 private key and all past envelopes are readable.
    In exchange, per-seal cost drops to microseconds — the per-recipient
    KEKs are derived once at init, and each seal is just CEK + N × AES-KW
    + AES-GCM body.
    """
    import base64
    import hashlib
    import os as _os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    from tn import indexing
    from tn.canonical import canonical_bytes
    from tn.signing import DeviceKey, signature_b64

    def _b64(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    N_RECIPIENTS = 4

    # Sender X25519 is long-lived. Recipients' pubs are long-lived. So
    # the per-recipient shared secret is a one-time derivation.
    sender_sk = X25519PrivateKey.generate()
    sender_pub = sender_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    recipients_sk = [X25519PrivateKey.generate() for _ in range(N_RECIPIENTS)]
    recipients_pub = [
        sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for sk in recipients_sk
    ]

    # Precompute per-recipient KEKs once.
    precomputed_keks: list[bytes] = []
    for rpub in recipients_pub:
        shared = sender_sk.exchange(X25519PublicKey.from_public_bytes(rpub))
        kek = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"jwe-static:A256KW",
        ).derive(shared)
        precomputed_keks.append(kek)

    device = DeviceKey.generate()
    master = indexing.new_master_key()
    group_index_key = indexing.derive_group_index_key(master, "jwestatic-bench", "default")

    log = ws / "jwestatic.ndjson"
    prev_hash = "sha256:" + "0" * 64
    latencies_us: list[float] = []

    t0 = time.perf_counter()
    with open(log, "ab") as f:
        for i in range(events):
            evt = _make_event(size_bytes, i)
            t_entry = time.perf_counter()

            field_hashes = {k: indexing.index_token(group_index_key, k, v) for k, v in evt.items()}

            cek = _os.urandom(32)
            iv = _os.urandom(12)
            plaintext = canonical_bytes(evt)
            ciphertext = AESGCM(cek).encrypt(iv, plaintext, None)

            # Only cost per seal: N × AES-KW (microseconds each).
            recipient_blocks = [_b64(aes_key_wrap(kek, cek)) for kek in precomputed_keks]

            envelope = {
                "did": device.did,
                "event_type": "bench.event",
                "prev_hash": prev_hash,
                "field_hashes": field_hashes,
                "default": {
                    "iv": _b64(iv),
                    "ciphertext": _b64(ciphertext),
                    "sender_pub": _b64(sender_pub),
                    "recipients": recipient_blocks,
                },
            }
            env_canon = canonical_bytes(envelope)
            row_hash = "sha256:" + hashlib.sha256(env_canon).hexdigest()
            sig = device.sign(row_hash.encode("ascii"))
            envelope["row_hash"] = row_hash
            envelope["signature"] = signature_b64(sig)

            line = json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"
            f.write(line)

            prev_hash = row_hash
            latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    total = time.perf_counter() - t0

    # Open pass: recipient 0 precomputes their KEK once against the
    # sender's pub, then per-entry is just AES-KW unwrap + AES-GCM.
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

    from tn.signing import signature_from_b64 as _sfb

    recipient_0 = recipients_sk[0]
    recv_shared = recipient_0.exchange(X25519PublicKey.from_public_bytes(sender_pub))
    recv_kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"jwe-static:A256KW",
    ).derive(recv_shared)

    decrypt_latencies_us: list[float] = []
    t_d0 = time.perf_counter()
    with open(log, "rb") as fr:
        for line in fr:
            t_entry = time.perf_counter()
            env = json.loads(line)
            wrapped = base64.b64decode(env["default"]["recipients"][0])
            iv_bytes = base64.b64decode(env["default"]["iv"])
            ct = base64.b64decode(env["default"]["ciphertext"])
            cek = aes_key_unwrap(recv_kek, wrapped)
            _pt = AESGCM(cek).decrypt(iv_bytes, ct, None)
            assert DeviceKey.verify(
                env["did"], env["row_hash"].encode("ascii"), _sfb(env["signature"])
            )
            decrypt_latencies_us.append((time.perf_counter() - t_entry) * 1e6)
    decrypt_total = time.perf_counter() - t_d0

    return {
        "total": total,
        "latencies_us": latencies_us,
        "decrypt_total": decrypt_total,
        "decrypt_latencies_us": decrypt_latencies_us,
        "bytes_on_disk": log.stat().st_size,
        "lines_written": _count_lines(log),
    }


def bench_old_sdk_ndjson(events: int, size_bytes: int, ws: Path) -> dict:
    """Old SDK (python/tn) via TNClient.log() with only NdjsonFileSink.

    Attests via Ed25519 signature over a Merkle-chained row, per-column
    X25519/CEK envelope encryption, then appends the encrypted row to a
    rolling ndjson file. Delta-Table and Avro sinks are explicitly
    removed so this variant measures only the ndjson path.
    """
    import asyncio
    import os
    import sys

    # Make the old SDK importable. Inserting at index 0 overrides the
    # new SDK's `tn` package for the duration of this pass.
    old_sdk_root = str(
        Path("/mnt/c/codex/content_platform/python").resolve()
        if os.name != "nt"
        else Path("C:/codex/content_platform/python")
    )
    # Drop any cached `tn*` modules loaded from the new SDK so this
    # variant binds to the old package namespace.
    for m in list(sys.modules):
        if m == "tn" or m.startswith("tn."):
            del sys.modules[m]
    sys.path.insert(0, old_sdk_root)

    try:
        from tn.auth.did import derive_did
        from tn.client import TNClient
        from tn.encryption import generate_x25519_keypair
        from tn.sinks.ndjson import NdjsonFileSink
        from tn.types import Config, ManifestField, ServiceManifest

        from tn.signing import generate_ed25519_keypair

        sk, pk = generate_ed25519_keypair()
        esk, _ = generate_x25519_keypair()
        did = derive_did(pk)
        manifest = ServiceManifest(
            did=did,
            name="bench",
            description="benchmark",
            fields=[ManifestField(name=k, type="string", description=k) for k in _BASE_FIELDS],
            endpoint="https://bench.example/",
        )
        cfg = Config(
            did=did,
            signing_key=sk,
            encryption_key=esk,
            storage_path=str(ws / "oldsdk"),
            manifest=manifest,
        )
        (ws / "oldsdk").mkdir(exist_ok=True)

        client = TNClient(cfg)
        # Isolate the ndjson path: drop DeltaTable + Avro sinks.
        client._sinks = [NdjsonFileSink()]

        latencies_us: list[float] = []

        async def hot_loop() -> float:
            t0 = time.perf_counter()
            for i in range(events):
                evt = _make_event(size_bytes, i)
                t_entry = time.perf_counter()
                await client.log(f"bench-{i}", "bench.event", evt)
                latencies_us.append((time.perf_counter() - t_entry) * 1e6)
            return time.perf_counter() - t0

        total = asyncio.run(hot_loop())

        # Collect every file the sink wrote under the storage root.
        storage_root = ws / "oldsdk"
        ndjson_files = list(storage_root.rglob("*.ndjson"))
        bytes_on_disk = sum(p.stat().st_size for p in ndjson_files)
        lines_written = sum(_count_lines(p) for p in ndjson_files)

        return {
            "total": total,
            "latencies_us": latencies_us,
            # Old SDK read path goes through DeltaTable, not the
            # NdjsonFileSink we write to in this bench — not directly
            # comparable. Left unmeasured.
            "decrypt_total": None,
            "decrypt_latencies_us": [],
            "bytes_on_disk": bytes_on_disk,
            "lines_written": lines_written,
            "ndjson_file_count": len(ndjson_files),
        }
    finally:
        # Remove the old SDK from the path and drop its modules so the
        # next variant doesn't see them.
        if old_sdk_root in sys.path:
            sys.path.remove(old_sdk_root)
        for m in list(sys.modules):
            if m == "tn" or m.startswith("tn."):
                del sys.modules[m]


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------

VARIANTS = [
    ("plaintext", bench_plaintext),
    ("plaintext+sign", bench_plaintext_signed),
    ("tn_envelope_bgw", bench_tn_envelope),
    ("tn_envelope_jwe", bench_tn_envelope_jwe),
    ("jwe_envelope", bench_jwe_envelope),
    ("jwe_static_dh", bench_jwe_static_dh),
    ("old_sdk_ndjson", bench_old_sdk_ndjson),
]

# (label, target_payload_bytes, events)
SIZE_MATRIX = [
    ("256 B", 256, 2000),
    ("1 KB", 1024, 2000),
    ("4 KB", 4096, 1000),
    ("16 KB", 16384, 500),
    ("64 KB", 65536, 200),
]


def _pct(lat: list[float], p: int) -> float:
    if not lat:
        return float("nan")
    if p == 50:
        return statistics.median(lat)
    if p == 95:
        return statistics.quantiles(lat, n=20)[18]
    if p == 99:
        return statistics.quantiles(lat, n=100)[98]
    raise ValueError(p)


def _summarize(result: dict, events: int) -> dict:
    lat = result["latencies_us"]
    dec_lat = result.get("decrypt_latencies_us") or []
    dec_total = result.get("decrypt_total")
    # The iterator on the read side may process fewer entries than the
    # seal side wrote (tn's file handler can rotate mid-run and we
    # deliberately read only the primary log). Rate the decrypt
    # throughput against the actual number of entries opened, not the
    # number sealed.
    dec_count = len(dec_lat)
    return {
        "entries_per_sec": events / result["total"],
        "p50_us": _pct(lat, 50),
        "p95_us": _pct(lat, 95),
        "p99_us": _pct(lat, 99),
        "bytes_per_entry": result["bytes_on_disk"] / max(1, events),
        "lines_written": result.get("lines_written", events),
        "expected_events": events,
        "total_ms": result["total"] * 1000,
        "decrypt_entries_per_sec": (dec_count / dec_total) if dec_total and dec_count else None,
        "decrypt_p50_us": _pct(dec_lat, 50) if dec_lat else None,
        "decrypt_p95_us": _pct(dec_lat, 95) if dec_lat else None,
        "decrypt_p99_us": _pct(dec_lat, 99) if dec_lat else None,
        "decrypt_entries": dec_count,
    }


def _print_section(size_label: str, rows: list[tuple[str, dict]]) -> None:
    baseline_eps = rows[0][1]["entries_per_sec"]
    print(f"\n### payload size: {size_label}")
    # Sealing / encrypt side.
    print("  SEAL")
    print(
        f"  {'variant':<18} {'entries/s':>10} {'p50 µs':>10} {'p95 µs':>10} "
        f"{'p99 µs':>10} {'B/event':>10} {'rel tput':>10} {'fanout':>8}"
    )
    print("  " + "-" * 96)
    for name, s in rows:
        rel = s["entries_per_sec"] / baseline_eps
        fanout = s["lines_written"] / max(1, s["expected_events"])
        fanout_tag = f"{fanout:.1f}x" if fanout != 1.0 else "1x"
        print(
            f"  {name:<18} {s['entries_per_sec']:>10,.0f} "
            f"{s['p50_us']:>10.1f} {s['p95_us']:>10.1f} {s['p99_us']:>10.1f} "
            f"{s['bytes_per_entry']:>10,.0f} {rel:>9.2%} {fanout_tag:>8}"
        )
    # Open / decrypt side.
    open_rows = [(n, s) for n, s in rows if s.get("decrypt_entries_per_sec") is not None]
    if not open_rows:
        return
    base_open = open_rows[0][1]["decrypt_entries_per_sec"]
    print("  OPEN")
    print(
        f"  {'variant':<18} {'entries/s':>10} {'p50 µs':>10} {'p95 µs':>10} "
        f"{'p99 µs':>10} {'rel tput':>10}"
    )
    print("  " + "-" * 76)
    for name, s in open_rows:
        eps = s["decrypt_entries_per_sec"]
        rel = eps / base_open
        print(
            f"  {name:<18} {eps:>10,.0f} "
            f"{s['decrypt_p50_us']:>10.1f} {s['decrypt_p95_us']:>10.1f} "
            f"{s['decrypt_p99_us']:>10.1f} {rel:>9.2%}"
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--events-scale",
        type=float,
        default=1.0,
        help="scale factor for event counts (default 1.0)",
    )
    ap.add_argument(
        "--json-out", type=Path, default=None, help="if set, also dump raw numbers here"
    )
    args = ap.parse_args()

    all_results: dict = {"variants": [n for n, _ in VARIANTS], "sizes": []}
    print("=" * 84)
    print("Envelope vs plaintext — per-entry appending throughput")
    print("=" * 84)

    for size_label, size_bytes, events in SIZE_MATRIX:
        events = max(50, int(events * args.events_scale))
        rows: list[tuple[str, dict]] = []
        for variant_name, fn in VARIANTS:
            with tempfile.TemporaryDirectory(prefix=f"tnbench_{variant_name}_") as td:
                ws = Path(td)
                (ws / "logs").mkdir(exist_ok=True)
                result = fn(events, size_bytes, ws)
                summary = _summarize(result, events)
                rows.append((variant_name, summary))
        _print_section(f"{size_label} ({events} events)", rows)
        all_results["sizes"].append(
            {
                "label": size_label,
                "bytes_target": size_bytes,
                "events": events,
                "results": {name: s for name, s in rows},
            }
        )

    if args.json_out:
        args.json_out.write_text(json.dumps(all_results, indent=2))
        print(f"\nwrote raw results to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
