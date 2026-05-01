"""Tests for the multi-device restore flow (Session 10).

Covers:
  * ``LoopbackReceiver`` lifecycle: bind, accept, reject, timeout.
  * ``decrypt_blob_with_bek``: AES-GCM round-trip with a known key.
  * ``write_restored_bytes``: tn.pkg.export-frame unpack + raw-bytes
    fallback.
  * ``restore_with_token``: end-to-end with monkey-patched HTTP.

Refs: D-3, D-19, D-20, D-22; spec section 9.9; plan
``docs/superpowers/plans/2026-04-29-multi-device-restore.md``.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tn import wallet_restore as wr
from tn import wallet_restore_loopback as wrl


# ── LoopbackReceiver ──────────────────────────────────────────────────


def _post_json(url: str, body: dict, timeout: float = 5.0) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.getcode(), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8") if e.fp else "")


def test_loopback_receiver_binds_to_loopback_only():
    rx = wrl.LoopbackReceiver.start()
    try:
        # Confirm the URL is loopback and the port is non-zero.
        assert rx.callback_url.startswith("http://127.0.0.1:")
        assert rx.port > 0
        # Confirm the server is actually listening.
        s = socket.socket()
        try:
            s.settimeout(1.0)
            s.connect(("127.0.0.1", rx.port))
        finally:
            s.close()
    finally:
        rx.shutdown()


def test_loopback_receiver_accepts_valid_token():
    rx = wrl.LoopbackReceiver.start()
    try:
        payload = {
            "vault_jwt": "fake.jwt.value",
            "account_id": "01HXACCT",
            "project_id": "01HXPROJ",
            "raw_bek_b64": base64.urlsafe_b64encode(b"\x42" * 32).decode("ascii"),
            "state": rx.state,
        }
        # POST in a thread so the receiver doesn't deadlock.
        result = {}

        def _send():
            code, body = _post_json(rx.callback_url, payload)
            result["code"] = code
            result["body"] = body

        t = threading.Thread(target=_send, daemon=True)
        t.start()

        token = rx.wait_for_token(timeout_seconds=5.0)
        assert token.vault_jwt == "fake.jwt.value"
        assert token.account_id == "01HXACCT"
        assert token.project_id == "01HXPROJ"
        assert token.state == rx.state

        t.join(timeout=2.0)
        assert result["code"] == 200
        assert "Restore initiated" in result["body"]
    finally:
        rx.shutdown()


def test_loopback_receiver_rejects_state_mismatch():
    rx = wrl.LoopbackReceiver.start()
    try:
        bad = {
            "vault_jwt": "x",
            "account_id": "y",
            "project_id": "z",
            "raw_bek_b64": "ABCD",
            "state": "WRONG",
        }
        code, _ = _post_json(rx.callback_url, bad)
        assert code == 400
    finally:
        rx.shutdown()


def test_loopback_receiver_rejects_get():
    rx = wrl.LoopbackReceiver.start()
    try:
        req = urllib.request.Request(rx.callback_url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:  # noqa: S310
                pytest.fail(f"expected error, got {resp.getcode()}")
        except urllib.error.HTTPError as e:
            assert e.code == 405
    finally:
        rx.shutdown()


def test_loopback_receiver_rejects_missing_fields():
    rx = wrl.LoopbackReceiver.start()
    try:
        # vault_jwt missing.
        bad = {
            "account_id": "y",
            "project_id": "z",
            "raw_bek_b64": "ABCD",
            "state": rx.state,
        }
        code, _ = _post_json(rx.callback_url, bad)
        assert code == 400
    finally:
        rx.shutdown()


def test_loopback_receiver_times_out_cleanly():
    rx = wrl.LoopbackReceiver.start()
    try:
        with pytest.raises(TimeoutError) as exc:
            rx.wait_for_token(timeout_seconds=0.5)
        assert "no transfer token received" in str(exc.value)
    finally:
        rx.shutdown()


def test_loopback_receiver_pinned_port():
    # Pick a free port up front so we know what to expect.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rx = wrl.LoopbackReceiver.start(port=port)
    try:
        assert rx.port == port
    finally:
        rx.shutdown()


def test_loopback_receiver_shutdown_idempotent():
    rx = wrl.LoopbackReceiver.start()
    rx.shutdown()
    # Second shutdown must not raise.
    rx.shutdown()


# ── S2: exclusive bind + peer-IP gate ────────────────────────────────


def test_loopback_bind_is_exclusive_to_127_0_0_1():
    """The receiver's listening socket must not be reachable off-host.

    Confirm the socket family + bound address are loopback IPv4.
    """
    rx = wrl.LoopbackReceiver.start()
    try:
        sock = rx.server.socket
        assert sock.family == socket.AF_INET
        bound_host, bound_port = sock.getsockname()
        assert bound_host == "127.0.0.1"
        assert bound_port == rx.port
    finally:
        rx.shutdown()


def test_loopback_bind_refuses_second_listener_on_same_port():
    """SO_EXCLUSIVEADDRUSE / SO_REUSEADDR=0 prevents a co-resident
    process from binding the same (host, port) tuple — closes the S2
    port-stealing window. (Behavior varies by OS; on POSIX the
    default kernel rule already disallows duplicate binds without
    SO_REUSEADDR=1, so this is mostly a Windows-relevant test, but
    asserting it on every platform pins the invariant.)
    """
    rx = wrl.LoopbackReceiver.start()
    try:
        attacker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Don't set SO_REUSEADDR — emulate a hostile co-resident
            # that's just trying to grab the port.
            with pytest.raises(OSError):
                attacker.bind(("127.0.0.1", rx.port))
        finally:
            attacker.close()
    finally:
        rx.shutdown()


def test_loopback_handler_rejects_non_loopback_peer(monkeypatch):
    """Defense-in-depth: even if a connection somehow originates from
    off-loopback, ``do_POST`` must refuse to deliver the token.

    We can't actually reach the listener from a non-127 address (the
    bind blocks that), so simulate the check directly by constructing
    a request handler with a synthetic ``client_address``.
    """
    # Build a minimal fake request that exercises the early peer-IP
    # check in do_POST without touching the socket layer.
    class FakeRfile:
        def read(self, n):
            return b""

    class FakeWfile:
        def __init__(self):
            self.buf = bytearray()

        def write(self, b):
            self.buf.extend(b)

        def flush(self):
            return None

    # Use the receiver's actual handler subclass so expected_state +
    # received_event are wired up the way they are at runtime.
    rx = wrl.LoopbackReceiver.start()
    try:
        cls = rx.handler_cls
        # Construct without calling __init__ (which would try to
        # handle a real request); patch in only the attributes the
        # methods we exercise actually read.
        handler = cls.__new__(cls)
        handler.client_address = ("8.8.8.8", 12345)
        handler.path = "/cb"
        handler.headers = {"Content-Length": "10", "Origin": ""}
        handler.rfile = FakeRfile()
        handler.wfile = FakeWfile()

        sent = {}

        def fake_send_response(code):
            sent["code"] = code

        def fake_send_header(k, v):
            sent.setdefault("headers", []).append((k, v))

        def fake_end_headers():
            sent["ended"] = True

        handler.send_response = fake_send_response
        handler.send_header = fake_send_header
        handler.end_headers = fake_end_headers

        handler.do_POST()
        assert sent["code"] == 403
        # No payload should have been delivered to the waiting CLI.
        assert cls.received is None
        assert not cls.received_event.is_set()
    finally:
        rx.shutdown()


# ── S4: CORS preflight + headers on real responses ──────────────────


def _http_request(method: str, url: str, *, headers: dict | None = None,
                  body: bytes | None = None, timeout: float = 5.0):
    req = urllib.request.Request(
        url=url, method=method, data=body, headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.getcode(), resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b""), dict(e.headers or {})


def test_loopback_emits_cors_headers_when_allow_origin_set():
    """With ``allow_origin`` configured, both the OPTIONS preflight
    and the actual POST response must carry the CORS allow-list
    headers — otherwise the browser fetch can't run mode:"cors" and
    we're back to the S4 opaque-success bug.
    """
    origin = "http://localhost:8790"
    rx = wrl.LoopbackReceiver.start(allow_origin=origin)
    try:
        # OPTIONS preflight.
        code, _, headers = _http_request(
            "OPTIONS",
            rx.callback_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert code == 204
        assert headers.get("Access-Control-Allow-Origin") == origin
        assert "POST" in headers.get("Access-Control-Allow-Methods", "")
        assert "Content-Type" in headers.get("Access-Control-Allow-Headers", "")

        # Actual POST: deliver a valid token, response carries CORS too.
        payload = {
            "vault_jwt": "j",
            "account_id": "a",
            "project_id": "p",
            "raw_bek_b64": base64.urlsafe_b64encode(b"\x01" * 32).decode("ascii"),
            "state": rx.state,
        }
        result = {}

        def _send():
            code2, body, hdrs = _http_request(
                "POST",
                rx.callback_url,
                headers={"Origin": origin, "Content-Type": "application/json"},
                body=json.dumps(payload).encode("utf-8"),
            )
            result["code"] = code2
            result["headers"] = hdrs

        t = threading.Thread(target=_send, daemon=True)
        t.start()
        rx.wait_for_token(timeout_seconds=5.0)
        t.join(timeout=2.0)
        assert result["code"] == 200
        assert result["headers"].get("Access-Control-Allow-Origin") == origin
    finally:
        rx.shutdown()


def test_loopback_omits_cors_headers_when_no_allow_origin():
    """Defaults preserve the prior behavior: no allow_origin =>
    no CORS headers (so callers that haven't been updated to the new
    API don't accidentally start exposing the loopback to web origins
    they didn't configure)."""
    rx = wrl.LoopbackReceiver.start()
    try:
        code, _, headers = _http_request(
            "OPTIONS",
            rx.callback_url,
            headers={"Origin": "http://example.com"},
        )
        # OPTIONS still returns 204 (preflight) but with no allow-* headers.
        assert code == 204
        assert "Access-Control-Allow-Origin" not in headers
    finally:
        rx.shutdown()


def test_loopback_options_rejects_non_loopback_peer():
    """OPTIONS preflight must apply the same loopback peer check as
    POST so a stray off-host probe can't even discover that the
    server speaks CORS."""
    # Construct a handler manually (same trick as the POST test).
    rx = wrl.LoopbackReceiver.start(allow_origin="http://localhost:8790")
    try:
        cls = rx.handler_cls
        handler = cls.__new__(cls)
        handler.client_address = ("10.0.0.5", 12345)
        handler.path = "/cb"
        handler.headers = {"Origin": "http://localhost:8790"}

        sent = {}
        handler.send_response = lambda code: sent.setdefault("code", code)
        handler.send_header = lambda k, v: sent.setdefault("headers", []).append((k, v))
        handler.end_headers = lambda: sent.setdefault("ended", True)
        handler.wfile = type("F", (), {"write": lambda self, b: None,
                                        "flush": lambda self: None})()

        handler.do_OPTIONS()
        assert sent["code"] == 403
    finally:
        rx.shutdown()


# Avoid pyflakes unused-import in older Python versions.
_ = time


# ── decrypt_blob_with_bek ─────────────────────────────────────────────


def test_decrypt_blob_round_trip():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    bek = os.urandom(32)
    plaintext = b"the test of all tests is whether anyone reads this far"
    nonce = os.urandom(12)
    ct = AESGCM(bek).encrypt(nonce, plaintext, None)
    blob = nonce + ct

    out = wr._decrypt_blob_with_bek(blob, bek)
    assert out == plaintext


def test_decrypt_blob_rejects_short_input():
    with pytest.raises(wr.RestoreError):
        wr._decrypt_blob_with_bek(b"\x00" * 10, b"\x00" * 32)


def test_decrypt_blob_rejects_wrong_key():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    bek = os.urandom(32)
    other = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(bek).encrypt(nonce, b"hi", None)
    with pytest.raises(wr.RestoreError):
        wr._decrypt_blob_with_bek(nonce + ct, other)


# ── write_restored_bytes ──────────────────────────────────────────────


def _make_export_frame(members: dict[str, bytes]) -> bytes:
    out = bytearray()
    out.extend(struct.pack(">I", len(members)))
    for name, data in sorted(members.items()):
        nb = name.encode("utf-8")
        out.extend(struct.pack(">I", len(nb)))
        out.extend(nb)
        out.extend(struct.pack(">I", len(data)))
        out.extend(data)
    return bytes(out)


def test_write_restored_bytes_unpacks_export_frame(tmp_path):
    members = {
        "manifest.json": b'{"hello":"world"}',
        "body/encrypted.bin": b"not really encrypted in the test",
    }
    plaintext = _make_export_frame(members)
    files, raw, notes = wr._write_restored_bytes(
        plaintext=plaintext,
        out_dir=tmp_path,
        project_id="01HX",
    )
    assert raw is None  # frame unpacked successfully
    written = {p.relative_to(tmp_path).as_posix(): p.read_bytes() for p in files}
    assert written == members
    assert any("unpacked" in n for n in notes)


def test_write_restored_bytes_falls_back_to_raw_blob(tmp_path):
    plaintext = b"\x00\x00\x00\x00not an export frame"
    files, raw, notes = wr._write_restored_bytes(
        plaintext=plaintext,
        out_dir=tmp_path,
        project_id="01HX",
    )
    assert raw is not None
    assert len(files) == 1 and files[0] == raw
    assert raw.read_bytes() == plaintext
    assert any("raw bytes" in n for n in notes)


# ── restore_with_token end-to-end ─────────────────────────────────────


def test_restore_with_token_full_flow(monkeypatch, tmp_path):
    """Mock the HTTP layer + compose a full restore."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Build a known plaintext + matching ciphertext + BEK.
    bek = os.urandom(32)
    plaintext = _make_export_frame({"keys/local.public": b"did:key:zABC"})
    nonce = os.urandom(12)
    ct = AESGCM(bek).encrypt(nonce, plaintext, None)
    blob = nonce + ct

    captured = {}

    def fake_request(*, method, url, bearer, timeout=30.0):
        captured["url"] = url
        captured["bearer"] = bearer
        body = json.dumps({
            "project_id": "01HXPROJ",
            "ciphertext_b64": base64.b64encode(blob).decode("ascii"),
        }).encode("utf-8")
        return 200, body, {"content-type": "application/json"}

    monkeypatch.setattr(wr, "_http_request", fake_request)

    token = wrl.TransferToken(
        vault_jwt="fake.jwt.x",
        account_id="01HXACCT",
        project_id="01HXPROJ",
        raw_bek_b64=base64.urlsafe_b64encode(bek).decode("ascii"),
    )
    result = wr._restore_with_token(
        vault_url="http://127.0.0.1:9999",
        token=token,
        out_dir=tmp_path,
    )
    assert result.project_id == "01HXPROJ"
    assert "encrypted-blob" in captured["url"]
    assert captured["bearer"] == "fake.jwt.x"
    assert any(p.name == "local.public" for p in result.files_written)


def test_restore_with_token_rejects_bad_bek_length(monkeypatch, tmp_path):
    token = wrl.TransferToken(
        vault_jwt="x",
        account_id="y",
        project_id="z",
        raw_bek_b64=base64.urlsafe_b64encode(b"too-short").decode("ascii"),
    )
    with pytest.raises(wr.RestoreError) as exc:
        wr._restore_with_token(
            vault_url="http://127.0.0.1:9999",
            token=token,
            out_dir=tmp_path,
        )
    assert "expected 32" in str(exc.value)


def test_restore_with_token_surfaces_404(monkeypatch, tmp_path):
    def fake_request(*, method, url, bearer, timeout=30.0):
        return 404, b'{"detail":"missing"}', {}

    monkeypatch.setattr(wr, "_http_request", fake_request)
    token = wrl.TransferToken(
        vault_jwt="x",
        account_id="y",
        project_id="z",
        raw_bek_b64=base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii"),
    )
    with pytest.raises(wr.RestoreError) as exc:
        wr._restore_with_token(
            vault_url="http://127.0.0.1:9999",
            token=token,
            out_dir=tmp_path,
        )
    assert "404" in str(exc.value) or "not found" in str(exc.value).lower()


# ── _try_unpack_export_frame edge cases ───────────────────────────────


def test_unpack_returns_none_for_bad_frame():
    # Member count of 0 -> rejected.
    assert wr._try_unpack_export_frame(b"\x00\x00\x00\x00") is None
    # Truncated frame -> rejected.
    bad = struct.pack(">I", 1) + struct.pack(">I", 999) + b"x"
    assert wr._try_unpack_export_frame(bad) is None
    # Member count too large -> rejected.
    huge = struct.pack(">I", 9999999)
    assert wr._try_unpack_export_frame(huge) is None


# ── b64decode loose ───────────────────────────────────────────────────


def test_b64decode_loose_accepts_url_safe_and_padded():
    raw = b"\xfe\xff\xff"
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert wr._b64decode_loose(std) == raw
    assert wr._b64decode_loose(url) == raw
