"""tn.read(verify='skip') survives parse errors mid-stream.

Covers a high-severity finding filed after 0.4.2a2: ``verify='skip'``
correctly skipped verify failures (signature, row_hash, chain) but
the iterator TERMINATED after the first malformed entry (e.g.
corrupt base64 ciphertext from a partial write or disk corruption).
Production read mode needs to be resilient to any per-entry failure.

The Rust read path (``read_from`` /
``read_from_with_validity``) now wraps each row's body so per-row
errors (JSON parse, base64 decode, post-decrypt plaintext json)
yield a sentinel envelope (``event_type == "<parse-error>"``) and
continue to the next line. The Python ``tn.read`` verify loop
recognises the sentinel and routes it to ``stats.skipped_parse``.
"""
from __future__ import annotations

import base64
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import tn
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.signing import DeviceKey, _signature_b64


@pytest.fixture(params=["{not-json", "{}"], ids=["invalid-json", "invalid-shape"])
def three_entries_with_bad_middle(tmp_path: Path, request):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    os.environ["TN_NO_STDOUT"] = "1"
    import tn

    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.init()
    tn.info("a", x=1)
    tn.info("b", x=2)
    tn.info("c", x=3)
    tn.flush_and_close()

    log = tmp_path / ".tn" / tmp_path.name / "logs" / "default.ndjson"
    lines = log.read_text().splitlines()
    assert len(lines) >= 3, f"expected 3 user entries, got {lines!r}"
    lines[1] = request.param
    log.write_text("\n".join(lines) + "\n")

    tn.init()  # rebind runtime against the mutated file
    try:
        yield tn
    finally:
        tn.flush_and_close()
        os.chdir(cwd)


def _assert_transport_skip_observability(result, seen):
    rows = list(result)

    assert [row["event_type"] for row in rows] == ["a", "c"]
    assert [row["_valid"]["chain"] for row in rows] == [True, True]
    assert result.stats.yielded == 2
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 0
    assert result.stats.skipped_reasons == ["record_invalid"]
    assert len(seen) == 1
    sentinel_env, reason = seen[0]
    assert sentinel_env.get("event_type") == "<parse-error>"
    assert sentinel_env["_valid"]["reasons"] == ["record_invalid"]
    assert reason == "record_invalid"


def _sealed_envelope(
    device: DeviceKey,
    *,
    event_type: str,
    sequence: int,
    ciphertext: bytes,
    row_hash_valid: bool = True,
):
    group = {
        "ciphertext": base64.standard_b64encode(ciphertext).decode("ascii"),
        "field_hashes": {},
    }
    row_hash = _compute_row_hash(
        device_identity=device.did,
        timestamp="2026-07-12T12:00:00.000000Z",
        event_id=f"01J0000000000000000000000{sequence}",
        event_type=event_type,
        level="info",
        prev_hash=ZERO_HASH,
        public_fields={},
        groups={
            "default": {
                "ciphertext": ciphertext,
                "field_hashes": {},
            },
        },
    )
    if not row_hash_valid:
        row_hash = "sha256:" + "f" * 64
    return {
        "timestamp": "2026-07-12T12:00:00.000000Z",
        "event_type": event_type,
        "level": "info",
        "device_identity": device.did,
        "sequence": sequence,
        "event_id": f"01J0000000000000000000000{sequence}",
        "prev_hash": ZERO_HASH,
        "row_hash": row_hash,
        "signature": _signature_b64(device.sign(row_hash.encode("ascii"))),
        "default": group,
    }


@pytest.fixture(
    params=[b"not-json", b"\xff", b"[]"],
    ids=["invalid-json", "invalid-utf8", "invalid-shape"],
)
def authenticated_bad_plaintext(tmp_path: Path, monkeypatch, request):
    class _SpyCipher:
        def __init__(self, bad_payload: bytes):
            self.bad_payload = bad_payload
            self.calls: list[bytes] = []

        def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
            del aad
            self.calls.append(ciphertext)
            if ciphertext == b"bad-plaintext":
                return self.bad_payload
            return b'{"marker":"later"}'

    device = DeviceKey.generate()
    spy = _SpyCipher(request.param)
    log_path = tmp_path / "local.ndjson"
    envelopes = [
        _sealed_envelope(
            device,
            event_type="rejected.before-decrypt",
            sequence=1,
            ciphertext=b"must-not-decrypt",
            row_hash_valid=False,
        ),
        _sealed_envelope(
            device,
            event_type="bad.plaintext",
            sequence=2,
            ciphertext=b"bad-plaintext",
        ),
        _sealed_envelope(
            device,
            event_type="later.clean",
            sequence=3,
            ciphertext=b"later-clean",
        ),
    ]
    log_path.write_text(
        "".join(json.dumps(envelope) + "\n" for envelope in envelopes),
        encoding="utf-8",
    )
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    keystore.mkdir()
    (keystore / "default.btn.mykit").write_bytes(b"test-spy-kit")
    cfg = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        sign=True,
        chain=True,
        public_fields=[],
        groups={"default": SimpleNamespace(cipher=spy)},
        resolve_log_path=lambda: log_path,
    )

    read_module = importlib.import_module("tn.read")
    reader_module = importlib.import_module("tn.reader")
    monkeypatch.setattr(tn, "_dispatch_rt", None)
    monkeypatch.setattr(tn, "_maybe_autoinit_load_only", lambda: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)
    monkeypatch.setattr(read_module, "_resolve_read_source", lambda *args: None)
    monkeypatch.setattr(
        reader_module,
        "_discover_keybag_ciphers",
        lambda path: {"default": [spy]},
    )
    monkeypatch.setattr(
        reader_module._cipher.BtnGroupCipher,
        "load",
        classmethod(lambda cls, path, group: spy),
    )
    return SimpleNamespace(cfg=cfg, log_path=log_path, spy=spy)


def _assert_authenticated_plaintext_parse_contract(result, seen, spy):
    rows = list(result)

    assert [row["event_type"] for row in rows] == ["later.clean"]
    assert result.stats.yielded == 1
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 1
    assert result.stats.skipped_reasons == [
        "row_hash_invalid",
        "record_invalid",
    ]
    assert [reason for _envelope, reason in seen] == [
        "row_hash_invalid",
        "record_invalid",
    ]
    parse_envelope = seen[1][0]
    assert parse_envelope["event_type"] == "<parse-error>"
    assert parse_envelope["_valid"]["reasons"] == ["record_invalid"]
    assert "default" not in parse_envelope
    assert spy.calls == [b"bad-plaintext", b"later-clean"]


@pytest.fixture()
def candidate_precedence_harness(tmp_path: Path, monkeypatch):
    reader_module = importlib.import_module("tn.reader")

    class _OutcomeCipher:
        def __init__(self, outcome: str):
            self.outcome = outcome
            self.calls = 0

        def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
            del ciphertext, aad
            self.calls += 1
            if self.outcome == "not-recipient":
                raise reader_module._cipher.NotARecipientError("not enrolled")
            if self.outcome == "failure":
                raise RuntimeError("authenticated open failed")
            return b'{"marker":"success"}'

    def make_cipher(outcome: str):
        return _OutcomeCipher(outcome)

    device = DeviceKey.generate()
    envelope = _sealed_envelope(
        device,
        event_type="candidate.precedence",
        sequence=1,
        ciphertext=b"candidate-ciphertext",
    )
    line = json.dumps(envelope)
    log_path = tmp_path / "local.ndjson"
    log_path.write_text(line + "\n", encoding="utf-8")
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    keystore.mkdir()
    (keystore / "default.btn.mykit").write_bytes(b"test-btn-kit")
    (keystore / "default.jwe.mykey").write_bytes(b"test-jwe-key")
    local_cipher = make_cipher("failure")
    cfg = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        sign=True,
        chain=True,
        public_fields=[],
        groups={"default": SimpleNamespace(cipher=local_cipher)},
        resolve_log_path=lambda: log_path,
    )

    read_module = importlib.import_module("tn.read")
    monkeypatch.setattr(tn, "_dispatch_rt", None)
    monkeypatch.setattr(tn, "_maybe_autoinit_load_only", lambda: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)
    monkeypatch.setattr(read_module, "_resolve_read_source", lambda *args: None)
    return SimpleNamespace(
        cfg=cfg,
        line=line,
        local_cipher=local_cipher,
        log_path=log_path,
        make_cipher=make_cipher,
        read_module=read_module,
        reader_module=reader_module,
    )


def _assert_aad_invalid_skip(result, seen):
    assert list(result) == []
    assert result.stats.yielded == 0
    assert result.stats.skipped_parse == 0
    assert result.stats.skipped_verify == 1
    assert result.stats.skipped_reasons == ["aad_invalid"]
    assert [reason for _envelope, reason in seen] == ["aad_invalid"]
    assert seen[0][0]["_valid"]["reasons"][0] == "aad_invalid"


def _patch_recipient_candidates(monkeypatch, harness, first, second):
    monkeypatch.setattr(
        harness.reader_module._cipher.BtnGroupCipher,
        "load",
        classmethod(lambda cls, path, group: first),
    )
    monkeypatch.setattr(
        harness.reader_module._cipher.JWEGroupCipher,
        "load",
        classmethod(lambda cls, path, group: second),
    )


def test_skip_yields_clean_entries_around_parse_error(
    three_entries_with_bad_middle,
):
    """The spec the tester filed: with one parse-failing entry
    between two clean ones, ``tn.read(verify='skip', on_skip=cb)``
    yields BOTH clean entries and fires ``cb`` once for the bad one."""
    tn = three_entries_with_bad_middle
    seen = []
    result = tn.read(
        verify="skip",
        on_skip=lambda env, reason: seen.append((env, reason)),
    )
    out = [e.event_type for e in result]

    assert out == ["a", "c"], (
        f"expected clean entries on either side of the parse error to "
        f"yield, got {out!r}"
    )
    assert result.stats.yielded == 2
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 0
    assert len(seen) == 1
    sentinel_env, reason = seen[0]
    assert sentinel_env.get("event_type") == "<parse-error>"
    assert reason == "record_invalid"
    assert sentinel_env["_valid"]["reasons"] == ["record_invalid"]


def test_verify_true_fires_callback_then_raises_on_parse_error(
    three_entries_with_bad_middle,
):
    """``verify=True`` still raises on parse errors, but the
    ``on_skip`` callback fires once before the exception so callers
    can log/alert before the read exits."""
    tn = three_entries_with_bad_middle
    seen = []
    result = tn.read(
        verify=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )
    with pytest.raises(Exception, match=r"parse|chain|failed"):
        list(result)
    assert len(seen) == 1, (
        f"observer should fire exactly once before raise; got {seen!r}"
    )
    assert seen[0][1] == "record_invalid"


def test_stats_count_distinguishes_parse_from_verify(
    three_entries_with_bad_middle,
):
    """The headline stats split: parse failures count toward
    ``skipped_parse``, not ``skipped_verify``. Lets callers tell
    "the bytes are malformed" from "verify failed."""
    tn = three_entries_with_bad_middle
    result = tn.read(verify="skip")
    list(result)
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_verify == 0
    assert "record_invalid" in result.stats.skipped_reasons


def test_explicit_log_keybag_survives_bad_middle_row(
    three_entries_with_bad_middle,
):
    tn = three_entries_with_bad_middle
    seen = []
    result = tn.read(
        log=tn.current_config().resolve_log_path(),
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_transport_skip_observability(result, seen)


def test_read_as_recipient_survives_bad_middle_row(
    three_entries_with_bad_middle,
):
    tn = three_entries_with_bad_middle
    cfg = tn.current_config()
    seen = []
    result = tn.read(
        log=cfg.resolve_log_path(),
        as_recipient=cfg.keystore,
        group="default",
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_transport_skip_observability(result, seen)


def test_configured_network_keybag_survives_bad_middle_row(
    three_entries_with_bad_middle,
    monkeypatch,
):
    tn = three_entries_with_bad_middle
    read_module = importlib.import_module("tn.read")
    lines = tn.current_config().resolve_log_path().read_text().splitlines()

    class _NetworkSource:
        def reader(self, options, *, selection, filter):
            del options, selection, filter
            return iter(
                (f"memory://events/{index}", line)
                for index, line in enumerate(lines)
            )

    monkeypatch.setattr(
        read_module,
        "_resolve_read_source",
        lambda cfg, runtime: _NetworkSource(),
    )
    seen = []
    result = tn.read(
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_transport_skip_observability(result, seen)


def test_local_authenticated_bad_plaintext_is_record_invalid(
    authenticated_bad_plaintext,
):
    harness = authenticated_bad_plaintext
    seen = []
    result = tn.read(
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_authenticated_plaintext_parse_contract(result, seen, harness.spy)


def test_keybag_authenticated_bad_plaintext_is_record_invalid(
    authenticated_bad_plaintext,
):
    harness = authenticated_bad_plaintext
    seen = []
    result = tn.read(
        log=harness.log_path,
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_authenticated_plaintext_parse_contract(result, seen, harness.spy)


def test_recipient_authenticated_bad_plaintext_is_record_invalid(
    authenticated_bad_plaintext,
):
    harness = authenticated_bad_plaintext
    seen = []
    result = tn.read(
        log=harness.log_path,
        as_recipient=harness.cfg.keystore,
        group="default",
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_authenticated_plaintext_parse_contract(result, seen, harness.spy)


def test_local_candidate_precedence_baseline_is_aad_invalid(
    candidate_precedence_harness,
):
    harness = candidate_precedence_harness
    seen = []
    result = tn.read(
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_aad_invalid_skip(result, seen)
    assert harness.local_cipher.calls == 1


def test_explicit_keybag_candidate_failure_beats_not_recipient(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    not_recipient = harness.make_cipher("not-recipient")
    failure = harness.make_cipher("failure")
    monkeypatch.setattr(
        harness.reader_module,
        "_discover_keybag_ciphers",
        lambda path: {"default": [not_recipient, failure]},
    )
    seen = []
    result = tn.read(
        log=harness.log_path,
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_aad_invalid_skip(result, seen)
    assert (not_recipient.calls, failure.calls) == (1, 1)


def test_network_candidate_failure_beats_later_not_recipient(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    failure = harness.make_cipher("failure")
    not_recipient = harness.make_cipher("not-recipient")
    monkeypatch.setattr(
        harness.reader_module,
        "_discover_keybag_ciphers",
        lambda path: {"default": [failure, not_recipient]},
    )

    class _NetworkSource:
        def reader(self, options, *, selection, filter):
            del options, selection, filter
            return iter([("memory://candidate/1", harness.line)])

    monkeypatch.setattr(
        harness.read_module,
        "_resolve_read_source",
        lambda cfg, runtime: _NetworkSource(),
    )
    seen = []
    result = tn.read(
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_aad_invalid_skip(result, seen)
    assert (failure.calls, not_recipient.calls) == (1, 1)


def test_recipient_candidate_failure_beats_not_recipient(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    not_recipient = harness.make_cipher("not-recipient")
    failure = harness.make_cipher("failure")
    _patch_recipient_candidates(monkeypatch, harness, not_recipient, failure)
    seen = []
    result = tn.read(
        log=harness.log_path,
        as_recipient=harness.cfg.keystore,
        group="default",
        verify="skip",
        raw=True,
        on_skip=lambda env, reason: seen.append((env, reason)),
    )

    _assert_aad_invalid_skip(result, seen)
    assert seen[0][0]["_valid"]["reasons"] == [
        "aad_invalid",
        "not_a_recipient",
    ]
    assert (not_recipient.calls, failure.calls) == (1, 1)


def test_keybag_all_not_recipient_preserves_no_read_key(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    first = harness.make_cipher("not-recipient")
    second = harness.make_cipher("not-recipient")
    monkeypatch.setattr(
        harness.reader_module,
        "_discover_keybag_ciphers",
        lambda path: {"default": [first, second]},
    )

    rows = list(
        harness.reader_module._lines_with_keybag(
            iter([("memory://candidate/1", harness.line)]),
            harness.cfg.keystore,
        ),
    )

    assert rows[0]["plaintext"] == {"default": {"$no_read_key": True}}
    assert rows[0]["valid"]["aad"] is True


def test_recipient_all_not_recipient_preserves_no_read_key(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    first = harness.make_cipher("not-recipient")
    second = harness.make_cipher("not-recipient")
    _patch_recipient_candidates(monkeypatch, harness, first, second)

    rows = list(
        harness.reader_module.read_as_recipient(
            harness.log_path,
            harness.cfg.keystore,
            group="default",
        ),
    )

    assert rows[0]["plaintext"] == {"default": {"$no_read_key": True}}
    assert rows[0]["valid"]["aad"] is True


def test_keybag_success_after_not_recipient_is_preserved(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    not_recipient = harness.make_cipher("not-recipient")
    success = harness.make_cipher("success")
    monkeypatch.setattr(
        harness.reader_module,
        "_discover_keybag_ciphers",
        lambda path: {"default": [not_recipient, success]},
    )

    rows = list(
        harness.reader_module._lines_with_keybag(
            iter([("memory://candidate/1", harness.line)]),
            harness.cfg.keystore,
        ),
    )

    assert rows[0]["plaintext"] == {"default": {"marker": "success"}}
    assert rows[0]["valid"]["aad"] is True


def test_recipient_success_after_failure_is_preserved(
    candidate_precedence_harness,
    monkeypatch,
):
    harness = candidate_precedence_harness
    failure = harness.make_cipher("failure")
    success = harness.make_cipher("success")
    _patch_recipient_candidates(monkeypatch, harness, failure, success)

    rows = list(
        harness.reader_module.read_as_recipient(
            harness.log_path,
            harness.cfg.keystore,
            group="default",
        ),
    )

    assert rows[0]["plaintext"] == {"default": {"marker": "success"}}
    assert rows[0]["valid"]["aad"] is True
