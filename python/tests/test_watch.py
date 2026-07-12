"""Tests for tn.watch — the async-iterable library verb and CLI.

Note: pytest-asyncio is not currently installed in this project.
The async tests below wrap asyncio.run() in sync test functions so they
run without any asyncio pytest plugin. If pytest-asyncio is added in the
future, the functions can be converted to `async def` with
`@pytest.mark.asyncio`.
"""
from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import asyncio
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn._entry import VerifyError
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.security_audit import TnSecurityWarning
from tn.signing import _signature_b64


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Library verb: tn.watch()
# ---------------------------------------------------------------------------


def _tamper_signature(log_path: Path, event_type: str) -> None:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        envelope = json.loads(line)
        if envelope.get("event_type") == event_type:
            envelope["signature"] = "AAAA"
            lines[index] = json.dumps(envelope, separators=(",", ":"))
            break
    else:
        raise AssertionError(f"missing event_type {event_type!r}")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _append_entry_shape_invalid_row(log_path: Path) -> None:
    device = tn.current_config().device
    envelope = {
        "timestamp": "not-a-timestamp",
        "event_type": "watch.shape.invalid",
        "level": "info",
        "device_identity": device.did,
        "sequence": 1,
        "event_id": "01J00000000000000000000999",
        "prev_hash": ZERO_HASH,
    }
    row_hash = _compute_row_hash(
        device_identity=device.did,
        timestamp=envelope["timestamp"],
        event_id=envelope["event_id"],
        event_type=envelope["event_type"],
        level=envelope["level"],
        prev_hash=envelope["prev_hash"],
        public_fields={},
        groups={},
    )
    envelope["row_hash"] = row_hash
    envelope["signature"] = _signature_b64(device.sign(row_hash.encode("ascii")))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(envelope, separators=(",", ":")) + "\n")


def test_watch_defaults_to_auto_and_exposes_read_policy_controls() -> None:
    parameters = inspect.signature(tn.watch).parameters
    assert parameters["verify"].default == "auto"
    assert parameters["require_signature"].default is None
    assert parameters["allow_unauthenticated"].default is None
    assert parameters["trusted_writers"].default is None
    assert parameters["allow_unknown_writers"].default is False


def test_watch_initial_drain_uses_read_decisions_and_full_reasons(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    tn.info("watch.good")
    tn.info("watch.bad")
    log_path = tn.current_config().resolve_log_path()
    _tamper_signature(log_path, "watch.bad")

    with pytest.raises(VerifyError) as read_error:
        list(tn.read())

    async def drain() -> None:
        async for _ in tn.watch(since="start", poll_interval=0.01):
            pass

    with pytest.raises(VerifyError) as watch_error:
        asyncio.run(asyncio.wait_for(drain(), timeout=2.0))

    assert watch_error.value.reason == read_error.value.reason == "signature_invalid"
    assert watch_error.value.reasons == read_error.value.reasons == ["signature_invalid"]


def test_watch_post_gate_entry_shape_failure_is_record_invalid(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    _append_entry_shape_invalid_row(tn.current_config().resolve_log_path())

    async def first() -> Any:
        return await anext(tn.watch(since="start", poll_interval=0.01))

    with pytest.raises(VerifyError) as raised:
        asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert raised.value.reason == "record_invalid"
    assert raised.value.reasons == ["record_invalid"]
    assert raised.value.sequence == 1
    assert raised.value.event_type == "watch.shape.invalid"


def test_watch_disabled_does_not_hide_post_gate_entry_shape_failure(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    _append_entry_shape_invalid_row(tn.current_config().resolve_log_path())

    async def first() -> Any:
        return await anext(
            tn.watch(since="start", verify=False, poll_interval=0.01),
        )

    with pytest.warns(TnSecurityWarning), pytest.raises(Exception) as raised:
        asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert not isinstance(raised.value, TimeoutError)


def test_watch_skip_observes_post_gate_shape_failure_and_continues(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    log_path = tn.current_config().resolve_log_path()
    _append_entry_shape_invalid_row(log_path)
    tn.info("watch.shape.after", marker="visible")

    async def first() -> Any:
        return await anext(
            tn.watch(since="start", verify="skip", poll_interval=0.01),
        )

    entry = asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert entry.event_type == "watch.shape.after"
    skipped = [
        item
        for item in tn.read(log="admin")
        if item.event_type == "tn.read.tampered_row_skipped"
    ]
    assert len(skipped) == 1
    assert skipped[0].fields["invalid_reasons"] == ["record_invalid"]


def test_watch_later_poll_uses_read_decisions_and_reasons(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    log_path = tn.current_config().resolve_log_path()

    async def later_rejection() -> None:
        stream = tn.watch(poll_interval=0.2)
        pending = asyncio.create_task(anext(stream))
        await asyncio.sleep(0.05)
        tn.info("watch.bad.later")
        _tamper_signature(log_path, "watch.bad.later")
        await pending

    with pytest.raises(VerifyError) as watch_error:
        asyncio.run(asyncio.wait_for(later_rejection(), timeout=2.0))
    with pytest.raises(VerifyError) as read_error:
        list(tn.read())

    assert watch_error.value.reason == read_error.value.reason == "signature_invalid"
    assert watch_error.value.reasons == read_error.value.reasons == ["signature_invalid"]


def test_watch_skip_advances_past_rejected_row_and_yields_later_polls(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    tn.info("watch.first")
    tn.info("watch.rejected")
    tn.info("watch.after_rejection")
    log_path = tn.current_config().resolve_log_path()
    _tamper_signature(log_path, "watch.rejected")
    seen: list[str] = []

    async def run() -> tuple[dict[str, object], str]:
        stream = tn.watch(
            since="start",
            verify="skip",
            poll_interval=0.01,
        )
        seen.append((await asyncio.wait_for(anext(stream), timeout=2.0)).event_type)
        seen.append((await asyncio.wait_for(anext(stream), timeout=2.0)).event_type)
        tn.info("watch.later")
        seen.append((await asyncio.wait_for(anext(stream), timeout=2.0)).event_type)
        saved = stream.cursor.to_dict()
        source_cursor = next(iter(saved["sources"].values()))
        scanned_offset = source_cursor["value"]
        assert scanned_offset == str(log_path.stat().st_size)
        await stream.aclose()

        tn.info("watch.resumed")
        resumed = tn.watch(
            cursor=saved,
            verify="skip",
            poll_interval=0.01,
        )
        seen.append((await asyncio.wait_for(anext(resumed), timeout=2.0)).event_type)
        await resumed.aclose()
        return saved, scanned_offset

    saved, scanned_offset = asyncio.run(run())
    assert saved["version"] == 1
    assert scanned_offset.isdecimal()
    assert seen == [
        "watch.first",
        "watch.after_rejection",
        "watch.later",
        "watch.resumed",
    ]


def test_watch_cursor_validation_and_multisource_ids(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    sources = tmp_path / "sources"
    sources.mkdir()
    paths = [sources / "a.ndjson", sources / "b.ndjson"]
    for path in paths:
        path.write_bytes(b"")

    stream = tn.watch(log=str(sources / "{event_type}.ndjson"), since="start")
    from tn._watch_impl import canonical_file_source_id

    assert set(stream.cursor.sources) == {
        canonical_file_source_id(path) for path in paths
    }
    assert all(source.value == "0" for source in stream.cursor.sources.values())
    asyncio.run(stream.aclose())

    valid_source_id = "source:sha256:" + "0" * 64
    invalid_cursors = [
        {"version": 2, "sources": {}},
        {
            "version": 1,
            "sources": {"not-a-source-id": {"kind": "byte_offset", "value": "0"}},
        },
        {
            "version": 1,
            "sources": {valid_source_id: {"kind": "rows", "value": "0"}},
        },
        {
            "version": 1,
            "sources": {valid_source_id: {"kind": "byte_offset", "value": 0}},
        },
        {
            "version": 1,
            "sources": {valid_source_id: {"kind": "byte_offset", "value": "-1"}},
        },
        {"version": 1, "sources": {}, "extra": True},
    ]
    for cursor in invalid_cursors:
        with pytest.raises(ValueError):
            tn.watch(cursor=cursor)

    with pytest.raises(ValueError, match="cursor.*since"):
        tn.watch(cursor={"version": 1, "sources": {}}, since="start")


def test_watch_rejects_before_group_decrypt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    tn.info("watch.secret", secret="must-not-open")
    cfg = tn.current_config()
    _tamper_signature(cfg.resolve_log_path(), "watch.secret")
    cipher_type = type(cfg.groups["default"].cipher)
    original_decrypt = cipher_type.decrypt
    calls = 0

    def spy_decrypt(self: Any, ciphertext: bytes, aad: bytes) -> bytes:
        nonlocal calls
        calls += 1
        return original_decrypt(self, ciphertext, aad)

    monkeypatch.setattr(cipher_type, "decrypt", spy_decrypt)

    async def first() -> Any:
        return await anext(tn.watch(since="start", poll_interval=0.01))

    with pytest.raises(VerifyError):
        asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert calls == 0


def test_watch_raw_includes_read_validity_metadata(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    tn.info("watch.raw", marker=True)

    async def first() -> dict[str, Any]:
        return await anext(
            tn.watch(since="start", raw=True, poll_interval=0.01),
        )

    row = asyncio.run(first())
    assert row["event_type"] == "watch.raw"
    assert row["_valid"] == {
        "signature": True,
        "row_hash": True,
        "chain": True,
        "writer_authenticated": True,
        "writer_authorized": True,
        "reasons": [],
    }


def test_watch_as_recipient_matches_read_source_controls(tmp_path: Path) -> None:
    log_path = tmp_path / "publisher.ndjson"
    tn.init(tmp_path / "tn.yaml", cipher="jwe", log_path=log_path)
    tn.info("watch.recipient", secret="reader-visible")
    keystore = tn.current_config().keystore

    async def first() -> Any:
        stream = tn.watch(
            log=log_path,
            as_recipient=keystore,
            group="default",
            since="start",
            poll_interval=0.01,
        )
        return await asyncio.wait_for(anext(stream), timeout=2.0)

    entry = asyncio.run(first())
    assert entry.event_type == "watch.recipient"
    assert entry.fields["secret"] == "reader-visible"


def test_watch_yields_new_appends(tmp_path):
    """tn.watch() yields entries appended after the watcher starts."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)

    seen: list[str] = []

    async def reader():
        async for entry in tn.watch(poll_interval=0.05):
            seen.append(entry.event_type)
            if len(seen) >= 2:
                break

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.info("a")
        tn.info("b")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    assert "a" in seen
    assert "b" in seen


def test_watch_default_main_log_only(tmp_path):
    """Default ``tn.watch()`` tails the main log only.

    Admin events (``tn.*``) live in a separate log since the
    runtime-correctness work split them off. They must be addressed
    explicitly via ``log="admin"`` (or an equivalent path) — the
    default surface does NOT merge them in. This regression-guards
    against re-introducing the previous "admin visible by default"
    behavior.
    """
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)

    seen: list[str] = []

    async def reader():
        async for entry in tn.watch(poll_interval=0.05):
            seen.append(entry.event_type)
            if "user.thing" in seen:
                # Give one more tick to confirm the admin event does
                # NOT arrive on the default surface, then stop.
                await asyncio.sleep(0.3)
                return

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.log("tn.test.admin_default", level="info", marker="alpha")
        tn.info("user.thing", marker="beta")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    assert "user.thing" in seen, f"user event missing; saw {seen}"
    assert "tn.test.admin_default" not in seen, (
        f"admin event leaked into default tn.watch(); saw {seen}"
    )


def test_watch_admin_alias_addresses_admin_log(tmp_path):
    """``tn.watch(log='admin')`` tails the admin log explicitly.

    Confirms the symmetric-by-explicit-address design: admin events
    are reachable via the ``"admin"`` alias on either verb, and
    main-log user events are NOT merged into that admin surface.
    """
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)

    seen: list[str] = []

    async def reader():
        async for entry in tn.watch(log="admin", poll_interval=0.05):
            seen.append(entry.event_type)
            if any(t.startswith("tn.test.") for t in seen):
                return

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.info("user.thing", marker="ignored")
        tn.log("tn.test.admin_alias", level="info", marker="seen")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    assert "tn.test.admin_alias" in seen, (
        f"admin event missing via log='admin'; saw {seen}"
    )
    assert "user.thing" not in seen, (
        f"main-log event leaked into log='admin' tail; saw {seen}"
    )


def test_watch_since_start_replays_existing(tmp_path):
    """tn.watch(since='start') replays entries written before the watcher started."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)
    tn.info("pre.1")
    tn.info("pre.2")

    seen: list[str] = []

    async def reader():
        # Break when we've seen both pre-events. tn.init() emits admin
        # envelopes (tn.ceremony.init / tn.group.added) into the same
        # log, so a fixed counter would race those — assert on
        # observation, not position.
        async for entry in tn.watch(since="start", poll_interval=0.05):
            seen.append(entry.event_type)
            if "pre.1" in seen and "pre.2" in seen:
                break

    async def run():
        task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        tn.info("post.1")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(run())
    assert "pre.1" in seen
    assert "pre.2" in seen


# ---------------------------------------------------------------------------
# CLI compatibility: existing --once test preserved
# ---------------------------------------------------------------------------


def test_watch_once_emits_entry_shape(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.info("order.created", amount=100, order_id="A100")
    tn.flush_and_close()

    # Run `python -m tn.watch --once --since start` and parse each line.
    result = subprocess.run(
        [sys.executable, "-m", "tn.watch", str(yaml), "--once", "--since", "start"],
        cwd=str(_HERE.parent),
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    assert lines, f"no output from tn.watch: stderr={result.stderr}"

    # Find the order.created line (ceremony.init may also appear; that's OK).
    order_lines = [l for l in lines if '"order.created"' in l]
    assert order_lines, f"no order.created in output: {lines!r}"

    parsed = json.loads(order_lines[0])
    # Shape: Entry.model_dump_json keys present.
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "event_type" in parsed
    assert "fields" in parsed
    assert "did" in parsed
    assert "row_hash" in parsed
    assert "signature" in parsed
    assert parsed["event_type"] == "order.created"
    assert parsed["fields"]["amount"] == 100
    assert parsed["fields"]["order_id"] == "A100"
    # Crypto plumbing is preserved on Entry.model_dump_json so chain
    # tools / forensics keep working. (The previous shape stripped it;
    # 0.4.0a1 surfaces it as typed Entry attributes.)
    assert parsed["signature"]
    assert parsed["row_hash"].startswith("sha256:")
    assert parsed["prev_hash"].startswith("sha256:")
    # The on-disk ciphertext block stays out of the dump — only raw=True
    # surfaces that.
    assert "ciphertext" not in json.dumps(parsed)
