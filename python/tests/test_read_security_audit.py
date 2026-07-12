from __future__ import annotations

import asyncio
import importlib
import warnings
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import tn
from tn._entry import VerifyError
from tn.security_audit import TnSecurityWarning
from tn.security_audit import (
    UnsafeOperation,
    UnsafeOperationNotice,
    UnsafeRelaxation,
    _AUDIT_RECURSION,
    record_unsafe_operation,
)
from tn.signing import DeviceKey


class _AuditRuntime:
    def __init__(
        self,
        *,
        fail: bool = False,
        nested: Callable[[], None] | None = None,
    ) -> None:
        self.fail = fail
        self.nested = nested
        self.events: list[tuple[str, str, dict[str, object]]] = []

    def emit(
        self,
        level: str,
        event_type: str,
        fields: dict[str, object],
    ) -> None:
        if self.fail:
            raise RuntimeError("audit sink unavailable")
        self.events.append((level, event_type, fields))
        if self.nested is not None:
            self.nested()


@pytest.fixture(autouse=True)
def _clean_tn() -> Any:
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


@pytest.fixture()
def read_audit_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    device = DeviceKey.generate()
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    keystore.mkdir()
    log_path = tmp_path / "main.ndjson"
    cfg = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        sign=True,
        chain=True,
        resolve_log_path=lambda: log_path,
    )
    rows = [
        {
            "envelope": {
                "timestamp": "2026-07-12T12:00:00.000000Z",
                "event_type": "audit.read",
                "level": "info",
                "device_identity": device.did,
                "sequence": 1,
                "event_id": "01J00000000000000000000100",
                "run_id": "run-audit",
                "prev_hash": "sha256:" + "0" * 64,
                "row_hash": "sha256:" + "1" * 64,
                "signature": "signed",
            },
            "plaintext": {},
            "valid": {"signature": True, "row_hash": True, "chain": True},
        },
    ]
    read_module = importlib.import_module("tn.read")
    read_impl = importlib.import_module("tn._read_impl")
    monkeypatch.setattr(read_module, "_resolve_read_source", lambda *args: None)
    monkeypatch.setattr(
        read_impl,
        "_read_raw_inner",
        lambda *args, **kwargs: iter(rows),
    )
    return SimpleNamespace(cfg=cfg, rows=rows, read_module=read_module)


def _security_warnings(caught: list[warnings.WarningMessage]) -> list[TnSecurityWarning]:
    return [
        item.message
        for item in caught
        if isinstance(item.message, TnSecurityWarning)
    ]


def test_read_weakening_warns_once_and_emits_exact_writable_event(
    read_audit_harness: Any,
) -> None:
    runtime = _AuditRuntime()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        rows = list(
            read_audit_harness.read_module._read_bound(
                verify=False,
                raw=True,
                _cfg=read_audit_harness.cfg,
                _runtime=runtime,
            ),
        )

    security = _security_warnings(caught)
    assert len(rows) == 1
    assert len(security) == 1
    assert security[0].notice.to_fields() == {
        "artifact_digest": None,
        "group": None,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": None,
    }
    assert runtime.events == [
        (
            "warning",
            "tn.security.unsafe_operation",
            security[0].notice.to_fields(),
        ),
    ]


def test_read_post_gate_entry_shape_failure_uses_record_invalid_policy(
    read_audit_harness: Any,
) -> None:
    read_audit_harness.rows[0]["envelope"]["timestamp"] = "not-a-timestamp"

    with pytest.raises(VerifyError) as raised:
        list(
            read_audit_harness.read_module._read_bound(
                _cfg=read_audit_harness.cfg,
                _runtime=_AuditRuntime(),
            ),
        )
    assert raised.value.reason == "record_invalid"
    assert raised.value.reasons == ["record_invalid"]
    assert raised.value.sequence == 1
    assert raised.value.event_type == "audit.read"

    observed: list[tuple[dict[str, Any], str]] = []
    result = read_audit_harness.read_module._read_bound(
        verify="skip",
        on_skip=lambda envelope, reason: observed.append((envelope, reason)),
        _cfg=read_audit_harness.cfg,
        _runtime=_AuditRuntime(),
    )
    assert list(result) == []
    assert result.stats.skipped_parse == 1
    assert result.stats.skipped_reasons == ["record_invalid"]
    assert observed[0][0]["event_type"] == "audit.read"
    assert observed[0][1] == "record_invalid"

    with pytest.warns(TnSecurityWarning), pytest.raises(Exception) as disabled:
        list(
            read_audit_harness.read_module._read_bound(
                verify=False,
                _cfg=read_audit_harness.cfg,
                _runtime=_AuditRuntime(),
            ),
        )
    assert not isinstance(disabled.value, VerifyError)


def test_detached_read_warns_without_admin_event(read_audit_harness: Any, tmp_path: Path) -> None:
    runtime = _AuditRuntime()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        read_audit_harness.read_module._read_bound(
            log=tmp_path / "detached.ndjson",
            verify=False,
            _cfg=read_audit_harness.cfg,
            _runtime=runtime,
        )

    assert len(_security_warnings(caught)) == 1
    assert runtime.events == []


def test_admin_read_excludes_only_its_own_new_unsafe_audit_row(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    before = list(tn.read(log="admin"))
    before_ids = [entry.event_id for entry in before]

    with pytest.warns(TnSecurityWarning):
        weakened = list(tn.read(log="admin", verify=False))

    assert [entry.event_id for entry in weakened] == before_ids
    after = list(tn.read(log="admin"))
    unsafe = [
        entry
        for entry in after
        if entry.event_type == "tn.security.unsafe_operation"
    ]
    assert len(unsafe) == 1
    assert len(after) == len(before) + 1


def test_audit_failure_never_changes_read_results(read_audit_harness: Any) -> None:
    runtime = _AuditRuntime(fail=True)
    with pytest.warns(TnSecurityWarning):
        rows = list(
            read_audit_harness.read_module._read_bound(
                verify=False,
                raw=True,
                _cfg=read_audit_harness.cfg,
                _runtime=runtime,
            ),
        )
    assert len(rows) == 1


def test_read_audit_recursion_guard_is_task_local_and_single_shot(
    read_audit_harness: Any,
) -> None:
    runtime: _AuditRuntime

    def nested_read() -> None:
        list(
            read_audit_harness.read_module._read_bound(
                verify=False,
                raw=True,
                _cfg=read_audit_harness.cfg,
                _runtime=runtime,
            ),
        )

    runtime = _AuditRuntime(nested=nested_read)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        list(
            read_audit_harness.read_module._read_bound(
                verify=False,
                raw=True,
                _cfg=read_audit_harness.cfg,
                _runtime=runtime,
            ),
        )

    assert len(_security_warnings(caught)) == 1
    assert len(runtime.events) == 1


def test_explicit_unsigned_settings_do_not_warn_for_automatic_unsigned_local_profile(
    read_audit_harness: Any,
) -> None:
    read_audit_harness.cfg.sign = False
    runtime = _AuditRuntime()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        read_audit_harness.read_module._read_bound(
            require_signature=False,
            allow_unauthenticated=True,
            _cfg=read_audit_harness.cfg,
            _runtime=runtime,
        )

    assert _security_warnings(caught) == []
    assert runtime.events == []


def test_read_unsigned_and_unknown_writer_notice_composes_exact_relaxations(
    read_audit_harness: Any,
) -> None:
    runtime = _AuditRuntime()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        list(
            read_audit_harness.read_module._read_bound(
                require_signature=False,
                allow_unauthenticated=True,
                allow_unknown_writers=True,
                raw=True,
                _cfg=read_audit_harness.cfg,
                _runtime=runtime,
            ),
        )

    security = _security_warnings(caught)
    assert len(security) == 1
    assert security[0].notice.to_fields() == {
        "artifact_digest": None,
        "group": None,
        "operation": "read",
        "relaxations": [
            "signature_not_required",
            "unauthenticated_allowed",
            "unknown_writer_allowed",
        ],
        "subject_did": None,
    }
    assert runtime.events == [
        (
            "warning",
            "tn.security.unsafe_operation",
            security[0].notice.to_fields(),
        ),
    ]


def test_contextvar_guard_in_one_task_does_not_suppress_independent_task() -> None:
    notice = UnsafeOperationNotice(
        operation=UnsafeOperation.READ,
        relaxations=(UnsafeRelaxation.VERIFICATION_DISABLED,),
    )

    class DirectContext:
        writable = True

        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, object]]] = []

        def emit_admin(self, event_type: str, fields: dict[str, object]) -> None:
            self.events.append((event_type, fields))

    guarded_context = DirectContext()
    independent_context = DirectContext()

    async def run() -> None:
        guard_held = asyncio.Event()
        release_guard = asyncio.Event()

        async def guarded_nested() -> None:
            token = _AUDIT_RECURSION.set(True)
            try:
                guard_held.set()
                await release_guard.wait()
                record_unsafe_operation(notice, guarded_context)
            finally:
                _AUDIT_RECURSION.reset(token)

        async def independent() -> None:
            await guard_held.wait()
            record_unsafe_operation(notice, independent_context)
            release_guard.set()

        await asyncio.gather(guarded_nested(), independent())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        asyncio.run(run())

    assert len(_security_warnings(caught)) == 1
    assert guarded_context.events == []
    assert independent_context.events == [
        ("tn.security.unsafe_operation", notice.to_fields()),
    ]


def test_watch_weakening_warns_once_and_emits_one_admin_event(tmp_path: Path) -> None:
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="jwe")
    tn.info("watch.audit", marker="visible")

    async def first() -> Any:
        stream = tn.watch(
            since="start",
            poll_interval=0.01,
            verify="skip",
            require_signature=False,
            allow_unauthenticated=True,
            allow_unknown_writers=True,
        )
        return await asyncio.wait_for(anext(stream), timeout=2.0)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        entry = asyncio.run(first())

    security = _security_warnings(caught)
    assert entry.event_type == "watch.audit"
    assert len(security) == 1
    assert security[0].notice.to_fields() == {
        "artifact_digest": None,
        "group": None,
        "operation": "watch",
        "relaxations": [
            "signature_not_required",
            "unauthenticated_allowed",
            "unknown_writer_allowed",
        ],
        "subject_did": None,
    }
    audit_events = [
        item
        for item in tn.read(log="admin")
        if item.event_type == "tn.security.unsafe_operation"
    ]
    assert len(audit_events) == 1
    assert audit_events[0].fields == security[0].notice.to_fields()


def test_watch_audit_failure_does_not_change_yielded_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    tn.info("watch.audit.failure", marker="visible")
    runtime = _AuditRuntime(fail=True)
    monkeypatch.setattr(tn, "_dispatch_rt", runtime)

    async def first() -> Any:
        return await anext(
            tn.watch(since="start", verify=False, poll_interval=0.01),
        )

    with pytest.warns(TnSecurityWarning):
        entry = asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert entry.event_type == "watch.audit.failure"


def test_detached_watch_warns_without_admin_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_path = tmp_path / "publisher.ndjson"
    tn.init(tmp_path / "tn.yaml", cipher="jwe", log_path=log_path)
    tn.info("watch.audit.detached", marker="visible")
    keystore = tn.current_config().keystore
    runtime = _AuditRuntime()
    monkeypatch.setattr(tn, "_dispatch_rt", runtime)

    async def first() -> Any:
        return await anext(
            tn.watch(
                log=log_path,
                as_recipient=keystore,
                group="default",
                since="start",
                verify=False,
                poll_interval=0.01,
            ),
        )

    with pytest.warns(TnSecurityWarning):
        entry = asyncio.run(asyncio.wait_for(first(), timeout=2.0))
    assert entry.event_type == "watch.audit.detached"
    assert runtime.events == []


def test_admin_watch_excludes_its_own_audit_row_and_keeps_later_chain_valid(
    tmp_path: Path,
) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    before = list(tn.read(log="admin"))
    before_ids = [entry.event_id for entry in before]

    async def run() -> tuple[list[str], str]:
        stream = tn.watch(
            log="admin",
            since="start",
            verify=False,
            poll_interval=0.01,
        )
        seen = [
            (await asyncio.wait_for(anext(stream), timeout=2.0)).event_id
            for _ in before
        ]
        tn.log("tn.audit.after_unsafe_watch", level="info", marker="later")
        later = await asyncio.wait_for(anext(stream), timeout=2.0)
        await stream.aclose()
        return seen, later.event_type

    with pytest.warns(TnSecurityWarning):
        seen_ids, later_type = asyncio.run(run())

    assert seen_ids == before_ids
    assert later_type == "tn.audit.after_unsafe_watch"
    # A strict replay validates the audit row and the later append's chains.
    after = list(tn.read(log="admin"))
    assert len(after) == len(before) + 2
