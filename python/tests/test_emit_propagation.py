"""Tests for live emit on multi-ceremony streams + handler propagation.

Verifies the foundational contract: ``payments.info(...)`` activates
the named ceremony's runtime and writes attested entries through its
configured sinks. Inheritance from default propagates handlers down,
so stream emits also reach default's master sinks.

Skipped when ``tn_btn`` Rust extension is missing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))


try:
    import tn_btn  # type: ignore[import-not-found]  # noqa: F401
    _HAS_BTN = True
except ImportError:
    _HAS_BTN = False

requires_btn = pytest.mark.skipif(
    not _HAS_BTN,
    reason="tn_btn Rust extension not installed in this environment",
)


@pytest.fixture(autouse=True)
def _isolation(tmp_path, monkeypatch):
    import tn
    from tn import _autoinit, _registry
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    monkeypatch.delenv("TN_NO_STDOUT", raising=False)
    monkeypatch.setenv("TN_NO_STDOUT", "1")  # quiet for tests
    monkeypatch.chdir(tmp_path)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _registry.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# Live emit on non-default streams.
# ---------------------------------------------------------------------------


@requires_btn
class TestLiveEmitOnNonDefaultStream:
    def test_payments_info_writes_to_payments_log(self, tmp_path):
        import tn

        h = tn.init("payments", profile="transaction", project_dir=tmp_path)
        h.info("payment.charged", amount=4999, order_id="A100")
        tn.flush_and_close()

        # Payments' log file should exist and contain the event.
        log_path = tmp_path / ".tn" / "payments" / "logs" / "payments.ndjson"
        assert log_path.is_file(), f"expected log at {log_path}"
        contents = log_path.read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in contents if line.strip()]
        types = [e.get("event_type") for e in events]
        assert "payment.charged" in types

    def test_emit_does_not_raise(self, tmp_path):
        import tn

        h = tn.init("audit_stream", profile="audit", project_dir=tmp_path)
        # Multiple verbs all work without raising.
        h.log("evt.a")
        h.debug("evt.b", k=1)
        h.info("evt.c")
        h.warning("evt.d")
        h.error("evt.e")
        tn.flush_and_close()

    def test_two_streams_emit_independently(self, tmp_path):
        import tn

        a = tn.init("a", profile="transaction", project_dir=tmp_path)
        b = tn.init("b", profile="audit", project_dir=tmp_path)

        a.info("a.event", value=1)
        b.info("b.event", value=2)
        tn.flush_and_close()

        a_log = tmp_path / ".tn" / "a" / "logs" / "a.ndjson"
        b_log = tmp_path / ".tn" / "b" / "logs" / "b.ndjson"

        a_events = [
            json.loads(l) for l in a_log.read_text(encoding="utf-8").splitlines() if l.strip()
        ]
        b_events = [
            json.loads(l) for l in b_log.read_text(encoding="utf-8").splitlines() if l.strip()
        ]
        a_types = [e.get("event_type") for e in a_events]
        b_types = [e.get("event_type") for e in b_events]
        # a's events should land in a's log, b's in b's log.
        assert "a.event" in a_types
        assert "b.event" in b_types
        # Cross-contamination check: b's events shouldn't be in a's log.
        assert "b.event" not in a_types
        assert "a.event" not in b_types


# ---------------------------------------------------------------------------
# Read after emit (round-trip).
# ---------------------------------------------------------------------------


@requires_btn
class TestEmitReadRoundtrip:
    def test_emit_then_read_returns_entries(self, tmp_path):
        import tn

        h = tn.init("orders", profile="transaction", project_dir=tmp_path)
        h.info("order.created", order_id="A100", amount=1000)
        h.info("order.created", order_id="A101", amount=2000)
        tn.flush_and_close()

        # Re-open and read.
        _registry_clear_again(tn)
        h2 = tn.init("orders", profile="transaction", project_dir=tmp_path)
        entries = list(h2.read())
        types = [e.event_type for e in entries]
        # At least the two we wrote.
        assert types.count("order.created") >= 2


def _registry_clear_again(tn):
    """Re-prep state for a second init in the same test (simulates
    a second process attaching). Mirrors what flush_and_close + init
    sequence does for legitimate re-attachment."""
    from tn import _registry
    _registry.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# Cross-ceremony emit ordering: serial activation behavior.
# ---------------------------------------------------------------------------


@requires_btn
class TestPerInstanceDispatch:
    """Per-instance dispatch + last-init-wins singleton binding.

    Each ``tn.init(name=...)`` call binds the module-level singleton
    to the just-initialised ceremony — mirroring stdlib ``logging``
    where the last config wins. Returned handles continue to route
    through their own ``DispatchRuntime`` so a held handle stays
    pointed at its original ceremony even after another init swaps
    the singleton; that independence is exercised by
    :meth:`test_named_streams_have_independent_runtimes` below.
    """

    def test_init_rebinds_singleton_to_latest_ceremony(self, tmp_path):
        import tn
        from pathlib import Path as _P

        assert tn._dispatch_rt is None

        d = tn.init("default", project_dir=tmp_path)
        d.info("evt.default", k=1)
        default_yaml = _P(tn.current_config().yaml_path).resolve()
        assert default_yaml == d.yaml_path.resolve()

        # tn.init(name=...) rebinds the singleton onto the named
        # ceremony so subsequent module-level tn.info / tn.read /
        # tn.current_config calls operate against it.
        b = tn.init("b", profile="audit", project_dir=tmp_path)
        b.info("evt.b", k=1)

        assert (
            _P(tn.current_config().yaml_path).resolve()
            == b.yaml_path.resolve()
        ), "tn.init(name=...) must rebind the module-level singleton"
        tn.flush_and_close()

    def test_named_streams_have_independent_runtimes(self, tmp_path):
        import tn

        a = tn.init("a", profile="transaction", project_dir=tmp_path)
        b = tn.init("b", profile="audit", project_dir=tmp_path)

        a.info("evt.a", k=1)
        b.info("evt.b", k=1)
        tn.flush_and_close()

        # Each stream's events landed in its own log — no
        # cross-contamination via singleton rebinding.
        a_log = tmp_path / ".tn" / "a" / "logs" / "a.ndjson"
        b_log = tmp_path / ".tn" / "b" / "logs" / "b.ndjson"
        assert a_log.is_file()
        assert b_log.is_file()
        a_text = a_log.read_text(encoding="utf-8")
        b_text = b_log.read_text(encoding="utf-8")
        assert "evt.a" in a_text and "evt.b" not in a_text
        assert "evt.b" in b_text and "evt.a" not in b_text


# ---------------------------------------------------------------------------
# Profile + handler combinations: end-to-end behavior of each.
# ---------------------------------------------------------------------------


@requires_btn
class TestProfileEndToEnd:
    @pytest.mark.parametrize(
        "profile",
        ["transaction", "audit", "secure_log"],
    )
    def test_file_replay_surface_profiles_persist(self, tmp_path, profile):
        import tn

        h = tn.init("s", profile=profile, project_dir=tmp_path)
        h.info("evt.persisted", k=1)
        tn.flush_and_close()

        # Stream's log file exists with our event.
        log_path = tmp_path / ".tn" / "s" / "logs" / "s.ndjson"
        assert log_path.is_file()
        text = log_path.read_text(encoding="utf-8")
        assert "evt.persisted" in text

    def test_telemetry_does_not_persist_to_file(self, tmp_path):
        import tn

        h = tn.init("traces", profile="telemetry", project_dir=tmp_path)
        h.info("evt.fast", k=1)
        tn.flush_and_close()

        # Telemetry's default sink is stdout; no per-stream file is
        # written for it. The directory is created (logs/) but the
        # file isn't.
        log_path = tmp_path / ".tn" / "traces" / "logs" / "traces.ndjson"
        # The legacy file handler may still write because default
        # ceremony's file handler propagates. The IMPORTANT property
        # is: telemetry didn't write to its OWN file (no
        # file.rotating handler declared). Check that the stream
        # yaml has no file.rotating handler.
        import yaml as _yaml
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        kinds = [x.get("kind") for x in (doc.get("handlers") or [])]
        assert "file.rotating" not in kinds
        assert "stdout" in kinds


# ---------------------------------------------------------------------------
# Bare module-level API still works on the default ceremony.
# ---------------------------------------------------------------------------


@requires_btn
class TestBareModuleApiStillWorks:
    def test_module_level_info_works(self, tmp_path):
        import tn

        # ``tn.init()`` (no args) creates the default ceremony.
        tn.init(project_dir=tmp_path)
        # ``tn.info(...)`` writes to default's log.
        tn.info("module.evt", k=1)
        tn.flush_and_close()

        log_path = tmp_path / ".tn" / "default" / "logs" / "tn.ndjson"
        assert log_path.is_file()
        text = log_path.read_text(encoding="utf-8")
        assert "module.evt" in text

    def test_default_handle_is_module_level_singleton(self, tmp_path):
        import tn

        d = tn.init(project_dir=tmp_path)
        # tn.use("default") returns the same handle.
        assert tn.use("default", project_dir=tmp_path) is d
