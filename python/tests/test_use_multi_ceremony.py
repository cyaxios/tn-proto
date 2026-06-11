"""End-to-end tests for ``tn.use(name)``: the verb a user actually
reaches for when they want a logger handle for a named stream.

Style:
    Each test reads like a small documentation example. No mocks, no
    fixture parameter sprawl, no "build a yaml dict and assert keys."
    The shape is: ``use`` → ``info`` → ``read`` → assert what the user
    cares about.

Coverage:
    * ``tn.use(name)`` returns an isolated, named stream handle.
    * Second call with the same name returns the SAME handle (registry).
    * Different names give different handles, different logs.
    * Emits land in the named ceremony's log only.
    * ``handle.read()`` reads back what ``handle.info()`` wrote.
    * Two handles emit independently — no sequence/chain bleed.
    * ``tn.use(name, profile=...)`` stamps the profile at creation time.
    * The module-level singleton (``tn.info``) is untouched by named
      handles — no rebinding.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))


try:
    from tn._native import btn as tn_btn  # noqa: F401
    _HAS_BTN = True
except ImportError:
    _HAS_BTN = False

requires_btn = pytest.mark.skipif(
    not _HAS_BTN,
    reason="tn_btn Rust extension not installed in this environment",
)


@pytest.fixture(autouse=True)
def _isolation(tmp_path, monkeypatch):
    """Per-test isolation: fresh cwd, no env leakage, cleared registry."""
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
    monkeypatch.setenv("TN_NO_STDOUT", "1")  # quiet for tests
    monkeypatch.chdir(tmp_path)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _registry.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# Identity: who do you get back?
# ---------------------------------------------------------------------------


@requires_btn
def test_use_returns_a_handle_named_after_the_ceremony():
    """The headline shape: ``tn.use("payments")`` gives you a handle
    that knows its own name and yaml path."""
    import tn

    payments = tn.use("payments")
    assert payments.name == "payments"
    assert payments.yaml_path.is_file()
    assert payments.yaml_path.parent.name == "streams"
    assert payments.yaml_path.name == "payments.yaml"


@requires_btn
def test_use_is_a_registry_get_or_create():
    """Calling ``tn.use`` twice with the same name returns the SAME
    handle — not a fresh one. The registry is the source of truth
    for live handles in this process."""
    import tn

    a1 = tn.use("audits")
    a2 = tn.use("audits")
    assert a1 is a2


@requires_btn
def test_use_with_different_names_returns_different_handles():
    """``tn.use("a")`` and ``tn.use("b")`` give you two distinct
    handles, each with its own stream overlay in the current Project."""
    import tn

    a = tn.use("alpha")
    b = tn.use("beta")
    assert a is not b
    assert a.name != b.name
    assert a.yaml_path != b.yaml_path


# ---------------------------------------------------------------------------
# Behavior: emits + reads
# ---------------------------------------------------------------------------


def _user_entries(handle):
    """Filter helper — drop the protocol's own admin events
    (``tn.ceremony.*``, ``tn.group.*``, etc.) so tests assert on
    user-emitted entries only."""
    return [e for e in handle.read() if not e.event_type.startswith("tn.")]


@requires_btn
def test_info_then_read_round_trips_on_one_handle():
    """The dirt-easy promise: emit through a handle, read it back
    through the same handle, see your fields."""
    import tn

    orders = tn.use("orders")
    orders.info("order.created", order_id="A100", amount=4999)

    entries = _user_entries(orders)
    assert len(entries) == 1
    e = entries[0]
    assert e.event_type == "order.created"
    assert e.fields["order_id"] == "A100"
    assert e.fields["amount"] == 4999


@requires_btn
def test_two_handles_emit_into_separate_logs():
    """Cross-contamination test. ``payments.info`` must NOT land in
    ``audits``' log, and vice versa."""
    import tn

    payments = tn.use("payments")
    audits = tn.use("audits")

    payments.info("charge.captured", amount=4999)
    audits.info("policy.reviewed", reviewer="alice")

    payments_types = [e.event_type for e in _user_entries(payments)]
    audits_types = [e.event_type for e in _user_entries(audits)]

    assert payments_types == ["charge.captured"]
    assert audits_types == ["policy.reviewed"]


@requires_btn
def test_handles_keep_independent_sequence_numbers():
    """Each named ceremony owns its own attestation chain. Sequence
    numbers don't bleed across handles — payments' seq=1 is its
    first event regardless of what audits has written."""
    import tn

    payments = tn.use("payments")
    audits = tn.use("audits")

    audits.info("a.1")
    audits.info("a.2")
    audits.info("a.3")
    payments.info("p.first")  # payments has seen 3 events from audits — but on its own chain this is #1.

    a_entries = _user_entries(audits)
    p_entries = _user_entries(payments)

    # Audits saw three of its own events; payments saw one of its own.
    assert [e.event_type for e in a_entries] == ["a.1", "a.2", "a.3"]
    assert [e.event_type for e in p_entries] == ["p.first"]

    # Sequence is per-ceremony: payments' first user event is seq=1
    # regardless of how many events audits has written.
    assert p_entries[0].sequence == 1


# ---------------------------------------------------------------------------
# Profile is honored at creation time
# ---------------------------------------------------------------------------


@requires_btn
def test_use_with_profile_stamps_yaml_on_creation():
    """``tn.use("audit_stream", profile="audit")`` mints a yaml with
    ``ceremony.profile: audit`` baked in — the operator sees what
    profile they're running under by reading the yaml."""
    import yaml as _yaml
    import tn

    handle = tn.use("audit_stream", profile="audit")
    doc = _yaml.safe_load(handle.yaml_path.read_text(encoding="utf-8"))
    assert doc["ceremony"]["profile"] == "audit"


@requires_btn
def test_use_rejects_unknown_profile():
    """Profile typos fail fast with a clear error — same shape as
    ``tn.init(name, profile=...)``."""
    import tn
    from tn._multi import TNConfigConflict

    with pytest.raises(TNConfigConflict, match="unknown profile"):
        tn.use("oops", profile="not-a-real-profile")


# ---------------------------------------------------------------------------
# No-rebinding contract: module singleton stays put.
# ---------------------------------------------------------------------------


@requires_btn
def test_use_does_not_rebind_the_module_singleton():
    """Calling ``tn.use("payments").info(...)`` must not move
    ``tn.info`` (the singleton) onto payments. The singleton stays
    on whichever ceremony was last bound via ``tn.init()``."""
    import tn

    tn.init()  # binds the singleton to default
    default_yaml = tn.current_config().yaml_path

    payments = tn.use("payments")
    payments.info("charge.captured", amount=4999)

    # Singleton still points at default; tn.info still writes there.
    assert tn.current_config().yaml_path == default_yaml


# ---------------------------------------------------------------------------
# Profiles, end-to-end through tn.use
#
# Each profile encodes a different (signing, chaining, flush, sink)
# bundle. Tests below prove that picking a profile via ``tn.use``
# actually changes runtime behavior — not just the yaml stamp.
# ---------------------------------------------------------------------------


def _ceremony_yaml(handle):
    """Load the on-disk yaml a handle resolves to. Used to read the
    profile-derived ``ceremony.sign`` flag without rebinding the
    runtime."""
    import yaml as _yaml
    return _yaml.safe_load(handle.yaml_path.read_text(encoding="utf-8"))


@requires_btn
@pytest.mark.parametrize(
    "profile,expected_sign",
    [
        ("transaction", True),
        ("audit", True),
        ("secure_log", True),
        ("telemetry", False),
    ],
)
def test_use_honors_profile_sign_flag(profile, expected_sign):
    """The signing decision is the most visible profile knob. Three
    profiles sign, telemetry skips. ``tn.use(name, profile=p)`` flips
    ``ceremony.sign`` in the yaml accordingly — that flag drives the
    runtime's per-emit decision."""
    import tn

    handle = tn.use("s_" + profile, profile=profile)
    assert _ceremony_yaml(handle)["ceremony"]["sign"] is expected_sign


@requires_btn
def test_use_with_audit_profile_round_trips_entries():
    """Replay-surface profiles (transaction / audit / secure_log)
    write to a file and read back what they wrote — the normal
    ``info -> read`` contract."""
    import tn

    audits = tn.use("audits", profile="audit")
    audits.info("policy.reviewed", reviewer="alice")
    audits.info("policy.reviewed", reviewer="bob")

    entries = _user_entries(audits)
    reviewers = [e.fields["reviewer"] for e in entries]
    assert reviewers == ["alice", "bob"]


@requires_btn
def test_use_with_telemetry_profile_has_replay_surface():
    """0.4.2a9: telemetry HAS a file sink (in addition to stdout).
    The profile's "fast-as-stdlib-logger" contract is about CPU cost
    (unsigned, unchained), not about dropping the file — operators
    who want a truly forward-only profile use ``stdout`` instead."""
    import tn

    traces = tn.use("traces", profile="telemetry")
    traces.info("trace.span_ended", duration_ms=12)
    traces.info("trace.span_ended", duration_ms=7)

    rows = list(traces.read())
    assert len(rows) == 2, f"expected 2 user rows, got {len(rows)}"


@requires_btn
def test_use_writes_signed_envelopes_when_profile_signs():
    """A profile that signs (transaction here) puts a non-empty
    signature on every user-emitted row. Inspect the raw envelope
    via ``raw=True`` so we see the wire shape."""
    import tn

    payments = tn.use("payments", profile="transaction")
    payments.info("charge.captured", amount=4999)

    user_envs = [
        env for env in payments.read(raw=True)
        if not env["event_type"].startswith("tn.")
    ]
    assert len(user_envs) == 1
    sig = user_envs[0].get("signature") or ""
    assert len(sig) > 0, "transaction profile must sign every row"


@requires_btn
def test_use_with_stdout_profile_is_dev_friendly():
    """The ``stdout`` profile is the friendlier name for the
    "just print, no ceremony" shape. Same wire behavior as
    ``telemetry``: encrypted (floor), unsigned, unchained, stdout
    sink. The name change is the whole point — users see
    ``profile='stdout'`` and know what they're getting."""
    import tn

    dev = tn.use("dev_scratch", profile="stdout")
    dev.info("debug.note", note="quick check")

    yaml_doc = _ceremony_yaml(dev)
    assert yaml_doc["ceremony"]["profile"] == "stdout"
    assert yaml_doc["ceremony"]["sign"] is False
    # No on-disk replay surface (default sink is stdout) — read is empty.
    assert list(dev.read()) == []


@requires_btn
def test_use_keeps_each_profile_independent_in_the_same_process():
    """The whole point of multi-ceremony: one app can run a strict
    ``transaction`` stream and a fast ``telemetry`` stream at the
    same time. ``tn.use`` gives you a handle per stream; emits and
    profiles do not bleed."""
    import tn

    payments = tn.use("payments", profile="transaction")
    traces = tn.use("traces", profile="telemetry")

    payments.info("charge.captured", amount=4999)
    traces.info("trace.span_ended", duration_ms=12)

    # Payments has a replay surface and signs.
    p_yaml = _ceremony_yaml(payments)
    assert p_yaml["ceremony"]["sign"] is True
    assert [e.event_type for e in _user_entries(payments)] == ["charge.captured"]

    # Telemetry doesn't sign but DOES write a file you can read back
    # (0.4.2a9: file_rotating default sink restored).
    t_yaml = _ceremony_yaml(traces)
    assert t_yaml["ceremony"]["sign"] is False
    assert [e.event_type for e in _user_entries(traces)] == ["trace.span_ended"]
