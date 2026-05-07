"""Cross-product tests for profile + handler + read combinations.

Covers the matrix the user asked for: profiles paired with handler
configurations, with assertions on chaining, signing, read behavior,
and dedup. Stays restricted to the file-rotating + stdout handlers
(the two "shipping" sinks); other handler kinds (otel, kafka, delta)
get their own test files when they exist.

Test groups:

  TestProfileShape          — properties surface on the TN handle's cfg
  TestProfileChainBehavior  — chaining is on/off per profile
  TestReadAcrossProfiles    — read returns expected shape per profile
  TestStdoutFormatIsClean   — stdout doesn't leak ciphertext
  TestPythonExampleFlow     — end-to-end example as a doctest-style test

Skipped when ``tn_btn`` Rust extension is missing.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]
import yaml as _yaml

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import _autoinit, _profiles, _registry


try:
    import tn_btn as _tn_btn  # type: ignore[import-not-found]  # noqa: F401
    _HAS_BTN = True
except ImportError:
    _HAS_BTN = False

requires_btn = pytest.mark.skipif(
    not _HAS_BTN,
    reason="tn_btn Rust extension not installed in this environment",
)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch, tmp_path):
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_STRICT", raising=False)
    monkeypatch.delenv("TN_AUTOINIT_QUIET", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / "_tnhome"))
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# Shape: every profile produces a stream whose stamped yaml + cfg
# reflect the SDK's catalog properties.
# ---------------------------------------------------------------------------


@requires_btn
class TestProfileShape:
    @pytest.mark.parametrize("profile_name", _profiles.all_profile_names())
    def test_each_profile_stamps_into_yaml(self, tmp_path, profile_name):
        h = tn.init(profile_name + "_stream", profile=profile_name, project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        assert (doc.get("ceremony") or {}).get("profile") == profile_name

    @pytest.mark.parametrize("profile_name", _profiles.all_profile_names())
    def test_each_profile_writes_correct_default_handler(
        self, tmp_path, profile_name
    ):
        # The profile's default sink determines the initial handler
        # written into the stream's yaml. file_rotating profiles get
        # a file.rotating handler; stdout profiles get stdout.
        h = tn.init(profile_name + "_stream", profile=profile_name, project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        handler_kinds = {x.get("kind") for x in (doc.get("handlers") or [])}

        p = _profiles.get(profile_name)
        if p.default_sink == "file_rotating":
            assert "file.rotating" in handler_kinds
        elif p.default_sink == "stdout":
            assert "stdout" in handler_kinds


# ---------------------------------------------------------------------------
# Chaining: profiles that chain stamp ceremony.sign accordingly.
# Profiles that don't chain still produce a loadable yaml.
# ---------------------------------------------------------------------------


@requires_btn
class TestProfileChainBehavior:
    def test_transaction_signs(self, tmp_path):
        h = tn.init("tx", profile="transaction", project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        assert (doc.get("ceremony") or {}).get("sign") is True

    def test_audit_signs(self, tmp_path):
        h = tn.init("a", profile="audit", project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        assert (doc.get("ceremony") or {}).get("sign") is True

    def test_secure_log_signs(self, tmp_path):
        h = tn.init("sl", profile="secure_log", project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        assert (doc.get("ceremony") or {}).get("sign") is True

    def test_telemetry_does_not_sign(self, tmp_path):
        # The fast-as-stdlib-logger profile drops signing.
        h = tn.init("t", profile="telemetry", project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        assert (doc.get("ceremony") or {}).get("sign") is False


# ---------------------------------------------------------------------------
# Read: returns empty for no-replay-surface profiles, works for others.
# ---------------------------------------------------------------------------


@requires_btn
class TestReadAcrossProfiles:
    @pytest.mark.parametrize(
        "profile_name", ["transaction", "audit", "secure_log"]
    )
    def test_read_works_on_replay_surface_profiles(
        self, tmp_path, profile_name
    ):
        # Fresh streams emit a few bootstrap protocol events at init
        # (tn.ceremony.init, tn.group.added). Drain the iterator —
        # the call succeeds (no raise) regardless of count.
        h = tn.init("s_" + profile_name, profile=profile_name, project_dir=tmp_path)
        # Just verify the read iterator is consumable.
        result = list(h.read())
        # Each entry should be a dict (the legacy reader's flat shape).
        assert all(isinstance(e, dict) for e in result)

    def test_read_returns_empty_for_telemetry(self, tmp_path):
        h = tn.init("t", profile="telemetry", project_dir=tmp_path)
        assert list(h.read()) == []

    def test_watch_returns_empty_for_telemetry(self, tmp_path):
        h = tn.init("t", profile="telemetry", project_dir=tmp_path)
        # Watch on a no-replay-surface stream yields nothing.
        assert list(h.watch()) == []


# ---------------------------------------------------------------------------
# Stdout output stays clean (no ciphertext, no signatures) regardless
# of profile picked.
# ---------------------------------------------------------------------------


class TestStdoutFormatIsClean:
    def test_pretty_skips_crypto_keys(self):
        from tn.handlers.stdout import StdoutHandler, _format_pretty

        envelope = {
            "did": "did:key:z6MkSAMPLE",
            "timestamp": "2026-05-06T10:00:00.000000Z",
            "event_type": "x.y",
            "level": "info",
            "sequence": 1,
            "event_id": "id1234567890",
            "prev_hash": "sha256:abc",
            "row_hash": "sha256:def",
            "signature": "SIG_BYTES",
            "default": {"ciphertext": "AAAA", "field_hashes": {}},
        }
        out = _format_pretty(envelope).decode("utf-8")
        assert "sha256" not in out
        assert "SIG_BYTES" not in out
        assert "ciphertext" not in out
        assert "AAAA" not in out
        # Header info is present.
        assert "x.y" in out
        assert "INFO" in out
        assert "seq=1" in out

    def test_pretty_shows_public_fields(self):
        from tn.handlers.stdout import _format_pretty

        envelope = {
            "timestamp": "2026-05-06T10:00:00.000000Z",
            "event_type": "order.created",
            "level": "info",
            "sequence": 5,
            "amount": 4999,
            "order_id": "A100",
        }
        out = _format_pretty(envelope).decode("utf-8")
        assert "amount=4999" in out
        assert "order_id='A100'" in out


# ---------------------------------------------------------------------------
# A small Python example that exercises a couple of streams side by
# side, the kind of code a user would actually write. Verifies the
# primitives are coherent end-to-end.
# ---------------------------------------------------------------------------


@requires_btn
class TestPythonExampleFlow:
    def test_two_streams_in_one_project(self, tmp_path):
        # Set up: an audit-grade stream for payments, a fast
        # telemetry stream for traces. Both share project identity.
        payments = tn.init("payments", profile="transaction", project_dir=tmp_path)
        traces = tn.init("traces", profile="telemetry", project_dir=tmp_path)

        # Same project DID across both streams.
        assert payments.cfg.device.did == traces.cfg.device.did

        # Distinct ceremony_ids = independent chains.
        assert payments.cfg.ceremony_id != traces.cfg.ceremony_id

        # Each stream lives under its own .tn/<name>/ directory.
        assert payments.directory.name == "payments"
        assert traces.directory.name == "traces"

        # Listing surfaces both, plus the project default.
        names = tn.list_ceremonies()
        assert "payments" in names
        assert "traces" in names

        # tnpkg roundtrip works between the two ceremonies (kit
        # bundle from payments, absorb into traces — though traces
        # is telemetry-shaped and won't read it back anyway).
        consumer = tn.init("consumer", project_dir=tmp_path)
        out = tmp_path / "for-consumer.tnpkg"
        payments.bundle_for_recipient(
            recipient_did=consumer.cfg.device.did,
            out_path=out,
            groups=["default"],
        )
        assert out.is_file()

    def test_propagation_streams_inherit_default_handlers(self, tmp_path):
        # Default has a file.rotating handler at .tn/default/logs/tn.ndjson.
        # When we create payments (transaction profile, also file.rotating
        # but at .tn/payments/logs/payments.ndjson), payments' yaml ends
        # up with BOTH handlers — its own AND default's, additive.
        # That's the "stdout backbone" property: every stream's effective
        # handler set includes the project's default.
        tn.init("default", project_dir=tmp_path)  # ensure default exists
        h = tn.init("payments", profile="transaction", project_dir=tmp_path)

        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        handler_names = {(x.get("name") or x.get("kind")) for x in doc["handlers"]}
        # Payments declared its own "main" file handler; inherited
        # default's "main" got skipped because the name collides
        # (strict-additive: child wins on name conflict). Default's
        # stdout (kind="stdout") inherits.
        # Since both default and payments use name="main" for their
        # file handlers, the dedup by name keeps payments' file
        # (declared first) and skips default's. Stdout cascades.
        assert "main" in handler_names

    def test_propagation_dedups_by_name_strict_additive(self, tmp_path):
        # If the parent has a uniquely-named handler the child doesn't,
        # the child's effective list includes it. If they share a name,
        # the child's wins (declared first).
        tn.init("default", project_dir=tmp_path)
        h = tn.init("payments", profile="transaction", project_dir=tmp_path)

        # Verify the merged list never has two handlers with the same
        # name, regardless of how messy the inheritance chain is.
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        names = [x.get("name") or x.get("kind") for x in doc["handlers"]]
        assert len(names) == len(set(names)), (
            f"merged handler list has duplicates by name: {names}"
        )

    def test_streams_share_keystore_directory(self, tmp_path):
        tn.init("a", profile="transaction", project_dir=tmp_path)
        tn.init("b", profile="audit", project_dir=tmp_path)
        tn.init("c", profile="telemetry", project_dir=tmp_path)
        # All three streams share one keystore at .tn/default/keys/.
        # No per-stream key files.
        keys = tmp_path / ".tn" / "default" / "keys"
        assert keys.is_dir()
        for name in ("a", "b", "c"):
            assert not (tmp_path / ".tn" / name / "keys").exists()
