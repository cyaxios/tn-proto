"""Profile catalog tests.

Profiles are SDK-fixed types. These tests pin the catalog shape so a
PR that silently changes a property (e.g. flips signing on a profile)
fails in CI before it lands. Any intentional change here MUST update
the docstring in ``tn._profiles`` first to record the rationale.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from tn import _profiles


class TestCatalogShape:
    def test_all_profiles_listed(self):
        assert set(_profiles.all_profile_names()) == {
            "transaction",
            "audit",
            "secure_log",
            "telemetry",
        }

    def test_default_is_transaction(self):
        assert _profiles.DEFAULT_PROFILE == "transaction"

    def test_all_profiles_encrypt(self):
        # Encryption is the unconditional floor across the catalog.
        # If you flip this off for any profile, you've broken the
        # protocol's privacy guarantee.
        for name in _profiles.all_profile_names():
            assert _profiles.get(name).encrypts is True


class TestTransactionProfile:
    def test_properties(self):
        p = _profiles.get("transaction")
        assert p.signs is True
        assert p.chains is True
        assert p.flush == "fsync"
        assert p.default_sink == "file_rotating"
        assert p.has_replay_surface() is True


class TestAuditProfile:
    def test_properties(self):
        p = _profiles.get("audit")
        assert p.signs is True
        assert p.chains is True
        assert p.flush == "buffered"
        assert p.default_sink == "file_rotating"
        assert p.has_replay_surface() is True


class TestSecureLogProfile:
    def test_properties(self):
        p = _profiles.get("secure_log")
        assert p.signs is True
        assert p.chains is False  # entries stand alone
        assert p.flush == "buffered"
        assert p.default_sink == "file_rotating"
        assert p.has_replay_surface() is True


class TestTelemetryProfile:
    def test_properties(self):
        p = _profiles.get("telemetry")
        # Fast-as-stdlib-logger profile: drop signing for speed.
        # Encryption stays on (floor).
        assert p.signs is False
        assert p.chains is False
        assert p.flush == "async"
        assert p.default_sink == "stdout"

    def test_telemetry_has_no_replay_surface(self):
        p = _profiles.get("telemetry")
        assert p.has_replay_surface() is False


class TestLookup:
    def test_get_unknown_raises(self):
        with pytest.raises(KeyError, match="unknown profile"):
            _profiles.get("not_a_real_profile")

    def test_is_known(self):
        assert _profiles.is_known("transaction")
        assert not _profiles.is_known("not_a_real_profile")
