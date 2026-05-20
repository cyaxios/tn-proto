"""Tests for the ``extends:`` resolution in config.load.

These tests pin the merge semantics that make multi-ceremony work
without manual yaml duplication: streams declare only their
overrides; identity, groups, recipients come from default at
load time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]
import yaml as _yaml

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from tn import _autoinit, _registry, config as _config


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
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _registry.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# Mechanics: _read_yaml_doc + _resolve_extends.
# ---------------------------------------------------------------------------


class TestExtendsResolutionMechanics:
    def _setup_pair(self, tmp_path):
        """Write a minimal parent + child yaml; return their paths."""
        parent = tmp_path / "parent.yaml"
        child = tmp_path / "child.yaml"
        parent.write_text(
            _yaml.safe_dump(
                {
                    "ceremony": {"id": "P1", "cipher": "btn", "sign": True},
                    "me": {"did": "did:key:zParent"},
                    "keystore": {"path": "./keys"},
                    "groups": {
                        "default": {
                            "policy": "private",
                            "cipher": "btn",
                            "recipients": [{"did": "did:key:zParent"}],
                        }
                    },
                    "default_policy": "private",
                    "logs": {"path": "./logs/parent.ndjson"},
                    "handlers": [{"kind": "stdout", "name": "stdout"}],
                }
            ),
            encoding="utf-8",
        )
        child.write_text(
            _yaml.safe_dump(
                {
                    "extends": "parent.yaml",
                    "ceremony": {"id": "C1", "profile": "audit"},
                    "logs": {"path": "./logs/child.ndjson"},
                    "handlers": [
                        {"kind": "file.rotating", "name": "main", "path": "./logs/child.ndjson"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        return parent, child

    def test_extends_pulls_identity_from_parent(self, tmp_path):
        _, child = self._setup_pair(tmp_path)
        doc = _config._read_yaml_doc(child)
        merged = _config._resolve_extends(child, doc)
        assert merged["me"]["did"] == "did:key:zParent"
        assert "default" in merged["groups"]

    def test_extends_resolves_keystore_to_absolute_path(self, tmp_path):
        _, child = self._setup_pair(tmp_path)
        doc = _config._read_yaml_doc(child)
        merged = _config._resolve_extends(child, doc)
        # Parent's relative ./keys becomes absolute, rooted at parent's dir.
        ks_path = Path(merged["keystore"]["path"])
        assert ks_path.is_absolute()
        assert ks_path == (tmp_path / "keys").resolve()

    def test_extends_child_ceremony_fields_win(self, tmp_path):
        _, child = self._setup_pair(tmp_path)
        doc = _config._read_yaml_doc(child)
        merged = _config._resolve_extends(child, doc)
        # Child's ceremony.id wins.
        assert merged["ceremony"]["id"] == "C1"
        # Child's ceremony.profile is added.
        assert merged["ceremony"]["profile"] == "audit"
        # Parent's ceremony.cipher carries through.
        assert merged["ceremony"]["cipher"] == "btn"

    def test_extends_child_logs_wins(self, tmp_path):
        _, child = self._setup_pair(tmp_path)
        doc = _config._read_yaml_doc(child)
        merged = _config._resolve_extends(child, doc)
        # Child's logs.path wins outright (not absolutized at child level).
        assert merged["logs"]["path"] == "./logs/child.ndjson"

    def test_extends_handlers_replaces(self, tmp_path):
        """0.4.2a9: declaring ``handlers:`` on the child REPLACES the
        parent's list (was additive-with-dedupe, which surprised
        users — see 0.4.2a9 bug-2 fix in `_resolve_extends`)."""
        _, child = self._setup_pair(tmp_path)
        doc = _config._read_yaml_doc(child)
        merged = _config._resolve_extends(child, doc)
        # Child has file.rotating "main"; parent has stdout "stdout".
        # The child declared handlers, so its list replaces the parent's
        # — only "main" survives.
        names = {h.get("name") or h.get("kind") for h in merged["handlers"]}
        assert names == {"main"}, (
            f"child handlers: should replace parent's; got {names}"
        )

    def test_extends_child_overriding_parent_owned_logs_warning(
        self, tmp_path, caplog
    ):
        import logging
        _, child = self._setup_pair(tmp_path)
        # Child illegally tries to set me.did.
        doc = _yaml.safe_load(child.read_text(encoding="utf-8"))
        doc["me"] = {"did": "did:key:zCHILD_TRYING_TO_OVERRIDE"}
        child.write_text(_yaml.safe_dump(doc), encoding="utf-8")

        cdoc = _config._read_yaml_doc(child)
        with caplog.at_level(logging.WARNING, logger="tn"):
            merged = _config._resolve_extends(child, cdoc)
        # Parent wins.
        assert merged["me"]["did"] == "did:key:zParent"
        # Warning was logged.
        assert any("parent-owned" in rec.message for rec in caplog.records)

    def test_extends_missing_target_raises(self, tmp_path):
        child = tmp_path / "c.yaml"
        child.write_text(
            _yaml.safe_dump(
                {"extends": "nope.yaml", "ceremony": {"id": "x"}}
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="does not exist"):
            _config._resolve_extends(child, _config._read_yaml_doc(child))

    def test_extends_cycle_detected(self, tmp_path):
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text(_yaml.safe_dump({"extends": "b.yaml"}), encoding="utf-8")
        b.write_text(_yaml.safe_dump({"extends": "a.yaml"}), encoding="utf-8")
        with pytest.raises(ValueError, match="cycle"):
            _config._resolve_extends(a, _config._read_yaml_doc(a))


# ---------------------------------------------------------------------------
# Stream creation produces minimal extends-based yamls.
# ---------------------------------------------------------------------------


@requires_btn
class TestStreamYamlIsMinimal:
    def test_stream_yaml_contains_only_overrides(self, tmp_path):
        import tn
        h = tn.init("payments", profile="transaction", project_dir=tmp_path)
        with h.yaml_path.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        # Has extends pointing at default.
        assert "extends" in doc
        # Has stream-specific fields.
        assert (doc.get("ceremony") or {}).get("profile") == "transaction"
        assert "logs" in doc
        # Does NOT have parent-owned blocks.
        for forbidden in ("me", "keystore", "groups", "default_policy", "public_fields"):
            assert forbidden not in doc, (
                f"stream yaml should not duplicate parent-owned key {forbidden!r}"
            )

    def test_stream_loaded_cfg_is_complete(self, tmp_path):
        import tn
        h = tn.init("payments", profile="transaction", project_dir=tmp_path)
        cfg = _config.load(h.yaml_path)
        # Loader resolved extends — cfg has full identity + groups.
        assert cfg.device.did.startswith("did:key:z")
        assert "default" in cfg.groups

    def test_three_streams_share_identity(self, tmp_path):
        import tn
        a = tn.init("a", project_dir=tmp_path)
        b = tn.init("b", profile="audit", project_dir=tmp_path)
        c = tn.init("c", profile="telemetry", project_dir=tmp_path)
        # Same DID across all three.
        assert a.cfg.device.did == b.cfg.device.did == c.cfg.device.did
        # Same keystore path.
        assert a.cfg.keystore == b.cfg.keystore == c.cfg.keystore
        # Distinct ceremony_ids.
        assert len({a.cfg.ceremony_id, b.cfg.ceremony_id, c.cfg.ceremony_id}) == 3


# ---------------------------------------------------------------------------
# Editing default propagates to streams (no drift).
# ---------------------------------------------------------------------------


@requires_btn
class TestNoDriftFromDefault:
    def test_default_yaml_is_source_of_truth(self, tmp_path):
        import tn
        # Create default + a stream.
        tn.init("default", project_dir=tmp_path)
        tn.init("payments", profile="transaction", project_dir=tmp_path)

        default_yaml = tmp_path / ".tn" / "default" / "tn.yaml"
        with default_yaml.open("r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
        # default has the actual identity / groups / keystore.
        assert "me" in doc
        assert "groups" in doc
        assert "keystore" in doc

        stream_yaml = tmp_path / ".tn" / "payments" / "tn.yaml"
        with stream_yaml.open("r", encoding="utf-8") as fh:
            sdoc = _yaml.safe_load(fh)
        # Stream is minimal.
        assert "me" not in sdoc
        assert "groups" not in sdoc
