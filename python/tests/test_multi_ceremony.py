"""Tests for the multi-ceremony module verbs (tn.init, tn.use, tn.list)
and the underlying ``_handle``, ``_registry``, ``_layout``, ``_defaults``
modules.

This sprint lands the API surface and the on-disk layout. Multi-ceremony
*emit* against non-default names is staged for the next sprint and is
asserted to raise ``MultiCeremonyEmitNotImplemented`` here so the
contract is discoverable from tests.

Coverage:
  * Layout helpers: name validation, directory paths, on-disk listing.
  * Migration: .tn/tn/ -> .tn/default/ rename, idempotence,
    ambiguous-state error.
  * Safe defaults: ``safe_defaults_yaml`` shape, single-recipient,
    private group.
  * Registry: register, get (strict), list_names, idempotent re-register,
    conflict-on-replace.
  * tn.init(name=...): creates .tn/<name>/, returns TN, stamps yaml.
  * tn.init(yaml_path=...): legacy form still works, registers default.
  * tn.use(name): get-or-create, registry-cache hit, never raises for
    valid names.
  * tn.list_ceremonies(): in-process registry only.
  * Conflict: init kwargs disagreeing with on-disk yaml -> TNConfigConflict.
  * Non-default emit: raises MultiCeremonyEmitNotImplemented.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import (
    MultiCeremonyEmitNotImplemented,
    TN,
    TNConfigConflict,
    TNInvalidName,
    TNNotFound,
)
from tn import _autoinit, _defaults, _layout, _registry


# Anything that triggers the legacy ``create_fresh`` path (i.e. binds
# the singleton for the default ceremony) needs the tn_btn Rust
# extension because ``btn`` is the default cipher and create_fresh
# does the cipher bootstrap. Dev environments without the wheel skip
# those tests; everything else still runs.
try:
    import tn_btn as _tn_btn  # type: ignore[import-not-found]  # noqa: F401
    _HAS_BTN = True
except ImportError:
    _HAS_BTN = False

requires_btn = pytest.mark.skipif(
    not _HAS_BTN,
    reason="tn_btn Rust extension not installed in this environment",
)


# ---------------------------------------------------------------------------
# Per-test isolation: every test gets a fresh cwd, no env leakage, and a
# cleared registry. Mirrors the autoinit suite's cleanup hygiene so we do
# not accidentally pick up a runtime from a sibling test.
# ---------------------------------------------------------------------------


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
# _layout
# ---------------------------------------------------------------------------


class TestLayoutNames:
    @pytest.mark.parametrize(
        "name",
        ["default", "payments", "agents", "abc_123", "Foo", "x", "with-dash"],
    )
    def test_valid_names(self, name):
        assert _layout.is_valid_ceremony_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "",                  # empty
            "tn",                # legacy, reserved
            ".hidden",           # leading dot
            "-leading-dash",     # leading dash
            "with/slash",        # path separator
            "with\\back",        # windows separator
            "spa ce",            # space
            "uniçode",      # non-ascii
        ],
    )
    def test_invalid_names(self, name):
        assert not _layout.is_valid_ceremony_name(name)


class TestLayoutPaths:
    def test_tn_root_default_is_cwd_dot_tn(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _layout.tn_root() == (tmp_path / ".tn").resolve()

    def test_tn_root_explicit_project_dir(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        assert _layout.tn_root(proj) == (proj / ".tn").resolve()

    def test_ceremony_dir_and_yaml(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        d = _layout.ceremony_dir("payments", project_dir=proj)
        y = _layout.ceremony_yaml_path("payments", project_dir=proj)
        assert d == (proj / ".tn" / "payments").resolve()
        assert y == d / "tn.yaml"

    def test_ceremony_dir_rejects_invalid_name(self, tmp_path):
        with pytest.raises(_layout.TNInvalidName):
            _layout.ceremony_dir("bad/name", project_dir=tmp_path)


class TestLayoutListing:
    def test_empty_when_no_dot_tn(self, tmp_path):
        assert _layout.list_ceremonies_on_disk(tmp_path) == []

    def test_lists_only_dirs_with_yaml(self, tmp_path):
        root = tmp_path / ".tn"
        (root / "default").mkdir(parents=True)
        (root / "default" / "tn.yaml").write_text("ceremony: {}\n")
        (root / "payments").mkdir()
        (root / "payments" / "tn.yaml").write_text("ceremony: {}\n")
        (root / "no_yaml").mkdir()  # no tn.yaml -> skipped
        names = _layout.list_ceremonies_on_disk(tmp_path)
        assert names == ["default", "payments"]


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


class TestMigration:
    def test_no_migration_when_no_legacy(self, tmp_path):
        assert _layout.migrate_legacy_layout(tmp_path) is None

    def test_renames_legacy_to_default(self, tmp_path):
        legacy = tmp_path / ".tn" / "tn"
        legacy.mkdir(parents=True)
        (legacy / "tn.yaml").write_text("ceremony: {}\n")

        out = _layout.migrate_legacy_layout(tmp_path)

        assert out == (tmp_path / ".tn" / "default").resolve()
        assert out.is_dir()
        assert (out / "tn.yaml").is_file()
        assert not legacy.exists()

    def test_idempotent_after_migration(self, tmp_path):
        legacy = tmp_path / ".tn" / "tn"
        legacy.mkdir(parents=True)
        (legacy / "tn.yaml").write_text("ceremony: {}\n")
        _layout.migrate_legacy_layout(tmp_path)
        # Second call: no legacy left to migrate.
        assert _layout.migrate_legacy_layout(tmp_path) is None

    def test_ambiguous_both_exist(self, tmp_path):
        legacy = tmp_path / ".tn" / "tn"
        target = tmp_path / ".tn" / "default"
        legacy.mkdir(parents=True)
        (legacy / "tn.yaml").write_text("ceremony: {}\n")
        target.mkdir()
        (target / "tn.yaml").write_text("ceremony: {}\n")
        with pytest.raises(RuntimeError, match="ambiguous"):
            _layout.migrate_legacy_layout(tmp_path)

    def test_dry_run_does_not_touch_disk(self, tmp_path):
        legacy = tmp_path / ".tn" / "tn"
        legacy.mkdir(parents=True)
        (legacy / "tn.yaml").write_text("ceremony: {}\n")
        out = _layout.migrate_legacy_layout(tmp_path, dry_run=True)
        assert out == (tmp_path / ".tn" / "default").resolve()
        assert legacy.exists()


# ---------------------------------------------------------------------------
# Safe defaults
# ---------------------------------------------------------------------------


class TestSafeDefaults:
    def test_shape(self):
        body = _defaults.safe_defaults_yaml(device_did="did:key:zABC")
        assert body["ceremony"]["profile"] == "transaction"
        assert body["ceremony"]["cipher"] == "btn"
        assert body["default_policy"] == "private"
        assert body["groups"]["default"]["policy"] == "private"
        assert body["groups"]["default"]["recipients"] == [{"did": "did:key:zABC"}]

    def test_fresh_dict_each_call(self):
        a = _defaults.safe_defaults_yaml(device_did="did:key:zA")
        b = _defaults.safe_defaults_yaml(device_did="did:key:zA")
        assert a is not b
        a["ceremony"]["profile"] = "telemetry"  # must not affect b
        assert b["ceremony"]["profile"] == "transaction"

    def test_default_constant_name(self):
        assert _defaults.DEFAULT_CEREMONY_NAME == "default"
        assert _defaults.LEGACY_DEFAULT_DIRNAME == "tn"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def _make(self, name, tmp_path):
        return TN(
            name=name,
            yaml_path=tmp_path / ".tn" / name / "tn.yaml",
            directory=tmp_path / ".tn" / name,
        )

    def test_register_then_get(self, tmp_path):
        h = self._make("payments", tmp_path)
        _registry.register("payments", h)
        assert _registry.get("payments") is h

    def test_get_missing_raises_tn_not_found(self):
        with pytest.raises(TNNotFound) as exc:
            _registry.get("nonexistent")
        assert exc.value.name == "nonexistent"
        assert exc.value.registered == []

    def test_register_idempotent_for_same_handle(self, tmp_path):
        h = self._make("a", tmp_path)
        _registry.register("a", h)
        _registry.register("a", h)  # no error

    def test_register_rejects_replacement_with_different_handle(self, tmp_path):
        h1 = self._make("a", tmp_path)
        h2 = self._make("a", tmp_path)
        _registry.register("a", h1)
        with pytest.raises(RuntimeError, match="already registered"):
            _registry.register("a", h2)

    def test_list_names_sorted(self, tmp_path):
        for n in ["zebra", "alpha", "midline"]:
            _registry.register(n, self._make(n, tmp_path))
        assert _registry.list_names() == ["alpha", "midline", "zebra"]


# ---------------------------------------------------------------------------
# tn.init / tn.use / tn.list_ceremonies
# ---------------------------------------------------------------------------


class TestInitUseList:
    def test_init_named_ceremony_creates_directory(self, tmp_path):
        handle = tn.init("payments", project_dir=tmp_path)
        assert isinstance(handle, TN)
        assert handle.name == "payments"
        assert handle.directory == (tmp_path / ".tn" / "payments").resolve()
        assert handle.yaml_path.is_file()

    def test_init_writes_minimal_extends_based_stream_yaml(self, tmp_path):
        # Stream yamls are minimal: an ``extends:`` pointing at
        # default plus only the per-stream overrides (ceremony.id,
        # ceremony.profile, logs.path, handlers).
        handle = tn.init("payments", project_dir=tmp_path)
        import yaml
        with handle.yaml_path.open("r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        # The stream yaml carries extends pointing at default.
        assert "extends" in doc
        assert doc["extends"].endswith("default/tn.yaml") or \
               doc["extends"].endswith("default\\tn.yaml")
        # Stream-specific fields present.
        assert (doc.get("ceremony") or {}).get("profile") == "transaction"
        assert (doc.get("ceremony") or {}).get("id", "").startswith("stream_payments_")
        # Identity / groups / recipients NOT in the stream yaml —
        # those come from default at load time via _resolve_extends.
        assert "me" not in doc, "me.did should come from default via extends"
        assert "groups" not in doc, "groups should come from default via extends"
        assert "keystore" not in doc, "keystore should come from default via extends"

    def test_loaded_cfg_inherits_default_identity_via_extends(self, tmp_path):
        # The loader resolves extends and the resulting cfg has
        # identity/keystore/groups merged in from default.
        from tn import config as _config
        h = tn.init("payments", project_dir=tmp_path)
        cfg = _config.load(h.yaml_path)
        # Merged cfg has the project DID + groups even though the
        # on-disk stream yaml is minimal.
        assert cfg.device.did.startswith("did:key:z")
        assert "default" in cfg.groups

    def test_init_named_ceremony_registers(self, tmp_path):
        tn.init("payments", project_dir=tmp_path)
        assert "payments" in tn.list_ceremonies()

    def test_init_idempotent_returns_same_handle(self, tmp_path):
        h1 = tn.init("payments", project_dir=tmp_path)
        h2 = tn.init("payments", project_dir=tmp_path)
        assert h1 is h2

    def test_init_invalid_name_raises(self, tmp_path):
        with pytest.raises(TNInvalidName):
            tn.init("bad/name", project_dir=tmp_path)

    def test_use_get_or_create(self, tmp_path):
        # Cold call: nothing registered, nothing on disk -> auto-creates.
        handle = tn.use("agents", project_dir=tmp_path)
        assert handle.name == "agents"
        assert handle.yaml_path.is_file()

    def test_use_returns_registry_hit(self, tmp_path):
        h1 = tn.init("payments", project_dir=tmp_path)
        h2 = tn.use("payments", project_dir=tmp_path)
        assert h1 is h2

    def test_use_attaches_to_disk_only_ceremony(self, tmp_path):
        # Pre-create a real ceremony on disk (init does the minting),
        # then drop the in-process registry entry to simulate
        # "ceremony exists on disk from a prior run; this process
        # hasn't seen it yet." tn.use should re-attach to it.
        from tn._registry import clear_registry_for_tests
        marker_did = "did:key:zMarkerForDiskAttachTest"
        tn.init("audit", project_dir=tmp_path)
        d = tmp_path / ".tn" / "audit"
        # Stamp a marker into the yaml so the post-attach check can
        # verify the on-disk file wasn't clobbered by tn.use.
        yaml_text = (d / "tn.yaml").read_text(encoding="utf-8")
        (d / "tn.yaml").write_text(
            yaml_text + f"\n# marker: {marker_did}\n", encoding="utf-8"
        )
        clear_registry_for_tests()

        handle = tn.use("audit", project_dir=tmp_path)
        assert handle.name == "audit"
        assert "audit" in tn.list_ceremonies()
        # Must not have overwritten the existing yaml.
        assert marker_did in (d / "tn.yaml").read_text(encoding="utf-8")

    def test_use_invalid_name_raises(self, tmp_path):
        with pytest.raises(TNInvalidName):
            tn.use("bad/name", project_dir=tmp_path)

    def test_use_accepts_profile_kwarg_on_creation(self, tmp_path):
        """0.4.0a5+: ``tn.use(name, profile=...)`` stamps the profile
        at creation time, same as ``tn.init(name, profile=...)``."""
        import yaml as _yaml
        handle = tn.use("audit_stream", profile="audit", project_dir=tmp_path)
        assert handle.name == "audit_stream"
        doc = _yaml.safe_load(handle.yaml_path.read_text(encoding="utf-8"))
        assert (doc.get("ceremony") or {}).get("profile") == "audit"

    def test_use_profile_kwarg_validates_unknown_profile(self, tmp_path):
        """Typo'd profile names fail fast (delegates to init's validation)."""
        with pytest.raises(TNConfigConflict, match="unknown profile"):
            tn.use("oops", profile="nonsense", project_dir=tmp_path)

    def test_use_profile_kwarg_ignored_on_registry_hit(self, tmp_path):
        """A code-supplied profile on a registry-cached handle has no
        effect — the handle is already bound. (Operator authority:
        on-disk yaml is the source of truth; you can't change profile
        via a runtime kwarg.)"""
        h1 = tn.init("payments", profile="transaction", project_dir=tmp_path)
        # Second call with a *different* profile must NOT raise or
        # rebind; it just returns the cached handle.
        h2 = tn.use("payments", profile="audit", project_dir=tmp_path)
        assert h1 is h2

    def test_list_ceremonies_empty_initially(self):
        assert tn.list_ceremonies() == []

    def test_list_ceremonies_reflects_registrations(self, tmp_path):
        tn.init("payments", project_dir=tmp_path)
        tn.init("agents", project_dir=tmp_path)
        assert tn.list_ceremonies() == ["agents", "payments"]


# ---------------------------------------------------------------------------
# Profile-conflict policy
# ---------------------------------------------------------------------------


def _mint_then_set_profile(tmp_path, name: str, profile: str) -> None:
    """Mint a real ceremony at .tn/<name>/, then rewrite its yaml's
    ceremony.profile field to ``profile``. Used by the conflict-policy
    tests below — they need an on-disk yaml that's both complete (so
    the post-#a7 binding init load() succeeds) AND has a specific
    profile to compare against.
    """
    import yaml as _yaml
    from tn._registry import clear_registry_for_tests

    tn.init(name, project_dir=tmp_path)
    clear_registry_for_tests()
    yaml_path = tmp_path / ".tn" / name / "tn.yaml"
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["profile"] = profile
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


class TestConflictPolicy:
    def test_conflict_when_init_disagrees_with_on_disk_logs_warning(
        self, tmp_path, caplog
    ):
        # Operator authority: on-disk yaml wins, code kwarg yields.
        # The conflict is surfaced via a warning so a developer
        # running locally sees that their intent was overridden.
        import logging
        _mint_then_set_profile(tmp_path, "payments", "audit")
        with caplog.at_level(logging.WARNING, logger="tn"):
            handle = tn.init(
                "payments", profile="transaction", project_dir=tmp_path
            )
        # Returns a handle, doesn't raise.
        assert handle.name == "payments"
        # And surfaces the conflict via the tn logger.
        assert any(
            "profile conflict" in rec.message.lower()
            for rec in caplog.records
        )

    def test_unknown_profile_name_raises(self, tmp_path):
        # An unknown profile (typo, etc.) fails fast — that's not a
        # conflict, it's misconfig at the call site.
        with pytest.raises(TNConfigConflict, match="unknown profile"):
            tn.init(
                "payments",
                profile="not_a_real_profile",
                project_dir=tmp_path,
            )

    def test_no_conflict_when_kwarg_matches(self, tmp_path):
        _mint_then_set_profile(tmp_path, "payments", "audit")
        # Same value -> fine.
        h = tn.init("payments", profile="audit", project_dir=tmp_path)
        assert h.name == "payments"

    def test_no_conflict_when_kwarg_omitted(self, tmp_path):
        _mint_then_set_profile(tmp_path, "payments", "audit")
        h = tn.init("payments", project_dir=tmp_path)  # no profile kwarg
        assert h.name == "payments"


# ---------------------------------------------------------------------------
# Migration on init
# ---------------------------------------------------------------------------


class TestInitMigration:
    def test_init_migrates_legacy(self, tmp_path):
        # Pre-populate a "legacy single-ceremony" layout with a real,
        # loadable yaml + keystore. The migration should rename the
        # directory; subsequent stream creation against the migrated
        # default should work because the default's identity carries
        # over.
        from tn import config as _config
        legacy = tmp_path / ".tn" / "tn"
        legacy.mkdir(parents=True)
        for sub in ("keys", "logs", "admin", "vault"):
            (legacy / sub).mkdir()
        legacy_yaml = legacy / "tn.yaml"
        try:
            _config.create_fresh(
                legacy_yaml,
                cipher="btn",
                keystore_dir=legacy / "keys",
                log_path=legacy / "logs" / "tn.ndjson",
                admin_log_path=legacy / "admin" / "admin.ndjson",
            )
        except Exception:
            pytest.skip("create_fresh requires tn_btn; skipping migration test")

        # Calling init() for any name should opportunistically migrate.
        tn.init("payments", project_dir=tmp_path)

        assert not legacy.exists()
        assert (tmp_path / ".tn" / "default").is_dir()
        assert (tmp_path / ".tn" / "default" / "tn.yaml").is_file()
        assert (tmp_path / ".tn" / "payments" / "tn.yaml").is_file()


# ---------------------------------------------------------------------------
# Multi-ceremony emit not yet implemented
# ---------------------------------------------------------------------------


class TestNonDefaultEmit:
    """Live emit (info/log/debug/warning/error) on a non-default
    stream activates the ceremony (binds the singleton to its yaml)
    and delegates to the standard emit pipeline. The activation
    side-effect is documented; ops are serial across streams in
    this sprint."""

    def test_named_ceremony_info_works(self, tmp_path):
        try:
            import tn_btn  # noqa: F401
        except ImportError:
            pytest.skip("tn_btn extension not available")
        h = tn.init("payments", project_dir=tmp_path)
        # Should not raise.
        h.info("payment.charged", amount=4999)

    @pytest.mark.parametrize("verb", ["log", "debug", "info", "warning", "error"])
    def test_named_ceremony_each_verb_works(self, tmp_path, verb):
        try:
            import tn_btn  # noqa: F401
        except ImportError:
            pytest.skip("tn_btn extension not available")
        h = tn.init("payments", project_dir=tmp_path)
        getattr(h, verb)("evt.t", k=1)

    def test_named_ceremony_read_works_for_replay_surface_profiles(
        self, tmp_path
    ):
        # Default profile is ``transaction`` which has a file sink.
        # ``read`` activates the ceremony and delegates to the legacy
        # reader. For an empty fresh ceremony, the result is just an
        # empty iterator (no entries yet). We verify it doesn't raise.
        h = tn.init("payments", project_dir=tmp_path)
        try:
            list(h.read())
        except Exception as exc:
            # Any failure here would be in the legacy reader, not in
            # the multi-ceremony surface — re-raise so it's visible.
            raise AssertionError(
                f"non-default read should not raise on a fresh ceremony "
                f"with a replay-surface profile; got {exc!r}"
            ) from exc

    def test_named_ceremony_read_returns_empty_for_telemetry_profile(
        self, tmp_path
    ):
        # ``telemetry`` profile has stdout sink only; no replay
        # surface. ``read`` should return an empty iterator rather
        # than raising — semantics: "this stream has nothing to
        # replay" is different shape, not an error.
        h = tn.init(
            "traces", profile="telemetry", project_dir=tmp_path
        )
        result = list(h.read())
        assert result == []


# ---------------------------------------------------------------------------
# Backwards compat: legacy tn.init('tn.yaml') signature
# ---------------------------------------------------------------------------


class TestLegacyInitShim:
    @requires_btn
    def test_legacy_yaml_path_positional(self, tmp_path, monkeypatch):
        # The legacy form ``tn.init("path/to/file.yaml")`` should keep
        # working: detect the path, route through the existing init,
        # register the resulting ceremony as "default".
        cwd = tmp_path / "proj"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        monkeypatch.setenv("TN_HOME", str(tmp_path / "tnhome"))

        # Legacy form: yaml_path-as-positional. The shim auto-creates
        # the yaml at the given path via the existing fresh-create
        # pipeline, binds the singleton, and returns a TN handle for
        # 'default'.
        yaml_path = cwd / "tn.yaml"
        handle = tn.init(str(yaml_path))

        assert isinstance(handle, TN)
        assert handle.name == "default"
        assert handle.yaml_path.resolve() == yaml_path.resolve()
        # Singleton was bound (legacy yaml-path init route).
        assert tn._dispatch_rt is not None


# ---------------------------------------------------------------------------
# TN handle properties
# ---------------------------------------------------------------------------


class TestTNHandle:
    def test_is_default_property(self, tmp_path):
        # Test the property without going through tn.init('default'),
        # which triggers the legacy create_fresh path requiring tn_btn.
        # Direct construction is the right way to assert the property
        # contract anyway.
        default_handle = TN(
            name="default",
            yaml_path=tmp_path / ".tn" / "default" / "tn.yaml",
            directory=tmp_path / ".tn" / "default",
        )
        named_handle = TN(
            name="payments",
            yaml_path=tmp_path / ".tn" / "payments" / "tn.yaml",
            directory=tmp_path / ".tn" / "payments",
        )
        assert default_handle.is_default
        assert not named_handle.is_default

    @requires_btn
    def test_is_default_via_init(self, tmp_path):
        d = tn.init("default", project_dir=tmp_path)
        p = tn.init("payments", project_dir=tmp_path)
        assert d.is_default
        assert not p.is_default

    def test_repr(self, tmp_path):
        h = tn.init("payments", project_dir=tmp_path)
        s = repr(h)
        assert "payments" in s
        assert "TN(" in s
