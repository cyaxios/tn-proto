"""Known behavioral issues surfaced while authoring the Databricks
onboarding notebooks for the TN curriculum (2026-05).

Each test reproduces one finding from the alpha 0.3.0a1 SDK as exercised
end-to-end against the public API. They're marked ``xfail`` so the suite
stays green; if the underlying behavior is fixed the test will XPASS, at
which point the ``xfail`` mark should be removed.

The notebooks themselves live in ``tn_skills/notebooks/databricks/``;
``02_multi_handler_and_groups.py`` was where these specifically surfaced.
"""

from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import pytest
import yaml as _yaml

import tn


def _safe_close() -> None:
    try:
        tn.flush_and_close()
    except Exception:
        pass


@pytest.mark.xfail(
    reason="Finding 02-A: extra file.rotating handlers declared in tn.yaml "
    "are silently ignored under the default Rust emit runtime — only "
    "cfg.log_path receives writes. Workaround: pass extra_handlers=[...] "
    "to tn.init programmatically. Surfaced while authoring Databricks "
    "onboarding notebook 02 (multi-handler & groups)."
)
def test_yaml_multihandler_fans_out_under_rust_runtime():
    """Two ``file.rotating`` handlers declared in ``tn.yaml`` should both
    receive a single emitted entry."""
    cwd_before = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="tn_finding_a_") as td:
        td_path = Path(td)
        os.chdir(td_path)
        try:
            # Mint a baseline tn.yaml.
            tn.init(td_path / "tn.yaml")
            _safe_close()

            # Append a second file.rotating handler at a different path.
            yaml_path = td_path / "tn.yaml"
            cfg = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            cfg["handlers"].append(
                {
                    "kind": "file.rotating",
                    "name": "extra",
                    "path": "./.tn/extra/extra.ndjson",
                    "max_bytes": 5_242_880,
                    "backup_count": 5,
                    "rotate_on_init": False,
                }
            )
            yaml_path.write_text(_yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")

            # Re-init from the updated yaml and emit one entry.
            tn.init(yaml_path)
            tn.info("multihandler.probe", payload="hello")
            _safe_close()

            main_log = td_path / ".tn/tn/logs/tn.ndjson"
            extra_log = td_path / ".tn/extra/extra.ndjson"
            assert main_log.exists(), "main log missing"
            assert extra_log.exists(), "extra log missing"

            main_has = any(
                '"multihandler.probe"' in ln for ln in main_log.open(encoding="utf-8")
            )
            extra_has = any(
                '"multihandler.probe"' in ln for ln in extra_log.open(encoding="utf-8")
            )
            assert main_has, "main log lacks the probe entry"
            assert extra_has, (
                "extra log lacks the probe entry — yaml-declared extra "
                "handlers are silently ignored under the Rust runtime"
            )
        finally:
            os.chdir(cwd_before)
            _safe_close()


@pytest.mark.xfail(
    reason="Finding 02-B: tn.read_as_recipient yields entries shaped as "
    "{envelope, plaintext, valid} while tn.read yields flat dicts. The "
    "two views of the same log should expose event_type at the same "
    "level so consumers don't need shape-aware accessors. Surfaced while "
    "authoring Databricks onboarding notebook 02."
)
def test_read_as_recipient_shape_matches_read():
    """``tn.read`` and ``tn.read_as_recipient`` should yield entries with
    the same dict shape — specifically, ``entry["event_type"]`` should
    work for both."""
    cwd_before = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="tn_finding_b_pub_") as pub_td, \
         tempfile.TemporaryDirectory(prefix="tn_finding_b_recip_") as recip_td:
        pub = Path(pub_td)
        recip = Path(recip_td)
        os.chdir(pub)
        try:
            tn.init(pub / "tn.yaml")
            tn.info("probe.event", note="shape-check")

            # Mint a kit for a label-DID recipient and manually unpack it
            # into a fresh keystore (per Finding 02-C, absorb itself can't
            # target a separate keystore).
            kit_pkg = pub / "recipient.tnpkg"
            tn.pkg.bundle_for_recipient(
                "did:key:zLabel-bob", kit_pkg, groups=["default"]
            )
            recip_keys = recip / "keys"
            recip_keys.mkdir(parents=True)
            with zipfile.ZipFile(kit_pkg) as z:
                for name in z.namelist():
                    if name.startswith("body/") and name.endswith(".btn.mykit"):
                        z.extract(name, recip)
                        (recip / name).rename(recip_keys / Path(name).name)

            log_path = pub / ".tn/tn/logs/tn.ndjson"
            flat_event_type = next(
                (e.get("event_type") for e in tn.read()
                 if e.get("event_type") == "probe.event"),
                None,
            )
            recip_event_type = next(
                (
                    e.get("event_type")
                    for e in tn.read_as_recipient(log_path, recip_keys, group="default")
                    if e.get("event_type") == "probe.event"
                ),
                None,
            )

            assert flat_event_type == "probe.event"
            assert recip_event_type == "probe.event", (
                "read_as_recipient should yield the same flat-dict shape "
                "as read"
            )
        finally:
            os.chdir(cwd_before)
            _safe_close()


@pytest.mark.xfail(
    reason="Finding 02-C: tn.pkg.absorb writes into the active cfg's "
    "keystore (the publisher's). There is no documented way to point "
    "absorb at a separate recipient keystore, so recipient demos must "
    "manually unzip the .tnpkg body. Surfaced while authoring Databricks "
    "onboarding notebook 02."
)
def test_pkg_absorb_can_target_separate_keystore():
    """``tn.pkg.absorb`` should accept a target keystore directory so a
    recipient can absorb a kit into their own keystore without conflating
    state with the publisher."""
    cwd_before = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="tn_finding_c_pub_") as pub_td, \
         tempfile.TemporaryDirectory(prefix="tn_finding_c_recip_") as recip_td:
        pub = Path(pub_td)
        recip = Path(recip_td)
        os.chdir(pub)
        try:
            tn.init(pub / "tn.yaml")
            kit_pkg = pub / "recipient.tnpkg"
            tn.pkg.bundle_for_recipient(
                "did:key:zLabel-bob", kit_pkg, groups=["default"]
            )

            recip_keys = recip / "keys"
            recip_keys.mkdir(parents=True)

            # Try every plausible kwarg name; if none work, the API is
            # missing the feature this test is asserting.
            absorbed = False
            for kw in (
                {"keystore": recip_keys},
                {"keystore_dir": recip_keys},
                {"target_keystore": recip_keys},
                {"into": recip_keys},
            ):
                try:
                    tn.pkg.absorb(kit_pkg, **kw)
                    absorbed = True
                    break
                except TypeError:
                    continue

            assert absorbed, (
                "tn.pkg.absorb has no recognised kwarg for redirecting "
                "into a separate keystore directory"
            )

            mykit_files = [p for p in recip_keys.iterdir() if p.name.endswith(".btn.mykit")]
            assert mykit_files, (
                f"recipient keystore should contain absorbed .btn.mykit files; "
                f"got: {[p.name for p in recip_keys.iterdir()]}"
            )
        finally:
            os.chdir(cwd_before)
            _safe_close()
