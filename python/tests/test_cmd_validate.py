"""Characterization tests for ``tn.cli.cmd_validate`` (the CC-51 validator).

Written BEFORE decomposing the function into per-check helpers so the
extracted pieces must preserve every branch. These call ``cmd_validate``
in-process against a hand-crafted ``.tn/`` tree (fast, no subprocess /
real keystore) and assert on exit code + captured stderr. The DID-mismatch
and clean-init paths are already covered by
``test_validate_did_consistency.py``.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from tn.cli import cmd_validate

FULL_DEFAULT = (
    "ceremony:\n  id: c1\n  cipher: btn\n"
    "logs:\n  path: ./logs/tn.ndjson\n"
    "keystore:\n  path: ./keys\n"
    "device:\n  device_identity: did:key:zDEV\n"
    "groups:\n  default:\n    policy: private\n"
)


def _ns(project_dir: Path) -> argparse.Namespace:
    return argparse.Namespace(project_dir=str(project_dir))


def _write(root: Path, name: str, text: str) -> Path:
    d = root / ".tn" / name
    d.mkdir(parents=True, exist_ok=True)
    p = d / "tn.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_no_tn_directory_is_clean(tmp_path: Path, capsys) -> None:
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 0
    assert "nothing to validate" in capsys.readouterr().out


def test_empty_tn_directory_is_clean(tmp_path: Path, capsys) -> None:
    (tmp_path / ".tn").mkdir()
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 0
    assert "nothing to validate" in capsys.readouterr().out


def test_non_mapping_yaml_is_rejected(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "default", "- a\n- b\n")
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    assert "top-level must be a mapping" in capsys.readouterr().err


def test_missing_required_top_level_key(tmp_path: Path, capsys) -> None:
    # Only `ceremony:` present, not a stream -> logs/keystore/device/groups
    # are all required.
    _write(tmp_path, "default", "ceremony:\n  id: c1\n")
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    err = capsys.readouterr().err
    assert "missing required top-level key" in err
    assert "'keystore'" in err


def test_missing_ceremony_id(tmp_path: Path, capsys) -> None:
    text = FULL_DEFAULT.replace("  id: c1\n", "")
    _write(tmp_path, "default", text)
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    assert "ceremony.id is required" in capsys.readouterr().err


def test_unknown_profile_is_rejected(tmp_path: Path, capsys) -> None:
    text = FULL_DEFAULT.replace("  cipher: btn\n", "  cipher: btn\n  profile: no_such_profile\n")
    _write(tmp_path, "default", text)
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    assert "unknown profile" in capsys.readouterr().err


def test_legacy_me_block_is_rejected(tmp_path: Path, capsys) -> None:
    text = (
        "ceremony:\n  id: c1\n  cipher: btn\n"
        "logs:\n  path: ./logs/tn.ndjson\n"
        "keystore:\n  path: ./keys\n"
        "me:\n  did: did:key:zOLD\n"
        "groups:\n  default:\n    policy: private\n"
    )
    _write(tmp_path, "default", text)
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    assert "legacy `me:`" in capsys.readouterr().err


def test_missing_group_kit_is_flagged(tmp_path: Path, capsys) -> None:
    # FULL_DEFAULT declares a btn `default` group + keystore.path=./keys,
    # but no default.btn.mykit exists -> "kit missing".
    _write(tmp_path, "default", FULL_DEFAULT)
    rc = cmd_validate(_ns(tmp_path))
    assert rc == 1
    err = capsys.readouterr().err
    assert "kit missing" in err
    assert "default.btn.mykit" in err


def test_stream_yaml_has_narrower_requirements(tmp_path: Path, capsys) -> None:
    # A stream (`extends:`) only requires `ceremony`; it must NOT be flagged
    # for missing logs/keystore/device/groups.
    _write(tmp_path, "stream", "extends: ../default/tn.yaml\nceremony:\n  id: s1\n")
    rc = cmd_validate(_ns(tmp_path))
    err = capsys.readouterr().err
    assert "missing required top-level key" not in err
    # No 'default' ceremony -> a warning (not an error), so exit stays 0.
    assert rc == 0


def test_no_default_ceremony_warns(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "stream", "extends: ../default/tn.yaml\nceremony:\n  id: s1\n")
    cmd_validate(_ns(tmp_path))
    assert "no 'default' ceremony" in capsys.readouterr().err
