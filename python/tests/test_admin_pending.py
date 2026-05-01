from pathlib import Path

import yaml as _yaml

from tn import admin
from tn.config import load_or_create


def test_add_recipient_without_pub_records_pending(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    recipients = doc["groups"]["default"]["recipients"]
    bob = next(r for r in recipients if r.get("did") == "did:key:z6MkBob")
    assert "pub_b64" not in bob


def test_add_recipient_on_btn_group_raises(tmp_path: Path):
    """Per-group cipher dispatch: admin.add_recipient is JWE-only;
    btn groups must use tn.admin_add_recipient instead."""
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    admin.ensure_group(cfg, "press", cipher="btn")
    import pytest

    with pytest.raises(RuntimeError) as e:
        admin._add_recipient_jwe_impl(cfg, "press", "did:key:z6MkBob")
    msg = str(e.value)
    assert "press" in msg
    assert "btn" in msg.lower()
