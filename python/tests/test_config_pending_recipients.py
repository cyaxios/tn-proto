from pathlib import Path

import yaml as _yaml

from tn.config import load_or_create


def test_pending_recipient_loads_without_pub(tmp_path: Path):
    """Yaml recipient entry with no pub_b64 must not crash config load."""
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, cipher="jwe")
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["groups"]["default"]["recipients"].append({"did": "did:key:z6MkBob"})
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    # Reload — must not raise.
    cfg2 = load_or_create(yaml_path)
    assert cfg2 is not None
    # Bob should NOT appear in the cipher's KEK cache — he's pending.
    kek_cache = cfg2.groups["default"].cipher._kek_cache or {}
    assert "did:key:z6MkBob" not in kek_cache
