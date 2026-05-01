from pathlib import Path

from tn import admin
from tn.config import load_or_create


def test_ceremony_with_mixed_ciphers(tmp_path: Path):
    """A single yaml can have JWE and btn groups side by side."""
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    assert cfg.groups["default"].cipher.name == "jwe"
    admin.ensure_group(cfg, "press", cipher="btn")
    cfg2 = load_or_create(yaml_path)
    assert cfg2.groups["default"].cipher.name == "jwe"
    assert cfg2.groups["press"].cipher.name == "btn"


def test_ciphers_minted_list(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    # tn.agents is auto-injected with cipher=btn for every fresh ceremony
    # (per the 2026-04-25 read-ergonomics spec §2.3) so a fresh "jwe"
    # ceremony actually mints both jwe (default) and btn (tn.agents).
    assert set(cfg.ciphers_minted) == {"jwe", "btn"}
    admin.ensure_group(cfg, "press", cipher="btn")
    cfg2 = load_or_create(yaml_path)
    assert set(cfg2.ciphers_minted) == {"jwe", "btn"}
