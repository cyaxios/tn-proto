
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

from pathlib import Path

import yaml as _yaml

from tn.config import load_or_create


def test_pending_recipient_loads_without_pub(tmp_path: Path):
    """Yaml recipient entry with no pub_b64 must not crash config load."""
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, cipher=_workflow_cipher("jwe"))
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["groups"]["default"]["recipients"].append({"did": "did:key:z6MkBob"})
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    # Reload — must not raise.
    cfg2 = load_or_create(yaml_path)
    assert cfg2 is not None
    # Bob should NOT appear among the cipher's sealed recipients — he's
    # pending (no pub yet). The JWE cipher seals to the keystore recipients
    # file, which pending recipients never enter; other ciphers keep no such
    # per-recipient file, so a clean reload is the whole assertion there.
    import json

    rpath = getattr(cfg2.groups["default"].cipher, "_recipients_path", None)
    if rpath is not None and rpath.exists():
        dids = {e["recipient_identity"] for e in json.loads(rpath.read_text(encoding="utf-8"))}
        assert "did:key:z6MkBob" not in dids
