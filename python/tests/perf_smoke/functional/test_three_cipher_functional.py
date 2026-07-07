from __future__ import annotations

from pathlib import Path

import pytest

import tn
import tn.reader
from tn import _hibe


def _hibe_available() -> bool:
    try:
        _hibe.setup(1)
    except RuntimeError as exc:
        if "HIBE native extension is unavailable" in str(exc):
            return False
        raise
    return True


@pytest.mark.parametrize("cipher", ["btn", "jwe", "hibe"])
def test_signed_verified_decrypt_roundtrip_uses_isolated_cipher_dirs(
    tmp_path: Path, cipher: str
) -> None:
    if cipher == "hibe" and not _hibe_available():
        pytest.skip("tn._native was built without the HIBE submodule")

    cipher_root = tmp_path / cipher
    publisher_root = cipher_root / "publisher"
    yaml_path = publisher_root / "tn.yaml"
    log_path = publisher_root / "logs" / "tn.ndjson"

    try:
        tn.init(yaml_path, log_path=log_path, cipher=cipher)
        cfg = tn.current_config()
        assert cfg.cipher_name == cipher
        assert Path(cfg.keystore).is_relative_to(cipher_root)
        assert log_path.is_relative_to(cipher_root)

        tn.info(
            "perf_smoke.created",
            payload=f"{cipher}-alpha",
            amount=101,
            marker="signed",
        )
        tn.warning(
            "perf_smoke.warning",
            payload=f"{cipher}-beta",
            attempts=2,
            marker="verified",
        )
        tn.flush_and_close()

        tn.init(yaml_path, log_path=log_path, cipher=cipher)
        cfg = tn.current_config()
        entries = list(tn.reader.read(log_path, cfg))
    finally:
        tn.flush_and_close()

    assert log_path.exists()
    assert len(entries) == 2

    by_type = {entry["envelope"]["event_type"]: entry for entry in entries}
    assert set(by_type) == {"perf_smoke.created", "perf_smoke.warning"}

    for entry in entries:
        env = entry["envelope"]
        plaintext = entry["plaintext"]["default"]
        valid = entry["valid"]

        assert valid["signature"], env
        assert valid["row_hash"], env
        assert valid["chain"], env
        assert "$decrypt_error" not in plaintext
        assert "$no_read_key" not in plaintext
        assert plaintext["payload"].startswith(f"{cipher}-")

    assert by_type["perf_smoke.created"]["plaintext"]["default"]["amount"] == 101
    assert by_type["perf_smoke.warning"]["plaintext"]["default"]["attempts"] == 2
