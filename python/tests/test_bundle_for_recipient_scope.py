from __future__ import annotations

from pathlib import Path

import pytest

import tn


@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


@pytest.mark.parametrize("cipher", ["jwe", "hibe"])
def test_bundle_for_recipient_rejects_non_btn_groups(
    tmp_path: Path, cipher: str
) -> None:
    tn.init(
        tmp_path / cipher / "tn.yaml",
        log_path=tmp_path / cipher / "log.ndjson",
        cipher=cipher,
    )
    recipient_did = tn.current_config().device.device_identity

    with pytest.raises(ValueError, match=r"(?i)bundle_for_recipient.*BTN-only"):
        tn.pkg.bundle_for_recipient(
            recipient_did,
            tmp_path / f"{cipher}-reader.tnpkg",
        )

    assert not (tmp_path / f"{cipher}-reader.tnpkg").exists()


def test_mixed_bundle_is_rejected_before_any_btn_kit_is_minted(
    tmp_path: Path, monkeypatch
) -> None:
    tn.init(
        tmp_path / "mixed" / "tn.yaml",
        log_path=tmp_path / "mixed" / "log.ndjson",
        cipher="btn",
    )
    cfg = tn.current_config()
    tn.admin.ensure_group(cfg, "partner", cipher="jwe")
    recipient_did = cfg.device.device_identity
    mint_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def record_mint(*args, **kwargs):
        mint_calls.append((args, kwargs))
        raise AssertionError("validation must run before minting any BTN kit")

    monkeypatch.setattr(tn.admin, "add_recipient", record_mint)
    out_path = tmp_path / "mixed-reader.tnpkg"

    with pytest.raises(ValueError, match=r"(?i)bundle_for_recipient.*BTN-only"):
        tn.pkg.bundle_for_recipient(
            recipient_did,
            out_path,
            groups=["default", "partner"],
        )

    assert mint_calls == []
    assert not out_path.exists()
