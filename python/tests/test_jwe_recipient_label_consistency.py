"""JWE solo ceremonies must label the self-recipient with the device DID.

The yaml written at create time records ``recipients: [{recipient_identity:
<device DID>}]`` while the keystore's ``<group>.jwe.recipients`` file used to
label the same slot ``"self"``. Decrypt never reads the label (trial-decrypt),
so the mismatch was invisible to round-trips — but add/revoke match entries by
DID, and the TS SDK (``createJweGroup`` / ``jweRotateGroup``) writes the real
DID, so Python must too. Every path that mints a solo jwe group is covered:
create_fresh's default group, ensure_group, and admin rotate's re-mint.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _keystore_recipient_labels(keystore: Path, group: str) -> list[str]:
    doc = json.loads((keystore / f"{group}.jwe.recipients").read_text(encoding="utf-8"))
    return [e["recipient_identity"] for e in doc]


def test_create_fresh_labels_self_recipient_with_device_did(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    cfg = tn.current_config()
    did = cfg.device.device_identity

    labels = _keystore_recipient_labels(Path(cfg.keystore), "default")
    assert labels == [did]
    # And the yaml side already records the DID — both must agree.
    assert cfg.groups["default"].recipient_dids == [did]


def test_ensure_group_labels_self_recipient_with_device_did(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    cfg = tn.current_config()
    did = cfg.device.device_identity

    tn.admin.ensure_group(cfg, "pii")
    labels = _keystore_recipient_labels(Path(cfg.keystore), "pii")
    assert labels == [did]


def test_rotate_relabels_self_recipient_with_device_did(tmp_path: Path) -> None:
    tn.init(tmp_path / "tn.yaml", cipher="jwe")
    cfg = tn.current_config()
    did = cfg.device.device_identity

    tn.admin.rotate("default")
    labels = _keystore_recipient_labels(Path(cfg.keystore), "default")
    assert labels == [did]
