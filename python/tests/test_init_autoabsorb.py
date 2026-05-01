from pathlib import Path

import pytest

import tn
from tn import admin
from tn.config import load_or_create
from tn.conventions import inbox_dir
from tn.offer import offer


@pytest.fixture(autouse=True)
def _clean_tn():  # noqa: PT004
    """Best-effort flush_and_close after every test in this file.

    Without this, a test that errors mid-flow (e.g. on a stale path
    expectation) leaves the module-level Python runtime initialized,
    which then breaks every subsequent test in the same process —
    test_secure_read, test_signing_flag, etc. all start to return 0
    entries from tn.read() because they hit the dirty runtime.
    """
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_init_absorbs_inbox_and_reconciles(tmp_path: Path):
    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    tn.init(str(bob_cfg.yaml_path))
    offer(bob_cfg, publisher_did=alice_cfg.device.did)
    tn.flush_and_close()
    # Per-stem outbox layout: <yaml_dir>/.tn/<yaml_stem>/outbox/
    pkg_path = next((bob_dir / ".tn" / bob_cfg.yaml_path.stem / "outbox").glob("*.tnpkg"))
    inbox_dir(alice_dir).mkdir(parents=True, exist_ok=True)
    (inbox_dir(alice_dir) / pkg_path.name).write_bytes(pkg_path.read_bytes())

    # Alice declared intent for Bob (pending).
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.did)

    # Alice's init should: absorb Bob's offer, reconcile promote Bob.
    tn.init(str(alice_cfg.yaml_path))
    import yaml as _yaml

    doc = _yaml.safe_load(alice_cfg.yaml_path.read_text(encoding="utf-8"))
    bob = next(r for r in doc["groups"]["default"]["recipients"] if r["did"] == bob_cfg.device.did)
    assert "pub_b64" in bob, f"reconcile should have promoted Bob; yaml: {doc}"
    tn.flush_and_close()
