
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

from pathlib import Path

import pytest

import tn
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
    from datetime import timedelta

    from tn.enrollment import EnrollmentStore

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.init(str(bob_cfg.yaml_path))

    # Post trusted-enrollment refactor, only a *challenged + preauthorized* offer
    # auto-promotes at reconcile (an unsolicited offer needs explicit approval).
    # So Alice preauthorizes Bob and issues him a scoped challenge, and Bob
    # answers with a challenged offer carrying his key-binding proof.
    store = EnrollmentStore(alice_cfg, alice_cfg.device)
    store.preauthorize(bob_cfg.device.did, "default")
    challenge = store.issue_challenge(bob_cfg.device.did, "default", timedelta(minutes=10))
    offer(bob_cfg, alice_cfg.device.did, challenge=challenge)
    tn.flush_and_close()

    # Per-stem outbox layout: <yaml_dir>/.tn/<yaml_stem>/outbox/
    pkg_path = next((bob_dir / ".tn" / bob_cfg.yaml_path.stem / "outbox").glob("*.tnpkg"))
    inbox_dir(alice_dir).mkdir(parents=True, exist_ok=True)
    (inbox_dir(alice_dir) / pkg_path.name).write_bytes(pkg_path.read_bytes())

    # Alice's init should: absorb Bob's challenged offer, reconcile-promote Bob,
    # and wire his verified pubkey into the group.
    tn.init(str(alice_cfg.yaml_path))
    import yaml as _yaml

    doc = _yaml.safe_load(alice_cfg.yaml_path.read_text(encoding="utf-8"))
    # 0.4.3a1: yaml recipient identity key is `recipient_identity`.
    bob = next(
        r
        for r in doc["groups"]["default"]["recipients"]
        if r["recipient_identity"] == bob_cfg.device.did
    )
    assert "pub_b64" in bob, f"reconcile should have promoted Bob; yaml: {doc}"
    tn.flush_and_close()
