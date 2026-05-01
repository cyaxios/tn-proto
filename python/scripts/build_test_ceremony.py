"""Build the deterministic jwe_two_recipients fixture ceremony.

Run from tn-protocol/python/:

    ../../.venv/Scripts/python.exe scripts/build_test_ceremony.py

This produces tn/mcp/tests/fixtures/jwe_two_recipients/ with:
  - tn.yaml (jwe cipher, two groups, two recipients on the 'pii' group)
  - .tn/keys/   (publisher's keystore)
  - .tn/logs/   (a handful of pre-emitted entries spanning event types)

The fixture is committed to git so tests are hermetic — never regenerated
by the test runner. Re-run this script only when the fixture format
changes intentionally.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# Ensure deterministic state: clean slate, deterministic env.
HERE = Path(__file__).resolve().parent
FIXTURE_DIR = (HERE / ".." / "tn" / "mcp" / "tests" / "fixtures" / "jwe_two_recipients").resolve()


def _clean(p: Path) -> None:
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True)


def main() -> int:
    # Force jwe + python path for full determinism.
    os.environ["TN_FORCE_PYTHON"] = "1"
    os.environ["TN_NO_STDOUT"] = "1"

    _clean(FIXTURE_DIR)
    yaml_path = FIXTURE_DIR / "tn.yaml"

    # Late import: tn auto-init walks env vars / cwd, so we want to
    # control state before importing.
    import tn

    # Init with explicit jwe + path under the fixture dir.
    tn.init(str(yaml_path), cipher="jwe")
    cfg = tn.current_config()

    # Add a 'pii' group with three fields.
    cfg = tn.ensure_group(cfg, "pii", fields=["email", "ip", "user_agent"])

    # Add two recipients to 'pii'. Both are deterministic test DIDs.
    # In real usage these would be x25519 pubkeys from the recipient's
    # own ceremony; for the fixture we mint disposable ones.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    for did_suffix in ("z6MkFrank", "z6MkAcme"):
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = tn.admin.add_recipient(
            "pii",
            recipient_did=f"did:key:{did_suffix}",
            public_key=pub_bytes,
            cfg=cfg,
        )
        if result.updated_cfg is not None:
            cfg = result.updated_cfg

    # Re-init so the new group + recipients land in the live runtime.
    tn.flush_and_close()
    tn.init(str(yaml_path), cipher="jwe")

    # Emit a representative spread of entries.
    tn.info(
        "order.created",
        order_id="A100",
        item="apple",
        quantity=3,
        email="alice@example.com",
        ip="10.0.0.17",
    )
    tn.info(
        "order.created",
        order_id="A101",
        item="banana",
        quantity=1,
        email="bob@example.com",
        ip="10.0.0.18",
    )
    tn.warning(
        "auth.retry",
        attempts=3,
        email="alice@example.com",
    )
    tn.error(
        "payment.declined",
        order_id="A100",
        reason="cvv_mismatch",
    )
    tn.debug("cache.miss", key="user:42")

    # Final flush so the log file is closed cleanly before we hand it to git.
    tn.flush_and_close()

    print(f"[fixture] Built jwe_two_recipients at {FIXTURE_DIR}")
    print(f"[fixture]   tn.yaml: {yaml_path}")
    print(f"[fixture]   logs:    {FIXTURE_DIR / '.tn' / 'logs'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
