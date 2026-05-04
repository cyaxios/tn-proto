"""Tests for the ``zenoh.pull`` handler (in-process Zenoh peer round-trip).

Uses the same pinned-endpoint / multicast-off pattern as the spike's
storage_node.py to avoid Windows multicast loopback flakiness when
multiple peers run in one process.

Test plan:

* basic round-trip: a publisher peer puts a kit_bundle on the bus key;
  the handler subscribes, the worker absorbs, the keystore mutates.
* malformed payload: random bytes get rejected by absorb; handler
  stays subscribed and ready for the next sample.
* shutdown drain: ``close()`` returns after in-flight samples are
  absorbed (no orphaned bytes left in the worker queue).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import zenoh

from tn.absorb import _absorb_dispatch
from tn.config import load_or_create
from tn.export import export, export_identity_seed
from tn.handlers.zenoh import ZenohCredentials, ZenohPullHandler
from tn.signing import DeviceKey

# Pin distinct ports per test so fixtures can run in parallel without
# bumping into each other.
PUBLISHER_PORT_BASE = 7480


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _FakeMintClient:
    """Returns canned creds; never hits the network."""

    def fetch(self) -> ZenohCredentials:
        return ZenohCredentials(
            username="test_user",
            password="test_pass",
            expires_at="2026-12-31T23:59:59Z",
        )


def _open_publisher_session(listen_endpoint: str):
    """Open a Zenoh peer that LISTENs on the given endpoint. The handler
    under test connects to this peer."""
    cfg = zenoh.Config()
    cfg.insert_json5("listen/endpoints", json.dumps([listen_endpoint]))
    cfg.insert_json5("scouting/multicast/enabled", "false")
    return zenoh.open(cfg)


class _FakeCfg:
    """Minimal LoadedConfig stand-in. See test_kit_bundle_sealed.py for
    rationale: handler only needs cfg.device, cfg.keystore, cfg.yaml_path
    on the absorb path."""

    def __init__(self, host_dir: Path, device: DeviceKey):
        host_dir.mkdir(parents=True, exist_ok=True)
        self.yaml_path = host_dir / "tn.yaml"
        self.keystore = host_dir / "keys"
        self.keystore.mkdir(parents=True, exist_ok=True)
        self.device = device


def _install_recipient_identity(tmp_path: Path, device: DeviceKey, name: str = "frank"):
    """Write the recipient's identity tnpkg + absorb it onto a fresh cfg.

    Returns the FakeCfg with cfg.device == device.
    """
    pkg_path = tmp_path / f"{name}_identity.tnpkg"
    export_identity_seed(pkg_path, device=device, nickname=name)
    cfg = _FakeCfg(tmp_path / name, device)
    receipt = _absorb_dispatch(cfg, pkg_path)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason
    return cfg


def _make_publisher_with_btn_group(tmp_path: Path):
    """Real publisher cfg via load_or_create — needed to mint kit_bundles."""
    yaml_path = tmp_path / "alice" / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    return load_or_create(yaml_path, cipher="btn")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_zenoh_pull_round_trip(tmp_path: Path):
    """Publisher puts a sealed kit_bundle on the bus; handler absorbs;
    keystore gains the kit."""
    listen_ep = f"tcp/127.0.0.1:{PUBLISHER_PORT_BASE}"
    pub_session = _open_publisher_session(listen_ep)
    try:
        alice_cfg = _make_publisher_with_btn_group(tmp_path)
        frank_device = DeviceKey.generate()
        frank_cfg = _install_recipient_identity(tmp_path, frank_device, name="frank")

        # Build a sealed kit_bundle for frank.
        out = tmp_path / "frank_kit.tnpkg"
        export(
            out,
            kind="kit_bundle",
            cfg=alice_cfg,
            to_did=frank_device.did,
            seal_for_recipient=True,
        )
        payload = out.read_bytes()

        handler = ZenohPullHandler(
            "test_pull",
            zenoh_endpoints=[listen_ep],
            cfg_provider=lambda: frank_cfg,
            autostart=True,
        )
        try:
            # Give the subscriber a beat to register.
            time.sleep(0.5)

            sub_key = f"tn/inbox/{frank_device.did}/snapshots/_test/0001"
            pub_session.put(sub_key, payload)

            # Wait for the worker to drain.
            assert handler.wait_for_absorbs(1, timeout=5.0), (
                f"handler didn't absorb in time; absorbed={handler.absorbed_count} "
                f"rejected={handler.rejected_count}"
            )
            assert handler.absorbed_count == 1
            assert handler.rejected_count == 0
            assert (frank_cfg.keystore / "default.btn.mykit").exists()
        finally:
            handler.close(timeout=5.0)
    finally:
        pub_session.close()


def test_zenoh_pull_rejects_malformed_payload(tmp_path: Path):
    """Garbage bytes don't crash the handler — they get rejected and the
    subscription keeps running."""
    listen_ep = f"tcp/127.0.0.1:{PUBLISHER_PORT_BASE + 1}"
    pub_session = _open_publisher_session(listen_ep)
    try:
        frank_device = DeviceKey.generate()
        frank_cfg = _install_recipient_identity(tmp_path, frank_device, name="frank")

        handler = ZenohPullHandler(
            "test_garbage",
            zenoh_endpoints=[listen_ep],
            cfg_provider=lambda: frank_cfg,
            autostart=True,
        )
        try:
            time.sleep(0.5)
            sub_key = f"tn/inbox/{frank_device.did}/snapshots/_test/junk"
            pub_session.put(sub_key, b"not a tnpkg zip at all")

            assert handler.wait_for_absorbs(1, timeout=5.0)
            assert handler.absorbed_count == 0
            assert handler.rejected_count == 1
        finally:
            handler.close(timeout=5.0)
    finally:
        pub_session.close()


def test_zenoh_pull_close_is_idempotent(tmp_path: Path):
    """Calling close() twice doesn't blow up."""
    listen_ep = f"tcp/127.0.0.1:{PUBLISHER_PORT_BASE + 2}"
    pub_session = _open_publisher_session(listen_ep)
    try:
        frank_device = DeviceKey.generate()
        frank_cfg = _install_recipient_identity(tmp_path, frank_device, name="frank")

        handler = ZenohPullHandler(
            "test_close",
            zenoh_endpoints=[listen_ep],
            cfg_provider=lambda: frank_cfg,
            autostart=True,
        )
        time.sleep(0.3)
        handler.close(timeout=5.0)
        # Second close is a no-op.
        handler.close(timeout=5.0)
    finally:
        pub_session.close()


def test_zenoh_pull_validates_args(tmp_path: Path):
    """on_absorb_error must be 'log' or 'raise'."""
    with pytest.raises(ValueError, match="on_absorb_error"):
        ZenohPullHandler(
            "bad",
            zenoh_endpoints=["tcp/127.0.0.1:9999"],
            mint_client_factory=lambda: _FakeMintClient(),
            on_absorb_error="explode",
            autostart=False,
        )

    # No-auth mode is allowed — handler opens a zenoh session without
    # usrpwd creds when neither mint_client_factory nor (mint_url+
    # jwt_provider) are provided.
    handler = ZenohPullHandler(
        "no_auth",
        zenoh_endpoints=["tcp/127.0.0.1:9999"],
        autostart=False,
    )
    assert handler._mint_factory is None  # no-auth shape
