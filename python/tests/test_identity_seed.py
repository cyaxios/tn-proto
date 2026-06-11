"""Tests for the identity_seed manifest kind (export + absorb round-trip).

Coverage:

* Round-trip: export an identity_seed, absorb on a fresh keystore, confirm
  local.private + local.public + tn.yaml are installed correctly and the
  derived DID matches.
* Self-signed manifest verification (the bundle's own key signs the
  manifest; absorb verifies before installing).
* Cross-identity rejection: absorbing an identity_seed into a keystore
  that already has a different local.private fails loud rather than
  silently overwriting.
* Idempotent re-absorb: same identity twice returns no_op success.
* Tamper detection: swapping body/local.private without re-signing
  the manifest is rejected.
* Signing-key-derived check: the manifest.publisher_identity MUST match the DID
  derived from body/local.private (caught even if the manifest sig
  itself is consistent — which it can't be, but we test the layer).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tn.absorb import _absorb_dispatch
from tn.config import load_or_create
from tn.export import IDENTITY_SEED_CEREMONY_PLACEHOLDER, export_identity_seed
from tn.signing import DeviceKey
from tn.tnpkg import _read_manifest, _verify_manifest_signature


def _fresh_keystore(tmp_path: Path, name: str = "fresh"):
    """Create a config with a directory that has NO local.private yet.

    load_or_create() would mint a fresh device key for us; we want to
    skip that so absorb is the only path that writes local.private.
    Build the cfg minimally by hand.
    """
    yaml_path = tmp_path / name / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)

    # We use load_or_create to get a fully-formed LoadedConfig, then
    # remove local.private so absorb has a clean slate.
    cfg = load_or_create(yaml_path, cipher="btn")
    (cfg.keystore / "local.private").unlink(missing_ok=True)
    (cfg.keystore / "local.public").unlink(missing_ok=True)
    yaml_path.unlink(missing_ok=True)
    return cfg


def test_identity_seed_round_trip(tmp_path: Path):
    """Export -> absorb on empty keystore -> private bytes installed."""
    device = DeviceKey.generate()
    out = tmp_path / "agent.tnpkg"

    export_identity_seed(out, device=device, nickname="frank-the-agent")
    assert out.is_file()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "identity_seed"
    assert manifest.publisher_identity == device.did
    assert manifest.recipient_identity == device.did
    assert manifest.ceremony_id == IDENTITY_SEED_CEREMONY_PLACEHOLDER
    assert manifest.scope == "identity"
    assert _verify_manifest_signature(manifest), (
        "self-signed manifest must verify against from_did's pubkey"
    )
    state = manifest.state or {}
    identity_state = state.get("identity") or {}
    assert identity_state.get("nickname") == "frank-the-agent"
    assert identity_state.get("schema") == "tn-identity-seed-v1"

    cfg = _fresh_keystore(tmp_path, name="agent")
    receipt = _absorb_dispatch(cfg, out)

    assert receipt.legacy_status == "enrolment_applied", (
        f"expected install, got {receipt.legacy_status} ({receipt.legacy_reason})"
    )
    assert receipt.accepted_count == 1
    assert (cfg.keystore / "local.private").read_bytes() == device.private_bytes
    assert (cfg.keystore / "local.public").read_text(encoding="utf-8").strip() == device.did

    # The yaml stub should land at cfg.yaml_path since it was unlinked
    # by _fresh_keystore.
    assert cfg.yaml_path.exists(), "stub tn.yaml should be installed"


def test_identity_seed_idempotent(tmp_path: Path):
    """Second absorb of the same identity is a clean no-op."""
    device = DeviceKey.generate()
    out = tmp_path / "agent.tnpkg"
    export_identity_seed(out, device=device)

    cfg = _fresh_keystore(tmp_path, name="agent")
    receipt1 = _absorb_dispatch(cfg, out)
    assert receipt1.accepted_count == 1

    receipt2 = _absorb_dispatch(cfg, out)
    assert receipt2.noop is True
    assert receipt2.accepted_count == 0
    assert receipt2.legacy_status == "no_op"


def test_identity_seed_rejects_cross_identity_after_user_events(tmp_path: Path):
    """Absorbing identity B over identity A must fail once A has signed
    user events.

    Updated semantics (Bug 3 in the 0.4.0a2 brief): the cross-identity
    overwrite guard is gated on whether any user-emitted entries exist
    in the local main log. When the local log only has admin (`tn.*`)
    events from init — or nothing at all — re-absorbing a different
    identity is the dirt-easy "I just downloaded my identity, set it
    up" flow and proceeds. Once a user has emitted real events signed
    by identity A, identity B can no longer overwrite (signature trail
    would be orphaned).
    """
    import tn

    device_a = DeviceKey.generate()
    device_b = DeviceKey.generate()
    assert device_a.did != device_b.did

    pkg_b = tmp_path / "b.tnpkg"
    export_identity_seed(pkg_b, device=device_b)

    # Stand up a fully-formed ceremony bound to identity A (private +
    # yaml minted by load_or_create so tn.init can reload it later).
    yaml_path = tmp_path / "agent" / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = load_or_create(yaml_path, cipher="btn", device_private_bytes=device_a.private_bytes)

    # Emit a real user event so local.private's signature trail is
    # load-bearing (B would orphan it).
    tn.init(str(cfg.yaml_path))
    tn.info("hello.world", note="from_a")
    tn.flush_and_close()

    # Reload cfg to pick up post-init mutations.
    from tn.config import load as _load_cfg

    cfg = _load_cfg(cfg.yaml_path)
    r2 = _absorb_dispatch(cfg, pkg_b)
    assert r2.legacy_status == "rejected", (
        f"cross-identity install must fail once user events exist, "
        f"got {r2.legacy_status} ({r2.legacy_reason})"
    )
    assert "refusing to overwrite" in r2.legacy_reason.lower()
    # Original identity remains untouched.
    assert (cfg.keystore / "local.private").read_bytes() == device_a.private_bytes


def test_identity_seed_overwrites_fresh_install(tmp_path: Path):
    """When the local log has no user events yet, re-absorbing a
    different identity overwrites cleanly. Mirrors the dashboard
    "downloaded the wrong seed, downloaded the right one" flow.
    """
    device_a = DeviceKey.generate()
    device_b = DeviceKey.generate()

    pkg_a = tmp_path / "a.tnpkg"
    export_identity_seed(pkg_a, device=device_a)
    pkg_b = tmp_path / "b.tnpkg"
    export_identity_seed(pkg_b, device=device_b)

    cfg = _fresh_keystore(tmp_path, name="agent")
    r1 = _absorb_dispatch(cfg, pkg_a)
    assert r1.accepted_count == 1

    r2 = _absorb_dispatch(cfg, pkg_b)
    assert r2.legacy_status == "enrolment_applied", (
        f"fresh-state overwrite should succeed; got {r2.legacy_status} "
        f"({r2.legacy_reason})"
    )
    assert (cfg.keystore / "local.private").read_bytes() == device_b.private_bytes


def test_identity_seed_rejects_swapped_private(tmp_path: Path):
    """Tampered body (swap local.private without re-signing) is rejected.

    Even though the manifest signature still verifies (we don't touch
    the manifest), the body/local.private no longer derives to
    manifest.publisher_identity. The integrity check in _absorb_identity_seed
    catches this.
    """
    device_a = DeviceKey.generate()
    device_b = DeviceKey.generate()
    out = tmp_path / "agent.tnpkg"
    export_identity_seed(out, device=device_a)

    # Swap body/local.private with device_b's bytes; leave manifest +
    # local.public alone. The absorber must catch the disagreement
    # between (manifest.publisher_identity, body/local.public, derived-from-priv).
    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        public_bytes = zf.read("body/local.public")
        yaml_bytes = zf.read("body/tn.yaml")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("body/local.private", device_b.private_bytes)
        zf.writestr("body/local.public", public_bytes)
        zf.writestr("body/tn.yaml", yaml_bytes)

    cfg = _fresh_keystore(tmp_path, name="agent")
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "integrity" in receipt.legacy_reason.lower()


def test_identity_seed_rejects_missing_body_member(tmp_path: Path):
    """Missing body/local.private is a hard reject."""
    device = DeviceKey.generate()
    out = tmp_path / "agent.tnpkg"
    export_identity_seed(out, device=device)

    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        public_bytes = zf.read("body/local.public")
        yaml_bytes = zf.read("body/tn.yaml")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("body/local.public", public_bytes)
        zf.writestr("body/tn.yaml", yaml_bytes)
        # body/local.private intentionally omitted

    cfg = _fresh_keystore(tmp_path, name="agent")
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "local.private" in receipt.legacy_reason


def test_identity_seed_signature_verification(tmp_path: Path):
    """Hand-tampering the manifest fails signature verification (which
    happens BEFORE the body integrity check in _absorb_dispatch)."""
    device = DeviceKey.generate()
    out = tmp_path / "agent.tnpkg"
    export_identity_seed(out, device=device, nickname="frank")

    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        priv_bytes = zf.read("body/local.private")
        public_bytes = zf.read("body/local.public")
        yaml_bytes = zf.read("body/tn.yaml")

    # Mutate one byte in the manifest's nickname so the signed canonical
    # bytes change but the signature stays the same.
    bad_manifest = manifest_bytes.replace(b'"frank"', b'"FRANK"')
    assert bad_manifest != manifest_bytes, "tamper failed to land"

    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", bad_manifest)
        zf.writestr("body/local.private", priv_bytes)
        zf.writestr("body/local.public", public_bytes)
        zf.writestr("body/tn.yaml", yaml_bytes)

    cfg = _fresh_keystore(tmp_path, name="agent")
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "signature" in receipt.legacy_reason.lower()


def test_export_identity_seed_with_default_device(tmp_path: Path):
    """export_identity_seed() generates a fresh DeviceKey when none provided."""
    out = tmp_path / "fresh.tnpkg"
    export_identity_seed(out)
    manifest, _ = _read_manifest(out)
    assert manifest.kind == "identity_seed"
    assert manifest.publisher_identity.startswith("did:key:z")
    assert manifest.publisher_identity == manifest.recipient_identity
    assert _verify_manifest_signature(manifest)


def test_export_kind_validation(tmp_path: Path):
    """export(kind='identity_seed') without device= is a clean error."""
    from tn.export import export

    with pytest.raises(ValueError, match="device="):
        export(tmp_path / "x.tnpkg", kind="identity_seed")


def test_init_then_absorb_succeeds_on_fresh_ceremony(tmp_path: Path):
    """Bug 3 dirt-easy fix: init() then absorb(identity_seed) succeeds
    when no user events have been emitted yet. The local.private and
    tn.yaml minted by init are treated as fresh state and overwritten.
    """
    import os

    import tn

    device = DeviceKey.generate()
    pkg = tmp_path / "downloaded.identity.tnpkg"
    export_identity_seed(pkg, device=device)

    work = tmp_path / "ceremony"
    work.mkdir()
    old_cwd = os.getcwd()
    os.chdir(work)
    try:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        tn.init(str(work / "tn.yaml"))
        # No user emit has happened yet — only init-time admin events.
        receipt = tn.pkg.absorb(str(pkg))
        assert receipt.legacy_status in ("enrolment_applied", "no_op"), (
            f"init+absorb of identity_seed should succeed, got "
            f"{receipt.legacy_status} ({receipt.legacy_reason})"
        )
        # The keystore now holds the absorbed identity.
        keystore = tn.current_config().keystore
        assert keystore.joinpath("local.private").read_bytes() == device.private_bytes
    finally:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        os.chdir(old_cwd)


def test_init_emit_then_absorb_refuses(tmp_path: Path):
    """The flip side of Bug 3: once a user event has been emitted, a
    cross-identity absorb is refused. The signature trail is real.
    """
    import os

    import tn

    device = DeviceKey.generate()
    pkg = tmp_path / "downloaded.identity.tnpkg"
    export_identity_seed(pkg, device=device)

    work = tmp_path / "ceremony"
    work.mkdir()
    old_cwd = os.getcwd()
    os.chdir(work)
    try:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        tn.init(str(work / "tn.yaml"))
        tn.info("hello.user.event", marker="real_user_activity")
        tn.flush_and_close()

        # Re-init so absorb sees the now-populated log.
        tn.init(str(work / "tn.yaml"))
        receipt = tn.pkg.absorb(str(pkg))
        assert receipt.legacy_status == "rejected", (
            f"absorb of a different identity over a ceremony with user "
            f"events should be rejected, got {receipt.legacy_status} "
            f"({receipt.legacy_reason})"
        )
        assert "refusing to overwrite" in receipt.legacy_reason.lower()
    finally:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        os.chdir(old_cwd)


def test_absorb_before_init_in_fresh_dir(tmp_path: Path):
    """The dirt-easy bootstrap: in an empty directory with no
    ``tn.init()``, ``tn.pkg.absorb(identity_seed)`` installs everything
    so a follow-up ``tn.init()`` picks up the seeded keystore.
    """
    import os

    import tn

    device = DeviceKey.generate()
    pkg = tmp_path / "downloaded.identity.tnpkg"
    export_identity_seed(pkg, device=device)

    work = tmp_path / "fresh"
    work.mkdir()
    old_cwd = os.getcwd()
    os.chdir(work)
    try:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        receipt = tn.pkg.absorb(str(pkg))
        assert receipt.kind == "identity_seed"
        assert receipt.legacy_status == "enrolment_applied"
        # local.private landed under the synthesized keystore path.
        candidates = list(work.rglob("local.private"))
        assert candidates, f"local.private should be installed under {work}"
        assert candidates[0].read_bytes() == device.private_bytes
    finally:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        os.chdir(old_cwd)
