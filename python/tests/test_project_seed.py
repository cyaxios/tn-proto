"""Tests for the project_seed manifest kind.

The dashboard's marquee "Create Project" flow at vault.tn-proto.org mints
``kind: "project_seed"`` packages with body shape::

    body/tn.yaml
    body/keys/local.private
    body/keys/local.public
    body/keys/index_master.key
    body/keys/<group>.btn.mykit
    body/keys/<group>.btn.state
    body/keys/tn.agents.btn.mykit
    body/keys/tn.agents.btn.state

(Files nested under ``body/keys/`` — not flat under ``body/`` like
``kit_bundle``.) See ``tn_proto_web/static/account/project_minter.js``.

Coverage:

* Real-fixture round-trip: ``tests/fixtures/Agentic20.project.tnpkg`` is
  a real dashboard-minted bundle. Absorb it into a fresh tempdir; assert
  every file lands at its expected destination.
* Hand-crafted round-trip: bypass the dashboard JS entirely — build a
  bundle with valid manifest + body in Python, absorb, assert state.
* Tamper guard: swapping ``body/keys/local.private`` without re-signing
  is rejected (matches identity_seed's tamper logic).
* Dirt-easy bootstrap: ``tn.pkg.absorb`` of a project_seed in a fresh
  cwd with no prior ``tn.init()`` succeeds and writes everything; the
  follow-up ``tn.init()`` picks up the absorbed yaml + keystore.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tn.absorb import _absorb_dispatch, absorb
from tn.config import LoadedConfig, load as load_cfg
from tn.signing import DeviceKey
from tn.tnpkg import _read_manifest


FIXTURE = Path(__file__).parent / "fixtures" / "Agentic20.project.tnpkg"


def _bootstrap_cfg_for(tmp_path: Path) -> LoadedConfig:
    """Build a synthetic LoadedConfig that points at ``tmp_path`` —
    same shape ``_try_bootstrap_cfg`` builds for the dirt-easy
    "absorb-before-init" flow. Used so the test exercises the real
    dispatch path with a fresh-dir cfg.
    """
    yaml_path = tmp_path / "tn.yaml"
    keystore = (tmp_path / ".tn" / "tn" / "keys").resolve()
    placeholder = b"\x00" * 32
    return LoadedConfig(
        yaml_path=yaml_path,
        keystore=keystore,
        device=DeviceKey.from_private_bytes(placeholder),
        ceremony_id="_bootstrap_absorb",
        master_index_key=b"",
        cipher_name="btn",
        public_fields=[],
        default_policy="private",
        groups={},
        field_to_groups={},
        handler_specs=None,
        admin_log_location="./.tn/tn/admin/admin.ndjson",
        log_path="./.tn/tn/logs/tn.ndjson",
    )


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason=f"real dashboard-minted fixture not present at {FIXTURE}",
)
def test_project_seed_real_fixture_round_trip(tmp_path: Path):
    """Absorb the real Agentic20.project.tnpkg fixture; assert tn.yaml
    and every body/keys/<rel> file lands at the right place with the
    right bytes.
    """
    manifest, body = _read_manifest(FIXTURE)
    assert manifest.kind == "project_seed"
    assert manifest.scope == "project"
    assert manifest.from_did == manifest.to_did

    cfg = _bootstrap_cfg_for(tmp_path)
    receipt = _absorb_dispatch(cfg, FIXTURE)
    assert receipt.legacy_status == "enrolment_applied", (
        f"expected install, got {receipt.legacy_status} ({receipt.legacy_reason})"
    )
    # We know the fixture has 9 body members (tn.yaml + 8 keys).
    expected_body = [n for n in body if n.startswith("body/")]
    assert receipt.accepted_count == len(expected_body)

    # tn.yaml landed.
    assert cfg.yaml_path.exists()
    assert cfg.yaml_path.read_bytes() == body["body/tn.yaml"]

    # Every body/keys/<rel> entry lives in the keystore.
    for name, data in body.items():
        if not name.startswith("body/keys/"):
            continue
        rel = name[len("body/keys/"):]
        dest = cfg.keystore / rel
        assert dest.exists(), f"{dest} should be installed"
        assert dest.read_bytes() == data


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason=f"real dashboard-minted fixture not present at {FIXTURE}",
)
def test_project_seed_idempotent_re_absorb(tmp_path: Path):
    """Second absorb of the same project_seed is a clean no-op (every
    file deduped, accepted_count == 0).
    """
    cfg = _bootstrap_cfg_for(tmp_path)
    r1 = _absorb_dispatch(cfg, FIXTURE)
    assert r1.accepted_count > 0

    r2 = _absorb_dispatch(cfg, FIXTURE)
    assert r2.accepted_count == 0, (
        f"idempotent re-absorb should write nothing; got "
        f"accepted={r2.accepted_count} reason={r2.legacy_reason!r}"
    )
    assert r2.deduped_count == r1.accepted_count
    assert r2.legacy_status == "no_op"


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason=f"real dashboard-minted fixture not present at {FIXTURE}",
)
def test_project_seed_dirt_easy_bootstrap_flow(tmp_path: Path):
    """The headline UX: drop into a fresh tempdir, ``tn.pkg.absorb``
    the project tnpkg, then ``tn.init()`` and use it. No prior init
    required.
    """
    import tn

    # 1. fresh empty cwd; no tn.init().
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Make sure no inherited runtime is hanging around.
        try:
            tn.flush_and_close()
        except Exception:
            pass

        # 2. absorb the project_seed. Public verb, no cfg arg.
        receipt = tn.pkg.absorb(str(FIXTURE))
        assert receipt.kind == "project_seed"
        assert receipt.legacy_status == "enrolment_applied"

        # 3. yaml + keystore are on disk.
        assert (tmp_path / "tn.yaml").exists()
        assert (tmp_path / ".tn" / "tn" / "keys" / "local.private").exists()

        # 4. tn.init() with no args: discovery should find the
        #    just-absorbed ./tn.yaml.
        tn.init(str(tmp_path / "tn.yaml"))

        # 5. emit a user event and read it back.
        tn.info("hello.dirt.easy", note="absorb-before-init works")
        tn.flush_and_close()

        # Re-init for read.
        tn.init(str(tmp_path / "tn.yaml"))
        types = [e.event_type for e in tn.read()]
        assert "hello.dirt.easy" in types
    finally:
        try:
            tn.flush_and_close()
        except Exception:
            pass
        os.chdir(old_cwd)


def _hand_built_project_seed(out_path: Path, device: DeviceKey) -> Path:
    """Build a minimal project_seed bundle using only Python (no
    dashboard JS). Mirrors the body shape the dashboard emits so the
    handler can be exercised on synthetic input where ``Agentic20`` is
    unavailable.
    """
    import json
    import zipfile
    from datetime import datetime, timezone

    from tn.tnpkg import TnpkgManifest

    keystore_bytes = {
        "local.private": device.private_bytes,
        "local.public": device.did.encode("utf-8"),
        "index_master.key": b"\x11" * 32,
        "default.btn.state": b"FAKE_BTN_STATE_DEFAULT",
        "default.btn.mykit": b"FAKE_BTN_MYKIT_DEFAULT",
        "tn.agents.btn.state": b"FAKE_BTN_STATE_TNAGENTS",
        "tn.agents.btn.mykit": b"FAKE_BTN_MYKIT_TNAGENTS",
    }
    yaml_text = (
        "ceremony:\n"
        "  id: synthetic_proj\n"
        "  cipher: btn\n"
        "me:\n"
        f"  did: {device.did}\n"
        "groups:\n"
        "  default:\n"
        "    cipher: btn\n"
        "    recipients:\n"
        f"      - did: {device.did}\n"
        "keystore:\n"
        "  path: ./.tn/tn/keys\n"
    )

    manifest = TnpkgManifest(
        kind="project_seed",
        from_did=device.did,
        ceremony_id="synthetic_proj",
        as_of=datetime.now(timezone.utc).isoformat(),
        scope="project",
        to_did=device.did,
        state={
            "project": {
                "schema": "tn-project-seed-v1",
                "project_id": "synthetic_proj",
                "ceremony_id": "synthetic_proj",
            }
        },
    )
    manifest.sign(device.signing_key())

    body: dict[str, bytes] = {"body/tn.yaml": yaml_text.encode("utf-8")}
    for name, data in keystore_bytes.items():
        body[f"body/keys/{name}"] = data

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(
            "manifest.json", json.dumps(manifest.to_dict(), indent=2, sort_keys=True)
        )
        for k, v in body.items():
            zf.writestr(k, v)
    return out_path


def test_project_seed_hand_built_round_trip(tmp_path: Path):
    """Synthetic project_seed (no dashboard) round-trips through absorb."""
    device = DeviceKey.generate()
    out = tmp_path / "synthetic.project.tnpkg"
    _hand_built_project_seed(out, device)

    cfg = _bootstrap_cfg_for(tmp_path)
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason
    assert (cfg.keystore / "local.private").read_bytes() == device.private_bytes
    assert (cfg.keystore / "default.btn.state").exists()
    assert (cfg.keystore / "tn.agents.btn.mykit").exists()
    assert cfg.yaml_path.exists()


def test_project_seed_rejects_swapped_private(tmp_path: Path):
    """Tampered body/keys/local.private (without re-signing) is rejected."""
    import zipfile

    device_a = DeviceKey.generate()
    device_b = DeviceKey.generate()
    out = tmp_path / "tamper.project.tnpkg"
    _hand_built_project_seed(out, device_a)

    # Swap body/keys/local.private with B's bytes; leave manifest alone.
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(out, "r") as zf:
        for n in zf.namelist():
            members[n] = zf.read(n)
    members["body/keys/local.private"] = device_b.private_bytes
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        for n, data in members.items():
            zf.writestr(n, data)

    cfg = _bootstrap_cfg_for(tmp_path)
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "integrity" in receipt.legacy_reason.lower()


def test_project_seed_rejects_non_self_addressed(tmp_path: Path):
    """from_did != to_did must be rejected (not a self-issued seed)."""
    import json
    import zipfile

    device = DeviceKey.generate()
    out = tmp_path / "p.project.tnpkg"
    _hand_built_project_seed(out, device)

    # Mutate manifest's to_did so it differs from from_did. The
    # signature will then fail to verify, so the rejection arrives via
    # the signature path — but that's fine: a real attacker can't
    # produce a valid signed manifest with mismatched from/to either.
    # We assert the reject lands somewhere — either the signature
    # check or the self-addressed check.
    other = DeviceKey.generate()
    with zipfile.ZipFile(out, "r") as zf:
        manifest_doc = json.loads(zf.read("manifest.json").decode("utf-8"))
        members = {n: zf.read(n) for n in zf.namelist()}
    manifest_doc["to_did"] = other.did
    members["manifest.json"] = json.dumps(manifest_doc, indent=2, sort_keys=True).encode("utf-8")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        for n, d in members.items():
            zf.writestr(n, d)

    cfg = _bootstrap_cfg_for(tmp_path)
    receipt = _absorb_dispatch(cfg, out)
    assert receipt.legacy_status == "rejected"


def test_project_seed_skips_nested_subpaths(tmp_path: Path):
    """body/keys/foo/bar must NOT install into <keystore>/foo/bar — the
    handler only honors flat names directly under keys/.
    """
    import json
    import zipfile

    device = DeviceKey.generate()
    out = tmp_path / "smuggle.project.tnpkg"
    _hand_built_project_seed(out, device)

    # Add a nested smuggled file. We need to re-sign because the
    # canonical manifest is unaffected (manifest doesn't enumerate
    # body), so just append to the zip.
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(out, "r") as zf:
        for n in zf.namelist():
            members[n] = zf.read(n)
    members["body/keys/etc/passwd"] = b"smuggled"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        for n, d in members.items():
            zf.writestr(n, d)

    cfg = _bootstrap_cfg_for(tmp_path)
    receipt = _absorb_dispatch(cfg, out)
    # The handler should accept (the legitimate flat-path entries
    # land), and the nested entry must NOT exist anywhere under
    # cfg.keystore.
    assert not (cfg.keystore / "etc" / "passwd").exists()
    smuggled_anywhere = list(cfg.keystore.rglob("passwd"))
    assert smuggled_anywhere == [], f"nested smuggling should be skipped; found {smuggled_anywhere}"
