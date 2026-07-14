"""Real same-language round-trip coverage for the ``tn absorb`` CLI verb.

This is the Python side of the same-language round-trip: there was
previously **zero** coverage of ``cmd_absorb`` (the CLI verb).
``test_absorb.py``
exercises only the *library* ``tn.absorb.absorb(cfg, path)`` on the
offer / JWE-enrolment paths; nothing drove the btn CLI verb chain
``tn add_recipient`` / ``tn bundle`` -> ``tn absorb``.

Every test here drives the ACTUAL argparse verbs as a subprocess
(``python -m tn.cli ...``) across **two separate ceremonies** — a
publisher P and a recipient R — so we exercise the real CLI wiring, the
real originate verb (``cmd_add_recipient`` / ``cmd_bundle`` ->
``bundle_for_recipient``), and the real ``cmd_absorb``. Two ceremonies
are mandatory: ``absorb`` installs a reader kit INTO a ceremony that is
not the one that minted it, and the verb actively refuses self-absorb.

Isolation is per-party on THREE axes, all critical:

  * ``TN_HOME``         — shared TN state root.
  * ``TN_IDENTITY_DIR`` — identity.json lives here. **Without this the
    two parties share the machine's real identity.json and get the SAME
    DID**, which would silently turn every "kit for R" into a
    self-addressed kit and make the self-absorb guard / read-back checks
    meaningless. ``_init_party`` asserts ``P.did != R.did``.
  * per-party cwd       — keystore + logs land under here.

The load-bearing assertion is the **read-back** (PASS #4): after R
absorbs P's kit, R can ``tn read`` P's log and the decrypted plaintext
(``amount=4200``) is present — proving the *correct* key installed, not
just that a file landed. The before/after contrast (R cannot decrypt P's
payload until it absorbs P's kit) is the genuine negative complement.

GAP (documented, not weakened): for the **unsealed btn** kit_bundle the
group read-key ships in the clear, so a kit whose manifest names a
*different* recipient still decrypts once absorbed (the binding is
attestation-only, sealing is the ``--seal-for-recipient`` path). So
FAIL #6 "a kit minted for a DIFFERENT recipient cannot be decrypted by
this one" does NOT hold for unsealed btn and is intentionally NOT
asserted here — see ``test_wrong_recipient_*`` for the documented gap
plus the negative that genuinely holds (no kit absorbed => no decrypt).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

_PYTHON_DIR = Path(__file__).resolve().parent.parent
_DID_RE = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{20,}")


def _env_for(home: Path, idir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_PYTHON_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["TN_HOME"] = str(home)
    # Per-party identity dir: this is what makes P.did != R.did. Sharing
    # the machine identity.json (the bug the prior send/receive test had)
    # would give both parties the SAME DID and defeat the round-trip.
    env["TN_IDENTITY_DIR"] = str(idir)
    env["TN_NO_STDOUT"] = "1"
    return env


def _run_cli(
    *args: str, cwd: Path, home: Path, idir: Path, timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run ``python -m tn.cli ...`` with an isolated HOME + identity dir."""
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", *args],
        cwd=str(cwd),
        env=_env_for(home, idir),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_py(
    code: str, *, cwd: Path, home: Path, idir: Path, timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run a tiny ``python -c`` snippet in the same isolated env.

    Used only for the producer-side ``tn.info(...)`` write: there is no
    ``tn info`` CLI verb (the CLI exposes init/bundle/add_recipient/
    absorb/read/...), so the publisher writes its log entry through the
    library API. The absorb verb itself is always driven via the CLI.
    """
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(cwd),
        env=_env_for(home, idir),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class Party:
    """One ceremony: its cwd, yaml, DID, and isolated HOME + identity dir."""

    def __init__(self, root: Path, name: str) -> None:
        self.name = name
        self.cwd = root / name
        self.home = self.cwd / ".tnhome"
        self.idir = self.cwd / ".id"
        self.cwd.mkdir(parents=True, exist_ok=True)
        res = _run_cli(
            "init",
            name,
            "--no-link",
            "--skip-confirm",
            cwd=self.cwd,
            home=self.home,
            idir=self.idir,
        )
        assert res.returncode == 0, f"init {name} failed:\n{res.stdout}\n{res.stderr}"
        yamls = list(self.cwd.glob("**/tn.yaml"))
        assert yamls, f"no tn.yaml produced under {self.cwd}"
        self.yaml = yamls[0]
        # The CEREMONY's device DID — read from the keystore's local.public,
        # NOT from init stdout. `tn init` mints a fresh per-ceremony device
        # key whose DID differs from the identity.json DID echoed on stdout;
        # the ceremony key is the one that signs kits (kit
        # publisher_identity) and that the self-absorb guard compares
        # against (cfg.device.did). Using the stdout DID here would point at
        # the wrong key and break the round-trip's identity reasoning.
        pubs = list(self.cwd.glob("**/keys/local.public"))
        assert pubs, f"no keystore local.public under {self.cwd}"
        self.did = pubs[0].read_text(encoding="utf-8").strip()
        assert _DID_RE.fullmatch(self.did), f"bad ceremony DID: {self.did!r}"

    def cli(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return _run_cli(*args, cwd=self.cwd, home=self.home, idir=self.idir, **kw)

    def write_entry(self, event: str = "payday", **fields) -> None:
        """Publisher writes one ``default``-group entry via the library API."""
        kw = ", ".join(f"{k}={v!r}" for k, v in fields.items())
        code = f"import tn; tn.init(r'{self.yaml}'); tn.info({event!r}, {kw}); tn.flush_and_close()"
        res = _run_py(code, cwd=self.cwd, home=self.home, idir=self.idir)
        assert res.returncode == 0, f"write_entry failed:\n{res.stdout}\n{res.stderr}"

    @property
    def main_log(self) -> Path:
        logs = list(self.cwd.glob("**/logs/tn.ndjson"))
        assert logs, f"no main log under {self.cwd}"
        return logs[0]

    @property
    def keystore(self) -> Path:
        keys = list(self.cwd.glob("**/keys"))
        assert keys, f"no keystore under {self.cwd}"
        return keys[0]


def _kit_blob_bytes(pkg: Path, member: str = "body/default.btn.mykit") -> bytes:
    with zipfile.ZipFile(pkg) as zf:
        return zf.read(member)


# ---------------------------------------------------------------------------
# PASS path: real produce -> consume round-trip with on-disk install + decrypt
# ---------------------------------------------------------------------------


def test_round_trip_install_and_readback(tmp_path: Path):
    """The headline round-trip (PASS #1-#4).

    P writes a ``default`` entry and mints a kit FOR R (real
    ``tn add_recipient`` -> ``bundle_for_recipient``). R absorbs it
    (real ``tn absorb``). Assertions:

      * absorb exits 0, receipt ``kind=kit_bundle accepted>=1`` (PASS 1/2)
      * ``default.btn.mykit`` lands in R's keystore with the KIT's bytes,
        distinct from R's own pre-absorb self-kit (PASS #3)
      * **read-back**: R ``tn read``s P's log and the decrypted
        ``amount=4200`` is present (PASS #4 — the load-bearing proof)
    """
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    assert P.did != R.did, "two isolated ceremonies must have distinct DIDs"

    prior_publisher = "did:key:z6MkhDA92BRnspkcBZVVMhfdRVhZSHWejjYqUipaj8zvXUs5"
    trust_path = R.keystore / "trust" / "verified_publishers.v1.json"
    trust_path.parent.mkdir(parents=True)
    trust_path.write_text(
        json.dumps(
            {
                "version": 1,
                "publishers": {prior_publisher: {"source": "existing-verification"}},
            }
        ),
        encoding="utf-8",
    )

    P.write_entry("payday", amount=4200)

    # --- Negative complement (proves the kit is load-bearing): before R
    # absorbs P's kit, R holds only its OWN group key, so it CANNOT
    # decrypt P's payload. The event_type is public, the field is not.
    pre = R.cli("read", str(P.main_log), "--yaml", str(R.yaml), "--no-verify")
    assert pre.returncode == 0, pre.stderr
    assert "payday" in pre.stdout, f"event_type should be visible:\n{pre.stdout}"
    assert "amount=4200" not in pre.stdout, (
        f"R must NOT decrypt P's payload before absorbing P's kit:\n{pre.stdout}"
    )

    # Record R's own self-kit bytes so we can prove the absorb replaced
    # them with P's group key (PASS #3: the RIGHT bytes, not R's own).
    r_self_kit = R.keystore / "default.btn.mykit"
    r_self_bytes = r_self_kit.read_bytes()

    kit = tmp_path / "for_rec.tnpkg"
    res = P.cli("add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml))
    assert res.returncode == 0, f"add_recipient failed:\n{res.stdout}\n{res.stderr}"
    assert kit.exists(), "add_recipient did not write the kit .tnpkg"
    kit_bytes = _kit_blob_bytes(kit)

    res = R.cli("absorb", str(kit), "--yaml", str(R.yaml))
    assert res.returncode == 0, f"absorb failed:\n{res.stdout}\n{res.stderr}"
    assert res.stderr == "", f"no stderr on the happy path:\n{res.stderr}"
    # PASS #1/#2: receipt line with accepted>=1.
    m = re.search(r"\[tn absorb\] kind=kit_bundle accepted=(\d+) skipped=(\d+)", res.stdout)
    assert m, f"receipt line missing:\n{res.stdout}"
    assert int(m.group(1)) >= 1, f"expected accepted>=1:\n{res.stdout}"

    trust_doc = json.loads(trust_path.read_text(encoding="utf-8"))
    assert trust_doc["publishers"][prior_publisher]["source"] == "existing-verification"
    assert trust_doc["publishers"][P.did]["source"] == "verified-signed-kit-bundle"

    # PASS #3: the kit really installed, with the KIT's bytes (not R's
    # original self-kit). The displaced original is preserved sidecar.
    assert r_self_kit.exists(), "default.btn.mykit missing after absorb"
    assert r_self_kit.read_bytes() == kit_bytes, "installed kit != kit blob bytes"
    assert r_self_kit.read_bytes() != r_self_bytes, (
        "absorb left R's own self-kit in place; the publisher's kit did not install"
    )
    backups = list(R.keystore.glob("default.btn.mykit.previous.*"))
    assert backups, "prior self-kit was not backed up to a .previous.<UTC_TS> sidecar"
    assert backups[0].read_bytes() == r_self_bytes, "backup != prior self-kit bytes"

    # PASS #4 (load-bearing): R now decrypts P's entry.
    post = R.cli("read", str(P.main_log), "--yaml", str(R.yaml))
    assert post.returncode == 0, post.stderr
    assert "amount=4200" in post.stdout, (
        f"read-back failed: R should decrypt P's entry after absorb:\n{post.stdout}"
    )


def test_re_absorb_is_idempotent(tmp_path: Path):
    """PASS #6: absorbing the SAME kit twice dedupes — second absorb
    reports ``accepted=0 skipped=1`` and still exits 0."""
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    kit = tmp_path / "k.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )

    first = R.cli("absorb", str(kit), "--yaml", str(R.yaml))
    assert first.returncode == 0, first.stderr
    assert "kind=kit_bundle accepted=1 skipped=0" in first.stdout, first.stdout

    second = R.cli("absorb", str(kit), "--yaml", str(R.yaml))
    assert second.returncode == 0, second.stderr
    assert "kind=kit_bundle accepted=0 skipped=1" in second.stdout, second.stdout


def test_bundle_verb_round_trip_install_and_readback(tmp_path: Path):
    """The headline round-trip again, but driven through ``tn bundle``.

    Was BROKEN: ``cmd_bundle`` read ``args.recipient_did`` but the argparse
    positional is registered as ``recipient_identity`` → AttributeError
    before minting anything. Fixed to read ``args.recipient_identity``.

    ``bundle <recipient> <out> --groups default`` is the alternate originate
    shape (vs ``add_recipient <group> <recipient> --out``); both land on
    ``bundle_for_recipient``. This mirrors
    ``test_round_trip_install_and_readback`` end-to-end so the ``bundle``
    verb is proven to mint a kit R can actually absorb and read back with —
    not merely that a file appears on disk.
    """
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    assert P.did != R.did, "two isolated ceremonies must have distinct DIDs"

    P.write_entry("payday", amount=4200)

    # Negative complement: before R absorbs P's bundle it holds only its own
    # group key, so the public event_type is visible but the field is not.
    pre = R.cli("read", str(P.main_log), "--yaml", str(R.yaml), "--no-verify")
    assert pre.returncode == 0, pre.stderr
    assert "payday" in pre.stdout, f"event_type should be visible:\n{pre.stdout}"
    assert "amount=4200" not in pre.stdout, (
        f"R must NOT decrypt P's payload before absorbing P's bundle:\n{pre.stdout}"
    )

    r_self_kit = R.keystore / "default.btn.mykit"
    r_self_bytes = r_self_kit.read_bytes()

    kit = tmp_path / "bundle.tnpkg"
    res = P.cli("bundle", R.did, str(kit), "--groups", "default", "--yaml", str(P.yaml))
    assert res.returncode == 0, f"tn bundle failed:\n{res.stdout}\n{res.stderr}"
    assert kit.exists(), "bundle should have written the kit .tnpkg"
    kit_bytes = _kit_blob_bytes(kit)

    res = R.cli("absorb", str(kit), "--yaml", str(R.yaml))
    assert res.returncode == 0, f"absorb failed:\n{res.stdout}\n{res.stderr}"
    assert res.stderr == "", f"no stderr on the happy path:\n{res.stderr}"
    m = re.search(r"\[tn absorb\] kind=kit_bundle accepted=(\d+) skipped=(\d+)", res.stdout)
    assert m, f"receipt line missing:\n{res.stdout}"
    assert int(m.group(1)) >= 1, f"expected accepted>=1:\n{res.stdout}"

    # The bundle's group key really installed, with the kit's bytes.
    assert r_self_kit.exists(), "default.btn.mykit missing after absorb"
    assert r_self_kit.read_bytes() == kit_bytes, "installed kit != bundle blob bytes"
    assert r_self_kit.read_bytes() != r_self_bytes, (
        "absorb left R's own self-kit in place; the bundle's kit did not install"
    )

    # Load-bearing: R now decrypts P's entry.
    post = R.cli("read", str(P.main_log), "--yaml", str(R.yaml))
    assert post.returncode == 0, post.stderr
    assert "amount=4200" in post.stdout, (
        f"read-back failed: R should decrypt P's entry after bundle->absorb:\n{post.stdout}"
    )


def test_overwrite_with_backup_warn_block(tmp_path: Path):
    """FAIL #7: absorbing a kit over an existing ``default.btn.mykit``
    whose bytes differ overwrites it, the receipt carries
    ``replaced_kit_paths`` (WARN block printed), AND the prior bytes are
    preserved at ``<name>.previous.<UTC_TS>`` (data never lost silently).

    R always starts with its OWN ``default.btn.mykit`` (minted by
    ``tn init``), whose bytes differ from P's group key, so a plain
    absorb already triggers the overwrite+backup path.
    """
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    prior = (R.keystore / "default.btn.mykit").read_bytes()

    kit = tmp_path / "for_rec.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )

    res = R.cli("absorb", str(kit), "--yaml", str(R.yaml))
    assert res.returncode == 0, res.stderr
    assert "WARN: overwrote" in res.stdout, f"WARN block missing:\n{res.stdout}"
    assert "default.btn.mykit" in res.stdout, res.stdout
    assert "prior bytes preserved at" in res.stdout, res.stdout

    backups = list(R.keystore.glob("default.btn.mykit.previous.*"))
    assert len(backups) == 1, f"expected exactly one backup sidecar; got {backups}"
    assert backups[0].read_bytes() == prior, "backup does not hold the prior bytes"


# ---------------------------------------------------------------------------
# FAIL paths
# ---------------------------------------------------------------------------


def test_self_absorb_refused_exit_2(tmp_path: Path):
    """FAIL #1: a ceremony absorbing a kit it MINTED itself exits 2 with
    the guard message and nothing on stdout (the 0.4.2a9 guard)."""
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")  # a real foreign recipient to bundle *for*
    kit = tmp_path / "self.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )

    # P (the minter) tries to absorb its own kit.
    res = P.cli("absorb", str(kit), "--yaml", str(P.yaml))
    assert res.returncode == 2, f"self-absorb must exit 2:\n{res.stdout}\n{res.stderr}"
    assert "refusing to absorb a package this ceremony minted" in res.stderr, res.stderr
    assert f"from_did={P.did}" in res.stderr, res.stderr
    assert "--allow-self-absorb" in res.stderr, res.stderr
    assert res.stdout == "", f"refusal must print nothing to stdout:\n{res.stdout}"


def test_allow_self_absorb_override_exit_0(tmp_path: Path):
    """FAIL #2: ``--allow-self-absorb`` overrides the guard, exit 0."""
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    kit = tmp_path / "self.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )

    res = P.cli("absorb", str(kit), "--allow-self-absorb", "--yaml", str(P.yaml))
    assert res.returncode == 0, f"--allow-self-absorb must exit 0:\n{res.stderr}"
    assert "kind=kit_bundle accepted=" in res.stdout, res.stdout


def test_garbage_package_rejected_no_crash(tmp_path: Path):
    """FAIL #4: a non-zip ``.tnpkg`` does not crash. The manifest peek
    swallows the parse error and absorb prints its own
    ``kind=unknown accepted=0 skipped=0`` receipt, exit 0."""
    R = Party(tmp_path, "rec")
    garbage = tmp_path / "garbage.tnpkg"
    garbage.write_text("this is not a zip file at all")
    res = R.cli("absorb", str(garbage), "--yaml", str(R.yaml))
    assert res.returncode == 0, f"garbage absorb should not crash:\n{res.stderr}"
    assert "[tn absorb] kind=unknown accepted=0 skipped=0" in res.stdout, res.stdout


def test_missing_package_exit_1(tmp_path: Path):
    """FAIL #8 (package): a missing .tnpkg exits 1 with ``package not
    found:`` and nothing on stdout."""
    R = Party(tmp_path, "rec")
    res = R.cli("absorb", str(tmp_path / "does-not-exist.tnpkg"), "--yaml", str(R.yaml))
    assert res.returncode == 1, f"missing package must exit 1:\n{res.stdout}"
    assert "package not found:" in res.stderr, res.stderr
    assert res.stdout == "", res.stdout


def test_missing_yaml_exit_1(tmp_path: Path):
    """FAIL #8 (yaml): an explicit ``--yaml`` that doesn't exist exits 1
    with ``yaml not found:``."""
    P = Party(tmp_path, "pub")
    R = Party(tmp_path, "rec")
    kit = tmp_path / "k.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", R.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )
    res = R.cli("absorb", str(kit), "--yaml", str(tmp_path / "missing.yaml"))
    assert res.returncode == 1, f"missing yaml must exit 1:\n{res.stdout}"
    assert "yaml not found:" in res.stderr, res.stderr


def test_wrong_recipient_kit_unsealed_btn_still_decrypts_DOCUMENTED_GAP(
    tmp_path: Path,
):
    """FAIL #6 — DOCUMENTED GAP, not a weakened assertion.

    The contract's FAIL #6 ("a kit minted for a DIFFERENT recipient
    cannot be decrypted by this one") does NOT hold for the **unsealed
    btn** kit_bundle, and that is a genuine protocol property, not a test
    bug: an unsealed kit ships the group's ``default.btn.mykit`` read-key
    in the clear (verified: the kit zip is just
    ``{manifest.json, body/default.btn.mykit}``, manifest
    ``state.body_encryption is None``). The ``recipient_identity`` in the
    manifest is attestation metadata; it does NOT cryptographically bind
    the kit. Recipient-binding requires the ``--seal-for-recipient``
    sealed-box path (``_maybe_unseal_recipient_wrap``), which mints a
    per-recipient BEK wrap — a different originate route whose CLI
    read-back does not currently land cleanly (sealed absorb reported
    ``accepted=0`` in exploration), so per the plan's HARD RULE we do NOT
    build a PASS/FAIL assertion on it here.

    What this test DOES pin down, so the gap is explicit and regressions
    are caught:

      1. The wrong-recipient kit (minted for T, absorbed by W) currently
         DOES decrypt P's entry — documenting the unsealed-btn reality.
         If sealing ever becomes the default and this flips, this
         assertion fails and forces a contract revisit.
      2. The negative that DOES genuinely hold: a ceremony that absorbed
         NO kit for P's group cannot decrypt P's payload (covered as the
         pre-absorb branch of ``test_round_trip_install_and_readback``;
         re-asserted minimally here for a fresh ceremony).
    """
    P = Party(tmp_path, "pub")
    T = Party(tmp_path, "third")  # the DID the kit is minted FOR
    W = Party(tmp_path, "wrong")  # absorbs a kit not addressed to it
    P.write_entry("payday", amount=4200)

    # Genuine negative: W with NO P-kit cannot decrypt P's payload.
    pre = W.cli("read", str(P.main_log), "--yaml", str(W.yaml), "--no-verify")
    assert pre.returncode == 0, pre.stderr
    assert "payday" in pre.stdout and "amount=4200" not in pre.stdout, (
        f"fresh ceremony must not decrypt P's payload:\n{pre.stdout}"
    )

    # Kit minted for T, absorbed by W. Documents the unsealed-btn gap:
    # W decrypts even though the manifest names T.
    kit = tmp_path / "for_third.tnpkg"
    assert (
        P.cli(
            "add_recipient", "default", T.did, "--out", str(kit), "--yaml", str(P.yaml)
        ).returncode
        == 0
    )
    # Cross-check the kit is unsealed (no body_encryption) so the gap
    # rationale above is anchored to the actual artifact, not an assumption.
    with zipfile.ZipFile(kit) as zf:
        import json

        manifest = json.loads(zf.read("manifest.json"))
    assert (manifest.get("state") or {}).get("body_encryption") is None, (
        "kit unexpectedly sealed; the unsealed-btn gap rationale no longer holds"
    )

    assert W.cli("absorb", str(kit), "--yaml", str(W.yaml)).returncode == 0
    # This assertion isolates the documented bearer-key cipher gap. The
    # wrong-recipient package must not also grant publisher authenticity.
    post = W.cli("read", str(P.main_log), "--yaml", str(W.yaml), "--no-verify")
    assert post.returncode == 0, post.stderr
    assert "amount=4200" in post.stdout, (
        "DOCUMENTED GAP changed: an unsealed btn kit minted for a DIFFERENT "
        "recipient no longer decrypts. FAIL #6 may now be enforceable at the "
        "CLI — revisit the absorb contract and add the real "
        f"can't-decrypt assertion.\n{post.stdout}"
    )
