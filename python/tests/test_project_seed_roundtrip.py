"""Proof: Python ``project_seed`` export -> fresh-dir absorb -> readback.

This is the cross-surface restore contract's Python leg (yaml-identity-ironout
P3). Each tn flow runs in its OWN subprocess (one-flow-per-process), then the
produced ``.tnpkg`` is inspected by hand. Hard evidence only:

  * the seed is a self-addressed (from_did == to_did) ``project_seed`` carrying
    a 32-byte ``local.private`` and a canonical ``tn.yaml``;
  * the restored ceremony's ``device_identity`` equals the original;
  * the restored private keys are usable (a fresh event writes + reads back).

The backup scope is keys + config only: the event log is device-local and is
NOT in the seed, so the restored log starts empty and the proof writes one new
event rather than expecting the original two back.
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]  # .../tn_proto
PYPATH = (REPO / "python").as_posix()


def _run_child(code: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=180
    )
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line and line.split("=", 1)[0].isupper():
            k, v = line.split("=", 1)
            out[k] = v
    out["_rc"] = proc.returncode  # type: ignore[assignment]
    out["_stderr"] = proc.stderr  # type: ignore[assignment]
    return out


def test_project_seed_export_absorb_readback(tmp_path: Path) -> None:
    a = tmp_path / "A"
    b = tmp_path / "B"
    a.mkdir()
    b.mkdir()
    seed = a / "backup.tnpkg"
    ayaml = (a / "tn.yaml").as_posix()

    flow1 = f'''
import sys; sys.path.insert(0, r"{PYPATH}")
import tn
from tn import config as C
from tn.export import export as do_export
from pathlib import Path
yp = r"{ayaml}"
tn.init(yp, cipher="btn", link=False)
tn.info("test.one")
tn.info("test.two")
cc = tn.current_config()
print("FLOW1_DID=" + cc.device.device_identity)
print("FLOW1_MODE=" + str(cc.mode))
tn.flush_and_close()
cfg = C.load(Path(yp))
do_export(r"{seed.as_posix()}", kind="project_seed", cfg=cfg, confirm_includes_secrets=True)
print("FLOW1_OK=1")
'''
    r1 = _run_child(flow1)
    assert r1["_rc"] == 0, f"flow1 failed:\n{r1['_stderr']}"
    assert r1.get("FLOW1_MODE") == "local", f"expected mode:local, got {r1.get('FLOW1_MODE')}"
    assert seed.exists() and seed.stat().st_size > 0

    # Inspect the seed by hand (no runtime).
    with zipfile.ZipFile(seed) as z:
        names = set(z.namelist())
        manifest = json.loads(z.read("manifest.json"))
        yaml_text = z.read("body/tn.yaml").decode("utf-8")
        priv = z.read("body/keys/local.private")
    assert manifest["kind"] == "project_seed"
    assert manifest["publisher_identity"] == manifest["recipient_identity"], "must be self-addressed"
    assert manifest["publisher_identity"] == r1["FLOW1_DID"]
    assert len(priv) == 32
    assert "device:" in yaml_text and "recipient_identity" in yaml_text
    assert "\nme:" not in yaml_text
    assert "\nproject_id:" not in yaml_text
    assert "\nlabel:" not in yaml_text
    assert {"body/tn.yaml", "body/keys/local.private", "body/keys/local.public"} <= names
    assert not any("/logs/" in n or n.endswith(".ndjson") for n in names), (
        f"project_seed must not include application logs; saw {sorted(names)}"
    )

    # Restore into a fresh dir, prove identity + key usability.
    flow2 = f'''
import sys; sys.path.insert(0, r"{PYPATH}")
import os, glob
os.chdir(r"{b.as_posix()}")
import tn
tn.absorb(r"{seed.as_posix()}")
ys = glob.glob(r"{b.as_posix()}/**/tn.yaml", recursive=True)
yp = ys[0]
tn.init(yp, link=False)
print("FLOW2_DID=" + tn.current_config().device.device_identity)
print("FLOW2_MODE=" + str(tn.current_config().mode))
tn.info("test.restore_proof")
tn.flush_and_close()
tn.init(yp, link=False)
print("FLOW2_ROWS=" + str(len(list(tn.read()))))
tn.flush_and_close()
'''
    r2 = _run_child(flow2)
    assert r2["_rc"] == 0, f"flow2 failed:\n{r2['_stderr']}"
    assert r2["FLOW2_DID"] == r1["FLOW1_DID"], "restored device identity must match original"
    assert r2.get("FLOW2_MODE") == "local"
    assert int(r2["FLOW2_ROWS"]) >= 1, "restored keys must be usable (write+read a new event)"
