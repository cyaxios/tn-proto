"""Load-proof for tests/golden/canonical_tn.yaml.

The golden fixture carries placeholder DIDs and no key material (real
keys must never live in the repo). config.load() reads real key files
from keystore.path, so this proof:

  1. mints a fresh real keystore into a temp ceremony dir,
  2. substitutes the golden's placeholder device/recipient DID with the
     freshly-minted real DID so the yaml matches its keystore,
  3. loads the patched yaml through tn.config.load(),
  4. prints the parsed project_name + device_identity + group count.

Run:  C:/codex/tn/tn_proto/.venv/Scripts/python.exe \
        C:/codex/tn/tn_proto/tests/golden/load_check_canonical.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

import tn  # noqa: E402
from tn import config as _config  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "canonical_tn.yaml"
PLACEHOLDER = "did:key:z6GOLDENdevicexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="goldload_"))
    seed_yaml = tmp / "tn.yaml"

    # 1. Mint a real ceremony (gives us a real keystore + real DID).
    tn.init(str(seed_yaml), cipher="btn", link=False)
    real_did = tn.current_config().device.device_identity
    tn.flush_and_close()

    # 2. Drop the golden yaml over the minted one, swapping the
    #    placeholder DID for the real minted DID so the keystore matches.
    golden_text = GOLDEN.read_text(encoding="utf-8")
    patched = golden_text.replace(PLACEHOLDER, real_did)
    seed_yaml.write_text(patched, encoding="utf-8")

    # 3. Load the golden-shaped yaml through the real loader.
    cfg = _config.load(seed_yaml)

    # 4. Report.
    print("LOADED_OK")
    print("project_name=", cfg.project_name)
    print("device_identity=", cfg.device.device_identity)
    print("ceremony_id=", cfg.ceremony_id)
    print("mode=", cfg.mode)
    print("cipher=", cfg.cipher_name)
    print("group_count=", len(cfg.groups))
    print("groups=", sorted(cfg.groups.keys()))
    print("did_substituted=", real_did)

    shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
