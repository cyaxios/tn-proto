"""Subprocess loader leg for the conformance test (one tn flow per process).

Reads a producer's tn.yaml text from stdin, mints a fresh real keystore in a
temp dir, substitutes every `did:key:...` in the text for the freshly-minted
DID (so the yaml matches its keystore), drops it over the minted yaml, and
loads it through `tn.config.load`. Exits 0 on a clean load, non-zero otherwise.

Mirrors tests/golden/load_check_canonical.py, but DID-substitutes via regex so
it works for any producer's yaml (not just the golden placeholder), and runs in
its own process so the module-global `tn` runtime is never shared across the
four surfaces.

Run:  python load_via_mint.py  < producer.yaml
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "python"))

import tn  # noqa: E402
from tn import config as _config  # noqa: E402

_DID = re.compile(r"did:key:[1-9A-HJ-NP-Za-km-z]+")


def main() -> int:
    text = sys.stdin.read()
    tmp = Path(tempfile.mkdtemp(prefix="conf_load_"))
    try:
        seed_yaml = tmp / "tn.yaml"
        tn.init(str(seed_yaml), cipher="btn", link=False)
        real_did = tn.current_config().device.device_identity
        tn.flush_and_close()

        patched = _DID.sub(real_did, text)
        seed_yaml.write_text(patched, encoding="utf-8")
        _config.load(seed_yaml)
        print("LOADED_OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
