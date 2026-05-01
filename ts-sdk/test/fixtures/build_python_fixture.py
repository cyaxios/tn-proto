"""Generate a Python-produced `.tnpkg` fixture for cross-language byte
verification. Produces a deterministic ``admin_log_snapshot`` package in
this directory.

Run with the project venv:

    .venv/Scripts/python.exe ts-sdk/test/fixtures/build_python_fixture.py

The fixture is committed to source control. Re-running this script
overwrites it; the generated file is deterministic only modulo wall-clock
fields (``as_of``, envelope ``timestamp``), which the TS test ignores.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
PYDIR = REPO / "tn-protocol" / "python"
sys.path.insert(0, str(PYDIR))

import tn  # noqa: E402


def main() -> None:
    fixture_path = HERE / "python_admin_snapshot.tnpkg"
    with tempfile.TemporaryDirectory() as td:
        yaml_path = Path(td) / "tn.yaml"
        tn.init(yaml_path, cipher="btn")
        tn.admin_add_recipient(
            "default",
            str(Path(td) / "alice.kit"),
            recipient_did="did:key:zAlice",
        )
        out = tn.export(
            fixture_path,
            kind="admin_log_snapshot",
            cfg=tn.current_config(),
        )
        tn.flush_and_close()
        print(f"wrote {out} ({fixture_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
