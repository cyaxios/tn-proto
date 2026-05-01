"""Generate the Python-produced ``python_admin_snapshot.tnpkg`` fixture
for cross-language byte-compare tests.

Canonical scenario (mirrored in the Rust + TS builders):

    1. Fresh btn ceremony.
    2. ``tn.recipient.added`` for did:key:zAlice  -> leaf A
    3. ``tn.recipient.added`` for did:key:zBob    -> leaf B
    4. ``tn.recipient.revoked`` for leaf A
    5. ``tn.vault.linked``     vault=did:web:vault.example  project_id=demo

Result: ``kind=admin_log_snapshot`` body with one ceremony.init + one
group.added (auto from ``tn.init``) plus the 4 events above.

Run with the project venv:

    .venv/Scripts/python.exe \
        tn-protocol/python/tests/fixtures/build_admin_snapshot_fixture.py

Re-running overwrites the file. The byte-compare consumers verify that
the signed manifest parses and the AdminState matches this scenario;
they DO NOT compare bytes against fixtures from other languages
(producer state is unique per ceremony). Wire-format byte-equivalence
is asserted separately via the manifest-canonical-bytes test.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parents[1]
sys.path.insert(0, str(PYDIR))

import tn


def main() -> None:
    fixture_path = HERE / "python_admin_snapshot.tnpkg"
    with tempfile.TemporaryDirectory() as td:
        yaml_path = Path(td) / "tn.yaml"
        tn.init(yaml_path, cipher="btn")

        leaf_a = tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(Path(td) / "alice.btn.mykit"))
        tn.admin.add_recipient("default", recipient_did="did:key:zBob", out_path=str(Path(td) / "bob.btn.mykit"))
        tn.admin.revoke_recipient("default", leaf_index=leaf_a)
        tn.vault.link("did:web:vault.example", "demo")

        out = tn.pkg.export(
            fixture_path,
            kind="admin_log_snapshot",
            cfg=tn.current_config(),
        )
        tn.flush_and_close()
        print(f"wrote {out} ({fixture_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
