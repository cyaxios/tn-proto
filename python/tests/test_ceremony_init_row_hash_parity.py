"""Regression: the bootstrap ``tn.ceremony.init`` row must verify row_hash
under every reader.

Root cause this guards against (0.5.0a4): the Rust core wrote
``device_identity`` into the ``tn.ceremony.init`` public ``init_fields``,
*and* ``device_identity`` is the mandatory reserved envelope scalar. On a
Python/TS-written ceremony (whose yaml carries the full
``DEFAULT_PUBLIC_FIELDS`` including ``device_identity``) the writer hashed
``device_identity`` twice — once as the scalar, once as a public field —
while every spec-correct reader (pure-Python ``reader._read``, the
Rust-backed ``_rust_entries_with_valid`` path, and the TS
``node_runtime``) excludes the reserved scalar when recomputing the
row_hash. The two disagreed → ``tn.ceremony.init`` failed row_hash
verification, while user events (``txn.created``) and ``tn.group.added``
verified fine because they never inject ``device_identity`` into their
public fields.

Historically the interop suite *filtered out* ``tn.*`` bootstrap rows
(see ``test_rust_runtime_interop`` comments), so this row's verification
was never asserted. This test asserts it head-on, across both reader
camps, so the writer/reader can never drift on the reserved scalar again.
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # tn_proto/python on sys.path


def _admin_log_path(cfg) -> Path:
    from tn._log_targets import resolve_log_target

    targets = resolve_log_target("admin", cfg)
    assert targets, "admin log target did not resolve"
    return targets[0]


def test_ceremony_init_verifies_under_pure_python_reader(tmp_path):
    """The canonical (Camp-B) pure-Python reader must verify row_hash on
    the Rust-written ``tn.ceremony.init`` row."""
    import tn
    from tn import current_config
    from tn import reader as _reader

    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=_workflow_cipher("btn"), link=False)
    try:
        assert tn.using_rust(), "regression requires the Rust-backed writer"
        cfg = current_config()
        admin = _admin_log_path(cfg)
        assert admin.exists(), f"expected admin log at {admin}"

        rows = list(_reader._read(str(admin), cfg))
    finally:
        tn.flush_and_close()

    event_types = [r["envelope"].get("event_type") for r in rows]
    assert "tn.ceremony.init" in event_types, (
        f"tn.ceremony.init missing from admin log; saw {event_types}"
    )

    failures = [
        r["envelope"].get("event_type")
        for r in rows
        if not r["valid"]["row_hash"]
    ]
    assert not failures, (
        "row_hash verification failed for: "
        f"{failures} (every admin row, including tn.ceremony.init, must verify)"
    )


def test_ceremony_init_verifies_under_rust_backed_reader(tmp_path):
    """The Rust-backed own-ceremony read path (``_rust_entries_with_valid``)
    must agree with the writer on the reserved-scalar exclusion."""
    import tn
    from tn import current_config
    from tn._dispatch import DispatchRuntime, _rust_entries_with_valid

    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=_workflow_cipher("btn"), link=False)
    try:
        assert tn.using_rust(), "regression requires the Rust-backed reader"
        cfg = current_config()
        admin = _admin_log_path(cfg)

        rt = DispatchRuntime(str(yaml_path))
        entries = (
            rt._rt.read_raw(str(admin)) if rt._use_rust else None
        )
        assert entries is not None, "regression requires the Rust read path"
        rows = list(_rust_entries_with_valid(entries))
    finally:
        tn.flush_and_close()

    by_type = {r["envelope"].get("event_type"): r["valid"] for r in rows}
    assert "tn.ceremony.init" in by_type, f"saw {list(by_type)}"
    assert by_type["tn.ceremony.init"]["row_hash"] is True, (
        "Rust-backed reader failed row_hash on tn.ceremony.init: "
        f"{by_type['tn.ceremony.init']}"
    )
