"""Cross-runtime interop: Python<->Rust read/write of btn ceremonies.

Python writes, Rust reads:
  Create a ceremony with cipher="btn", emit events via tn.info(), then
  invoke the Rust CLI (tn-core-cli read) and verify it decrypts and
  returns both entries with the expected plaintext.

Rust writes, Python reads:
  Create a ceremony with cipher="btn", invoke tn-core-cli log to emit
  two events, then call tn.read() from Python and verify Python can
  verify signatures and decrypt both entries.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # tn-protocol/python on sys.path

# Path layout:
#   HERE           = tn-protocol/python/tests/
#   HERE.parents[1] = tn-protocol/    (workspace Cargo.toml, where cargo build runs)
#   HERE.parents[2] = content_platform/  (repo root)
TN_PROTO = HERE.parents[1]  # tn-protocol/
RUST_BIN_DEBUG = TN_PROTO / "target" / "debug" / "tn-core-cli.exe"
RUST_BIN_RELEASE = TN_PROTO / "target" / "release" / "tn-core-cli.exe"


def _rust_bin() -> Path:
    """Return the tn-core-cli binary path, building it (debug) if needed.

    Prefer the debug binary because it is the most recently built artifact
    and reflects the current source tree.  The release binary may be stale
    if only a debug build was done after the last source change.
    """
    if RUST_BIN_DEBUG.exists():
        return RUST_BIN_DEBUG
    if RUST_BIN_RELEASE.exists():
        return RUST_BIN_RELEASE
    # Neither exists — build a debug binary now.
    subprocess.check_call(
        ["cargo", "build", "-p", "tn-core", "--bin", "tn-core-cli"],
        cwd=str(TN_PROTO),
    )
    return RUST_BIN_DEBUG


def _default_log_path(yaml_path: Path) -> Path:
    """Both Python and Rust default to <yaml-dir>/logs/tn.ndjson."""
    return yaml_path.parent / ".tn/tn/logs" / "tn.ndjson"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_python_writes_rust_reads(tmp_path):
    """Python emits btn-encrypted events; Rust CLI decrypts and reads them."""
    import tn

    yaml_path = tmp_path / "tn.yaml"

    # Create a fresh btn ceremony and emit two events.
    tn.init(yaml_path, cipher="btn")
    try:
        tn.info("order.created", amount=100, note="first")
        tn.info("order.paid", amount=100, currency="USD")
    finally:
        tn.flush_and_close()

    log_path = _default_log_path(yaml_path)
    assert log_path.exists(), f"expected log at {log_path}"

    bin_path = _rust_bin()
    proc = subprocess.run(
        [str(bin_path), "--yaml", str(yaml_path), "read"],
        capture_output=True,
        text=True,
        check=True,
    )

    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    parsed = [json.loads(ln) for ln in lines]
    # Filter out bootstrap attestations (tn.ceremony.init, tn.group.added).
    parsed = [e for e in parsed if not e["envelope"]["event_type"].startswith("tn.")]
    assert len(parsed) == 2, (
        f"expected 2 user entries from Rust read, got {len(parsed)}:\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )

    # First entry: order.created
    e0 = parsed[0]
    assert e0["envelope"]["event_type"] == "order.created", e0["envelope"]
    # plaintext shape: {group_name: {field: value, ...}}; default group holds private fields.
    assert e0["plaintext"]["default"]["amount"] == 100, e0["plaintext"]
    assert e0["plaintext"]["default"]["note"] == "first", e0["plaintext"]

    # Second entry: order.paid
    e1 = parsed[1]
    assert e1["envelope"]["event_type"] == "order.paid", e1["envelope"]
    assert e1["plaintext"]["default"]["amount"] == 100, e1["plaintext"]
    assert e1["plaintext"]["default"]["currency"] == "USD", e1["plaintext"]


def test_rust_writes_python_reads(tmp_path):
    """Rust CLI emits btn-encrypted events; Python decrypts and verifies them."""
    import tn

    yaml_path = tmp_path / "tn.yaml"

    # Create the ceremony in Python so the keystore exists on disk.
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()

    bin_path = _rust_bin()

    # Emit two events via the Rust CLI using the Python-created ceremony.
    # Fields are parsed as JSON if possible; raw strings are kept as strings.
    subprocess.run(
        [
            str(bin_path),
            "--yaml",
            str(yaml_path),
            "log",
            "--event-type",
            "order.created",
            "amount=100",
            "note=from-rust",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        [
            str(bin_path),
            "--yaml",
            str(yaml_path),
            "log",
            "--event-type",
            "order.paid",
            "amount=100",
            "currency=USD",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    log_path = _default_log_path(yaml_path)
    assert log_path.exists(), f"expected log at {log_path}"

    # Re-open the ceremony in Python to read and decrypt.
    tn.init(yaml_path)
    try:
        # verify=True surfaces a _valid block; we assert each user entry
        # passes signature + row_hash + chain.
        # Filter out bootstrap tn.* attestations emitted at ceremony init.
        entries = [
            e for e in tn.read(log_path, verify=True) if not e["event_type"].startswith("tn.")
        ]
    finally:
        tn.flush_and_close()

    assert len(entries) == 2, f"expected 2 user entries from Python read, got {len(entries)}"

    # Spot-check field values recovered from Rust-produced envelopes.
    e0 = entries[0]
    assert e0["event_type"] == "order.created"
    assert all(e0["_valid"].values()) is True  # sig + row_hash + chain all verified
    assert e0["amount"] == 100
    assert e0["note"] == "from-rust"

    e1 = entries[1]
    assert e1["event_type"] == "order.paid"
    assert all(e1["_valid"].values()) is True
    assert e1["amount"] == 100
    assert e1["currency"] == "USD"
