#!/usr/bin/env python3
"""btn revocation showcase.

Demonstrates add/revoke through the Python skin on the Rust runtime.

Usage:
    .venv/Scripts/python.exe tn-protocol/python/examples/demo_revocation.py
    .venv/Scripts/python.exe tn-protocol/python/examples/demo_revocation.py --legacy
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — ensure tn package is importable from any working directory.
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR.parent))

# --legacy: set TN_FORCE_PYTHON before importing tn so the Python path is used.
parser = argparse.ArgumentParser(description="btn revocation demo")
parser.add_argument(
    "--legacy",
    action="store_true",
    help="Force the pure-Python runtime path (sets TN_FORCE_PYTHON=1)",
)
args, _ = parser.parse_known_args()

if args.legacy:
    os.environ["TN_FORCE_PYTHON"] = "1"

import tn

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
N_RECIPIENTS = 20
N_TO_REVOKE = 5  # revoke recipients 0..4 (first N_TO_REVOKE minted)
PRE_REVOKE_EVENTS = 5
POST_REVOKE_EVENTS = 5
GROUP = "default"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decrypt_envelope_with_kit(kit_bytes: bytes, env: dict[str, Any]) -> bool:
    """Try to decrypt the `default` group ciphertext with a raw btn kit.

    Returns True on success, False if NotEntitled or any btn error.
    Uses btn.decrypt (kit_bytes, ct_bytes) — the btn-py module-level fn.
    """
    import btn  # type: ignore[import-not-found]  # PyO3 ext (maturin)

    ct_b64 = env.get(GROUP, {}).get("ciphertext")
    if ct_b64 is None:
        return False
    ct_bytes = base64.standard_b64decode(ct_b64)
    try:
        btn.decrypt(kit_bytes, ct_bytes)
        return True
    except Exception:
        return False


def _read_log_envelopes(log_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log_path.read_text("utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Main demo logic
# ---------------------------------------------------------------------------


def run_demo(tmp_dir: Path) -> dict[str, Any]:
    """Run the revocation demo in `tmp_dir`. Returns timing / result data."""
    yaml = tmp_dir / "tn.yaml"
    tn.init(yaml, cipher="btn")
    runtime_label = "tn_core (Rust)" if tn.using_rust() else "pure Python"

    # --- Phase 1: mint N_RECIPIENTS reader kits ---
    kits_dir = tmp_dir / "kits"
    kits_dir.mkdir(exist_ok=True)
    kit_paths: list[Path] = []
    kit_leaf_map: list[int] = []  # kit_leaf_map[i] = leaf index of kit i

    print(f"Minting {N_RECIPIENTS} reader kits via {runtime_label}...")
    if tn.using_rust():
        for i in range(N_RECIPIENTS):
            p = kits_dir / f"reader_{i:02d}.mykit"
            leaf = tn.admin.add_recipient(GROUP, out_path=str(p))
            kit_paths.append(p)
            kit_leaf_map.append(leaf)
    else:
        # Python path: btn PublisherState lives in the keystore as .btn.state
        # We need to drive it manually using the tn.admin Python API which
        # doesn't yet have per-recipient add for btn.  For the legacy demo we
        # use the btn Python bindings directly against the persisted state.
        import btn  # type: ignore[import-not-found]  # PyO3 ext (maturin)

        cfg = tn.current_config()
        state_path = cfg.keystore / f"{GROUP}.btn.state"
        state = btn.PublisherState.from_bytes(state_path.read_bytes())
        for i in range(N_RECIPIENTS):
            p = kits_dir / f"reader_{i:02d}.mykit"
            kit_bytes = state.mint()
            leaf = btn.kit_leaf(kit_bytes)
            p.write_bytes(kit_bytes)
            kit_paths.append(p)
            kit_leaf_map.append(leaf)
        # Persist updated state so the runtime uses it for future encrypts.
        state_path.write_bytes(state.to_bytes())
        # Reload tn so the in-memory cipher picks up the new state.
        tn.flush_and_close()
        tn.init(yaml, cipher="btn")

    # --- Phase 2: emit PRE_REVOKE_EVENTS ---
    print(f"Emitting {PRE_REVOKE_EVENTS} pre-revoke events...")
    for i in range(PRE_REVOKE_EVENTS):
        tn.info("page.view", batch="pre", index=i, path=f"/pre/{i}")

    # --- Phase 3: revoke recipients 0..N_TO_REVOKE-1 ---
    revoke_times_ms: list[float] = []
    print(f"Revoking recipients 0..{N_TO_REVOKE - 1}...")
    revoked_leaves = kit_leaf_map[:N_TO_REVOKE]
    for leaf in revoked_leaves:
        t0 = time.perf_counter()
        if tn.using_rust():
            tn.admin.revoke_recipient(GROUP, leaf_index=leaf)
        else:
            # Python path: mutate persisted state directly.
            import btn  # type: ignore[import-not-found]  # PyO3 ext (maturin)

            cfg = tn.current_config()
            state_path = cfg.keystore / f"{GROUP}.btn.state"
            state = btn.PublisherState.from_bytes(state_path.read_bytes())
            state.revoke_by_leaf(leaf)
            state_path.write_bytes(state.to_bytes())
        revoke_times_ms.append((time.perf_counter() - t0) * 1000)

    if tn.using_rust():
        actual_revoked = tn.admin.revoked_count(GROUP)
    else:
        # Reload after revocations so cipher uses updated state.
        tn.flush_and_close()
        tn.init(yaml, cipher="btn")
        actual_revoked = N_TO_REVOKE  # we just revoked N_TO_REVOKE leaves

    mean_revoke_ms = sum(revoke_times_ms) / len(revoke_times_ms)

    # --- Phase 4: emit POST_REVOKE_EVENTS ---
    print(f"Emitting {POST_REVOKE_EVENTS} post-revoke events...")
    for i in range(POST_REVOKE_EVENTS):
        tn.info("page.view", batch="post", index=i, path=f"/post/{i}")

    tn.flush_and_close()

    # --- Phase 5: verify which kits can decrypt what ---
    log_path = yaml.parent / ".tn" / "logs" / "tn.ndjson"
    envelopes = _read_log_envelopes(log_path)
    total_events = PRE_REVOKE_EVENTS + POST_REVOKE_EVENTS
    assert len(envelopes) == total_events, (
        f"expected {total_events} log entries, got {len(envelopes)}"
    )

    pre_envelopes = envelopes[:PRE_REVOKE_EVENTS]
    post_envelopes = envelopes[PRE_REVOKE_EVENTS:]

    print("Verifying decryption across all kits and batches...")
    pre_can_decrypt = 0
    post_can_decrypt = 0
    table_rows: list[tuple[int, int, bool, bool]] = []

    for i, kit_path in enumerate(kit_paths):
        kit_bytes = kit_path.read_bytes()
        # Check pre-revoke batch (all kits should succeed — readers existed before revocation).
        pre_ok = all(_decrypt_envelope_with_kit(kit_bytes, env) for env in pre_envelopes)
        # Check post-revoke batch (only non-revoked kits should succeed).
        post_ok = all(_decrypt_envelope_with_kit(kit_bytes, env) for env in post_envelopes)
        table_rows.append((i, kit_leaf_map[i], pre_ok, post_ok))
        if pre_ok:
            pre_can_decrypt += 1
        if post_ok:
            post_can_decrypt += 1

    return {
        "runtime_label": runtime_label,
        "n_recipients": N_RECIPIENTS,
        "n_revoked": actual_revoked,
        "total_events": total_events,
        "pre_can_decrypt": pre_can_decrypt,
        "post_can_decrypt": post_can_decrypt,
        "mean_revoke_ms": mean_revoke_ms,
        "table_rows": table_rows,
    }


def _print_results(results: dict[str, Any]) -> None:
    """Print per-kit table and summary block."""
    print()
    print("Kit #  Leaf  Pre-batch  Post-batch")
    print("-----  ----  ---------  ----------")
    for i, leaf, pre_ok, post_ok in results["table_rows"]:
        revoked_marker = " (revoked)" if i < N_TO_REVOKE else ""
        pre_str = "OK" if pre_ok else "FAIL"
        post_str = "OK" if post_ok else "FAIL"
        print(f"  {i:3d}  {leaf:4d}  {pre_str:9s}  {post_str}{revoked_marker}")

    n_active = N_RECIPIENTS - N_TO_REVOKE
    print()
    print("================================================================")
    print(" TN btn revocation demo — summary")
    print("================================================================")
    print("Cipher:        btn (h=8, 256 leaves)")
    print(f"Recipients:    {n_active} active, {results['n_revoked']} revoked")
    print(
        f"Events:        {results['total_events']} total "
        f"({PRE_REVOKE_EVENTS} pre-revoke + {POST_REVOKE_EVENTS} post-revoke)"
    )
    print(
        f"Entitlement:   {results['post_can_decrypt']} readers decrypted post-revoke batch "
        f"(expected {n_active})"
    )
    print(
        f"               {results['pre_can_decrypt']} readers decrypted pre-revoke batch "
        f"(expected {N_RECIPIENTS})"
    )
    print(
        f"Revocation:    mean {results['mean_revoke_ms']:.1f} ms per revoke call (N={N_TO_REVOKE})"
    )
    print(f"Runtime path:  {results['runtime_label']}")
    print("================================================================")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="tn_revoke_demo_") as tmp:
        tmp_dir = Path(tmp)
        print(f"Demo workspace: {tmp_dir}")
        print(f"Runtime path:   {'pure Python (--legacy)' if args.legacy else 'tn_core (Rust)'}")
        print()
        results = run_demo(tmp_dir)

    _print_results(results)

    # Sanity assertions.
    n_active = N_RECIPIENTS - N_TO_REVOKE
    assert results["post_can_decrypt"] == n_active, (
        f"Expected {n_active} post-revoke readers, got {results['post_can_decrypt']}"
    )
    assert results["pre_can_decrypt"] == N_RECIPIENTS, (
        f"Expected {N_RECIPIENTS} pre-revoke readers, got {results['pre_can_decrypt']}"
    )
    print("All assertions passed.")


if __name__ == "__main__":
    main()
