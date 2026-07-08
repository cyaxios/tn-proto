"""Cipher-parity sweep: rerun every parameterized workflow test under an
alternate cipher and compare against its default-cipher baseline.

Workflow tests read their cipher through the ``_workflow_cipher`` hook
(``TN_TEST_CIPHER`` env var, injected across the suite for the hibe parity
work). This runner executes each such test twice — once with the default,
once with the target cipher — and reports:

    OK         passed both ways (the workflow is cipher-agnostic)
    GAP        baseline passes, target cipher fails  <- the signal
    ENV        baseline itself fails here (environment/stale test; ignored)
    SKIP       excluded by design (reason printed)

Usage:  python tests/run_cipher_sweep.py [--cipher hibe] [--only substr]
Exit code = number of GAPs.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Excluded from the sweep by design, with the honest reason.
SKIP: dict[str, str] = {
    # live-service tests: need a running vault / cloud creds; they are not
    # cipher seams and time out or self-skip here.
    "test_account_sync_full_live.py": "needs a live vault",
    "test_day1_backup_restore_live.py": "needs a live vault",
    "test_day1_two_device_group_sync_live.py": "needs a live vault",
    "test_init_attach_live.py": "needs a live vault",
    "integration/test_vault_push_pull_e2e.py": "needs a live vault",
    "integration/test_vault_api_key_persistent_e2e.py": "needs a live vault",
    "integration/test_vault_api_key_single_pickup_e2e.py": "needs a live vault",
}

TIMEOUT = 180


def parameterized_files() -> list[Path]:
    out = []
    for f in sorted(HERE.rglob("test_*.py")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "TN_TEST_CIPHER" in text:
            out.append(f)
    return out


def run_one(f: Path, cipher: str | None) -> bool:
    env = dict(os.environ)
    env.pop("TN_TEST_CIPHER", None)
    if cipher:
        env["TN_TEST_CIPHER"] = cipher
    try:
        r = subprocess.run(
            [sys.executable, str(f)],
            cwd=HERE.parent,
            env=env,
            capture_output=True,
            timeout=TIMEOUT,
        )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cipher", default="hibe")
    ap.add_argument("--only", default=None, help="substring filter on filename")
    args = ap.parse_args()

    results: dict[str, list[str]] = {"OK": [], "GAP": [], "ENV": [], "SKIP": []}
    for f in parameterized_files():
        rel = f.relative_to(HERE).as_posix()
        if args.only and args.only not in rel:
            continue
        if rel in SKIP:
            results["SKIP"].append(f"{rel}  ({SKIP[rel]})")
            print(f"SKIP {rel}  ({SKIP[rel]})", flush=True)
            continue
        if not run_one(f, None):
            results["ENV"].append(rel)
            print(f"ENV  {rel}", flush=True)
            continue
        if run_one(f, args.cipher):
            results["OK"].append(rel)
            print(f"OK   {rel}", flush=True)
        else:
            results["GAP"].append(rel)
            print(f"GAP  {rel}", flush=True)

    print(
        f"\nsweep({args.cipher}): {len(results['OK'])} ok, "
        f"{len(results['GAP'])} gaps, {len(results['ENV'])} env-broken, "
        f"{len(results['SKIP'])} skipped"
    )
    for rel in results["GAP"]:
        print(f"  GAP {rel}")
    return len(results["GAP"])


if __name__ == "__main__":
    sys.exit(main())
