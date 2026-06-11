"""Real CLI-verb coverage for send/receive + the two-way `tn wallet sync`.

Everything here drives the ACTUAL argparse verbs as a subprocess
(`python -m tn.cli ...`) against an isolated TN_HOME — mirroring
test_cli_rotate.py — so we exercise the CLI wiring, not just the Python
API underneath. This closes the "we only test the handlers, never the
verbs" gap.

Two parties (Alice, Frank) get separate TN_HOME dirs so their
identities/ceremonies don't collide.

The out-of-band kit round-trip needs no server. The `tn wallet sync`
error-path cases exercise the new pull->absorb->push branching and the
--push-only flag without a vault (the full vault round-trip via the verb
is a separate, server-backed test).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

_PYTHON_DIR = Path(__file__).resolve().parent.parent
_DID_RE = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{20,}")


def _run_cli(
    *args: str, cwd: Path, home: Path, timeout: int = 90
) -> subprocess.CompletedProcess:
    """Run `python -m tn.cli ...` with an isolated TN_HOME."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_PYTHON_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["TN_HOME"] = str(home)
    env["TN_NO_STDOUT"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _init_party(root: Path, name: str) -> tuple[Path, Path, str]:
    """`tn init <name> --no-link` in an isolated dir. Returns
    (cwd, yaml_path, did)."""
    cwd = root / name
    home = cwd / ".tnhome"
    cwd.mkdir(parents=True, exist_ok=True)
    res = _run_cli("init", name, "--no-link", "--skip-confirm", cwd=cwd, home=home)
    assert res.returncode == 0, f"init failed: {res.stdout}\n{res.stderr}"
    m = _DID_RE.search(res.stdout + res.stderr)
    assert m, f"no did:key in init output:\n{res.stdout}\n{res.stderr}"
    yamls = list(cwd.glob("**/tn.yaml"))
    assert yamls, f"no tn.yaml produced under {cwd}"
    return cwd, yamls[0], m.group(0)


def test_cli_out_of_band_kit_roundtrip(tmp_path: Path):
    """Alice mints a kit for Frank via `tn add_recipient --out`; Frank
    receives it via `tn absorb`. Both are real CLI verbs, no server."""
    a_cwd, a_yaml, _a_did = _init_party(tmp_path, "alice")
    f_cwd, f_yaml, f_did = _init_party(tmp_path, "frank")
    a_home = a_cwd / ".tnhome"
    f_home = f_cwd / ".tnhome"

    kit = tmp_path / "for_frank.tnpkg"
    res = _run_cli(
        "add_recipient", "default", f_did, "--out", str(kit),
        "--yaml", str(a_yaml), cwd=a_cwd, home=a_home,
    )
    assert res.returncode == 0, f"add_recipient failed: {res.stdout}\n{res.stderr}"
    assert kit.exists(), "add_recipient did not write the kit .tnpkg"

    res = _run_cli(
        "absorb", str(kit), "--yaml", str(f_yaml), cwd=f_cwd, home=f_home,
    )
    assert res.returncode == 0, f"absorb failed: {res.stdout}\n{res.stderr}"
    assert "tn absorb" in res.stdout, res.stdout
    # The kit landed in Frank's keystore.
    assert "rejected" not in res.stdout.lower(), res.stdout


def test_cli_wallet_sync_push_only_unlinked_errors(tmp_path: Path):
    """`tn wallet sync --push-only` on an offline ceremony fails clearly
    (nothing to push) — exercises the new --push-only branch."""
    cwd, yaml, _did = _init_party(tmp_path, "solo")
    res = _run_cli(
        "wallet", "sync", str(yaml), "--push-only",
        cwd=cwd, home=cwd / ".tnhome",
    )
    assert res.returncode != 0, f"expected failure, got 0: {res.stdout}"
    assert "not linked" in (res.stdout + res.stderr).lower()


def test_cli_wallet_sync_bare_unlinked_unbound_errors(tmp_path: Path):
    """Bare `tn wallet sync` on an offline, unbound ceremony fails with a
    clear message — exercises the new pull->absorb->push branching when
    there is nothing to pull and nothing to push."""
    cwd, yaml, _did = _init_party(tmp_path, "solo2")
    res = _run_cli(
        "wallet", "sync", str(yaml), cwd=cwd, home=cwd / ".tnhome",
    )
    assert res.returncode != 0, f"expected failure, got 0: {res.stdout}"
    blob = (res.stdout + res.stderr).lower()
    assert "not linked" in blob and "account-bound" in blob, blob
