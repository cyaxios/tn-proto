#!/usr/bin/env python3
"""Root developer task runner for tn-proto.

Run from the repository root:

    python tools/dev.py bootstrap
    python tools/dev.py native
    python tools/dev.py verify-native
    python tools/dev.py test-hibe
    python tools/dev.py wheel

The runner intentionally keeps cwd management inside the script so Windows,
macOS, Linux, shells, and CI can use the same entry points from `tn_proto/`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "python"
TS_DIR = ROOT / "ts-sdk"
VENV_DIR = ROOT / ".venv"


def exe(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"required executable not found on PATH: {name}")
    return found


def repo_python() -> str:
    override = os.environ.get("TN_PYTHON")
    if override:
        return override
    candidate = (
        VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    )
    if candidate.exists():
        return str(candidate)
    return sys.executable


def run(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print(f"==> {cwd.relative_to(ROOT) if cwd != ROOT else '.'}> {' '.join(cmd)}", flush=True)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    subprocess.run(cmd, cwd=cwd, env=merged_env, check=True)


def python_env_path() -> dict[str, str]:
    current = os.environ.get("PYTHONPATH")
    path = str(PY_DIR)
    if current:
        path = path + os.pathsep + current
    return {"PYTHONPATH": path}


def cmd_bootstrap(args: argparse.Namespace) -> None:
    if args.recreate and VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    if not VENV_DIR.exists():
        print(f"==> creating {VENV_DIR.relative_to(ROOT)}")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)

    py = repo_python()
    run([py, "-m", "pip", "install", "--upgrade", "pip", "maturin"], cwd=ROOT)
    run([py, "-m", "pip", "install", "-e", "python[test]"], cwd=ROOT)
    if args.node:
        run([exe("npm"), "install"], cwd=TS_DIR)

    print()
    print("Bootstrap complete.")
    print("Use .\\.venv\\Scripts\\Activate.ps1 on Windows, or keep using:")
    print("  python tools/dev.py <command>")


def cmd_native(_args: argparse.Namespace) -> None:
    py = repo_python()
    run([py, "-m", "maturin", "develop", "--release", "--skip-install"], cwd=PY_DIR)
    cmd_verify_native(argparse.Namespace())


def cmd_verify_native(_args: argparse.Namespace) -> None:
    py = repo_python()
    code = (
        "from tn._native import core, btn, hibe\n"
        "mpk, msk = hibe.setup(2)\n"
        "assert hibe.mpk_max_depth(mpk) == 2\n"
        "import tn._hibe as h\n"
        "assert h.mpk_max_depth(mpk) == 2\n"
        "print('native OK: core + btn + hibe')\n"
    )
    run([py, "-c", code], cwd=ROOT, env=python_env_path())


def cmd_wheel(args: argparse.Namespace) -> None:
    py = repo_python()
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    run([py, "-m", "maturin", "build", "--release", "--out", str(out)], cwd=PY_DIR)
    print(f"Wheel output: {out}")


def cmd_rust_hibe(_args: argparse.Namespace) -> None:
    run([exe("cargo"), "test", "-p", "tn-bbg"], cwd=ROOT)
    run([exe("cargo"), "test", "-p", "tn-hibe"], cwd=ROOT)
    run(
        [
            exe("cargo"),
            "test",
            "-p",
            "tn-core",
            "--features",
            "fs",
            "cipher::hibe::test",
        ],
        cwd=ROOT,
    )


def cmd_python_hibe(_args: argparse.Namespace) -> None:
    py = repo_python()
    run(
        [
            py,
            "-m",
            "pytest",
            "python/tests/test_hibe_boundary.py",
            "python/tests/test_cipher_hibe.py",
            "python/tests/test_hibe_aad.py",
            "python/tests/test_cipher_jwe.py",
            "-q",
        ],
        cwd=ROOT,
        env=python_env_path(),
    )


def cmd_ts_hibe(_args: argparse.Namespace) -> None:
    run([exe("npm"), "run", "typecheck"], cwd=TS_DIR)
    run(
        [
            exe("node"),
            "--import",
            "tsx",
            "--import",
            "./test/_setup_wasm.mjs",
            "--test",
            "test/hibe_group_validation.test.ts",
            "test/hibe_lifecycle.test.ts",
            "test/hibe_revoke.test.ts",
            "test/hibe_aad.test.ts",
            "test/jwe_group_lifecycle.test.ts",
            "test/jwe_cipher.test.ts",
            "test/jwe_admin.test.ts",
            "test/jwe_emit_async.test.ts",
            "test/jwe_read_async.test.ts",
            "test/jwe_foreign_read.test.ts",
        ],
        cwd=TS_DIR,
    )


def cmd_test_hibe(args: argparse.Namespace) -> None:
    cmd_verify_native(args)
    cmd_rust_hibe(args)
    cmd_python_hibe(args)
    cmd_ts_hibe(args)


def cmd_build(_args: argparse.Namespace) -> None:
    py = repo_python()
    run([exe("cargo"), "check", "-p", "tn-proto-native"], cwd=ROOT)
    run(
        [
            exe("cargo"),
            "check",
            "-p",
            "tn-wasm",
            "--features",
            "runtime",
            "--target",
            "wasm32-unknown-unknown",
        ],
        cwd=ROOT,
    )
    run([exe("npm"), "run", "build"], cwd=TS_DIR)
    run([py, "-m", "py_compile", "python/tn/_hibe.py", "python/tn/cipher.py"], cwd=ROOT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run tn-proto developer tasks from the repository root."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("bootstrap", help="Create .venv and install Python dev deps.")
    p.add_argument("--recreate", action="store_true", help="Delete and recreate .venv first.")
    p.add_argument("--node", action="store_true", help="Also run npm install in ts-sdk.")
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("native", help="Rebuild python/tn/_native in place.")
    p.set_defaults(func=cmd_native)

    p = sub.add_parser("verify-native", help="Import core, btn, and hibe from source tree.")
    p.set_defaults(func=cmd_verify_native)

    p = sub.add_parser("wheel", help="Build the single tn-proto wheel.")
    p.add_argument("--out", default="dist", help="Output directory, relative to repo root.")
    p.set_defaults(func=cmd_wheel)

    p = sub.add_parser("build", help="Run root build checks for Rust, wasm, TS, Python.")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("rust-hibe", help="Run Rust HIBE/BBG focused tests.")
    p.set_defaults(func=cmd_rust_hibe)

    p = sub.add_parser("python-hibe", help="Run Python HIBE/JWE focused tests.")
    p.set_defaults(func=cmd_python_hibe)

    p = sub.add_parser("ts-hibe", help="Run TypeScript HIBE/JWE focused tests.")
    p.set_defaults(func=cmd_ts_hibe)

    p = sub.add_parser("test-hibe", help="Run native import plus Rust/Python/TS HIBE checks.")
    p.set_defaults(func=cmd_test_hibe)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
