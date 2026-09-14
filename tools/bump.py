#!/usr/bin/env python3
"""Propagate and check the TypeScript SDK release version.

The repo-root ``VERSION`` file holds the TypeScript semver string.
This script propagates it into the package and generated runtime constant:

    VERSION                     (canonical)
    ts-sdk/package.json         version
    ts-sdk/src/version.ts       SDK_VERSION  (also regenerated at TS build time
                                by ts-sdk/scripts/gen-version.mjs)

Usage:
    python tools/bump.py 0.6.3     # set the TypeScript version
    python tools/bump.py           # propagate the current VERSION
    python tools/bump.py --check   # verify the TypeScript targets agree

Python's calendar version is set in ``python/pyproject.toml`` and checked
against its ``python-v*`` tag by the Python release workflow.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
PACKAGE_JSON = ROOT / "ts-sdk" / "package.json"
VERSION_TS = ROOT / "ts-sdk" / "src" / "version.ts"

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|alpha|beta)\d*)?$")

# Each target: (path, regex, human label). Group 1 captures everything up to
# the opening quote (so we can splice the new version in without disturbing
# surrounding formatting); group 2 captures the current value (for --check).
TARGETS = [
    (PACKAGE_JSON, re.compile(r'(?m)^(\s*"version"\s*:\s*)"([^"]*)"'), "package.json"),
    (VERSION_TS, re.compile(r'(?m)^(export const SDK_VERSION\s*=\s*)"([^"]*)"'), "version.ts"),
]


def read_canonical() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def current_in(path: Path, pattern: re.Pattern[str]) -> str | None:
    m = pattern.search(path.read_text(encoding="utf-8"))
    return m.group(2) if m else None


def write_version(version: str) -> list[str]:
    changed = []
    VERSION_FILE.write_text(version + "\n", encoding="utf-8")
    for path, pattern, label in TARGETS:
        text = path.read_text(encoding="utf-8")
        new = pattern.sub(lambda m: f'{m.group(1)}"{version}"', text, count=1)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed.append(label)
    return changed


def check() -> int:
    canonical = read_canonical()
    if not SEMVER.match(canonical):
        print(f"VERSION '{canonical}' is not a valid semver string", file=sys.stderr)
        return 1
    drift = []
    for path, pattern, label in TARGETS:
        got = current_in(path, pattern)
        if got != canonical:
            drift.append(f"  {label}: {got!r} != VERSION {canonical!r}")
    if drift:
        print("version drift detected:", file=sys.stderr)
        print("\n".join(drift), file=sys.stderr)
        print("run `python tools/bump.py` to propagate the TypeScript VERSION.", file=sys.stderr)
        return 1
    print(f"TypeScript version OK: {canonical}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Set/propagate/verify the TypeScript SDK version.")
    p.add_argument("version", nargs="?", help="new semver to set (omit to propagate current VERSION)")
    p.add_argument("--check", action="store_true", help="verify all targets agree with VERSION; exit 1 on drift")
    args = p.parse_args(argv)

    if args.check:
        return check()

    version = args.version or read_canonical()
    if not SEMVER.match(version):
        print(f"'{version}' is not a valid semver string", file=sys.stderr)
        return 1
    changed = write_version(version)
    if changed:
        print(f"set version {version}; updated VERSION + {', '.join(changed)}")
    else:
        print(f"version {version} already set everywhere")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
