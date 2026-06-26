#!/usr/bin/env python3
"""docs_check — a crawler for docs/guide/*.md that catches drift from the code.

For each guide page it extracts fenced code blocks (tracking the section heading
each lives under) and the markdown links, then runs mechanical checks:

  links       every relative `](x.md#frag)` / `](x)` target file exists
  cli-verbs   every `tn <verb>` / `tn-js <verb>` invocation names a real verb
              (introspected from the Python argparse parser)
  py-symbols  every `tn.<attr>` / `tn.admin.<attr>` … referenced in a python
              block resolves on the installed/repo SDK
  run         a curated allowlist of safe CLI examples actually execute in a
              throwaway sandbox project (no vault/network)

It is judgment-free on purpose: clarity / "does this make sense" is a separate
human read. Exit code is non-zero if any check fails, so this is CI-usable.

Run:  python tools/docs_check.py            # all guide docs
      python tools/docs_check.py getting-started.md
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUIDE = REPO / "docs" / "guide"

# Verbs that need a vault/network or are inherently interactive — not executed,
# only existence-checked. (auth login opens a browser; wallet sync hits a vault.)
NEEDS_SERVER = {
    "auth", "account", "wallet", "vault", "firehose", "watch", "inbox",
}


# ── code-block + link extraction ────────────────────────────────────────────

def sections_and_blocks(md: str):
    """Yield (section_title, lang, code) for each fenced block, tracking the most
    recent `##`/`###` heading."""
    section = "(top)"
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        h = re.match(r"^#{2,3}\s+(.*)", line)
        if h:
            section = h.group(1).strip()
            i += 1
            continue
        fence = re.match(r"^```(\w+)?\s*$", line)
        if fence:
            lang = (fence.group(1) or "").lower()
            body = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            yield section, lang, "\n".join(body)
        i += 1


def links(md: str):
    """Yield every markdown link target (the parenthesized part)."""
    for m in re.finditer(r"\]\(([^)]+)\)", md):
        yield m.group(1).strip()


# ── checks ──────────────────────────────────────────────────────────────────

def valid_cli_verbs() -> set[str]:
    """The set of real `tn` subcommands, introspected from the argparse parser."""
    try:
        sys.path.insert(0, str(REPO / "python"))
        from tn.cli import build_parser  # type: ignore

        parser = build_parser()
        verbs: set[str] = set()
        for action in parser._actions:  # noqa: SLF001 — introspection is the point
            choices = getattr(action, "choices", None)
            if choices:
                verbs.update(choices.keys() if hasattr(choices, "keys") else choices)
        return verbs
    except Exception as exc:  # noqa: BLE001
        print(f"  ! could not introspect CLI parser: {exc}")
        return set()


def cli_invocations(code: str):
    """Yield (tool, verb) for each `tn`/`tn-js`/`python -m tn.x` command line."""
    for raw in code.splitlines():
        line = raw.strip()
        if line.startswith("#") or not line:
            continue
        # strip a leading `$ ` prompt if present
        line = re.sub(r"^\$\s+", "", line)
        m = re.match(r"^(tn-js|tn)\s+([a-z_]+)", line)
        if m:
            yield m.group(1), m.group(2)
        mm = re.match(r"^python\s+-m\s+tn\.([a-z_]+)", line)
        if mm:
            yield "python -m", mm.group(1)


def py_symbols(code: str):
    """Yield dotted attribute chains rooted at `tn.` referenced as code (not in a
    string), e.g. `tn.admin.ensure_group`, `tn.read`. The negative lookbehind
    skips quoted occurrences — event-type literals like "tn.ceremony.init" are
    wire strings, not SDK attributes, and must not be resolved."""
    # Strip Python comments line-by-line: event types shown as example output
    # (e.g. `# info tn.ceremony.init`) are not SDK attributes.
    uncommented = "\n".join(line.split("#", 1)[0] for line in code.splitlines())
    for m in re.finditer(r"(?<![\"'\w.])tn((?:\.[a-z_]+)+)", uncommented):
        yield m.group(1).lstrip(".")


def resolve_symbol(tn_mod, chain: str) -> bool:
    obj = tn_mod
    for part in chain.split("."):
        # stop at a call/subscript boundary; we only resolve attribute names
        if not part.isidentifier():
            return True
        if not hasattr(obj, part):
            return False
        obj = getattr(obj, part)
    return True


# Curated safe CLI examples to actually run, by doc. {placeholder} filled at run.
RUNNABLE = [
    ("init", ["init", "demo", "--no-link"]),
    ("info", ["info", "--yaml", "{yaml}", "--event", "order.created", "--field", "amount=10"]),
    ("read", ["read", "--yaml", "{yaml}"]),
    ("streams", ["streams"]),
    ("validate", ["validate"]),
    ("group add", ["group", "add", "audit", "--fields", "actor,action"]),
]


def run_smoke(report: list[str]) -> int:
    """Run the curated CLI examples in a throwaway project; return failure count."""
    fails = 0
    tn_js = REPO / "ts-sdk" / "bin" / "tn-js.mjs"
    with tempfile.TemporaryDirectory(prefix="docs-smoke-") as tmp:
        env = {
            **os.environ,
            "TN_IDENTITY_DIR": str(Path(tmp) / ".id"),
            "TN_HOME": str(Path(tmp) / ".home"),
            "TN_NO_LINK": "1",
        }
        yaml = str(Path(tmp) / ".tn" / "demo" / "tn.yaml")
        for label, args in RUNNABLE:
            cmd = ["node", str(tn_js), *[a.replace("{yaml}", yaml) for a in args]]
            try:
                r = subprocess.run(cmd, cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
                ok = r.returncode == 0
            except Exception as exc:  # noqa: BLE001
                ok = False
                r = None
                report.append(f"    run {label:<10} ERROR {exc}")
            if r is not None:
                status = "ok " if ok else "FAIL"
                report.append(f"    run {label:<10} {status} (exit {r.returncode})")
                if not ok:
                    report.append(f"        {(r.stderr or r.stdout).strip().splitlines()[-1:]}")
            if not ok:
                fails += 1
    return fails


def main() -> int:
    args = sys.argv[1:]
    docs = [GUIDE / a for a in args] if args else sorted(GUIDE.glob("*.md"))
    verbs = valid_cli_verbs()
    # module-main verbs (`python -m tn.watch`) aren't argparse subcommands
    module_verbs = {"watch", "inbox"}

    sys.path.insert(0, str(REPO / "python"))
    try:
        import tn as tn_mod  # type: ignore
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: cannot import repo tn: {exc}")
        return 2

    total_fail = 0
    for doc in docs:
        md = doc.read_text(encoding="utf-8")
        report: list[str] = []

        # links
        for target in links(md):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = (doc.parent / target.split("#")[0]).resolve()
            if not path.exists():
                report.append(f"  LINK MISSING  {target}")
                total_fail += 1

        # cli verbs + py symbols, per block
        for section, lang, code in sections_and_blocks(md):
            if lang in ("bash", "sh", "console", ""):
                for tool, verb in cli_invocations(code):
                    known = verb in verbs or verb in module_verbs
                    if not known:
                        report.append(f"  [{section}] UNKNOWN VERB  {tool} {verb}")
                        total_fail += 1
            if lang in ("python", "py"):
                for chain in py_symbols(code):
                    if not resolve_symbol(tn_mod, chain):
                        report.append(f"  [{section}] MISSING SYMBOL  tn.{chain}")
                        total_fail += 1

        if doc.name == "getting-started.md":
            report.append("  -- runnable smoke --")
            total_fail += run_smoke(report)

        status = "OK" if not any("MISSING" in r or "UNKNOWN" in r or "FAIL" in r for r in report) else "ISSUES"
        print(f"\n=== {doc.name} : {status} ===")
        for r in report:
            print(r)

    print(f"\n{'PASS' if total_fail == 0 else f'FAIL ({total_fail} issue(s))'}")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
