"""Phantom-features audit re-grounding.

For each item in PHANTOM_FEATURES_AUDIT.md, emit a row with:
- audit ID + title + recommendation (parsed from the markdown)
- current call-site count (grep-equivalent across source + tests)
- module/file presence count
- a simple "still present?" verdict (yes / partial / no)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path

from .config import IntrospectConfig
from .manifest import write_manifest


# (id, title, search_terms, recommendation_tier)
# Tiers: "rip" (ph audit ❌), "review" (🟡), "keep" (✅)
PHANTOM_ITEMS: list[tuple[int, str, list[str], str]] = [
    (1,  "WARNING_CONTAINS_PRIVATE_KEYS marker file",     ["WARNING_CONTAINS_PRIVATE_KEYS"], "rip"),
    (2,  "tn.read.tampered_row_skipped admin event",       ["tn.read.tampered_row_skipped", "tampered_row_skipped"], "rip"),
    (3,  "tn.agents.policy_published admin event",         ["tn.agents.policy_published", "policy_published"], "rip"),
    (4,  "secure_read forensic mode",                       ['"forensic"', "'forensic'", "Forensic", "= forensic"], "rip"),
    (5,  "tn.read(verify=True) flag",                       ["verify=True", "verify: bool", "verify:bool", "verify_bool", "read(verify"], "rip"),
    (6,  "anti-entropy / SSB / Dynamo / CRDT framing",      ["anti-entropy", "Bayou", "Secure Scuttlebutt", "CRDT", "Dynamo"], "rip"),
    (7,  "byte-compare matrix expansion to all admin events", ["admin_events_canonical.json", "byte_compare", "_canonical_scenario"], "rip"),
    (8,  "_pytest_fixtures.py as separate file",            ["_pytest_fixtures.py", "_pytest_fixtures"], "rip"),
    (9,  "tn.agents namespace reservation",                 ["ReservedGroupName", "reserved_group", '"tn.agents"', "'tn.agents'"], "review"),
    (10, "tn.agents auto-injected at create_fresh()",       ["tn_agents_group", "tn.agents", "agents_group", "auto-injects the tn.agents"], "review"),
    (11, "_hidden_groups + _decrypt_errors split",          ["_hidden_groups", "_decrypt_errors", "_unavailable_groups"], "review"),
    (12, "auto-init four-step discovery chain",             ["TN_YAML", "TN_HOME", "$TN_HOME", "_autoinit", "auto_init"], "review"),
    (13, "TN_STRICT env var",                                ["TN_STRICT", "set_strict"], "review"),
    (14, "Runtime::ephemeral / TNClient.ephemeral",          ["Runtime::ephemeral", "TNClient.ephemeral", ".ephemeral()", "static ephemeral"], "review"),
    (15, "policy_published reducer maps to StateDelta::Unknown", ["StateDelta::Unknown", "policy_published"], "review"),
    (16, "agents.md 5-field markdown schema",                ["instruction", "use_for", "do_not_use_for", "consequences", "on_violation_or_error"], "review"),
    (17, "vault retention 'append-only forever'",           ["append-only forever", "auto-prune"], "review"),
    (18, "to_did v1 routing requirement",                    ["to_did", "broadcast_inbox", "to_did is None"], "review"),
    (19, "tn.agents field-hash emission default ON",         ["field_hashes", "tn.agents"], "review"),
    (20, "recipient_invite manifest kind",                   ["recipient_invite", "RecipientInvite"], "keep"),
    (21, "full_keystore + confirm_includes_secrets",         ["full_keystore", "confirm_includes_secrets", "FullKeystore"], "keep"),
    (22, "manifest signature (.tnpkg index signing)",        ["manifest_signature", "manifest_signature_b64", "sign_manifest"], "keep"),
]


@dataclass
class PhantomVerdict:
    id: int
    title: str
    tier: str  # rip / review / keep
    matches_total: int
    matches_in_source: int
    matches_in_tests: int
    matches_in_docs: int
    matches_per_term: dict[str, int] = field(default_factory=dict)
    sample_files: list[str] = field(default_factory=list)
    verdict: str = "unknown"  # "still-present" / "partial" / "absent"


def _iter_files(roots: tuple[Path, ...], skip_dirs: frozenset[str], suffixes: tuple[str, ...] = (".py", ".rs", ".ts")):
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            if not path.suffix in suffixes:
                continue
            if any(part in skip_dirs for part in path.parts):
                continue
            # Avoid self-scanning: the introspect package itself contains
            # the search terms (as PHANTOM_ITEMS literals) and would generate
            # false-positive matches.
            posix = path.as_posix()
            if "/tools/introspect/" in posix or posix.endswith("/tools/introspect"):
                continue
            yield path


def _grep_count(text: str, term: str) -> int:
    return len(re.findall(re.escape(term), text))


def build_phantom_regrounding(cfg: IntrospectConfig) -> dict:
    # Source = primary scan. Tests = cfg.test_roots. Docs = repo's docs/.
    source_files = list(_iter_files(cfg.source_roots, cfg.skip_dirs))
    test_files = list(_iter_files(cfg.test_roots, cfg.skip_dirs))
    rust_files = list(_iter_files(cfg.rust_roots, cfg.skip_dirs))
    docs_root = cfg.repo_root / "docs"
    doc_files = []
    if docs_root.exists():
        for path in docs_root.rglob("*"):
            if path.is_file() and path.suffix in (".md", ".rst", ".txt"):
                if "audit-baseline" in path.parts:
                    continue
                doc_files.append(path)

    verdicts: list[PhantomVerdict] = []
    for pid, title, terms, tier in PHANTOM_ITEMS:
        per_term: dict[str, int] = {}
        sample: list[str] = []
        ms = mt = md = 0

        def _scan(files: list[Path], bucket: str) -> int:
            nonlocal sample
            count = 0
            for path in files:
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                file_match = False
                for term in terms:
                    n = _grep_count(text, term)
                    if n > 0:
                        per_term[term] = per_term.get(term, 0) + n
                        count += n
                        file_match = True
                if file_match:
                    rel = path.relative_to(cfg.repo_root).as_posix()
                    if rel not in sample and len(sample) < 6:
                        sample.append(rel)
            return count

        ms = _scan(source_files, "source") + _scan(rust_files, "source")
        mt = _scan(test_files, "tests")
        md = _scan(doc_files, "docs")
        total = ms + mt + md

        if total == 0:
            verdict = "absent"
        elif ms == 0 and mt == 0:
            verdict = "docs-only"
        elif ms == 0 and mt > 0:
            verdict = "tests-only"
        elif ms > 0:
            verdict = "still-present"
        else:
            verdict = "partial"

        verdicts.append(
            PhantomVerdict(
                id=pid,
                title=title,
                tier=tier,
                matches_total=total,
                matches_in_source=ms,
                matches_in_tests=mt,
                matches_in_docs=md,
                matches_per_term=per_term,
                sample_files=sample,
                verdict=verdict,
            )
        )

    return {"items": [asdict(v) for v in verdicts]}


def write_phantom_regrounding(cfg: IntrospectConfig) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_phantom_regrounding(cfg)
    json_path = cfg.output_dir / "phantom_regrounding.json"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Also render markdown for human review.
    md_path = cfg.output_dir / "phantom_regrounding.md"
    lines = [
        "# Phantom features audit — re-grounding (Phase 0 baseline)",
        "",
        "Each row pairs an item from `docs/handoff/PHANTOM_FEATURES_AUDIT.md` with",
        "current AST/grep evidence: how many times each search term appears in",
        "source / tests / docs, the verdict, and the disposition recommended by",
        "the original audit.",
        "",
        "**Verdict legend**:",
        "- `still-present` — non-zero source matches; phantom item is live.",
        "- `tests-only` — source clean, only tests reference it (likely test fixture cleanup).",
        "- `docs-only` — only docs mention it.",
        "- `absent` — fully removed.",
        "",
        "**Tier legend**:",
        "- `rip` — original audit's ❌ recommendation (rip recommended).",
        "- `review` — original audit's 🟡 (decision needed).",
        "- `keep` — original audit's ✅ (approved spec-aligned).",
        "",
        "| ID | Title | Tier | Verdict | Source | Tests | Docs | Top sample |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for v in payload["items"]:
        sample = v["sample_files"][0] if v["sample_files"] else ""
        lines.append(
            f"| {v['id']} | {v['title']} | `{v['tier']}` | `{v['verdict']}` "
            f"| {v['matches_in_source']} | {v['matches_in_tests']} | {v['matches_in_docs']} "
            f"| `{sample}` |"
        )
    lines.append("")
    lines.append("## Per-item evidence")
    lines.append("")
    for v in payload["items"]:
        lines.append(f"### {v['id']}. {v['title']} (tier: `{v['tier']}`, verdict: `{v['verdict']}`)")
        lines.append("")
        if v["matches_per_term"]:
            lines.append("Term hit counts:")
            for term, count in sorted(v["matches_per_term"].items(), key=lambda kv: -kv[1]):
                lines.append(f"- `{term}` — {count}")
            lines.append("")
        if v["sample_files"]:
            lines.append("Sample files:")
            for s in v["sample_files"]:
                lines.append(f"- `{s}`")
            lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    write_manifest(cfg, extras={"producer": "phantom_regrounding"})
    return md_path
