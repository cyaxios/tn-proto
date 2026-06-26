"""Dynamic pillar - governance synthesis (the part the locator does not do).

Consumes sensitivity.py output and writes the derived TN governance spec:

  - kit.yaml   : groups + field routing (who can decrypt what)
  - agents.md  : usage policy per event type (the five required subsections)

This is the synthesis stage. The deterministic draft here is a starting point;
low-confidence fields are flagged for human review, and an agent is expected to
enrich the usage-policy prose. Mirrors the locator's separation of a mechanical
stage from a judgment stage.

Usage:
    python -m tn.mcp.exhaust.govern <sensitivity.json> <out_dir>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Group -> (policy, audience note). "public" rides at the envelope top level.
GROUP_META = {
    "pii": ("private", "direct PII; restrict to holders with a lawful need"),
    "geo_device": ("private", "quasi-identifiers / fingerprint (GDPR); fraud/security audience"),
    "identity": ("private", "person-linking ids; keep OUT of the analytics audience"),
    "analytics": ("private", "behavioral; readable WITHOUT identity keys, so usage stays aggregate"),
    "default": ("private", "unclassified; encrypted by default pending review"),
}

REVIEW_CONF = 0.6  # fields at or below this confidence get a review flag

# Sensitivity class -> private group. There is deliberately NO "public" target:
# TN's default_policy is private, so a field rides in the clear ONLY if it is on
# the small SAFE_PUBLIC allowlist below. Everything else encrypts - uncertain
# (id / enum / temporal / unknown) falls to the encrypted `default` group, not
# to the clear. Default to private; make public earn its place.
GOVERN_GROUP = {
    "pii_direct": "pii",
    "pii_quasi": "geo_device",
    "person_id": "identity",
    "behavioral": "analytics",
    "id": "default",
    "enum_attr": "default",
    "temporal": "default",
    "unknown": "default",
}

# The ONLY fields allowed to ride unencrypted at the envelope top level:
# operational, non-identifying keys. Anything not listed here defaults to
# private. Business ids, geo, device, status-of-a-person, etc. are NOT here.
SAFE_PUBLIC = {
    "event_type", "timestamp", "level", "sequence", "event_id",
    "code", "status", "http_status", "method", "duration_ms", "ms",
    "count", "page", "limit", "attempt", "version", "step", "done",
}


def _quote(name: str) -> str:
    # yaml-safe list item: quote names with hyphens or other punctuation
    return f'"{name}"' if not name.replace("_", "").isalnum() else name


def synthesize(report: dict) -> tuple[str, str, list[str]]:
    events = report["events"]
    event_types = sorted(events)

    # collect leaf names per group and review flags, across all events
    group_fields: dict[str, list[str]] = {}
    public_fields: list[str] = []
    review: list[str] = []
    seen: set[str] = set()
    for etype in event_types:
        for f in events[etype]["fields"]:
            leaf = f["leaf"]
            # Default-private: clear only if explicitly safe-public; else encrypt.
            # An explicit f["group"] (e.g. a registry/human override) wins over
            # class-based routing; "public" there still demotes to the clear.
            override_grp = f.get("group")
            if leaf in SAFE_PUBLIC or override_grp == "public":
                if leaf not in public_fields:
                    public_fields.append(leaf)
            else:
                grp = override_grp or GOVERN_GROUP.get(f["class"], "default")
                group_fields.setdefault(grp, [])
                if leaf not in group_fields[grp]:
                    group_fields[grp].append(leaf)
            key = f"{etype}:{f['path']}"
            if key not in seen and (f["confidence"] <= REVIEW_CONF or f["class"] == "unknown"):
                seen.add(key)
                review.append(f"{f['path']} ({f['class']} @ {f['confidence']}) in {etype}")

    # --- kit.yaml ---
    n = report["record_count"]
    lines = [
        "# Derived governance kit - MINED from runtime evidence, not hand-authored.",
        f"# Evidence: {n} records.  Stage: sensitivity.py -> govern.py.",
        "# Field routing is classifier-driven; group design + REVIEW flags are judgment.",
        "",
        "id: derived",
        "event_types:",
    ]
    for et in event_types:
        lines.append(f"  - {et}")
    lines.append("")
    lines.append("groups:")
    # Emit known groups in GROUP_META order, then ANY other group present
    # (e.g. a `clinical` override the registry pinned) - never silently drop one.
    ordered = [g for g in GROUP_META if g in group_fields]
    ordered += [g for g in group_fields if g not in GROUP_META]
    for grp in ordered:
        policy, note = GROUP_META.get(grp, ("private", "custom group (override / pinned)"))
        lines.append(f"  # {note}")
        lines.append(f"  {grp}:")
        lines.append(f"    policy: {policy}")
        lines.append("    pool_size: 8")
        lines.append("    cipher: btn")
        lines.append(f"    fields: [{', '.join(_quote(x) for x in group_fields[grp])}]")
    lines.append("")
    lines.append("# default_policy: private - unrouted fields encrypt into `default`.")
    lines.append("default_policy: private")
    lines.append("")
    lines.append("# Only these operational, non-identifying fields ride in the clear.")
    lines.append("# TN defaults to private; everything else above is encrypted.")
    lines.append("public_fields:")
    for x in public_fields:
        lines.append(f"  - {_quote(x)}")
    if review:
        lines.append("")
        lines.append("# REVIEW - low-confidence or unclassified fields; confirm routing by hand:")
        for r in review:
            lines.append(f"#   - {r}")
    kit_yaml = "\n".join(lines) + "\n"

    # --- agents.md ---
    has_identity = "identity" in group_fields
    has_behavior = "analytics" in group_fields
    reident = has_identity and has_behavior
    ag = [
        "---",
        "version: 1",
        "schema: tn-agents-policy@v1",
        f"source: derived by the dynamic pillar from {n} records",
        "status: inferred - human review recommended",
        "---",
        "",
        "# TN Agents Policy",
    ]
    for et in event_types:
        ag += [
            "",
            f"## {et}",
            "",
            "### instruction",
            f"This row records a `{et}` event. Treat it as a fact-record of "
            "something that already happened; never replay it or read it as consent.",
            "",
            "### use_for",
            "Aggregate analytics and reporting over the public and behavioral "
            "fields. Operate in aggregate.",
            "",
            "### do_not_use_for",
            (
                "Re-identifying individuals by joining behavioral fields to the "
                "`identity` group; per-person profiling without a lawful basis; "
                "sharing the `geo_device` fingerprint outside fraud/security."
                if reident else
                "Any purpose beyond the stated use without review; sharing "
                "restricted-group fields outside their intended audience."
            ),
            "",
            "### consequences",
            (
                "The identity and geo_device groups decrypt only for their key "
                "holders; joining either to behavior is a re-identification event "
                "with privacy exposure. The segmentation is the control."
                if reident else
                "Restricted-group fields decrypt only for their key holders; the "
                "segmentation is what keeps the audiences separate."
            ),
            "",
            "### on_violation_or_error",
            "If you find restricted-group fields decrypted in a context that is "
            "not their intended audience, stop and surface to a human; do not "
            "produce a per-person report.",
        ]
    agents_md = "\n".join(ag) + "\n"
    return kit_yaml, agents_md, review


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print(__doc__)
        return 1
    in_path, out_dir = Path(args[0]), Path(args[1])
    if not in_path.exists():
        print(f"govern: not found: {in_path}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    report = json.loads(in_path.read_text(encoding="utf-8"))
    kit_yaml, agents_md, review = synthesize(report)
    (out_dir / "kit.yaml").write_text(kit_yaml, encoding="utf-8")
    (out_dir / "agents.md").write_text(agents_md, encoding="utf-8")
    print(f"wrote {out_dir / 'kit.yaml'} and {out_dir / 'agents.md'}", file=sys.stderr)
    if review:
        print(f"  {len(review)} field(s) flagged for human review", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
