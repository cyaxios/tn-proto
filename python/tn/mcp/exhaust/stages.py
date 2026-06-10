"""Stage functions for the Know-Your-Exhaust MCP.

One function per stage of the defensible process (see
design/know-your-exhaust.md):

    categorize  -> inventory_exhaust   (enumerate; the coverage denominator)
    lens        -> pick_kits           (match categories to industry kits)
    isolate     -> classify_fields     (per-field sensitivity, in isolation)
    contextualize -> linkage_graph     (cross-row re-identification risk)
    hook        -> emit_hook           (default-private TN config)
    (helper)    -> decrypt_stream      (read a TN-encrypted stream with keys)

These are plain library functions with JSON-friendly I/O so they can be called
directly (tests, a notebook) or wrapped by server.py as MCP tools. The proven
logic in ../locator (sensitivity.py, govern.py) is reused, not reimplemented;
the three new stages (inventory categories, pick_kits, linkage_graph) are built
here and meant to be iterated.
"""
from __future__ import annotations

import json
import os
import re as _re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Optional third-party: drain3 powers template mining. Its absence must not
# break import of this module; the mining entry points return a clear error
# dict instead (containment - never a raw traceback into the host).
try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    _HAVE_DRAIN3 = True
except ImportError:
    TemplateMiner = None  # type: ignore[assignment]
    TemplateMinerConfig = None  # type: ignore[assignment]
    _HAVE_DRAIN3 = False

from ... import init as _tn_init
from ... import read as _tn_read

# Self-contained: sensitivity.py / govern.py / registry.py are siblings in
# this package (originally proven in _lab/locator).
from . import govern as _gov  # synthesize
from . import registry as _reg  # durable classification/group catalog
from . import sensitivity as _sens  # classify_field, _flatten, load_ndjson, CLASS_TO_GROUP

_DRAIN3_MISSING = (
    "drain3 is not installed in this environment, so template mining is "
    "unavailable. Install the 'drain3' package (pip install drain3) and retry."
)

# The machine-readable kit catalog, vendored from tn-skills kits/index.json
# so pick_kits matches out of the box in an installed package. The agent
# loads kit BODIES itself (bundled kits/ dir, GitHub raw, or the web
# mirror). TN_KITS_INDEX points at an alternate catalog, e.g. a tn-skills
# checkout's kits/index.json.
_KITS_INDEX = Path(
    os.environ.get("TN_KITS_INDEX") or Path(__file__).with_name("kits_index.json")
)

# Category (event-name prefix / keyword) -> kit id. The off-scope guard lives in
# pick_kits: a category with no confident match gets no kit rather than a forced one.
_CATEGORY_KITS = {
    "auth": "oauth-oidc", "login": "oauth-oidc", "token": "oauth-oidc", "oauth": "oauth-oidc",
    "session": "oauth-oidc",
    "payment": "pci-cardholder", "card": "pci-cardholder", "charge": "pci-cardholder",
    "pci": "pci-cardholder",
    "order": "ecommerce-orders", "cart": "ecommerce-orders", "checkout": "ecommerce-orders",
    "shop": "ecommerce-orders", "saleor": "ecommerce-orders",
    "th": "fhir-clinical", "intake": "fhir-clinical", "patient": "fhir-clinical",
    "clinical": "fhir-clinical", "health": "fhir-clinical", "age_gate": "fhir-clinical",
    "crm": "crm-objects", "contact": "crm-objects", "lead": "crm-objects",
    "cloud": "cloud-audit", "audit": "cloud-audit",
    "email": "email-rfc5322", "mail": "email-rfc5322",
    "fix": "fix-trading", "trade": "fix-trading", "order_fix": "fix-trading",
    "iot": "iot-geolocation", "device": "iot-geolocation", "geo": "iot-geolocation",
    "page": "iot-geolocation",  # page_viewed carries geo/device-ish telemetry
}


# --- helpers ----------------------------------------------------------------

def _decision(stage: str, did: str, finding: str, question: str,
              options: list[str], recommended: str) -> dict:
    """A checkpoint the agent should surface to the user before proceeding.

    The tools never resolve these - they flag where judgment is needed. The
    agent asks the user (with the recommendation), then persists the answer
    (set_field_group, or a re-run param), so it is asked once and remembered.
    """
    return {"stage": stage, "id": did, "finding": finding, "question": question,
            "options": options, "recommended": recommended}


def _records_from_source(source: str | list[dict]) -> list[dict]:
    """Accept a path to ndjson, or an in-memory list of dicts."""
    if isinstance(source, list):
        return [r for r in source if isinstance(r, dict)]
    p = Path(source)
    if p.exists():
        return _sens.load_ndjson(p)
    # treat a raw blob as ndjson text
    out: list[dict] = []
    for line in str(source).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            if isinstance(o, dict):
                out.append(o)
        except json.JSONDecodeError:
            continue
    return out


def _records_any(source: str | list[dict], granularity: int = 2) -> list[dict]:
    """Records from ANY input - JSON lines OR plain text (parsed per line).
    Plain-text rows carry the recovered fields plus the mined event_type.
    granularity must match the value used in inventory so event types align."""
    if isinstance(source, list):
        return _records_from_source(source)
    p = Path(source)
    raw = p.read_text(encoding="utf-8", errors="replace") if p.exists() else str(source)
    lines = raw.splitlines()
    if _looks_like_json_lines(lines):
        return _records_from_source(source)
    delimiter = _sniff(lines).get("delimiter")
    rows: list[dict] = []
    for ln in lines:
        if not ln.strip():
            continue
        et, fields = parse_text_line(ln, granularity, delimiter)
        rows.append({**fields, "event_type": et})
    return rows


# --- categorize -------------------------------------------------------------
# Plain-text parsing: recover structure from unstructured log lines so the
# rest of the pipeline (value classification, linkage) works on text too. The
# slots are unnamed, so value detectors do the work, not field-name hints.

_LEVEL_RE = _re.compile(r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|TRACE|NOTICE)\b")
_TS_RE = _re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
# syslog/RFC3164 line prefix: "Mon DD HH:MM:SS host proc[pid]: " - the event
# content is the MESSAGE after the colon, so strip the prefix before typing.
_SYSLOG_RE = _re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*")
_KV_RE = _re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')
# inline typed values to lift out of free text and name by their type
_INLINE = [
    ("email", _re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("uuid", _re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("jwt", _re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("ip", _re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
]

# Custom-prefix / long-hex identifiers embedded in free text: blk_-1608..,
# req-7f3a, sess_ab12cd, or a bare long hex/alnum token. Captured as a field
# named by its prefix (blk -> blk_ref) so recurring ids surface for linkage.
_ID_TOKEN = _re.compile(
    r"\b([A-Za-z][A-Za-z0-9]{1,15})[-_]([A-Za-z0-9]{5,})\b"   # prefix_sep_value
    r"|\b(blk)_(-?\d{4,})\b")                                  # HDFS blk_<digits>


def _sniff(lines: list[str], sample: int = 200) -> dict:
    """Profile a text log over a sample: detect a column delimiter and shape so
    the parser can split fields instead of guessing. Returns a parse plan."""
    rows = [ln for ln in lines if ln.strip()][:sample]
    if not rows:
        return {"format": "empty", "delimiter": None}
    if _looks_like_json_lines(rows):
        return {"format": "json", "delimiter": None}
    if sum(bool(_SYSLOG_RE.match(r)) for r in rows) >= 0.6 * len(rows):
        return {"format": "syslog", "delimiter": None}
    # delimiter sniff: a char that appears a CONSISTENT, non-zero count per line
    for d, name in (("|", "pipe"), ("\t", "tab"), (";", "semicolon")):
        counts = [r.count(d) for r in rows]
        present = [c for c in counts if c > 0]
        if len(present) >= 0.8 * len(rows):
            top = max(set(counts), key=counts.count)
            if top > 0 and counts.count(top) >= 0.8 * len(rows):
                return {"format": f"delimited:{name}", "delimiter": d,
                        "columns": top + 1}
    kv_hits = sum(bool(_KV_RE.search(r)) for r in rows)
    if kv_hits >= 0.6 * len(rows):
        return {"format": "logfmt/kv", "delimiter": None}
    return {"format": "freetext", "delimiter": None}


def profile(source: str | list[dict], sample: int = 200) -> dict:
    """Initial pass: sniff the exhaust format/delimiter from a sample so parsing
    is informed, not guessed. Surface the result as a checkpoint - the detected
    shape is a judgment the user can correct."""
    lines = _source_lines(source)
    plan = _sniff(lines, sample)
    example = next((ln for ln in lines if ln.strip()), "")
    decisions = [_decision(
        "profile", "format",
        f"Sniffed format: {plan['format']}"
        + (f" (delimiter {plan['delimiter']!r}, ~{plan.get('columns','?')} columns)"
           if plan.get("delimiter") else "")
        + f". Example: {example[:80]!r}",
        "Is the detected format/delimiter right?",
        ["yes, parse with it", "no, it's a different delimiter", "treat as free text"],
        "yes, parse with it")]
    return {**plan, "example": example[:120], "decisions": decisions}


def _strip_prefix(line: str) -> str:
    """Drop a syslog/ISO timestamp + host/proc prefix so a clusterer sees the
    message, not the date. Returns the message portion."""
    work = line.rstrip("\n")
    sm = _SYSLOG_RE.match(work)
    if sm:
        return work[sm.end():]
    return _TS_RE.sub("", work).strip()


def _slug_from_template(tmpl: str, cluster_id: int) -> str:
    words = [w for w in _re.findall(r"[A-Za-z]+", tmpl)
             if w.lower() not in {"for", "from", "the", "a", "an", "of", "to", "ok"}]
    return ".".join(words[:2]).lower() if words else f"t{cluster_id}"


def _source_lines(source: str | list[dict]) -> list[str]:
    if isinstance(source, list):
        return [json.dumps(r) for r in source]
    p = Path(source)
    raw = p.read_text(encoding="utf-8", errors="replace") if p.exists() else str(source)
    return raw.splitlines()


def _drain_pass(lines: list[str], sim_th: float, depth: int):
    """Run Drain3 over the lines. Returns (per_line_cluster_ids, clusters) where
    clusters[id] = {template, count, slug}. Deterministic for a given config."""
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = sim_th
    cfg.drain_depth = depth
    cfg.profiling_enabled = False
    tm = TemplateMiner(config=cfg)
    per_line: list[int | None] = []
    for ln in lines:
        msg = _strip_prefix(ln)
        if msg.strip():
            r = tm.add_log_message(msg)
            per_line.append(r["cluster_id"])
        else:
            per_line.append(None)
    clusters: dict[int, dict] = {}
    for cl in tm.drain.clusters:
        tmpl = cl.get_template()
        clusters[cl.cluster_id] = {"template": tmpl, "count": cl.size,
                                   "slug": _slug_from_template(tmpl, cl.cluster_id)}
    return per_line, clusters


def mine_templates(source: str | list[dict], sim_th: float = 0.4,
                   depth: int = 4) -> dict:
    """Drain3 template mining: collapse many raw lines into a SMALL set of
    distinct templates. This is the deterministic floor that makes agent
    clustering tractable - the agent groups these tens of templates into
    families, never the thousands of raw lines.

    `sim_th` is the consolidate knob: LOWER merges more aggressively (fewer
    templates), HIGHER keeps them distinct (more templates).
    """
    if not _HAVE_DRAIN3:
        return {"error": _DRAIN3_MISSING, "templates": []}
    lines = _source_lines(source)
    _, clusters = _drain_pass(lines, sim_th, depth)
    templates = [{"id": cid, "template": c["template"], "count": c["count"],
                  "slug": c["slug"]}
                 for cid, c in sorted(clusters.items(), key=lambda kv: -kv[1]["count"])]
    return {"line_count": sum(c["count"] for c in clusters.values()),
            "template_count": len(templates), "sim_th": sim_th,
            "templates": templates,
            "note": "Cluster these template ids into families (you, the agent), "
                    "then pass {id: family} to inventory_exhaust(families=...) and "
                    "linkage_graph(families=...) so the pipeline keys on families. "
                    "Lower sim_th merges more; raise it to split."}


def _records_drain(source: str | list[dict], families: dict | None,
                   sim_th: float, depth: int) -> list[dict]:
    """Per-line records typed by Drain cluster -> family. event_type is the
    family name from `families` (keyed by cluster id), or the cluster slug if
    unmapped. Fields come from the same kv + inline-value extraction as the
    word path, so naming/sensitivity are unchanged - only the typing differs."""
    fam = {str(k): v for k, v in (families or {}).items()}
    lines = _source_lines(source)
    delimiter = _sniff(lines).get("delimiter")
    per_line, clusters = _drain_pass(lines, sim_th, depth)
    rows: list[dict] = []
    for ln, cid in zip(lines, per_line, strict=False):
        if cid is None:
            continue
        slug = clusters[cid]["slug"]
        etype = fam.get(str(cid)) or fam.get(slug) or slug
        _, fields = parse_text_line(ln, delimiter=delimiter)  # field extraction; ignore its typing
        fields["event_type"] = etype
        fields["__raw__"] = ln.strip()
        rows.append(fields)
    return rows


def _looks_like_json_lines(lines: list[str]) -> bool:
    checked = [ln for ln in lines if ln.strip()][:20]
    if not checked:
        return False
    hits = 0
    for ln in checked:
        s = ln.strip()
        if s.startswith("{"):
            try:
                json.loads(s)
                hits += 1
            except json.JSONDecodeError:
                pass
    return hits >= max(1, len(checked) // 2)


def _name_column(val: str, idx: int, used: set[str]) -> str:
    v = val.strip()
    if idx == 0 and _re.search(r"\d{2,}[-:]\d", v):
        base = "timestamp"
    elif v.isdigit():
        base = "id"
    elif _re.match(r"^[A-Za-z][\w.$-]*$", v):
        base = "component"
    else:
        base = f"col{idx}"
    name, k = base, 2
    while name in used:
        name, k = f"{base}{k}", k + 1
    used.add(name)
    return name


def parse_text_line(line: str, granularity: int = 2,
                    delimiter: str | None = None) -> tuple[str, dict]:
    """Parse one unstructured log line into (event_type, fields).

    If `delimiter` is given (from profile()), the line is split into columns -
    the last column is the message, earlier columns become named fields
    (timestamp / id / component). Otherwise the whole line is treated as a
    free-text message. The message is then mined for level, key=value pairs,
    inline typed values (email/ip/uuid/jwt), and custom id-tokens (blk_.., req-..);
    the event type is the leading words of what remains.

    `granularity` = how many leading words form the event type (the consolidate
    knob).
    """
    fields: dict[str, str] = {}
    raw = line.rstrip("\n")

    if delimiter and delimiter in raw:
        parts = raw.split(delimiter)
        used: set[str] = set()
        for i, col in enumerate(parts[:-1]):
            fields[_name_column(col, i, used)] = col.strip()
        work = parts[-1]
    else:
        work = raw
        sm = _SYSLOG_RE.match(work)      # strip syslog prefix when present
        if sm:
            fields["proc"] = sm.group(1)
            work = work[sm.end():]
        work = _TS_RE.sub(" ", work)

    m = _LEVEL_RE.search(work)
    if m:
        fields["level"] = m.group(1)
        work = work[:m.start()] + " " + work[m.end():]

    for km in _KV_RE.finditer(work):     # key=value pairs (logfmt-style)
        fields[km.group(1)] = km.group(2).strip("\"'")
    work = _KV_RE.sub(" ", work)

    for name, rx in _INLINE:             # inline typed values -> named by type
        def _take(mm, _n=name):
            fields.setdefault(_n, mm.group(0))
            return f" <{_n}> "
        work = rx.sub(_take, work)

    def _take_id(mm):                    # custom id-tokens -> named by prefix
        prefix = mm.group(1) or mm.group(3)
        fields.setdefault(f"{prefix.lower()}_ref", mm.group(0))
        return " <id> "
    work = _ID_TOKEN.sub(_take_id, work)

    words = [w for w in _re.findall(r"[A-Za-z]+", work)
             if w.lower() not in {"for", "from", "the", "a", "an", "of", "to", "ok"}]
    n = max(1, granularity)
    etype = ".".join(words[:n]).lower() if words else "log.line"
    return etype, fields


def _events_from_text(lines: list[str], granularity: int = 2,
                      delimiter: str | None = None) -> dict[str, list[dict]]:
    by_event: dict[str, list[dict]] = defaultdict(list)
    for ln in lines:
        if not ln.strip():
            continue
        etype, fields = parse_text_line(ln, granularity, delimiter)
        fields["event_type"] = etype
        fields["__raw__"] = ln.strip()           # the original line, for context
        by_event[etype].append(fields)
    return by_event


def _events_struct(by_event: dict[str, list[dict]]) -> dict:
    events: dict[str, dict] = {}
    categories: dict[str, int] = defaultdict(int)
    for etype, recs in by_event.items():
        samples: dict[str, list[str]] = defaultdict(list)
        counts: dict[str, int] = defaultdict(int)
        distinct: dict[str, set] = defaultdict(set)
        missing: dict[str, int] = defaultdict(int)
        context: dict[str, str] = {}             # leaf-path -> a full example log line/record
        for r in recs:
            raw = r.get("__raw__")
            clean = {k: v for k, v in r.items() if k != "__raw__"}
            if raw is None:                      # JSON path: render the record as context,
                # leading with event_type + meaningful fields, dropping envelope noise.
                _noise = {"level", "sequence", "timestamp", "prev_hash", "row_hash",
                          "signature", "event_id", "device_identity", "client_ts"}
                compact = {k: v for k, v in clean.items() if k not in _noise}
                raw = json.dumps(compact, default=str)
            for path, val in _sens._flatten(clean).items():
                counts[path] += 1
                sval = "" if val is None else str(val)
                if sval.strip().lower() in _sens.MISSING:
                    missing[path] += 1
                else:
                    distinct[path].add(sval)
                    if len(samples[path]) < 5 and sval not in samples[path]:
                        samples[path].append(sval[:80])
                    if path not in context:
                        context[path] = str(raw)[:160]
        fields = [{
            "path": p, "leaf": p.split(".")[-1],
            "distinct": len(distinct[p]),
            "null_rate": round(missing[p] / counts[p], 2) if counts[p] else 0.0,
            "samples": samples[p],
            "example_context": context.get(p, ""),
        } for p in sorted(counts)]
        events[etype] = {"count": len(recs), "fields": fields}
        categories[etype.split(".")[0]] += 1
    return {"event_type_count": len(events), "categories": sorted(categories),
            "events": events}


def inventory_exhaust(source: str | list[dict], event_key: str = "event_type",
                      granularity: int = 2, families: dict | None = None,
                      sim_th: float = 0.4, depth: int = 4) -> dict:
    """Enumerate event types and their fields from ANY exhaust input.

    Accepts JSON-lines (named fields) OR unstructured plain-text logs (structure
    recovered by template mining + value detection). The coverage denominator:
    every event type and field, with value samples, so later stages can claim
    they looked at everything.

    Event-typing for plain text, in increasing power:
      - `granularity` (default): leading-word typing. Lower = coarser.
      - `families`: a {cluster_id: family_name} map from your clustering of
        mine_templates output. When provided, lines are typed by Drain cluster
        -> family, so the pipeline keys on YOUR families. Unmapped clusters fall
        back to their template slug. Pass the same families to linkage_graph.
    """
    # In-memory list of dicts -> json path.
    if isinstance(source, list):
        records = _records_from_source(source)
        by_event = defaultdict(list)
        for r in records:
            by_event[str(r.get(event_key, "_unknown"))].append(r)
        struct = _events_struct(by_event)
        fmt, n = "json", len(records)
    else:
        p = Path(source)
        raw = p.read_text(encoding="utf-8", errors="replace") if p.exists() else str(source)
        lines = raw.splitlines()
        if _looks_like_json_lines(lines):
            records = _records_from_source(source)
            by_event = defaultdict(list)
            for r in records:
                by_event[str(r.get(event_key, "_unknown"))].append(r)
            struct = _events_struct(by_event)
            fmt, n = "json", len(records)
        elif families is not None:
            if not _HAVE_DRAIN3:
                return {"error": _DRAIN3_MISSING}
            rows = _records_drain(source, families, sim_th, depth)
            by_event = defaultdict(list)
            for r in rows:
                by_event[r["event_type"]].append(r)
            struct = _events_struct(by_event)
            fmt = "plain-text (families)"
            n = len(rows)
        else:
            plan = _sniff(lines)
            by_event = _events_from_text(lines, granularity, plan.get("delimiter"))
            struct = _events_struct(by_event)
            fmt = f"plain-text ({plan['format']})"
            n = sum(len(v) for v in by_event.values())

    out = {"record_count": n, "event_key": event_key, "format": fmt, **struct}

    decisions = []
    etc = out["event_type_count"]
    if fmt == "plain-text" and (etc > 25 or (n and etc / n > 0.15)):
        decisions.append(_decision(
            "categorize", "fragmentation",
            f"Mined {etc} event types from {n} lines - that looks over-"
            "fragmented. The leading-word typer bottoms out on varied logs.",
            "How to consolidate?",
            ["mine_templates + cluster into families (best)",
             "lower granularity", "keep as-is"],
            "mine_templates + cluster into families (best)"))
    out["decisions"] = decisions
    return out


# --- lens -------------------------------------------------------------------

def pick_kits(categories: list[str]) -> dict:
    """Match categories to bundled industry kits (the defensible vocabulary).

    Off-scope guard: a category with no confident keyword match gets no kit.
    """
    index = json.loads(_KITS_INDEX.read_text(encoding="utf-8")) if _KITS_INDEX.exists() else []
    known = {k["id"]: k for k in index}
    matches: dict[str, dict] = {}
    unmatched: list[str] = []
    for cat in categories:
        cat_l = str(cat).lower()
        kit_id = None
        for kw, kid in _CATEGORY_KITS.items():
            if kw in cat_l:
                kit_id = kid
                break
        if kit_id and kit_id in known:
            matches.setdefault(kit_id, {"kit": known[kit_id], "for_categories": []})
            matches[kit_id]["for_categories"].append(cat)
        else:
            unmatched.append(cat)
    decisions = []
    if unmatched:
        decisions.append(_decision(
            "lens", "off-scope",
            f"These categories matched no industry kit: {unmatched}.",
            "How should the unmatched categories be treated?",
            ["leave unmapped (classify from project conventions)",
             "suggest a kit for them", "they are not exhaust I care about"],
            "leave unmapped (classify from project conventions)"))
    return {
        "matched_kits": list(matches.values()),
        "unmatched_categories": unmatched,   # off-scope: no kit forced on these
        "decisions": decisions,
        "note": "Load each matched kit's .md + .yaml as the classification "
                "vocabulary before judging its categories' fields.",
    }


# --- isolate ----------------------------------------------------------------

def classify_fields(inventory: dict) -> dict:
    """Per-field sensitivity in isolation. Consumes inventory_exhaust output,
    returns the sensitivity-report shape emit_hook expects."""
    cache = _sens.load_cache()
    events_out: dict[str, dict] = {}
    for etype, ev in inventory["events"].items():
        fields = []
        for f in ev["fields"]:
            cls, conf, dets = _sens.classify_field(f["leaf"], f.get("samples", []), cache)
            group, label = _sens.CLASS_TO_GROUP[cls]
            fields.append({**f, "class": cls, "class_label": label,
                           "confidence": conf, "detectors": dets,
                           "recommended_group": group})
        events_out[etype] = {"count": ev["count"], "fields": fields}
    _sens.save_cache(cache)

    # Decision points: borderline fields the agent should ask about. A field is
    # borderline if it is low-confidence or unclassified AND looks like it could
    # carry a person attribute (not obviously operational). One decision per
    # distinct field leaf, deduped across events.
    decisions, seen = [], set()
    for _etype, ev in events_out.items():
        for f in ev["fields"]:
            leaf = f["leaf"]
            if leaf in seen or leaf in _gov.SAFE_PUBLIC:
                continue
            if f["confidence"] <= 0.6 or f["class"] == "unknown":
                seen.add(leaf)
                sample = (f["samples"][0] if f["samples"] else "")[:32]
                decisions.append(_decision(
                    "isolate", f"field:{leaf}",
                    f"`{leaf}` classified {f['class']} @ {f['confidence']} "
                    f"(e.g. {sample!r}) - low confidence.",
                    f"What is `{leaf}` and where should it route?",
                    ["private group (pii / identity / clinical / geo_device)",
                     "encrypted default", "safe to ride public"],
                    "encrypted default"))
    return {"version": "0.1", "event_key": inventory.get("event_key", "event_type"),
            "record_count": inventory["record_count"], "events": events_out,
            "decisions": decisions}


# --- contextualize ----------------------------------------------------------

# Protocol / operational fields that recur on every row by construction. They
# bridge event types trivially but do not identify a person, so they are not
# join keys. (Mirrors govern.SAFE_PUBLIC plus a few low-cardinality operationals.)
_LINKAGE_DENYLIST = {
    "event_type", "level", "sequence", "timestamp", "event_id", "code",
    "status", "http_status", "method", "duration_ms", "ms", "count", "page",
    "limit", "attempt", "version", "step", "done", "role", "provider",
    "operation", "collection", "next", "client_ts", "proc", "pid", "host",
    "logname", "tty", "uid", "euid",
}


def linkage_graph(source: str | list[dict], event_key: str = "event_type",
                  min_span: int = 2, ratio_floor: float = 0.0,
                  granularity: int = 2, families: dict | None = None,
                  sim_th: float = 0.4, depth: int = 4) -> dict:
    """Cross-row re-identification risk (per-entity grouping).

    A field benign in isolation can reassemble a person in context. The signal
    is NOT how many distinct values recur - it is how many event types a SINGLE
    value threads. Group rows by each field's value (the "entity") and look at
    how many distinct event types each value spans:

      - join key  : a value threads MANY event types with FEW rows each (one per
                    step of a session). e.g. one `correlation` value appearing
                    once each in session.started / age_gate / question / answer
                    threads 4 event types = reassembles one person's visit. ONE
                    such value is enough to flag the field.
      - enum/attr : a value appears in many rows (often the same event type); low
                    uniqueness. Excluded by the protocol denylist + a uniqueness
                    floor.

    Works on JSON or plain-text exhaust. Pass the same `families` you gave
    inventory_exhaust so the event types match (else linkage spans the raw
    template slugs instead of your families).
    """
    if families is not None and not isinstance(source, list) \
            and not _looks_like_json_lines(_source_lines(source)):
        if not _HAVE_DRAIN3:
            return {"error": _DRAIN3_MISSING}
        records = _records_drain(source, families, sim_th, depth)
    else:
        records = _records_any(source, granularity)
    field_value_events: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    field_value_rows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    field_events: dict[str, set] = defaultdict(set)
    for r in records:
        et = str(r.get(event_key, "_unknown"))
        for path, val in _sens._flatten(r).items():
            leaf = path.split(".")[-1]
            if leaf in _LINKAGE_DENYLIST:
                continue
            sval = "" if val is None else str(val)
            if sval.strip().lower() in _sens.MISSING:
                continue
            field_events[leaf].add(et)
            field_value_events[leaf][sval].add(et)
            field_value_rows[leaf][sval] += 1

    links = []
    for leaf, vals in field_value_events.items():
        # values that thread >= min_span event types (each reassembles an entity)
        bridging = {v: sorted(ets) for v, ets in vals.items() if len(ets) >= min_span}
        if not bridging:
            continue
        n_distinct = len(vals)
        appears = sum(field_value_rows[leaf].values())
        ratio = round(n_distinct / appears, 2) if appears else 0.0   # informational
        # Enum protection is the denylist + min_span; the uniqueness ratio is
        # reported (not gated by default) because a busy single session is
        # low-ratio yet a real key - e.g. one `correlation` value on 13 rows.
        if ratio_floor and ratio < ratio_floor:
            continue
        max_span = max(len(ets) for ets in vals.values())
        avg_rows = round(sum(field_value_rows[leaf][v] for v in bridging) / len(bridging), 1)
        links.append({
            "field": leaf,
            "spans_event_types": sorted(field_events[leaf]),
            "max_threaded_event_types": max_span,
            "distinct_values": n_distinct,
            "bridging_value_count": len(bridging),
            "avg_rows_per_bridging_value": avg_rows,
            "uniqueness_ratio": ratio,
            "example_bridges": {v: ets for v, ets in list(bridging.items())[:3]},
            "risk": "join key - threads one entity's activity across events; "
                    "treat as person-linking even if the value looks opaque",
        })
    # rank by re-identification reach: how many event types a single value threads
    links.sort(key=lambda x: (-x["max_threaded_event_types"], -x["uniqueness_ratio"]))
    return {"record_count": len(records), "linkage_candidates": links,
            "note": "Fields here re-identify across rows; route to identity/"
                    "clinical, not analytics, whatever their in-isolation class. "
                    "max_threaded_event_types is the re-identification reach of a "
                    "single value."}


# --- hook -------------------------------------------------------------------

def emit_hook(classified: dict, use_registry: bool = False,
              out_dir: str = "") -> dict:
    """Default-private TN config from a classification report.

    With use_registry=True, each field's group is overlaid from the durable
    registry first - so persisted human overrides and linkage escalations take
    effect in the emitted config, not just this run's fresh classification.

    With out_dir set, the derived kit is written to `<out_dir>/kye-kit.yaml`
    (+ kye-agents.md). Put that under the project's `.tn/` so the static tools
    (tn-lint, tn-annotate) discover and ADDITIVELY include it - it complements
    `tn.yaml` + `extends:` packs, it does not replace them (project config wins
    on conflicts). Not either/or.
    """
    report = classified
    overlaid = 0
    if use_registry:
        report = json.loads(json.dumps(classified))  # don't mutate caller's dict
        for ev in report["events"].values():
            for f in ev["fields"]:
                g = _reg.field_group(f["leaf"])
                if g:
                    f["group"] = g
                    overlaid += 1
    kit_yaml, agents_md, review = _gov.synthesize(report)
    written = None
    if out_dir:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "kye-kit.yaml").write_text(kit_yaml, encoding="utf-8")
        (d / "kye-agents.md").write_text(agents_md, encoding="utf-8")
        written = str(d / "kye-kit.yaml")
    return {"kit_yaml": kit_yaml, "agents_md": agents_md,
            "review_flags": review, "review_count": len(review),
            "registry_overlaid_fields": overlaid, "written_to": written,
            "note": "Default-private: only an operational allowlist rides clear; "
                    "everything else (including unclassified) is encrypted."
                    + (" Registry overrides applied." if use_registry else "")
                    + (" Wrote derived kit; static tools include it additively."
                       if written else "")}


# --- registry: the durable group catalog ------------------------------------

def remember_classification(classified: dict) -> dict:
    """Persist a classification report into the registry (source=detector).
    Accumulates across runs; respects existing human/linkage overrides."""
    n = 0
    for etype, ev in classified["events"].items():
        for f in ev["fields"]:
            _reg.observe(f["leaf"], f["class"], f.get("confidence", 0.0),
                         f["recommended_group"], source="detector",
                         event_types=[etype])
            n += 1
    return {"recorded": n, "groups": _reg.groups()}


def set_field_group(leaf: str, group: str, note: str = "") -> dict:
    """Pin a field to a group - a durable human override that survives re-runs
    and wins over future detector passes."""
    _reg.override(leaf, group, note=note, source="human")
    return {"leaf": leaf, "group": group, "overridden": True, "groups": _reg.groups()}


# Groups that are already appropriately restricted - linkage should not relabel
# a field out of one of these (a direct-PII `ip` stays in `pii`, not `identity`).
_ALREADY_RESTRICTED = {"pii", "geo_device", "identity", "clinical"}


def apply_linkage(linkage: dict) -> dict:
    """Escalate cross-row join keys from a linkage_graph result to a person-
    linking group. Linkage only UPGRADES toward privacy: a field already in a
    restricted group keeps its (better) isolation label; only non-sensitive
    fields (analytics/default/public) get pulled into identity."""
    escalated, kept = [], []
    for cand in linkage.get("linkage_candidates", []):
        leaf = cand["field"]
        cur = _reg.field_group(leaf)
        if cur in _ALREADY_RESTRICTED:
            kept.append({"field": leaf, "group": cur})  # already restricted; leave it
        else:
            _reg.mark_linkage(leaf, note=cand.get("risk", ""))
            escalated.append(leaf)
    return {"escalated": escalated, "kept_already_restricted": kept,
            "groups": _reg.groups()}


def groups_registry() -> dict:
    """Inspect the durable catalog: current group->fields map + full snapshot."""
    return {"groups": _reg.groups(), "fields": _reg.snapshot()}


def unwind() -> dict:
    """Undo the most recent override / linkage escalation - the 'unwind' move in
    the checkpoint loop. Restores the field to its prior group (or removes it if
    it was new)."""
    result = _reg.unwind()
    return {**result, "groups": _reg.groups()}


_SENSITIVE_GROUPS = {"pii", "identity", "clinical", "geo_device"}


def _protection_line(state: str) -> str:
    if state == "on_tn":
        return ("**Protection status: routed through TN.** The proposed routing "
                "refines an already-encrypted stream; applying it updates "
                "`tn.yaml` and mints group keys (no code change).")
    if state == "plaintext":
        return ("**Protection status: NOT protected yet.** This app does not emit "
                "through TN, so the sensitive fields below are in PLAINTEXT today. "
                "The routing here is a TARGET - applying the hook and routing the "
                "app through TN (via tn-annotate or a logging handler) is what "
                "protects them.")
    return ("**Protection status: unknown.** Whether these fields are encrypted "
            "today depends on whether the app already emits through TN. The "
            "routing below is the proposed target either way.")


def registry_status() -> dict:
    """What is already in the durable catalog. Call at the START of a session so
    you know whether you are continuing prior work or should clear it - a
    registry left over from a DIFFERENT app carries stale decisions."""
    snap = _reg.snapshot()
    by_source: dict[str, int] = defaultdict(int)
    for f in snap:
        by_source[(f["source"] or "detector").split(":")[0]] += 1
    sensitive = [f["leaf"] for f in snap if f["group_name"] in _SENSITIVE_GROUPS]
    last = max((f["last_seen"] for f in snap), default=None)
    return {
        "empty": not snap,
        "field_count": len(snap),
        "groups": _reg.groups(),
        "by_source": dict(by_source),
        "human_overrides": by_source.get("human", 0),
        "linkage_escalations": by_source.get("linkage", 0),
        "sensitive_fields": sensitive,
        "last_updated": last,
        "hint": "Empty -> fresh start. Non-empty -> you are continuing prior "
                "work; if this is a DIFFERENT exhaust source, call "
                "clear_registry() first so stale decisions do not leak in.",
    }


def clear_registry() -> dict:
    """Wipe the durable catalog (fields + override history). Use when starting
    on a new/unrelated exhaust source. Irreversible - confirm with the user
    first."""
    before = len(_reg.snapshot())
    _reg.reset()
    return {"cleared": before, "field_count": 0}


def report(inventory: dict | None = None, linkage: dict | None = None,
           title: str = "Exhaust governance report", as_of: str | None = None,
           protection_state: str = "unknown") -> dict:
    """Assemble the DATA for a governance report from the durable catalog (+
    optional inventory/linkage). Returns {markdown, summary}.

    This tool produces facts and tables; the AGENT is expected to write the
    surrounding narrative and tailor it. Crucially, nothing here claims the data
    is protected - the analysis does not change code or move data. Pass
    `protection_state` so the status line is accurate:
      - "on_tn"     : the app already emits through TN; the proposed routing
                      refines an already-encrypted stream.
      - "plaintext" : the app does NOT yet emit through TN; the sensitive fields
                      are in the clear TODAY. The hook is a TARGET - applying it
                      and routing the app through TN (tn-annotate or a handler)
                      is what protects them. This analysis is read-only on code.
      - "unknown"   : not determined; say so.
    """
    stamp = as_of or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    snap = _reg.snapshot()
    groups = _reg.groups()

    # Examples (the field's value AND the surrounding log line for context) are
    # pulled from the live inventory at report time, NOT stored in the registry -
    # the catalog must not hold raw sample values (they may be PII).
    sample_of: dict[str, str] = {}
    context_of: dict[str, str] = {}
    if inventory:
        for ev in inventory.get("events", {}).values():
            for f in ev.get("fields", []):
                leaf = f["leaf"]
                if leaf not in sample_of and f.get("samples"):
                    sample_of[leaf] = str(f["samples"][0])[:40]
                if leaf not in context_of and f.get("example_context"):
                    context_of[leaf] = str(f["example_context"])[:110]

    def _ex(leaf: str) -> str:
        val = sample_of.get(leaf)
        ctx = context_of.get(leaf)
        if ctx:
            return f"`{val}` in `{ctx}`" if val else f"`{ctx}`"
        return f"`{val}`" if val else "-"

    by_source: dict[str, int] = defaultdict(int)
    for f in snap:
        by_source[(f["source"] or "detector").split(":")[0]] += 1
    sensitive = [f for f in snap if f["group_name"] in _SENSITIVE_GROUPS]
    unreviewed = [f for f in snap
                  if (f["source"] or "").startswith("detector") and f["confidence"] <= 0.6]

    L = [f"# {title}", "", f"_Generated {stamp}_", ""]
    if inventory:
        L += [f"**Exhaust:** {inventory.get('record_count', '?')} records, "
              f"{inventory.get('event_type_count', '?')} event types "
              f"(format: {inventory.get('format', '?')}).", ""]
    L += [
        "## What this is", "",
        "The data your application throws off - logs, telemetry, traces, stdout - "
        "escapes the governance your warehouse and database already have. It is "
        "where sensitive data leaks by accident: an email in a debug line, a "
        "token in a stack trace, an opaque id that quietly reassembles a person. "
        "This report is a pass over that exhaust to make it visible and propose a "
        "safe routing. Routing the exhaust through TN encrypts to you by default; "
        "ONCE routed, even what we missed cannot sit in the clear. This analysis "
        "is read-only - it does not change your code or move your data; it tells "
        "you what is there and what the safe routing would be.",
        "",
        _protection_line(protection_state),
        "",
        "## What it looks for", "",
        "- **Direct PII in values** - emails, IPs, tokens, even in a field whose "
        "name looks harmless (we classify by the value, not the name).",
        "- **Quasi-identifiers** - user-agent, geo, device fingerprints that "
        "narrow down a person.",
        "- **Person-linking ids** - session / user / customer ids.",
        "- **Re-identification across rows** - the subtle one. A single opaque "
        "value (a correlation or request id) that appears across several event "
        "types threads one person's activity back together, even when no single "
        "row is identifying.",
        "- **Anything riding in the clear that should not be** - the safe default "
        "is that only operational keys (timestamps, levels, codes) are "
        "unencrypted; everything else is encrypted, including fields nobody "
        "classified.",
        "",
        "## How to read this", "",
        "- **Groups** - who can decrypt what. `public` rides in the clear; every "
        "other group is encrypted to a distinct audience.",
        "- **Sensitive fields** - what we found, with the source of the call "
        "(value detector, kit, linkage, or a human decision) and an example in "
        "its log line.",
        "- **Re-identification** - the cross-row join keys; route these to "
        "identity, not analytics, whatever they look like alone.",
        "- **Review queue** - low-confidence guesses to confirm. In the proposed "
        "routing they fall to an encrypted default, but may belong somewhere more "
        "specific (and are only protected once the app routes through TN).",
        "",
    ]
    L += [
        "## Summary", "",
        f"- {len(snap)} fields catalogued across {len(groups)} groups",
        f"- {len(sensitive)} sensitive (pii / identity / clinical / geo_device)",
        f"- {by_source.get('human', 0)} human overrides, "
        f"{by_source.get('linkage', 0)} linkage escalations, "
        f"{by_source.get('detector', 0)} auto-classified",
        f"- {len(unreviewed)} low-confidence fields still unreviewed",
        "",
        "## Groups (who can decrypt what)", "",
    ]
    for g in sorted(groups):
        marker = " (encrypted)" if g != "public" else " (clear)"
        L.append(f"- **{g}**{marker}: {', '.join(sorted(groups[g]))}")
    L += ["", "## Sensitive fields", "",
          "| field | group | source | confidence | example |",
          "|---|---|---|---|---|"]
    for f in sorted(sensitive, key=lambda x: x["group_name"]):
        L.append(f"| `{f['leaf']}` | {f['group_name']} | {f['source']} | "
                 f"{f['confidence']} | {_ex(f['leaf'])} |")
    if linkage and linkage.get("linkage_candidates"):
        L += ["", "## Re-identification (cross-row join keys)", "",
              "| field | threads | example |", "|---|---|---|"]
        for c in linkage["linkage_candidates"][:10]:
            ex = list(c.get("example_bridges", {}))
            L.append(f"| `{c['field']}` | {c['max_threaded_event_types']} event types | "
                     f"{(ex[0][:24] if ex else '')} |")
    if unreviewed:
        L += ["", "## Review queue (confirm these)",
              "Low-confidence / unclassified fields the engine guessed. In the "
              "proposed routing they fall to `default` (encrypted, once the app "
              "is on TN) - they are NOT necessarily protected today (see "
              "protection status above). They may also belong in a more specific "
              "group. Confirm or re-route each.", "",
              "| field | guessed | confidence | proposed group | example |",
              "|---|---|---|---|---|"]
        for f in unreviewed:
            L.append(f"| `{f['leaf']}` | {f['klass']} | {f['confidence']} | "
                     f"{f['group_name']} | {_ex(f['leaf'])} |")
    L += ["", "---",
          "_Default-private routing: only an operational allowlist rides in the "
          "clear; everything else is encrypted ONCE the exhaust is routed through "
          "TN. This report proposes that routing; it does not change code or move "
          "data. Decisions are durable in the registry (precedence "
          "human > linkage > kit > detector)._"]
    if sample_of:
        L += ["", "_Note: example values are pulled from the live exhaust for "
              "this report and may contain real data; they are NOT stored in the "
              "catalog. Handle this report accordingly._"]
    md = "\n".join(L)
    return {"markdown": md,
            "summary": {"fields": len(snap), "groups": len(groups),
                        "sensitive": len(sensitive), "unreviewed": len(unreviewed)}}


# --- helper: decrypt a TN stream -------------------------------------------

def decrypt_stream(log: str, tn_yaml: str, keystore: str | None = None,
                   groups: list[str] | None = None) -> dict:
    """Read a TN-encrypted exhaust stream into plaintext rows (user's own env).

    Needs the user's keystore. Returns flattened rows so the isolate/context
    stages see real values, not ciphertext.
    """
    try:
        _tn_init(tn_yaml, link=False)
    except Exception as exc:  # noqa: BLE001 - surface init issues to the agent
        return {"error": f"tn.init failed: {exc}", "rows": []}

    rows: list[dict] = []
    read_kwargs = {"log": str(Path(log).resolve())}
    if keystore:
        read_kwargs["as_recipient"] = str(Path(keystore).resolve())
    try:
        if groups:
            merged: dict[int, dict] = {}
            for g in groups:
                for e in _tn_read(group=g, **read_kwargs):
                    seq = getattr(e, "sequence", len(merged))
                    row = merged.setdefault(seq, {"event_type": getattr(e, "event_type", None)})
                    row.update(getattr(e, "fields", {}) or {})
            rows = list(merged.values())
        else:
            for e in _tn_read(**read_kwargs):
                row = {"event_type": getattr(e, "event_type", None)}
                row.update(getattr(e, "fields", {}) or {})
                rows.append(row)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"tn.read failed: {exc}", "rows": rows}
    return {"row_count": len(rows), "rows": rows}
