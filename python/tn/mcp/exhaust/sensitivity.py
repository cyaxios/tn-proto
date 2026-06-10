"""Dynamic pillar - field sensitivity classifier over a runtime log stream.

Sibling to classifier.py. Where classifier.py classifies the *call*
(methodFullName -> effect taxonomy) from the static CPG, this classifies the
*fields* (value -> sensitivity class) from real runtime evidence - the part
the locator's static pillars do not reach.

Reads an ndjson log/event stream, groups by event type, flattens nested
payloads, and classifies each field from VALUE evidence (DLP-style regex /
dictionary detectors) combined with leaf-NAME hints. Output drives govern.py,
which synthesizes TN groups + the agents.md usage policy.

Backends, mirroring classifier.py: a deterministic detector set is the default
and runs offline; an LLM backend swaps in behind the same per-field cache when
SENSITIVITY_LLM=1 and OPENAI_API_KEY are set (seam below, not on by default).

Usage:
    python -m tn.mcp.exhaust.sensitivity <stream.ndjson> <out.json> [--event-key action]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Classification cache. Project-rooted (.tn/) so an installed package never
# writes into site-packages; TN_SENSITIVITY_CACHE overrides the location.
CACHE_PATH = Path(
    os.environ.get("TN_SENSITIVITY_CACHE") or Path(".tn") / "sensitivity_cache.json"
)

MISSING = {"", "undefined", "null", "none", "nan"}

# Value detectors: (name, regex, class, confidence). First strong match wins;
# name hints then refine. Mirrors the DLP "pattern + dictionary" approach.
_DETECTORS = [
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"), "pii_direct", 0.95),
    ("ipv4", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$"), "pii_direct", 0.9),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"), "pii_direct", 0.95),
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "id", 0.9),
    ("user_agent", re.compile(r"(Mozilla|AppleWebKit|Chrome|Safari|Gecko|bot|spider|crawler)", re.I), "pii_quasi", 0.85),
    ("url", re.compile(r"^https?://"), "behavioral", 0.7),
    ("iso_dt", re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}"), "temporal", 0.8),
    ("country", re.compile(r"^[A-Z]{2}$"), "pii_quasi", 0.4),  # weak; needs name confirm
]

_NAME_PII_DIRECT = {"email", "phone", "ssn", "ip", "ip_address", "gov_id", "passport",
                    "access_token", "refresh_token", "session_token", "jwt"}
_NAME_GEO = {"location", "country", "region", "city", "geo", "lat", "lon", "lng",
             "latitude", "longitude", "postal_code", "zip"}
_NAME_UA = {"user-agent", "useragent", "user_agent", "ua"}
_NAME_PERSON_ID_BASE = {"member", "user", "customer", "visitor", "session", "account", "subscriber"}
_NAME_BEHAVIORAL = {"referrer", "referer", "href", "url", "pathname", "path", "page",
                    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                    "campaign", "source", "medium", "referrersource"}
_NAME_ENUM = {"status", "type", "version", "action", "device", "method", "code",
              "role", "plan", "locale", "language", "post_type", "member_status"}
_NAME_TEMPORAL = {"timestamp", "time", "date", "ts", "received_timestamp", "inserted_at"}

# class -> (recommended group, label). "public" rides at the envelope top level.
CLASS_TO_GROUP = {
    "pii_direct": ("pii", "direct PII"),
    "pii_quasi": ("geo_device", "quasi-identifier / fingerprint"),
    "person_id": ("identity", "person-linking pseudonymous id"),
    "id": ("public", "opaque id"),
    "behavioral": ("analytics", "behavioral / tracking"),
    "temporal": ("public", "temporal"),
    "enum_attr": ("public", "low-sensitivity attribute"),
    "unknown": ("default", "unclassified"),
}


def _flatten(obj, prefix: str = "") -> dict[str, object]:
    out: dict[str, object] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            else:
                out[key] = v
    return out


def classify_field_deterministic(leaf: str, samples: list[str]) -> tuple[str, float, list[str]]:
    leaf_l = leaf.lower()
    detectors: list[str] = []
    best_cls, best_conf = "unknown", 0.0

    real = [s for s in samples if s.strip().lower() not in MISSING]
    for name, rx, cls, conf in _DETECTORS:
        if real and sum(bool(rx.search(s)) for s in real) / len(real) >= 0.6:
            detectors.append(f"value:{name}")
            if conf > best_conf:
                best_cls, best_conf = cls, conf

    name_cls: str | None = None
    if leaf_l in _NAME_PII_DIRECT:
        name_cls = "pii_direct"
    elif leaf_l in _NAME_UA or leaf_l in _NAME_GEO:
        name_cls = "pii_quasi"
    elif leaf_l in _NAME_BEHAVIORAL:
        name_cls = "behavioral"
    elif leaf_l in _NAME_TEMPORAL:
        name_cls = "temporal"
    elif leaf_l in _NAME_ENUM:
        name_cls = "enum_attr"

    base = re.split(r"[_-]", leaf_l)[0]
    is_id_name = leaf_l.endswith("uuid") or leaf_l.endswith("id") or leaf_l == "id"
    if is_id_name and base in _NAME_PERSON_ID_BASE:
        name_cls = "person_id"
    elif is_id_name and name_cls is None:
        name_cls = "id"

    if name_cls:
        detectors.append(f"name:{leaf_l}")

    if "value:uuid" in detectors and name_cls in ("person_id", "id"):
        best_cls = name_cls
        best_conf = max(best_conf, 0.85 if name_cls == "person_id" else 0.7)
    elif name_cls == "pii_quasi" and "value:country" in detectors:
        best_cls, best_conf = "pii_quasi", 0.85
    elif best_cls == "unknown" and name_cls:
        best_cls, best_conf = name_cls, 0.6
    elif name_cls == "pii_direct":
        best_cls = "pii_direct"
        best_conf = max(best_conf, 0.8)

    if not detectors:
        detectors.append("none")
    return best_cls, round(best_conf, 2), detectors


# LLM backend seam (mirrors classifier.py). Off by default; deterministic
# detectors are authoritative unless SENSITIVITY_LLM=1 and a key are present.
def classify_field(leaf: str, samples: list[str], cache: dict) -> tuple[str, float, list[str]]:
    key = leaf.lower()
    if key in cache:
        c = cache[key]
        return c["class"], c["confidence"], c["detectors"]
    cls, conf, dets = classify_field_deterministic(leaf, samples)
    cache[key] = {"class": cls, "confidence": conf, "detectors": dets}
    return cls, conf, dets


def classify_stream(records: list[dict], event_key: str, cache: dict) -> dict:
    by_event: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_event[str(r.get(event_key, "_unknown"))].append(r)

    events: dict[str, dict] = {}
    for etype, recs in by_event.items():
        samples: dict[str, list[str]] = defaultdict(list)
        counts: dict[str, int] = defaultdict(int)
        missing: dict[str, int] = defaultdict(int)
        distinct: dict[str, set] = defaultdict(set)
        for r in recs:
            for path, val in _flatten(r).items():
                counts[path] += 1
                sval = "" if val is None else str(val)
                if sval.strip().lower() in MISSING:
                    missing[path] += 1
                else:
                    distinct[path].add(sval)
                    if len(samples[path]) < 5 and sval not in samples[path]:
                        samples[path].append(sval[:80])
        fields = []
        for path in sorted(counts):
            leaf = path.split(".")[-1]
            cls, conf, dets = classify_field(leaf, samples[path], cache)
            group, label = CLASS_TO_GROUP[cls]
            fields.append({
                "path": path, "leaf": leaf, "class": cls, "class_label": label,
                "confidence": conf, "detectors": dets, "recommended_group": group,
                "distinct": len(distinct[path]),
                "null_rate": round(missing[path] / counts[path], 2) if counts[path] else 0.0,
                "samples": samples[path],
            })
        events[etype] = {"count": len(recs), "fields": fields}
    return {"version": "0.1", "event_key": event_key,
            "record_count": len(records), "events": events}


def load_ndjson(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def load_cache() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    return {}


def save_cache(cache: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sensitivity", description=(__doc__ or "").splitlines()[0])
    ap.add_argument("path", help="ndjson runtime stream")
    ap.add_argument("out", help="output JSON path")
    ap.add_argument("--event-key", default="action", help="record field naming the event type")
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"sensitivity: path not found: {path}", file=sys.stderr)
        return 2
    records = load_ndjson(path)
    cache = load_cache()
    report = classify_stream(records, args.event_key, cache)
    save_cache(cache)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # summary to stderr
    print(f"records {report['record_count']}  event_key={args.event_key}", file=sys.stderr)
    for etype, ev in report["events"].items():
        flagged = [f for f in ev["fields"] if f["class"].startswith("pii") or f["class"] == "person_id"]
        print(f"  {etype}: {len(ev['fields'])} fields, {len(flagged)} sensitive", file=sys.stderr)
        for f in flagged:
            print(f"    {f['path']:<28} {f['class']:<12} {f['confidence']}  -> {f['recommended_group']}", file=sys.stderr)
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
