"""Classification / group registry - a durable catalog for the exhaust pipeline.

Closes the statelessness gap: without this, every run re-derives groups from
scratch and any human (or agent) override is lost. The registry persists, per
field, its sensitivity class, the TN group it routes to, where that decision
came from (detector / kit / linkage / human), and whether a human overrode it -
so decisions accumulate and stay consistent across runs and event types. This
is the Unity-Catalog-style classification catalog, local and dependency-free
(stdlib sqlite3).

TN routes by FIELD NAME (email -> pii regardless of event), so the registry is
keyed by the field leaf, matching the routing model. Each field also tracks
which event types it has been seen in (coverage).

Source precedence (who wins on conflict):
    human > linkage > kit > detector
A human override (overridden=1) is never silently downgraded by a later
detector pass; observe() respects it.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

# Per-instance registry so parallel servers (one per agent) do not collide.
# Default lives under the project's .tn/ (cwd-relative); override with
# TN_EXHAUST_REGISTRY to pin a specific path.
DB_PATH = Path(os.environ.get("TN_EXHAUST_REGISTRY",
              str(Path(".tn") / "exhaust_registry.db")))

_SOURCE_RANK = {"detector": 0, "kit": 1, "linkage": 2, "human": 3}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fields (
  leaf        TEXT PRIMARY KEY,
  klass       TEXT,
  confidence  REAL,
  group_name  TEXT,
  source      TEXT,
  overridden  INTEGER DEFAULT 0,
  note        TEXT,
  seen_in     TEXT,                              -- json list of event types
  first_seen  TEXT DEFAULT CURRENT_TIMESTAMP,
  last_seen   TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS history (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  leaf  TEXT,
  prev  TEXT                                     -- json of prior row, or null if new
);
"""


def _conn(db: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db or DB_PATH)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    c.executescript(_SCHEMA)
    return c


def _rank(source: str) -> int:
    return _SOURCE_RANK.get((source or "detector").split(":")[0], 0)


def observe(leaf: str, klass: str, confidence: float, group: str,
            source: str = "detector", event_types: list[str] | None = None,
            db: str | Path | None = None) -> None:
    """Record a classifier verdict. Respects an existing higher-precedence
    decision (a human override is not overwritten by a detector pass)."""
    c = _conn(db)
    try:
        row = c.execute("SELECT * FROM fields WHERE leaf=?", (leaf,)).fetchone()
        seen = set(json.loads(row["seen_in"]) if row and row["seen_in"] else [])
        seen.update(event_types or [])
        if row is None:
            c.execute(
                "INSERT INTO fields(leaf,klass,confidence,group_name,source,overridden,seen_in) "
                "VALUES(?,?,?,?,?,0,?)",
                (leaf, klass, confidence, group, source, json.dumps(sorted(seen))))
        elif _rank(source) >= _rank(row["source"]) and not row["overridden"]:
            c.execute(
                "UPDATE fields SET klass=?,confidence=?,group_name=?,source=?,"
                "seen_in=?,last_seen=CURRENT_TIMESTAMP WHERE leaf=?",
                (klass, confidence, group, source, json.dumps(sorted(seen)), leaf))
        else:
            # keep the stronger decision; just widen coverage
            c.execute("UPDATE fields SET seen_in=?,last_seen=CURRENT_TIMESTAMP WHERE leaf=?",
                      (json.dumps(sorted(seen)), leaf))
        c.commit()
    finally:
        c.close()


def override(leaf: str, group: str, klass: str | None = None, note: str = "",
             source: str = "human", db: str | Path | None = None) -> None:
    """Pin a field to a group (human decision or a linkage escalation).
    Records the prior state to the history stack so it can be unwound."""
    c = _conn(db)
    try:
        row = c.execute("SELECT * FROM fields WHERE leaf=?", (leaf,)).fetchone()
        prev = json.dumps(dict(row)) if row else None
        c.execute("INSERT INTO history(leaf, prev) VALUES(?,?)", (leaf, prev))
        seen = row["seen_in"] if row else json.dumps([])
        kl = klass or (row["klass"] if row else "unknown")
        ov = 1 if source == "human" else (row["overridden"] if row else 0)
        if row is None:
            c.execute(
                "INSERT INTO fields(leaf,klass,confidence,group_name,source,overridden,note,seen_in) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (leaf, kl, 1.0, group, source, ov, note, seen))
        else:
            c.execute(
                "UPDATE fields SET klass=?,group_name=?,source=?,overridden=?,note=?,"
                "last_seen=CURRENT_TIMESTAMP WHERE leaf=?",
                (kl, group, source, ov, note, leaf))
        c.commit()
    finally:
        c.close()


def unwind(db: str | Path | None = None) -> dict:
    """Undo the most recent override / linkage escalation, restoring the field
    to its prior state (or removing it if it was new). The 'unwind' move in the
    checkpoint loop."""
    c = _conn(db)
    try:
        h = c.execute("SELECT * FROM history ORDER BY id DESC LIMIT 1").fetchone()
        if h is None:
            return {"unwound": None, "note": "nothing to unwind"}
        leaf = h["leaf"]
        if h["prev"] is None:
            c.execute("DELETE FROM fields WHERE leaf=?", (leaf,))
            restored = None
        else:
            p = json.loads(h["prev"])
            c.execute(
                "UPDATE fields SET klass=?,confidence=?,group_name=?,source=?,"
                "overridden=?,note=?,seen_in=? WHERE leaf=?",
                (p["klass"], p["confidence"], p["group_name"], p["source"],
                 p["overridden"], p.get("note"), p["seen_in"], leaf))
            restored = p["group_name"]
        c.execute("DELETE FROM history WHERE id=?", (h["id"],))
        c.commit()
        return {"unwound": leaf, "restored_group": restored}
    finally:
        c.close()


def mark_linkage(leaf: str, group: str = "identity", note: str = "",
                 db: str | Path | None = None) -> None:
    """Escalate a cross-row join key to a person-linking group. Beats detector
    and kit, but a human override still wins."""
    override(leaf, group, klass="person_id",
             note=note or "cross-row join key (linkage stage)",
             source="linkage", db=db)


def groups(db: str | Path | None = None) -> dict[str, list[str]]:
    """Materialize the current group -> [fields] map from the registry."""
    c = _conn(db)
    try:
        out: dict[str, list[str]] = {}
        for r in c.execute("SELECT leaf, group_name FROM fields ORDER BY group_name, leaf"):
            out.setdefault(r["group_name"] or "default", []).append(r["leaf"])
        return out
    finally:
        c.close()


def field_group(leaf: str, db: str | Path | None = None) -> str | None:
    c = _conn(db)
    try:
        r = c.execute("SELECT group_name FROM fields WHERE leaf=?", (leaf,)).fetchone()
        return r["group_name"] if r else None
    finally:
        c.close()


def snapshot(db: str | Path | None = None) -> list[dict]:
    """Full registry dump - the audit artifact."""
    c = _conn(db)
    try:
        rows = []
        for r in c.execute("SELECT * FROM fields ORDER BY group_name, leaf"):
            d = dict(r)
            d["seen_in"] = json.loads(d["seen_in"]) if d["seen_in"] else []
            d["overridden"] = bool(d["overridden"])
            rows.append(d)
        return rows
    finally:
        c.close()


def reset(db: str | Path | None = None) -> None:
    c = _conn(db)
    try:
        c.execute("DELETE FROM fields")
        c.execute("DELETE FROM history")
        c.commit()
    finally:
        c.close()
