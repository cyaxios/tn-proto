"""Static HTML renderers for human-viewable artifacts."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .config import IntrospectConfig

_STYLE = """
body { font-family: -apple-system, Segoe UI, sans-serif; margin: 2em; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; position: sticky; top: 0; }
code { font-family: ui-monospace, Menlo, monospace; font-size: 90%; }
tr:nth-child(even) { background: #fafafa; }
input { width: 100%; padding: 4px; margin-bottom: 1em; font-size: 14px; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 80%; margin-right: 4px; }
.tag.public { background: #d4edda; color: #155724; }
.tag.private { background: #e9ecef; color: #6c757d; }
.tag.in-all { background: #cce5ff; color: #004085; }
"""

_SCRIPT = """
const q = document.getElementById('q');
const rows = document.querySelectorAll('tbody tr');
q.addEventListener('input', () => {
  const v = q.value.toLowerCase();
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(v) ? '' : 'none';
  });
});
"""


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        f"<html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>"
        "<input id='q' placeholder='Filter...' autofocus />"
        f"{body}"
        f"<script>{_SCRIPT}</script>"
        "</body></html>\n"
    )


def write_symbols_html(cfg: IntrospectConfig) -> Path:
    src = cfg.output_dir / "surface_inventory.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    rows = []
    for s in data["symbols"]:
        tags = []
        if s.get("is_public"):
            tags.append("<span class='tag public'>public</span>")
        else:
            tags.append("<span class='tag private'>private</span>")
        if s.get("in_all") is True:
            tags.append("<span class='tag in-all'>__all__</span>")
        rows.append(
            "<tr>"
            f"<td>{html.escape(s['kind'])}</td>"
            f"<td>{''.join(tags)}</td>"
            f"<td><code>{html.escape(s['qualname'])}</code></td>"
            f"<td><code>{html.escape(s['signature'])}</code></td>"
            f"<td>{html.escape(s['file'])}:{s['lineno']}</td>"
            f"<td>{html.escape((s.get('docstring') or '')[:120])}</td>"
            "</tr>"
        )
    body = (
        "<table><thead><tr>"
        "<th>Kind</th><th>Tags</th><th>Qualname</th><th>Signature</th>"
        "<th>File</th><th>Docstring</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )
    out = cfg.output_dir / "surface_inventory.html"
    out.write_text(_page("tn-protocol surface inventory", body), encoding="utf-8")
    return out


def write_extension_points_html(cfg: IntrospectConfig) -> Path:
    src = cfg.output_dir / "extension_points.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    sections = []
    for section_title, key in [("emit() hooks", "emit_hooks"), ("tn.log() event types", "tn_log_event_types")]:
        rows = []
        for h in data.get(key, []):
            sites = "<br>".join(
                f"<code>{html.escape(cs['file'])}:{cs['lineno']}</code>"
                for cs in h["call_sites"]
            )
            keys = ", ".join(html.escape(k) for k in h["inferred_payload_keys"])
            rows.append(
                "<tr>"
                f"<td><code>{html.escape(h['name'])}</code></td>"
                f"<td>{len(h['call_sites'])}</td>"
                f"<td>{sites}</td>"
                f"<td>{keys}</td>"
                "</tr>"
            )
        if not rows:
            continue
        sections.append(
            f"<h2>{html.escape(section_title)} ({len(rows)})</h2>"
            "<table><thead><tr>"
            "<th>Name</th><th>#</th><th>Call sites</th><th>Inferred payload keys</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    body = "".join(sections) if sections else "<p>No emit() or tn.log() events found.</p>"
    out = cfg.output_dir / "extension_points.html"
    out.write_text(_page("tn-protocol extension points", body), encoding="utf-8")
    return out


def write_env_vars_html(cfg: IntrospectConfig) -> Path:
    src = cfg.output_dir / "env_vars.json"
    if not src.exists():
        return cfg.output_dir / "env_vars.html"  # caller skipped
    data = json.loads(src.read_text(encoding="utf-8"))
    rows = []
    for ev in data.get("env_vars", []):
        sites = "<br>".join(
            f"<code>{html.escape(cs['file'])}:{cs['lineno']}</code>"
            for cs in ev["call_sites"]
        )
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(ev['name'])}</code></td>"
            f"<td>{len(ev['call_sites'])}</td>"
            f"<td>{html.escape(ev.get('default') or '')}</td>"
            f"<td>{sites}</td>"
            "</tr>"
        )
    body = (
        "<p>Discovered environment variables (os.environ.get / os.getenv / os.environ[]):</p>"
        "<table><thead><tr>"
        "<th>Name</th><th>#</th><th>Default</th><th>Call sites</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )
    out = cfg.output_dir / "env_vars.html"
    out.write_text(_page("tn-protocol environment variables", body), encoding="utf-8")
    return out


def write_flag_inventory_html(cfg: IntrospectConfig) -> Path:
    src = cfg.output_dir / "flag_inventory.json"
    if not src.exists():
        return cfg.output_dir / "flag_inventory.html"
    data = json.loads(src.read_text(encoding="utf-8"))
    rows = []
    for f in data.get("flags", []):
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(f['function_qualname'])}</code></td>"
            f"<td><code>{html.escape(f['kwarg_name'])}</code></td>"
            f"<td><code>{html.escape(f.get('annotation') or '')}</code></td>"
            f"<td><code>{html.escape(f.get('default') or '')}</code></td>"
            f"<td><code>{html.escape(f['file'])}:{f['lineno']}</code></td>"
            f"<td>{f.get('call_site_count', 0)}</td>"
            "</tr>"
        )
    body = (
        "<p>Bool / Optional[bool] keyword arguments (the most common form of feature flag).</p>"
        "<table><thead><tr>"
        "<th>Function</th><th>Kwarg</th><th>Annotation</th><th>Default</th>"
        "<th>Defined at</th><th>Call sites</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )
    out = cfg.output_dir / "flag_inventory.html"
    out.write_text(_page("tn-protocol flag inventory", body), encoding="utf-8")
    return out
