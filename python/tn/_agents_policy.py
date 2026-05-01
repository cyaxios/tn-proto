"""Markdown loader for ``.tn/config/agents.md`` policy files.

Per the 2026-04-25 read-ergonomics spec §2.4 the canonical format for
the ``tn.agents`` policy file is markdown. Each event type is a
``## <event_type>`` section; each section MUST have all five required
``### <field>`` subsections (``instruction``, ``use_for``,
``do_not_use_for``, ``consequences``, ``on_violation_or_error``).

A YAML-frontmatter block at the top carries ``version`` and ``schema``.
The loader is intentionally tiny — split-on-line-prefix is enough.

Returned per event type:

    PolicyTemplate(
        instruction="...",
        use_for="...",
        do_not_use_for="...",
        consequences="...",
        on_violation_or_error="...",
        content_hash="sha256:...",
        version="v1",
        path=".tn/config/agents.md",
    )

If the file is missing, ``load_policy_file()`` returns an empty dict —
absence is not an error (no policy → no splice → ``tn.agents`` group
stays empty for every event).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

REQUIRED_FIELDS: tuple[str, ...] = (
    "instruction",
    "use_for",
    "do_not_use_for",
    "consequences",
    "on_violation_or_error",
)

POLICY_RELATIVE_PATH: str = ".tn/config/agents.md"


@dataclass(frozen=True)
class PolicyTemplate:
    """One event type's worth of policy text."""

    event_type: str
    instruction: str
    use_for: str
    do_not_use_for: str
    consequences: str
    on_violation_or_error: str
    content_hash: str  # "sha256:<hex>"
    version: str
    path: str  # repository-relative path, e.g. ".tn/config/agents.md"


@dataclass(frozen=True)
class PolicyDocument:
    """Top-level shape returned by :func:`load_policy_file`."""

    templates: dict[str, PolicyTemplate]
    version: str
    schema: str
    path: str
    body: str  # raw markdown text (after frontmatter)
    content_hash: str  # sha256 of canonical-bytes(per_event_dict)


def _canonical_bytes(obj: object) -> bytes:
    """Stable JSON encoding for hashing — sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strip_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Pull a tiny ``key: value`` block off the top of the doc.

    Frontmatter is the leading lines before the first ``# `` heading. Each
    line must look like ``key: value``. Two supported flavours:

    1. Plain leading lines (no fences) before the first ``# `` heading.
    2. A fenced block delimited by ``---`` lines (Jekyll-style).

    Anything inside ``# TN Agents Policy`` (the title) belongs to the body.
    """
    lines = text.splitlines()
    meta: dict[str, str] = {}

    # Fenced ``---`` style.
    if lines and lines[0].strip() == "---":
        end = -1
        for i, ln in enumerate(lines[1:], start=1):
            if ln.strip() == "---":
                end = i
                break
        if end > 0:
            for ln in lines[1:end]:
                if ":" in ln:
                    k, _, v = ln.partition(":")
                    meta[k.strip()] = v.strip()
            return meta, "\n".join(lines[end + 1 :])

    # Plain-leading style: scan until the first level-1 or level-2 heading.
    body_start = 0
    for i, ln in enumerate(lines):
        if ln.startswith("# ") or ln.startswith("## "):
            body_start = i
            break
        s = ln.strip()
        if not s:
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            meta[k.strip()] = v.strip()
    return meta, "\n".join(lines[body_start:])


def _strip_title(body: str) -> str:
    """Drop a single leading ``# `` heading and any frontmatter-shaped
    ``key: value`` lines that follow it (some authors put ``version: 1``
    under the title rather than at the very top of the file).
    """
    lines = body.splitlines()
    # Drop leading blank lines.
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].startswith("# "):
        lines.pop(0)
    # Drop any subsequent ``key: value`` lines (no markdown structure) until
    # we hit the first ``## `` event-type heading or a blank-then-content.
    while lines:
        s = lines[0].strip()
        if s.startswith("## "):
            break
        if not s:
            lines.pop(0)
            continue
        if ":" in s and not s.startswith("#"):
            lines.pop(0)
            continue
        break
    return "\n".join(lines)


def _split_event_sections(body: str) -> list[tuple[str, str]]:
    """Split ``body`` on ``## `` headings. Returns ``[(event_type, body), ...]``."""
    out: list[tuple[str, str]] = []
    cur_event: str | None = None
    cur_lines: list[str] = []
    for ln in body.splitlines():
        if ln.startswith("## "):
            if cur_event is not None:
                out.append((cur_event, "\n".join(cur_lines).strip()))
            cur_event = ln[3:].strip()
            cur_lines = []
        else:
            cur_lines.append(ln)
    if cur_event is not None:
        out.append((cur_event, "\n".join(cur_lines).strip()))
    return out


def _split_field_sections(section_body: str) -> dict[str, str]:
    """Split one event-type section on ``### `` subheadings."""
    out: dict[str, str] = {}
    cur: str | None = None
    cur_lines: list[str] = []
    for ln in section_body.splitlines():
        if ln.startswith("### "):
            if cur is not None:
                out[cur] = "\n".join(cur_lines).strip()
            cur = ln[4:].strip()
            cur_lines = []
        else:
            cur_lines.append(ln)
    if cur is not None:
        out[cur] = "\n".join(cur_lines).strip()
    return out


def parse_policy_text(text: str, path: str) -> PolicyDocument:
    """Parse a markdown policy doc.

    Raises ``ValueError`` if a section is missing one of the five required
    subfields, or if frontmatter is malformed. ``path`` is a label only;
    no I/O is done by this function.
    """
    meta, after_frontmatter = _strip_frontmatter(text)
    body = _strip_title(after_frontmatter)

    version = str(meta.get("version") or "1")
    schema = str(meta.get("schema") or "tn-agents-policy@v1")

    sections = _split_event_sections(body)
    templates: dict[str, PolicyTemplate] = {}
    per_event_for_hash: dict[str, dict[str, str]] = {}

    for event_type, section_body in sections:
        if not event_type:
            continue
        fields = _split_field_sections(section_body)
        missing = [f for f in REQUIRED_FIELDS if f not in fields or not fields[f]]
        if missing:
            raise ValueError(
                f"{path}: agents policy section ## {event_type} is missing "
                f"required subsection(s): {missing!r}"
            )

        per_event_for_hash[event_type] = {f: fields[f] for f in REQUIRED_FIELDS}

    # Top-level content_hash covers every event_type's payload + the
    # version + schema string. Per-template content_hash is identical for
    # all templates in the same file (it's the file-level signature).
    canonical = _canonical_bytes(
        {
            "version": version,
            "schema": schema,
            "events": per_event_for_hash,
        }
    )
    content_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()

    for event_type, payload in per_event_for_hash.items():
        templates[event_type] = PolicyTemplate(
            event_type=event_type,
            instruction=payload["instruction"],
            use_for=payload["use_for"],
            do_not_use_for=payload["do_not_use_for"],
            consequences=payload["consequences"],
            on_violation_or_error=payload["on_violation_or_error"],
            content_hash=content_hash,
            version=version,
            path=path,
        )

    return PolicyDocument(
        templates=templates,
        version=version,
        schema=schema,
        path=path,
        body=text,
        content_hash=content_hash,
    )


def policy_path_for(yaml_dir: Path) -> Path:
    """Canonical absolute path for the policy file given a yaml directory."""
    return (yaml_dir / POLICY_RELATIVE_PATH).resolve()


def load_policy_file(yaml_dir: Path) -> PolicyDocument | None:
    """Load ``<yaml_dir>/.tn/config/agents.md`` if it exists.

    Returns ``None`` when the file does not exist (no policy → no splice).
    Raises ``ValueError`` for malformed content.
    """
    p = policy_path_for(yaml_dir)
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8")
    return parse_policy_text(text, POLICY_RELATIVE_PATH)


__all__ = [
    "POLICY_RELATIVE_PATH",
    "REQUIRED_FIELDS",
    "PolicyDocument",
    "PolicyTemplate",
    "load_policy_file",
    "parse_policy_text",
    "policy_path_for",
]
