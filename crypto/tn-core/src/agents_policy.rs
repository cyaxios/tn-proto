//! Markdown loader for `.tn/config/agents.md` policy files.
//!
//! Mirrors `tn-protocol/python/tn/_agents_policy.py` byte-for-byte. Each
//! event type is a `## <event_type>` section; each section MUST have all
//! five required `### <field>` subsections (`instruction`, `use_for`,
//! `do_not_use_for`, `consequences`, `on_violation_or_error`).
//!
//! A YAML-frontmatter block at the top carries `version` and `schema`.
//! The loader is intentionally tiny — split-on-line-prefix is enough.
//! No markdown crate; the parser is hand-rolled.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The five required subsection field names per `## <event_type>` section.
pub const REQUIRED_FIELDS: [&str; 5] = [
    "instruction",
    "use_for",
    "do_not_use_for",
    "consequences",
    "on_violation_or_error",
];

/// Repository-relative path callers should write the policy file to.
pub const POLICY_RELATIVE_PATH: &str = ".tn/config/agents.md";

/// One event type's worth of policy text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTemplate {
    /// The event_type this template applies to.
    pub event_type: String,
    /// Body of `### instruction`.
    pub instruction: String,
    /// Body of `### use_for`.
    pub use_for: String,
    /// Body of `### do_not_use_for`.
    pub do_not_use_for: String,
    /// Body of `### consequences`.
    pub consequences: String,
    /// Body of `### on_violation_or_error`.
    pub on_violation_or_error: String,
    /// `sha256:<hex>` of canonical-bytes(per_event_dict). Same value for
    /// every template loaded from the same file (file-level signature).
    pub content_hash: String,
    /// Top-level `version` from frontmatter.
    pub version: String,
    /// Repository-relative path label used in the wire `policy` field
    /// (e.g. `.tn/config/agents.md`).
    pub path: String,
}

/// Top-level shape returned by [`load_policy_file`].
#[derive(Debug, Clone)]
pub struct PolicyDocument {
    /// Per-event-type policy templates keyed by event_type.
    pub templates: BTreeMap<String, PolicyTemplate>,
    /// Top-level `version` from frontmatter.
    pub version: String,
    /// Top-level `schema` from frontmatter.
    pub schema: String,
    /// Repository-relative path (`POLICY_RELATIVE_PATH`).
    pub path: String,
    /// Raw markdown text (after frontmatter).
    pub body: String,
    /// `sha256:<hex>` covering version+schema+per-event payloads.
    pub content_hash: String,
}

/// Stable JSON encoding for hashing — sorted keys, compact separators.
///
/// Matches Python `_canonical_bytes` in `tn/_agents_policy.py`:
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
fn canonical_bytes_for_hash(
    version: &str,
    schema: &str,
    events: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<u8> {
    // Build the dict in the same shape as Python:
    // {"events": {...}, "schema": "...", "version": "..."}
    // sort_keys=True walks alphabetically: events, schema, version.
    // Each event's per-event dict is also sorted; BTreeMap iteration is sorted.
    let mut s = String::new();
    s.push('{');
    // "events"
    s.push_str("\"events\":{");
    let mut first_event = true;
    for (event_type, fields) in events {
        if !first_event {
            s.push(',');
        }
        first_event = false;
        s.push('"');
        push_json_escaped(&mut s, event_type);
        s.push_str("\":{");
        let mut first_field = true;
        for (k, v) in fields {
            if !first_field {
                s.push(',');
            }
            first_field = false;
            s.push('"');
            push_json_escaped(&mut s, k);
            s.push_str("\":\"");
            push_json_escaped(&mut s, v);
            s.push('"');
        }
        s.push('}');
    }
    s.push_str("},\"schema\":\"");
    push_json_escaped(&mut s, schema);
    s.push_str("\",\"version\":\"");
    push_json_escaped(&mut s, version);
    s.push_str("\"}");
    s.into_bytes()
}

/// JSON-escape a string into `out` (no surrounding quotes).
fn push_json_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Strip a leading `key: value` frontmatter block off `text`.
///
/// Two flavours mirroring Python's `_strip_frontmatter`:
///   1. Fenced `---` block (Jekyll-style).
///   2. Plain leading lines before the first `# ` or `## ` heading.
fn strip_frontmatter(text: &str) -> (BTreeMap<String, String>, String) {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut meta: BTreeMap<String, String> = BTreeMap::new();

    // Fenced --- style.
    if !lines.is_empty() && lines[0].trim() == "---" {
        let mut end: Option<usize> = None;
        for (i, ln) in lines.iter().enumerate().skip(1) {
            if ln.trim() == "---" {
                end = Some(i);
                break;
            }
        }
        if let Some(end) = end {
            for ln in &lines[1..end] {
                if let Some((k, v)) = ln.split_once(':') {
                    meta.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            let body = lines[end + 1..].join("\n");
            return (meta, body);
        }
    }

    // Plain-leading style.
    let mut body_start = 0;
    for (i, ln) in lines.iter().enumerate() {
        if ln.starts_with("# ") || ln.starts_with("## ") {
            body_start = i;
            break;
        }
        let s = ln.trim();
        if s.is_empty() {
            continue;
        }
        if let Some((k, v)) = s.split_once(':') {
            meta.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    (meta, lines[body_start..].join("\n"))
}

/// Drop a single leading `# ` heading and any frontmatter-shaped
/// `key: value` lines that follow it. Mirrors Python `_strip_title`.
fn strip_title(body: &str) -> String {
    let mut lines: Vec<&str> = body.split('\n').collect();

    // Drop leading blank lines.
    while !lines.is_empty() && lines[0].trim().is_empty() {
        lines.remove(0);
    }

    // Drop a single leading `# ` heading.
    if !lines.is_empty() && lines[0].starts_with("# ") {
        lines.remove(0);
    }

    // Drop subsequent `key: value` lines (no markdown structure) until we
    // hit the first `## ` event-type heading or content.
    while !lines.is_empty() {
        let s = lines[0].trim();
        if s.starts_with("## ") {
            break;
        }
        if s.is_empty() {
            lines.remove(0);
            continue;
        }
        if !s.starts_with('#') && s.contains(':') {
            lines.remove(0);
            continue;
        }
        break;
    }
    lines.join("\n")
}

/// Split `body` on `## ` headings. Returns `[(event_type, body), ...]`.
fn split_event_sections(body: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur_event: Option<String> = None;
    let mut cur_lines: Vec<&str> = Vec::new();
    for ln in body.split('\n') {
        if let Some(rest) = ln.strip_prefix("## ") {
            if let Some(et) = cur_event.take() {
                out.push((et, cur_lines.join("\n").trim().to_string()));
            }
            cur_event = Some(rest.trim().to_string());
            cur_lines.clear();
        } else {
            cur_lines.push(ln);
        }
    }
    if let Some(et) = cur_event {
        out.push((et, cur_lines.join("\n").trim().to_string()));
    }
    out
}

/// Split one event-type section on `### ` subheadings.
fn split_field_sections(section_body: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut cur: Option<String> = None;
    let mut cur_lines: Vec<&str> = Vec::new();
    for ln in section_body.split('\n') {
        if let Some(rest) = ln.strip_prefix("### ") {
            if let Some(name) = cur.take() {
                out.insert(name, cur_lines.join("\n").trim().to_string());
            }
            cur = Some(rest.trim().to_string());
            cur_lines.clear();
        } else {
            cur_lines.push(ln);
        }
    }
    if let Some(name) = cur {
        out.insert(name, cur_lines.join("\n").trim().to_string());
    }
    out
}

/// Parse a markdown policy doc. Mirrors Python `parse_policy_text`.
///
/// `path` is a label only; no I/O performed.
///
/// # Errors
///
/// Returns `Error::Malformed` if a section is missing one of the five
/// required subfields.
pub fn parse_policy_text(text: &str, path: &str) -> Result<PolicyDocument> {
    let (meta, after_frontmatter) = strip_frontmatter(text);
    let body = strip_title(&after_frontmatter);

    let version = meta
        .get("version")
        .cloned()
        .unwrap_or_else(|| "1".to_string());
    let schema = meta
        .get("schema")
        .cloned()
        .unwrap_or_else(|| "tn-agents-policy@v1".to_string());

    let sections = split_event_sections(&body);
    let mut per_event: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for (event_type, section_body) in sections {
        if event_type.is_empty() {
            continue;
        }
        let fields = split_field_sections(&section_body);
        let mut missing: Vec<&str> = Vec::new();
        let mut payload: BTreeMap<String, String> = BTreeMap::new();
        for f in REQUIRED_FIELDS {
            match fields.get(f) {
                Some(v) if !v.is_empty() => {
                    payload.insert((*f).to_string(), v.clone());
                }
                _ => missing.push(f),
            }
        }
        if !missing.is_empty() {
            return Err(Error::Malformed {
                kind: "agents policy",
                reason: format!(
                    "{path}: agents policy section ## {event_type} is missing required \
                     subsection(s): {missing:?}"
                ),
            });
        }
        per_event.insert(event_type, payload);
    }

    let canonical = canonical_bytes_for_hash(&version, &schema, &per_event);
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let content_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    let mut templates: BTreeMap<String, PolicyTemplate> = BTreeMap::new();
    for (event_type, payload) in &per_event {
        templates.insert(
            event_type.clone(),
            PolicyTemplate {
                event_type: event_type.clone(),
                instruction: payload["instruction"].clone(),
                use_for: payload["use_for"].clone(),
                do_not_use_for: payload["do_not_use_for"].clone(),
                consequences: payload["consequences"].clone(),
                on_violation_or_error: payload["on_violation_or_error"].clone(),
                content_hash: content_hash.clone(),
                version: version.clone(),
                path: path.to_string(),
            },
        );
    }

    Ok(PolicyDocument {
        templates,
        version,
        schema,
        path: path.to_string(),
        body: text.to_string(),
        content_hash,
    })
}

/// Canonical absolute path for the policy file given a yaml directory.
pub fn policy_path_for(yaml_dir: &Path) -> PathBuf {
    yaml_dir.join(POLICY_RELATIVE_PATH)
}

/// Load `<yaml_dir>/.tn/config/agents.md` if present.
///
/// Returns `Ok(None)` when the file is absent (no policy → no splice).
///
/// # Errors
///
/// Returns `Error::Io` for filesystem failures, `Error::Malformed` for
/// missing required subsections.
pub fn load_policy_file(yaml_dir: &Path) -> Result<Option<PolicyDocument>> {
    let p = policy_path_for(yaml_dir);
    if !p.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&p)?;
    Ok(Some(parse_policy_text(&text, POLICY_RELATIVE_PATH)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# TN Agents Policy
version: 1
schema: tn-agents-policy@v1

## payment.completed

### instruction
This row records a completed payment.

### use_for
Aggregate reporting.

### do_not_use_for
Credit decisions.

### consequences
Exposure violates GDPR.

### on_violation_or_error
POST https://example.com/escalate

";

    #[test]
    fn parses_minimal_doc() {
        let doc = parse_policy_text(SAMPLE, ".tn/config/agents.md").unwrap();
        assert_eq!(doc.version, "1");
        assert_eq!(doc.schema, "tn-agents-policy@v1");
        let t = &doc.templates["payment.completed"];
        assert_eq!(t.instruction, "This row records a completed payment.");
        assert_eq!(t.use_for, "Aggregate reporting.");
        assert!(t.content_hash.starts_with("sha256:"));
    }

    #[test]
    fn rejects_missing_subsection() {
        let s = "## evt
### instruction
hi
### use_for
hi
### do_not_use_for
hi
### consequences
hi
";
        let err = parse_policy_text(s, ".tn/config/agents.md").unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }));
    }

    #[test]
    fn content_hash_stable() {
        let a = parse_policy_text(SAMPLE, "p").unwrap().content_hash;
        let b = parse_policy_text(SAMPLE, "p").unwrap().content_hash;
        assert_eq!(a, b);
    }
}
