//! Path-template parsing for templated `logs.path` ceremonies. Internal
//! primitive: most readers want the high-level API instead — see
//! [`crate::Runtime`], which renders these templates for you when writing
//! events (behind `tn.info()` / `tn log`). Reach here directly only to
//! resolve a `logs.path` template by hand.
//!
//! TN supports seven template tokens in `logs.path` (matching Python's
//! `LoadedConfig._render_path_template` in `python/tn/config.py`):
//!
//!   - `{event_type}`   — full event type, e.g. `order.created`
//!   - `{event_class}`  — prefix before first `.`, e.g. `order`
//!   - `{event_id}`     — the envelope's unique event_id (uuid7); one file per event
//!   - `{date}`         — UTC YYYY-MM-DD at emit time
//!   - `{yaml_dir}`     — directory containing the ceremony yaml (init-time)
//!   - `{ceremony_id}`  — ceremony id from yaml (init-time)
//!   - `{did}`          — first 16 chars of the publisher DID's last colon-segment (init-time)
//!
//! `{yaml_dir}`, `{ceremony_id}`, `{did}` are static for the
//! runtime's lifetime — we substitute them at parse time. The
//! remaining four tokens are evaluated per emit when [`PathTemplate::render`]
//! is called.
//!
//! `{event_id}` is special: because the id is unique per emit, a
//! template containing it renders to a distinct file for every event.
//! The writer layer ([`crate::log_file::LogWriters`]) detects this via
//! [`PathTemplate::is_per_event`] and uses an open-write-close path
//! (no writer pooling) so a long-running process can't accumulate
//! unbounded file handles.
//!
//! Templates with no per-emit tokens are still wrapped as
//! `PathTemplate` — `render()` returns the same path on every call
//! (resolved against `yaml_dir` if relative). The caller decides
//! whether to use a single writer (literal case) or a writer pool
//! (templated case) based on [`PathTemplate::is_templated`].

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// One piece of a parsed path template.
#[derive(Debug, Clone)]
pub(crate) enum Segment {
    /// Literal text — concatenated as-is.
    Literal(String),
    /// `{event_type}` — substituted at emit time.
    EventType,
    /// `{event_class}` — `event_type.split('.').next()`.
    EventClass,
    /// `{event_id}` — the envelope's unique per-emit id (uuid7).
    EventId,
    /// `{date}` — UTC date as `YYYY-MM-DD`.
    Date,
}

/// Parsed `logs.path` template.
///
/// Built once at `Runtime::init`; `render(event_type)` produces the
/// concrete path for one row. When [`is_templated`](Self::is_templated)
/// is false, every `render` call returns the same path (just resolved
/// against `yaml_dir` if relative).
#[derive(Debug, Clone)]
pub struct PathTemplate {
    segments: Vec<Segment>,
    yaml_dir: PathBuf,
    is_templated: bool,
}

impl PathTemplate {
    /// Parse `template` into segments, pre-substituting the three
    /// init-time tokens. Returns an error for unknown `{...}` tokens
    /// so misconfigured yamls fail at init, not on first emit.
    pub fn parse(template: &str, yaml_dir: &Path, ceremony_id: &str, did: &str) -> Result<Self> {
        // Substitute init-time tokens first. The result still
        // contains per-emit tokens (if any) plus literals.
        let did_short: String = {
            // Match Python's behaviour: take the last colon-segment
            // (or the whole DID if no colon) and truncate to 16
            // chars. Empty DIDs map to empty string.
            let last = did.rsplit(':').next().unwrap_or(did);
            last.chars().take(16).collect()
        };
        let yaml_dir_str = yaml_dir.to_str().unwrap_or("");
        let pre = template
            .replace("{yaml_dir}", yaml_dir_str)
            .replace("{ceremony_id}", ceremony_id)
            .replace("{did}", &did_short);

        // Now scan for remaining `{token}` placeholders.
        let mut segments: Vec<Segment> = Vec::new();
        let mut buf = String::new();
        let mut chars = pre.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if c == '{' {
                // Find the matching `}` and extract the token.
                let close = pre[i..].find('}').map(|j| i + j).ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "logs.path template {template:?}: unclosed '{{' at offset {i}",
                    ))
                })?;
                let token = &pre[i + 1..close];
                if !buf.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut buf)));
                }
                match token {
                    "event_type" => segments.push(Segment::EventType),
                    "event_class" => segments.push(Segment::EventClass),
                    "event_id" => segments.push(Segment::EventId),
                    "date" => segments.push(Segment::Date),
                    other => {
                        return Err(Error::InvalidConfig(format!(
                            "logs.path template {template:?}: unknown token \
                             {{{other}}}. Recognised tokens are: event_type, \
                             event_class, event_id, date (init-time tokens \
                             yaml_dir, ceremony_id, did are already substituted)."
                        )));
                    }
                }
                // Advance the iterator past `}`.
                while let Some(&(j, _)) = chars.peek() {
                    if j > close {
                        break;
                    }
                    chars.next();
                }
            } else {
                buf.push(c);
            }
        }
        if !buf.is_empty() {
            segments.push(Segment::Literal(buf));
        }
        let is_templated = segments.iter().any(|s| !matches!(s, Segment::Literal(_)));
        Ok(PathTemplate {
            segments,
            yaml_dir: yaml_dir.to_path_buf(),
            is_templated,
        })
    }

    /// True iff the template has any per-emit tokens. When false,
    /// `render` returns the same path every time.
    pub fn is_templated(&self) -> bool {
        self.is_templated
    }

    /// True iff the template contains `{event_id}`. Such a template
    /// renders to a unique file per emit, so the writer layer must
    /// open-write-close instead of pooling a writer per rendered path
    /// (which would grow without bound). See
    /// [`crate::log_file::LogWriters::writer_for`].
    pub fn is_per_event(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::EventId))
    }

    /// Substitute per-emit tokens against `event_type` / `event_id`
    /// and return the absolute path. Relative paths resolve against
    /// `yaml_dir`. `event_id` is only consumed by `{event_id}`
    /// templates; pass any value (e.g. `""`) when the template has no
    /// `{event_id}` token.
    pub fn render(&self, event_type: &str, event_id: &str) -> PathBuf {
        // Common case fast path: no per-emit tokens. Single
        // Literal segment.
        if !self.is_templated {
            if let Some(Segment::Literal(lit)) = self.segments.first() {
                let p = Path::new(lit);
                return if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.yaml_dir.join(p)
                };
            }
        }
        let mut s = String::with_capacity(64);
        for seg in &self.segments {
            match seg {
                Segment::Literal(lit) => s.push_str(lit),
                Segment::EventType => s.push_str(event_type),
                Segment::EventClass => {
                    let class = event_type.split('.').next().unwrap_or(event_type);
                    s.push_str(class);
                }
                Segment::EventId => s.push_str(event_id),
                Segment::Date => {
                    use std::fmt::Write as _;
                    let now = time::OffsetDateTime::now_utc();
                    let _ = write!(
                        s,
                        "{:04}-{:02}-{:02}",
                        now.year(),
                        u8::from(now.month()),
                        now.day()
                    );
                }
            }
        }
        let p = Path::new(&s);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.yaml_dir.join(p)
        }
    }

    /// Render a glob-style pattern that matches every concrete path
    /// this template could produce — replacing per-emit tokens with
    /// `*`. Used at init to scan existing files for chain-state
    /// seeding.
    pub fn glob_pattern(&self) -> String {
        let mut s = String::with_capacity(64);
        for seg in &self.segments {
            match seg {
                Segment::Literal(lit) => s.push_str(lit),
                Segment::EventType | Segment::EventClass | Segment::EventId | Segment::Date => {
                    s.push('*')
                }
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_dir() -> PathBuf {
        PathBuf::from("/cer")
    }

    #[test]
    fn literal_path_is_not_templated() {
        let t = PathTemplate::parse("./logs/tn.ndjson", &yaml_dir(), "cer_x", "did:key:z").unwrap();
        assert!(!t.is_templated());
        assert!(!t.is_per_event());
        let p = t.render("any.event", "ignored");
        assert_eq!(
            p,
            PathBuf::from("/cer/logs/tn.ndjson")
                .to_path_buf()
                .canonicalize()
                .unwrap_or(PathBuf::from("/cer/logs/tn.ndjson"))
        );
    }

    #[test]
    fn event_class_templating() {
        let t = PathTemplate::parse(
            "./logs/{event_class}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        assert!(t.is_templated());
        let p1 = t.render("order.created", "");
        let p2 = t.render("payment.captured", "");
        assert_eq!(p1.file_name().unwrap(), "order.ndjson");
        assert_eq!(p2.file_name().unwrap(), "payment.ndjson");
    }

    #[test]
    fn event_type_templating() {
        let t = PathTemplate::parse(
            "./logs/{event_type}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        let p = t.render("order.created", "");
        assert_eq!(p.file_name().unwrap(), "order.created.ndjson");
    }

    #[test]
    fn event_id_templating() {
        let t = PathTemplate::parse(
            "./logs/{event_id}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        assert!(t.is_templated());
        assert!(t.is_per_event());
        // event_type is irrelevant; the id alone drives the file name.
        let p1 = t.render("order.created", "0190aaaa-1111-7000-8000-000000000001");
        let p2 = t.render("order.created", "0190aaaa-1111-7000-8000-000000000002");
        assert_eq!(
            p1.file_name().unwrap(),
            "0190aaaa-1111-7000-8000-000000000001.ndjson"
        );
        assert_eq!(
            p2.file_name().unwrap(),
            "0190aaaa-1111-7000-8000-000000000002.ndjson"
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn event_id_combined_with_class() {
        let t = PathTemplate::parse(
            "./logs/{event_class}/{event_id}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        assert!(t.is_per_event());
        let p = t.render("order.created", "abc-123");
        assert_eq!(p, PathBuf::from("/cer/logs/order/abc-123.ndjson"));
    }

    #[test]
    fn event_id_glob_pattern() {
        let t = PathTemplate::parse(
            "./logs/{event_id}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        assert_eq!(t.glob_pattern(), "./logs/*.ndjson");
    }

    #[test]
    fn init_time_tokens_pre_substituted() {
        let t = PathTemplate::parse(
            "{yaml_dir}/.tn/{ceremony_id}/{did}/log.ndjson",
            &PathBuf::from("/cer"),
            "cer_abc",
            "did:key:z6MkrSAMPLEvalueXX",
        )
        .unwrap();
        // No per-emit tokens left → not templated.
        assert!(!t.is_templated());
        let p = t.render("ignored", "ignored");
        // did_short = "z6MkrSAMPLEvalu" wait — let me recompute.
        // did = "did:key:z6MkrSAMPLEvalueXX", last segment = "z6MkrSAMPLEvalueXX", first 16 chars = "z6MkrSAMPLEvalue"
        assert_eq!(
            p,
            PathBuf::from("/cer/.tn/cer_abc/z6MkrSAMPLEvalue/log.ndjson")
        );
    }

    #[test]
    fn unknown_token_rejected() {
        let err = PathTemplate::parse(
            "./logs/{unknown_tok}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown token"), "got: {msg}");
        assert!(msg.contains("unknown_tok"), "got: {msg}");
    }

    #[test]
    fn unclosed_brace_rejected() {
        let err = PathTemplate::parse(
            "./logs/{event_type.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn glob_pattern_replaces_tokens_with_star() {
        let t = PathTemplate::parse(
            "./logs/{event_class}/{date}.ndjson",
            &yaml_dir(),
            "cer_x",
            "did:key:z",
        )
        .unwrap();
        assert_eq!(t.glob_pattern(), "./logs/*/*.ndjson");
    }

    #[test]
    fn empty_did_handled() {
        let t = PathTemplate::parse("./logs/{did}/log.ndjson", &yaml_dir(), "cer_x", "").unwrap();
        assert!(!t.is_templated());
        let p = t.render("x", "y");
        assert_eq!(p, PathBuf::from("/cer/logs/log.ndjson"));
    }
}
