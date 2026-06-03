//! Session-start log rotation and init-time chain seeding.
//!
//! The disk-side helpers [`Runtime::init`](super::Runtime::init) runs
//! before it hands back a ready runtime: the process-scoped rotation
//! guard, the stdlib-style numbered-backup roll, the per-event_type chain
//! seed (literal and templated log paths), and the `tn.ceremony.init`
//! fresh-detection scan. None of these take a `Runtime`; they operate on
//! paths + the shared [`Storage`](crate::storage::Storage) handle so the
//! wasm adapter can satisfy the I/O.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;
use time::OffsetDateTime;

use crate::chain::ChainState;
use crate::log_file::{LogFileReader, LogFileWriter, LogWriters};
use crate::path_template::PathTemplate;
use crate::Result;

use super::util::is_absolute_xplat_path;

/// Process-scoped rotation guard.
///
/// Returns `true` the first time this process is asked to rotate
/// `log_path`, `false` on every subsequent call for the same path.
///
/// Why: `Runtime::init` is called both for a fresh process start
/// (where rotation is the right behavior — the previous session ended
/// and we want a clean log) AND for in-process re-init (where rotation
/// would discard work the caller just wrote and break the chain). The
/// guard distinguishes the two: a path that has not been seen this
/// process is a new session; a path we have already rotated must be a
/// re-init.
pub(crate) fn rotation_first_time_this_process(log_path: &Path) -> bool {
    static ROTATED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let set = ROTATED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match set.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Use a key that is stable across the file's existence transitions:
    // canonicalize the parent directory (which always exists by this
    // point because chain seeding has run) and append the filename.
    // We cannot canonicalize `log_path` itself: on the FIRST init the
    // file does not exist yet, canonicalize fails, and we fall back to
    // the raw path; on the SECOND init the file exists, canonicalize
    // succeeds, and the returned absolute path differs from the first
    // run's key — so the guard's HashSet sees them as distinct paths.
    let key = if let Some(parent) = log_path.parent() {
        let canon_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        match log_path.file_name() {
            Some(name) => canon_parent.join(name),
            None => canon_parent,
        }
    } else {
        log_path.to_path_buf()
    };
    guard.insert(key)
}

/// Pull `(rotate_on_init, backup_count)` from the yaml `handlers:`
/// list. Defaults: rotate OFF, backup_count = 5. Looks at the first
/// `file.rotating` entry — multiple file handlers in one yaml is an
/// edge case we don't model; whichever appears first wins.
///
/// **Default off** because TN logs are an attestation chain — the
/// `prev_hash`/`row_hash` chain spans the file in append-only fashion,
/// and rotating at session start would break verification across the
/// rotation boundary. Operators who want a separate file per session
/// (e.g. for size management) can opt in via yaml
/// `handlers[*].rotate_on_init: true`. The process-scoped guard in
/// `rotation_first_time_this_process` still applies on top so that
/// in-process re-init never rotates regardless of the yaml.
pub(crate) fn read_rotation_config(handlers: &[serde_yml::Value]) -> (bool, usize) {
    for h in handlers {
        let kind = h.get("kind").and_then(|v| v.as_str());
        if kind != Some("file.rotating") && kind != Some("file") {
            continue;
        }
        let rotate = h
            .get("rotate_on_init")
            .and_then(serde_yml::Value::as_bool)
            .unwrap_or(false);
        let backup_count = h
            .get("backup_count")
            .and_then(serde_yml::Value::as_u64)
            .map_or(5, |n| usize::try_from(n).unwrap_or(5));
        return (rotate, backup_count);
    }
    (false, 5)
}

/// Roll an existing non-empty log file to `<name>.1`, shifting any
/// existing numbered backups forward (`.1` → `.2`, `.2` → `.3`, ...,
/// up to `backup_count`). The `<name>.<backup_count>` slot is dropped
/// to keep the on-disk footprint bounded. Mirrors stdlib
/// `logging.handlers.RotatingFileHandler.doRollover` semantics.
///
/// Best-effort: filesystem errors (permission denied, race with
/// another process, missing parent) are logged and swallowed so a
/// rotation hiccup never blocks `Runtime::init`. The new session
/// falls through to writing into the existing file in that case.
pub(crate) fn rotate_log_on_session_start(
    log_path: &Path,
    backup_count: usize,
    storage: &Arc<dyn crate::storage::Storage>,
) {
    // Treat "missing" and "empty" the same: nothing to rotate. The
    // pre-Storage version checked metadata.len() to distinguish, but
    // the Storage trait doesn't expose file size — and a read-then-
    // check-len round-trip would be no cheaper than the rotate
    // itself. So peek via `read_bytes` and treat zero-length as
    // "skip rotation" (same external observable behaviour).
    match storage.read_bytes(log_path) {
        Ok(bytes) if bytes.is_empty() => return,
        Ok(_) => {}
        Err(_) => return, // missing or unreadable — nothing to rotate
    }

    // Walk backwards: drop the oldest, then shift each `.N` → `.N+1`.
    let max_n = backup_count.max(1);
    let oldest = path_with_backup_suffix(log_path, max_n);
    let _ = storage.remove(&oldest); // ignore "not found"
    for n in (1..max_n).rev() {
        let from = path_with_backup_suffix(log_path, n);
        let to = path_with_backup_suffix(log_path, n + 1);
        if storage.exists(&from) {
            if let Err(e) = storage.rename(&from, &to) {
                log::warn!(
                    "session rotation: failed to shift {} → {}: {e}",
                    from.display(),
                    to.display(),
                );
            }
        }
    }
    // Finally rename current → .1.
    let dot_one = path_with_backup_suffix(log_path, 1);
    if let Err(e) = storage.rename(log_path, &dot_one) {
        log::warn!(
            "session rotation: failed to roll {} → {}: {e}",
            log_path.display(),
            dot_one.display(),
        );
    }
}

/// `<name>` → `<name>.<n>` (e.g. `tn.ndjson` → `tn.ndjson.1`).
pub(crate) fn path_with_backup_suffix(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Seed chain state from a log file and return whether `tn.ceremony.init`
/// was present in that file.
pub(crate) fn seed_chain_from_log(
    log_path: &Path,
    chain: &ChainState,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    if !storage.exists(log_path) {
        return Ok(false);
    }
    let mut latest: HashMap<String, (u64, String)> = HashMap::new();
    let mut saw_ceremony_init = false;
    // 0.4.2a9: tolerate malformed lines during the chain-seed scan.
    // A process killed mid-emit leaves a partial JSON line at the
    // file tail; the prior version propagated that parse error and
    // crashed `tn.init` on every subsequent run, leaving the
    // operator with no graceful recovery. Mirror the per-row
    // resilience that `seed_chain_from_template` (and the runtime
    // read path) already have: skip the bad line, keep walking,
    // seed from whatever survived.
    for res in LogFileReader::open(log_path, storage)? {
        let env = match res {
            Ok(v) => v,
            Err(_) => continue, // skip malformed/truncated row, keep scanning
        };
        let et = match env.get("event_type").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if et == "tn.ceremony.init" {
            saw_ceremony_init = true;
        }
        let seq = match env.get("sequence").and_then(Value::as_u64) {
            Some(s) => s,
            None => continue,
        };
        let rh = match env.get("row_hash").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        latest.insert(et, (seq, rh));
    }
    chain.seed(latest);
    Ok(saw_ceremony_init)
}

/// Seed chain state from EVERY `.ndjson` file under the template's
/// parent directory. The templated counterpart of [`seed_chain_from_log`].
///
/// Templated `logs.path` (e.g. `./logs/{event_class}.ndjson`) renders
/// to N different files at emit time — one per event_class/event_type/
/// date combination. On restart the in-memory chain state has to be
/// seeded from ALL of them, otherwise the first emit after restart
/// resets `sequence=1 prev_hash=ZERO` for every event_type and
/// corrupts chain verification. Mirrors `python/tn/logger.py::
/// _seed_chain_from_logs` which scanned the log directory file-by-
/// file before chain=T templated ceremonies got Rust support
/// (0.4.2a7).
///
/// Resolves the parent directory from the template's static prefix
/// (everything before the first wildcard) and walks it
/// non-recursively. Templates that put per-emit tokens in
/// directory segments (e.g. `./logs/{date}/{event_class}.ndjson`)
/// still get the most-recent-day's parent directory scanned but
/// won't pick up older days; for that level of templating you'd
/// need a recursive walk, which we defer until someone actually
/// uses that shape.
///
/// Tolerant to malformed lines, missing fields, and unreadable
/// files — matches the Python helper's behaviour of "best-effort
/// seed, never block init."
pub(crate) fn seed_chain_from_template(
    template: &crate::path_template::PathTemplate,
    chain: &ChainState,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    // Resolve the parent directory we'll walk. Use `render` with a
    // placeholder event_type and take its parent — that gives us the
    // absolute path with yaml_dir already resolved.
    let sample = template.render("__seed_probe__", "__seed_probe__");
    let Some(parent_dir) = sample.parent() else {
        return Ok(false);
    };
    if !storage.exists(parent_dir) {
        return Ok(false);
    }
    let entries = match storage.list(parent_dir) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let mut latest: HashMap<String, (u64, String)> = HashMap::new();
    let mut saw_ceremony_init = false;
    for entry in entries {
        if entry.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue;
        }
        // Best-effort per file: a malformed file shouldn't block
        // seeding from other files. The Python equivalent's
        // try/except OSError around the file open is mirrored here.
        let reader = match LogFileReader::open(&entry, storage) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for res in reader {
            let env = match res {
                Ok(v) => v,
                Err(_) => continue, // skip malformed rows
            };
            let et = match env.get("event_type").and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if et == "tn.ceremony.init" {
                saw_ceremony_init = true;
            }
            let seq = match env.get("sequence").and_then(Value::as_u64) {
                Some(s) => s,
                None => continue,
            };
            let rh = match env.get("row_hash").and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Max-sequence-wins per event_type across all scanned
            // files. The same event_type can appear in multiple
            // rendered files only when the template doesn't isolate
            // by event_type (e.g. `{date}.ndjson` mixes types per
            // day). Per-event_type chain tip is the highest
            // sequence we observe anywhere.
            let prior_seq = latest.get(&et).map(|(s, _)| *s).unwrap_or(0);
            if seq > prior_seq {
                latest.insert(et, (seq, rh));
            }
        }
    }
    chain.seed(latest);
    Ok(saw_ceremony_init)
}

/// Scan a single ndjson file for any line whose `event_type` is `tn.ceremony.init`.
/// Returns `true` if found, `false` if file absent or not found.
pub(crate) fn scan_for_ceremony_init(path: &Path, storage: &Arc<dyn crate::storage::Storage>) -> Result<bool> {
    if !storage.exists(path) {
        return Ok(false);
    }
    for res in LogFileReader::open(path, storage)? {
        let env = res?;
        if env.get("event_type").and_then(|v| v.as_str()) == Some("tn.ceremony.init") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve the protocol-events-location template without a Runtime instance.
///
/// Only expands `{event_class}` to `"ceremony"` (the class of `tn.ceremony.init`),
/// plus `{yaml_dir}`, `{ceremony_id}`, and `{did}`. `{event_type}` becomes
/// `"tn.ceremony.init"`. `{date}` is not required for fresh-detection purposes;
/// the file either exists or it doesn't regardless of date.
pub(crate) fn resolve_pel_static(tmpl: &str, yaml_dir: &Path, ceremony_id: &str, did: &str) -> PathBuf {
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date = OffsetDateTime::now_utc()
        .format(&date_fmt)
        .unwrap_or_else(|_| "1970-01-01".to_string());
    let yaml_dir_s = yaml_dir.to_string_lossy().into_owned();
    // `{event_class}` is the first dotted segment of `tn.ceremony.init`
    // = `tn` (matches Python/PathTemplate, not the prior `nth(1)`
    // shorthand which would yield `ceremony`). The init-time fresh-
    // detection scan and the emit-time write must agree on the
    // rendered path, otherwise restart re-emits `tn.ceremony.init`.
    let filled = tmpl
        .replace("{event_type}", "tn.ceremony.init")
        .replace("{event_class}", "tn")
        .replace("{date}", &date)
        .replace("{yaml_dir}", &yaml_dir_s)
        .replace("{ceremony_id}", ceremony_id)
        .replace("{did}", did);
    // Anchor relative templates at the yaml dir — same fix as
    // ``Runtime::resolve_pel``. Without it, fresh-detection scans the
    // wrong file (process cwd) and we end up emitting tn.ceremony.init
    // twice on a re-init.
    let p = PathBuf::from(filled);
    if is_absolute_xplat_path(&p) {
        p
    } else {
        yaml_dir.join(p)
    }
}

/// Build the protocol-event-location writer pool that mirrors the main
/// `log_writer` for `tn.*` admin events. Lifted out of
/// [`Runtime::init`](super::Runtime).
///
/// When `pel_raw == "main_log"`, returns a shadow of `log_writer` (Arc
/// clones for a literal path, a fresh pool for a templated one) so
/// `flush_all` stays symmetric even though emit-time `pel_routed` is
/// always false in that mode and the field is never read. Otherwise parses
/// the PEL template and opens its own literal writer or lazy pool.
///
/// # Errors
///
/// Propagates [`PathTemplate::parse`] and [`LogFileWriter::open`] errors.
pub(crate) fn build_pel_writer(
    log_writer: &LogWriters,
    pel_raw: &str,
    yaml_dir: &Path,
    ceremony_id: &str,
    did: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<LogWriters> {
    if pel_raw == "main_log" {
        return Ok(match log_writer {
            LogWriters::Literal { path, writer } => LogWriters::Literal {
                path: path.clone(),
                writer: writer.clone(),
            },
            LogWriters::Templated {
                template,
                storage: stor,
                ..
            } => LogWriters::Templated {
                template: template.clone(),
                storage: Arc::clone(stor),
                writers: Mutex::new(HashMap::new()),
            },
        });
    }
    let pel_template = PathTemplate::parse(pel_raw, yaml_dir, ceremony_id, did)?;
    if pel_template.is_templated() {
        Ok(LogWriters::Templated {
            template: pel_template,
            storage: Arc::clone(storage),
            writers: Mutex::new(HashMap::new()),
        })
    } else {
        let path = pel_template.render("", "");
        let writer = LogFileWriter::open(&path, Arc::clone(storage))?;
        Ok(LogWriters::Literal {
            path,
            writer: Arc::new(Mutex::new(writer)),
        })
    }
}
