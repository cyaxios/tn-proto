//! Chain-state seeding from existing logs / ceremony templates.
//!
//! Split out of `runtime.rs` (file-size refactor). Behavior unchanged;
//! `use super::*` re-imports everything these helpers need from the parent.

use super::*;

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
pub(crate) fn scan_for_ceremony_init(
    path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
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

