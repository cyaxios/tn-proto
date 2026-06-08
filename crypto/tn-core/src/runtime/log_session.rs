//! Log lifecycle helpers: session-start rotation and foreign-log reads.
//!
//! Split out of `runtime.rs` (file-size refactor). Behavior unchanged;
//! `use super::*` re-imports everything these helpers need from the parent.

use super::*;

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
        let canon_parent =
            std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
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
        let rotate = h.get("rotate_on_init").and_then(serde_yml::Value::as_bool).unwrap_or(false);
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

/// True iff `log_path` is a foreign publisher's log (different `did`
/// on the first envelope) AND we have a kit on disk that could decrypt
/// it. Used by [`Runtime::read_from`] to auto-route cross-publisher
/// reads through the foreign-decrypt path. Mirrors Python's
/// `_is_foreign_log` and TS's `_isForeignLog`.
///
/// Conservative on failure: if the file is unreadable, has no
/// parseable line, lacks our default kit, or is exactly our own log,
/// return false so the regular path runs and surfaces the underlying
/// error itself.
pub(crate) fn is_foreign_log(
    log_path: &Path,
    own_log: &Path,
    own_did: &str,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> bool {
    // Exempt exactly our own log path — post-flush "reading my own log"
    // case where the auto-discovery cfg may have a different device but
    // the log is conceptually own. Narrowed per AVL J7.1 Bug 2.
    // `canonicalize` is filesystem-only (resolves symlinks) and has
    // no Storage equivalent; we keep it as a native shortcut. On wasm
    // it'll just fail (no symlinks) and we fall through to comparing
    // raw paths via the rest of the logic.
    if let (Ok(a), Ok(b)) = (log_path.canonicalize(), own_log.canonicalize()) {
        if a == b {
            return false;
        }
    }

    // No kit on disk → foreign route guaranteed to yield $no_read_key
    // for every entry. Regular path's "kit not entitled" is more
    // actionable, so let it run.
    if !storage.exists(&keystore.join("default.btn.mykit")) {
        return false;
    }

    // Peek the first parseable envelope's `did`.
    let Ok(bytes) = storage.read_bytes(log_path) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    for raw_line in text.split('\n') {
        let s = raw_line.trim();
        if s.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<Value>(s) else {
            continue;
        };
        if let Some(env_did) = env.get("device_identity").and_then(Value::as_str) {
            if !env_did.is_empty() {
                return env_did != own_did;
            }
        }
        // First non-empty line had no did — give up; let regular path run.
        return false;
    }
    false
}

/// Decrypt a foreign publisher's log, attempting EVERY group for which
/// the local keystore holds a `<group>.btn.mykit` kit. Mirrors what the
/// regular `read_from` path does (try every group the runtime knows
/// about) so `secure_read`'s `tn.agents` instructions splice surfaces
/// correctly even when the log is foreign.
///
/// Calls [`crate::read_as_recipient::read_as_recipient`] once per
/// kit-bearing group, then merges the per-group results back into a
/// single per-envelope `ReadEntry`. The signature/chain `valid` block
/// is dropped here; `secure_read` recomputes verification from the
/// envelope itself.
pub(crate) fn read_foreign_log(
    log_path: &Path,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<ReadEntry>> {
    use crate::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};

    // Discover every group the keystore has a kit for. The foreign
    // route is btn-only today (read_as_recipient errors out on JWE
    // keys) so we only scan `<group>.btn.mykit`.
    let mut groups: Vec<String> = Vec::new();
    if let Ok(entries) = storage.list(keystore) {
        for path in entries {
            let Some(s) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(stem) = s.strip_suffix(".btn.mykit") {
                if !stem.is_empty() {
                    groups.push(stem.to_string());
                }
            }
        }
    }
    if groups.is_empty() {
        // No kits at all — fall through to the single-group default
        // path so the underlying error message is "no recipient kit
        // for group 'default'" rather than a silently-empty result.
        groups.push("default".to_string());
    }
    groups.sort();

    // Run the foreign-decrypt iterator once per group. Each pass
    // produces a list of `ForeignReadEntry`s in log order; merge them
    // by envelope into a single `ReadEntry` whose `plaintext_per_group`
    // carries one decrypted block per kit-holding group.
    let mut envelopes: Vec<Map<String, Value>> = Vec::new();
    let mut merged_plaintext: Vec<BTreeMap<String, Value>> = Vec::new();
    for (idx, group) in groups.iter().enumerate() {
        let opts = ReadAsRecipientOptions {
            group: group.clone(),
            verify_signatures: true,
        };
        let foreign = read_as_recipient(log_path, keystore, opts)?;
        if idx == 0 {
            envelopes.reserve(foreign.len());
            merged_plaintext.reserve(foreign.len());
            for e in foreign {
                envelopes.push(e.envelope);
                let mut pt: BTreeMap<String, Value> = BTreeMap::new();
                for (gname, val) in e.plaintext {
                    pt.insert(gname, val);
                }
                merged_plaintext.push(pt);
            }
        } else {
            for (i, e) in foreign.into_iter().enumerate() {
                if i >= merged_plaintext.len() {
                    break;
                }
                for (gname, val) in e.plaintext {
                    merged_plaintext[i].insert(gname, val);
                }
            }
        }
    }

    let mut out = Vec::with_capacity(envelopes.len());
    for (env, pt) in envelopes.into_iter().zip(merged_plaintext.into_iter()) {
        out.push(ReadEntry {
            envelope: Value::Object(env),
            plaintext_per_group: pt,
        });
    }
    Ok(out)
}

