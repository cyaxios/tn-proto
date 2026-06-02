//! Append-only ndjson file + line iterator.
//!
//! Both reader and writer route every byte through an
//! [`Arc<dyn Storage>`](crate::storage::Storage) handle rather than
//! calling `std::fs::*` directly. The native [`crate::storage::FsStorage`]
//! satisfies these via `std::fs::OpenOptions::append` and
//! `std::fs::read`; on `wasm32-unknown-unknown` the JS-callback
//! adapter does the I/O. The held writer no longer pins an OS file
//! handle — each `append_line` is a single `storage.append_bytes`
//! call. That's slightly slower than a sticky `BufWriter<File>` in
//! the native case, but correctness across the wasm boundary is
//! load-bearing and the per-emit overhead has not shown up in any
//! benchmark yet. Revisit if it does.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::path_template::PathTemplate;
use crate::storage::Storage;
use crate::{Error, Result};

/// Append-only writer for ndjson log files.
///
/// Call `append_line(line)` with a string that already includes the
/// trailing newline. On native (`FsStorage`) backends the writer pins
/// an OS append-mode handle on first emit and reuses it for every
/// subsequent call — one `WriteFile` syscall per emit instead of
/// `CreateFileW + WriteFile + CloseHandle`. On backends that don't
/// expose a pinnable handle (wasm IndexedDB, in-memory test
/// adapters) it falls back to `storage.append_bytes` per call.
///
/// Lifecycle: lazy-open on first `append_line`, hold the handle for
/// the rest of the runtime's lifetime, drop on rotation (when
/// rotation is wired up) or runtime shutdown.
pub struct LogFileWriter {
    path: PathBuf,
    storage: Arc<dyn Storage>,
    /// Pinned append-mode writer. `None` until first append (lazy);
    /// stays `None` for the lifetime of the writer if the storage
    /// backend returned `None` from `open_append_writer` (signals
    /// "no pinned handle available — use append_bytes per call").
    writer: Option<Box<dyn std::io::Write + Send>>,
    /// True once we've attempted to pin a writer and gotten `None`
    /// back. Skips the per-emit `open_append_writer` call on
    /// non-pinnable backends so they don't pay an unnecessary trait
    /// dispatch on every write.
    pinned_unavailable: bool,
    /// Pinned READ handle for tail-byte chain-tip refresh
    /// (`read_tail`). Cached on first call. On Windows, re-opening
    /// a file in read mode while another handle of ours has it open
    /// in append mode takes ~9 ms (share-mode reconciliation or AV
    /// scan) — caching the read handle skips that path completely.
    /// `Mutex` because the runtime holds `LogFileWriter` inside its
    /// own Mutex, so the multiple-emitter case interleaves at this
    /// level too.
    reader: std::sync::Mutex<Option<std::fs::File>>,
    /// True once `OpenOptions::read` returned a non-fs error (wasm,
    /// in-memory adapters, anything whose std::fs is a no-op shim).
    /// Switches `read_tail_if_grown` to go through the
    /// `storage.read_bytes_tail` slow path forever after — the
    /// pinned-handle perf win is FsStorage-only.
    pinned_read_unavailable: std::sync::atomic::AtomicBool,
    /// Last file size we know about — initialised to the on-disk
    /// size at `open()` (so the init-time chain seed counts as
    /// "we know about these bytes"), incremented by every
    /// `append_line` write. The chain-tip refresh consults this
    /// via `read_tail_if_grown`: when the file's current size
    /// matches `our_known_size`, no other process has appended
    /// since our last write, and tip_refresh skips the seek+read.
    /// Saves ~25-30 µs/emit on chain=T profiles for the common
    /// single-writer case.
    our_known_size: std::sync::atomic::AtomicU64,
}

impl LogFileWriter {
    /// Open the writer for `path`. Parent directories are created
    /// via `storage.create_dir_all`. The OS file handle is NOT
    /// opened here — it's lazy-opened on the first `append_line`
    /// (typically the first emit, which is `tn.ceremony.init` for a
    /// fresh ceremony).
    pub fn open(path: &Path, storage: Arc<dyn Storage>) -> Result<Self> {
        if let Some(p) = path.parent() {
            storage.create_dir_all(p)?;
        }
        // 0.4.2a9: terminate a partial trailing line if present. A
        // process killed mid-emit leaves the log ending with a
        // truncated JSON fragment and no `\n`. The next emit
        // appending to that file would concatenate its envelope
        // bytes onto the fragment, producing one big malformed
        // line that breaks all subsequent reads. Detect the
        // missing newline once at open and append one — turns the
        // fragment into its own (still-malformed) line, which the
        // per-row parse-error resilience in the reader and
        // chain-seed code paths can skip past.
        let initial_size = if storage.exists(path) {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                // Read just the last byte. Cheap on any platform.
                let needs_terminator = (|| -> std::io::Result<bool> {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = std::fs::OpenOptions::new().read(true).open(path)?;
                    f.seek(SeekFrom::End(-1))?;
                    let mut last = [0u8; 1];
                    f.read_exact(&mut last)?;
                    Ok(last[0] != b'\n')
                })()
                .unwrap_or(false);
                if needs_terminator {
                    if let Some(mut w) = storage.open_append_writer(path)? {
                        let _ = w.write_all(b"\n");
                        let _ = w.flush();
                    }
                    // Re-read size after the recovery write.
                    std::fs::metadata(path).map(|m| m.len()).unwrap_or(size + 1)
                } else {
                    size
                }
            } else {
                0
            }
        } else {
            0
        };
        Ok(Self {
            path: path.to_path_buf(),
            storage,
            writer: None,
            pinned_unavailable: false,
            reader: std::sync::Mutex::new(None),
            pinned_read_unavailable: std::sync::atomic::AtomicBool::new(false),
            our_known_size: std::sync::atomic::AtomicU64::new(initial_size),
        })
    }

    /// Read up to `max_bytes` from the end of the log via a pinned
    /// read handle. Lazy-opens the handle on first call and reuses
    /// thereafter. Used by the chain-tip refresh on every chain=T
    /// emit; the cached handle skips the ~9 ms NTFS share-mode
    /// reconciliation cost that a fresh `OpenOptions::open(read)`
    /// pays when another handle has the file open in append mode.
    ///
    /// Returns the bytes; the first line may be partial (we sliced
    /// into the middle of a row). Caller (the reverse-scan ndjson
    /// walker) tolerates that.
    pub fn read_tail(&self, max_bytes: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut guard = self.reader.lock().expect("log_file reader mutex poisoned");
        if guard.is_none() {
            // Lazy open. Errors propagate; if the file doesn't
            // exist yet, NotFound is the right return.
            let f = std::fs::OpenOptions::new().read(true).open(&self.path)?;
            *guard = Some(f);
        }
        let f = guard.as_mut().expect("just inserted");
        let len = f.metadata()?.len();
        let start = len.saturating_sub(max_bytes as u64);
        f.seek(SeekFrom::Start(start))?;
        let cap = (len - start) as usize;
        let mut buf = Vec::with_capacity(cap);
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Like [`read_tail`] but returns `Ok(None)` when the file size
    /// matches what we've written ourselves — i.e. no other process
    /// has appended since our last write, and the caller's
    /// in-memory chain state is already current.
    ///
    /// This is the single-writer fast path for the chain-tip
    /// refresh: in the common case (one Python process owning the
    /// log) the file's size matches `our_known_size` and we return
    /// `Ok(None)` after just one cheap `metadata()` call. The
    /// caller then skips the seek+read+parse work entirely.
    ///
    /// Correctness across multi-writer setups is preserved by the
    /// metadata check: if another process appended N bytes, we see
    /// `file_size > our_known_size` and fall through to the same
    /// tail read as `read_tail` — chain integrity is unaffected.
    pub fn read_tail_if_grown(&self, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        // Fallback path for backends whose `std::fs::OpenOptions::read`
        // is a no-op shim (wasm32-unknown-unknown, in-memory test
        // adapters). Once we know the OS doesn't support real fs
        // reads, route every subsequent call through
        // `storage.read_bytes_tail` so the chain-tip refresh still
        // works — just without the FsStorage Windows-AV bypass.
        if self
            .pinned_read_unavailable
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return self.read_tail_via_storage(max_bytes);
        }
        let mut guard = self.reader.lock().expect("log_file reader mutex poisoned");
        if guard.is_none() {
            match std::fs::OpenOptions::new().read(true).open(&self.path) {
                Ok(f) => *guard = Some(f),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(e.into());
                }
                Err(_) => {
                    // Non-fs backend (wasm shim returns "operation
                    // not supported on this platform"). Remember so
                    // subsequent calls skip the std::fs probe, then
                    // serve this call from storage.
                    drop(guard);
                    self.pinned_read_unavailable
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return self.read_tail_via_storage(max_bytes);
                }
            }
        }
        let f = guard.as_mut().expect("just inserted");
        let len = f.metadata()?.len();
        let our_size = self
            .our_known_size
            .load(std::sync::atomic::Ordering::Relaxed);
        if len <= our_size {
            // No bytes beyond what we've written ourselves; nothing
            // to refresh. Caller's in-memory chain state is the
            // authoritative tip.
            return Ok(None);
        }
        // Another writer appended. Read the tail and let the caller
        // re-seed from the new bytes.
        let start = len.saturating_sub(max_bytes as u64);
        f.seek(SeekFrom::Start(start))?;
        let cap = (len - start) as usize;
        let mut buf = Vec::with_capacity(cap);
        f.read_to_end(&mut buf)?;
        // Catch our_known_size up so we don't repeat this read
        // if no further external writes happen — the bytes we
        // just consumed are now "known" to us.
        self.our_known_size
            .store(len, std::sync::atomic::Ordering::Relaxed);
        Ok(Some(buf))
    }

    /// Storage-backed tail read for non-FsStorage backends. The
    /// `our_known_size` skip still applies — when the backend reports
    /// the same file size we've written, no refresh needed.
    fn read_tail_via_storage(&self, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        if !self.storage.exists(&self.path) {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        }
        // No cheap metadata() through the trait; just read the
        // tail every time and let the caller's reverse-scan
        // dedupe via its in-memory chain state.
        let bytes = self.storage.read_bytes_tail(&self.path, max_bytes)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    /// Append `line` (must already include a trailing `\n`).
    ///
    /// Hot path: pinned handle present, one `write_all` syscall.
    /// Slow path: first call on a `FsStorage`-backed writer triggers
    /// `open_append_writer` (one open syscall, cached for the rest
    /// of the lifecycle). Fallback path: `pinned_unavailable` set
    /// (wasm / in-memory backend), per-call `append_bytes`.
    pub fn append_line(&mut self, line: &str) -> Result<()> {
        let line_len = line.len() as u64;
        if let Some(w) = self.writer.as_mut() {
            w.write_all(line.as_bytes())?;
            self.our_known_size
                .fetch_add(line_len, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        if !self.pinned_unavailable {
            // First emit on this writer: try to pin a handle.
            match self.storage.open_append_writer(&self.path)? {
                Some(mut w) => {
                    w.write_all(line.as_bytes())?;
                    self.writer = Some(w);
                    self.our_known_size
                        .fetch_add(line_len, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                None => {
                    // Backend has no pinnable handle (wasm, memory
                    // adapter). Remember so we don't trait-dispatch
                    // through `open_append_writer` on every emit.
                    self.pinned_unavailable = true;
                }
            }
        }
        self.storage.append_bytes(&self.path, line.as_bytes())?;
        self.our_known_size
            .fetch_add(line_len, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Flush OS buffers to disk. On the pinned-handle path this
    /// calls through to the underlying `Write::flush` (which for
    /// `File` is a no-op — Windows page-cache and POSIX page-cache
    /// handle their own flushing, and we don't fsync here). On the
    /// fallback path each `append_bytes` call already round-trips
    /// to storage so there's nothing to flush.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
        }
        Ok(())
    }

    /// Path this writer opened.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Writer dispatcher for emit: literal `logs.path` → one shared
/// writer; templated `logs.path` → lazy pool keyed by rendered path.
///
/// The Runtime swaps `Mutex<LogFileWriter>` for `LogWriters` so a
/// ceremony with `logs: {path: ./.tn/{event_class}.ndjson}` routes
/// each emit to its rendered file — same Rust-accelerated path that
/// non-templated ceremonies use. Before 0.4.2a7 the dispatch layer
/// fell back to the legacy Python emit for templated ceremonies,
/// paying an 18× perf tax. With `LogWriters::Templated`, both
/// shapes run through the same hot path.
pub enum LogWriters {
    /// Single literal path — no templating, one shared writer.
    /// Path is cached separately from the writer so
    /// `path_for(event_type)` doesn't need to acquire the writer
    /// mutex on the hot path.
    Literal {
        /// Resolved absolute path the writer appends to.
        path: PathBuf,
        /// Shared writer handle for that path.
        writer: Arc<Mutex<LogFileWriter>>,
    },
    /// Templated `logs.path`. The first emit of each rendered path
    /// lazy-opens its `LogFileWriter`; subsequent emits to the same
    /// rendered path reuse the cached writer (all the
    /// pinned-handle / offset-skip / lock-cache machinery applies
    /// per writer).
    Templated {
        /// Parsed template — `render(event_type)` produces the
        /// per-emit path.
        template: PathTemplate,
        /// Shared storage handle passed through to each writer.
        storage: Arc<dyn Storage>,
        /// Lazy pool. Outer Mutex protects the HashMap; inner
        /// `Arc<Mutex>` so a caller can clone the writer's Arc out
        /// and drop the pool mutex before locking the writer.
        writers: Mutex<HashMap<PathBuf, Arc<Mutex<LogFileWriter>>>>,
    },
}

impl LogWriters {
    /// Resolve the rendered path for an emit with this event_type /
    /// event_id. Cheap on the literal path (clone of cached PathBuf);
    /// does one template render on the templated path.
    pub fn path_for(&self, event_type: &str, event_id: &str) -> PathBuf {
        match self {
            LogWriters::Literal { path, .. } => path.clone(),
            LogWriters::Templated { template, .. } => template.render(event_type, event_id),
        }
    }

    /// Return (or lazy-create) the writer for a row whose
    /// `event_type` / `event_id` render to a given path. The returned
    /// `Arc<Mutex<LogFileWriter>>` lives independently of the pool
    /// — caller drops the pool mutex before locking the writer.
    ///
    /// `{event_id}` templates ([`PathTemplate::is_per_event`]) render
    /// to a unique path per emit, so pooling a writer per rendered
    /// path would grow the pool — and the OS file-handle count —
    /// without bound. For those we open a *fresh* writer that is NOT
    /// inserted into the pool: the caller appends its single row and
    /// drops the `Arc`, which closes the handle (open-write-close).
    /// Rotation / backup_count are moot for one-row files.
    pub fn writer_for(
        &self,
        event_type: &str,
        event_id: &str,
    ) -> Result<Arc<Mutex<LogFileWriter>>> {
        match self {
            LogWriters::Literal { writer, .. } => Ok(writer.clone()),
            LogWriters::Templated {
                template,
                storage,
                writers,
            } => {
                let path = template.render(event_type, event_id);
                if template.is_per_event() {
                    // Unique path per emit — don't pool. The returned
                    // Arc is the sole reference; once the caller drops
                    // it the handle closes.
                    let w = LogFileWriter::open(&path, storage.clone())?;
                    return Ok(Arc::new(Mutex::new(w)));
                }
                let mut pool = writers.lock().expect("log writers pool mutex poisoned");
                if let Some(existing) = pool.get(&path) {
                    return Ok(existing.clone());
                }
                let w = LogFileWriter::open(&path, storage.clone())?;
                let arc = Arc::new(Mutex::new(w));
                pool.insert(path, arc.clone());
                Ok(arc)
            }
        }
    }

    /// True iff this writer set was constructed from a templated
    /// path (any rendered path may differ per event_type).
    pub fn is_templated(&self) -> bool {
        matches!(self, LogWriters::Templated { .. })
    }

    /// True iff this writer set renders a unique file per emit
    /// (template contains `{event_id}`). Drives the runtime's
    /// lockless open-write-close emit path — see
    /// `Runtime::emit_inner`.
    pub fn is_per_event(&self) -> bool {
        match self {
            LogWriters::Literal { .. } => false,
            LogWriters::Templated { template, .. } => template.is_per_event(),
        }
    }

    /// Consume the writer pool, flushing each writer. Called from
    /// `Runtime::flush_and_close` at shutdown to drain any
    /// buffered state. Errors during flush are swallowed — we're
    /// going down anyway and propagating wouldn't help the caller.
    pub fn flush_all(self) {
        let arcs: Vec<Arc<Mutex<LogFileWriter>>> = match self {
            LogWriters::Literal { writer, .. } => vec![writer],
            LogWriters::Templated { writers, .. } => match writers.into_inner() {
                Ok(pool) => pool.into_values().collect(),
                Err(_) => return,
            },
        };
        for arc in arcs {
            if let Ok(mtx) = Arc::try_unwrap(arc) {
                if let Ok(mut w) = mtx.into_inner() {
                    let _ = w.flush();
                }
            }
        }
    }
}

/// Eager line iterator over an ndjson file.
///
/// Loads the full file into memory at construction time via
/// `storage.read_bytes` and yields one parsed [`serde_json::Value`]
/// per non-empty line. Memory usage is `O(file_size)`; for ceremony-
/// scale logs (single-digit MB) that's fine — the chain seed +
/// `read*` paths each walk the file end-to-end anyway. If logs ever
/// grow to the point where streaming matters, add a
/// `Storage::read_lines` method then.
pub struct LogFileReader {
    lines: std::vec::IntoIter<String>,
}

impl LogFileReader {
    /// Open `path` for reading through `storage`.
    pub fn open(path: &Path, storage: &Arc<dyn Storage>) -> Result<Self> {
        let bytes = storage.read_bytes(path)?;
        let text = String::from_utf8(bytes).map_err(|e| Error::Malformed {
            kind: "log file",
            reason: format!("log file is not valid UTF-8: {e}"),
        })?;
        // Collect into a Vec rather than building a borrow-of-self
        // iterator. Each line is small (one ndjson envelope) and the
        // full file is already in memory; the extra `String` per line
        // is a wash with the parse cost downstream.
        let lines: Vec<String> = text
            .split('\n')
            .map(std::string::ToString::to_string)
            .collect();
        Ok(Self {
            lines: lines.into_iter(),
        })
    }
}

impl Iterator for LogFileReader {
    type Item = Result<Value>;

    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref() {
            let trimmed = line.trim_end_matches('\n');
            if trimmed.is_empty() {
                continue;
            }
            return Some(serde_json::from_str::<Value>(trimmed).map_err(Into::into));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FsStorage;

    fn fs() -> Arc<dyn Storage> {
        Arc::new(FsStorage::new())
    }

    #[test]
    fn write_and_read_two_lines() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join(".tn").join("logs").join("tn.ndjson");
        let storage = fs();
        let mut w = LogFileWriter::open(&p, Arc::clone(&storage)).unwrap();
        w.append_line("{\"a\":1}\n").unwrap();
        w.append_line("{\"b\":2}\n").unwrap();
        w.flush().unwrap();
        drop(w);
        let vals: Vec<Value> = LogFileReader::open(&p, &storage)
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0]["a"], 1);
        assert_eq!(vals[1]["b"], 2);
    }

    #[test]
    fn reader_tolerates_trailing_blank_line() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("tn.ndjson");
        let storage = fs();
        storage
            .write_bytes(&p, b"{\"a\":1}\n\n{\"b\":2}\n")
            .unwrap();
        let vals: Vec<Value> = LogFileReader::open(&p, &storage)
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn append_after_drop_continues_file() {
        // Round 1's writer held a sticky File handle; this round
        // holds only a path + Arc<Storage>. Confirm that opening a
        // fresh writer to the same path after the first is dropped
        // continues the file (no truncation).
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("tn.ndjson");
        let storage = fs();
        {
            let mut w = LogFileWriter::open(&p, Arc::clone(&storage)).unwrap();
            w.append_line("{\"a\":1}\n").unwrap();
        }
        {
            let mut w = LogFileWriter::open(&p, Arc::clone(&storage)).unwrap();
            w.append_line("{\"b\":2}\n").unwrap();
        }
        let vals: Vec<Value> = LogFileReader::open(&p, &storage)
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0]["a"], 1);
        assert_eq!(vals[1]["b"], 2);
    }
}
