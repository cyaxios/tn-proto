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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

use crate::storage::Storage;
use crate::{Error, Result};

/// Append-only writer for ndjson log files.
///
/// Call `append_line(line)` with a string that already includes the
/// trailing newline. Each call goes straight to
/// `storage.append_bytes`; there is no in-memory buffer to flush. The
/// `flush()` method is retained for source-compat with the previous
/// `BufWriter<File>`-backed shape — it's a no-op today.
pub struct LogFileWriter {
    path: PathBuf,
    storage: Arc<dyn Storage>,
}

impl LogFileWriter {
    /// Open (creating if missing) `path` in append mode. Parent
    /// directories are created through `storage.create_dir_all` so
    /// the very first emit lands cleanly even on a fresh
    /// `FsStorage`/wasm filesystem.
    ///
    /// Unlike the previous `OpenOptions::append` shape, this does not
    /// hold an OS file handle — every subsequent
    /// [`Self::append_line`] re-opens via `storage.append_bytes`. On
    /// native that's `std::fs::OpenOptions::new().append(true)`; on
    /// wasm it's a single JS callback per append.
    pub fn open(path: &Path, storage: Arc<dyn Storage>) -> Result<Self> {
        if let Some(p) = path.parent() {
            storage.create_dir_all(p)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            storage,
        })
    }

    /// Append `line` (must already include a trailing `\n`).
    pub fn append_line(&mut self, line: &str) -> Result<()> {
        self.storage.append_bytes(&self.path, line.as_bytes())?;
        Ok(())
    }

    /// Flush OS buffers to disk. No-op today — each `append_line`
    /// already round-trips to storage. Kept on the public API so
    /// callers can still call `.flush()` for symmetry with the
    /// pre-Storage shape.
    pub fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Path this writer opened.
    pub fn path(&self) -> &Path {
        &self.path
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
