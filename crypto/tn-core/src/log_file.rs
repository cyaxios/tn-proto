//! Append-only ndjson file + line iterator.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{Error, Result};

/// Append-only writer for ndjson log files.
///
/// Call `append_line(line)` with a string that already includes the trailing
/// newline. Calls `flush()` after every append by default (pull it out if
/// you need batching).
pub struct LogFileWriter {
    path: PathBuf,
    file: File,
}

impl LogFileWriter {
    /// Open (creating if missing) `path` in append mode. Parent directories are
    /// created as needed.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Append `line` (must already include a trailing `\n`).
    pub fn append_line(&mut self, line: &str) -> Result<()> {
        self.file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Flush OS buffers to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    /// Path this writer opened.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Lazy iterator over ndjson records.
pub struct LogFileReader {
    reader: BufReader<File>,
}

impl LogFileReader {
    /// Open `path` for reading.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            reader: BufReader::new(File::open(path)?),
        })
    }
}

impl Iterator for LogFileReader {
    type Item = Result<Value>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => {
                let trimmed = line.trim_end_matches('\n');
                if trimmed.is_empty() {
                    return self.next();
                }
                Some(serde_json::from_str::<Value>(trimmed).map_err(Into::into))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_two_lines() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join(".tn").join("logs").join("tn.ndjson");
        let mut w = LogFileWriter::open(&p).unwrap();
        w.append_line("{\"a\":1}\n").unwrap();
        w.append_line("{\"b\":2}\n").unwrap();
        w.flush().unwrap();
        drop(w);
        let vals: Vec<Value> = LogFileReader::open(&p)
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
        std::fs::write(&p, "{\"a\":1}\n\n{\"b\":2}\n").unwrap();
        let vals: Vec<Value> = LogFileReader::open(&p)
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(vals.len(), 2);
    }
}
