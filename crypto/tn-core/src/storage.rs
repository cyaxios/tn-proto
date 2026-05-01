//! Storage abstraction for log files and keystore blobs.
//!
//! Filesystem-backed only for now; WASM targets (IndexedDB / OPFS) are
//! future work behind a separate feature.

use std::path::Path;

use crate::Result;

/// Minimal byte storage surface: read, write, append, exists.
///
/// Paths are resolved relative to the implementation's root when relative;
/// absolute paths are used as-is.
pub trait Storage: Send + Sync {
    /// Read the full contents of `path`.
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>>;
    /// Overwrite `path` with `data` (creates parents as needed).
    fn write_bytes(&self, path: &Path, data: &[u8]) -> Result<()>;
    /// Append `data` to `path` (creates the file + parents if missing).
    fn append_bytes(&self, path: &Path, data: &[u8]) -> Result<()>;
    /// Whether `path` exists.
    fn exists(&self, path: &Path) -> bool;
}

/// Filesystem-backed `Storage` rooted at `root`.
#[cfg(feature = "fs")]
pub struct FsStorage {
    /// Root directory that relative paths are resolved against.
    pub root: std::path::PathBuf,
}

#[cfg(feature = "fs")]
impl FsStorage {
    /// Construct rooted at `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, p: &Path) -> std::path::PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.root.join(p)
        }
    }
}

#[cfg(feature = "fs")]
impl Storage for FsStorage {
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.resolve(path))?)
    }

    fn write_bytes(&self, path: &Path, data: &[u8]) -> Result<()> {
        let full = self.resolve(path);
        if let Some(p) = full.parent() {
            std::fs::create_dir_all(p)?;
        }
        Ok(std::fs::write(full, data)?)
    }

    fn append_bytes(&self, path: &Path, data: &[u8]) -> Result<()> {
        use std::io::Write;
        let full = self.resolve(path);
        if let Some(p) = full.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(full)?;
        f.write_all(data)?;
        Ok(())
    }

    fn exists(&self, path: &Path) -> bool {
        self.resolve(path).exists()
    }
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;

    #[test]
    fn fs_storage_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let s = FsStorage::new(td.path());
        let rel = Path::new("sub/file.bin");
        assert!(!s.exists(rel));
        s.write_bytes(rel, b"hello").unwrap();
        assert!(s.exists(rel));
        assert_eq!(s.read_bytes(rel).unwrap(), b"hello");
        s.append_bytes(rel, b" world").unwrap();
        assert_eq!(s.read_bytes(rel).unwrap(), b"hello world");
    }
}
