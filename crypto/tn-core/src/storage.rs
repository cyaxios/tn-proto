//! Storage abstraction for log files and keystore blobs.
//!
//! Two implementations ship in this crate:
//!
//! * [`FsStorage`] — `std::fs`-backed, gated on the `fs` cargo feature.
//!   The default for every native-target consumer (CLI bin, PyO3 wheel).
//! * Wasm consumers (`tn-wasm`) implement their own `Storage` against
//!   JS-host callbacks, then construct `Runtime` via
//!   [`crate::Runtime::init_with_storage`] passing an `Arc<dyn Storage>`.
//!
//! The trait is **synchronous** by design. Node-side adapters wrap
//! `fs.readFileSync` / `fs.writeFileSync` / etc.; browser-side
//! adapters need a synchronous shim (in-memory cache loaded at init
//! time, or SharedArrayBuffer + Atomics.wait for the future).
//!
//! ## Why this exists
//!
//! `Runtime::init` reads yaml + keystore + agents-md off disk. On
//! `wasm32-unknown-unknown` (the wasm-pack target) `std::fs::*` is
//! stubbed to return `io::Error::Unsupported` at runtime, and worse,
//! the `fs4` advisory-lock crate's transitive dep on `errno` refuses
//! to compile at all. Routing every `Runtime` filesystem call through
//! a `Storage` trait lets the wasm side substitute a JS-callback
//! adapter and gives every other consumer (tests, fuzzers, in-memory
//! sandboxes) an injection point without poking at `std::fs` directly.

use std::io;
use std::path::{Path, PathBuf};

/// Synchronous byte-storage surface used by [`crate::Runtime`].
///
/// All methods take `&self` so a single `Arc<dyn Storage>` can be
/// shared across runtime clones / handlers / admin verbs without
/// locking. Implementations are expected to be `Send + Sync` for the
/// same reason.
///
/// Paths are interpreted as the storage backend sees fit. The default
/// [`FsStorage`] treats absolute paths as absolute and relative paths
/// as relative-to-cwd (no internal root) — `Runtime::init` always
/// hands fully-resolved absolute paths anyway. A wasm storage backend
/// is free to treat the entire `Path` as an opaque key into an
/// IndexedDB / JS-side cache.
pub trait Storage: Send + Sync {
    /// Read the full contents of `path`. Returns [`io::ErrorKind::NotFound`]
    /// if no such entry exists.
    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Overwrite `path` with `data` (creating parents as needed for
    /// fs-backed impls).
    fn write_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()>;

    /// Append `data` to `path` (creating the file + parents if missing).
    fn append_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()>;

    /// Whether `path` exists.
    fn exists(&self, path: &Path) -> bool;

    /// List entries inside `dir`. Returned paths are full paths
    /// (i.e. `dir.join(child_name)`), matching what
    /// `std::fs::read_dir(...).map(|e| e.path())` would yield.
    fn list(&self, dir: &Path) -> io::Result<Vec<PathBuf>>;

    /// Atomic rename from `from` to `to`. Required for the keystore's
    /// tmp+rename atomic-write commit point.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Remove a file (no-op for missing entries — match `fs::remove_file`
    /// semantics that bubble `NotFound`).
    fn remove(&self, path: &Path) -> io::Result<()>;

    /// Recursively create `dir` and any missing parents.
    fn create_dir_all(&self, dir: &Path) -> io::Result<()>;

    /// Atomic compare-and-swap write of `path`. The contract:
    /// 1. Lock the entry (or its sibling lock file) exclusively.
    /// 2. Read current contents (or `None` if missing).
    /// 3. If current != `prior`, return [`io::ErrorKind::AlreadyExists`]
    ///    so the caller can recognise the CAS failure.
    /// 4. Otherwise atomically replace with `new`.
    ///
    /// Used by `keystore_backend::LocalKeystore::write_state`. Native
    /// `FsStorage` implements this via `fs4` (when the `fs-locking`
    /// feature is on) or a best-effort tmp+rename (when it's off — on
    /// `wasm32` there's no other process to race against). Wasm
    /// adapters typically implement CAS via a single IndexedDB
    /// transaction (the JS side gives us the primitive).
    fn cas_write(&self, path: &Path, prior: Option<&[u8]>, new: &[u8]) -> io::Result<()>;

    /// Acquire an advisory cross-process lock on `path` for the
    /// duration of `f`. On native `FsStorage` with `fs-locking`, this
    /// uses `fs4`'s `flock`/`LockFileEx`. On wasm (single-threaded,
    /// single-process), the lock is a no-op — `f()` runs immediately.
    ///
    /// Implementations should pass through `f`'s return value
    /// unchanged. The `io::Result<R>` wrapping is for the lock
    /// acquisition itself (open + flock); `f` is expected to handle
    /// its own errors.
    ///
    /// Default no-op implementation is provided so wasm adapters
    /// don't need to override it.
    fn with_advisory_lock(
        &self,
        path: &Path,
        f: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let _ = path;
        f()
    }
}

// ---------------------------------------------------------------------------
// FsStorage — std::fs-backed, gated on the `fs` cargo feature.
// ---------------------------------------------------------------------------

/// `std::fs`-backed [`Storage`].
///
/// Stateless: absolute paths are used as-is, relative paths resolve
/// against the process cwd. The previous "rooted at" variant was
/// removed when `Runtime::init` started resolving paths against the
/// yaml dir before they reach storage — having two layers of "where
/// is this relative to" was just confusing.
#[cfg(feature = "fs")]
#[derive(Debug, Default)]
pub struct FsStorage;

#[cfg(feature = "fs")]
impl FsStorage {
    /// Construct a fresh `FsStorage`. Stateless — every instance is
    /// equivalent.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "fs")]
impl Storage for FsStorage {
    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn write_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, data)
    }

    fn append_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        f.write_all(data)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            out.push(e.path());
        }
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    fn cas_write(&self, path: &Path, prior: Option<&[u8]>, new: &[u8]) -> io::Result<()> {
        // Native CAS: acquire the sibling .lock, re-read, compare,
        // atomic-write. Mirrors the body of
        // keystore_backend::LocalKeystore::write_state from before the
        // Storage abstraction landed — that function now delegates
        // here so wasm consumers can supply their own primitive.
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;

        let lock_path = {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("tn_cas");
            parent.join(format!("{file_name}.lock"))
        };

        // We hand the lock setup to the `with_advisory_lock` helper so
        // a backend that turns off `fs-locking` gets a clean no-op
        // path without bypassing the rest of the CAS dance.
        self.with_advisory_lock(&lock_path, &mut || {
            // Under the lock: re-read on-disk state and compare.
            let current = if path.exists() {
                Some(std::fs::read(path)?)
            } else {
                None
            };
            if current.as_deref() != prior {
                // AlreadyExists is the closest stdlib variant to
                // "CAS pre-image mismatch"; callers should match
                // the kind not the message.
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "cas_write: prior snapshot does not match on-disk state",
                ));
            }
            atomic_write_via_tmp(path, new)
        })
    }

    #[cfg(feature = "fs-locking")]
    fn with_advisory_lock(
        &self,
        path: &Path,
        f: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        use fs4::fs_std::FileExt;
        // Open (creating if missing) the lock file. We never write to
        // it; the lock itself lives in OS-kernel state keyed on the
        // file's inode.
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        lock_file.lock_exclusive()?;
        let res = f();
        // Lock is released when `lock_file` is dropped at scope exit.
        // We want to keep `lock_file` alive across `f()` so we hold it
        // explicitly via the trailing drop:
        drop(lock_file);
        res
    }

    // When the `fs-locking` feature is off we inherit the trait
    // default (`f()` with no locking). That's intentional for wasm:
    // single-process, single-threaded — there is no other writer to
    // race against, so the lock would only block ourselves.
}

/// Atomic tmp+fsync+rename helper. Public-in-crate because
/// `keystore_backend::atomic_write_bytes` re-exports the same shape;
/// keeping one implementation here means CAS goes through the same
/// code path.
#[cfg(feature = "fs")]
fn atomic_write_via_tmp(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("tn_atomic");
    let tmp = parent.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    let res = (|| -> io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;

    #[test]
    fn fs_storage_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let s = FsStorage::new();
        let p = td.path().join("sub").join("file.bin");
        assert!(!s.exists(&p));
        s.write_bytes(&p, b"hello").unwrap();
        assert!(s.exists(&p));
        assert_eq!(s.read_bytes(&p).unwrap(), b"hello");
        s.append_bytes(&p, b" world").unwrap();
        assert_eq!(s.read_bytes(&p).unwrap(), b"hello world");
    }

    #[test]
    fn fs_storage_cas_first_write_succeeds() {
        let td = tempfile::tempdir().unwrap();
        let s = FsStorage::new();
        let p = td.path().join("state.bin");
        s.cas_write(&p, None, b"v1").unwrap();
        assert_eq!(s.read_bytes(&p).unwrap(), b"v1");
    }

    #[test]
    fn fs_storage_cas_stale_prior_rejected() {
        let td = tempfile::tempdir().unwrap();
        let s = FsStorage::new();
        let p = td.path().join("state.bin");
        s.cas_write(&p, None, b"v1").unwrap();
        let err = s
            .cas_write(&p, Some(b"v0"), b"v2")
            .expect_err("stale prior must error");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn fs_storage_cas_fresh_prior_succeeds() {
        let td = tempfile::tempdir().unwrap();
        let s = FsStorage::new();
        let p = td.path().join("state.bin");
        s.cas_write(&p, None, b"v1").unwrap();
        s.cas_write(&p, Some(b"v1"), b"v2").unwrap();
        assert_eq!(s.read_bytes(&p).unwrap(), b"v2");
    }
}
