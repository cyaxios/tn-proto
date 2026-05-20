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

    /// Read at most the last `max_bytes` of `path`. If the file is
    /// smaller than the window, returns the whole file. Used by the
    /// emit-time chain-tip refresh to avoid reading megabytes of log
    /// on every emit just to find the latest row — the tip is almost
    /// always within the last few KB of the file.
    ///
    /// The default impl is correct-but-slow (calls `read_bytes` then
    /// slices the tail). `FsStorage` overrides with a
    /// `seek(SeekFrom::End)` + `read_to_end` for the fast path; on
    /// NTFS this drops chain-mode emit latency from ~10 ms (whole-
    /// file read of a 1 MB log) to ~50 µs.
    ///
    /// Caller-side note: the first line of the returned buffer may
    /// be a partial line (we sliced into the middle of a row). The
    /// reverse-scan ndjson walker handles that — `serde_json::from_slice`
    /// fails on the partial leading line and the helper silently
    /// skips it.
    fn read_bytes_tail(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        let bytes = self.read_bytes(path)?;
        if bytes.len() <= max_bytes {
            return Ok(bytes);
        }
        Ok(bytes[bytes.len() - max_bytes..].to_vec())
    }

    /// Open `path` for append-only writes and return a pinned writer
    /// suitable for repeated emits. The caller holds the returned
    /// writer for as long as it needs and calls `write_all` (then
    /// optionally `flush`) on it per emit — saving the open + close
    /// syscalls that `append_bytes` pays on every call.
    ///
    /// Returning `Ok(None)` instructs the caller to fall back to
    /// `append_bytes` per write. This is appropriate for storage
    /// backends that don't have an OS-level append-mode handle to
    /// pin (in-memory, IndexedDB, wasm). The default implementation
    /// returns `None` so non-fs backends stay correct without
    /// overriding.
    ///
    /// Fs-backed implementations should override to return
    /// `Ok(Some(writer))` wrapping a long-lived `File` opened with
    /// `O_APPEND | O_CREAT` (or the Windows equivalent). On NTFS
    /// this saves ~200 µs per emit relative to `OpenOptions::open`
    /// every time. See `LogFileWriter` for the consumer.
    fn open_append_writer(
        &self,
        path: &Path,
    ) -> io::Result<Option<Box<dyn io::Write + Send>>> {
        let _ = path;
        Ok(None)
    }

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
pub struct FsStorage {
    /// Per-path lock-file handle cache (0.4.2a7 perf fix). On NTFS
    /// the per-emit `OpenOptions::open` + `CloseHandle` round-trip
    /// on the `.emit.lock` sentinel costs ~150 µs even when no
    /// other process contends for the lock. Caching the file
    /// handle reduces the per-emit cost to just `lock_exclusive`
    /// + `unlock` (~20-40 µs).
    ///
    /// Value type is `Arc<Mutex<File>>` — the inner Mutex serializes
    /// in-process callers BEFORE they hit `lock_exclusive`. Without
    /// it, Windows `LockFileEx` would happily grant the same handle
    /// nested locks (and Linux flock would behave the same on a
    /// shared FD), breaking the cross-thread serialization the
    /// callers depend on. The outer cache Mutex protects the
    /// HashMap; callers clone the Arc out, drop the outer mutex,
    /// then lock the inner Mutex (waits for any peer in the same
    /// process) before calling `lock_exclusive` (waits for any
    /// peer in another process).
    #[cfg(feature = "fs-locking")]
    lock_files: std::sync::Mutex<
        std::collections::HashMap<
            std::path::PathBuf,
            std::sync::Arc<std::sync::Mutex<std::fs::File>>,
        >,
    >,
}

#[cfg(feature = "fs")]
impl FsStorage {
    /// Construct a fresh `FsStorage`. Empty lock-file cache; first
    /// use of each lock path lazy-opens the handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    fn read_bytes_tail(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        // Native fast path: open read-only, seek to end-max_bytes,
        // read_to_end. Avoids the std::fs::read whole-file allocation
        // when the file is large and the caller only needs the tail.
        // For the chain-tip refresh (the only consumer today), this
        // drops the per-emit read cost from O(log_size) to O(window).
        use std::io::{Read, Seek, SeekFrom};
        let _t0_open = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else { None };
        let mut f = std::fs::OpenOptions::new().read(true).open(path)?;
        if let Some(t) = _t0_open {
            crate::perf::record_ns("emit:tip_refresh.open", t.elapsed().as_nanos() as u64);
        }
        let _t0_meta = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else { None };
        let len = f.metadata()?.len();
        if let Some(t) = _t0_meta {
            crate::perf::record_ns("emit:tip_refresh.metadata", t.elapsed().as_nanos() as u64);
        }
        let start = len.saturating_sub(max_bytes as u64);
        if start > 0 {
            f.seek(SeekFrom::Start(start))?;
        }
        let cap = (len - start) as usize;
        let mut buf = Vec::with_capacity(cap);
        let _t0_read = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else { None };
        f.read_to_end(&mut buf)?;
        if let Some(t) = _t0_read {
            crate::perf::record_ns("emit:tip_refresh.read", t.elapsed().as_nanos() as u64);
        }
        Ok(buf)
    }

    fn open_append_writer(
        &self,
        path: &Path,
    ) -> io::Result<Option<Box<dyn io::Write + Send>>> {
        // Pin one OS handle for the lifetime of the writer instead of
        // the open/write/close-per-emit pattern that `append_bytes`
        // uses. Saves ~200 µs/emit on NTFS (two CreateFileW +
        // CloseHandle round-trips per write). The runtime's
        // `LogFileWriter` is the consumer; per-emit `flush()` calls
        // still go through to the OS, but the `OpenOptions::open`
        // and `CloseHandle` syscalls happen exactly once each over
        // the writer's lifetime.
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Some(Box::new(f)))
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
        // Cached lock-file handle (0.4.2a7). Open lazily on first
        // call per path, then reuse: each subsequent emit just calls
        // `lock_exclusive` + `unlock` on the held handle, skipping
        // the ~150 µs `OpenOptions::open` + `CloseHandle` pair that
        // the prior shape paid every emit.
        //
        // Re-locking the same handle across emits is the standard
        // fs4 / flock pattern: on Linux `flock` accepts the same
        // descriptor repeatedly; on Windows `LockFileEx` is
        // by-handle and unlocking releases the kernel state. We
        // unlock explicitly after `f()` so the lock is released
        // even when `f()` errors.
        let cached: std::sync::Arc<std::sync::Mutex<std::fs::File>> = {
            let mut cache = self
                .lock_files
                .lock()
                .expect("fs storage lock_files mutex poisoned");
            if let Some(existing) = cache.get(path) {
                existing.clone()
            } else {
                // Ensure parent dir exists. The first emit to a
                // templated PEL path (e.g. `./.tn/logs/protocol/tn.ndjson`)
                // races: the LogFileWriter's lazy open creates the
                // dir, but the advisory lock is acquired BEFORE the
                // writer runs. Creating the dir here makes the lock
                // open robust to never-seen rendered paths. Cost:
                // one create_dir_all per (process, path) — amortized
                // across all subsequent emits via the cache hit.
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let f = std::sync::Arc::new(std::sync::Mutex::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(false)
                        .write(true)
                        .open(path)?,
                ));
                cache.insert(path.to_path_buf(), f.clone());
                f
            }
            // cache mutex dropped at end of this block — emits to
            // OTHER paths can proceed while we hold the per-path
            // inner Mutex below.
        };
        // Inner Mutex serializes in-process threads. Holding it
        // across `lock_exclusive` + f() + unlock ensures only one
        // thread of this process is inside the critical section
        // for this path at a time — required because LockFileEx
        // on Windows grants nested locks on the same handle.
        let lock_file = cached.lock().expect("inner lock_file mutex poisoned");
        lock_file.lock_exclusive()?;
        let res = f();
        // Best-effort unlock. If the unlock call itself fails, the
        // closure's result still propagates — the OS releases the
        // lock when the process exits even if unlock here errors.
        let _ = lock_file.unlock();
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
