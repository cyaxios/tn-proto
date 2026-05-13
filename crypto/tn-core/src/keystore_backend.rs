//! Atomic + CAS + flock keystore writes for the publisher state file.
//!
//! Rust counterpart to `python/tn/_keystore_backend.py`. The publisher
//! state file (`<group>.btn.state`) is the **cryptographic ledger of
//! who can decrypt** — losing a write to a race, or leaving a partial
//! state on disk after a crash, is the worst-possible failure mode
//! for this primitive. So every write goes through three checks:
//!
//! 1. **Atomic write** — tmp file + `fsync` + `rename` so a crash
//!    mid-write never leaves a partial file. The previous contents
//!    are untouched on failure.
//! 2. **OS-level exclusive lock** — `flock` on Unix / `LockFileEx`
//!    on Windows, via the `fs4` crate. Serialises concurrent writers
//!    across processes, not just threads.
//! 3. **Compare-and-swap** — re-read on-disk state under the lock
//!    and compare it byte-for-byte against the caller's `prior`
//!    snapshot. On divergence the caller's view is stale; the write
//!    is refused and a [`KeystoreConflictError`] is returned so the
//!    caller can re-read, re-apply their mutation, and retry. This
//!    prevents the lost-update problem the lock alone wouldn't catch.
//!
//! The Python side ships #1 and #3 but says #2 is a "best-effort
//! under cooperating writers" gap. This Rust implementation closes
//! that gap.
//!
//! ## Layout
//!
//! For a keystore directory `<dir>` and group name `<g>`:
//!
//! * `<dir>/<g>.btn.state`           — the state file itself
//! * `<dir>/<g>.btn.state.lock`      — sibling lock file (created on
//!                                     first write, then re-used)
//! * `<dir>/.<g>.btn.state.tmp.<pid>` — staging file during atomic
//!                                     write (gone after success or
//!                                     cleanup on failure)
//!
//! ## When to use the high-level API
//!
//! Use [`LocalKeystore::write_state`] for the publisher state file.
//! Use [`atomic_write_bytes`] directly for files that don't need CAS
//! (initial identity setup, kit files, etc.) — those still benefit
//! from torn-write protection.

#![cfg(feature = "fs")]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use thiserror::Error;

/// Error raised when a [`LocalKeystore::write_state`] CAS check fails.
///
/// The caller passed a `prior` snapshot that no longer matches what's
/// on disk — another writer mutated the state between the caller's
/// read and the caller's write. The caller's mutation is stale and
/// must be re-derived from a fresh read.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// CAS check failed: on-disk state is not what the caller expected.
    /// Re-read and retry.
    #[error("state for group {group:?} has diverged on disk; re-read and retry")]
    Conflict {
        /// The group name whose state file diverged. Echoed back to
        /// the caller so a multi-group retry loop can decide whether
        /// to re-fetch this group's snapshot or bail.
        group: String,
    },

    /// Underlying I/O failure (read, write, lock acquisition, rename).
    /// Distinct from [`KeystoreError::Conflict`] because callers may
    /// want to surface I/O errors immediately rather than retry.
    #[error("keystore I/O: {0}")]
    Io(#[from] io::Error),
}

/// Filesystem-backed publisher state keystore.
///
/// Owns a directory. Each group's state lives in
/// `<dir>/<group>.btn.state`; the sibling `.lock` file is the
/// exclusive-write token. Stateless — safe to instantiate per call,
/// drop, recreate; the lock is held only for the duration of a
/// single `write_state` invocation.
pub struct LocalKeystore {
    dir: PathBuf,
}

impl LocalKeystore {
    /// Construct rooted at `dir`. Does NOT create the directory; the
    /// caller is expected to have set up the keystore layout (yaml,
    /// device key, etc.) before mutating state. If the dir is missing
    /// at write time, the atomic-write helper will fail with a clear
    /// I/O error.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn state_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{group}.btn.state"))
    }

    fn lock_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{group}.btn.state.lock"))
    }

    /// Read the current on-disk state for `group`, or `None` if no
    /// state file exists yet (fresh ceremony).
    ///
    /// Not lock-guarded — a write may land between this read and the
    /// caller's next action. Use the value as a CAS `prior`, not as
    /// "the truth at this instant."
    pub fn read_state(&self, group: &str) -> io::Result<Option<Vec<u8>>> {
        let p = self.state_path(group);
        if !p.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(p)?))
    }

    /// Compare-and-swap write of the publisher state for `group`.
    ///
    /// Semantics:
    ///
    /// 1. Acquire the exclusive sibling lock (`<g>.btn.state.lock`).
    ///    This blocks other processes / threads attempting to mutate
    ///    the same group's state until our write completes.
    /// 2. Under the lock, re-read the on-disk state.
    /// 3. Compare to `prior`. `prior == None` means "the file must not
    ///    exist"; `prior == Some(bytes)` means "the file must contain
    ///    exactly these bytes." Any divergence returns
    ///    [`KeystoreError::Conflict`].
    /// 4. Atomic-write `new` (tmp + fsync + rename).
    /// 5. Release the lock on scope exit.
    ///
    /// The lock file itself is created on first call and left in
    /// place after; subsequent writes re-open and re-lock the same
    /// file. Removing it manually between two write_state calls is
    /// safe but pointless.
    ///
    /// # Errors
    ///
    /// * [`KeystoreError::Conflict`] — CAS check failed; another
    ///   writer beat us to the lock and mutated state.
    /// * [`KeystoreError::Io`] — lock acquisition, read, write, or
    ///   rename failed.
    pub fn write_state(
        &self,
        group: &str,
        prior: Option<&[u8]>,
        new: &[u8],
    ) -> Result<(), KeystoreError> {
        // Ensure parent exists before we try to create the lock file.
        // A missing keystore dir at this stage is an operator error
        // (ceremony was never initialised); we surface as I/O.
        std::fs::create_dir_all(&self.dir)?;

        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path(group))?;
        // Blocks until we hold the exclusive lock. fs4's lock_exclusive
        // is cross-platform: flock on Unix, LockFileEx on Windows.
        lock_file.lock_exclusive()?;

        // Under lock: re-read disk state and CAS-check it against the
        // caller's prior snapshot. A divergence here means another
        // process committed a write between the caller's read and
        // now.
        let path = self.state_path(group);
        let current = if path.exists() {
            Some(std::fs::read(&path)?)
        } else {
            None
        };
        if current.as_deref() != prior {
            return Err(KeystoreError::Conflict {
                group: group.to_string(),
            });
        }

        atomic_write_bytes(&path, new)?;
        // Lock is released when `lock_file` is dropped at scope exit.
        Ok(())
    }
}

/// Write `data` to `path` atomically — tmp file in the same dir,
/// `fsync` to push the page-cache to disk, then `rename` over the
/// destination.
///
/// Guarantees:
///
/// * On success, `path` contains exactly `data`.
/// * On any failure (write, fsync, rename) the previous contents of
///   `path` (if any) are untouched — `rename` is the commit point,
///   nothing before it is observable to readers.
/// * No `.<name>.tmp.<pid>` siblings are left around after either
///   outcome.
///
/// `rename` is atomic on POSIX and Windows when source and
/// destination share a filesystem; we always create the tmp file in
/// the destination's parent dir so this invariant holds.
///
/// # Errors
///
/// Returns the underlying I/O error from any of `create_dir_all`,
/// tmp-file `create`, `write_all`, `sync_all`, or `rename`. The tmp
/// file is removed before propagating the error, so a failed write
/// doesn't leak.
pub fn atomic_write_bytes(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("tn_atomic_write");
    let tmp = parent.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    let write_result = write_and_fsync(&tmp, data);
    if let Err(e) = write_result {
        // Best-effort cleanup of the staging file; ignore secondary
        // failures (it'll get reaped next reboot if the tmp dir
        // survives, otherwise atomic_write itself was the real
        // failure to surface).
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // The commit point. Atomic on every platform we target.
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Inner helper for [`atomic_write_bytes`]. Splits the
/// write+fsync+close phase out so the outer fn can keep a flat
/// flow with explicit cleanup on the failure path.
fn write_and_fsync(tmp: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = File::create(tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_round_trip() {
        let td = tempdir().unwrap();
        let p = td.path().join("file.bin");
        atomic_write_bytes(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_overwrites_existing_content() {
        let td = tempdir().unwrap();
        let p = td.path().join("file.bin");
        std::fs::write(&p, b"old").unwrap();
        atomic_write_bytes(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
    }

    #[test]
    fn atomic_write_leaves_no_tmp_siblings_on_success() {
        let td = tempdir().unwrap();
        let p = td.path().join("file.bin");
        atomic_write_bytes(&p, b"data").unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(td.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.contains(".tmp."))
            })
            .collect();
        assert!(leftovers.is_empty(), "tmp file leaked: {leftovers:?}");
    }

    #[test]
    fn cas_first_write_against_none_succeeds() {
        let td = tempdir().unwrap();
        let ks = LocalKeystore::new(td.path());
        assert_eq!(ks.read_state("default").unwrap(), None);

        ks.write_state("default", None, b"v1").unwrap();
        assert_eq!(ks.read_state("default").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn cas_second_write_with_stale_prior_is_rejected() {
        let td = tempdir().unwrap();
        let ks = LocalKeystore::new(td.path());
        ks.write_state("default", None, b"v1").unwrap();

        // Caller's `prior` is stale (still believes "v0" was on disk).
        let err = ks
            .write_state("default", Some(b"v0"), b"v2")
            .expect_err("stale prior must trigger Conflict");
        assert!(matches!(err, KeystoreError::Conflict { .. }));
        // State on disk is unchanged.
        assert_eq!(ks.read_state("default").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn cas_second_write_with_fresh_prior_succeeds() {
        let td = tempdir().unwrap();
        let ks = LocalKeystore::new(td.path());
        ks.write_state("default", None, b"v1").unwrap();
        ks.write_state("default", Some(b"v1"), b"v2").unwrap();
        assert_eq!(ks.read_state("default").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn cas_write_existing_with_none_prior_is_rejected() {
        // Caller passes `prior=None` meaning "the file must not
        // exist" — but it does exist. This is the symmetric error to
        // the stale-bytes case.
        let td = tempdir().unwrap();
        let ks = LocalKeystore::new(td.path());
        ks.write_state("default", None, b"v1").unwrap();

        let err = ks
            .write_state("default", None, b"v2")
            .expect_err("existing file vs None prior must Conflict");
        assert!(matches!(err, KeystoreError::Conflict { .. }));
    }

    #[test]
    fn concurrent_writers_serialise_via_lock() {
        // Two threads racing to write the same group. Both succeed
        // (each takes the lock in turn) but the second observes the
        // first's write as `prior` and explicitly carries it through
        // — same pattern a real caller would use after a Conflict
        // retry. Without the lock, the inner read-then-write would
        // be a TOCTOU race.
        let td = tempdir().unwrap();
        let ks = Arc::new(LocalKeystore::new(td.path()));

        // Seed initial state.
        ks.write_state("default", None, b"v0").unwrap();

        let n = 20;
        let mut handles = Vec::new();
        for i in 0..n {
            let ks2 = Arc::clone(&ks);
            handles.push(thread::spawn(move || {
                // Retry loop: read, mutate, write; on Conflict, retry.
                loop {
                    let current = ks2.read_state("default").unwrap();
                    let mut new = current.clone().unwrap_or_default();
                    new.push(b'a' + (i % 26) as u8);
                    match ks2.write_state("default", current.as_deref(), &new) {
                        Ok(()) => break,
                        Err(KeystoreError::Conflict { .. }) => continue,
                        Err(e) => panic!("unexpected I/O: {e:?}"),
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // End state has exactly the seed plus n appends — every
        // mutation landed, none were lost.
        let final_state = ks.read_state("default").unwrap().unwrap();
        assert_eq!(
            final_state.len(),
            2 + n as usize, // "v0" + n single-byte appends
            "expected every concurrent write to land via retry, got {final_state:?}"
        );
    }
}
