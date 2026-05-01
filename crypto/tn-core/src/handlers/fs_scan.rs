//! `fs.scan` handler — pick up `.tnpkg` files from a watched directory.
//!
//! Mirrors `python/tn/handlers/fs_scan.py`. Polls a directory for
//! `.tnpkg` files, calls [`crate::Runtime::absorb`] for each, then
//! moves them to `.processed/` (default) or deletes them. Bad-signature
//! / rejected files always go to `.rejected/` so operators can inspect
//! them without re-processing on every tick.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value as JsonValue;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::handlers::spec::{self, FilterSpec, HandlerSpec};
use crate::runtime_export::AbsorbSource;
use crate::{Error, Result, Runtime};

use super::TnHandler;

const DEFAULT_POLL_INTERVAL_SEC: f64 = 30.0;

const SUFFIX_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

/// On-processed disposition for absorbed files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnProcessed {
    /// Move to `archive_dir` (default `<in_dir>/.processed/`).
    Archive,
    /// Delete the file.
    Delete,
}

/// Poll a directory for `.tnpkg` files and absorb them.
pub struct FsScanHandler {
    name: String,
    in_dir: PathBuf,
    poll_interval: Duration,
    on_processed: OnProcessed,
    archive_dir: PathBuf,
    rejected_dir: PathBuf,
    runtime: Arc<Runtime>,
    #[allow(dead_code)]
    filter: FilterSpec,
    stop: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    join: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl FsScanHandler {
    /// Build from a parsed [`HandlerSpec`].
    ///
    /// # Errors
    /// `Error::InvalidConfig` for unknown `on_processed` values or when
    /// the required `in_dir` is missing.
    pub fn from_spec(
        spec: &HandlerSpec,
        runtime: Arc<Runtime>,
        yaml_dir: &Path,
    ) -> Result<Self> {
        let ctx = "fs.scan";
        let in_dir_str = spec::require_str(&spec.raw, "in_dir", ctx)?;
        let in_dir = spec::resolve_path(&in_dir_str, yaml_dir);
        let poll_secs = spec::parse_duration(
            spec.raw.get("poll_interval").unwrap_or(&JsonValue::Null),
            DEFAULT_POLL_INTERVAL_SEC,
        )?;
        let on_processed = match spec::str_field(&spec.raw, "on_processed").unwrap_or("archive") {
            "archive" => OnProcessed::Archive,
            "delete" => OnProcessed::Delete,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "fs.scan: on_processed must be 'archive' or 'delete', got {other:?}"
                )));
            }
        };
        let archive_dir = spec::str_field(&spec.raw, "archive_dir").map_or_else(
            || in_dir.join(".processed"),
            |s| spec::resolve_path(s, yaml_dir),
        );
        let rejected_dir = spec::str_field(&spec.raw, "rejected_dir").map_or_else(
            || in_dir.join(".rejected"),
            |s| spec::resolve_path(s, yaml_dir),
        );

        let h = Self {
            name: spec.name.clone(),
            in_dir,
            poll_interval: secs_to_duration(poll_secs),
            on_processed,
            archive_dir,
            rejected_dir,
            runtime,
            filter: spec.filter.clone(),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        };
        Ok(h)
    }

    /// Direct test-only constructor (no scheduler started).
    pub fn new(
        name: impl Into<String>,
        in_dir: PathBuf,
        runtime: Arc<Runtime>,
        on_processed: OnProcessed,
    ) -> Self {
        let archive_dir = in_dir.join(".processed");
        let rejected_dir = in_dir.join(".rejected");
        Self {
            name: name.into(),
            in_dir,
            poll_interval: Duration::from_secs(30),
            on_processed,
            archive_dir,
            rejected_dir,
            runtime,
            filter: FilterSpec::default(),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Start the background scheduler thread. Idempotent.
    pub fn start(self: &Arc<Self>) {
        let mut guard = self.join.lock().expect("fs.scan join lock");
        if guard.is_some() {
            return;
        }
        let me = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("tn-fs-scan-{}", self.name))
            .spawn(move || me.schedule_loop())
            .expect("fs.scan: spawn scheduler");
        *guard = Some(h);
    }

    fn schedule_loop(self: Arc<Self>) {
        // Initial tick (matches Python).
        if let Err(e) = self.tick_once() {
            log::warn!("[{}] fs.scan initial tick failed: {e}", self.name);
        }
        loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // Sleep with cancellation.
            let (lock, cv) = &*self.cv;
            let guard = lock.lock().expect("fs.scan cv lock");
            let (_g, _r) = cv
                .wait_timeout(guard, self.poll_interval)
                .expect("fs.scan cv wait");
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = self.tick_once() {
                log::warn!("[{}] fs.scan tick failed: {e}", self.name);
            }
        }
    }

    /// Run one scan cycle. Returns count of newly absorbed files.
    ///
    /// # Errors
    /// Surfaces filesystem errors. Per-file absorb failures are logged
    /// and routed to the rejected dir; they don't abort the cycle.
    pub fn tick_once(&self) -> Result<usize> {
        if !self.in_dir.exists() {
            return Ok(0);
        }
        let mut absorbed = 0usize;
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.in_dir)
            .map_err(Error::Io)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("tnpkg"))
            .collect();
        entries.sort();
        for entry in entries {
            match self.runtime.absorb(AbsorbSource::Path(&entry)) {
                Ok(receipt) => {
                    let rejected = !receipt.legacy_reason.is_empty()
                        || receipt.legacy_status == "rejected";
                    if rejected {
                        log::warn!(
                            "[{}] fs.scan: rejecting {}: {}",
                            self.name,
                            entry.display(),
                            receipt.legacy_reason
                        );
                        self.move_to(&entry, &self.rejected_dir);
                        continue;
                    }
                    absorbed += 1;
                    self.dispose(&entry);
                }
                Err(e) => {
                    log::warn!(
                        "[{}] fs.scan: absorb crashed for {}: {e}",
                        self.name,
                        entry.display()
                    );
                    self.move_to(&entry, &self.rejected_dir);
                }
            }
        }
        Ok(absorbed)
    }

    fn dispose(&self, path: &Path) {
        match self.on_processed {
            OnProcessed::Delete => {
                if let Err(e) = std::fs::remove_file(path) {
                    log::warn!(
                        "[{}] fs.scan: failed to delete {}: {e}",
                        self.name,
                        path.display()
                    );
                }
            }
            OnProcessed::Archive => self.move_to(path, &self.archive_dir),
        }
    }

    fn move_to(&self, path: &Path, dest_dir: &Path) {
        if let Err(e) = std::fs::create_dir_all(dest_dir) {
            log::warn!(
                "[{}] fs.scan: failed to create {}: {e}",
                self.name,
                dest_dir.display()
            );
            return;
        }
        let file_name = path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        let mut target = dest_dir.join(&file_name);
        if target.exists() {
            let now = OffsetDateTime::now_utc();
            let ts = now
                .format(SUFFIX_FMT)
                .unwrap_or_else(|_| "00000000T000000Z".into());
            let stem = target
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("file");
            let ext = target
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("tnpkg");
            target = dest_dir.join(format!("{stem}__{ts}.{ext}"));
        }
        if let Err(e) = std::fs::rename(path, &target) {
            log::warn!(
                "[{}] fs.scan: failed to move {} -> {}: {e}",
                self.name,
                path.display(),
                target.display()
            );
        }
    }

    /// Stop the scheduler and join the thread.
    pub fn close_handler(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        let (_, cv) = &*self.cv;
        cv.notify_all();
        if let Some(h) = self
            .join
            .lock()
            .expect("fs.scan close join lock")
            .take()
        {
            // Best-effort join; don't panic on a poisoned scheduler.
            let _ = h.join();
        }
    }
}

impl TnHandler for FsScanHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, _envelope: &JsonValue) -> bool {
        // Scan handlers don't react to local emits.
        false
    }
    fn emit(&self, _envelope: &JsonValue, _raw_line: &[u8]) {}
    fn close(&self) {
        self.close_handler();
    }
}

impl Drop for FsScanHandler {
    fn drop(&mut self) {
        self.close_handler();
    }
}

fn secs_to_duration(s: f64) -> Duration {
    if !s.is_finite() || s <= 0.0 {
        return Duration::from_secs(30);
    }
    // Clamp to a sane range to avoid panic on absurd values.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    {
        let nanos = (s * 1_000_000_000.0) as u64;
        Duration::from_nanos(nanos)
    }
}
