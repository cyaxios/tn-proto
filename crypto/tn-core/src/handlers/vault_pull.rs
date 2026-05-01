//! `vault.pull` handler — fetch admin-log snapshots from a TN vault.
//!
//! Mirrors `python/tn/handlers/vault_pull.py`. On a schedule, GETs new
//! `.tnpkg` files from the vault inbox addressed to this DID and calls
//! [`crate::Runtime::absorb`] for each. Idempotent because absorb
//! dedupes by `row_hash`.
//!
//! Cursor persistence at `<yaml_dir>/.tn/admin/vault_pull.cursor.json`
//! mirrors Python byte-for-byte.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value as JsonValue;

use crate::handlers::spec::{self, FilterSpec, HandlerSpec};
use crate::runtime_export::AbsorbSource;
use crate::{Error, Result, Runtime};

use super::TnHandler;

const DEFAULT_POLL_INTERVAL_SEC: f64 = 60.0;
const CURSOR_FILE: &str = "vault_pull.cursor.json";

/// One incoming snapshot reference (mirrors Python's
/// `{path, head_row_hash, received_at, since_marker}` shape).
#[derive(Debug, Clone)]
pub struct VaultInboxItem {
    /// URL path relative to the vault base URL.
    pub path: String,
    /// Optional row-hash; may be used by hosts for idempotency.
    pub head_row_hash: Option<String>,
    /// Receive timestamp (wall-clock; fallback for cursor advance when
    /// `since_marker` is absent).
    pub received_at: Option<String>,
    /// Server-supplied opaque, order-preserving cursor (per spec §4.1).
    /// When present, the handler advances `?since=...` by this value
    /// rather than `received_at`. Falls back to `received_at` for
    /// vault implementations that don't emit `since_marker` yet.
    pub since_marker: Option<String>,
}

/// HTTP transport surface for pull. Hosts implement this; tests pass a
/// mock that returns canned items.
pub trait VaultInboxClient: Send + Sync {
    /// Return new inbox items for `did` since `cursor` (exclusive).
    ///
    /// # Errors
    /// Returns operator-readable string. The handler logs and retries.
    fn list_incoming(
        &self,
        did: &str,
        since: Option<&str>,
    ) -> std::result::Result<Vec<VaultInboxItem>, String>;

    /// Download one `.tnpkg` body by URL path.
    ///
    /// # Errors
    /// Returns operator-readable string.
    fn download(&self, path: &str) -> std::result::Result<Vec<u8>, String>;
}

/// Failure mode for absorb errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnAbsorbError {
    /// Log; cursor doesn't advance for the failing item.
    Log,
    /// Propagate out of the scheduler tick.
    Raise,
}

/// Poll a TN vault inbox for `.tnpkg` snapshots and absorb them.
pub struct VaultPullHandler {
    name: String,
    endpoint: String,
    #[allow(dead_code)]
    project_id: String,
    poll_interval: Duration,
    on_absorb_error: OnAbsorbError,
    cursor_path: PathBuf,
    client: Arc<dyn VaultInboxClient>,
    runtime: Arc<Runtime>,
    #[allow(dead_code)]
    filter: FilterSpec,
    tick_lock: Mutex<()>,
    stop: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    join: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl VaultPullHandler {
    /// Build from a parsed [`HandlerSpec`]. Default client is a stub
    /// that returns "not wired" — replace via [`Self::with_client`].
    ///
    /// # Errors
    /// Missing required fields or unknown `on_absorb_error` mode.
    pub fn from_spec(
        spec: &HandlerSpec,
        runtime: Arc<Runtime>,
        yaml_dir: &Path,
    ) -> Result<Self> {
        let ctx = "vault.pull";
        let endpoint = spec::require_str(&spec.raw, "endpoint", ctx)?;
        let project_id = spec::require_str(&spec.raw, "project_id", ctx)?;
        let poll_secs = spec::parse_duration(
            spec.raw.get("poll_interval").unwrap_or(&JsonValue::Null),
            DEFAULT_POLL_INTERVAL_SEC,
        )?;
        let on_absorb_error =
            match spec::str_field(&spec.raw, "on_absorb_error").unwrap_or("log") {
                "log" => OnAbsorbError::Log,
                "raise" => OnAbsorbError::Raise,
                other => {
                    return Err(Error::InvalidConfig(format!(
                        "vault.pull: on_absorb_error must be 'log' or 'raise', got {other:?}"
                    )));
                }
            };
        let cursor_path = yaml_dir.join(".tn").join("admin").join(CURSOR_FILE);

        Ok(Self {
            name: spec.name.clone(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            project_id,
            poll_interval: secs_to_duration(poll_secs),
            on_absorb_error,
            cursor_path,
            client: Arc::new(NullInboxClient),
            runtime,
            filter: spec.filter.clone(),
            tick_lock: Mutex::new(()),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Direct test-only constructor.
    pub fn new(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        project_id: impl Into<String>,
        runtime: Arc<Runtime>,
        client: Arc<dyn VaultInboxClient>,
        cursor_path: PathBuf,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            project_id: project_id.into(),
            poll_interval: Duration::from_secs(60),
            on_absorb_error: OnAbsorbError::Log,
            cursor_path,
            client,
            runtime,
            filter: FilterSpec::default(),
            tick_lock: Mutex::new(()),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Replace the HTTP client. Returns self for chaining.
    #[must_use]
    pub fn with_client(mut self, client: Arc<dyn VaultInboxClient>) -> Self {
        self.client = client;
        self
    }

    /// Endpoint accessor.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Start the scheduler thread. Idempotent.
    pub fn start(self: &Arc<Self>) {
        let mut guard = self.join.lock().expect("vault.pull join lock");
        if guard.is_some() {
            return;
        }
        let me = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("tn-vault-pull-{}", self.name))
            .spawn(move || me.schedule_loop())
            .expect("vault.pull spawn");
        *guard = Some(h);
    }

    fn schedule_loop(self: Arc<Self>) {
        if let Err(e) = self.tick_once() {
            log::warn!("[{}] vault.pull initial tick failed: {e}", self.name);
        }
        loop {
            let (lock, cv) = &*self.cv;
            let guard = lock.lock().expect("vault.pull cv lock");
            let (_g, _r) = cv
                .wait_timeout(guard, self.poll_interval)
                .expect("vault.pull cv wait");
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = self.tick_once() {
                if self.on_absorb_error == OnAbsorbError::Raise {
                    log::error!("[{}] vault.pull tick raise: {e}", self.name);
                    break;
                }
                log::warn!("[{}] vault.pull tick failed: {e}", self.name);
            }
        }
    }

    /// One fetch+absorb cycle. Returns the count of newly absorbed
    /// snapshots.
    ///
    /// # Errors
    /// Surfaces transport / IO errors when `on_absorb_error=Raise`;
    /// otherwise logs and returns the partial count.
    pub fn tick_once(&self) -> Result<usize> {
        let _g = self.tick_lock.lock().expect("vault.pull tick lock");
        self.tick_locked()
    }

    fn tick_locked(&self) -> Result<usize> {
        let mut cursor = self.load_cursor();
        let did = self.runtime.device.did();
        let items = match self
            .client
            .list_incoming(did, cursor.as_deref())
        {
            Ok(items) => items,
            Err(e) => {
                if self.on_absorb_error == OnAbsorbError::Raise {
                    return Err(Error::InvalidConfig(format!(
                        "vault.pull: list_incoming: {e}"
                    )));
                }
                log::warn!("[{}] vault.pull: list_incoming failed: {e}", self.name);
                return Ok(0);
            }
        };
        if items.is_empty() {
            return Ok(0);
        }
        let mut absorbed = 0;
        let mut highest = cursor.clone();
        for item in items {
            let blob = match self.client.download(&item.path) {
                Ok(b) => b,
                Err(e) => {
                    if self.on_absorb_error == OnAbsorbError::Raise {
                        return Err(Error::InvalidConfig(format!(
                            "vault.pull: download {} failed: {e}",
                            item.path
                        )));
                    }
                    log::warn!(
                        "[{}] vault.pull: download {} failed: {e}",
                        self.name,
                        item.path
                    );
                    return Ok(absorbed);
                }
            };
            match self.runtime.absorb(AbsorbSource::Bytes(&blob)) {
                Ok(receipt) => {
                    if !receipt.legacy_reason.is_empty()
                        || receipt.legacy_status == "rejected"
                    {
                        log::warn!(
                            "[{}] vault.pull: absorb rejected {}: {}",
                            self.name,
                            item.path,
                            receipt.legacy_reason
                        );
                        continue;
                    }
                    absorbed += 1;
                    // Per spec §4.1: prefer server-supplied since_marker
                    // (opaque, order-preserving). Fall back to received_at
                    // for vault implementations that don't emit since_marker.
                    let cursor_value = item
                        .since_marker
                        .as_deref()
                        .or(item.received_at.as_deref());
                    if let Some(ts) = cursor_value {
                        match &highest {
                            None => highest = Some(ts.to_string()),
                            Some(prev) if ts > prev.as_str() => {
                                highest = Some(ts.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    if self.on_absorb_error == OnAbsorbError::Raise {
                        return Err(e);
                    }
                    log::warn!(
                        "[{}] vault.pull: absorb crashed for {}: {e}",
                        self.name,
                        item.path
                    );
                }
            }
        }
        if highest.is_some() && highest != cursor {
            cursor = highest;
            if let Err(e) = self.save_cursor(cursor.as_deref()) {
                log::warn!("[{}] vault.pull: save cursor failed: {e}", self.name);
            }
        }
        Ok(absorbed)
    }

    fn load_cursor(&self) -> Option<String> {
        let path = &self.cursor_path;
        if !path.exists() {
            return None;
        }
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<JsonValue>(&s) {
                Ok(v) => v
                    .get("last_seen")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                Err(e) => {
                    log::warn!(
                        "[{}] vault.pull: cursor at {} is corrupt; starting fresh ({e})",
                        self.name,
                        path.display()
                    );
                    None
                }
            },
            Err(e) => {
                log::warn!(
                    "[{}] vault.pull: cursor read failed at {}: {e}",
                    self.name,
                    path.display()
                );
                None
            }
        }
    }

    fn save_cursor(&self, cursor: Option<&str>) -> std::io::Result<()> {
        let path = &self.cursor_path;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut obj = serde_json::Map::new();
        if let Some(c) = cursor {
            obj.insert("last_seen".into(), JsonValue::String(c.to_string()));
        }
        let pretty = serde_json::to_string_pretty(&JsonValue::Object(obj))
            .unwrap_or_else(|_| "{}".into());
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, pretty)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Cursor file path (test introspection).
    pub fn cursor_path(&self) -> &Path {
        &self.cursor_path
    }
}

impl TnHandler for VaultPullHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, _envelope: &JsonValue) -> bool {
        false
    }
    fn emit(&self, _envelope: &JsonValue, _raw_line: &[u8]) {}
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        let (_, cv) = &*self.cv;
        cv.notify_all();
        if let Some(h) = self
            .join
            .lock()
            .expect("vault.pull close join lock")
            .take()
        {
            let _ = h.join();
        }
    }
}

impl Drop for VaultPullHandler {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::SeqCst) {
            self.stop.store(true, Ordering::SeqCst);
            let (_, cv) = &*self.cv;
            cv.notify_all();
            if let Some(h) = self
                .join
                .lock()
                .expect("vault.pull drop join lock")
                .take()
            {
                let _ = h.join();
            }
        }
    }
}

struct NullInboxClient;

impl VaultInboxClient for NullInboxClient {
    fn list_incoming(
        &self,
        _did: &str,
        _since: Option<&str>,
    ) -> std::result::Result<Vec<VaultInboxItem>, String> {
        Ok(vec![])
    }
    fn download(&self, _path: &str) -> std::result::Result<Vec<u8>, String> {
        Err("vault.pull: no HTTP client wired (NullInboxClient). Inject one via with_client.".into())
    }
}

fn secs_to_duration(s: f64) -> Duration {
    if !s.is_finite() || s <= 0.0 {
        return Duration::from_secs(60);
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    {
        Duration::from_nanos((s * 1_000_000_000.0) as u64)
    }
}
