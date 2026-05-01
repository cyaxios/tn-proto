//! `vault.push` handler — POST `.tnpkg` admin snapshots to a TN vault.
//!
//! Mirrors `python/tn/handlers/vault_push.py`. Builds an admin-log
//! snapshot via [`crate::Runtime::export`] and POSTs it to:
//!
//! ```text
//! {endpoint}/api/v1/inbox/{my_did}/snapshots/{ceremony_id}/{ts}.tnpkg
//! ```
//!
//! The HTTP transport itself is abstracted via [`VaultPostClient`] so
//! tn-core stays light (no `reqwest` / `ureq` dependency on the core
//! crate). Hosts that want a real HTTP transport implement the trait;
//! tests pass a mock that records calls.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value as JsonValue;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::handlers::spec::{self, FilterSpec, HandlerSpec};
use crate::runtime_export::ExportOptions;
use crate::tnpkg::{read_tnpkg, ManifestKind, TnpkgSource};
use crate::{Error, Result, Runtime};

use super::TnHandler;

const DEFAULT_POLL_INTERVAL_SEC: f64 = 60.0;

const TS_FMT: &[FormatItem<'_>] = format_description!(
    "[year][month][day]T[hour][minute][second][subsecond digits:6]Z"
);

/// HTTP transport surface for [`VaultPushHandler`]. One method —
/// `post_snapshot` — receives the raw `.tnpkg` body plus the URL path
/// and idempotency-hint query params.
///
/// Implementations are responsible for adding the bearer token, retry
/// on 401, etc. — mirroring the Python `_SnapshotPostingClient`
/// adapter.
pub trait VaultPostClient: Send + Sync {
    /// POST one snapshot. `path` is the URL path component starting
    /// with `/api/v1/...`; the implementation prefixes the configured
    /// vault base URL. `query` carries idempotency hints (e.g.
    /// `head_row_hash`).
    ///
    /// # Errors
    /// Returns a string with operator-readable context. The handler
    /// logs and retries on the next tick.
    fn post_snapshot(
        &self,
        path: &str,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> std::result::Result<(), String>;
}

/// Trigger mode for push handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Snapshot per accepted emit.
    OnEmit,
    /// Snapshot every `poll_interval` seconds.
    OnSchedule,
}

/// Push admin-log snapshots to a TN vault inbox.
pub struct VaultPushHandler {
    name: String,
    endpoint: String,
    #[allow(dead_code)]
    project_id: String,
    scope: String,
    trigger: Trigger,
    poll_interval: Duration,
    client: Arc<dyn VaultPostClient>,
    runtime: Arc<Runtime>,
    filter: FilterSpec,
    state: Mutex<PushState>,
    stop: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    join: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

#[derive(Default)]
struct PushState {
    last_shipped_head: Option<String>,
}

impl VaultPushHandler {
    /// Build from a parsed [`HandlerSpec`].
    ///
    /// The default HTTP client is a no-op that errors on every call
    /// (mirroring the "wired but the server isn't there yet" Python
    /// shape). Tests inject a mock via [`VaultPushHandler::with_client`].
    ///
    /// # Errors
    /// `Error::InvalidConfig` for missing required fields or unsupported
    /// trigger values.
    pub fn from_spec(spec: &HandlerSpec, runtime: Arc<Runtime>) -> Result<Self> {
        let ctx = "vault.push";
        let endpoint = spec::require_str(&spec.raw, "endpoint", ctx)?;
        let project_id = spec::require_str(&spec.raw, "project_id", ctx)?;
        let trigger_raw = spec::str_field(&spec.raw, "trigger").unwrap_or("on_schedule");
        let trigger = match trigger_raw {
            "on_emit" => Trigger::OnEmit,
            "on_schedule" => Trigger::OnSchedule,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "vault.push: trigger must be 'on_emit' or 'on_schedule', got {other:?}"
                )));
            }
        };
        let poll_secs = spec::parse_duration(
            spec.raw.get("poll_interval").unwrap_or(&JsonValue::Null),
            DEFAULT_POLL_INTERVAL_SEC,
        )?;
        let scope = spec::str_field(&spec.raw, "scope")
            .unwrap_or("admin")
            .to_string();
        Ok(Self {
            name: spec.name.clone(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            project_id,
            scope,
            trigger,
            poll_interval: secs_to_duration(poll_secs),
            client: Arc::new(NullPostClient),
            runtime,
            filter: spec.filter.clone(),
            state: Mutex::new(PushState::default()),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Replace the HTTP client (test seam, also lets a host plug in
    /// `reqwest` / `ureq` from outside the core crate).
    #[must_use]
    pub fn with_client(mut self, client: Arc<dyn VaultPostClient>) -> Self {
        self.client = client;
        self
    }

    /// Direct test-only constructor.
    pub fn new(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        project_id: impl Into<String>,
        runtime: Arc<Runtime>,
        client: Arc<dyn VaultPostClient>,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            project_id: project_id.into(),
            scope: "admin".into(),
            trigger: Trigger::OnEmit,
            poll_interval: Duration::from_secs(60),
            client,
            runtime,
            filter: FilterSpec::default(),
            state: Mutex::new(PushState::default()),
            stop: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(()), Condvar::new())),
            join: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Start the scheduler thread (only used when `trigger=on_schedule`).
    /// Idempotent.
    pub fn start_scheduler(self: &Arc<Self>) {
        if self.trigger != Trigger::OnSchedule {
            return;
        }
        let mut guard = self.join.lock().expect("vault.push join lock");
        if guard.is_some() {
            return;
        }
        let me = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("tn-vault-push-{}", self.name))
            .spawn(move || me.schedule_loop())
            .expect("vault.push spawn scheduler");
        *guard = Some(h);
    }

    fn schedule_loop(self: Arc<Self>) {
        loop {
            let (lock, cv) = &*self.cv;
            let guard = lock.lock().expect("vault.push cv lock");
            let (_g, _r) = cv
                .wait_timeout(guard, self.poll_interval)
                .expect("vault.push cv wait");
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = self.push_snapshot() {
                log::warn!("[{}] vault.push scheduler tick failed: {e}", self.name);
            }
        }
    }

    /// Build, sign, and POST a snapshot. Returns true when something
    /// was pushed; false when the head hasn't advanced since the
    /// previous push.
    ///
    /// # Errors
    /// Surfaces export / IO / HTTP errors; the scheduler logs and
    /// retries on the next tick.
    pub fn push_snapshot(&self) -> Result<bool> {
        let ts_now = OffsetDateTime::now_utc();
        let ts = ts_now
            .format(TS_FMT)
            .map_err(|e| Error::InvalidConfig(format!("vault.push ts format: {e}")))?;

        let yaml_dir = self
            .runtime
            .yaml_path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
        let out_dir = yaml_dir.join(".tn").join("admin").join("outbox");
        std::fs::create_dir_all(&out_dir).map_err(Error::Io)?;
        let out_path = out_dir.join(format!("snapshot_{ts}.tnpkg"));
        let opts = ExportOptions {
            kind: Some(ManifestKind::AdminLogSnapshot),
            scope: Some(self.scope.clone()),
            ..ExportOptions::default()
        };
        self.runtime.export(&out_path, opts)?;

        let bytes = std::fs::read(&out_path).map_err(Error::Io)?;
        let (manifest, _body) = read_tnpkg(TnpkgSource::Bytes(&bytes))?;
        let head = manifest.head_row_hash.clone();

        {
            let mut guard = self.state.lock().expect("vault.push state lock");
            if let (Some(last), Some(current)) = (&guard.last_shipped_head, &head) {
                if last == current {
                    log::debug!(
                        "[{}] vault.push: head_row_hash unchanged ({current}), skipping POST",
                        self.name
                    );
                    let _ = std::fs::remove_file(&out_path);
                    return Ok(false);
                }
            }
            guard.last_shipped_head.clone_from(&head);
        }

        let url_path = format!(
            "/api/v1/inbox/{}/snapshots/{}/{}.tnpkg",
            manifest.from_did, manifest.ceremony_id, ts
        );
        let mut query = BTreeMap::new();
        if let Some(h) = &head {
            query.insert("head_row_hash".into(), h.clone());
        }
        self.client
            .post_snapshot(&url_path, &query, &bytes)
            .map_err(|e| {
                Error::InvalidConfig(format!("vault.push: POST {url_path} failed: {e}"))
            })?;
        log::info!(
            "[{}] vault.push: pushed {} (head={:?})",
            self.name,
            out_path.display(),
            head
        );
        Ok(true)
    }

    /// Read-only access to the configured endpoint (for tests / logging).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Access the shared client (mainly for tests inspecting recorded calls).
    pub fn client(&self) -> Arc<dyn VaultPostClient> {
        Arc::clone(&self.client)
    }
}

impl TnHandler for VaultPushHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, envelope: &JsonValue) -> bool {
        if !self.filter.matches(envelope) {
            return false;
        }
        // Mirror Python: only admin events trigger a snapshot push.
        envelope
            .get("event_type")
            .and_then(JsonValue::as_str)
            .is_some_and(|s| s.starts_with("tn."))
    }
    fn emit(&self, _envelope: &JsonValue, _raw_line: &[u8]) {
        if self.trigger == Trigger::OnEmit {
            if let Err(e) = self.push_snapshot() {
                log::warn!("[{}] vault.push on_emit failed: {e}", self.name);
            }
        }
    }
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
            .expect("vault.push close join lock")
            .take()
        {
            let _ = h.join();
        }
        // Best-effort final flush.
        if let Err(e) = self.push_snapshot() {
            log::debug!("[{}] vault.push final flush: {e}", self.name);
        }
    }
}

impl Drop for VaultPushHandler {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::SeqCst) {
            self.stop.store(true, Ordering::SeqCst);
            let (_, cv) = &*self.cv;
            cv.notify_all();
            if let Some(h) = self
                .join
                .lock()
                .expect("vault.push drop join lock")
                .take()
            {
                let _ = h.join();
            }
        }
    }
}

/// Default no-op HTTP client. Errors on every call. Hosts must replace
/// this with a real implementation (`with_client`) before production
/// use; the registry leaves it in place because tn-core does not
/// depend on a specific HTTP runtime.
struct NullPostClient;

impl VaultPostClient for NullPostClient {
    fn post_snapshot(
        &self,
        _path: &str,
        _query: &BTreeMap<String, String>,
        _body: &[u8],
    ) -> std::result::Result<(), String> {
        Err("vault.push: no HTTP client wired (NullPostClient). Inject one via with_client.".into())
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
