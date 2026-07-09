//! Main `Tn` handle and everyday lifecycle/read/emit APIs.
//!
//! This module is the first ergonomic layer over [`tn_core::Runtime`]. Keep it
//! focused on the core user flow before growing the broader namespaces:
//!
//! ```text
//! Tn::init(...) -> tn.info(...) -> tn.read(...) -> tn.close()
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::{Map, Value};
use tn_core::Runtime;

use crate::account::Account;
use crate::admin::Admin;
use crate::entry::Entry;
use crate::identity::Identity;
use crate::inbox::Inbox;
use crate::pkg::Package;
use crate::vault::Vault;
#[cfg(feature = "http")]
use crate::vault::{VaultHttpProjectClient, VaultInitUploadOptions, VaultInitUploadResult};
use crate::wallet::Wallet;
#[cfg(feature = "watch")]
use crate::watch::{NativeWatch, NativeWatchOptions};
use crate::watch::{PollingWatch, PollingWatchOptions, Watch, WatchOptions};
use crate::{Error, Result};

/// Main SDK handle for one TN ceremony.
///
/// A `Tn` owns one [`tn_core::Runtime`] and exposes the higher-level methods
/// Rust users should reach for first. Protocol primitives remain available in
/// `tn-core`; this type is the ergonomic SDK surface.
#[derive(Debug)]
pub struct Tn {
    runtime: Runtime,
}

/// Options used when opening a ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TnInitOptions {
    /// Skip the automatic `tn.ceremony.init` event during runtime load.
    pub skip_ceremony_init_emit: bool,
    /// Skip the automatic `tn.agents.policy_published` event during runtime load.
    pub skip_policy_published_emit: bool,
}

const DEFAULT_PROJECT_NAME: &str = "default";

/// Fixed TN evidence profile for a newly-created project ceremony.
///
/// Profiles mirror the Python/TypeScript catalog: callers pick a named bundle
/// instead of composing signing, chaining, and sink behavior ad hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TnProfile {
    /// Signed, chained, file-backed. Conservative default.
    #[default]
    Transaction,
    /// Signed, chained, file-backed, buffered durability profile.
    Audit,
    /// Signed, unchained, file-backed profile for sensitive application logs.
    SecureLog,
    /// Unsigned, unchained, file-backed profile for high-volume telemetry.
    Telemetry,
    /// Unsigned, unchained, stdout-only profile for local/dev flows.
    Stdout,
}

impl TnProfile {
    /// Parse a profile name from the shared SDK catalog.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `name` is not a known profile.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "transaction" => Ok(Self::Transaction),
            "audit" => Ok(Self::Audit),
            "secure_log" => Ok(Self::SecureLog),
            "telemetry" => Ok(Self::Telemetry),
            "stdout" => Ok(Self::Stdout),
            other => Err(Error::InvalidArgument(format!(
                "unknown profile {other:?}; expected one of transaction, audit, secure_log, telemetry, stdout"
            ))),
        }
    }

    /// Return the canonical profile name written into `tn.yaml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::Audit => "audit",
            Self::SecureLog => "secure_log",
            Self::Telemetry => "telemetry",
            Self::Stdout => "stdout",
        }
    }

    fn signs(self) -> bool {
        matches!(self, Self::Transaction | Self::Audit | Self::SecureLog)
    }

    fn chains(self) -> bool {
        matches!(self, Self::Transaction | Self::Audit)
    }

    fn default_sink_is_file(self) -> bool {
        !matches!(self, Self::Stdout)
    }
}

/// Options used when creating or opening a project ceremony.
#[derive(Debug, Clone, Default)]
pub struct TnProjectOptions {
    /// Workspace directory that owns `.tn/<project>/`.
    ///
    /// Defaults to the current working directory.
    pub project_dir: Option<PathBuf>,
    /// Optional 32-byte Ed25519 seed for the project device identity.
    ///
    /// When omitted, `init_project` loads or mints a machine-global
    /// `identity.json` and uses that device key, matching Python/TypeScript
    /// onboarding. Supplying a seed overrides identity discovery and binds the
    /// ceremony to that exact device identity.
    pub device_private_bytes: Option<Vec<u8>>,
    /// Evidence profile stamped into the ceremony.
    ///
    /// Defaults to [`TnProfile::Transaction`].
    pub profile: TnProfile,
    /// Options applied when opening the newly-created ceremony.
    pub init: TnInitOptions,
}

/// Options for [`Tn::init_project_with_vault_claim_options`].
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct TnProjectVaultClaimOptions {
    /// Local project creation/opening options.
    pub project: TnProjectOptions,
    /// Pending-claim upload options.
    pub upload: VaultInitUploadOptions,
}

/// Result from the project-init plus vault-claim onboarding helper.
#[cfg(feature = "http")]
#[derive(Debug)]
pub struct TnProjectVaultClaim {
    /// Opened local TN project.
    pub tn: Tn,
    /// Pending-claim upload result, including the browser claim URL.
    pub claim: VaultInitUploadResult,
}

/// Options for [`Tn::read`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    /// Include entries from every run in the log instead of only this process.
    pub all_runs: bool,
    /// Include per-entry verification flags in a `_valid` block.
    ///
    /// The underlying `tn-core` verification read currently spans all runs.
    pub verify: bool,
}

/// Standard TN log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug-level diagnostic event.
    Debug,
    /// Info-level event.
    Info,
    /// Warning-level event.
    Warning,
    /// Error-level event.
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// Result of an emit call.
#[derive(Debug, Clone, PartialEq)]
pub struct EmitReceipt {
    /// Whether an envelope was written. `false` means the event was filtered by
    /// the active log-level threshold.
    pub emitted: bool,
    /// Parsed envelope for the written row when one was produced.
    pub envelope: Option<Value>,
}

/// Lightweight view of the active ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigView {
    /// Device identity of this runtime.
    pub device_identity: String,
    /// Path to the active log file.
    pub log_path: PathBuf,
    /// Path to the active `tn.yaml`.
    pub yaml_path: PathBuf,
    /// Group names declared by the active ceremony.
    pub groups: Vec<String>,
}

impl Tn {
    /// Open an existing ceremony from a `tn.yaml` path.
    ///
    /// This is the Rust SDK's explicit first step. Auto-discovery and
    /// project-name based creation can be added later once the layout behavior
    /// is covered by parity tests.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when `tn-core` cannot load the yaml, keystore, groups,
    /// or log writer.
    pub fn init(yaml_path: impl AsRef<Path>) -> Result<Self> {
        Self::init_with_options(yaml_path, TnInitOptions::default())
    }

    /// Open an existing ceremony from a `tn.yaml` path with explicit options.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when `tn-core` cannot load the runtime.
    pub fn init_with_options(yaml_path: impl AsRef<Path>, options: TnInitOptions) -> Result<Self> {
        let storage: Arc<dyn tn_core::storage::Storage> =
            Arc::new(tn_core::storage::FsStorage::new());
        let runtime_options = runtime_init_options(options);
        let runtime = Runtime::init_with_options(yaml_path.as_ref(), storage, runtime_options)?;
        Ok(Self { runtime })
    }

    /// Create or open a local project ceremony.
    ///
    /// The on-disk layout mirrors the Python and TypeScript SDKs:
    /// `.tn/<project>/tn.yaml` plus sibling `keys`, `logs`, `admin`, `vault`,
    /// and `streams` directories. Calling this again reuses the existing
    /// project yaml.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the project name is invalid, the ceremony cannot be
    /// created, or the resulting yaml cannot be loaded.
    pub fn init_project(project: &str) -> Result<Self> {
        Self::init_project_with_options(project, TnProjectOptions::default())
    }

    /// Create or open a local project ceremony with explicit options.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the project name is invalid, the ceremony cannot be
    /// created, or the resulting yaml cannot be loaded.
    pub fn init_project_with_options(project: &str, options: TnProjectOptions) -> Result<Self> {
        let yaml_path = ensure_project_layout(project, &options)?;
        Self::init_with_options(yaml_path, options.init)
    }

    /// Create or open a local project, upload an encrypted pending claim, and
    /// return both the opened project and browser claim URL.
    ///
    /// This is the Rust SDK's explicit equivalent of the Python/TypeScript
    /// onboarding flow that surfaces a vault claim link during init. It keeps
    /// [`Tn::init_project`] local-only while giving applications a single
    /// opt-in helper for first-run vault onboarding.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if local project creation/loading fails, package
    /// export fails, the HTTP upload fails, or the vault response is malformed.
    #[cfg(feature = "http")]
    pub fn init_project_with_vault_claim(
        project: &str,
        client: &VaultHttpProjectClient,
    ) -> Result<TnProjectVaultClaim> {
        Self::init_project_with_vault_claim_options(
            project,
            client,
            TnProjectVaultClaimOptions::default(),
        )
    }

    /// Create or open a local project and upload an encrypted pending claim
    /// with explicit local/project upload options.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if local project creation/loading fails, package
    /// export fails, the HTTP upload fails, or the vault response is malformed.
    #[cfg(feature = "http")]
    pub fn init_project_with_vault_claim_options(
        project: &str,
        client: &VaultHttpProjectClient,
        options: TnProjectVaultClaimOptions,
    ) -> Result<TnProjectVaultClaim> {
        let tn = Self::init_project_with_options(project, options.project)?;
        let claim = tn.vault().init_upload_http(client, options.upload)?;
        Ok(TnProjectVaultClaim { tn, claim })
    }

    /// Create a temporary btn-backed ceremony for tests and one-shot examples.
    ///
    /// The temporary directory is removed when the runtime is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the temporary ceremony cannot be created or loaded.
    pub fn ephemeral() -> Result<Self> {
        Ok(Self {
            runtime: Runtime::ephemeral()?,
        })
    }

    /// Emit a severity-less attested event.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object or the underlying
    /// runtime fails to write the event.
    pub fn log(&self, event_type: &str, fields: impl Serialize) -> Result<EmitReceipt> {
        self.emit("", event_type, fields)
    }

    /// Emit a debug-level attested event.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object or the underlying
    /// runtime fails to write the event.
    pub fn debug(&self, event_type: &str, fields: impl Serialize) -> Result<EmitReceipt> {
        self.emit(LogLevel::Debug.as_str(), event_type, fields)
    }

    /// Emit an info-level attested event.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object or the underlying
    /// runtime fails to write the event.
    pub fn info(&self, event_type: &str, fields: impl Serialize) -> Result<EmitReceipt> {
        self.emit(LogLevel::Info.as_str(), event_type, fields)
    }

    /// Emit a warning-level attested event.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object or the underlying
    /// runtime fails to write the event.
    pub fn warning(&self, event_type: &str, fields: impl Serialize) -> Result<EmitReceipt> {
        self.emit(LogLevel::Warning.as_str(), event_type, fields)
    }

    /// Emit an error-level attested event.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object or the underlying
    /// runtime fails to write the event.
    pub fn error(&self, event_type: &str, fields: impl Serialize) -> Result<EmitReceipt> {
        self.emit(LogLevel::Error.as_str(), event_type, fields)
    }

    /// Emit an attested event at an explicit level string.
    ///
    /// Use the level-specific helpers for normal application code.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `fields` is not a JSON object, if the emitted
    /// envelope cannot be parsed back from the core runtime, or if the
    /// underlying runtime fails.
    pub fn emit(
        &self,
        level: &str,
        event_type: &str,
        fields: impl Serialize,
    ) -> Result<EmitReceipt> {
        let fields = fields_to_map(fields)?;
        let line = self
            .runtime
            .emit_with_override_sign_returning_line(level, event_type, fields, None, None, None)?;
        let Some(line) = line else {
            return Ok(EmitReceipt {
                emitted: false,
                envelope: None,
            });
        };
        let envelope = serde_json::from_str::<Value>(line.trim_end()).map_err(|err| {
            Error::InvalidArgument(format!("tn-core returned malformed envelope JSON: {err}"))
        })?;
        Ok(EmitReceipt {
            emitted: true,
            envelope: Some(envelope),
        })
    }

    /// Read decrypted entries from the active log.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the log cannot be read or decrypted.
    pub fn read(&self, options: ReadOptions) -> Result<Vec<Entry>> {
        let entries = if options.verify {
            self.runtime.read_with_verify()?
        } else if options.all_runs {
            self.runtime.read_all_runs()?
        } else {
            self.runtime.read()?
        };
        Ok(entries.into_iter().map(Entry::from).collect())
    }

    /// Return the ceremony administration namespace.
    pub fn admin(&mut self) -> Admin<'_> {
        Admin::new(self)
    }

    /// Return the account namespace.
    pub fn account(&self) -> Account<'_> {
        Account::new(self)
    }

    /// Return the `.tnpkg` package namespace.
    pub fn pkg(&self) -> Package<'_> {
        Package::new(self)
    }

    /// Return the vault audit-event namespace.
    pub fn vault(&self) -> Vault<'_> {
        Vault::new(self)
    }

    /// Return the headless wallet sync namespace.
    pub fn wallet(&self) -> Wallet<'_> {
        Wallet::new(self)
    }

    /// Return the local invitation inbox namespace.
    pub fn inbox(&self) -> Inbox<'_> {
        Inbox::new(self)
    }

    /// Return a synchronous polling watcher over this runtime's read view.
    ///
    /// The current watcher is a v0 convenience API: it calls
    /// [`Tn::read`](Self::read) on each poll and filters newly visible entries.
    /// It does not use filesystem notifications or spawn a background tailing
    /// task.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the initial read used to position the watcher
    /// fails.
    pub fn watch(&self, options: WatchOptions) -> Result<Watch<'_>> {
        self.polling_watch(options)
    }

    /// Return a synchronous polling watcher over this runtime's read view.
    ///
    /// This is the explicit name for the SDK's default read-backed watcher.
    /// It is equivalent to [`Tn::watch`](Self::watch), but makes the polling
    /// behavior clear at call sites that may later choose a native watcher.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the initial read used to position the watcher
    /// fails.
    pub fn polling_watch(&self, options: PollingWatchOptions) -> Result<PollingWatch<'_>> {
        Watch::new(self, options)
    }

    /// Return a synchronous native file notification watcher.
    ///
    /// This API is available with the `watch` feature. It subscribes to the
    /// active log file with the `notify` crate and drains visible entries
    /// through the same read-backed filtering path as [`Tn::polling_watch`].
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the initial read used to position the watcher
    /// fails or native file watching cannot be initialized for the active log.
    #[cfg(feature = "watch")]
    pub fn native_watch(&self, options: NativeWatchOptions) -> Result<NativeWatch<'_>> {
        NativeWatch::new(self, options)
    }

    /// Return a lightweight view of the active runtime configuration.
    pub fn config(&self) -> ConfigView {
        ConfigView {
            device_identity: self.runtime.did().to_string(),
            log_path: self.runtime.log_path().to_path_buf(),
            yaml_path: self.runtime.yaml_path().to_path_buf(),
            groups: self.runtime.group_names(),
        }
    }

    /// This runtime's device identity.
    pub fn did(&self) -> &str {
        self.runtime.did()
    }

    /// Path to the active log file.
    pub fn log_path(&self) -> &Path {
        self.runtime.log_path()
    }

    /// Path to the active `tn.yaml`.
    pub fn yaml_path(&self) -> &Path {
        self.runtime.yaml_path()
    }

    /// Names of groups declared in the active ceremony.
    pub fn group_names(&self) -> Vec<String> {
        self.runtime.group_names()
    }

    /// Explicitly flush and close the runtime.
    ///
    /// Dropping `Tn` is fine for most callers; explicit close gives you a
    /// result you can surface.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying runtime close operation fails.
    pub fn close(self) -> Result<()> {
        Ok(self.runtime.close()?)
    }

    /// Set the process-wide log-level threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `level` is not recognized by `tn-core`.
    pub fn set_level(level: &str) -> Result<()> {
        Ok(Runtime::set_level(level)?)
    }

    /// Return the active process-wide log-level threshold.
    pub fn get_level() -> String {
        Runtime::get_level()
    }

    /// True when `level` would currently emit.
    pub fn is_enabled_for(level: &str) -> bool {
        Runtime::is_enabled_for(level)
    }

    pub(crate) fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub(crate) fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
    }
}

fn runtime_init_options(options: TnInitOptions) -> tn_core::RuntimeInitOptions {
    tn_core::RuntimeInitOptions {
        skip_ceremony_init_emit: options.skip_ceremony_init_emit,
        skip_policy_published_emit: options.skip_policy_published_emit,
    }
}

fn ensure_project_layout(project: &str, options: &TnProjectOptions) -> Result<PathBuf> {
    validate_project_name(project)?;

    let workspace = match &options.project_dir {
        Some(path) => path.clone(),
        None => std::env::current_dir()?,
    };
    let project_root = workspace.join(".tn").join(project);
    let yaml_path = project_root.join("tn.yaml");
    if yaml_path.is_file() {
        return Ok(yaml_path);
    }

    let keys_dir = project_root.join("keys");
    let private_path = keys_dir.join("local.private");
    if private_path.exists() {
        return Err(Error::InvalidArgument(format!(
            "refusing to create fresh ceremony at {}: {} already exists",
            yaml_path.display(),
            private_path.display()
        )));
    }

    for dir in [
        &project_root,
        &keys_dir,
        &project_root.join("logs"),
        &project_root.join("admin"),
        &project_root.join("vault"),
        &project_root.join("streams"),
    ] {
        std::fs::create_dir_all(dir)?;
    }

    let device_seed = project_device_seed(options, &workspace)?;
    write_project_ceremony(project, &project_root, &device_seed, options.profile)?;

    let default_stream = project_root.join("streams").join("default.yaml");
    if !default_stream.exists() {
        tn_core::keystore_backend::atomic_write_bytes(&default_stream, b"extends: ../tn.yaml\n")?;
    }

    Ok(yaml_path)
}

fn validate_project_name(project: &str) -> Result<()> {
    let mut chars = project.chars();
    let Some(first) = chars.next() else {
        return Err(invalid_project_name(project));
    };
    if project == "tn" || !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(invalid_project_name(project));
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
        return Err(invalid_project_name(project));
    }
    Ok(())
}

fn invalid_project_name(project: &str) -> Error {
    Error::InvalidArgument(format!(
        "invalid project name {project:?}; must match [a-zA-Z0-9_][a-zA-Z0-9_-]* and not be 'tn'"
    ))
}

fn write_project_ceremony(
    project: &str,
    project_root: &Path,
    device_private_bytes: &[u8; 32],
    profile: TnProfile,
) -> Result<()> {
    use tn_core::keystore_backend::atomic_write_bytes;

    let keys_dir = project_root.join("keys");
    let device = tn_core::DeviceKey::from_private_bytes(device_private_bytes)?;
    atomic_write_bytes(&keys_dir.join("local.private"), &device.private_bytes())?;
    atomic_write_bytes(&keys_dir.join("local.public"), device.did().as_bytes())?;

    let mut master = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    atomic_write_bytes(&keys_dir.join("index_master.key"), &master)?;

    write_btn_group(&keys_dir, "default")?;
    write_btn_group(&keys_dir, "tn.agents")?;

    let mut id_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut id_bytes);
    let ceremony_id = format!("local_{}", hex_lower(&id_bytes));
    let did = device.did();
    let handlers_yaml = handler_yaml(profile);
    let profile_name = profile.as_str();
    let signs = profile.signs();
    let chains = profile.chains();
    let yaml = format!(
        "ceremony:\n\
         \x20 id: {ceremony_id}\n\
         \x20 mode: local\n\
         \x20 cipher: btn\n\
         \x20 admin_log_location: ./admin/{DEFAULT_PROJECT_NAME}.ndjson\n\
         \x20 project_name: {project}\n\
         \x20 profile: {profile_name}\n\
         \x20 sign: {signs}\n\
         \x20 chain: {chains}\n\
         vault:\n\
         \x20 enabled: false\n\
         \x20 autosync: false\n\
         logs:\n\
         \x20 path: ./logs/{DEFAULT_PROJECT_NAME}.ndjson\n\
         {handlers_yaml}\
         keystore:\n\
         \x20 path: ./keys\n\
         device:\n\
         \x20 device_identity: \"{did}\"\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - recipient_identity: \"{did}\"\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - recipient_identity: \"{did}\"\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier:\n\
         \x20 enabled: false\n\
         \x20 provider: \"\"\n\
         \x20 model: \"\"\n",
    );
    atomic_write_bytes(&project_root.join("tn.yaml"), yaml.as_bytes())?;
    Ok(())
}

fn project_device_seed(options: &TnProjectOptions, workspace: &Path) -> Result<[u8; 32]> {
    if let Some(bytes) = options.device_private_bytes.as_deref() {
        return bytes.try_into().map_err(|_| {
            Error::InvalidArgument(format!(
                "device_private_bytes must be 32 bytes, got {}",
                bytes.len()
            ))
        });
    }

    let identity_path = match &options.project_dir {
        Some(_) => workspace.join(".tn").join("identity.json"),
        None => crate::default_identity_path(),
    };
    let identity = Identity::load_or_mint(&identity_path)?;
    identity.device_private_bytes()
}

fn handler_yaml(profile: TnProfile) -> String {
    if profile.default_sink_is_file() {
        return format!(
            "handlers:\n\
             \x20 - kind: file.rotating\n\
             \x20   name: main\n\
             \x20   path: ./logs/{DEFAULT_PROJECT_NAME}.ndjson\n\
             \x20   max_bytes: 5242880\n\
             \x20   backup_count: 5\n\
             \x20   rotate_on_init: false\n\
             \x20 - kind: stdout\n\
             \x20   format: compact\n"
        );
    }
    "handlers:\n\x20 - kind: stdout\n\x20   format: compact\n".to_string()
}

fn write_btn_group(keys_dir: &Path, group: &str) -> Result<()> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed)
        .map_err(|err| Error::InvalidArgument(format!("btn setup failed: {err:?}")))?;
    let kit = state
        .mint()
        .map_err(|err| Error::InvalidArgument(format!("btn mint failed: {err:?}")))?;
    tn_core::keystore_backend::atomic_write_bytes(
        &keys_dir.join(format!("{group}.btn.state")),
        &state.to_bytes(),
    )?;
    tn_core::keystore_backend::atomic_write_bytes(
        &keys_dir.join(format!("{group}.btn.mykit")),
        &kit.to_bytes(),
    )?;
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn fields_to_map(fields: impl Serialize) -> Result<Map<String, Value>> {
    match serde_json::to_value(fields).map_err(|err| Error::InvalidArgument(err.to_string()))? {
        Value::Object(map) => Ok(map),
        other => Err(Error::InvalidArgument(format!(
            "fields must serialize to a JSON object, got {}",
            value_kind(&other)
        ))),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
