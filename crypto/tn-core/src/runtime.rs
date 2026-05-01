//! Runtime: stateful composition of config, identity, ciphers, chain, log file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::{
    admin_catalog,
    admin_reduce::{reduce as admin_reduce_envelope, StateDelta},
    agents_policy::{load_policy_file, PolicyDocument},
    canonical::canonical_bytes,
    chain::{compute_row_hash, ChainState, GroupInput, RowHashInput},
    cipher::{
        btn::{BtnPublisherCipher, BtnReaderCipher},
        GroupCipher,
    },
    classifier::classify,
    config::{load as load_config, Config, GroupSpec},
    envelope::{build_envelope, EnvelopeInput, GroupPayload},
    identity::load_device,
    indexing::index_token,
    log_file::{LogFileReader, LogFileWriter},
    signing::{signature_b64, signature_from_b64, DeviceKey},
    Error, Result,
};

// tn_btn::LeafIndex needed by admin verbs.
// tn-btn is a direct dependency of tn-core (in Cargo.toml).

/// One decoded log entry returned from `read_raw`.
pub struct ReadEntry {
    /// Raw envelope value.
    pub envelope: Value,
    /// Per-group decrypted plaintext (only groups we can decrypt). May
    /// also carry sentinel values `{"$no_read_key": true}` (group present
    /// but no kit) or `{"$decrypt_error": true}` (decrypt threw) when
    /// produced through [`Runtime::read_raw_with_validity`].
    pub plaintext_per_group: BTreeMap<String, Value>,
}

/// Flat-shape entry returned from [`Runtime::read`] /
/// [`Runtime::read_with_verify`]. The six envelope basics + decrypted
/// fields from every readable group land at the top level. Per the
/// 2026-04-25 read-ergonomics spec §1.1.
pub type FlatEntry = Map<String, Value>;

/// Per-entry validity flags surfaced by [`Runtime::read_raw_with_validity`]
/// and the `_valid` block of [`Runtime::read_with_verify`].
#[derive(Debug, Clone, Copy)]
pub struct ValidFlags {
    /// Signature verifies against the envelope's `did`.
    pub signature: bool,
    /// Row_hash recomputes from canonical inputs.
    pub row_hash: bool,
    /// Per-event_type chain `prev_hash` lines up with the previous row.
    pub chain: bool,
}

/// What [`Runtime::secure_read`] does on a non-verifying entry. Per spec §3.1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnInvalid {
    /// Silently drop. A `tn.read.tampered_row_skipped` event is appended
    /// to the local admin log so monitoring can surface tampering
    /// without exposing the bad row's payload. Default.
    #[default]
    Skip,
    /// Return `Err(Error::Malformed{...})` on the first failure.
    Raise,
    /// Surface the entry with `_valid` and `_invalid_reasons` keys
    /// exposed. For auditor investigations only.
    Forensic,
}

/// Options for [`Runtime::secure_read`]. Mirrors Python's keyword args.
#[derive(Debug, Clone, Default)]
pub struct SecureReadOptions {
    /// What to do on a non-verifying entry.
    pub on_invalid: OnInvalid,
    /// Optional log path override; falls back to the runtime's own log.
    pub log_path: Option<PathBuf>,
}

/// Six writer-authored policy fields surfaced as a separate concern by
/// [`Runtime::secure_read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instructions {
    /// What this row records. From `tn.agents.instruction`.
    pub instruction: String,
    /// Sanctioned uses. From `tn.agents.use_for`.
    pub use_for: String,
    /// Explicitly denied uses. From `tn.agents.do_not_use_for`.
    pub do_not_use_for: String,
    /// What mishandling costs. From `tn.agents.consequences`.
    pub consequences: String,
    /// Escalation endpoint. From `tn.agents.on_violation_or_error`.
    pub on_violation_or_error: String,
    /// `<path>#<event_type>@<version>#<content_hash>`. From `tn.agents.policy`.
    pub policy: String,
}

/// One verified entry from [`Runtime::secure_read`]. Mirrors the dict
/// shape Python `tn.secure_read()` yields.
#[derive(Debug, Clone)]
pub struct SecureEntry {
    /// Flat decrypted data fields (envelope basics + every readable
    /// non-`tn.agents` group, plus public fields). The six `tn.agents`
    /// field names are NOT in this map — they live in `instructions`.
    pub fields: FlatEntry,
    /// Six tn.agents fields when the caller holds the kit AND the
    /// entry has populated tn.agents plaintext. Otherwise `None`.
    pub instructions: Option<Instructions>,
    /// Groups present in envelope with no readable plaintext.
    pub hidden_groups: Vec<String>,
    /// Groups whose decrypt threw.
    pub decrypt_errors: Vec<String>,
}

/// One row in the recipient roster derived from a log replay.
///
/// Mirrors the dict returned by Python `tn.recipients(group)` and the
/// `RecipientEntry` produced by TypeScript `client.recipients(group)`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecipientEntry {
    /// btn leaf index (or whatever recipient identifier the cipher uses).
    pub leaf_index: u64,
    /// Optional `did:key:…` of the recipient — `None` when the mint did not
    /// name one.
    pub recipient_did: Option<String>,
    /// Envelope timestamp from the `tn.recipient.added` event.
    pub minted_at: Option<String>,
    /// `sha256:` prefixed digest of the kit bytes the publisher minted.
    pub kit_sha256: Option<String>,
    /// True once a `tn.recipient.revoked` event was seen for this leaf.
    pub revoked: bool,
    /// Envelope timestamp from the revocation event when present.
    pub revoked_at: Option<String>,
}

/// `tn.ceremony.init` summary surfaced in `admin_state`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminCeremony {
    /// Ceremony identifier — matches `cfg.ceremony.id`.
    pub ceremony_id: String,
    /// Cipher name (`"btn"`, `"jwe"`, …).
    pub cipher: String,
    /// `did:key:…` of the device that initialized the ceremony.
    pub device_did: String,
    /// Envelope timestamp on the `tn.ceremony.init` event. `None` when the
    /// ceremony record is reconstructed from config (btn fallback).
    pub created_at: Option<String>,
}

/// One `tn.group.added` row in `admin_state.groups`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminGroupRecord {
    /// Group name (envelope key).
    pub group: String,
    /// Cipher backing this group.
    pub cipher: String,
    /// `did:key:…` of the publisher that declared the group.
    pub publisher_did: String,
    /// Envelope timestamp on the `tn.group.added` event.
    pub added_at: String,
}

/// One row in `admin_state.recipients`. Carries the recipient's lifecycle
/// status (`active` / `revoked` / `retired`) — distinct from the
/// `RecipientEntry` returned by `recipients`, which compresses the lifecycle
/// into a single `revoked` boolean.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminRecipientRecord {
    /// Group the recipient belongs to.
    pub group: String,
    /// btn leaf index (or cipher-specific identifier).
    pub leaf_index: u64,
    /// Optional `did:key:…` named at mint time.
    pub recipient_did: Option<String>,
    /// `sha256:` digest of the minted kit.
    pub kit_sha256: String,
    /// Envelope timestamp on the `tn.recipient.added` event.
    pub minted_at: Option<String>,
    /// Lifecycle: `"active"`, `"revoked"`, or `"retired"`.
    pub active_status: String,
    /// Envelope timestamp on the `tn.recipient.revoked` event when present.
    pub revoked_at: Option<String>,
    /// Envelope timestamp on the `tn.rotation.completed` event that retired
    /// this recipient when present.
    pub retired_at: Option<String>,
}

/// One row in `admin_state.rotations`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminRotation {
    /// Group whose kit was rotated.
    pub group: String,
    /// Cipher backing the group.
    pub cipher: String,
    /// New generation number.
    pub generation: u64,
    /// `sha256:` digest of the kit replaced by this rotation.
    pub previous_kit_sha256: String,
    /// Envelope timestamp on the `tn.rotation.completed` event.
    pub rotated_at: String,
}

/// One row in `admin_state.coupons`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminCoupon {
    /// Group the coupon was issued in.
    pub group: String,
    /// Coupon slot index.
    pub slot: u64,
    /// Recipient `did:key:…`.
    pub to_did: String,
    /// Free-form recipient label.
    pub issued_to: String,
    /// Envelope timestamp on the `tn.coupon.issued` event.
    pub issued_at: Option<String>,
}

/// One row in `admin_state.enrolments`. Status is `"offered"` until a
/// matching `tn.enrolment.absorbed` event lands, then `"absorbed"`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminEnrolment {
    /// Group the enrolment was compiled / absorbed for.
    pub group: String,
    /// `did:key:…` of the peer the package was for / from.
    pub peer_did: String,
    /// `sha256:` digest of the enrolment package bytes.
    pub package_sha256: String,
    /// `"offered"` or `"absorbed"`.
    pub status: String,
    /// Envelope timestamp on the `tn.enrolment.compiled` event.
    pub compiled_at: Option<String>,
    /// Envelope timestamp on the `tn.enrolment.absorbed` event.
    pub absorbed_at: Option<String>,
}

/// One row in `admin_state.vault_links`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdminVaultLink {
    /// `did:key:…` of the vault.
    pub vault_did: String,
    /// Vault project identifier.
    pub project_id: String,
    /// Envelope timestamp on the `tn.vault.linked` event.
    pub linked_at: String,
    /// Envelope timestamp on the `tn.vault.unlinked` event when present.
    pub unlinked_at: Option<String>,
}

/// Aggregate admin state derived by replaying the log through
/// `admin_reduce::reduce`. Mirrors Python `tn.admin_state(group=…)`.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct AdminState {
    /// Either the `tn.ceremony.init` record or, if absent, a record
    /// reconstructed from the active config (btn ceremonies don't write
    /// `ceremony.init` to the main log — the publisher state lives on disk).
    pub ceremony: Option<AdminCeremony>,
    /// Groups declared via `tn.group.added`.
    pub groups: Vec<AdminGroupRecord>,
    /// Recipient lifecycle rows.
    pub recipients: Vec<AdminRecipientRecord>,
    /// Rotation completion records.
    pub rotations: Vec<AdminRotation>,
    /// Coupons issued via `tn.coupon.issued`.
    pub coupons: Vec<AdminCoupon>,
    /// Peer enrolment records.
    pub enrolments: Vec<AdminEnrolment>,
    /// Vault-link records.
    pub vault_links: Vec<AdminVaultLink>,
}

/// Per-group runtime state: cipher + derived index key.
pub(crate) struct GroupState {
    pub(crate) cipher: Arc<dyn GroupCipher>,
    pub(crate) index_key: [u8; 32],
}

/// Stateful TN runtime: one per ceremony.
///
/// Holds identity, per-group ciphers, chain state, and an open log writer.
/// Constructed via [`Runtime::init`]; emit/read/close are implemented in
/// subsequent tasks.
///
/// Manual `Debug` impl: internal fields contain crypto material and OS file
/// handles that do not implement `Debug` themselves.
pub struct Runtime {
    pub(crate) yaml_path: PathBuf,
    pub(crate) cfg: Config,
    pub(crate) device: DeviceKey,
    pub(crate) chain: ChainState,
    /// Per-group state wrapped in RwLock so admin verbs can swap the cipher
    /// inside while emit/read hold a read lock.
    pub(crate) groups: BTreeMap<String, Arc<RwLock<GroupState>>>,
    pub(crate) log_writer: Mutex<LogFileWriter>,
    pub(crate) log_path: PathBuf,
    #[allow(dead_code)]
    pub(crate) master_index_key: [u8; 32],
    /// Side-table for btn publisher states: gives admin verbs typed mutable
    /// access without downcasting the `GroupCipher` trait object.
    pub(crate) btn_admin: BTreeMap<String, Arc<Mutex<BtnPublisherCipher>>>,
    /// Remembered mykit bytes per btn group (for rebuilding cipher after admin).
    pub(crate) btn_mykit: BTreeMap<String, Option<Vec<u8>>>,
    /// Keystore path, needed by admin verbs to persist updated state.
    pub(crate) keystore: PathBuf,
    /// Optional owned tempdir for [`Runtime::ephemeral`] — kept alive so
    /// `Drop` cleans the directory when this runtime goes out of scope.
    /// `None` for runtimes built via [`Runtime::init`] that point at a
    /// caller-managed yaml.
    #[allow(dead_code)]
    pub(crate) owned_tempdir: Option<tempfile::TempDir>,
    /// Optional `.tn/config/agents.md` policy document loaded at init time.
    /// Used by the emit-side splice (per 2026-04-25 spec §2.6) and the
    /// `tn.agents.policy_published` lifecycle event.
    pub(crate) agent_policies: Option<PolicyDocument>,
    /// Handlers registered via [`Runtime::add_handler`]. Each emitted
    /// envelope is fanned out to every handler whose `accepts()` returns
    /// true. Mirrors Python's `Logger.handlers` and TS's
    /// `NodeRuntime.handlers` (see `python/tn/logger.py:343` and
    /// `ts-sdk/src/runtime/node_runtime.ts:376`). Failing handlers are
    /// logged + swallowed — they never propagate back to the caller.
    pub(crate) handlers: Mutex<Vec<Arc<dyn crate::handlers::TnHandler>>>,
    /// Per-runtime UUID auto-injected on every emit as a public field.
    /// Lets [`Runtime::read`] default-filter to "this run only" so naive
    /// filters don't pick up entries from prior runs (FINDINGS.md #12).
    /// Mirrors Python's per-process `_run_id` and TS's per-client run id.
    pub(crate) run_id: String,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("yaml_path", &self.yaml_path)
            .field("did", &self.device.did())
            .field("log_path", &self.log_path)
            .finish_non_exhaustive()
    }
}

/// Standard log-level numeric values, mirroring stdlib Python `logging`.
/// Used by [`Runtime::set_level`] / [`Runtime::is_enabled_for`] (AVL J3.2).
pub mod log_level {
    /// DEBUG threshold (10). Lowest level; floor default — emits everything.
    pub const DEBUG: i32 = 10;
    /// INFO threshold (20). Drops debug-level emits.
    pub const INFO: i32 = 20;
    /// WARNING threshold (30). Drops debug + info emits.
    pub const WARNING: i32 = 30;
    /// ERROR threshold (40). Drops everything below error.
    pub const ERROR: i32 = 40;
}

/// Process-wide level threshold. Verbs whose level is below this value
/// short-circuit before any work happens — no canonicalize, no sign, no
/// I/O. Default 10 (DEBUG, the floor) so callers see prior behavior;
/// raise via [`Runtime::set_level`]. Static so the early-exit gate is a
/// single atomic load. Mirrors Python's `_log_level_threshold` and TS's
/// `TNClient._logLevelThreshold`.
static LOG_LEVEL_THRESHOLD: AtomicI32 = AtomicI32::new(log_level::DEBUG);

/// Map a level name to its numeric threshold. Empty string and any
/// unrecognized name both fall through to -1 so they treat as
/// "always passes" / "below every meaningful threshold." The four
/// standard names match case-insensitively; `warn` is an alias for
/// `warning`.
fn level_value(level: &str) -> i32 {
    match level {
        "debug" | "DEBUG" => log_level::DEBUG,
        "info" | "INFO" => log_level::INFO,
        "warning" | "WARNING" | "warn" | "WARN" => log_level::WARNING,
        "error" | "ERROR" => log_level::ERROR,
        _ => -1,
    }
}

impl Runtime {
    /// Set the process-wide log-level threshold. Verbs at a lower level
    /// short-circuit before any work happens. Mirrors Python
    /// `tn.set_level()` and TS `TNClient.setLevel()`. (AVL J3.2.)
    ///
    /// Accepts the four standard names ("debug" / "info" / "warning" /
    /// "error") case-insensitively, plus "warn" as an alias for warning.
    /// Returns `Err(Error::InvalidConfig)` for unrecognized names.
    ///
    /// The severity-less [`Runtime::log`] always emits regardless of the
    /// threshold — it's an explicit "this is a fact" primitive.
    pub fn set_level(level: &str) -> Result<()> {
        let normalized = level.to_lowercase();
        let v = match normalized.as_str() {
            "" => -1,
            "debug" => log_level::DEBUG,
            "info" => log_level::INFO,
            "warning" | "warn" => log_level::WARNING,
            "error" => log_level::ERROR,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "set_level: unknown level {other:?}; expected debug/info/warning/error"
                )));
            }
        };
        LOG_LEVEL_THRESHOLD.store(v, Ordering::Relaxed);
        Ok(())
    }

    /// Set the threshold from a numeric value (10/20/30/40 etc.). Lets
    /// callers plug in custom severities without round-tripping through
    /// the string map.
    pub fn set_level_value(level: i32) {
        LOG_LEVEL_THRESHOLD.store(level, Ordering::Relaxed);
    }

    /// Return the active threshold as a level name when it matches one
    /// of the standard four; otherwise return its numeric stringified
    /// value.
    pub fn get_level() -> String {
        match LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) {
            log_level::DEBUG => "debug".to_string(),
            log_level::INFO => "info".to_string(),
            log_level::WARNING => "warning".to_string(),
            log_level::ERROR => "error".to_string(),
            other => other.to_string(),
        }
    }

    /// True iff `level` would currently emit. Use as a guard for
    /// expensive log-arg construction (mirrors stdlib
    /// `logging.Logger.isEnabledFor`).
    pub fn is_enabled_for(level: &str) -> bool {
        level_value(level) >= LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed)
    }

    /// Load a ceremony from `yaml_path` and return a ready-to-use Runtime.
    ///
    /// Long by design: the init flow needs to thread keystore loading,
    /// per-group cipher construction, log-path resolution, chain seeding,
    /// stdout-handler honoring of the yaml `handlers:` block (FINDINGS
    /// S0.4), yaml-driven `log_level` apply (AVL J3.2), and a
    /// `tn.ceremony.init` first-emit on fresh creation. Splitting it
    /// further would fragment those invariants across helpers.
    #[allow(clippy::too_many_lines)]
    pub fn init(yaml_path: &Path) -> Result<Self> {
        let cfg = load_config(yaml_path)?;
        let yaml_dir = yaml_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let keystore = resolve(&yaml_dir, Path::new(&cfg.keystore.path));

        let device = load_device(&keystore)?;
        if device.did() != cfg.me.did {
            return Err(Error::InvalidConfig(format!(
                "keystore DID {} does not match yaml me.did {}",
                device.did(),
                cfg.me.did
            )));
        }

        // Master index key; filename matches Python tn/config.py: index_master.key, 32 raw bytes.
        let master_path = keystore.join("index_master.key");
        let master_index_key: [u8; 32] = std::fs::read(&master_path)
            .map_err(Error::Io)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("index_master.key must be 32 bytes".into()))?;

        let mut groups: BTreeMap<String, Arc<RwLock<GroupState>>> = BTreeMap::new();
        let mut btn_admin: BTreeMap<String, Arc<Mutex<BtnPublisherCipher>>> = BTreeMap::new();
        let mut btn_mykit: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();

        for (name, spec) in &cfg.groups {
            let index_key = crate::indexing::derive_group_index_key(
                &master_index_key,
                &cfg.ceremony.id,
                name,
                spec.index_epoch,
            )?;
            let (cipher, maybe_pub_cipher, mykit_bytes) =
                build_cipher_with_admin(spec, &keystore, name)?;
            groups.insert(
                name.clone(),
                Arc::new(RwLock::new(GroupState { cipher, index_key })),
            );
            if let Some(pub_cipher) = maybe_pub_cipher {
                btn_admin.insert(name.clone(), Arc::new(Mutex::new(pub_cipher)));
            }
            btn_mykit.insert(name.clone(), mykit_bytes);
        }

        // Honor `logs.path` from the yaml. Relative paths resolve against
        // the yaml directory; absolute paths are used as-is. Default is
        // `./.tn/logs/tn.ndjson` relative to yaml dir (set by config's serde
        // default if the yaml doesn't mention `logs:`).
        let configured = Path::new(&cfg.logs.path);
        let log_path = if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            yaml_dir.join(configured)
        };

        // Session-start rotation: when the existing log has content
        // from a prior PROCESS, roll it to `<name>.1` (shifting any
        // older `.1`..`.N` backups forward up to `backup_count`) so
        // the new session writes into a fresh file. Matches stdlib
        // `logging` mental model and the Python `FileRotatingHandler`
        // / TS `NodeRuntime` behavior.
        //
        // Process-scoped guard: the rotation must only happen ONCE per
        // process per log path. A common test/dev pattern is:
        //
        //     tn.init(yaml)         # first init: rotate (new session)
        //     tn.info(...)
        //     tn.flush_and_close()
        //     tn.init(yaml)         # re-init in SAME process: append, do not rotate
        //     tn.read()             # must see what we just wrote
        //
        // Without the guard, every Runtime::init in the same process
        // would rotate the log and the chain would break. We track which
        // log paths we've already rotated in this process via a global
        // set, populated lazily on first rotation per path.
        // Honors yaml `handlers[*].rotate_on_init: false` to opt out.
        let (rotate_on_init, backup_count) = read_rotation_config(&cfg.handlers);
        if rotate_on_init && rotation_first_time_this_process(&log_path) {
            rotate_log_on_session_start(&log_path, backup_count);
        }

        let chain = ChainState::new();

        // Seed chain state from the main log and check for a prior ceremony.init.
        let mut saw_ceremony_init = seed_chain_from_log(&log_path, &chain)?;

        // Session rotation makes the current main log empty; a prior
        // `tn.ceremony.init` may live on a rotation backup. Scan the
        // shifted `<log>.1`..`.N` files so we don't re-emit
        // `tn.ceremony.init` on every session start (which would
        // pollute the admin log with one Frank-own event per session
        // and break cross-publisher reads of admin snapshots).
        if !saw_ceremony_init {
            for n in 1..=backup_count.max(1) {
                let backup = path_with_backup_suffix(&log_path, n);
                if backup.exists() && scan_for_ceremony_init(&backup)? {
                    saw_ceremony_init = true;
                    break;
                }
            }
        }

        // When protocol_events_location routes tn.* events to a separate file,
        // tn.ceremony.init never touches the main log. Check that file too.
        if !saw_ceremony_init && cfg.ceremony.protocol_events_location != "main_log" {
            let pel = resolve_pel_static(
                &cfg.ceremony.protocol_events_location,
                &yaml_dir,
                &cfg.ceremony.id,
                device.did(),
            );
            saw_ceremony_init = scan_for_ceremony_init(&pel)?;
        }

        // A ceremony is fresh iff no prior tn.ceremony.init exists in the log(s).
        // Checking main-log existence would miss the case where
        // protocol_events_location routes tn.* events to a separate file.
        let is_fresh = !saw_ceremony_init;

        let log_writer = Mutex::new(LogFileWriter::open(&log_path)?);

        // Load `<yaml_dir>/.tn/config/agents.md` if present. Absent file is
        // fine — splice no-ops and `tn.agents` group plaintext stays empty.
        let agent_policies = match load_policy_file(&yaml_dir) {
            Ok(opt) => opt,
            Err(Error::Io(_)) => None,
            Err(e) => return Err(e),
        };

        let rt = Self {
            yaml_path: yaml_path.to_path_buf(),
            cfg,
            device,
            chain,
            groups,
            log_writer,
            log_path,
            master_index_key,
            btn_admin,
            btn_mykit,
            keystore,
            owned_tempdir: None,
            agent_policies,
            handlers: Mutex::new(Vec::new()),
            // Honor $TN_RUN_ID if the host (e.g. the Python wrapper) has
            // already minted one for this process. Otherwise mint a fresh
            // UUID. Either way every emit stamps the same `run_id` so
            // `Runtime::read` can default-filter to "this run only".
            run_id: std::env::var("TN_RUN_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string()),
        };

        // Default-on stdout handler: emit every envelope as a JSON line on
        // stdout in addition to the configured file/sink handlers. Mirrors
        // Python's `tn.init(stdout=True)` default and the TS SDK's
        // `TNClient` default. Opt-out via:
        //
        //   * ``TN_NO_STDOUT=1`` (env, all sinks)
        //   * yaml ``handlers: [...]`` declared with no ``kind: stdout``
        //     entry — yaml-as-contract per FINDINGS S0.4. The shipping
        //     ``create_fresh`` writes ``handlers: [file.rotating, stdout]``
        //     so the operator can edit/remove the entry to silence stdout
        //     for both admin and user emits without having to set the
        //     env var.
        let yaml_silences_stdout = !rt.cfg.handlers.is_empty()
            && !rt
                .cfg
                .handlers
                .iter()
                .any(|h| h.get("kind").and_then(|v| v.as_str()) == Some("stdout"));
        if std::env::var("TN_NO_STDOUT").as_deref() != Ok("1") && !yaml_silences_stdout {
            rt.add_handler(Arc::new(crate::handlers::StdoutHandler::new()));
        }

        // Honor an optional yaml `ceremony.log_level` so operators can
        // bake the threshold into config (AVL J3.2). Programmatic
        // `Runtime::set_level` calls are sticky across re-inits in the
        // same process, so only apply the yaml value when the threshold
        // is still at the floor default (DEBUG).
        if !rt.cfg.ceremony.log_level.is_empty()
            && LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) == log_level::DEBUG
        {
            // Best-effort: bad level names are logged + ignored so init
            // doesn't fail on a stale yaml field.
            if let Err(e) = Runtime::set_level(&rt.cfg.ceremony.log_level) {
                log::warn!(
                    "ceremony.log_level={:?} ignored: {e}",
                    rt.cfg.ceremony.log_level
                );
            }
        }

        // Fresh ceremony: emit tn.ceremony.init as the first attested event.
        // The reload path does not emit this (only fresh creation). See spec §2.1.
        if is_fresh {
            let now = current_timestamp();
            let mut init_fields = serde_json::Map::new();
            init_fields.insert("ceremony_id".into(), serde_json::json!(rt.cfg.ceremony.id));
            init_fields.insert("cipher".into(), serde_json::json!(rt.cfg.ceremony.cipher));
            init_fields.insert("device_did".into(), serde_json::json!(rt.device.did()));
            init_fields.insert("created_at".into(), serde_json::json!(now));
            if let Err(e) = rt.emit("info", "tn.ceremony.init", init_fields) {
                log::warn!(
                    "ceremony_init attestation failed: event_type=tn.ceremony.init error={e}"
                );
            }
        }

        // Emit tn.agents.policy_published when the loaded policy hash differs
        // from the most recent published one in the local logs (or no prior
        // event exists). Mirrors Python `_maybe_emit_policy_published`.
        if let Err(e) = rt.maybe_emit_policy_published() {
            log::warn!("tn.agents.policy_published emit failed: {e}");
        }

        Ok(rt)
    }

    /// Build a runtime backed by a freshly-minted ceremony in a private
    /// tempdir. The tempdir is owned by the returned `Runtime` and is
    /// deleted when the runtime is dropped.
    ///
    /// Mirrors the ergonomics of Python's `tn.session()` / TS
    /// `TNClient.ephemeral()` for tests and one-shot scripts where the
    /// caller doesn't care about persisting the ceremony.
    ///
    /// Always uses `cipher: btn` because (a) it's hermetic — no JWE
    /// keypair wiring required — and (b) it's the cipher the cross-SDK
    /// test surface targets first.
    pub fn ephemeral() -> Result<Self> {
        let td = tempfile::Builder::new()
            .prefix("tn-ephemeral-")
            .tempdir()
            .map_err(Error::Io)?;
        let yaml_path = td.path().join("tn.yaml");
        write_fresh_btn_ceremony(td.path()).map_err(Error::Io)?;

        let mut rt = Self::init(&yaml_path)?;
        rt.owned_tempdir = Some(td);
        Ok(rt)
    }

    /// This runtime's `did:key:z…`.
    pub fn did(&self) -> &str {
        self.device.did()
    }

    /// Path to the main ndjson log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Names of groups declared in the active config.
    pub fn group_names(&self) -> Vec<String> {
        self.cfg.groups.keys().cloned().collect()
    }

    /// Emit an event with current timestamp and fresh UUID.
    ///
    /// Signing follows the ceremony's `sign` config flag; use
    /// [`Runtime::emit_override_sign`] to override on a per-call basis.
    ///
    /// Returns `Result<()>` for cross-language parity (Python `tn.log`
    /// returns `None`, TS `tn.log` returns `void`). Internal callers that
    /// need the row_hash / event_id / sequence drop down to `emit_inner`.
    pub fn emit(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
    ) -> Result<()> {
        self.emit_inner(level, event_type, fields, None, None, None)
    }

    /// Emit with explicit timestamp and event_id; used by deterministic tests.
    ///
    /// Signing follows the ceremony's `sign` config flag. Use
    /// [`Runtime::emit_override_sign`] or [`Runtime::emit_with_override_sign`]
    /// when the caller wants to flip signing for one entry.
    ///
    /// # Panics
    ///
    /// Panics if the internal log-writer mutex is poisoned.
    pub fn emit_with(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<()> {
        self.emit_inner(level, event_type, fields, timestamp, event_id, None)
    }

    /// Emit with an explicit `sign` override and current timestamp / fresh UUID.
    ///
    /// `Some(true)` forces a signature regardless of yaml config;
    /// `Some(false)` skips the signature; `None` uses the ceremony default.
    pub fn emit_override_sign(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        sign: Option<bool>,
    ) -> Result<()> {
        self.emit_inner(level, event_type, fields, None, None, sign)
    }

    /// Full-control emit: explicit timestamp, event_id, and sign override.
    ///
    /// `sign=None` uses the ceremony default; `Some(true)` forces signing;
    /// `Some(false)` skips signing.
    pub fn emit_with_override_sign(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<()> {
        self.emit_inner(level, event_type, fields, timestamp, event_id, sign)
    }

    /// Severity-less attested event. Matches Python `tn.log(event_type, **fields)`.
    ///
    /// Use when the event isn't fundamentally debug/info/warning/error — it's a
    /// fact to attest. The emitted envelope carries `level: ""`.
    pub fn log(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("", event_type, fields)
    }

    /// DEBUG-level attested event. Matches Python `tn.debug(event_type, **fields)`.
    pub fn debug(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("debug", event_type, fields)
    }

    /// INFO-level attested event. Matches Python `tn.info(event_type, **fields)`.
    pub fn info(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("info", event_type, fields)
    }

    /// WARNING-level attested event. Matches Python `tn.warning(event_type, **fields)`.
    pub fn warning(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("warning", event_type, fields)
    }

    /// ERROR-level attested event. Matches Python `tn.error(event_type, **fields)`.
    pub fn error(&self, event_type: &str, fields: Map<String, Value>) -> Result<()> {
        self.emit("error", event_type, fields)
    }

    // emit_inner is the single canonical path for building + signing an
    // envelope; splitting it further would fragment the invariants enforced
    // across the sealing/signing/writing phases.
    #[allow(clippy::too_many_lines)]
    fn emit_inner(
        &self,
        level: &str,
        event_type: &str,
        mut fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<()> {
        // Log-level filter (AVL J3.2). Drop emits whose level is below
        // the active threshold before any work happens. Severity-less
        // ("") always passes — it's an explicit "this is a fact"
        // primitive whose semantics shouldn't depend on the filter.
        if !level.is_empty() {
            let lv = level_value(level);
            if lv >= 0 && lv < LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) {
                return Ok(());
            }
        }

        validate_event_type(event_type)?;

        // Auto-inject run_id (FINDINGS.md #12). Caller can override by
        // passing `run_id` explicitly in fields.
        if !fields.contains_key("run_id") {
            fields.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        }

        // Splice the `tn.agents` policy text into `fields` for this
        // event_type, if a template is loaded. setdefault semantics — the
        // caller can override individual fields per-emit. Per 2026-04-25
        // spec §2.6.
        self.splice_agent_policy(event_type, &mut fields);

        // Catalog check: any tn.* event that's in the catalog must pass schema
        // validation before we sign it. This prevents the publisher from
        // accidentally signing an envelope that the reducer would later reject.
        // Unknown tn.* events (not in the catalog) pass through unchecked --
        // forward-compat for event kinds added in newer publishers.
        if event_type.starts_with("tn.") {
            if let Some(_kind) = admin_catalog::kind_for(event_type) {
                admin_catalog::validate_emit(event_type, &fields).map_err(|e| {
                    Error::Malformed {
                        kind: "admin event",
                        reason: format!("admin event {event_type} failed schema: {e}"),
                    }
                })?;
            }
        }

        let ts = timestamp.map_or_else(current_timestamp, str::to_string);
        let eid = event_id.map_or_else(|| Uuid::new_v4().to_string(), str::to_string);
        let level_norm = level.to_ascii_lowercase();

        // 1. Classify fields: public vs per-group.
        //
        // Multi-group routing: a field declared under N groups in yaml
        // (`groups[<g>].fields: [...]`) is encrypted into all N groups'
        // payloads. The `field_to_groups()` map is sorted alphabetically
        // per field at load time so envelope encoding stays canonical
        // across SDK implementations.
        let public_set: HashSet<&str> = self.cfg.public_fields.iter().map(String::as_str).collect();
        let field_to_groups = self.cfg.field_to_groups()?;
        let mut public_out: Map<String, Value> = Map::new();
        let mut per_group: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for (k, v) in fields {
            if public_set.contains(k.as_str()) {
                public_out.insert(k, v);
                continue;
            }
            let routed = field_to_groups.get(&k).cloned().unwrap_or_default();
            let gnames: Vec<String> = if routed.is_empty() {
                // Field has no declared route. Try the legacy classifier
                // (returns a single name today, "default" by stub). If
                // that lands in a known group, use it; otherwise fall
                // back to the "default" group when present. Last resort
                // raise — silent fall-through is exactly what multi-group
                // routing was meant to fix.
                let guess = classify(&self.cfg, &k).to_string();
                if self.cfg.groups.contains_key(&guess) {
                    vec![guess]
                } else if self.cfg.groups.contains_key("default") {
                    vec!["default".to_string()]
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "field {k:?} has no group route and is not in \
                         public_fields. Add it to `groups[<g>].fields` in \
                         tn.yaml, list it under public_fields, or define a \
                         `default` group to absorb unknowns."
                    )));
                }
            } else {
                routed
            };
            for gname in gnames {
                per_group
                    .entry(gname)
                    .or_default()
                    .insert(k.clone(), v.clone());
            }
        }

        // 2. Index tokens + 3. Encrypt per group.
        let mut group_inputs_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
        let mut group_payloads: Map<String, Value> = Map::new();

        for (gname, plain) in per_group {
            let Some(gstate_arc) = self.groups.get(&gname) else {
                // Field routed to a group we don't know; skip silently, matching
                // Python's fall-through to "default".
                continue;
            };
            let gstate = gstate_arc.read().expect("group state RwLock poisoned");
            // Deterministic sort: ciphertext is canonical of sorted fields.
            let sorted: BTreeMap<String, Value> = plain.into_iter().collect();
            let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in &sorted {
                field_hashes.insert(k.clone(), index_token(&gstate.index_key, k, v)?);
            }
            let plaintext_bytes = canonical_bytes(&Value::Object(sorted.into_iter().collect()))?;
            let ct = match gstate.cipher.encrypt(&plaintext_bytes) {
                Ok(ct) => ct,
                Err(Error::NotAPublisher { .. }) => continue,
                Err(e) => return Err(e),
            };
            group_inputs_for_hash.insert(
                gname.clone(),
                GroupInput {
                    ciphertext: ct.clone(),
                    field_hashes: field_hashes.clone(),
                },
            );
            let payload = GroupPayload {
                ciphertext: ct,
                field_hashes,
            };
            group_payloads.insert(gname, serde_json::to_value(payload)?);
        }

        // 4. Chain advance.
        let (seq, prev_hash) = self.chain.advance(event_type);

        // 5. Row hash.
        let public_bmap: BTreeMap<String, Value> = public_out.clone().into_iter().collect();
        let row_hash = compute_row_hash(&RowHashInput {
            did: self.device.did(),
            timestamp: &ts,
            event_id: &eid,
            event_type,
            level: &level_norm,
            prev_hash: &prev_hash,
            public_fields: &public_bmap,
            groups: &group_inputs_for_hash,
        });

        // 6. Sign: respects per-call override, then ceremony default.
        let should_sign = sign.unwrap_or(self.cfg.ceremony.sign);
        let sig_b64 = if should_sign {
            let sig = self.device.sign(row_hash.as_bytes());
            signature_b64(&sig)
        } else {
            // Unsigned mode: envelope's signature field is the empty string.
            // Chain and row_hash are still computed, so accidental corruption
            // is still detectable. See RFC 2026-04-22-tn-transaction-protocol.
            String::new()
        };

        // 7. Envelope serialize.
        let line = build_envelope(EnvelopeInput {
            did: self.device.did(),
            timestamp: &ts,
            event_id: &eid,
            event_type,
            level: &level_norm,
            sequence: seq,
            prev_hash: &prev_hash,
            row_hash: &row_hash,
            signature_b64: &sig_b64,
            public_fields: public_out,
            group_payloads,
        })?;

        // 8. Append to log file; protocol events (`tn.*`) may route to a
        //    separate file when `protocol_events_location` is a template.
        let is_protocol = event_type.starts_with("tn.");
        if is_protocol && self.cfg.ceremony.protocol_events_location != "main_log" {
            use std::io::Write;
            let pel = self.resolve_pel(event_type);
            if let Some(parent) = pel.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&pel)?;
            f.write_all(line.as_bytes())?;
        } else {
            let mut w = self.log_writer.lock().expect("log writer mutex poisoned");
            w.append_line(&line)?;
            w.flush()?;
        }

        // 9. Commit row_hash into the chain.
        self.chain.commit(event_type, &row_hash);

        // 10. Fan out to handlers. Mirrors Python `tn/logger.py:343` and
        //     TS `node_runtime.ts:376`. A handler whose filter rejects
        //     the envelope is skipped; a handler whose `emit` panics or
        //     errors is logged + swallowed so the publish call still
        //     succeeds for the caller.
        self.fan_out_to_handlers(line.as_bytes(), event_type, &eid);

        // event_id, row_hash, and sequence are not surfaced — emit*()
        // returns Result<()> for cross-language parity with Python (None)
        // and TypeScript (void). The envelope on disk carries them.
        let _ = (eid, row_hash, seq);
        Ok(())
    }

    /// Register a handler to receive every subsequent emit fan-out.
    /// Mirrors Python's `extra_handlers` constructor parameter and TS
    /// `NodeRuntime.addHandler`.
    ///
    /// The handler's `accepts()` is consulted per-envelope; only
    /// matching events reach `emit()`. Errors raised inside `emit()` are
    /// logged via `log::warn!` and swallowed — the publish call must
    /// not fail because a downstream handler had a bad day.
    ///
    /// # Panics
    /// Panics if the internal handlers mutex is poisoned.
    pub fn add_handler(&self, handler: Arc<dyn crate::handlers::TnHandler>) {
        self.handlers
            .lock()
            .expect("handlers mutex poisoned")
            .push(handler);
    }

    /// Number of currently-attached handlers. Mainly for tests.
    ///
    /// # Panics
    /// Panics if the internal handlers mutex is poisoned.
    pub fn handler_count(&self) -> usize {
        self.handlers
            .lock()
            .expect("handlers mutex poisoned")
            .len()
    }

    fn fan_out_to_handlers(&self, raw_line: &[u8], event_type: &str, event_id: &str) {
        // Snapshot the handler list under the lock, then release it
        // before invoking handlers. A handler that re-enters emit (e.g.
        // to log a derived event) would otherwise deadlock the mutex.
        let handlers: Vec<Arc<dyn crate::handlers::TnHandler>> = {
            let guard = self.handlers.lock().expect("handlers mutex poisoned");
            if guard.is_empty() {
                return;
            }
            guard.iter().map(Arc::clone).collect()
        };

        // Re-parse the just-written line into an envelope Value. The
        // line is freshly produced by `build_envelope` so this is
        // infallible in practice; if it ever fails we log and skip
        // fan-out rather than corrupt the caller's emit.
        let envelope: Value = match serde_json::from_slice(raw_line) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "handler fan-out: failed to parse envelope JSON for {event_type}/{event_id}: {e}"
                );
                return;
            }
        };

        for h in &handlers {
            if !h.accepts(&envelope) {
                continue;
            }
            // The TnHandler trait's `emit` returns `()` — handlers are
            // expected to swallow their own errors and log internally
            // (see vault_push.rs:308). We additionally wrap the call
            // in catch_unwind so a panicking handler does not poison
            // the publish path. Panics are rare; log + continue.
            let h_for_call = Arc::clone(h);
            let env_ref = &envelope;
            let raw_ref = raw_line;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                h_for_call.emit(env_ref, raw_ref);
            }));
            if let Err(payload) = result {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                log::warn!(
                    "handler {:?} panicked on {event_type}/{event_id}; entry already sealed: {msg}",
                    h.name()
                );
            }
        }
    }

    /// Read all entries from this runtime's log file, decrypting every group
    /// this runtime can decrypt.
    ///
    /// **Default shape: flat dicts** per the 2026-04-25 read-ergonomics
    /// spec. The six envelope basics (`timestamp`, `event_type`, `level`,
    /// `did`, `sequence`, `event_id`) plus every readable group's
    /// decrypted fields land at the top level. `_hidden_groups` /
    /// `_decrypt_errors` markers surface only when non-empty. The six
    /// reserved `tn.agents` field names DO appear in the flat dict by
    /// default; use [`Runtime::secure_read`] to lift them into a separate
    /// `instructions` block instead.
    ///
    /// Use [`Runtime::read_raw`] for the audit-grade `{envelope,
    /// plaintext_per_group}` shape, [`Runtime::read_with_verify`] for the
    /// flat shape plus a `_valid` block.
    pub fn read(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw()?;
        Ok(raw
            .into_iter()
            .map(|r| flatten_raw_entry(&r, false))
            .filter(|flat| flat_in_current_run(flat, &self.run_id))
            .collect())
    }

    /// Like [`Runtime::read`] but returns entries from EVERY run (not
    /// just the current process's `run_id`). Use for audit / compliance
    /// reports that span the whole log lifetime; everyday "show me what
    /// just happened" queries should stick with [`Runtime::read`] so a
    /// naive filter doesn't pull in entries from prior runs (FINDINGS.md
    /// #12).
    pub fn read_all_runs(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw()?;
        Ok(raw.into_iter().map(|r| flatten_raw_entry(&r, false)).collect())
    }

    /// Like [`Runtime::read`] but adds a `_valid: {signature, row_hash,
    /// chain}` block to each flat dict per spec §1.3.
    pub fn read_with_verify(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw_with_validity()?;
        Ok(raw
            .into_iter()
            .map(|(entry, valid)| {
                let mut flat = flatten_raw_entry(&entry, false);
                let mut v = Map::new();
                v.insert("signature".into(), Value::Bool(valid.signature));
                v.insert("row_hash".into(), Value::Bool(valid.row_hash));
                v.insert("chain".into(), Value::Bool(valid.chain));
                flat.insert("_valid".into(), Value::Object(v));
                flat
            })
            .collect())
    }

    /// Read all entries as the audit-grade `ReadEntry` shape (envelope +
    /// per-group decrypted plaintext). Mirrors the pre-2026-04-25
    /// `Runtime::read()` return.
    pub fn read_raw(&self) -> Result<Vec<ReadEntry>> {
        let log_path = self.log_path.clone();
        self.read_from(&log_path)
    }

    /// Iterate verified entries — fail-closed on any (signature,
    /// row_hash, chain) failure. Per the 2026-04-25 read-ergonomics spec §3.
    ///
    /// Returns flat dicts in the same default shape as [`Runtime::read`],
    /// plus an `instructions` block when the caller holds the
    /// `tn.agents` kit and the entry carries a populated `tn.agents`
    /// group. The six `tn.agents` field names are NOT flattened into
    /// `fields` — they land in `instructions` as a separate concern.
    ///
    /// `on_invalid` controls the failure mode (skip / raise / forensic).
    /// Under `Skip` (default), a `tn.read.tampered_row_skipped` admin
    /// event is appended to the local log for each dropped row.
    #[allow(clippy::needless_pass_by_value)]
    pub fn secure_read(&self, opts: SecureReadOptions) -> Result<Vec<SecureEntry>> {
        let raw_with_valid = match opts.log_path.as_deref() {
            Some(p) => self.read_from_with_validity(p)?,
            None => self.read_raw_with_validity()?,
        };
        let mut out: Vec<SecureEntry> = Vec::new();
        for (entry, valid) in raw_with_valid {
            let all_valid = valid.signature && valid.row_hash && valid.chain;
            if !all_valid {
                let reasons = invalid_reasons(valid);
                match opts.on_invalid {
                    OnInvalid::Raise => {
                        let event_type = entry
                            .envelope
                            .get("event_type")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let event_id = entry
                            .envelope
                            .get("event_id")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        return Err(Error::Malformed {
                            kind: "verification",
                            reason: format!(
                                "tn.secure_read: envelope event_type={event_type:?} \
                                 event_id={event_id:?} failed verification: {reasons:?}"
                            ),
                        });
                    }
                    OnInvalid::Skip => {
                        // Don't loop our own tampered-row event back through
                        // secure_read — that would emit an event for the
                        // very event we're verifying. Skip silently.
                        let event_type = entry
                            .envelope
                            .get("event_type")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if event_type == "tn.read.tampered_row_skipped" {
                            continue;
                        }
                        if let Err(e) = self.emit_tampered_row_skipped(&entry, &reasons) {
                            log::warn!("tn.read.tampered_row_skipped emit failed: {e}");
                        }
                        continue;
                    }
                    OnInvalid::Forensic => {
                        let mut flat = flatten_raw_entry(&entry, false);
                        let mut v = Map::new();
                        v.insert("signature".into(), Value::Bool(valid.signature));
                        v.insert("row_hash".into(), Value::Bool(valid.row_hash));
                        v.insert("chain".into(), Value::Bool(valid.chain));
                        flat.insert("_valid".into(), Value::Object(v));
                        flat.insert(
                            "_invalid_reasons".into(),
                            Value::Array(
                                reasons
                                    .iter()
                                    .map(|s| Value::String((*s).to_string()))
                                    .collect(),
                            ),
                        );
                        let (instructions, hidden, errs) = attach_instructions(&mut flat, &entry);
                        out.push(SecureEntry {
                            fields: flat,
                            instructions,
                            hidden_groups: hidden,
                            decrypt_errors: errs,
                        });
                        continue;
                    }
                }
            }

            let mut flat = flatten_raw_entry(&entry, false);
            let (instructions, hidden, errs) = attach_instructions(&mut flat, &entry);
            out.push(SecureEntry {
                fields: flat,
                instructions,
                hidden_groups: hidden,
                decrypt_errors: errs,
            });
        }
        Ok(out)
    }

    /// Append a `tn.read.tampered_row_skipped` admin event with public
    /// fields only. The bad row's payload is NOT exposed.
    fn emit_tampered_row_skipped(
        &self,
        entry: &ReadEntry,
        reasons: &[&'static str],
    ) -> Result<()> {
        let env = entry.envelope.as_object();
        let event_id = env
            .and_then(|o| o.get("event_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let did = env
            .and_then(|o| o.get("did"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let event_type = env
            .and_then(|o| o.get("event_type"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let sequence = env.and_then(|o| o.get("sequence")).cloned();

        let mut fields = Map::new();
        fields.insert("envelope_event_id".into(), Value::String(event_id));
        fields.insert("envelope_did".into(), Value::String(did));
        fields.insert("envelope_event_type".into(), Value::String(event_type));
        fields.insert(
            "envelope_sequence".into(),
            sequence.unwrap_or(Value::Null),
        );
        fields.insert(
            "invalid_reasons".into(),
            Value::Array(
                reasons
                    .iter()
                    .map(|s| Value::String((*s).to_string()))
                    .collect(),
            ),
        );
        self.emit("warning", "tn.read.tampered_row_skipped", fields)
    }

    /// Mint a fresh kit for `recipient_did` across one or more groups
    /// and bundle them into a single `.tnpkg` at `out_path`.
    ///
    /// Mirrors Python's `tn.bundle_for_recipient` and TS's
    /// `client.bundleForRecipient` — closes the cross-binding parity
    /// gap surfaced by the cash-register survey (Rust callers had no
    /// equivalent ergonomic verb and faced the canonical-filename +
    /// temp-dir + export dance by hand).
    ///
    /// `groups = None` defaults to every NON-internal group declared in
    /// the active ceremony (excludes `tn.agents` — that group is for
    /// LLM-runtime bundles via [`Runtime::admin_add_agent_runtime`]).
    /// Passing an explicit slice scopes the bundle.
    ///
    /// Returns the absolute path to the written `.tnpkg`.
    ///
    /// # Errors
    ///
    /// - `InvalidConfig` if no real groups are available, or a requested
    ///   group is not declared in the yaml.
    /// - Filesystem errors from minting kits or writing the bundle.
    pub fn bundle_for_recipient(
        &self,
        recipient_did: &str,
        out_path: &Path,
        groups: Option<&[&str]>,
    ) -> Result<PathBuf> {
        let mut requested: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        match groups {
            Some(list) => {
                for g in list {
                    let s = (*g).to_string();
                    if seen.insert(s.clone()) {
                        requested.push(s);
                    }
                }
            }
            None => {
                // Default: every group except tn.agents (the internal
                // LLM-policy channel doesn't make sense to ship to a
                // human reader).
                for k in self.cfg.groups.keys() {
                    if k == "tn.agents" {
                        continue;
                    }
                    requested.push(k.clone());
                }
            }
        }

        if requested.is_empty() {
            return Err(Error::InvalidConfig(
                "bundle_for_recipient: no groups to bundle. The ceremony \
                 has only the internal tn.agents group; declare a \
                 regular group first or pass an explicit groups slice."
                    .to_string(),
            ));
        }

        for g in &requested {
            if !self.cfg.groups.contains_key(g) {
                return Err(Error::InvalidConfig(format!(
                    "bundle_for_recipient: unknown group {g:?}; this \
                     ceremony declares {:?}",
                    self.cfg.groups.keys().collect::<Vec<_>>()
                )));
            }
        }

        let td = tempfile::Builder::new()
            .prefix("tn-bundle-")
            .tempdir()
            .map_err(Error::Io)?;
        for gname in &requested {
            let kit_path = td.path().join(format!("{gname}.btn.mykit"));
            self.admin_add_recipient(gname, &kit_path, Some(recipient_did))?;
        }

        let opts = crate::runtime_export::ExportOptions {
            kind: Some(crate::tnpkg::ManifestKind::KitBundle),
            to_did: Some(recipient_did.to_string()),
            scope: None,
            confirm_includes_secrets: false,
            groups: Some(requested.clone()),
            package_body: None,
        };
        let out = self.export(out_path, opts)?;
        drop(td);
        Ok(out)
    }

    /// Mint kits for an LLM-runtime DID across all named groups + the
    /// reserved `tn.agents` group, then export a `kit_bundle` `.tnpkg`
    /// at `out_path`.
    ///
    /// Per the 2026-04-25 read-ergonomics spec §2.8. The `tn.agents`
    /// group is always implicitly added (de-duplicated if the caller
    /// passed it). `label` is written to a `.label` sidecar next to the
    /// output `.tnpkg` for downstream identification — best-effort,
    /// never fails the call.
    ///
    /// Returns the absolute `.tnpkg` path.
    ///
    /// # Errors
    ///
    /// - `InvalidConfig` if a requested group is not declared in this
    ///   ceremony's yaml.
    /// - Filesystem errors from minting kits or writing the bundle.
    pub fn admin_add_agent_runtime(
        &self,
        runtime_did: &str,
        groups: &[&str],
        out_path: &Path,
        label: Option<&str>,
    ) -> Result<PathBuf> {
        // Dedup: tn.agents is always added; if the caller passed it,
        // don't double-mint. Preserve order for the others.
        let mut requested: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for g in groups {
            if *g == "tn.agents" {
                continue;
            }
            let s = (*g).to_string();
            if seen.insert(s.clone()) {
                requested.push(s);
            }
        }
        requested.push("tn.agents".to_string());

        for g in &requested {
            if !self.cfg.groups.contains_key(g) {
                return Err(Error::InvalidConfig(format!(
                    "admin_add_agent_runtime: group {g:?} is not declared in this \
                     ceremony's yaml (known: {:?})",
                    self.cfg.groups.keys().collect::<Vec<_>>()
                )));
            }
        }

        // Mint kits into a temp directory using the canonical filename
        // so export(kind='kit_bundle') picks them up.
        let td = tempfile::Builder::new()
            .prefix("tn-agent-bundle-")
            .tempdir()
            .map_err(Error::Io)?;
        for gname in &requested {
            let kit_path = td.path().join(format!("{gname}.btn.mykit"));
            self.admin_add_recipient(gname, &kit_path, Some(runtime_did))?;
        }

        let opts = crate::runtime_export::ExportOptions {
            kind: Some(crate::tnpkg::ManifestKind::KitBundle),
            to_did: Some(runtime_did.to_string()),
            scope: None,
            confirm_includes_secrets: false,
            groups: Some(requested.clone()),
            package_body: None,
        };
        // `export` already drops the temp-dir kits into the bundle. We
        // pass `keystore=None` because export reads from the runtime's
        // own keystore — but the kits were minted into the temp dir.
        // Workaround: copy them into the keystore (admin_add_recipient
        // already wrote the actual tnpkg, but the *.mykit goes to the
        // path we pass). The export reads from `self.keystore` so the
        // mykit files for the requested groups are already there from
        // the side-effects of admin_add_recipient.
        let out = self.export(out_path, opts)?;

        // Best-effort label sidecar.
        if let Some(lbl) = label {
            let mut sidecar_str = out.as_os_str().to_owned();
            sidecar_str.push(".label");
            let sidecar = PathBuf::from(sidecar_str);
            if let Err(e) = std::fs::write(&sidecar, lbl) {
                log::warn!(
                    "admin_add_agent_runtime: failed to write label sidecar: {e}"
                );
            }
        }

        // Keep tempdir alive until export completes.
        drop(td);
        Ok(out)
    }

    /// Read all entries plus per-entry validity flags
    /// `(signature, row_hash, chain)`.
    ///
    /// Verification mirrors Python `tn.reader._read`: chain integrity
    /// per event_type, row_hash recomputed from canonical inputs,
    /// signature checked against the envelope's `did`.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_raw_with_validity(&self) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        let log_path = self.log_path.clone();
        self.read_from_with_validity(&log_path)
    }

    /// As [`Runtime::read_raw_with_validity`] but for an explicit log path.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    #[allow(clippy::too_many_lines)]
    pub fn read_from_with_validity(
        &self,
        log_path: &Path,
    ) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        if !log_path.exists() {
            return Ok(Vec::new());
        }
        let mut out: Vec<(ReadEntry, ValidFlags)> = Vec::new();
        let mut prev_hash_by_event: HashMap<String, String> = HashMap::new();
        let public_set: HashSet<&str> = self.cfg.public_fields.iter().map(String::as_str).collect();
        let group_names: HashSet<&str> = self.cfg.groups.keys().map(String::as_str).collect();

        for res in LogFileReader::open(log_path)? {
            let env = res?;

            let event_type = env
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let prev = env
                .get("prev_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let row_hash = env
                .get("row_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let did = env
                .get("did")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let signature = env
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let last = prev_hash_by_event.get(&event_type).cloned();
            let chain_ok = match last {
                None => true,
                Some(l) => l == prev,
            };
            prev_hash_by_event.insert(event_type.clone(), row_hash.clone());

            // Decrypt every group we hold a kit for.
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            let mut groups_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
            if let Value::Object(env_map) = &env {
                for (k, v) in env_map {
                    if let Some(g_obj) = v.as_object() {
                        if let Some(ct_str) = g_obj.get("ciphertext").and_then(Value::as_str) {
                            let ct = STANDARD.decode(ct_str).map_err(|e| Error::Malformed {
                                kind: "ciphertext base64",
                                reason: e.to_string(),
                            })?;
                            let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
                            if let Some(fh_obj) =
                                g_obj.get("field_hashes").and_then(Value::as_object)
                            {
                                for (fname, fv) in fh_obj {
                                    if let Some(s) = fv.as_str() {
                                        field_hashes
                                            .insert(fname.clone(), s.to_string());
                                    }
                                }
                            }
                            groups_for_hash.insert(
                                k.clone(),
                                GroupInput {
                                    ciphertext: ct.clone(),
                                    field_hashes,
                                },
                            );
                            // Decrypt if we hold a kit for this group.
                            if let Some(gstate_arc) = self.groups.get(k) {
                                let gstate = gstate_arc
                                    .read()
                                    .expect("group state RwLock poisoned");
                                match gstate.cipher.decrypt(&ct) {
                                    Ok(pt) => {
                                        let pv: Value = serde_json::from_slice(&pt)?;
                                        plaintext_per_group.insert(k.clone(), pv);
                                    }
                                    Err(
                                        Error::NotEntitled { .. } | Error::NotAPublisher { .. },
                                    ) => {
                                        plaintext_per_group.insert(
                                            k.clone(),
                                            serde_json::json!({"$no_read_key": true}),
                                        );
                                    }
                                    Err(_) => {
                                        plaintext_per_group.insert(
                                            k.clone(),
                                            serde_json::json!({"$decrypt_error": true}),
                                        );
                                    }
                                }
                            } else {
                                plaintext_per_group.insert(
                                    k.clone(),
                                    serde_json::json!({"$no_read_key": true}),
                                );
                            }
                        }
                    }
                }
            }

            // Recompute row_hash from envelope + decrypted/raw groups.
            let envelope_reserved: HashSet<&'static str> = [
                "did",
                "timestamp",
                "event_id",
                "event_type",
                "level",
                "prev_hash",
                "row_hash",
                "signature",
                "sequence",
            ]
            .iter()
            .copied()
            .collect();
            let mut public_out: BTreeMap<String, Value> = BTreeMap::new();
            if let Value::Object(env_map) = &env {
                for (k, v) in env_map {
                    if envelope_reserved.contains(k.as_str()) {
                        continue;
                    }
                    if v.as_object()
                        .is_some_and(|o| o.contains_key("ciphertext"))
                    {
                        continue;
                    }
                    if !public_set.contains(k.as_str()) {
                        continue;
                    }
                    if group_names.contains(k.as_str()) {
                        continue;
                    }
                    public_out.insert(k.clone(), v.clone());
                }
            }
            let timestamp = env
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let event_id = env
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let level = env
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let expected = compute_row_hash(&RowHashInput {
                did: &did,
                timestamp: &timestamp,
                event_id: &event_id,
                event_type: &event_type,
                level: &level,
                prev_hash: &prev,
                public_fields: &public_out,
                groups: &groups_for_hash,
            });
            let row_hash_ok = expected == row_hash;

            // Signature: empty signature counts as `false` (unsigned mode
            // is intentionally fail-closed for verifiers — matches Python).
            let sig_ok = if signature.is_empty() {
                false
            } else {
                match signature_from_b64(&signature) {
                    Ok(sig_bytes) => DeviceKey::verify_did(
                        &did,
                        row_hash.as_bytes(),
                        &sig_bytes,
                    )
                    .unwrap_or(false),
                    Err(_) => false,
                }
            };

            out.push((
                ReadEntry {
                    envelope: env,
                    plaintext_per_group,
                },
                ValidFlags {
                    signature: sig_ok,
                    row_hash: row_hash_ok,
                    chain: chain_ok,
                },
            ));
        }
        Ok(out)
    }

    /// Read all entries from a specific log path (for cross-party reads).
    ///
    /// FINDINGS S6.2 cross-binding parity: when `log_path` points at a
    /// foreign publisher's ndjson, the runtime's own group state can't
    /// decrypt the ciphertexts. Detect by peeking at the first
    /// envelope's `did` and route through
    /// [`crate::read_as_recipient::read_as_recipient`] using this
    /// runtime's keystore (where `Runtime::absorb` placed the foreign
    /// kit). The exemption: when `log_path` is exactly our own
    /// `log_path` (the post-flush "reading my own log" case), skip the
    /// foreign route and use the regular self-decrypt path.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned (another thread panicked while
    /// holding a write lock on group state).
    pub fn read_from(&self, log_path: &Path) -> Result<Vec<ReadEntry>> {
        if !log_path.exists() {
            return Ok(Vec::new());
        }
        if is_foreign_log(log_path, &self.log_path, self.device.did(), &self.keystore) {
            return read_foreign_log(log_path, &self.keystore);
        }
        let mut out = Vec::new();
        for res in LogFileReader::open(log_path)? {
            let env = res?;
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            for (gname, gstate_arc) in &self.groups {
                let Some(group_v) = env.get(gname) else {
                    continue;
                };
                let Some(ct_b64) = group_v.get("ciphertext").and_then(|v| v.as_str()) else {
                    continue;
                };
                let ct = STANDARD.decode(ct_b64).map_err(|e| Error::Malformed {
                    kind: "ciphertext base64",
                    reason: e.to_string(),
                })?;
                let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                match gstate.cipher.decrypt(&ct) {
                    Ok(pt) => {
                        let v: Value = serde_json::from_slice(&pt)?;
                        plaintext_per_group.insert(gname.clone(), v);
                    }
                    Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => {
                        // Skip groups we can't read.
                    }
                    Err(e) => return Err(e),
                }
            }
            out.push(ReadEntry {
                envelope: env,
                plaintext_per_group,
            });
        }
        Ok(out)
    }

    /// Explicit close: flushes the log file and consumes self.
    ///
    /// Dropping a `Runtime` without calling `close` is fine; `File`'s own
    /// Drop impl flushes OS buffers. Calling `close` gives you a
    /// `Result` you can surface if flushing errored.
    pub fn close(self) -> Result<()> {
        if let Ok(mut w) = self.log_writer.into_inner() {
            w.flush()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Admin verbs: cipher-agnostic recipient management.
    //
    // Public names follow the SDK parity matrix (tn-protocol/docs/sdk-parity.md):
    // `admin_add_recipient`, `admin_revoke_recipient`, `admin_revoked_count`.
    // Today only btn ceremonies are supported; JWE support lands alongside the
    // second cipher and reuses these same public names.
    // ------------------------------------------------------------------

    /// Mint a new reader kit for `group`, write it to `out_kit_path`, persist
    /// the updated publisher state, and return the recipient identifier (leaf
    /// index for btn).
    ///
    /// When `recipient_did` is `Some`, a `tn.recipient.added` event is
    /// appended to the log carrying the leaf index + recipient DID + kit SHA.
    /// Readers can replay these events to reconstruct the recipient map
    /// without any sidecar state file; the attested log is the source of truth.
    ///
    /// Matches Python `tn.admin_add_recipient(group, out_path, recipient_did)`.
    ///
    /// # Errors
    /// - `InvalidConfig` if `group` is not a btn group in this runtime.
    /// - `Io` if the state or kit file cannot be written.
    /// - `Btn` if the tree is exhausted or minting fails.
    ///
    /// # Panics
    ///
    /// Panics if the group's `PublisherState` mutex is poisoned by a prior panic
    /// while holding it. The runtime treats a poisoned admin mutex as an
    /// unrecoverable invariant violation.
    pub fn admin_add_recipient(
        &self,
        group: &str,
        out_kit_path: &Path,
        recipient_did: Option<&str>,
    ) -> Result<u64> {
        // FINDINGS #5 cross-binding parity: reject suffix-mismatched
        // filenames up front. The kit_bundle exporter regex requires
        // `.btn.mykit`; non-matching files get silently skipped on
        // export and the publisher's own self-kit ships in their
        // place — a critical identity-leak path. Mirrors Python
        // `tn.admin_add_recipient` and TS `client.adminAddRecipient`.
        let basename = out_kit_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !basename.ends_with(".btn.mykit") || basename == ".btn.mykit" {
            return Err(Error::InvalidConfig(format!(
                "admin_add_recipient: out_kit_path basename must end with \
                 '.btn.mykit' (e.g. {group:?}.btn.mykit, or \
                 {group:?}_alt.btn.mykit for a second kit in the same group), \
                 got {basename:?}. The kit_bundle exporter regex requires the \
                 .btn.mykit suffix; non-matching files get silently skipped \
                 and the publisher's own self-kit ships in their place \
                 (FINDINGS #5). For ergonomic per-recipient bundling, use \
                 Runtime::bundle_for_recipient — it handles minting + \
                 canonical filename + export in one call."
            )));
        }
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_add_recipient: group {group:?} is not a btn publisher group in this runtime"
            ))
        })?;
        let mut pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");

        // Mint the new reader kit.
        let kit = pub_cipher.state_mut().mint()?;
        let leaf_index = kit.leaf().0;
        let kit_bytes = kit.to_bytes();
        let state_bytes = pub_cipher.state_to_bytes();

        // Persist state first (fail before writing kit if state write fails).
        let state_path = self.keystore.join(format!("{group}.btn.state"));
        std::fs::write(&state_path, &state_bytes).map_err(Error::Io)?;

        // Write the kit to the caller-specified path.
        if let Some(parent) = out_kit_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
        }
        std::fs::write(out_kit_path, &kit_bytes).map_err(Error::Io)?;

        // Rebuild cipher from updated state and swap into the groups table.
        let mykit_bytes = self.btn_mykit.get(group).and_then(Option::as_deref);
        let new_cipher: Arc<dyn GroupCipher> = rebuild_btn_cipher(&pub_cipher, mykit_bytes)?;
        drop(pub_cipher); // release Mutex before taking RwLock write

        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = new_cipher;
        }

        // Emit attested `tn.recipient.added` event so readers/subscribers
        // can reconstruct the recipient map by replaying the log.
        let mut fields = Map::new();
        fields.insert("group".into(), Value::String(group.to_string()));
        fields.insert("leaf_index".into(), Value::Number(leaf_index.into()));
        // recipient_did is OptionalString; include null when not provided so
        // validate_emit can confirm the field is present.
        fields.insert(
            "recipient_did".into(),
            recipient_did.map_or(Value::Null, |d| Value::String(d.to_string())),
        );
        fields.insert(
            "kit_sha256".into(),
            Value::String(format!("sha256:{}", hex::encode(sha2_256(&kit_bytes)))),
        );
        // cipher is required by the catalog schema.
        fields.insert("cipher".into(), Value::String("btn".to_string()));
        // Emission failures don't roll back the mint (the kit is already on
        // disk and the state is persisted). Log-and-continue.
        if let Err(e) = self.emit("info", "tn.recipient.added", fields) {
            log::warn!(
                "admin state persisted but attestation emit failed: event_type={} error={}",
                "tn.recipient.added",
                e
            );
        }

        Ok(leaf_index)
    }

    /// Revoke the reader identified by `leaf_index` in `group`.
    ///
    /// Persists the updated publisher state to disk and swaps the cipher so
    /// subsequent `emit` calls exclude the revoked leaf. Emits a
    /// `tn.recipient.revoked` attested event.
    ///
    /// Matches Python `tn.admin_revoke_recipient(group, leaf_index)`.
    ///
    /// # Errors
    /// - `InvalidConfig` if `group` is not a btn publisher group.
    /// - `Io` if the state file cannot be written.
    /// - `Btn` if `leaf_index` is out of range.
    ///
    /// # Panics
    ///
    /// Panics if an internal `Mutex` or `RwLock` is poisoned.
    pub fn admin_revoke_recipient(&self, group: &str, leaf_index: u64) -> Result<()> {
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_revoke_recipient: group {group:?} is not a btn publisher group"
            ))
        })?;
        let mut pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");

        pub_cipher
            .state_mut()
            .revoke_by_leaf(tn_btn::LeafIndex(leaf_index))?;
        let state_bytes = pub_cipher.state_to_bytes();

        let state_path = self.keystore.join(format!("{group}.btn.state"));
        std::fs::write(&state_path, &state_bytes).map_err(Error::Io)?;

        // Rebuild cipher with revocation applied.
        let mykit_bytes = self.btn_mykit.get(group).and_then(Option::as_deref);
        let new_cipher: Arc<dyn GroupCipher> = rebuild_btn_cipher(&pub_cipher, mykit_bytes)?;
        drop(pub_cipher);

        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = new_cipher;
        }

        // Emit attested `tn.recipient.revoked` event.
        let mut fields = Map::new();
        fields.insert("group".into(), Value::String(group.to_string()));
        fields.insert("leaf_index".into(), Value::Number(leaf_index.into()));
        // recipient_did is OptionalString in the catalog schema; include null
        // so validate_emit can confirm the field is present.
        fields.insert("recipient_did".into(), Value::Null);
        if let Err(e) = self.emit("info", "tn.recipient.revoked", fields) {
            log::warn!(
                "admin state persisted but attestation emit failed: event_type={} error={}",
                "tn.recipient.revoked",
                e
            );
        }

        Ok(())
    }

    /// Return the number of revoked recipients in `group`'s publisher state.
    ///
    /// Matches Python `tn.admin_revoked_count(group)`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `group` is not a btn publisher group.
    ///
    /// # Panics
    ///
    /// Panics if an internal `Mutex` is poisoned.
    pub fn admin_revoked_count(&self, group: &str) -> Result<usize> {
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_revoked_count: group {group:?} is not a btn publisher group"
            ))
        })?;
        let pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");
        Ok(pub_cipher.state().revoked_count())
    }

    /// Return the current recipient roster for `group` by replaying the log
    /// through the admin reducer. Mirrors Python `tn.recipients(group, …)`
    /// and TypeScript `client.recipients(group, …)`.
    ///
    /// Active recipients are returned sorted by `leaf_index`; when
    /// `include_revoked` is true, revoked entries are appended after the
    /// active ones (also sorted by leaf_index).
    ///
    /// Reducer errors on a single envelope are warn-logged and skipped — a
    /// single corrupt admin event does not abort the whole replay.
    ///
    /// **Divergence from Python/TS:** Rust's `read()` does not currently
    /// produce per-event signature/row_hash/chain validity flags, so
    /// tampered admin events cannot be filtered out the way Python and TS
    /// do via `valid.{signature, row_hash, chain}`. Until `ReadEntry`
    /// carries validity flags, this function trusts whatever `read()`
    /// returned. Tampered envelopes that still parse and pass schema will
    /// be reflected in the roster.
    pub fn recipients(
        &self,
        group: &str,
        include_revoked: bool,
    ) -> Result<Vec<RecipientEntry>> {
        let mut active: BTreeMap<u64, RecipientEntry> = BTreeMap::new();
        let mut revoked: BTreeMap<u64, RecipientEntry> = BTreeMap::new();

        for entry in self.read_raw()? {
            let event_type = entry
                .envelope
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !event_type.starts_with("tn.recipient.") {
                continue;
            }

            let merged = merge_envelope(&entry);
            let merged_v = apply_schema_defaults(event_type, merged);
            let ts = entry
                .envelope
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string);

            let delta = match admin_reduce_envelope(&merged_v) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!(
                        "tn.recipients: admin event failed reduce: event={event_type:?}: {e}"
                    );
                    continue;
                }
            };

            match delta {
                StateDelta::RecipientAdded {
                    group: g,
                    leaf_index: Some(leaf),
                    recipient_did,
                    kit_sha256,
                    ..
                } if g == group => {
                    active.insert(
                        leaf,
                        RecipientEntry {
                            leaf_index: leaf,
                            recipient_did,
                            minted_at: ts.clone(),
                            kit_sha256: Some(kit_sha256),
                            revoked: false,
                            revoked_at: None,
                        },
                    );
                }
                StateDelta::RecipientRevoked {
                    group: g,
                    leaf_index: Some(leaf),
                    ..
                } if g == group => {
                    let mut rec = active.remove(&leaf).unwrap_or(RecipientEntry {
                        leaf_index: leaf,
                        recipient_did: None,
                        minted_at: None,
                        kit_sha256: None,
                        revoked: false,
                        revoked_at: None,
                    });
                    rec.revoked = true;
                    rec.revoked_at.clone_from(&ts);
                    revoked.insert(leaf, rec);
                }
                // Other groups, deltas without a leaf index, or non-recipient
                // deltas — ignored.
                _ => {}
            }
        }

        let mut out: Vec<RecipientEntry> = active.into_values().collect();
        if include_revoked {
            out.extend(revoked.into_values());
        }
        Ok(out)
    }

    /// Return the full local admin state by replaying the log through the
    /// admin reducer. Mirrors Python `tn.admin_state(group=…)`.
    ///
    /// When `group` is `Some`, the `groups`, `recipients`, `rotations`,
    /// `coupons`, and `enrolments` lists are filtered to that group.
    /// `ceremony` and `vault_links` are not filtered.
    ///
    /// If no `tn.ceremony.init` event is present in the log (common for
    /// btn ceremonies — the publisher state lives on disk, not the
    /// attested log), the ceremony record is reconstructed from the
    /// active config with `created_at == None`.
    #[allow(clippy::too_many_lines)] // single replay loop; splitting fragments invariants
    pub fn admin_state(&self, group: Option<&str>) -> Result<AdminState> {
        let mut state = AdminState::default();

        // Active+lifecycle recipient rows keyed by (group, leaf_index).
        let mut by_leaf: BTreeMap<(String, u64), AdminRecipientRecord> = BTreeMap::new();
        // Enrolment rows keyed by (group, peer_did).
        let mut enrolments_by_peer: BTreeMap<(String, String), AdminEnrolment> = BTreeMap::new();
        // Vault links keyed by vault_did.
        let mut vault_links_by_did: BTreeMap<String, AdminVaultLink> = BTreeMap::new();

        for entry in self.read_raw()? {
            let event_type = entry
                .envelope
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            if !(event_type.starts_with("tn.ceremony.")
                || event_type.starts_with("tn.group.")
                || event_type.starts_with("tn.recipient.")
                || event_type.starts_with("tn.rotation.")
                || event_type.starts_with("tn.coupon.")
                || event_type.starts_with("tn.enrolment.")
                || event_type.starts_with("tn.vault."))
            {
                continue;
            }

            let merged = merge_envelope(&entry);
            let merged_v = apply_schema_defaults(&event_type, merged);
            let ts = merged_v
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string);

            let delta = match admin_reduce_envelope(&merged_v) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!(
                        "tn.admin_state: admin event failed reduce: event={event_type:?}: {e}"
                    );
                    continue;
                }
            };

            match delta {
                StateDelta::CeremonyInit {
                    ceremony_id,
                    cipher,
                    device_did,
                    created_at,
                } => {
                    state.ceremony = Some(AdminCeremony {
                        ceremony_id,
                        cipher,
                        device_did,
                        created_at: Some(created_at),
                    });
                }
                StateDelta::GroupAdded {
                    group: g,
                    cipher,
                    publisher_did,
                    added_at,
                } => {
                    state.groups.push(AdminGroupRecord {
                        group: g,
                        cipher,
                        publisher_did,
                        added_at,
                    });
                }
                StateDelta::RecipientAdded {
                    group: g,
                    leaf_index: Some(leaf),
                    recipient_did,
                    kit_sha256,
                    ..
                } => {
                    by_leaf.insert(
                        (g.clone(), leaf),
                        AdminRecipientRecord {
                            group: g,
                            leaf_index: leaf,
                            recipient_did,
                            kit_sha256,
                            minted_at: ts.clone(),
                            active_status: "active".to_string(),
                            revoked_at: None,
                            retired_at: None,
                        },
                    );
                }
                StateDelta::RecipientRevoked {
                    group: g,
                    leaf_index: Some(leaf),
                    ..
                } => {
                    if let Some(rec) = by_leaf.get_mut(&(g, leaf)) {
                        rec.active_status = "revoked".to_string();
                        rec.revoked_at.clone_from(&ts);
                    }
                }
                StateDelta::RotationCompleted {
                    group: g,
                    cipher,
                    generation,
                    previous_kit_sha256,
                    rotated_at,
                    ..
                } => {
                    state.rotations.push(AdminRotation {
                        group: g.clone(),
                        cipher,
                        generation,
                        previous_kit_sha256,
                        rotated_at,
                    });
                    // Retire any currently-active recipients in this group.
                    for ((rg, _leaf), rec) in &mut by_leaf {
                        if rg == &g && rec.active_status == "active" {
                            rec.active_status = "retired".to_string();
                            rec.retired_at.clone_from(&ts);
                        }
                    }
                }
                StateDelta::CouponIssued {
                    group: g,
                    slot,
                    to_did,
                    issued_to,
                } => {
                    state.coupons.push(AdminCoupon {
                        group: g,
                        slot,
                        to_did,
                        issued_to,
                        issued_at: ts.clone(),
                    });
                }
                StateDelta::EnrolmentCompiled {
                    group: g,
                    peer_did,
                    package_sha256,
                    compiled_at,
                } => {
                    enrolments_by_peer.insert(
                        (g.clone(), peer_did.clone()),
                        AdminEnrolment {
                            group: g,
                            peer_did,
                            package_sha256,
                            status: "offered".to_string(),
                            compiled_at: Some(compiled_at),
                            absorbed_at: None,
                        },
                    );
                }
                StateDelta::EnrolmentAbsorbed {
                    group: g,
                    from_did,
                    package_sha256,
                    absorbed_at,
                } => {
                    let key = (g.clone(), from_did.clone());
                    if let Some(existing) = enrolments_by_peer.get_mut(&key) {
                        existing.status = "absorbed".to_string();
                        existing.absorbed_at = Some(absorbed_at);
                    } else {
                        enrolments_by_peer.insert(
                            key,
                            AdminEnrolment {
                                group: g,
                                peer_did: from_did,
                                package_sha256,
                                status: "absorbed".to_string(),
                                compiled_at: None,
                                absorbed_at: Some(absorbed_at),
                            },
                        );
                    }
                }
                StateDelta::VaultLinked {
                    vault_did,
                    project_id,
                    linked_at,
                } => {
                    vault_links_by_did.insert(
                        vault_did.clone(),
                        AdminVaultLink {
                            vault_did,
                            project_id,
                            linked_at,
                            unlinked_at: None,
                        },
                    );
                }
                StateDelta::VaultUnlinked {
                    vault_did,
                    unlinked_at,
                    ..
                } => {
                    if let Some(link) = vault_links_by_did.get_mut(&vault_did) {
                        link.unlinked_at = Some(unlinked_at);
                    }
                }
                // Unknown deltas + RecipientAdded/Revoked with
                // leaf_index == None are catalog-valid but useless to
                // admin_state.
                StateDelta::Unknown { .. }
                | StateDelta::RecipientAdded { .. }
                | StateDelta::RecipientRevoked { .. } => {}
            }
        }

        state.recipients = by_leaf.into_values().collect();
        state.enrolments = enrolments_by_peer.into_values().collect();
        state.vault_links = vault_links_by_did.into_values().collect();

        // Fallback: derive ceremony from active config when no
        // tn.ceremony.init landed in the log (the btn case).
        if state.ceremony.is_none() {
            state.ceremony = Some(AdminCeremony {
                ceremony_id: self.cfg.ceremony.id.clone(),
                cipher: self.cfg.ceremony.cipher.clone(),
                device_did: self.device.did().to_string(),
                created_at: None,
            });
        }

        if let Some(g) = group {
            state.groups.retain(|x| x.group == g);
            state.recipients.retain(|x| x.group == g);
            state.rotations.retain(|x| x.group == g);
            state.coupons.retain(|x| x.group == g);
            state.enrolments.retain(|x| x.group == g);
        }

        Ok(state)
    }

    /// Emit a signed `tn.vault.linked` admin event, recording that this
    /// ceremony is paired with `vault_did`'s project `project_id`.
    ///
    /// Idempotent: if `admin_state` already shows an active link to
    /// `vault_did` (i.e. an entry whose `unlinked_at` is `None`), this is a
    /// no-op. Mirrors Python `tn.vault_link(vault_did, project_id)`,
    /// which returns `None`.
    pub fn vault_link(&self, vault_did: &str, project_id: &str) -> Result<()> {
        // Idempotency check — match Python: an active link to the same
        // vault_did short-circuits. admin_state failures do NOT block the
        // emit (Python catches blanket `Exception`); on error we proceed.
        if let Ok(state) = self.admin_state(None) {
            for link in &state.vault_links {
                if link.vault_did == vault_did
                    && link.project_id == project_id
                    && link.unlinked_at.is_none()
                {
                    return Ok(());
                }
            }
        }

        let mut fields = Map::new();
        fields.insert("vault_did".into(), Value::String(vault_did.to_string()));
        fields.insert("project_id".into(), Value::String(project_id.to_string()));
        fields.insert(
            "linked_at".into(),
            Value::String(current_timestamp_rfc3339()),
        );
        self.emit("info", "tn.vault.linked", fields)
    }

    /// Emit a signed `tn.vault.unlinked` admin event, recording that the
    /// pairing between this ceremony and `vault_did`'s project
    /// `project_id` has been severed.
    ///
    /// `reason` is an optional free-form string forwarded into the event.
    ///
    /// Mirrors Python `tn.vault_unlink(vault_did, project_id, reason)`.
    pub fn vault_unlink(
        &self,
        vault_did: &str,
        project_id: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut fields = Map::new();
        fields.insert("vault_did".into(), Value::String(vault_did.to_string()));
        fields.insert("project_id".into(), Value::String(project_id.to_string()));
        fields.insert(
            "unlinked_at".into(),
            Value::String(current_timestamp_rfc3339()),
        );
        // Only include reason when provided; the catalog schema treats it as
        // OptionalString so absent vs null both validate, but matching
        // Python's "reason: None when unset" requires emitting null.
        // Python passes `reason: None` unconditionally; mirror that so the
        // canonical row matches across SDKs.
        match reason {
            Some(r) => fields.insert("reason".into(), Value::String(r.to_string())),
            None => fields.insert("reason".into(), Value::Null),
        };
        self.emit("info", "tn.vault.unlinked", fields)
    }

    /// Splice `tn.agents` policy fields into `fields` per spec §2.6.
    ///
    /// Looks up `event_type` in the cached policy doc; if a template
    /// exists, fills the six tn.agents fields via `setdefault` semantics
    /// (existing keys win). The yaml-declared `tn.agents` group routes
    /// those six field names automatically; this just populates them.
    fn splice_agent_policy(&self, event_type: &str, fields: &mut Map<String, Value>) {
        let Some(doc) = &self.agent_policies else {
            return;
        };
        let Some(t) = doc.templates.get(event_type) else {
            return;
        };
        fields
            .entry("instruction".to_string())
            .or_insert_with(|| Value::String(t.instruction.clone()));
        fields
            .entry("use_for".to_string())
            .or_insert_with(|| Value::String(t.use_for.clone()));
        fields
            .entry("do_not_use_for".to_string())
            .or_insert_with(|| Value::String(t.do_not_use_for.clone()));
        fields
            .entry("consequences".to_string())
            .or_insert_with(|| Value::String(t.consequences.clone()));
        fields
            .entry("on_violation_or_error".to_string())
            .or_insert_with(|| Value::String(t.on_violation_or_error.clone()));
        let policy_str = format!(
            "{}#{}@{}#{}",
            t.path, t.event_type, t.version, t.content_hash
        );
        fields
            .entry("policy".to_string())
            .or_insert_with(|| Value::String(policy_str));
    }

    /// Walk every log file (main + admin) and return the `content_hash`
    /// of the most recent `tn.agents.policy_published` event, or `None`.
    ///
    /// Decrypts each readable group's plaintext and merges into the
    /// envelope dict before lookup so it works whether the publisher
    /// listed the policy fields under `public_fields:` or routed them
    /// into the default group.
    fn last_policy_published_hash(&self) -> Option<String> {
        let mut paths: Vec<PathBuf> = Vec::new();
        if self.log_path.exists() {
            paths.push(self.log_path.clone());
        }
        let pel = &self.cfg.ceremony.protocol_events_location;
        if pel != "main_log" {
            let resolved = self.resolve_pel("tn.agents.policy_published");
            if resolved != self.log_path && resolved.exists() {
                paths.push(resolved);
            }
        }

        let mut last_ts = String::new();
        let mut last_hash: Option<String> = None;
        for path in &paths {
            let Ok(entries) = self.read_from(path) else {
                continue;
            };
            for entry in entries {
                if entry.envelope.get("event_type").and_then(Value::as_str)
                    != Some("tn.agents.policy_published")
                {
                    continue;
                }
                let ts = entry
                    .envelope
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                // Try envelope root first, then merge group plaintext.
                let mut h = entry
                    .envelope
                    .get("content_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if h.is_none() {
                    for v in entry.plaintext_per_group.values() {
                        if let Some(s) = v.get("content_hash").and_then(Value::as_str) {
                            h = Some(s.to_string());
                            break;
                        }
                    }
                }
                if let Some(h) = h {
                    if ts >= last_ts {
                        last_ts = ts;
                        last_hash = Some(h);
                    }
                }
            }
        }
        last_hash
    }

    /// Emit `tn.agents.policy_published` iff the active policy file's
    /// content_hash differs from the last published one in the log (or no
    /// prior event exists). No-op when no policy doc is loaded.
    fn maybe_emit_policy_published(&self) -> Result<()> {
        let Some(doc) = &self.agent_policies else {
            return Ok(());
        };
        if self.last_policy_published_hash().as_deref() == Some(doc.content_hash.as_str()) {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("policy_uri".into(), Value::String(doc.path.clone()));
        fields.insert("version".into(), Value::String(doc.version.clone()));
        fields.insert(
            "content_hash".into(),
            Value::String(doc.content_hash.clone()),
        );
        let event_types: Vec<Value> = doc
            .templates
            .keys()
            .map(|k| Value::String(k.clone()))
            .collect();
        fields.insert("event_types_covered".into(), Value::Array(event_types));
        fields.insert("policy_text".into(), Value::String(doc.body.clone()));
        self.emit("info", "tn.agents.policy_published", fields)?;
        Ok(())
    }

    /// Resolve the per-event file path for a `tn.*` event when
    /// `protocol_events_location` is a template string.
    ///
    /// Supported placeholders (mirrors `tn/config.py::resolve_protocol_events_path`):
    /// `{event_type}`, `{event_class}` (second dotted segment),
    /// `{yaml_dir}`, `{ceremony_id}`, `{did}`, `{date}` (UTC YYYY-MM-DD).
    fn resolve_pel(&self, event_type: &str) -> PathBuf {
        let tmpl = &self.cfg.ceremony.protocol_events_location;
        if tmpl == "main_log" {
            return self.log_path.clone();
        }
        let event_class = event_type.split('.').nth(1).unwrap_or("unknown");
        let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
        let date = OffsetDateTime::now_utc()
            .format(&date_fmt)
            .unwrap_or_else(|_| "1970-01-01".to_string());
        let yaml_dir_path = self
            .yaml_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let yaml_dir = yaml_dir_path.to_string_lossy().into_owned();
        let filled = tmpl
            .replace("{event_type}", event_type)
            .replace("{event_class}", event_class)
            .replace("{date}", &date)
            .replace("{yaml_dir}", &yaml_dir)
            .replace("{ceremony_id}", &self.cfg.ceremony.id)
            .replace("{did}", self.device.did());
        // Mirror Python's tn/config.py::resolve_protocol_events_path: a
        // template that resolves to a relative path is anchored at the
        // yaml's parent directory, NOT the process cwd. Without this
        // anchor, the publisher subprocess inherits its caller's cwd and
        // admin events end up in completely the wrong tree (e.g. the
        // FastAPI server's working dir instead of the per-publisher
        // ceremony dir).
        let p = PathBuf::from(filled);
        if p.is_absolute() {
            p
        } else {
            yaml_dir_path.join(p)
        }
    }
}

fn current_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    // "2026-04-21T12:00:00.000000Z": microseconds, Z suffix. Matches Python.
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    );
    now.format(&fmt).expect("formatting infallible")
}

/// RFC-3339 timestamp matching Python's `datetime.now(tz.utc).isoformat()`
/// shape with offset suffix `+00:00`. Used by vault_link / vault_unlink so
/// the canonical row matches the Python emitter.
fn current_timestamp_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]+00:00"
    );
    now.format(&fmt).expect("formatting infallible")
}

/// Map a [`ValidFlags`] to the public ``invalid_reasons`` shape.
fn invalid_reasons(valid: ValidFlags) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if !valid.signature {
        out.push("signature");
    }
    if !valid.row_hash {
        out.push("row_hash");
    }
    if !valid.chain {
        out.push("chain");
    }
    out
}

/// Lift the six tn.agents fields out of `flat` into a typed
/// `Instructions` block. Returns the instructions plus the
/// `(hidden_groups, decrypt_errors)` lists already computed by
/// [`flatten_raw_entry`].
fn attach_instructions(
    flat: &mut FlatEntry,
    raw: &ReadEntry,
) -> (Option<Instructions>, Vec<String>, Vec<String>) {
    // Pull hidden_groups / decrypt_errors out so we can return them as
    // typed Vec<String>. They were inserted by flatten_raw_entry.
    let hidden = match flat.remove("_hidden_groups") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let errs = match flat.remove("_decrypt_errors") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };

    let body = raw.plaintext_per_group.get("tn.agents");
    let Some(obj) = body.and_then(Value::as_object) else {
        return (None, hidden, errs);
    };
    if obj.get("$no_read_key") == Some(&Value::Bool(true))
        || obj.get("$decrypt_error") == Some(&Value::Bool(true))
    {
        return (None, hidden, errs);
    }

    // Both fetch the field for the Instructions block AND remove it
    // from the flat top level. flat already had these (flatten_raw_entry
    // merges every readable group's fields).
    let take = |flat: &mut FlatEntry, k: &str| -> String {
        flat.remove(k);
        obj.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    };
    let instr = Instructions {
        instruction: take(flat, "instruction"),
        use_for: take(flat, "use_for"),
        do_not_use_for: take(flat, "do_not_use_for"),
        consequences: take(flat, "consequences"),
        on_violation_or_error: take(flat, "on_violation_or_error"),
        policy: take(flat, "policy"),
    };
    if instr.instruction.is_empty()
        && instr.use_for.is_empty()
        && instr.do_not_use_for.is_empty()
        && instr.consequences.is_empty()
        && instr.on_violation_or_error.is_empty()
        && instr.policy.is_empty()
    {
        return (None, hidden, errs);
    }
    (Some(instr), hidden, errs)
}

/// Project a `ReadEntry` to the flat shape used by `Runtime::read()` per
/// the 2026-04-25 read-ergonomics spec.
///
/// - Six envelope basics (`timestamp`, `event_type`, `level`, `did`,
///   `sequence`, `event_id`) surface as top-level keys.
/// - Public fields beyond envelope basics surface flat.
/// - Decrypted fields from every readable group are merged in
///   alphabetical group order so last-write-wins on collision is
///   deterministic across runs.
/// - Crypto plumbing (`prev_hash`, `row_hash`, `signature`, ciphertext,
///   `field_hashes`) is excluded.
/// - `_hidden_groups` lists groups present in the envelope with no
///   readable plaintext. Omitted when empty.
/// - `_decrypt_errors` lists groups whose decrypt threw. Omitted when
///   empty.
///
/// `_include_valid` is wired through from the spec but the actual
/// `_valid` block is added by the caller (`read_with_verify`) since
/// validity flags don't live on `ReadEntry` itself.
pub fn flatten_raw_entry(entry: &ReadEntry, _include_valid: bool) -> FlatEntry {
    const FLAT_ENVELOPE_KEYS: [&str; 6] = [
        "timestamp",
        "event_type",
        "level",
        "did",
        "sequence",
        "event_id",
    ];
    const CRYPTO_KEYS: [&str; 3] = ["prev_hash", "row_hash", "signature"];

    let env_obj: &Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m,
        _ => return Map::new(),
    };

    let mut out: FlatEntry = Map::new();

    // 1. Envelope basics.
    for k in FLAT_ENVELOPE_KEYS {
        if let Some(v) = env_obj.get(k) {
            out.insert(k.into(), v.clone());
        }
    }

    let mut reserved: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for k in FLAT_ENVELOPE_KEYS {
        reserved.insert(k);
    }
    for k in CRYPTO_KEYS {
        reserved.insert(k);
    }

    // 2. Public fields beyond envelope basics: anything in env that
    //    isn't an envelope basic, isn't crypto plumbing, and isn't a
    //    group payload (dict with "ciphertext").
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }

    // 3. Decrypted group fields, merged in alphabetical group order.
    let mut decrypt_errors: Vec<String> = Vec::new();
    // BTreeMap iteration is alphabetical.
    for (gname, body) in &entry.plaintext_per_group {
        if let Some(obj) = body.as_object() {
            if obj.get("$decrypt_error") == Some(&Value::Bool(true)) {
                decrypt_errors.push(gname.clone());
                continue;
            }
            if obj.get("$no_read_key") == Some(&Value::Bool(true)) {
                continue;
            }
            for (k, v) in obj {
                out.insert(k.clone(), v.clone());
            }
        }
    }

    // 4. _hidden_groups: groups in envelope with ciphertext but no
    //    readable plaintext.
    let mut hidden: Vec<String> = Vec::new();
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if !v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        let body = entry.plaintext_per_group.get(k);
        let no_read = body.is_none()
            || body.is_some_and(|b| {
                b.as_object()
                    .is_some_and(|o| o.get("$no_read_key") == Some(&Value::Bool(true)))
            });
        if no_read {
            hidden.push(k.clone());
        }
    }
    if !hidden.is_empty() {
        hidden.sort();
        out.insert(
            "_hidden_groups".into(),
            Value::Array(hidden.into_iter().map(Value::String).collect()),
        );
    }
    if !decrypt_errors.is_empty() {
        decrypt_errors.sort();
        out.insert(
            "_decrypt_errors".into(),
            Value::Array(decrypt_errors.into_iter().map(Value::String).collect()),
        );
    }

    out
}

/// Flatten a `ReadEntry` into a single JSON object: envelope fields plus
/// every per-group plaintext dict merged on top. Mirrors Python's
/// `recipients()` / `admin_state()` and TS `_mergeEnvelope` exactly.
fn merge_envelope(entry: &ReadEntry) -> Map<String, Value> {
    let mut merged: Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    for v in entry.plaintext_per_group.values() {
        if let Value::Object(group_fields) = v {
            for (k, vv) in group_fields {
                merged.insert(k.clone(), vv.clone());
            }
        }
    }
    merged
}

/// Apply schema defaults the Rust emitter omits but the catalog requires
/// at reduce time. Mirrors Python and TS `_applySchemaDefaults`.
fn apply_schema_defaults(event_type: &str, mut merged: Map<String, Value>) -> Value {
    if event_type == "tn.recipient.added" && !merged.contains_key("cipher") {
        merged.insert("cipher".into(), Value::String("btn".into()));
    }
    if event_type == "tn.recipient.revoked" && !merged.contains_key("recipient_did") {
        merged.insert("recipient_did".into(), Value::Null);
    }
    Value::Object(merged)
}

fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Predicate for `Runtime::read`: does this flat entry belong to the
/// current process's run? True iff the entry's `run_id` is a string
/// matching the runtime's. Entries with no `run_id` (or a non-string
/// value) are EXCLUDED — for cross-session safety, the default is
/// "this run only." Use [`Runtime::read_all_runs`] for the full
/// history. (FINDINGS.md #12.)
fn flat_in_current_run(flat: &FlatEntry, current_run_id: &str) -> bool {
    matches!(flat.get("run_id"), Some(Value::String(s)) if s == current_run_id)
}

/// Process-scoped rotation guard.
///
/// Returns `true` the first time this process is asked to rotate
/// `log_path`, `false` on every subsequent call for the same path.
///
/// Why: `Runtime::init` is called both for a fresh process start
/// (where rotation is the right behavior — the previous session ended
/// and we want a clean log) AND for in-process re-init (where rotation
/// would discard work the caller just wrote and break the chain). The
/// guard distinguishes the two: a path that has not been seen this
/// process is a new session; a path we have already rotated must be a
/// re-init.
fn rotation_first_time_this_process(log_path: &Path) -> bool {
    static ROTATED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let set = ROTATED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match set.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Use a key that is stable across the file's existence transitions:
    // canonicalize the parent directory (which always exists by this
    // point because chain seeding has run) and append the filename.
    // We cannot canonicalize `log_path` itself: on the FIRST init the
    // file does not exist yet, canonicalize fails, and we fall back to
    // the raw path; on the SECOND init the file exists, canonicalize
    // succeeds, and the returned absolute path differs from the first
    // run's key — so the guard's HashSet sees them as distinct paths.
    let key = if let Some(parent) = log_path.parent() {
        let canon_parent =
            std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        match log_path.file_name() {
            Some(name) => canon_parent.join(name),
            None => canon_parent,
        }
    } else {
        log_path.to_path_buf()
    };
    guard.insert(key)
}

/// Pull `(rotate_on_init, backup_count)` from the yaml `handlers:`
/// list. Defaults: rotate OFF, backup_count = 5. Looks at the first
/// `file.rotating` entry — multiple file handlers in one yaml is an
/// edge case we don't model; whichever appears first wins.
///
/// **Default off** because TN logs are an attestation chain — the
/// `prev_hash`/`row_hash` chain spans the file in append-only fashion,
/// and rotating at session start would break verification across the
/// rotation boundary. Operators who want a separate file per session
/// (e.g. for size management) can opt in via yaml
/// `handlers[*].rotate_on_init: true`. The process-scoped guard in
/// `rotation_first_time_this_process` still applies on top so that
/// in-process re-init never rotates regardless of the yaml.
fn read_rotation_config(handlers: &[serde_yml::Value]) -> (bool, usize) {
    for h in handlers {
        let kind = h.get("kind").and_then(|v| v.as_str());
        if kind != Some("file.rotating") && kind != Some("file") {
            continue;
        }
        let rotate = h.get("rotate_on_init").and_then(serde_yml::Value::as_bool).unwrap_or(false);
        let backup_count = h
            .get("backup_count")
            .and_then(serde_yml::Value::as_u64)
            .map_or(5, |n| usize::try_from(n).unwrap_or(5));
        return (rotate, backup_count);
    }
    (false, 5)
}

/// Roll an existing non-empty log file to `<name>.1`, shifting any
/// existing numbered backups forward (`.1` → `.2`, `.2` → `.3`, ...,
/// up to `backup_count`). The `<name>.<backup_count>` slot is dropped
/// to keep the on-disk footprint bounded. Mirrors stdlib
/// `logging.handlers.RotatingFileHandler.doRollover` semantics.
///
/// Best-effort: filesystem errors (permission denied, race with
/// another process, missing parent) are logged and swallowed so a
/// rotation hiccup never blocks `Runtime::init`. The new session
/// falls through to writing into the existing file in that case.
fn rotate_log_on_session_start(log_path: &Path, backup_count: usize) {
    let Ok(metadata) = std::fs::metadata(log_path) else {
        return; // file doesn't exist; nothing to rotate
    };
    if metadata.len() == 0 {
        return; // empty file; treat as "no prior session"
    }

    // Walk backwards: drop the oldest, then shift each `.N` → `.N+1`.
    let max_n = backup_count.max(1);
    let oldest = path_with_backup_suffix(log_path, max_n);
    let _ = std::fs::remove_file(&oldest); // ignore "not found"
    for n in (1..max_n).rev() {
        let from = path_with_backup_suffix(log_path, n);
        let to = path_with_backup_suffix(log_path, n + 1);
        if from.exists() {
            if let Err(e) = std::fs::rename(&from, &to) {
                log::warn!(
                    "session rotation: failed to shift {} → {}: {e}",
                    from.display(),
                    to.display(),
                );
            }
        }
    }
    // Finally rename current → .1.
    let dot_one = path_with_backup_suffix(log_path, 1);
    if let Err(e) = std::fs::rename(log_path, &dot_one) {
        log::warn!(
            "session rotation: failed to roll {} → {}: {e}",
            log_path.display(),
            dot_one.display(),
        );
    }
}

/// `<name>` → `<name>.<n>` (e.g. `tn.ndjson` → `tn.ndjson.1`).
fn path_with_backup_suffix(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// True iff `log_path` is a foreign publisher's log (different `did`
/// on the first envelope) AND we have a kit on disk that could decrypt
/// it. Used by [`Runtime::read_from`] to auto-route cross-publisher
/// reads through the foreign-decrypt path. Mirrors Python's
/// `_is_foreign_log` and TS's `_isForeignLog`.
///
/// Conservative on failure: if the file is unreadable, has no
/// parseable line, lacks our default kit, or is exactly our own log,
/// return false so the regular path runs and surfaces the underlying
/// error itself.
fn is_foreign_log(
    log_path: &Path,
    own_log: &Path,
    own_did: &str,
    keystore: &Path,
) -> bool {
    // Exempt exactly our own log path — post-flush "reading my own log"
    // case where the auto-discovery cfg may have a different device but
    // the log is conceptually own. Narrowed per AVL J7.1 Bug 2.
    if let (Ok(a), Ok(b)) = (log_path.canonicalize(), own_log.canonicalize()) {
        if a == b {
            return false;
        }
    }

    // No kit on disk → foreign route guaranteed to yield $no_read_key
    // for every entry. Regular path's "kit not entitled" is more
    // actionable, so let it run.
    if !keystore.join("default.btn.mykit").exists() {
        return false;
    }

    // Peek the first parseable envelope's `did`.
    let Ok(text) = std::fs::read_to_string(log_path) else {
        return false;
    };
    for raw_line in text.split('\n') {
        let s = raw_line.trim();
        if s.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<Value>(s) else {
            continue;
        };
        if let Some(env_did) = env.get("did").and_then(Value::as_str) {
            if !env_did.is_empty() {
                return env_did != own_did;
            }
        }
        // First non-empty line had no did — give up; let regular path run.
        return false;
    }
    false
}

/// Decrypt a foreign publisher's log, attempting EVERY group for which
/// the local keystore holds a `<group>.btn.mykit` kit. Mirrors what the
/// regular `read_from` path does (try every group the runtime knows
/// about) so `secure_read`'s `tn.agents` instructions splice surfaces
/// correctly even when the log is foreign.
///
/// Calls [`crate::read_as_recipient::read_as_recipient`] once per
/// kit-bearing group, then merges the per-group results back into a
/// single per-envelope `ReadEntry`. The signature/chain `valid` block
/// is dropped here; `secure_read` recomputes verification from the
/// envelope itself.
fn read_foreign_log(log_path: &Path, keystore: &Path) -> Result<Vec<ReadEntry>> {
    use crate::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};

    // Discover every group the keystore has a kit for. The foreign
    // route is btn-only today (read_as_recipient errors out on JWE
    // keys) so we only scan `<group>.btn.mykit`.
    let mut groups: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(keystore) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(s) = name.to_str() else { continue };
            if let Some(stem) = s.strip_suffix(".btn.mykit") {
                if !stem.is_empty() {
                    groups.push(stem.to_string());
                }
            }
        }
    }
    if groups.is_empty() {
        // No kits at all — fall through to the single-group default
        // path so the underlying error message is "no recipient kit
        // for group 'default'" rather than a silently-empty result.
        groups.push("default".to_string());
    }
    groups.sort();

    // Run the foreign-decrypt iterator once per group. Each pass
    // produces a list of `ForeignReadEntry`s in log order; merge them
    // by envelope into a single `ReadEntry` whose `plaintext_per_group`
    // carries one decrypted block per kit-holding group.
    let mut envelopes: Vec<Map<String, Value>> = Vec::new();
    let mut merged_plaintext: Vec<BTreeMap<String, Value>> = Vec::new();
    for (idx, group) in groups.iter().enumerate() {
        let opts = ReadAsRecipientOptions {
            group: group.clone(),
            verify_signatures: true,
        };
        let foreign = read_as_recipient(log_path, keystore, opts)?;
        if idx == 0 {
            envelopes.reserve(foreign.len());
            merged_plaintext.reserve(foreign.len());
            for e in foreign {
                envelopes.push(e.envelope);
                let mut pt: BTreeMap<String, Value> = BTreeMap::new();
                for (gname, val) in e.plaintext {
                    pt.insert(gname, val);
                }
                merged_plaintext.push(pt);
            }
        } else {
            for (i, e) in foreign.into_iter().enumerate() {
                if i >= merged_plaintext.len() {
                    break;
                }
                for (gname, val) in e.plaintext {
                    merged_plaintext[i].insert(gname, val);
                }
            }
        }
    }

    let mut out = Vec::with_capacity(envelopes.len());
    for (env, pt) in envelopes.into_iter().zip(merged_plaintext.into_iter()) {
        out.push(ReadEntry {
            envelope: Value::Object(env),
            plaintext_per_group: pt,
        });
    }
    Ok(out)
}

fn validate_event_type(et: &str) -> Result<()> {
    if et.is_empty() {
        return Err(Error::InvalidConfig("event_type empty".into()));
    }
    if !et
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(Error::InvalidConfig(format!(
            "event_type has invalid chars: {et:?}"
        )));
    }
    Ok(())
}

fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Return value of `build_cipher_with_admin`: (cipher, optional pub cipher for admin, optional mykit bytes).
type BuildCipherResult = (
    Arc<dyn GroupCipher>,
    Option<BtnPublisherCipher>,
    Option<Vec<u8>>,
);

/// Returns `(cipher, Option<BtnPublisherCipher for admin>, Option<mykit_bytes>)`.
///
/// The `BtnPublisherCipher` returned for admin still reflects the **current**
/// state (no reader kit attached; admin only needs the PublisherState).  The
/// mykit bytes are kept separately so `rebuild_btn_cipher` can re-attach them.
fn build_cipher_with_admin(
    spec: &GroupSpec,
    keystore: &Path,
    group_name: &str,
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin(keystore, group_name),
        "jwe" | "bearer" => Err(Error::NotImplemented(
            "JWE groups run through the Python runtime in this plan; migrate to btn for Rust",
        )),
        "bgw" => Err(Error::NotImplemented(
            "BGW groups run through the Python runtime; FFI port deferred",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

/// Collect all kit files for a group: the current `<group>.btn.mykit` first,
/// followed by any `<group>.btn.mykit.revoked.<ts>` siblings sorted by
/// timestamp descending (most recent first). Returned as a vec of byte
/// blobs in try-first order. Empty vec if no kit files exist.
///
/// Rotation preserves previous kits under `.revoked.<ts>` so pre-rotation
/// entries stay readable. `BtnReaderCipher` tries each kit in order and
/// the first successful decrypt wins.
fn collect_btn_kit_bytes(keystore: &Path, group: &str) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if current.exists() {
        kits.push(std::fs::read(&current).map_err(Error::Io)?);
    }

    // Gather all `<group>.btn.mykit.revoked.<ts>` siblings.
    let prefix = format!("{group}.btn.mykit.revoked.");
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(keystore) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Some(ts_str) = name_str.strip_prefix(&prefix) {
                // Expect ts_str to be a unix timestamp like "1776797973"; tolerate
                // non-numeric suffixes by falling back to 0 (gets sorted last).
                let ts: u64 = ts_str.parse().unwrap_or(0);
                revoked.push((entry.path(), ts));
            }
        }
    }
    // Most-recent revoked first; that's the most likely era for any given
    // older entry to belong to, so it's tried before deeper-history kits.
    revoked.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in revoked {
        kits.push(std::fs::read(&path).map_err(Error::Io)?);
    }

    Ok(kits)
}

fn build_btn_cipher_with_admin(keystore: &Path, group: &str) -> Result<BuildCipherResult> {
    // Filenames verified against tn/cipher.py::BtnGroupCipher:
    //   <keystore>/<group>.btn.state                  - serialized PublisherState (SECRET)
    //   <keystore>/<group>.btn.mykit                  - current self-kit (for decrypt)
    //   <keystore>/<group>.btn.mykit.revoked.<ts>     - preserved kits from previous rotations
    let state_path = keystore.join(format!("{group}.btn.state"));
    let all_kits = collect_btn_kit_bytes(keystore, group)?;
    let has_any_kit = !all_kits.is_empty();

    match (state_path.exists(), has_any_kit) {
        (true, _) => {
            let state_bytes = std::fs::read(&state_path).map_err(Error::Io)?;
            let pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            // Admin side-table holds the raw publisher cipher (no kit attached).
            // We need a second copy for admin, so deserialize again.
            let admin_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            // Remember the CURRENT kit bytes only (admin flows rebuild the
            // publisher using this as the "latest" kit; rotation-preserved
            // kits are discovered fresh on each init via collect_btn_kit_bytes).
            let current_mykit = all_kits.first().cloned();
            let cipher: Arc<dyn GroupCipher> = if has_any_kit {
                Arc::new(pc.with_reader_kits(&all_kits)?)
            } else {
                Arc::new(pc)
            };
            Ok((cipher, Some(admin_pc), current_mykit))
        }
        (false, true) => {
            let current_mykit = all_kits.first().cloned();
            let cipher = Arc::new(BtnReaderCipher::from_multi_kit_bytes(&all_kits)?);
            // Reader-only: no admin capability.
            Ok((cipher, None, current_mykit))
        }
        (false, false) => Err(Error::InvalidConfig(format!(
            "btn group {group}: no {group}.btn.state and no {group}.btn.mykit in keystore"
        ))),
    }
}

/// Rebuild a `BtnPublisherCipher` trait object from the current admin cipher state,
/// re-attaching the mykit if available.
fn rebuild_btn_cipher(
    pub_cipher: &BtnPublisherCipher,
    mykit_bytes: Option<&[u8]>,
) -> Result<Arc<dyn GroupCipher>> {
    let state_bytes = pub_cipher.state_to_bytes();
    let new_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
    let cipher: Arc<dyn GroupCipher> = if let Some(kit) = mykit_bytes {
        Arc::new(new_pc.with_reader_kit(kit)?)
    } else {
        Arc::new(new_pc)
    };
    Ok(cipher)
}

/// Seed chain state from a log file and return whether `tn.ceremony.init`
/// was present in that file.
fn seed_chain_from_log(log_path: &Path, chain: &ChainState) -> Result<bool> {
    if !log_path.exists() {
        return Ok(false);
    }
    let mut latest: HashMap<String, (u64, String)> = HashMap::new();
    let mut saw_ceremony_init = false;
    for res in LogFileReader::open(log_path)? {
        let env = res?;
        let et = env
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Malformed {
                kind: "log entry",
                reason: "missing event_type".into(),
            })?
            .to_string();
        if et == "tn.ceremony.init" {
            saw_ceremony_init = true;
        }
        let seq = env
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Malformed {
                kind: "log entry",
                reason: "missing sequence".into(),
            })?;
        let rh = env
            .get("row_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Malformed {
                kind: "log entry",
                reason: "missing row_hash".into(),
            })?
            .to_string();
        latest.insert(et, (seq, rh));
    }
    chain.seed(latest);
    Ok(saw_ceremony_init)
}

/// Scan a single ndjson file for any line whose `event_type` is `tn.ceremony.init`.
/// Returns `true` if found, `false` if file absent or not found.
fn scan_for_ceremony_init(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    for res in LogFileReader::open(path)? {
        let env = res?;
        if env.get("event_type").and_then(|v| v.as_str()) == Some("tn.ceremony.init") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve the protocol-events-location template without a Runtime instance.
///
/// Only expands `{event_class}` to `"ceremony"` (the class of `tn.ceremony.init`),
/// plus `{yaml_dir}`, `{ceremony_id}`, and `{did}`. `{event_type}` becomes
/// `"tn.ceremony.init"`. `{date}` is not required for fresh-detection purposes;
/// the file either exists or it doesn't regardless of date.
fn resolve_pel_static(tmpl: &str, yaml_dir: &Path, ceremony_id: &str, did: &str) -> PathBuf {
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date = OffsetDateTime::now_utc()
        .format(&date_fmt)
        .unwrap_or_else(|_| "1970-01-01".to_string());
    let yaml_dir_s = yaml_dir.to_string_lossy().into_owned();
    let filled = tmpl
        .replace("{event_type}", "tn.ceremony.init")
        .replace("{event_class}", "ceremony")
        .replace("{date}", &date)
        .replace("{yaml_dir}", &yaml_dir_s)
        .replace("{ceremony_id}", ceremony_id)
        .replace("{did}", did);
    // Anchor relative templates at the yaml dir — same fix as
    // ``Runtime::resolve_pel``. Without it, fresh-detection scans the
    // wrong file (process cwd) and we end up emitting tn.ceremony.init
    // twice on a re-init.
    let p = PathBuf::from(filled);
    if p.is_absolute() {
        p
    } else {
        yaml_dir.join(p)
    }
}

/// Mint a fresh btn ceremony at `root`. Layout matches the test helper
/// in `tests/common/mod.rs::setup_minimal_btn_ceremony`:
///
/// ```text
/// <root>/
///   .tn/
///     keys/
///       local.private        — 32-byte Ed25519 seed
///       index_master.key     — 32 random bytes
///       default.btn.state    — serialized PublisherState
///       default.btn.mykit    — minted ReaderKit
///       tn.agents.btn.state  — serialized PublisherState (reserved policy group)
///       tn.agents.btn.mykit  — minted ReaderKit (reserved policy group)
///   tn.yaml
/// ```
///
/// Used by [`Runtime::ephemeral`]. Lives in the public crate so
/// downstream tests + benches don't have to duplicate it.
///
/// Auto-injects the reserved `tn.agents` group per the 2026-04-25
/// read-ergonomics spec §2.3. Pure-logging users pay nothing — the
/// group's plaintext stays empty when no policy file exists.
fn write_fresh_btn_ceremony(root: &Path) -> std::io::Result<()> {
    use rand_core::{OsRng, RngCore};

    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore)?;

    // Device key — 32-byte Ed25519 seed.
    let dk = crate::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes())?;

    // Master index key — 32 random bytes from the OS.
    let mut master = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    std::fs::write(keystore.join("index_master.key"), master)?;

    // default group: btn publisher state + self-reader kit.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed).map_err(|e| {
            std::io::Error::other(format!("btn setup failed: {e:?}"))
        })?;
    let kit = pub_state.mint().map_err(|e| {
        std::io::Error::other(format!("btn mint failed: {e:?}"))
    })?;
    std::fs::write(keystore.join("default.btn.state"), pub_state.to_bytes())?;
    std::fs::write(keystore.join("default.btn.mykit"), kit.to_bytes())?;

    // tn.agents reserved group: btn publisher state + self-reader kit.
    let mut agents_seed = [0u8; 32];
    OsRng.fill_bytes(&mut agents_seed);
    let mut agents_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, agents_seed).map_err(|e| {
            std::io::Error::other(format!("btn setup (tn.agents) failed: {e:?}"))
        })?;
    let agents_kit = agents_state
        .mint()
        .map_err(|e| std::io::Error::other(format!("btn mint (tn.agents) failed: {e:?}")))?;
    std::fs::write(
        keystore.join("tn.agents.btn.state"),
        agents_state.to_bytes(),
    )?;
    std::fs::write(keystore.join("tn.agents.btn.mykit"), agents_kit.to_bytes())?;

    let did = dk.did().to_string();
    let id = format!("cer_eph_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let yaml = format!(
        "ceremony: {{id: {id}, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         me: {{did: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    std::fs::write(root.join("tn.yaml"), yaml)?;
    Ok(())
}
