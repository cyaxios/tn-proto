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
    agents_policy::PolicyDocument,
    canonical::canonical_bytes,
    chain::{chain_tip_from_log_tail_reverse, compute_row_hash, ChainState, GroupInput, RowHashInput},
    cipher::{
        btn::{BtnPublisherCipher, BtnReaderCipher},
        GroupCipher,
    },
    classifier::classify,
    config::{Config, GroupSpec},
    envelope::{build_envelope, EnvelopeInput, GroupPayload},
    indexing::index_token_with_template,
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

/// Options for [`Runtime::init_with_options`]. Mirrors the
/// [`SecureReadOptions`] pattern: a small `Default`-able struct that
/// extends the load path without bloating the function signature.
///
/// The single knob today is the `tn.ceremony.init` auto-emit. SDK
/// wrappers that already initialized the ceremony out-of-band (e.g.
/// the TS `NodeRuntime` lazily attaching a `WasmRuntime` mid-process)
/// need to skip the auto-emit so they don't double-attest the
/// ceremony from two runtimes.
#[derive(Default, Clone, Debug)]
pub struct RuntimeInitOptions {
    /// If true, skip the auto-emit of `tn.ceremony.init` even when no
    /// prior one is found in the admin log. Used by SDK wrappers that
    /// have already initialized the ceremony out-of-band (e.g. TS
    /// `NodeRuntime` attaching wasm mid-lifecycle).
    pub skip_ceremony_init_emit: bool,
    /// If true, skip the auto-emit of `tn.agents.policy_published`
    /// during init. The TS-side `Tn` constructor performs its own
    /// policy-published dedupe + emit (mirroring Python's TNClient),
    /// so when a lazy-attached wasm runtime runs the same logic at
    /// `attachWasm()` time, both writers emit independently and the
    /// log ends up with a duplicate event. SDK wrappers that own the
    /// policy-published lifecycle on their side set this flag.
    pub skip_policy_published_emit: bool,
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
    pub recipient_identity: Option<String>,
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
    pub device_identity: String,
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
    pub publisher_identity: String,
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
    pub recipient_identity: Option<String>,
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
    pub recipient_identity: String,
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
    pub peer_identity: String,
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
    pub vault_identity: String,
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
    /// Pre-initialized HMAC-SHA256 keyed by `index_key`. Each
    /// per-emit `index_token` call clones this template and feeds
    /// the field bytes into the clone — skips the `Mac::new_from_slice`
    /// init cost (~2-3 µs per field) every emit. Built once at
    /// runtime construction, never mutated.
    pub(crate) hmac_template: hmac::Hmac<sha2::Sha256>,
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
    pub(crate) log_writer: crate::log_file::LogWriters,
    /// Writer pool for protocol-event-location (PEL) admin writes.
    /// When `cfg.ceremony.protocol_events_location != "main_log"`,
    /// admin events route here so they get the same pinned-handle /
    /// lock-cache / offset-skip machinery as the main log. When PEL
    /// is `"main_log"`, `pel_routed` is always false at emit time so
    /// this field is never consulted; we still construct it as a
    /// shadow of `log_writer` to keep `flush_all` symmetric.
    pub(crate) pel_writer: crate::log_file::LogWriters,
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
    /// Field-routing table cached at init (0.4.2a7 perf fix).
    ///
    /// `field_to_groups()` walks the config and builds a routing map
    /// from scratch — that's O(groups × fields_per_group) of allocation
    /// and validation work. It's a static function of the loaded
    /// `Config`, so the result is the same on every emit. We compute
    /// once at runtime construction and reference for the lifetime
    /// of this `Runtime`. Rebuilt only on `Runtime::reload`/re-init
    /// after admin verbs mutate the yaml (e.g. `ensure_group`).
    pub(crate) field_to_groups: BTreeMap<String, Vec<String>>,
    /// `public_fields` rendered as a HashSet for O(1) membership
    /// tests (0.4.2a7 perf fix). Was previously built every emit
    /// from the `Vec<String>` in the config; that's wasted
    /// allocation when the result is invariant per runtime.
    pub(crate) public_set: std::collections::HashSet<String>,
    /// Group names whose `policy == "public"` — fields routed to
    /// these groups skip the cipher and land in the envelope as
    /// plaintext (same effect as listing them under `public_fields`).
    /// Cached at init so the field-classify hot path can check
    /// membership inline; the prior version did a two-pass dance
    /// (classify normally → walk `per_group` again → promote).
    pub(crate) public_groups: std::collections::HashSet<String>,
    /// Pluggable byte-storage backend. Native consumers (CLI, PyO3
    /// wheel) construct this from `FsStorage`; the wasm wrapper
    /// injects a JS-callback adapter. Every emit / read / log-rotation
    /// / chain-seeding call site routes through this handle so a wasm
    /// consumer can satisfy the I/O from JS-side callbacks. Admin
    /// verbs (handlers, vault, export) are deliberately still on
    /// `std::fs::*` — those are operator-side concerns and the wasm
    /// adapter wouldn't have anything sensible to do with a vault
    /// drop directory anyway.
    #[cfg(feature = "fs")]
    pub(crate) storage: Arc<dyn crate::storage::Storage>,
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
    /// Native filesystem-backed factory. Internally delegates to
    /// [`Runtime::init_with_storage`] passing an `FsStorage` so the
    /// two paths share a single body. Use `init_with_storage`
    /// directly when you need an injected storage backend (wasm,
    /// tests, in-memory sandboxes).
    pub fn init(yaml_path: &Path) -> Result<Self> {
        crate::perf::init_from_env();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
        Self::init_with_storage(yaml_path, storage)
    }

    /// Load a ceremony with a caller-supplied [`Storage`] backend.
    ///
    /// Thin wrapper over [`Runtime::init_with_options`] using
    /// `RuntimeInitOptions::default()`. See that method for the full
    /// docstring.
    ///
    /// [`Storage`]: crate::storage::Storage
    pub fn init_with_storage(
        yaml_path: &Path,
        storage: Arc<dyn crate::storage::Storage>,
    ) -> Result<Self> {
        Self::init_with_options(yaml_path, storage, RuntimeInitOptions::default())
    }

    /// Load a ceremony with a caller-supplied [`Storage`] backend and
    /// extra options.
    ///
    /// The storage handle is stored on the returned `Runtime` so
    /// subsequent emit / read / admin calls route file I/O through
    /// the same backend. **Today (Phase 7 landing) only the
    /// load-bearing reads inside `init` consult the storage; later
    /// phases fan it out across the rest of `Runtime`. See the
    /// `storage` field comment for the migration status.**
    ///
    /// `yaml_path` is read via `storage.read_bytes`; on wasm with a
    /// `JsStorageAdapter` that means the JS callback is invoked.
    ///
    /// `opts` lets the caller suppress side-effects that are
    /// inappropriate when the SDK has already initialized the
    /// ceremony out-of-band — see [`RuntimeInitOptions`].
    ///
    /// [`Storage`]: crate::storage::Storage
    #[allow(clippy::too_many_lines)]
    // cognitive_complexity: this fn intentionally holds the
    // ceremony-mint vs ceremony-load invariant in one place — see the
    // comment above. Splitting helpers would scatter the "what state
    // must be coherent before we hand back a Runtime" check across
    // call sites where it's easy to miss in review.
    #[allow(clippy::cognitive_complexity)]
    pub fn init_with_options(
        yaml_path: &Path,
        storage: Arc<dyn crate::storage::Storage>,
        opts: RuntimeInitOptions,
    ) -> Result<Self> {
        // Call site 1: yaml read. Routes through Storage so a wasm
        // `JsStorageAdapter` can satisfy the request from its JS-side
        // callback rather than `std::fs::read_to_string`.
        let yaml_bytes = storage.read_bytes(yaml_path).map_err(Error::Io)?;
        let yaml_str = std::str::from_utf8(&yaml_bytes).map_err(|e| {
            Error::InvalidConfig(format!("yaml is not valid UTF-8: {e}"))
        })?;
        let expanded = crate::config::substitute_env_vars(yaml_str, yaml_path)?;
        // Resolve `extends:` chain through the same Storage backend so
        // stream yamls written by `createFreshCeremony` (which carry
        // `extends: ../default/tn.yaml`) load correctly under wasm too.
        // Matches Python `_resolve_extends` semantics.
        let cfg = crate::config::parse_with_extends(&expanded, yaml_path, storage.as_ref())?;
        let yaml_dir = yaml_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let keystore = resolve(&yaml_dir, Path::new(&cfg.keystore.path));

        // Call site 2: device-key load (32-byte seed at <keystore>/local.private).
        let seed_path = keystore.join(crate::identity::DEVICE_SEED_FILENAME);
        let seed_bytes = storage.read_bytes(&seed_path).map_err(Error::Io)?;
        let device = DeviceKey::from_private_bytes(&seed_bytes)?;
        if device.did() != cfg.device.device_identity {
            return Err(Error::InvalidConfig(format!(
                "keystore DID {} does not match yaml device.device_identity {}",
                device.did(),
                cfg.device.device_identity
            )));
        }

        // Call site 3: master index key (32 raw bytes at <keystore>/index_master.key).
        // Filename matches Python tn/config.py.
        let master_path = keystore.join("index_master.key");
        let master_index_key: [u8; 32] = storage
            .read_bytes(&master_path)
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
            // Call site 4: cipher construction reads `<group>.btn.state`
            // and `<group>.btn.mykit` through storage.
            let (cipher, maybe_pub_cipher, mykit_bytes) =
                build_cipher_with_admin_with_storage(spec, &keystore, name, &storage)?;
            let hmac_template =
                crate::indexing::build_hmac_template(&index_key)?;
            groups.insert(
                name.clone(),
                Arc::new(RwLock::new(GroupState {
                    cipher,
                    index_key,
                    hmac_template,
                })),
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
        let log_path = if is_absolute_xplat_path(configured) {
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
            rotate_log_on_session_start(&log_path, backup_count, &storage);
        }

        // Parse the main-log template once. The parsed template is
        // reused both for the chain seed (literal vs templated) and
        // for the `LogWriters` construction below.
        let log_path_template = crate::path_template::PathTemplate::parse(
            &cfg.logs.path,
            &yaml_dir,
            &cfg.ceremony.id,
            device.did(),
        )?;

        let chain = ChainState::new();

        // Seed chain state from the main log and check for a prior
        // ceremony.init. Templated `logs.path` walks every rendered
        // `.ndjson` under the template's parent directory; literal
        // paths just walk the one file. Wiring the templated seed
        // closes a silent regression introduced when templated paths
        // moved off the Python emit path — without it, chained
        // templated ceremonies reset every event_type's
        // (sequence, prev_hash) to (1, ZERO) on each restart.
        let mut saw_ceremony_init = if log_path_template.is_templated() {
            seed_chain_from_template(&log_path_template, &chain, &storage)?
        } else {
            seed_chain_from_log(&log_path, &chain, &storage)?
        };

        // Session rotation makes the current main log empty; a prior
        // `tn.ceremony.init` may live on a rotation backup. Scan the
        // shifted `<log>.1`..`.N` files so we don't re-emit
        // `tn.ceremony.init` on every session start (which would
        // pollute the admin log with one Frank-own event per session
        // and break cross-publisher reads of admin snapshots).
        if !saw_ceremony_init {
            for n in 1..=backup_count.max(1) {
                let backup = path_with_backup_suffix(&log_path, n);
                if storage.exists(&backup) && scan_for_ceremony_init(&backup, &storage)? {
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
            saw_ceremony_init = scan_for_ceremony_init(&pel, &storage)?;
        }

        // A ceremony is fresh iff no prior tn.ceremony.init exists in the log(s).
        // Checking main-log existence would miss the case where
        // protocol_events_location routes tn.* events to a separate file.
        let is_fresh = !saw_ceremony_init;

        // Construct the writer pool from the template hoisted above.
        // Init-time tokens (`{yaml_dir}`, `{ceremony_id}`, `{did}`)
        // were substituted at parse time. The dispatcher routes
        // per-emit to a literal writer (one shared `LogFileWriter`)
        // OR a lazy pool keyed by rendered path.
        let log_writer = if log_path_template.is_templated() {
            crate::log_file::LogWriters::Templated {
                template: log_path_template,
                storage: Arc::clone(&storage),
                writers: Mutex::new(std::collections::HashMap::new()),
            }
        } else {
            // Literal path — render once (returns the path with
            // any relative root resolved against yaml_dir) and
            // open the single writer.
            let path = log_path_template.render("");
            let writer = LogFileWriter::open(&path, Arc::clone(&storage))?;
            crate::log_file::LogWriters::Literal {
                path,
                writer: Arc::new(Mutex::new(writer)),
            }
        };

        // PEL writer mirrors the main log writer for `tn.*` admin
        // events when `protocol_events_location != "main_log"`. The
        // pre-0.4.2a8 emit path opened a fresh file handle per admin
        // emit via `storage.append_bytes`, paying ~150 us of Windows
        // syscall floor (CreateFileW + WriteFile + CloseHandle).
        // Routing PEL emits through a `LogWriters` pool reuses the
        // pinned-handle, lock-cache, and offset-skip machinery and
        // closes that asymmetry with the main path.
        //
        // PEL=="main_log" shadow: emit-time `pel_routed` is always
        // false in that mode, so this field is never read. We still
        // build a placeholder that mirrors the main log so
        // `flush_all` at shutdown is symmetric and the struct field
        // always holds a valid `LogWriters`.
        let pel_writer = {
            let pel_raw = &cfg.ceremony.protocol_events_location;
            if pel_raw == "main_log" {
                match &log_writer {
                    crate::log_file::LogWriters::Literal { path, writer } => {
                        crate::log_file::LogWriters::Literal {
                            path: path.clone(),
                            writer: writer.clone(),
                        }
                    }
                    crate::log_file::LogWriters::Templated { template, storage: stor, .. } => {
                        crate::log_file::LogWriters::Templated {
                            template: template.clone(),
                            storage: Arc::clone(stor),
                            writers: Mutex::new(std::collections::HashMap::new()),
                        }
                    }
                }
            } else {
                let pel_template = crate::path_template::PathTemplate::parse(
                    pel_raw,
                    &yaml_dir,
                    &cfg.ceremony.id,
                    device.did(),
                )?;
                if pel_template.is_templated() {
                    crate::log_file::LogWriters::Templated {
                        template: pel_template,
                        storage: Arc::clone(&storage),
                        writers: Mutex::new(std::collections::HashMap::new()),
                    }
                } else {
                    let path = pel_template.render("");
                    let writer = LogFileWriter::open(&path, Arc::clone(&storage))?;
                    crate::log_file::LogWriters::Literal {
                        path,
                        writer: Arc::new(Mutex::new(writer)),
                    }
                }
            }
        };

        // Call site 5: agents.md policy load routes through storage so
        // a wasm consumer's JS adapter can supply the file (or report
        // it absent).
        let agent_policies =
            match crate::agents_policy::load_policy_file_with_storage(&yaml_dir, &storage) {
                Ok(opt) => opt,
                Err(Error::Io(_)) => None,
                Err(e) => return Err(e),
            };

        // 0.4.2a7: pre-compute the field-routing table, public
        // membership set, and the set of groups whose policy is
        // public so emit_inner doesn't rebuild them per call. All
        // three are pure functions of the loaded `Config` —
        // invalidate only by re-init (which builds a fresh Runtime
        // anyway).
        let field_to_groups = cfg.field_to_groups()?;
        let public_set: std::collections::HashSet<String> =
            cfg.public_fields.iter().cloned().collect();
        let public_groups: std::collections::HashSet<String> = cfg
            .groups
            .iter()
            .filter(|(_, gspec)| gspec.policy == "public")
            .map(|(gname, _)| gname.clone())
            .collect();

        let rt = Self {
            yaml_path: yaml_path.to_path_buf(),
            cfg,
            device,
            chain,
            groups,
            log_writer,
            pel_writer,
            log_path,
            master_index_key,
            btn_admin,
            btn_mykit,
            keystore,
            owned_tempdir: None,
            agent_policies,
            handlers: Mutex::new(Vec::new()),
            storage,
            // Honor $TN_RUN_ID if the host (e.g. the Python wrapper) has
            // already minted one for this process. Otherwise mint a fresh
            // UUID. Either way every emit stamps the same `run_id` so
            // `Runtime::read` can default-filter to "this run only".
            run_id: std::env::var("TN_RUN_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string()),
            field_to_groups,
            public_set,
            public_groups,
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
        let stdout_entry = rt
            .cfg
            .handlers
            .iter()
            .find(|h| h.get("kind").and_then(|v| v.as_str()) == Some("stdout"));
        let yaml_silences_stdout = !rt.cfg.handlers.is_empty() && stdout_entry.is_none();
        if std::env::var("TN_NO_STDOUT").as_deref() != Ok("1") && !yaml_silences_stdout {
            // Honour an explicit ``format:`` on the yaml stdout entry so a
            // yaml that asks for json gets json by default. The
            // ``TN_STDOUT_FORMAT`` env var still wins (resolved per-emit
            // inside the handler).
            let format = stdout_entry
                .and_then(|h| h.get("format"))
                .and_then(|v| v.as_str())
                .map(crate::handlers::StdoutFormat::parse)
                .unwrap_or_default();
            rt.add_handler(Arc::new(crate::handlers::StdoutHandler::with_format_and_filter(
                format,
                crate::handlers::spec::FilterSpec::default(),
            )));
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
        //
        // `opts.skip_ceremony_init_emit` short-circuits the auto-emit even on a
        // fresh ceremony. SDK wrappers that bootstrap the ceremony from
        // another runtime (e.g. TS `NodeRuntime` lazily attaching a
        // `WasmRuntime` mid-process) set this to avoid double-attesting
        // the ceremony from two runtime instances.
        if is_fresh && !opts.skip_ceremony_init_emit {
            let now = current_timestamp();
            let mut init_fields = serde_json::Map::new();
            init_fields.insert("ceremony_id".into(), serde_json::json!(rt.cfg.ceremony.id));
            init_fields.insert("cipher".into(), serde_json::json!(rt.cfg.ceremony.cipher));
            init_fields.insert("device_identity".into(), serde_json::json!(rt.device.did()));
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
        // SDK wrappers (TS NodeRuntime) that own this lifecycle on their
        // side set `skip_policy_published_emit` to avoid the duplicate.
        if !opts.skip_policy_published_emit {
            if let Err(e) = rt.maybe_emit_policy_published() {
                log::warn!("tn.agents.policy_published emit failed: {e}");
            }
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
            .map(|_| ())
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
            .map(|_| ())
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
            .map(|_| ())
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
            .map(|_| ())
    }

    /// Same as [`Runtime::emit_with_override_sign`] but returns the canonical
    /// envelope NDJSON line (newline-terminated) so the host can fan out to
    /// its own handlers without re-deriving it. `Ok(None)` means the emit
    /// was filtered by the log-level threshold and produced no envelope.
    ///
    /// Used by the Python `DispatchRuntime` to run user-registered Python
    /// handlers (kafka, S3, vault.sync, etc.) after the Rust runtime has
    /// already written the entry, signed it, advanced the chain, and fanned
    /// out to its own native handlers (file, stdout). Mirrors what TS does
    /// natively in-process — Python pays the JSON-parse cost once on the
    /// returned line rather than re-encrypting + re-signing in pure Python.
    pub fn emit_with_override_sign_returning_line(
        &self,
        level: &str,
        event_type: &str,
        fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<Option<String>> {
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
    // across the sealing/signing/writing phases. The chain-enabled
    // closure (under `with_advisory_lock`) builds on the same locals,
    // so it carries the same allow.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn emit_inner(
        &self,
        level: &str,
        event_type: &str,
        mut fields: Map<String, Value>,
        timestamp: Option<&str>,
        event_id: Option<&str>,
        sign: Option<bool>,
    ) -> Result<Option<String>> {
        // Outer perf wrapper — measures total emit_inner time so we
        // can confirm the per-stage breakdown sums correctly.
        // `TN_PERF_TRACE` env var gates the instrumentation; when
        // off this is one atomic-bool load per emit.
        let _emit_total_start = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };

        // Log-level filter (AVL J3.2). Drop emits whose level is below
        // the active threshold before any work happens. Severity-less
        // ("") always passes — it's an explicit "this is a fact"
        // primitive whose semantics shouldn't depend on the filter.
        if !level.is_empty() {
            let lv = level_value(level);
            if lv >= 0 && lv < LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) {
                return Ok(None);
            }
        }

        let _prelude_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
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
        if let Some(t0) = _prelude_t0 {
            crate::perf::record_ns("emit:prelude", t0.elapsed().as_nanos() as u64);
        }

        let (ts, eid, level_norm) = crate::perf::time_stage("emit:header", || {
            (
                timestamp.map_or_else(current_timestamp, str::to_string),
                // UUID v7 (0.4.2a7): time-sortable event_id with a
                // 48-bit ms timestamp in the high bits. Sorting log
                // entries by event_id now puts them in chronological
                // order — drop-in friendly for DB indexes and binary
                // tree scans. Older event_ids passed in via the
                // ``event_id`` override (replay, deterministic test
                // fixtures) still take precedence verbatim, so the
                // change is transparent to callers who supply their
                // own ids.
                event_id.map_or_else(|| Uuid::now_v7().to_string(), str::to_string),
                level.to_ascii_lowercase(),
            )
        });

        // 1. Classify fields: public vs per-group.
        //
        // Multi-group routing: a field declared under N groups in yaml
        // (`groups[<g>].fields: [...]`) is encrypted into all N groups'
        // payloads. The `field_to_groups` table is precomputed at
        // `Runtime::init` (0.4.2a7 — was rebuilt every emit) and
        // sorted alphabetically per field at load time so envelope
        // encoding stays canonical across SDK implementations.
        let field_to_groups = &self.field_to_groups;
        let public_set = &self.public_set;
        let public_groups = &self.public_groups;
        let (public_out, per_group) = {
            let t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let mut public_out: Map<String, Value> = Map::new();
            let mut per_group: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
            // Inline routing logic. A field is destined for `public_out`
            // when ANY of these are true: (a) explicitly listed in
            // top-level `public_fields`, or (b) routed to a group whose
            // policy is `"public"`. Everything else goes through the
            // per-group encrypt path. Multi-group fan-out clones the
            // field into each target.
            for (k, v) in fields {
                if public_set.contains(&k) {
                    public_out.insert(k, v);
                    continue;
                }
                if let Some(routed) = field_to_groups.get(&k) {
                    if routed.len() == 1 {
                        // Single-group: most common case. Avoid the
                        // v.clone() that the multi-group path needs
                        // on the last iteration.
                        let gname = &routed[0];
                        if public_groups.contains(gname) {
                            public_out.insert(k, v);
                        } else {
                            per_group
                                .entry(gname.clone())
                                .or_default()
                                .insert(k, v);
                        }
                    } else {
                        for gname in routed {
                            if public_groups.contains(gname) {
                                public_out.insert(k.clone(), v.clone());
                            } else {
                                per_group
                                    .entry(gname.clone())
                                    .or_default()
                                    .insert(k.clone(), v.clone());
                            }
                        }
                    }
                } else {
                    // Field has no declared route. Try the legacy
                    // classifier (returns a single name today,
                    // "default" by stub). If that lands in a known
                    // group, use it; otherwise fall back to the
                    // "default" group when present. Last resort:
                    // raise.
                    let guess = classify(&self.cfg, &k);
                    let target = if self.cfg.groups.contains_key(guess) {
                        guess.to_string()
                    } else if self.cfg.groups.contains_key("default") {
                        "default".to_string()
                    } else {
                        return Err(Error::InvalidConfig(format!(
                            "field {k:?} has no group route and is not in \
                             public_fields. Add it to `groups[<g>].fields` in \
                             tn.yaml, list it under public_fields, or define a \
                             `default` group to absorb unknowns."
                        )));
                    };
                    if public_groups.contains(&target) {
                        public_out.insert(k, v);
                    } else {
                        per_group.entry(target).or_default().insert(k, v);
                    }
                }
            }
            if let Some(t0) = t0 {
                crate::perf::record_ns("emit:field_classify", t0.elapsed().as_nanos() as u64);
            }
            (public_out, per_group)
        };

        // row_hash gating (0.4.2a7): hoisted up here from below so the
        // per-group encrypt loop can skip building `group_inputs_for_hash`
        // when no consumer will read it. The structure only feeds into
        // `compute_row_hash`; when chain=F sign=F (pure-log mode), the
        // row_hash compute is skipped and the structure is dead. The
        // per-call sign override (`sign=true` passed explicitly) also
        // pulls it back in since the signature is over row_hash bytes.
        let chain_enabled_for_row_hash = self.cfg.ceremony.chain;
        let need_row_hash = chain_enabled_for_row_hash
            || self.cfg.ceremony.sign
            || sign.unwrap_or(false);

        // 2. Index tokens + 3. Encrypt per group.
        let mut group_inputs_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
        // group_payloads (0.4.2a7): pre-rendered JSON snippets rather
        // than serde_json::Value trees. envelope_build splices the
        // raw snippet in verbatim, skipping a `to_value` tree alloc
        // here AND a re-walk inside envelope_build.
        let mut group_payloads: BTreeMap<String, String> = BTreeMap::new();

        let _group_encrypt_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };

        for (gname, plain) in per_group {
            let Some(gstate_arc) = self.groups.get(&gname) else {
                // Field routed to a group we don't know; skip silently, matching
                // Python's fall-through to "default".
                continue;
            };
            let gstate = gstate_arc.read().expect("group state RwLock poisoned");

            // Sub-stage timing inside group_encrypt. emit:group_encrypt
            // (outer) is still the total; these four sum to it.
            let _sort_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else { None };
            let sorted: BTreeMap<String, Value> = plain.into_iter().collect();
            if let Some(t0) = _sort_t0 {
                crate::perf::record_ns(
                    "emit:group_encrypt.sort",
                    t0.elapsed().as_nanos() as u64,
                );
            }

            let _idx_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else { None };
            let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in &sorted {
                field_hashes.insert(
                    k.clone(),
                    index_token_with_template(&gstate.hmac_template, k, v)?,
                );
            }
            if let Some(t0) = _idx_t0 {
                crate::perf::record_ns(
                    "emit:group_encrypt.index_token",
                    t0.elapsed().as_nanos() as u64,
                );
            }

            let _canon_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else { None };
            let plaintext_bytes =
                canonical_bytes(&Value::Object(sorted.into_iter().collect()))?;
            if let Some(t0) = _canon_t0 {
                crate::perf::record_ns(
                    "emit:group_encrypt.canonical_bytes",
                    t0.elapsed().as_nanos() as u64,
                );
            }

            let _enc_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else { None };
            let ct = match gstate.cipher.encrypt(&plaintext_bytes) {
                Ok(ct) => ct,
                Err(Error::NotAPublisher { .. }) => continue,
                Err(e) => return Err(e),
            };
            if let Some(t0) = _enc_t0 {
                crate::perf::record_ns(
                    "emit:group_encrypt.cipher",
                    t0.elapsed().as_nanos() as u64,
                );
            }

            let _build_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else { None };
            // group_inputs_for_hash only feeds compute_row_hash; skip
            // the clones when no row_hash will be computed (chain=F
            // sign=F pure-log mode).
            if need_row_hash {
                group_inputs_for_hash.insert(
                    gname.clone(),
                    GroupInput {
                        ciphertext: ct.clone(),
                        field_hashes: field_hashes.clone(),
                    },
                );
            }
            // Render GroupPayload to a JSON snippet directly via
            // serde_json::to_string. Skips the prior `to_value`
            // intermediate that envelope_build then had to re-walk.
            let payload = GroupPayload {
                ciphertext: ct,
                field_hashes,
            };
            let payload_json = serde_json::to_string(&payload)?;
            group_payloads.insert(gname, payload_json);
            if let Some(t0) = _build_t0 {
                crate::perf::record_ns(
                    "emit:group_encrypt.payload_build",
                    t0.elapsed().as_nanos() as u64,
                );
            }
        }

        if let Some(t0) = _group_encrypt_t0 {
            crate::perf::record_ns("emit:group_encrypt", t0.elapsed().as_nanos() as u64);
        }

        // DX review 0.4.2a3: cross-process emit serialization.
        //
        // Steps 4–9 (chain advance through chain commit) MUST execute
        // atomically across processes. Otherwise, two workers writing
        // to the same log race on per-process ChainState: both compute
        // (seq, prev_hash) from a stale local view, both write rows
        // referencing the same parent, and the chain branches —
        // ``tn.read(verify=True)`` then rejects every branch except
        // the first.
        //
        // The fix bookends 4–9 with an advisory file lock on a
        // sentinel adjacent to the write target (main log OR pel for
        // protocol events). Under the lock we refresh ChainState from
        // disk truth for this event_type before advance, then proceed.
        // The lock is released as soon as the row is on disk + chain
        // committed; handler fan-out runs unlocked because the row is
        // already durable.
        //
        // The wasm code path inherits the trait's no-op lock impl
        // (single-threaded, single-process — no race to coordinate).
        let _path_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let is_protocol = event_type.starts_with("tn.");
        let pel_routed =
            is_protocol && self.cfg.ceremony.protocol_events_location != "main_log";
        // Derive the on-disk path from the writer pool's template so
        // the advisory-lock file always sits next to the file we're
        // actually appending to. Going through `pel_writer.path_for`
        // also keeps the `{event_class}` semantics consistent with
        // PathTemplate / Python (first dotted segment) — the prior
        // `self.resolve_pel(event_type)` used `nth(1)` and would
        // disagree with the writer pool when the PEL template
        // contains `{event_class}`.
        let target_path: PathBuf = if pel_routed {
            self.pel_writer.path_for(event_type)
        } else {
            self.log_writer.path_for(event_type)
        };
        let lock_path = {
            let mut s = target_path.as_os_str().to_os_string();
            s.push(".emit.lock");
            PathBuf::from(s)
        };
        // Parent-directory creation moved into `LogFileWriter::open`
        // (0.4.2a8 PEL pinned-writer fix). Each rendered path opens
        // its writer lazily on first emit; `LogFileWriter::open`
        // already calls `storage.create_dir_all(parent)` then.
        // Subsequent emits to the same rendered path reuse the pinned
        // handle and skip the parent-create syscall entirely.
        if let Some(t0) = _path_t0 {
            crate::perf::record_ns("emit:path_setup", t0.elapsed().as_nanos() as u64);
        }

        // Capture the row's outputs from inside the closure so the
        // outer scope can return them. The lock helper returns
        // io::Result<()>; non-io errors get parked here and re-raised
        // after the lock releases.
        let mut row_hash_out: Option<String> = None;
        let mut line_out: Option<String> = None;
        let mut deferred_err: Option<Error> = None;

        // Pre-clone the inputs the closure consumes by reference so
        // the borrow checker is happy with the FnMut signature.
        let public_out_for_lock = public_out;
        let group_inputs_for_lock = group_inputs_for_hash;
        let group_payloads_for_lock = group_payloads;

        // Chain gating (0.4.2a7): `ceremony.chain: false` skips the
        // cross-process advisory lock and the per-emit tail-scan.
        // Used by the `telemetry` and `secure_log` profiles where
        // per-row prev_hash linkage isn't part of the audit story
        // and the per-emit lock cost would dominate hot paths.
        //
        // 0.4.2a9: the unchained path still increments a per-
        // event_type `sequence` counter (no lock, in-memory only —
        // resets to 1 on restart). `prev_hash` stays empty as the
        // "no linkage claim" sentinel. Readers that check chain
        // integrity see `ceremony.chain == false` and skip the
        // per-row prev_hash compare; sequence remains useful for
        // ordering inside a single run.
        let chain_enabled = self.cfg.ceremony.chain;

        // `need_row_hash` was computed earlier (just before the
        // group-encrypt loop) so the loop could skip building
        // `group_inputs_for_hash` when no consumer will read it.
        // Reuse the same value here for the row_hash skip below.

        // Shared inline body for build + write — used twice below
        // (under-lock for chain_enabled, direct for !chain_enabled).
        // Kept as a macro to sidestep nested-FnMut borrow issues
        // (`with_advisory_lock` takes an `FnMut`, and another
        // captured closure inside it would double-borrow the
        // shared `&mut deferred_err` / `&mut row_hash_out` /
        // `&mut line_out` slots).
        macro_rules! build_and_write {
            ($seq:expr, $prev_hash:expr) => {{
                let seq: u64 = $seq;
                let prev_hash: &str = $prev_hash;

                // 5. Row hash — skipped when neither chain nor sign
                //    consumes it (chain=F sign=F pure-log mode).
                let _rh_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else { None };
                let row_hash = if need_row_hash {
                    let public_bmap: BTreeMap<String, Value> =
                        public_out_for_lock.clone().into_iter().collect();
                    compute_row_hash(&RowHashInput {
                        device_identity: self.device.did(),
                        timestamp: &ts,
                        event_id: &eid,
                        event_type,
                        level: &level_norm,
                        prev_hash,
                        public_fields: &public_bmap,
                        groups: &group_inputs_for_lock,
                    })
                } else {
                    // Pure-log mode (chain=F sign=F): no consumer.
                    // Envelope ships ``row_hash: ""`` as the
                    // documented unchained-and-unsigned sentinel,
                    // matching prev_hash="" and signature="".
                    String::new()
                };
                if let Some(t0) = _rh_t0 {
                    crate::perf::record_ns("emit:row_hash", t0.elapsed().as_nanos() as u64);
                }

                // 6. Sign: respects per-call override, then ceremony default.
                let _sign_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else { None };
                let should_sign = sign.unwrap_or(self.cfg.ceremony.sign);
                let sig_b64 = if should_sign {
                    let sig = self.device.sign(row_hash.as_bytes());
                    signature_b64(&sig)
                } else {
                    String::new()
                };
                if let Some(t0) = _sign_t0 {
                    crate::perf::record_ns("emit:sign", t0.elapsed().as_nanos() as u64);
                }

                // 7. Envelope serialize.
                let _env_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else { None };
                let line = match build_envelope(EnvelopeInput {
                    device_identity: self.device.did(),
                    timestamp: &ts,
                    event_id: &eid,
                    event_type,
                    level: &level_norm,
                    sequence: seq,
                    prev_hash,
                    row_hash: &row_hash,
                    signature_b64: &sig_b64,
                    public_fields: public_out_for_lock.clone(),
                    group_payloads: group_payloads_for_lock.clone(),
                }) {
                    Ok(line) => line,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other("build_envelope failed (deferred)"));
                    }
                };
                if let Some(t0) = _env_t0 {
                    crate::perf::record_ns("emit:envelope_build", t0.elapsed().as_nanos() as u64);
                }

                // 8. Append to log file (or the resolved pel for tn.* events).
                let _wr_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else { None };
                // Get-or-create the writer for this event_type's
                // rendered path. PEL admin emits route through
                // `pel_writer`; everything else through `log_writer`.
                // Both fields are pinned-writer pools so the syscall
                // floor matches whether we're writing to the main log
                // or a split admin log.
                let writers = if pel_routed {
                    &self.pel_writer
                } else {
                    &self.log_writer
                };
                let writer_arc = match writers.writer_for(event_type) {
                    Ok(a) => a,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other("writer_for failed (deferred)"));
                    }
                };
                let mut w = writer_arc.lock().expect("log writer mutex poisoned");
                if let Err(e) = w.append_line(&line) {
                    deferred_err = Some(e);
                    return Err(std::io::Error::other("append_line failed (deferred)"));
                }
                if let Err(e) = w.flush() {
                    deferred_err = Some(e);
                    return Err(std::io::Error::other("flush failed (deferred)"));
                }
                if let Some(t0) = _wr_t0 {
                    crate::perf::record_ns("emit:file_write", t0.elapsed().as_nanos() as u64);
                }

                (row_hash, line)
            }};
        }

        if chain_enabled {
            let storage_for_lock = Arc::clone(&self.storage);
            let _lock_t0 = if crate::perf::enabled() {
                Some(std::time::Instant::now())
            } else {
                None
            };
            storage_for_lock.with_advisory_lock(&lock_path, &mut || {
                if let Some(t0) = _lock_t0 {
                    crate::perf::record_ns(
                        "emit:lock_acquire",
                        t0.elapsed().as_nanos() as u64,
                    );
                }
                // Under the lock: refresh in-memory chain tip from
                // disk truth. If another process appended rows since
                // our last emit, this is where we discover the
                // latest (seq, prev_hash) for our event_type —
                // overwriting the local ChainState entry.
                //
                // Reverse-scan from the file tail (0.4.2a7 perf
                // fix): we only care about ONE event_type's tip,
                // not the full tips map; stopping at the first
                // matching row keeps the hot path O(scan-window)
                // instead of the prior O(filesize) forward scan.
                // See chain.rs::chain_tip_from_log_tail_reverse
                // and the S11 stress regression that surfaced the
                // issue.
                let _tip_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                // Tail-byte windowing (0.4.2a7 perf fix). The chain
                // tip is always near the end of the log — the row we
                // just emitted last time is right before whatever
                // someone else may have appended since. Reading the
                // whole file every emit (which the prior version
                // did) cost ~10 ms on a 1 MB log; reading 64 KB of
                // tail through a PINNED read handle costs ~50 µs.
                //
                // The pinned read handle (`log_writer.read_tail`) is
                // what makes this fast on Windows: opening a fresh
                // read handle while our own writer holds an append
                // handle to the same file costs ~9 ms on NTFS
                // (share-mode reconciliation / AV scan). The pinned
                // handle skips that cost — `seek + read` on an
                // already-open file is ~50 µs.
                //
                // For chain=T emits targeting a PEL admin path (rare:
                // only fires when admin events are chained AND the
                // PEL is not "main_log"), we fall back to
                // `storage.read_bytes_tail` which opens a fresh
                // handle. That path pays the ~9 ms once per
                // admin emit but admin emits are rare so the
                // amortized cost is negligible.
                //
                // Cold path (no match in window): the in-memory
                // chain state is already seeded from a whole-file
                // scan at `Runtime::init`, so missing the tip in the
                // tail just leaves the existing in-memory tip in
                // place. Documented as a known trade-off in
                // docs/superpowers/specs/2026-05-19-commit-envelopes-and-rotation.md.
                const TIP_REFRESH_TAIL_WINDOW: usize = 64 * 1024;
                // Pinned-read fast path with single-writer skip
                // (0.4.2a7). `read_tail_if_grown` returns None when
                // the file's current size matches what we wrote
                // ourselves — no other process appended,
                // in-memory chain tip is current, no read needed.
                // In multi-writer setups this falls through to a
                // full tail read.
                //
                // PEL admin emits use the same pinned-writer pool
                // (0.4.2a8 PEL pinned-writer fix), so the tip
                // refresh for `pel_routed=true` consults
                // `pel_writer` and gets the same machinery.
                //
                // The file-not-yet-created case (very first emit
                // before any append) yields NotFound from the lazy
                // reader open; treat as "no prior rows, leave
                // in-memory tip alone".
                let writers = if pel_routed {
                    &self.pel_writer
                } else {
                    &self.log_writer
                };
                let writer_arc = match writers.writer_for(event_type) {
                    Ok(a) => a,
                    Err(e) => {
                        deferred_err = Some(e);
                        return Err(std::io::Error::other(
                            "writer_for failed (deferred)",
                        ));
                    }
                };
                let bytes_opt: Option<Vec<u8>> = {
                    let w = writer_arc.lock().expect("log writer mutex poisoned");
                    match w.read_tail_if_grown(TIP_REFRESH_TAIL_WINDOW) {
                        Ok(opt) => opt,
                        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => return Err(e).map_err(|err| {
                            std::io::Error::other(format!("read_tail: {err}"))
                        }),
                    }
                };
                if let Some(bytes) = bytes_opt {
                    if let Some((tip_seq, tip_hash)) =
                        chain_tip_from_log_tail_reverse(&bytes, event_type)
                    {
                        let mut single: HashMap<String, (u64, String)> = HashMap::new();
                        single.insert(event_type.to_string(), (tip_seq, tip_hash));
                        self.chain.seed(single);
                    }
                }
                if let Some(t0) = _tip_t0 {
                    crate::perf::record_ns(
                        "emit:tip_refresh",
                        t0.elapsed().as_nanos() as u64,
                    );
                }

                // 4. Chain advance (now reflects disk truth).
                let _adv_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                let (seq, prev_hash) = self.chain.advance(event_type);
                if let Some(t0) = _adv_t0 {
                    crate::perf::record_ns(
                        "emit:chain_advance",
                        t0.elapsed().as_nanos() as u64,
                    );
                }

                let (row_hash, line) = build_and_write!(seq, &prev_hash);

                // 9. Commit row_hash into the chain.
                let _cm_t0 = if crate::perf::enabled() {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                self.chain.commit(event_type, &row_hash);
                if let Some(t0) = _cm_t0 {
                    crate::perf::record_ns(
                        "emit:chain_commit",
                        t0.elapsed().as_nanos() as u64,
                    );
                }

                row_hash_out = Some(row_hash);
                line_out = Some(line);
                Ok(())
            })?;
        } else {
            // Lockless emit for unchained profiles. No advisory
            // lock means no `.emit.lock` artifact on disk, no
            // tail-scan, no chain prev_hash linkage. The append-only
            // syscall is the only ordering primitive — interleaving
            // across processes is acceptable because there's no
            // chain to break.
            //
            // 0.4.2a9: even unchained profiles increment a per-
            // event_type sequence counter. `prev_hash` stays empty
            // (sentinel pattern; the verifier knows to skip the
            // linkage check when `ceremony.chain == false`), but
            // `sequence` grows monotonically within a single
            // process. Across restart the counter resets to 1 —
            // there's no seed scan for unchained profiles, by
            // design (would defeat the perf-first promise). Users
            // that need cross-restart sequence continuity should
            // pick `audit` or `transaction`.
            let (seq, _prev_unused) = self.chain.advance(event_type);
            let result: std::io::Result<()> = (|| {
                let (row_hash, line) = build_and_write!(seq, "");
                row_hash_out = Some(row_hash);
                line_out = Some(line);
                Ok(())
            })();
            result?;
        }

        if let Some(e) = deferred_err {
            return Err(e);
        }
        let row_hash =
            row_hash_out.expect("with_advisory_lock returned Ok but row_hash unset");
        let line =
            line_out.expect("with_advisory_lock returned Ok but line unset");

        // 10. Fan out to handlers. Mirrors Python `tn/logger.py:343` and
        //     TS `node_runtime.ts:376`. A handler whose filter rejects
        //     the envelope is skipped; a handler whose `emit` panics or
        //     errors is logged + swallowed so the publish call still
        //     succeeds for the caller.
        let _fan_t0 = if crate::perf::enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        self.fan_out_to_handlers(line.as_bytes(), event_type, &eid);
        if let Some(t0) = _fan_t0 {
            crate::perf::record_ns("emit:fan_out", t0.elapsed().as_nanos() as u64);
        }
        if let Some(t0) = _emit_total_start {
            crate::perf::record_ns("emit:_TOTAL", t0.elapsed().as_nanos() as u64);
        }

        // event_id, row_hash, and sequence are not surfaced through the
        // public emit*() facades (which discard the line and return
        // Result<()> for cross-language parity with Python None / TS void).
        // The on-disk envelope carries them. The `_returning_line` variant
        // hands the canonical NDJSON back so a host runtime (PyO3) can fan
        // out to its own handlers without re-deriving it.
        //
        // ``seq`` lives inside the cross-process lock closure after the
        // 0.4.2a3 emit-locking refactor; the envelope itself still
        // carries it on disk, so this sink only needs the two values
        // we have in this scope.
        let _ = (eid, row_hash);
        Ok(Some(line))
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
            .and_then(|o| o.get("device_identity"))
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
        fields.insert("envelope_device_identity".into(), Value::String(did));
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

        // Best-effort label sidecar. Routed through `self.storage` so
        // wasm consumers satisfy the write via their JS callback set;
        // failure is logged + swallowed either way.
        if let Some(lbl) = label {
            let mut sidecar_str = out.as_os_str().to_owned();
            sidecar_str.push(".label");
            let sidecar = PathBuf::from(sidecar_str);
            if let Err(e) = self.storage.write_bytes(&sidecar, lbl.as_bytes()) {
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
    // cognitive_complexity: the read+verify loop walks one envelope at
    // a time and decides per-envelope whether each integrity check
    // (signature, row_hash, chain) passes. Splitting "per-check"
    // helpers would force ValidFlags re-aggregation per row, which
    // breaks the audit-grade trace the reader produces in one pass.
    #[allow(clippy::cognitive_complexity)]
    pub fn read_from_with_validity(
        &self,
        log_path: &Path,
    ) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        if !self.storage.exists(log_path) {
            return Ok(Vec::new());
        }
        let mut out: Vec<(ReadEntry, ValidFlags)> = Vec::new();
        let mut prev_hash_by_event: HashMap<String, String> = HashMap::new();
        let public_set: HashSet<&str> = self.cfg.public_fields.iter().map(String::as_str).collect();
        let group_names: HashSet<&str> = self.cfg.groups.keys().map(String::as_str).collect();

        for res in LogFileReader::open(log_path, &self.storage)? {
            // DX review 0.4.2a3 follow-up: a single malformed row (bad
            // base64 ciphertext, JSON parse failure, etc.) must not
            // halt iteration. Skip the row and emit a sentinel triple
            // with the special event_type "<parse-error>" + all-false
            // validity flags; the reader's verify='skip' path
            // recognises this and counts it as ``skipped_parse``.
            let env = match res {
                Ok(e) => e,
                Err(e) => {
                    out.push((
                        ReadEntry {
                            envelope: serde_json::json!({
                                "event_type": "<parse-error>",
                                "_parse_error": e.to_string(),
                            }),
                            plaintext_per_group: BTreeMap::new(),
                        },
                        ValidFlags {
                            signature: false,
                            row_hash: false,
                            chain: false,
                        },
                    ));
                    continue;
                }
            };

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
            let sequence = env
                .get("sequence")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let did = env
                .get("device_identity")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let signature = env
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            // Chain-disabled ceremonies (telemetry / secure_log /
            // stdout — anything with `ceremony.chain: false`) emit
            // every row with `prev_hash=""` + `sequence=1` sentinels.
            // The writer never advances the chain; the on-disk shape
            // is "N independent attestations" rather than a linked
            // list. A byte-for-byte `prev_hash == prior.row_hash`
            // compare always fails from row 2 onward. Skip the
            // per-row chain check entirely for such ceremonies — the
            // chain claim isn't being made, so there's nothing to
            // verify against. We could check the sentinel pattern is
            // intact (`prev == ""` + `sequence == 1`) and fail
            // otherwise; for now treat chain=false as "chain is not
            // a load-bearing field," matching the writer's contract.
            //
            // sequence is read for parity with the writer's sentinel
            // contract and to make this branch self-documenting in
            // a future tightening.
            let _ = sequence;
            let last = prev_hash_by_event.get(&event_type).cloned();
            let chain_ok = if !self.cfg.ceremony.chain {
                true
            } else {
                match last {
                    None => true,
                    Some(l) => l == prev,
                }
            };
            // Track the row_hash forward only for chained ceremonies.
            // Chain-disabled rows have nothing to chain, and carrying
            // their row_hash forward would just confuse a future
            // tightening of this branch.
            if self.cfg.ceremony.chain {
                prev_hash_by_event.insert(event_type.clone(), row_hash.clone());
            }

            // Decrypt every group we hold a kit for.
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            let mut groups_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
            // DX review 0.4.2a3 follow-up: per-row resilience for the
            // base64-decode + post-decrypt JSON-parse paths. A row
            // whose ciphertext is corrupt or whose plaintext doesn't
            // parse becomes a sentinel rather than killing iteration.
            let mut row_parse_error: Option<String> = None;
            if let Value::Object(env_map) = &env {
                'group_loop: for (k, v) in env_map {
                    if let Some(g_obj) = v.as_object() {
                        if let Some(ct_str) = g_obj.get("ciphertext").and_then(Value::as_str) {
                            let ct = match STANDARD.decode(ct_str) {
                                Ok(b) => b,
                                Err(e) => {
                                    row_parse_error = Some(format!(
                                        "ciphertext base64 in group {k:?}: {e}"
                                    ));
                                    break 'group_loop;
                                }
                            };
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
                                        match serde_json::from_slice::<Value>(&pt) {
                                            Ok(pv) => {
                                                plaintext_per_group.insert(k.clone(), pv);
                                            }
                                            Err(e) => {
                                                // Bad plaintext bytes after decrypt;
                                                // treat as a per-row parse error rather
                                                // than aborting the iterator.
                                                row_parse_error = Some(format!(
                                                    "plaintext json in group {k:?}: {e}"
                                                ));
                                                break 'group_loop;
                                            }
                                        }
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

            // DX review 0.4.2a3 follow-up: if any per-row error fired
            // during the group/ciphertext loop above, surface a
            // sentinel triple and move on. Don't update
            // ``prev_hash_by_event`` — subsequent rows that chain
            // through this one will fail chain verify, which is the
            // correct semantics (the chain branched at this row, and
            // we can't tell which fork is real).
            if let Some(err) = row_parse_error {
                out.push((
                    ReadEntry {
                        envelope: serde_json::json!({
                            "event_type": "<parse-error>",
                            "_parse_error": err,
                        }),
                        plaintext_per_group: BTreeMap::new(),
                    },
                    ValidFlags {
                        signature: false,
                        row_hash: false,
                        chain: false,
                    },
                ));
                continue;
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

            // Row-hash sentinel: when the writer's ceremony has both
            // `chain: false` AND `sign: false` (telemetry, stdout),
            // `need_row_hash` was false at emit time and the
            // envelope's `row_hash` field is the documented empty
            // sentinel. Recomputing would produce a non-empty hash
            // and the byte compare would always fail. Accept the
            // sentinel as "row_hash is not a load-bearing field for
            // this ceremony shape" — same shape the writer
            // documents at emit time.
            let row_hash_ok = if !self.cfg.ceremony.chain
                && !self.cfg.ceremony.sign
                && row_hash.is_empty()
            {
                true
            } else {
                let expected = compute_row_hash(&RowHashInput {
                    device_identity: &did,
                    timestamp: &timestamp,
                    event_id: &event_id,
                    event_type: &event_type,
                    level: &level,
                    prev_hash: &prev,
                    public_fields: &public_out,
                    groups: &groups_for_hash,
                });
                expected == row_hash
            };

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
        if !self.storage.exists(log_path) {
            return Ok(Vec::new());
        }
        if is_foreign_log(
            log_path,
            &self.log_path,
            self.device.did(),
            &self.keystore,
            &self.storage,
        ) {
            return read_foreign_log(log_path, &self.keystore, &self.storage);
        }
        let mut out = Vec::new();
        for res in LogFileReader::open(log_path, &self.storage)? {
            // DX review 0.4.2a3 follow-up: per-row resilience. A bad
            // row (malformed JSON, corrupt base64 ciphertext, bad
            // post-decrypt plaintext) yields a sentinel envelope so
            // the caller's verify='skip' path can count it as
            // ``skipped_parse`` and continue. Without this, a single
            // disk-corrupt row killed the iterator and clean rows
            // after it never reached the caller.
            let env = match res {
                Ok(e) => e,
                Err(e) => {
                    out.push(ReadEntry {
                        envelope: serde_json::json!({
                            "event_type": "<parse-error>",
                            "_parse_error": e.to_string(),
                        }),
                        plaintext_per_group: BTreeMap::new(),
                    });
                    continue;
                }
            };
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            let mut row_parse_error: Option<String> = None;
            'group_loop: for (gname, gstate_arc) in &self.groups {
                let Some(group_v) = env.get(gname) else {
                    continue;
                };
                let Some(ct_b64) = group_v.get("ciphertext").and_then(|v| v.as_str()) else {
                    continue;
                };
                let ct = match STANDARD.decode(ct_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        row_parse_error = Some(format!(
                            "ciphertext base64 in group {gname:?}: {e}"
                        ));
                        break 'group_loop;
                    }
                };
                let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                match gstate.cipher.decrypt(&ct) {
                    Ok(pt) => match serde_json::from_slice::<Value>(&pt) {
                        Ok(v) => {
                            plaintext_per_group.insert(gname.clone(), v);
                        }
                        Err(e) => {
                            row_parse_error = Some(format!(
                                "plaintext json in group {gname:?}: {e}"
                            ));
                            break 'group_loop;
                        }
                    },
                    Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => {
                        // Skip groups we can't read.
                    }
                    Err(e) => return Err(e),
                }
            }
            if let Some(err) = row_parse_error {
                out.push(ReadEntry {
                    envelope: serde_json::json!({
                        "event_type": "<parse-error>",
                        "_parse_error": err,
                    }),
                    plaintext_per_group: BTreeMap::new(),
                });
                continue;
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
        // Hand the LogWriters dispatchers off — for literal paths
        // this flushes the single writer; for templated pools it
        // walks every cached per-rendered-path writer. `pel_writer`
        // is a shadow of `log_writer` when PEL=="main_log"; its
        // separate `flush_all` is a no-op there (Arc clones, no
        // distinct writers), and a real flush when PEL is split.
        self.log_writer.flush_all();
        self.pel_writer.flush_all();
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

        // Snapshot the pre-mutation state bytes as the CAS prior.
        // We READ THE FILE rather than re-serialising the in-memory
        // cipher because PublisherState::from_bytes(x).to_bytes() is
        // not guaranteed byte-stable: a load + re-serialise can
        // produce different bytes than the originals (set ordering,
        // internal layout). Comparing in-memory bytes against disk
        // would false-positive on every admin verb in single-process
        // mode. The Python BtnGroupCipher caches _last_persisted_bytes
        // for the same reason.
        //
        // The keystore now routes through `self.storage` so wasm
        // consumers can satisfy these reads + the CAS write below via
        // their `JsStorageAdapter`. Native `FsStorage` retains the
        // tmp+fsync+rename + flock dance under the hood.
        let keystore_backend = crate::keystore_backend::LocalKeystore::new(
            self.keystore.clone(),
            self.storage.clone(),
        );
        let prior_state_bytes = keystore_backend.read_state(group).map_err(Error::Io)?;

        // Mint the new reader kit. After this point the in-memory
        // cipher is ahead of disk; if the CAS write below fails the
        // caller MUST treat the in-memory state as stale and re-load
        // from disk before any further admin op (the runtime's
        // KeystoreConflict error is the signal).
        let kit = pub_cipher.state_mut().mint()?;
        let leaf_index = kit.leaf().0;
        let kit_bytes = kit.to_bytes();
        let state_bytes = pub_cipher.state_to_bytes();

        // Persist state first (fail before writing kit if state write
        // fails). Atomic + flock + CAS via LocalKeystore: torn-write
        // proof, multi-process serialised, lost-update detected.
        keystore_backend.write_state(group, prior_state_bytes.as_deref(), &state_bytes)?;

        // Kit file is per-recipient — no concurrent writer to race
        // against. Route through `self.storage.write_bytes` so wasm
        // consumers can satisfy the write via their JS callback set;
        // native `FsStorage::write_bytes` creates parents + writes the
        // file directly. (We previously used `atomic_write_bytes`
        // here for the crash-safety tmp+fsync+rename; on native that
        // guarantee was nice but not load-bearing — a torn `.mykit`
        // is recoverable by re-running the admin verb. The wasm path
        // can't realistically replay `fsync` semantics anyway, so
        // moving to `write_bytes` is the right unification.)
        self.storage
            .write_bytes(out_kit_path, &kit_bytes)
            .map_err(Error::Io)?;

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
        // recipient_identity is OptionalString; include null when not provided
        // so validate_emit can confirm the field is present.
        fields.insert(
            "recipient_identity".into(),
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

        // Pre-mutation snapshot for CAS — read the file rather than
        // re-serialise the in-memory cipher (see comment in
        // admin_add_recipient: PublisherState round-trip is not
        // byte-stable). On KeystoreConflict the in-memory state is
        // ahead of disk and must be discarded by the caller.
        //
        // Routes through `self.storage` for wasm parity (admin verbs
        // on wasm would otherwise short-circuit the storage abstraction
        // and hit a stubbed `std::fs::read`).
        let keystore_backend = crate::keystore_backend::LocalKeystore::new(
            self.keystore.clone(),
            self.storage.clone(),
        );
        let prior_state_bytes = keystore_backend.read_state(group).map_err(Error::Io)?;

        pub_cipher
            .state_mut()
            .revoke_by_leaf(tn_btn::LeafIndex(leaf_index))?;
        let state_bytes = pub_cipher.state_to_bytes();

        // Atomic + flock + CAS write.
        keystore_backend.write_state(group, prior_state_bytes.as_deref(), &state_bytes)?;

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
        // recipient_identity is OptionalString in the catalog schema; include
        // null so validate_emit can confirm the field is present.
        fields.insert("recipient_identity".into(), Value::Null);
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
                    recipient_identity,
                    kit_sha256,
                    ..
                } if g == group => {
                    active.insert(
                        leaf,
                        RecipientEntry {
                            leaf_index: leaf,
                            recipient_identity,
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
                        recipient_identity: None,
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
                    device_identity,
                    created_at,
                } => {
                    state.ceremony = Some(AdminCeremony {
                        ceremony_id,
                        cipher,
                        device_identity,
                        created_at: Some(created_at),
                    });
                }
                StateDelta::GroupAdded {
                    group: g,
                    cipher,
                    publisher_identity,
                    added_at,
                } => {
                    state.groups.push(AdminGroupRecord {
                        group: g,
                        cipher,
                        publisher_identity,
                        added_at,
                    });
                }
                StateDelta::RecipientAdded {
                    group: g,
                    leaf_index: Some(leaf),
                    recipient_identity,
                    kit_sha256,
                    ..
                } => {
                    by_leaf.insert(
                        (g.clone(), leaf),
                        AdminRecipientRecord {
                            group: g,
                            leaf_index: leaf,
                            recipient_identity,
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
                    recipient_identity,
                    issued_to,
                } => {
                    state.coupons.push(AdminCoupon {
                        group: g,
                        slot,
                        recipient_identity,
                        issued_to,
                        issued_at: ts.clone(),
                    });
                }
                StateDelta::EnrolmentCompiled {
                    group: g,
                    peer_identity,
                    package_sha256,
                    compiled_at,
                } => {
                    enrolments_by_peer.insert(
                        (g.clone(), peer_identity.clone()),
                        AdminEnrolment {
                            group: g,
                            peer_identity,
                            package_sha256,
                            status: "offered".to_string(),
                            compiled_at: Some(compiled_at),
                            absorbed_at: None,
                        },
                    );
                }
                StateDelta::EnrolmentAbsorbed {
                    group: g,
                    publisher_identity,
                    package_sha256,
                    absorbed_at,
                } => {
                    let key = (g.clone(), publisher_identity.clone());
                    if let Some(existing) = enrolments_by_peer.get_mut(&key) {
                        existing.status = "absorbed".to_string();
                        existing.absorbed_at = Some(absorbed_at);
                    } else {
                        enrolments_by_peer.insert(
                            key,
                            AdminEnrolment {
                                group: g,
                                peer_identity: publisher_identity,
                                package_sha256,
                                status: "absorbed".to_string(),
                                compiled_at: None,
                                absorbed_at: Some(absorbed_at),
                            },
                        );
                    }
                }
                StateDelta::VaultLinked {
                    vault_identity,
                    project_id,
                    linked_at,
                } => {
                    vault_links_by_did.insert(
                        vault_identity.clone(),
                        AdminVaultLink {
                            vault_identity,
                            project_id,
                            linked_at,
                            unlinked_at: None,
                        },
                    );
                }
                StateDelta::VaultUnlinked {
                    vault_identity,
                    unlinked_at,
                    ..
                } => {
                    if let Some(link) = vault_links_by_did.get_mut(&vault_identity) {
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
                device_identity: self.device.did().to_string(),
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
                if link.vault_identity == vault_did
                    && link.project_id == project_id
                    && link.unlinked_at.is_none()
                {
                    return Ok(());
                }
            }
        }

        let mut fields = Map::new();
        fields.insert("vault_identity".into(), Value::String(vault_did.to_string()));
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
        fields.insert("vault_identity".into(), Value::String(vault_did.to_string()));
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
        // First dotted segment. Matches `python/tn/config.py::
        // resolve_path_template` (which uses `event_type.split(".")[0]`)
        // and `path_template.rs` (`event_type.split('.').next()`).
        let event_class = event_type.split('.').next().unwrap_or("unknown");
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
        if is_absolute_xplat_path(&p) {
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
//
// cognitive_complexity: this is a deliberate flat dispatch over the
// six envelope shapes (public fields / groups / decrypt errors /
// reserved fields / …). Each branch is a few-line projection. The
// alternative — a per-shape helper — buys no clarity and forces an
// allocation per shape that's currently elided inline.
#[allow(clippy::cognitive_complexity)]
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
fn rotate_log_on_session_start(
    log_path: &Path,
    backup_count: usize,
    storage: &Arc<dyn crate::storage::Storage>,
) {
    // Treat "missing" and "empty" the same: nothing to rotate. The
    // pre-Storage version checked metadata.len() to distinguish, but
    // the Storage trait doesn't expose file size — and a read-then-
    // check-len round-trip would be no cheaper than the rotate
    // itself. So peek via `read_bytes` and treat zero-length as
    // "skip rotation" (same external observable behaviour).
    match storage.read_bytes(log_path) {
        Ok(bytes) if bytes.is_empty() => return,
        Ok(_) => {}
        Err(_) => return, // missing or unreadable — nothing to rotate
    }

    // Walk backwards: drop the oldest, then shift each `.N` → `.N+1`.
    let max_n = backup_count.max(1);
    let oldest = path_with_backup_suffix(log_path, max_n);
    let _ = storage.remove(&oldest); // ignore "not found"
    for n in (1..max_n).rev() {
        let from = path_with_backup_suffix(log_path, n);
        let to = path_with_backup_suffix(log_path, n + 1);
        if storage.exists(&from) {
            if let Err(e) = storage.rename(&from, &to) {
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
    if let Err(e) = storage.rename(log_path, &dot_one) {
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
    storage: &Arc<dyn crate::storage::Storage>,
) -> bool {
    // Exempt exactly our own log path — post-flush "reading my own log"
    // case where the auto-discovery cfg may have a different device but
    // the log is conceptually own. Narrowed per AVL J7.1 Bug 2.
    // `canonicalize` is filesystem-only (resolves symlinks) and has
    // no Storage equivalent; we keep it as a native shortcut. On wasm
    // it'll just fail (no symlinks) and we fall through to comparing
    // raw paths via the rest of the logic.
    if let (Ok(a), Ok(b)) = (log_path.canonicalize(), own_log.canonicalize()) {
        if a == b {
            return false;
        }
    }

    // No kit on disk → foreign route guaranteed to yield $no_read_key
    // for every entry. Regular path's "kit not entitled" is more
    // actionable, so let it run.
    if !storage.exists(&keystore.join("default.btn.mykit")) {
        return false;
    }

    // Peek the first parseable envelope's `did`.
    let Ok(bytes) = storage.read_bytes(log_path) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
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
        if let Some(env_did) = env.get("device_identity").and_then(Value::as_str) {
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
fn read_foreign_log(
    log_path: &Path,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<ReadEntry>> {
    use crate::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};

    // Discover every group the keystore has a kit for. The foreign
    // route is btn-only today (read_as_recipient errors out on JWE
    // keys) so we only scan `<group>.btn.mykit`.
    let mut groups: Vec<String> = Vec::new();
    if let Ok(entries) = storage.list(keystore) {
        for path in entries {
            let Some(s) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
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
    if is_absolute_xplat_path(p) {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Cross-platform absolute-path test. Mirrors
/// `config::is_absolute_xplat` but works on `&Path` so callers in the
/// runtime don't have to round-trip through a string. Required for
/// wasm32 hosts on Windows where `Path::is_absolute()` follows Unix
/// rules and would mis-classify `C:\…` as relative, causing
/// `extends:`-resolved paths to double-join.
fn is_absolute_xplat_path(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    let s = p.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() >= 3 {
        let drive = bytes[0];
        if drive.is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\') {
            return true;
        }
    }
    false
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
#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
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

/// Storage-aware variant of [`build_cipher_with_admin`] used by
/// [`Runtime::init_with_storage`]. Reads the publisher state file and
/// kit bytes through the supplied [`Storage`] handle so a wasm
/// `JsStorageAdapter` can satisfy the loads from its JS callbacks.
///
/// Today (Phase 7 landing) only the publisher-state load is routed
/// through storage; the kit-bytes collection still goes through
/// `std::fs::read_dir` because the directory-listing storage hook is
/// part of the trait but not yet wired here. The wasm path therefore
/// still hits a runtime error when groups need kit-bytes from disk;
/// see the remaining-work notes in the Phase 7 implementation report.
///
/// [`Storage`]: crate::storage::Storage
#[allow(dead_code)]
fn build_cipher_with_admin_with_storage(
    spec: &GroupSpec,
    keystore: &Path,
    group_name: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin_with_storage(keystore, group_name, storage),
        "jwe" | "bearer" => Err(Error::NotImplemented(
            "JWE groups run through the Python runtime in this plan; migrate to btn for Rust",
        )),
        "bgw" => Err(Error::NotImplemented(
            "BGW groups run through the Python runtime; FFI port deferred",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

/// Storage-aware btn cipher builder. Reads `<group>.btn.state` and
/// `<group>.btn.mykit` through `storage`; `*.btn.mykit.revoked.<ts>`
/// rotation siblings are still discovered via `std::fs::read_dir`
/// pending Phase 7 follow-up on the directory-listing call sites.
fn build_btn_cipher_with_admin_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<BuildCipherResult> {
    let state_path = keystore.join(format!("{group}.btn.state"));
    let state_exists = storage.exists(&state_path);
    let all_kits = collect_btn_kit_bytes_with_storage(keystore, group, storage)?;
    let has_any_kit = !all_kits.is_empty();

    match (state_exists, has_any_kit) {
        (true, _) => {
            let state_bytes = storage.read_bytes(&state_path).map_err(Error::Io)?;
            let pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            let admin_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
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
            Ok((cipher, None, current_mykit))
        }
        (false, false) => Err(Error::InvalidConfig(format!(
            "btn group {group}: no {group}.btn.state and no {group}.btn.mykit in keystore"
        ))),
    }
}

/// Storage-aware kit-bytes collection. Mirrors
/// [`collect_btn_kit_bytes`] but routes the current-kit read through
/// `storage`. Revoked-kit discovery still falls back to
/// `std::fs::read_dir` because directory listing through storage is
/// part of the trait but not yet wired into all of init's helpers
/// (Phase 7 follow-up).
fn collect_btn_kit_bytes_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if storage.exists(&current) {
        kits.push(storage.read_bytes(&current).map_err(Error::Io)?);
    }

    // Retired + revoked kit discovery: list directory through storage if
    // the backend supports it; absent / errored listing means "no
    // archived kits" rather than a hard failure. That keeps a wasm
    // `JsStorageAdapter` whose `list()` returns an empty array from
    // breaking init when no rotations have happened.
    //
    // 0.4.3a1 introduces `.btn.mykit.retired.<epoch>` as the canonical
    // post-rotation archive name (epoch-indexed). The legacy
    // `.btn.mykit.revoked.<unix_ts>` shape from 0.4.2-line keystores is
    // still loaded so pre-rename keystores keep reading. Sort each
    // family by its own index descending so newer kits are tried first.
    let retired_prefix = format!("{group}.btn.mykit.retired.");
    let revoked_prefix = format!("{group}.btn.mykit.revoked.");
    let mut retired: Vec<(std::path::PathBuf, u32)> = Vec::new();
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = storage.list(keystore) {
        for path in entries {
            let Some(name_str) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Some(n_str) = name_str.strip_prefix(&retired_prefix) {
                if let Ok(n) = n_str.parse::<u32>() {
                    retired.push((path, n));
                }
            } else if let Some(ts_str) = name_str.strip_prefix(&revoked_prefix) {
                let ts: u64 = ts_str.parse().unwrap_or(0);
                revoked.push((path, ts));
            }
        }
    }
    retired.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in retired {
        kits.push(storage.read_bytes(&path).map_err(Error::Io)?);
    }
    revoked.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in revoked {
        kits.push(storage.read_bytes(&path).map_err(Error::Io)?);
    }

    Ok(kits)
}

/// Scan `keystore` for files of the form `<group>.btn.state.retired.<N>`
/// (where N is a u32 — the epoch the state served as active). Returns
/// each as `(epoch, bytes)`. Files whose suffix doesn't parse as u32
/// are skipped silently. Used by the publisher-side init path to
/// archive retired states alongside the active one, so historical
/// keywalk decryption has the seed material available.
///
/// 0.4.3a1 only. Pre-rename keystores use `<group>.btn.state.revoked.<ts>`
/// which intentionally is NOT picked up here — those entries archived
/// the prior PublisherState (kind 0x03), not the new lightweight
/// RetiredPublisherState (kind 0x04), so attempting to deserialize them
/// as retired states would error.
pub(crate) fn discover_retired_btn_states(
    keystore: &Path,
    group: &str,
) -> std::io::Result<Vec<(u32, Vec<u8>)>> {
    let prefix = format!("{group}.btn.state.retired.");
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(keystore) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(rest) = name_str.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(epoch) = rest.parse::<u32>() else {
            continue;
        };
        let bytes = std::fs::read(entry.path())?;
        out.push((epoch, bytes));
    }
    Ok(out)
}

/// Collect all kit files for a group: the current `<group>.btn.mykit` first,
/// followed by any `<group>.btn.mykit.revoked.<ts>` siblings sorted by
/// timestamp descending (most recent first). Returned as a vec of byte
/// blobs in try-first order. Empty vec if no kit files exist.
///
/// Rotation preserves previous kits under `.revoked.<ts>` so pre-rotation
/// entries stay readable. `BtnReaderCipher` tries each kit in order and
/// the first successful decrypt wins.
#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
fn collect_btn_kit_bytes(keystore: &Path, group: &str) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if current.exists() {
        kits.push(std::fs::read(&current).map_err(Error::Io)?);
    }

    // Gather both archived-kit families:
    //   `<group>.btn.mykit.retired.<epoch>` (0.4.3a1+, epoch-indexed)
    //   `<group>.btn.mykit.revoked.<unix_ts>` (legacy 0.4.2-line)
    let retired_prefix = format!("{group}.btn.mykit.retired.");
    let revoked_prefix = format!("{group}.btn.mykit.revoked.");
    let mut retired: Vec<(std::path::PathBuf, u32)> = Vec::new();
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(keystore) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Some(n_str) = name_str.strip_prefix(&retired_prefix) {
                if let Ok(n) = n_str.parse::<u32>() {
                    retired.push((entry.path(), n));
                }
            } else if let Some(ts_str) = name_str.strip_prefix(&revoked_prefix) {
                // Expect ts_str to be a unix timestamp like "1776797973"; tolerate
                // non-numeric suffixes by falling back to 0 (gets sorted last).
                let ts: u64 = ts_str.parse().unwrap_or(0);
                revoked.push((entry.path(), ts));
            }
        }
    }
    // Newest first within each family — most likely era for any given older
    // entry to belong to.
    retired.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in retired {
        kits.push(std::fs::read(&path).map_err(Error::Io)?);
    }
    revoked.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in revoked {
        kits.push(std::fs::read(&path).map_err(Error::Io)?);
    }

    Ok(kits)
}

#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
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
fn seed_chain_from_log(
    log_path: &Path,
    chain: &ChainState,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    if !storage.exists(log_path) {
        return Ok(false);
    }
    let mut latest: HashMap<String, (u64, String)> = HashMap::new();
    let mut saw_ceremony_init = false;
    // 0.4.2a9: tolerate malformed lines during the chain-seed scan.
    // A process killed mid-emit leaves a partial JSON line at the
    // file tail; the prior version propagated that parse error and
    // crashed `tn.init` on every subsequent run, leaving the
    // operator with no graceful recovery. Mirror the per-row
    // resilience that `seed_chain_from_template` (and the runtime
    // read path) already have: skip the bad line, keep walking,
    // seed from whatever survived.
    for res in LogFileReader::open(log_path, storage)? {
        let env = match res {
            Ok(v) => v,
            Err(_) => continue, // skip malformed/truncated row, keep scanning
        };
        let et = match env.get("event_type").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if et == "tn.ceremony.init" {
            saw_ceremony_init = true;
        }
        let seq = match env.get("sequence").and_then(Value::as_u64) {
            Some(s) => s,
            None => continue,
        };
        let rh = match env.get("row_hash").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        latest.insert(et, (seq, rh));
    }
    chain.seed(latest);
    Ok(saw_ceremony_init)
}

/// Seed chain state from EVERY `.ndjson` file under the template's
/// parent directory. The templated counterpart of [`seed_chain_from_log`].
///
/// Templated `logs.path` (e.g. `./logs/{event_class}.ndjson`) renders
/// to N different files at emit time — one per event_class/event_type/
/// date combination. On restart the in-memory chain state has to be
/// seeded from ALL of them, otherwise the first emit after restart
/// resets `sequence=1 prev_hash=ZERO` for every event_type and
/// corrupts chain verification. Mirrors `python/tn/logger.py::
/// _seed_chain_from_logs` which scanned the log directory file-by-
/// file before chain=T templated ceremonies got Rust support
/// (0.4.2a7).
///
/// Resolves the parent directory from the template's static prefix
/// (everything before the first wildcard) and walks it
/// non-recursively. Templates that put per-emit tokens in
/// directory segments (e.g. `./logs/{date}/{event_class}.ndjson`)
/// still get the most-recent-day's parent directory scanned but
/// won't pick up older days; for that level of templating you'd
/// need a recursive walk, which we defer until someone actually
/// uses that shape.
///
/// Tolerant to malformed lines, missing fields, and unreadable
/// files — matches the Python helper's behaviour of "best-effort
/// seed, never block init."
fn seed_chain_from_template(
    template: &crate::path_template::PathTemplate,
    chain: &ChainState,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    // Resolve the parent directory we'll walk. Use `render` with a
    // placeholder event_type and take its parent — that gives us the
    // absolute path with yaml_dir already resolved.
    let sample = template.render("__seed_probe__");
    let Some(parent_dir) = sample.parent() else {
        return Ok(false);
    };
    if !storage.exists(parent_dir) {
        return Ok(false);
    }
    let entries = match storage.list(parent_dir) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let mut latest: HashMap<String, (u64, String)> = HashMap::new();
    let mut saw_ceremony_init = false;
    for entry in entries {
        if entry.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue;
        }
        // Best-effort per file: a malformed file shouldn't block
        // seeding from other files. The Python equivalent's
        // try/except OSError around the file open is mirrored here.
        let reader = match LogFileReader::open(&entry, storage) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for res in reader {
            let env = match res {
                Ok(v) => v,
                Err(_) => continue, // skip malformed rows
            };
            let et = match env.get("event_type").and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if et == "tn.ceremony.init" {
                saw_ceremony_init = true;
            }
            let seq = match env.get("sequence").and_then(Value::as_u64) {
                Some(s) => s,
                None => continue,
            };
            let rh = match env.get("row_hash").and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Max-sequence-wins per event_type across all scanned
            // files. The same event_type can appear in multiple
            // rendered files only when the template doesn't isolate
            // by event_type (e.g. `{date}.ndjson` mixes types per
            // day). Per-event_type chain tip is the highest
            // sequence we observe anywhere.
            let prior_seq = latest.get(&et).map(|(s, _)| *s).unwrap_or(0);
            if seq > prior_seq {
                latest.insert(et, (seq, rh));
            }
        }
    }
    chain.seed(latest);
    Ok(saw_ceremony_init)
}

/// Scan a single ndjson file for any line whose `event_type` is `tn.ceremony.init`.
/// Returns `true` if found, `false` if file absent or not found.
fn scan_for_ceremony_init(
    path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    if !storage.exists(path) {
        return Ok(false);
    }
    for res in LogFileReader::open(path, storage)? {
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
    // `{event_class}` is the first dotted segment of `tn.ceremony.init`
    // = `tn` (matches Python/PathTemplate, not the prior `nth(1)`
    // shorthand which would yield `ceremony`). The init-time fresh-
    // detection scan and the emit-time write must agree on the
    // rendered path, otherwise restart re-emits `tn.ceremony.init`.
    let filled = tmpl
        .replace("{event_type}", "tn.ceremony.init")
        .replace("{event_class}", "tn")
        .replace("{date}", &date)
        .replace("{yaml_dir}", &yaml_dir_s)
        .replace("{ceremony_id}", ceremony_id)
        .replace("{did}", did);
    // Anchor relative templates at the yaml dir — same fix as
    // ``Runtime::resolve_pel``. Without it, fresh-detection scans the
    // wrong file (process cwd) and we end up emitting tn.ceremony.init
    // twice on a re-init.
    let p = PathBuf::from(filled);
    if is_absolute_xplat_path(&p) {
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
    use crate::keystore_backend::atomic_write_bytes;
    use rand_core::{OsRng, RngCore};

    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore)?;

    // Every write below uses atomic_write_bytes (tmp + fsync +
    // rename) so a crash mid-mint never leaves a half-formed
    // keystore on disk — partial state files would fail to parse on
    // next load and burn the ceremony silently. No CAS here because
    // this is fresh-ceremony init: by construction nobody else is
    // writing to this keystore yet.

    // Device key — 32-byte Ed25519 seed.
    let dk = crate::DeviceKey::generate();
    atomic_write_bytes(&keystore.join("local.private"), &dk.private_bytes())?;

    // Master index key — 32 random bytes from the OS.
    let mut master = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    atomic_write_bytes(&keystore.join("index_master.key"), &master)?;

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
    atomic_write_bytes(&keystore.join("default.btn.state"), &pub_state.to_bytes())?;
    atomic_write_bytes(&keystore.join("default.btn.mykit"), &kit.to_bytes())?;

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
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.state"),
        &agents_state.to_bytes(),
    )?;
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.mykit"),
        &agents_kit.to_bytes(),
    )?;

    let did = dk.did().to_string();
    let id = format!("cer_eph_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let yaml = format!(
        "ceremony: {{id: {id}, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    crate::keystore_backend::atomic_write_bytes(&root.join("tn.yaml"), yaml.as_bytes())?;
    Ok(())
}
