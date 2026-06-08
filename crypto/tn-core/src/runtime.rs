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

mod emit;
mod admin;
mod init;
mod read;
mod cipher_build;
pub(crate) use cipher_build::*;
mod chain_seed;
pub(crate) use chain_seed::*;
mod log_session;
pub(crate) use log_session::*;
mod entry_shape;
pub use entry_shape::flatten_raw_entry;
pub(crate) use entry_shape::*;
mod helpers;
pub(crate) use helpers::*;

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
    /// Pre-initialized HMAC-SHA256 keyed by the group's derived index
    /// key. Each
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

