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
            // The reserved set MUST exclude the same scalars the writer
            // treats as scalars. The wire key for the publisher identity
            // is `device_identity` (0.4.3a1 phase G flipped it from the
            // legacy `did`); leaving the stale `did` here let the
            // `device_identity` scalar leak into `public_out` for a
            // ceremony whose yaml lists it under public_fields, double-
            // hashing it relative to the corrected writer. Mirrors
            // `python/tn/reader.py::_envelope_reserved` and
            // `ts-sdk/.../node_runtime.ts::_ENVELOPE_RESERVED`.
            let envelope_reserved: HashSet<&'static str> = [
                "device_identity",
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
    if event_type == "tn.recipient.revoked" && !merged.contains_key("recipient_identity") {
        merged.insert("recipient_identity".into(), Value::Null);
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
            "BGW groups run through the Python runtime; FFI not wired in tn-core",
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
            "BGW groups run through the Python runtime; FFI not wired in tn-core",
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
    let sample = template.render("__seed_probe__", "__seed_probe__");
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
