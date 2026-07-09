//! [`Runtime`] is the crate's primary interface: the front door behind
//! the `tn.*` SDK verbs and the `tn` CLI.
//!
//! A `Runtime` is a stateful composition of one ceremony's config,
//! device identity, per-group ciphers, the per-event_type hash chain,
//! and an open append-only log writer. You load one with
//! [`Runtime::init`] (or [`Runtime::ephemeral`] for a throwaway one),
//! then call the write / read / admin verbs on it.
//!
//! User-verb mapping — the public methods here back the `tn.*` SDK
//! verbs (and, through the SDK, the `tn` CLI):
//!
//! | This crate | `tn.*` SDK verb |
//! |---|---|
//! | [`Runtime::init`] | `tn.init()` |
//! | [`Runtime::log`] / [`Runtime::info`] / [`Runtime::warning`] / [`Runtime::error`] / [`Runtime::debug`] | `tn.log()` / `tn.info()` / `tn.warning()` / `tn.error()` / `tn.debug()` |
//! | [`Runtime::read`] | `tn.read()` |
//! | [`Runtime::secure_read`] | `tn.secure_read()` |
//! | [`Runtime::recipients`] | `tn.recipients()` |
//! | [`Runtime::admin_state`] | `tn.admin_state()` |
//! | [`Runtime::admin_add_recipient`] | `tn.admin_add_recipient()` |
//! | [`Runtime::admin_revoke_recipient`] | `tn.admin_revoke_recipient()` |
//! | [`Runtime::bundle_for_recipient`] | `tn.bundle_for_recipient()` |
//! | [`Runtime::vault_link`] / [`Runtime::vault_unlink`] | `tn.vault_link()` / `tn.vault_unlink()` |
//!
//! The export / absorb verbs (`tn.export()` / `tn.absorb()`) hang off
//! this same `Runtime` but are implemented in the sibling
//! `runtime_export` module (`Runtime::export` / `Runtime::absorb`). Key
//! rotation builds on the admin recipient machinery here.
//!
//! Every fallible verb returns [`crate::Result`], surfacing the shared
//! [`crate::Error`] taxonomy across the language boundary.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex, RwLock};

use crate::agents_policy::PolicyDocument;
use crate::chain::ChainState;
use crate::cipher::{btn::BtnPublisherCipher, GroupCipher};
use crate::config::Config;
use crate::signing::DeviceKey;

mod admin;
mod cipher_build;
mod emit;
mod init;
mod log_rotation;
mod read;
mod seal;
mod types;
mod util;

pub use admin::EnsureGroupResult;
pub use seal::{unseal_as_recipient, SealOptions, SealedGroupInfo, UnsealOptions, UnsealOutcome};
pub use types::{
    AdminCeremony, AdminCoupon, AdminEnrolment, AdminGroupRecord, AdminRecipientRecord,
    AdminRotation, AdminState, AdminVaultLink, FlatEntry, Instructions, OnInvalid, ReadEntry,
    RecipientEntry, RuntimeInitOptions, SecureEntry, SecureReadOptions, ValidFlags,
};

pub use read::flatten_raw_entry;

/// Internal: per-group cipher and derived index-token HMAC state held
/// inside [`Runtime`]; backs every group on the write / read paths
/// (surfaced as `tn.info()` / `tn.read()`).
pub(crate) struct GroupState {
    pub(crate) cipher: Arc<dyn GroupCipher>,
    /// Pre-initialized HMAC-SHA256 keyed by the group's derived index key.
    /// Each per-emit `index_token` call clones this template and feeds the
    /// field bytes into the clone, skipping the `Mac::new_from_slice` init
    /// cost every emit. Built once at runtime construction, never mutated.
    pub(crate) hmac_template: hmac::Hmac<sha2::Sha256>,
    /// Default AAD marker for this group (from `groups.<name>.aad`),
    /// overlaid by any per-emit marker and bound into the body AEAD. Empty
    /// means the group binds no marker (byte-identical to a no-AAD group).
    pub(crate) aad_default: serde_json::Map<String, serde_json::Value>,
}

/// The crate's primary interface: one stateful runtime per ceremony.
///
/// A `Runtime` ties together a ceremony's loaded config, device
/// identity, per-group ciphers, the per-event_type hash chain, and an
/// open append-only log writer. It is the object the `tn.*` SDK verbs
/// and the `tn` CLI drive — see the module docs for the full
/// verb-to-method mapping.
///
/// Lifecycle: load with [`Runtime::init`] (or [`Runtime::ephemeral`]),
/// write attested events with [`Runtime::info`] / [`Runtime::log`] /
/// [`Runtime::warning`] / … , read them back with [`Runtime::read`] /
/// [`Runtime::secure_read`], manage recipients with the `admin_*` verbs,
/// then optionally [`Runtime::close`] for an explicit flush (dropping
/// also flushes via the file handles' own `Drop`).
///
/// A `Runtime` is `Send + Sync`; the write path serializes writers across
/// threads and processes via an advisory file lock so concurrent
/// publishers to the same log don't branch the chain.
///
/// The manual `Debug` impl prints only `yaml_path`, `did`, and
/// `log_path` — the other fields hold crypto material and OS file
/// handles that do not implement `Debug`.
///
/// # Examples
///
/// ```no_run
/// use tn_core::Runtime;
/// use std::path::Path;
///
/// # fn main() -> tn_core::Result<()> {
/// let rt = Runtime::init(Path::new("tn.yaml"))?;
///
/// // Write an attested event (backs `tn.info()`).
/// let mut fields = serde_json::Map::new();
/// fields.insert("amount".into(), serde_json::json!(42));
/// rt.info("order.placed", fields)?;
///
/// // Read it back as a flat dict (backs `tn.read()`).
/// for entry in rt.read()? {
///     println!("{}", entry["event_type"]);
/// }
///
/// rt.close()?;
/// # Ok(())
/// # }
/// ```
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
    /// Used by the emit-side policy splice and the
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
    /// filters don't pick up entries from prior runs.
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
