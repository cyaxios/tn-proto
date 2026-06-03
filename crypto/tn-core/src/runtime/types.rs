//! Public data types returned by [`Runtime`](super::Runtime)'s read /
//! admin verbs.
//!
//! These are the owned, (de)serializable record shapes the SDK surfaces
//! across the language boundary — the read shapes ([`ReadEntry`],
//! [`FlatEntry`], [`SecureEntry`], [`ValidFlags`], [`Instructions`]),
//! the option structs ([`SecureReadOptions`], [`RuntimeInitOptions`],
//! [`OnInvalid`]), and the admin-state records ([`AdminState`] and its
//! row types). The `Runtime` methods that build them live in the sibling
//! submodules.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value};

// Imported for the `[`Runtime::…`]` intra-doc links throughout this
// module's docstrings; the type itself is referenced only from docs.
#[allow(unused_imports)]
use super::Runtime;

/// One decoded log entry in the audit-grade shape returned by
/// [`Runtime::read_raw`].
///
/// This is the lossless view: the verbatim on-the-wire envelope plus a
/// side map of the plaintext for each group this runtime could decrypt.
/// The default [`Runtime::read`] flattens this into a [`FlatEntry`];
/// reach for `ReadEntry` when you need the envelope's crypto plumbing
/// (`prev_hash` / `row_hash` / `signature` / ciphertext blocks) intact
/// for auditing.
///
/// Groups present in the envelope but not in `plaintext_per_group` are
/// ones this runtime holds no kit for. Sentinel plaintext values
/// `{"$no_read_key": true}` (group present, no kit) and
/// `{"$decrypt_error": true}` (decrypt threw) only appear when the entry
/// is produced through [`Runtime::read_raw_with_validity`].
pub struct ReadEntry {
    /// The verbatim envelope as parsed off the log line, including the
    /// reserved scalars, public fields, and one `{ciphertext,
    /// field_hashes}` block per group.
    pub envelope: Value,
    /// Decrypted plaintext keyed by group name — only the groups this
    /// runtime holds a kit for. May also carry the sentinel values
    /// `{"$no_read_key": true}` / `{"$decrypt_error": true}` (see the
    /// type-level note) when produced through
    /// [`Runtime::read_raw_with_validity`].
    pub plaintext_per_group: BTreeMap<String, Value>,
}

/// Flat-shape entry returned from [`Runtime::read`] /
/// [`Runtime::read_with_verify`] — the everyday read shape.
///
/// A plain JSON object (`serde_json::Map`) where the six envelope basics
/// (`timestamp`, `event_type`, `level`, `did`, `sequence`, `event_id`)
/// and the decrypted fields from every readable group are merged at the
/// top level, so a caller can index a field by name without walking the
/// envelope's group structure. Crypto plumbing (`prev_hash`, `row_hash`,
/// `signature`, ciphertext blocks) is dropped. `_hidden_groups` /
/// `_decrypt_errors` marker keys appear only when non-empty;
/// [`Runtime::read_with_verify`] adds a `_valid` block. Per the
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
///
/// `Default` gives the fail-closed everyday behavior: verify every
/// entry, silently skip the ones that don't verify (recording a
/// `tn.read.tampered_row_skipped` admin event per drop), and read this
/// runtime's own log.
#[derive(Debug, Clone, Default)]
pub struct SecureReadOptions {
    /// What to do on a non-verifying entry — see [`OnInvalid`]. Default
    /// [`OnInvalid::Skip`].
    pub on_invalid: OnInvalid,
    /// Read this log path instead of the runtime's own log. `None` (the
    /// default) reads [`Runtime::log_path`]. Use to verify a foreign
    /// publisher's exported log.
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

/// Aggregate admin state derived by replaying the attested log through
/// the admin reducer. Mirrors Python `tn.admin_state(group=…)`.
///
/// Produced by [`Runtime::admin_state`]. This is the materialized view
/// of every governance event in the log — who the publisher is, which
/// groups exist, the recipient lifecycle, rotations, coupons, peer
/// enrolments, and vault links — with no sidecar state file required:
/// the log is the source of truth. Every field is a plain owned record
/// (de/serializable) so callers can render it directly.
///
/// # Examples
///
/// ```no_run
/// use tn_core::Runtime;
/// use std::path::Path;
///
/// # fn main() -> tn_core::Result<()> {
/// let rt = Runtime::init(Path::new("tn.yaml"))?;
/// let state = rt.admin_state(Some("default"))?; // scope to one group
/// for r in &state.recipients {
///     println!("leaf {} is {}", r.leaf_index, r.active_status);
/// }
/// # Ok(())
/// # }
/// ```
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
