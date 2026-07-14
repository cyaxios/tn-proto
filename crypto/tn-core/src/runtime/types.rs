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

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
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
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValidFlags {
    /// Signature verifies against the envelope's `did`.
    pub signature: bool,
    /// Row_hash recomputes from canonical inputs.
    pub row_hash: bool,
    /// Per-event_type chain `prev_hash` lines up with the previous row.
    pub chain: bool,
    /// True only when a present signature verifies for the writer DID.
    pub writer_authenticated: bool,
    /// True only when the authenticated writer is trusted and integrity holds.
    pub writer_authorized: bool,
    /// Stable, ordered, de-duplicated rejection metadata.
    pub reasons: Vec<ReadRejectReason>,
}

/// Public verification mode before receiver-local context is resolved.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode {
    /// Secure default. Resolves to [`VerifyMode::Raise`].
    Auto,
    /// Stop on the first rejected record.
    Raise,
    /// Continue scanning and omit rejected records.
    Skip,
    /// Ignore integrity, authentication, and writer-authorization gates only.
    Disabled,
}

/// Receiver-side policy inputs, snapshotted for one read.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadTrustPolicy {
    /// Verification action, with `Auto` resolved once at scan start.
    pub verify: VerifyMode,
    /// Explicit signature requirement, or `None` for context inference.
    pub require_signature: Option<bool>,
    /// Explicit absent-signature allowance, or `None` for the complement.
    pub allow_unauthenticated: Option<bool>,
    /// Immutable exact-DID writer allowlist for this read.
    pub trusted_writers: BTreeSet<String>,
    /// Whether the caller explicitly supplied the writer allowlist.
    pub trusted_writers_supplied: bool,
    /// Permit unknown writers without claiming writer authorization.
    pub allow_unknown_writers: bool,
}

/// Immutable receiver/source facts used to resolve a read policy.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadContext {
    /// Whether this context belongs to a live bound runtime.
    pub active: bool,
    /// Whether the selected source is the runtime's own attached log.
    pub local_log: bool,
    /// Whether the source is detached bytes rather than an attached log.
    pub detached: bool,
    /// Whether skip-mode audit callbacks may write through this runtime.
    pub writable: bool,
    /// Bound profile signature setting, when known.
    pub profile_sign: Option<bool>,
    /// Bound profile chain setting, when known.
    pub profile_chain: Option<bool>,
    /// Bound runtime device DID, when one exists.
    pub local_device_did: Option<String>,
    /// Group the caller explicitly requires recipient access to.
    pub required_group: Option<String>,
}

/// Stable wire reasons emitted by every read adapter.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReadRejectReason {
    /// The record cannot be parsed or fails its required shape.
    RecordInvalid,
    /// A required row hash is absent or does not recompute.
    RowHashInvalid,
    /// Per-event chain continuity failed.
    ChainInvalid,
    /// A required signature is absent.
    SignatureRequired,
    /// A present signature does not verify.
    SignatureInvalid,
    /// The exact writer DID is outside the frozen allowlist.
    WriterUntrusted,
    /// Authenticated decryption/AAD validation failed.
    AadInvalid,
    /// The explicitly required group is unavailable to this recipient.
    NotARecipient,
}

impl ReadRejectReason {
    /// Frozen snake-case wire value used in errors and callbacks.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordInvalid => "record_invalid",
            Self::RowHashInvalid => "row_hash_invalid",
            Self::ChainInvalid => "chain_invalid",
            Self::SignatureRequired => "signature_required",
            Self::SignatureInvalid => "signature_invalid",
            Self::WriterUntrusted => "writer_untrusted",
            Self::AadInvalid => "aad_invalid",
            Self::NotARecipient => "not_a_recipient",
        }
    }
}

/// Already-scanned facts for the pure policy evaluator.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadRecordState {
    /// Whether parsing and required envelope shape validation succeeded.
    pub record_valid: bool,
    /// Whether the envelope carries a non-empty row hash.
    pub row_hash_present: bool,
    /// Whether the row hash recomputes from canonical inputs.
    pub row_hash_valid: bool,
    /// Whether this row continues its per-event chain.
    pub chain_valid: bool,
    /// Whether the envelope carries a non-empty signature.
    pub signature_present: bool,
    /// Whether the present signature verifies for `writer_did`.
    pub signature_valid: bool,
    /// Exact writer DID extracted from the envelope.
    pub writer_did: Option<String>,
    /// Whether authenticated decryption accepted the bound AAD.
    pub aad_valid: bool,
    /// Groups for which recipient access succeeded.
    pub recipient_groups: BTreeSet<String>,
}

/// Result of applying one resolved policy to one scanned record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadDecision {
    /// Whether the record passes transport and policy gates.
    pub accepted: bool,
    /// Stable ordered and de-duplicated reason codes.
    pub reasons: Vec<ReadRejectReason>,
    /// Whether a present writer signature verified.
    pub writer_authenticated: bool,
    /// Whether the authenticated writer is trusted with intact integrity.
    pub writer_authorized: bool,
}

impl ReadDecision {
    /// Stable first reason used by raise and callback adapters.
    #[must_use]
    pub fn first_reason(&self) -> Option<ReadRejectReason> {
        self.reasons.first().copied()
    }
}

/// Cursor coordinate representation for one canonical source.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    /// Decimal byte position in a file-like source.
    ByteOffset,
    /// Decimal sequence position in an ordered handler source.
    Sequence,
    /// Source-defined token preserved without interpretation.
    Opaque,
}

/// Version-one cursor coordinate for one source.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceCursorV1 {
    /// Coordinate interpretation.
    pub kind: CursorKind,
    /// Lossless string coordinate; never coerced through a floating number.
    pub value: String,
}

/// Versioned, canonical multi-source cursor.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadCursorV1 {
    /// Cursor schema version. Version one is currently supported.
    pub version: u8,
    /// Canonical source ID to source-specific cursor, sorted by ID.
    pub sources: BTreeMap<String, SourceCursorV1>,
}

impl Default for ReadCursorV1 {
    fn default() -> Self {
        Self {
            version: 1,
            sources: BTreeMap::new(),
        }
    }
}

/// Materialized page plus scan accounting and the next lossless cursor.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReadReport<T> {
    /// Accepted entries in source order.
    pub entries: Vec<T>,
    /// Non-empty records examined after the supplied cursor.
    pub scanned: usize,
    /// Accepted records returned in `entries`.
    pub yielded: usize,
    /// Rejected records omitted from `entries`.
    pub skipped: usize,
    /// Next versioned cursor, preserving unrelated source coordinates.
    pub cursor: ReadCursorV1,
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
