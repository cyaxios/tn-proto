//! Universal `.tnpkg` wrapper — signed manifest + kind-specific body.
//!
//! Per `docs/superpowers/plans/2026-04-24-tn-admin-log-architecture.md`
//! Section 2: every `.tnpkg` is a zip archive with this structure:
//!
//! ```text
//! foo.tnpkg/
//!   manifest.json   (signed JSON; the index)
//!   body/...        (kind-specific contents)
//! ```
//!
//! This module owns the wire format invariants (manifest schema, signing
//! domain, zip layout). It mirrors `tn/tnpkg.py` byte-for-byte for the
//! manifest's canonical signing bytes — the receiver verifies the signature
//! against `publisher_identity`'s Ed25519 public key over the RFC 8785-style canonical
//! bytes of the manifest minus the signature field.
//!
//! The pieces are split across focused submodules — vector-clock helpers
//! (`clock`), manifest signing / verification (`sign`), and the zip
//! writer / reader (`zip_write` / `zip_read`) — while the manifest types
//! ([`Manifest`], [`ManifestKind`]) and their impls live here. Every public
//! item is re-exported at the `tnpkg::` path, so the wire format surface is
//! flat regardless of which submodule defines a given function.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::canonical::canonical_bytes;
use crate::{Error, Result};

mod clock;
mod sign;
mod zip_read;
mod zip_write;

use clock::{clock_to_json, json_to_clock};

pub use clock::{clock_dominates, clock_merge};
pub use sign::{sign_manifest, verify_manifest};
pub use zip_read::{
    read_tnpkg, MAX_MANIFEST_BYTES, MAX_PKG_COMPRESSION_RATIO, MAX_PKG_ENTRY_BYTES,
    MAX_PKG_ENTRY_COUNT, MAX_PKG_TOTAL_BYTES,
};
pub use zip_write::{write_tnpkg, write_tnpkg_bytes};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Manifest schema version. Bump when required fields change in a
/// backwards-incompatible way.
pub const MANIFEST_VERSION: u32 = 1;

/// Vector clock keyed by `did -> {event_type -> max sequence}`.
///
/// Summarizes how far a package's log has advanced: for each producing device
/// and each event type, the highest sequence number seen. Absorb compares the
/// incoming manifest's clock against the receiver's local clock to decide
/// whether the package carries anything new (see [`clock_dominates`]) and merges
/// the two on accept (see [`clock_merge`]).
///
/// `BTreeMap` (not `HashMap`) for deterministic JSON serialization (sorted
/// keys), matching Python's `dict` + canonical-bytes serialization exactly —
/// the clock rides inside the signed manifest, so its byte layout must be
/// stable across implementations.
pub type VectorClock = BTreeMap<String, BTreeMap<String, u64>>;

/// Dispatch discriminator for a `.tnpkg` — what the package *is*, and thus how
/// [`crate::Runtime::absorb`] routes it.
///
/// Serializes snake-case to match Python's `KNOWN_KINDS` set exactly (the kind
/// is a manifest field, so the wire spelling is load-bearing). Use
/// [`as_str`](Self::as_str) for the wire string and [`from_wire`](Self::from_wire)
/// to parse one back. Several kinds are recognized for round-tripping but not yet
/// applied by the Rust runtime — see the per-variant notes and
/// [`crate::Runtime::absorb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    /// Materialized admin-log snapshot (`body/admin.ndjson` + reduced state).
    /// The convergent kind: absorb dedupes envelopes by `row_hash` and advances
    /// local admin state. Produced by `tn export --kind admin_log_snapshot`.
    AdminLogSnapshot,
    /// Enrolment *offer* package (a `body/package.json` payload). Round-trips
    /// through Rust; the offer/enrolment handlers live on the Python side, so
    /// Rust absorb stashes it for the caller to route.
    Offer,
    /// Enrolment package (counterpart to [`Offer`](Self::Offer)). Stashed by
    /// Rust absorb; applied on the Python side today.
    Enrolment,
    /// Point-to-point recipient invite. Reserved in the kind catalog; export
    /// and absorb are not yet wired in Rust.
    RecipientInvite,
    /// Bundle of reader kits (`*.btn.mykit`) — no private signing material.
    /// Absorb writes the kits into the local keystore (existing files are
    /// preserved to `.previous.<UTC>` sidecars).
    KitBundle,
    /// Full keystore export including raw private keys. The foot-gun kind:
    /// export requires `confirm_includes_secrets = true`. Absorbs like a
    /// [`KitBundle`](Self::KitBundle).
    FullKeystore,
    /// Session 8 (plan `2026-04-29-contact-update-tnpkg.md`,
    /// spec §4.6 / D-11): vault-emitted notification that a
    /// counterparty claimed a share-link or backup-link. Rust core
    /// recognizes the kind so manifests round-trip through
    /// `read_manifest`; absorb is not implemented yet.
    ContactUpdate,
    /// Minimal identity/capability bootstrap bundle.
    IdentitySeed,
    /// Root-authoritative project state package. The public name is
    /// retained for compatibility; target semantics are additive unless
    /// creating a missing Project.
    ProjectSeed,
    /// Two-device group-key sync snapshot (DAY-1 wallet sync): group
    /// `.btn.state` / `.btn.mykit` key material published so a second
    /// device of the same identity can install it. On the wire today the
    /// packages ride `full_keystore` with `scope = "group_keys"`, but the
    /// kind is registered here so the cross-implementation kind catalogs
    /// (Python `KNOWN_KINDS`, TS `manifestKnownKinds()`) stay
    /// core-sourced and absorb routers can accept the explicit kind.
    GroupKeys,
}

impl ManifestKind {
    /// Return the wire form of the kind (snake_case).
    ///
    /// The exact string written to / read from the manifest's `kind` field, and
    /// the spelling cross-implementation fixtures pin. Inverse of
    /// [`from_wire`](Self::from_wire).
    ///
    /// # Examples
    ///
    /// ```
    /// use tn_core::ManifestKind;
    ///
    /// assert_eq!(ManifestKind::AdminLogSnapshot.as_str(), "admin_log_snapshot");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdminLogSnapshot => "admin_log_snapshot",
            Self::Offer => "offer",
            Self::Enrolment => "enrolment",
            Self::RecipientInvite => "recipient_invite",
            Self::KitBundle => "kit_bundle",
            Self::FullKeystore => "full_keystore",
            Self::ContactUpdate => "contact_update",
            Self::IdentitySeed => "identity_seed",
            Self::ProjectSeed => "project_seed",
            Self::GroupKeys => "group_keys",
        }
    }

    /// Parse a wire string back into a `ManifestKind`.
    ///
    /// Returns `None` for any string outside the catalog — an unknown `kind` is
    /// a malformed manifest, surfaced as [`crate::Error::Malformed`] by
    /// [`Manifest::from_json`]. Inverse of [`as_str`](Self::as_str).
    ///
    /// # Examples
    ///
    /// ```
    /// use tn_core::ManifestKind;
    ///
    /// assert_eq!(ManifestKind::from_wire("kit_bundle"), Some(ManifestKind::KitBundle));
    /// assert_eq!(ManifestKind::from_wire("not_a_kind"), None);
    /// ```
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "admin_log_snapshot" => Some(Self::AdminLogSnapshot),
            "offer" => Some(Self::Offer),
            "enrolment" => Some(Self::Enrolment),
            "recipient_invite" => Some(Self::RecipientInvite),
            "kit_bundle" => Some(Self::KitBundle),
            "full_keystore" => Some(Self::FullKeystore),
            "contact_update" => Some(Self::ContactUpdate),
            "identity_seed" => Some(Self::IdentitySeed),
            "project_seed" => Some(Self::ProjectSeed),
            "group_keys" => Some(Self::GroupKeys),
            _ => None,
        }
    }
}

/// Decoded `.tnpkg` manifest — the signed index at the head of every package.
///
/// The manifest names the package's kind, producer, recipient, ceremony,
/// vector clock, and (for snapshots) a copy of the reduced state, then carries
/// an Ed25519 signature over its own canonical bytes. It is the integrity and
/// dispatch surface of the `.tnpkg` format: a receiver verifies the signature
/// against [`publisher_identity`](Self::publisher_identity) before trusting the
/// body, and routes on [`kind`](Self::kind). Mirrors Python's `TnpkgManifest`
/// shape field-for-field.
///
/// The signature is computed over [`signing_bytes`](Self::signing_bytes) (the
/// canonical form *minus* the signature field) so that signing and verifying
/// agree on the exact bytes. Build a manifest, call [`sign_manifest`] with the
/// producer's Ed25519 key, then [`write_tnpkg`]; on the read side
/// [`read_tnpkg`] parses it and the caller runs [`verify_manifest`].
///
/// # Examples
///
/// A manifest round-trips through JSON, and [`signing_bytes`](Self::signing_bytes)
/// is stable regardless of whether the signature field is populated (this is
/// what lets a signer and a verifier bind identical bytes):
///
/// ```
/// use std::collections::BTreeMap;
/// use tn_core::{Manifest, ManifestKind};
///
/// let mut manifest = Manifest {
///     kind: ManifestKind::AdminLogSnapshot,
///     version: 1,
///     publisher_identity: "did:key:zExample".into(),
///     recipient_identity: None,
///     ceremony_id: "cer_demo".into(),
///     as_of: "2026-06-02T00:00:00.000+00:00".into(),
///     scope: "admin".into(),
///     clock: BTreeMap::new(),
///     event_count: 0,
///     head_row_hash: None,
///     state: None,
///     manifest_signature_b64: None,
/// };
///
/// // JSON round-trip preserves the dispatch kind.
/// let reparsed = Manifest::from_json(&manifest.to_json()).unwrap();
/// assert_eq!(reparsed.kind, ManifestKind::AdminLogSnapshot);
///
/// // signing_bytes ignores manifest_signature_b64, so populating it later
/// // does not change the bytes a signature is computed over.
/// let before = manifest.signing_bytes().unwrap();
/// manifest.manifest_signature_b64 = Some("not-a-real-signature".into());
/// assert_eq!(manifest.signing_bytes().unwrap(), before);
/// ```
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Dispatch discriminator.
    pub kind: ManifestKind,
    /// Schema version (currently 1).
    pub version: u32,
    /// Producer device identity — signature is verified against this
    /// device's Ed25519 key. Renamed from `from_did` in 0.4.3a1.
    pub publisher_identity: String,
    /// Optional point-to-point recipient identity. Renamed from
    /// `to_did` in 0.4.3a1.
    pub recipient_identity: Option<String>,
    /// Ceremony id this snapshot belongs to.
    pub ceremony_id: String,
    /// Wall-clock at export, RFC 3339 UTC. Diagnostic only.
    pub as_of: String,
    /// Scope label (`"admin"`, `"default"`, group name, or `"full"`).
    pub scope: String,
    /// Vector clock at point-of-export.
    pub clock: VectorClock,
    /// Number of envelopes in the body.
    pub event_count: u64,
    /// Row hash of the latest envelope in the body.
    pub head_row_hash: Option<String>,
    /// Materialized state (only set for snapshot kinds).
    pub state: Option<Value>,
    /// Ed25519 signature over `canonical_bytes(manifest minus this field)`.
    pub manifest_signature_b64: Option<String>,
}

impl Manifest {
    /// Serialize to a JSON object whose key set matches Python's `to_dict()`.
    ///
    /// Optional fields are omitted (not emitted as `null`) when `None`, so the
    /// canonical form is stable regardless of which optionals a caller left
    /// unset — important because these bytes feed [`signing_bytes`](Self::signing_bytes).
    /// This is the in-memory JSON shape; [`write_tnpkg`] handles pretty-printing
    /// for on-disk `manifest.json`.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), Value::String(self.kind.as_str().into()));
        out.insert("version".into(), Value::Number(self.version.into()));
        out.insert(
            "publisher_identity".into(),
            Value::String(self.publisher_identity.clone()),
        );
        out.insert(
            "ceremony_id".into(),
            Value::String(self.ceremony_id.clone()),
        );
        out.insert("as_of".into(), Value::String(self.as_of.clone()));
        out.insert("scope".into(), Value::String(self.scope.clone()));
        out.insert("clock".into(), clock_to_json(&self.clock));
        out.insert("event_count".into(), Value::Number(self.event_count.into()));
        if let Some(td) = &self.recipient_identity {
            out.insert("recipient_identity".into(), Value::String(td.clone()));
        }
        if let Some(rh) = &self.head_row_hash {
            out.insert("head_row_hash".into(), Value::String(rh.clone()));
        }
        if let Some(state) = &self.state {
            out.insert("state".into(), state.clone());
        }
        if let Some(sig) = &self.manifest_signature_b64 {
            out.insert("manifest_signature_b64".into(), Value::String(sig.clone()));
        }
        Value::Object(out)
    }

    /// Parse a manifest from a JSON object.
    ///
    /// The required fields (`kind`, `version`, `publisher_identity`,
    /// `ceremony_id`, `as_of`) must be present; the rest default (`scope`
    /// defaults to `"admin"`, `event_count` to `0`, optionals to `None`). Does
    /// not verify the signature — that is [`verify_manifest`]'s job. Inverse of
    /// [`to_json`](Self::to_json).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] if `doc` is not a JSON object, a
    /// required field is missing, or `kind` is outside the
    /// [`ManifestKind`] catalog.
    pub fn from_json(doc: &Value) -> Result<Self> {
        let obj = doc.as_object().ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest",
            reason: "manifest is not a JSON object".into(),
        })?;
        let kind_s = obj
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing kind".into(),
            })?;
        let kind = ManifestKind::from_wire(kind_s).ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest",
            reason: format!("unknown kind {kind_s:?}"),
        })?;
        let version =
            obj.get("version")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Malformed {
                    kind: "tnpkg manifest",
                    reason: "missing version".into(),
                })?;
        let publisher_identity = obj
            .get("publisher_identity")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing publisher_identity".into(),
            })?
            .to_string();
        let ceremony_id = obj
            .get("ceremony_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing ceremony_id".into(),
            })?
            .to_string();
        let as_of = obj
            .get("as_of")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing as_of".into(),
            })?
            .to_string();
        let scope = obj
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("admin")
            .to_string();
        let recipient_identity = obj
            .get("recipient_identity")
            .and_then(Value::as_str)
            .map(str::to_string);
        let clock = json_to_clock(obj.get("clock"));
        let event_count = obj.get("event_count").and_then(Value::as_u64).unwrap_or(0);
        let head_row_hash = obj
            .get("head_row_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        let state = obj.get("state").cloned();
        let manifest_signature_b64 = obj
            .get("manifest_signature_b64")
            .and_then(Value::as_str)
            .map(str::to_string);
        // version cast: only u32 expected, but the catalog allows wider.
        Ok(Self {
            kind,
            version: u32::try_from(version).unwrap_or(MANIFEST_VERSION),
            publisher_identity,
            recipient_identity,
            ceremony_id,
            as_of,
            scope,
            clock,
            event_count,
            head_row_hash,
            state,
            manifest_signature_b64,
        })
    }

    /// Compute the canonical bytes the producer signs — the manifest minus its
    /// own signature field.
    ///
    /// Serializes via [`to_json`](Self::to_json), drops
    /// `manifest_signature_b64`, and runs the bytes through the crate's
    /// RFC 8785-style canonicalizer. Signing and verifying both call this, so
    /// they bind the identical byte string regardless of whether the signature
    /// field is already populated. Pure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if canonicalization fails (e.g. a non-finite
    /// number somewhere in [`state`](Self::state)).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut v = self.to_json();
        if let Value::Object(m) = &mut v {
            m.remove("manifest_signature_b64");
        }
        canonical_bytes(&v)
    }
}

// --------------------------------------------------------------------------
// Body contents — caller-supplied logical path -> bytes mapping.
// --------------------------------------------------------------------------

/// Body payload for a `.tnpkg`: logical entry name → raw bytes.
///
/// Every key must be a POSIX-relative path under `body/` (e.g.
/// `body/admin.ndjson`); the writers reject anything else. The caller owns the
/// `body/` prefix and the per-kind layout — the `manifest.json` entry is added
/// by [`write_tnpkg`] / [`write_tnpkg_bytes`], never here. `BTreeMap` keeps the
/// zip entry order deterministic.
pub type BodyContents = BTreeMap<String, Vec<u8>>;

/// Where [`read_tnpkg`] reads a `.tnpkg` archive from.
pub enum TnpkgSource<'a> {
    /// On-disk path to the `.tnpkg` zip.
    Path(&'a Path),
    /// In-memory `.tnpkg` zip bytes (the filesystem-free path, used by WASM
    /// and other byte-array bindings).
    Bytes(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample_manifest() -> Manifest {
        let mut clock = BTreeMap::new();
        let mut inner = BTreeMap::new();
        inner.insert("tn.recipient.added".into(), 3u64);
        clock.insert("did:key:zABC".into(), inner);
        Manifest {
            kind: ManifestKind::AdminLogSnapshot,
            version: 1,
            publisher_identity: "did:key:zABC".into(),
            recipient_identity: None,
            ceremony_id: "cer_x".into(),
            as_of: "2026-04-24T00:00:00.000+00:00".into(),
            scope: "admin".into(),
            clock,
            event_count: 3,
            head_row_hash: Some("sha256:abc".into()),
            state: None,
            manifest_signature_b64: None,
        }
    }

    #[test]
    fn signing_bytes_strips_signature_field() {
        let mut m = sample_manifest();
        let bytes_unsigned = m.signing_bytes().unwrap();
        m.manifest_signature_b64 = Some("dummy".into());
        let bytes_after_sig = m.signing_bytes().unwrap();
        assert_eq!(bytes_unsigned, bytes_after_sig);
    }

    #[test]
    fn round_trip_sign_verify() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(pk.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(buf).into_string());

        let mut m = sample_manifest();
        m.publisher_identity = did;
        sign_manifest(&mut m, &sk).unwrap();
        verify_manifest(&m).unwrap();
    }

    #[test]
    fn tampered_manifest_rejected() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let pk = sk.verifying_key();
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(pk.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(buf).into_string());

        let mut m = sample_manifest();
        m.publisher_identity = did;
        sign_manifest(&mut m, &sk).unwrap();
        m.event_count += 1; // tamper
        assert!(verify_manifest(&m).is_err());
    }

    #[test]
    fn clock_dominates_equal_clocks() {
        let a = sample_manifest().clock;
        let b = sample_manifest().clock;
        assert!(clock_dominates(&a, &b));
    }

    #[test]
    fn clock_dominates_b_ahead_returns_false() {
        let mut a = sample_manifest().clock;
        let mut b = a.clone();
        b.get_mut("did:key:zABC")
            .unwrap()
            .insert("tn.recipient.added".into(), 99);
        assert!(!clock_dominates(&a, &b));
        // Reverse: a is now behind b on that coord.
        a.get_mut("did:key:zABC")
            .unwrap()
            .insert("tn.recipient.added".into(), 100);
        assert!(clock_dominates(&a, &b));
    }
}
