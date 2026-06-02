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

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::canonical::canonical_bytes;
use crate::{Error, Result};

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

fn clock_to_json(clock: &VectorClock) -> Value {
    let mut out = Map::new();
    for (did, et_map) in clock {
        let mut inner = Map::new();
        for (et, seq) in et_map {
            inner.insert(et.clone(), Value::Number((*seq).into()));
        }
        out.insert(did.clone(), Value::Object(inner));
    }
    Value::Object(out)
}

fn json_to_clock(v: Option<&Value>) -> VectorClock {
    let mut out: VectorClock = BTreeMap::new();
    let Some(Value::Object(m)) = v else {
        return out;
    };
    for (did, et_v) in m {
        let Value::Object(et_map) = et_v else {
            continue;
        };
        let mut inner = BTreeMap::new();
        for (et, seq_v) in et_map {
            if let Some(seq) = seq_v.as_u64() {
                inner.insert(et.clone(), seq);
            }
        }
        out.insert(did.clone(), inner);
    }
    out
}

/// Sign a manifest in place, populating
/// [`manifest_signature_b64`](Manifest::manifest_signature_b64).
///
/// Signs [`Manifest::signing_bytes`] (the canonical form minus the signature)
/// with `sk` and stores the standard-base64 Ed25519 signature back on the
/// manifest. `sk` must be the signing key whose public half is encoded in
/// [`Manifest::publisher_identity`], or the later [`verify_manifest`] will fail.
/// Side effect: mutates `manifest`.
///
/// # Errors
///
/// Returns [`crate::Error`] if [`Manifest::signing_bytes`] fails to
/// canonicalize.
pub fn sign_manifest(manifest: &mut Manifest, sk: &SigningKey) -> Result<()> {
    let bytes = manifest.signing_bytes()?;
    let sig = sk.sign(&bytes);
    manifest.manifest_signature_b64 = Some(B64_STANDARD.encode(sig.to_bytes()));
    Ok(())
}

/// Verify a manifest's signature against its declared producer.
///
/// Decodes the Ed25519 public key from [`Manifest::publisher_identity`]
/// (`did:key:z…`), decodes the standard-base64
/// [`manifest_signature_b64`](Manifest::manifest_signature_b64), and checks it
/// over [`Manifest::signing_bytes`]. This is the gate
/// [`crate::Runtime::absorb`] runs before trusting a package's body. Pure
/// (reads only the manifest); `Ok(())` means the producer named in the manifest
/// signed exactly these bytes.
///
/// # Errors
///
/// Returns [`crate::Error::Malformed`] when the manifest is unsigned, the
/// `publisher_identity` is not a verifiable Ed25519 `did:key`, the signature is
/// not valid 64-byte base64, or the signature does not verify (tampered
/// manifest).
pub fn verify_manifest(manifest: &Manifest) -> Result<()> {
    let sig_b64 = manifest
        .manifest_signature_b64
        .as_deref()
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest",
            reason: "manifest is unsigned".into(),
        })?;
    let pub_bytes = did_key_pub(&manifest.publisher_identity)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest pubkey",
        reason: e.to_string(),
    })?;
    let sig_bytes = B64_STANDARD.decode(sig_b64).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest signature",
        reason: e.to_string(),
    })?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed {
            kind: "tnpkg manifest signature",
            reason: "expected 64-byte Ed25519 signature".into(),
        })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let msg = manifest.signing_bytes()?;
    vk.verify(&msg, &sig).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest signature",
        reason: format!("verify failed: {e}"),
    })?;
    Ok(())
}

/// Extract the 32-byte Ed25519 public key from a `did:key:z…` identifier.
///
/// Internal helper for [`verify_manifest`]. Public callers verify `did:key`
/// signatures through [`crate::DeviceKey::verify_did`] (behind `tn init`),
/// not this function.
pub(crate) fn did_key_pub(did: &str) -> Result<[u8; 32]> {
    let rest = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: format!("unsupported DID form: {did:?}"),
        })?;
    let multi = bs58::decode(rest)
        .into_vec()
        .map_err(|e| Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: e.to_string(),
        })?;
    if multi.len() < 2 || multi[..2] != ED25519_MULTICODEC {
        return Err(Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: "manifest signing key must be Ed25519 (multicodec 0xed)".into(),
        });
    }
    let pub_bytes: [u8; 32] = multi[2..].try_into().map_err(|_| Error::Malformed {
        kind: "tnpkg manifest publisher_identity",
        reason: "DID pub bytes are not 32-byte Ed25519".into(),
    })?;
    Ok(pub_bytes)
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

// --------------------------------------------------------------------------
// Zip writer / reader
// --------------------------------------------------------------------------

/// Write a signed `.tnpkg` zip to `out_path`.
///
/// Emits `manifest.json` (pretty-printed, sorted keys, trailing newline — byte-
/// for-byte with Python's `json.dumps(..., sort_keys=True, indent=2) + "\n"`)
/// followed by every `body/...` entry, all stored uncompressed. Creates parent
/// directories as needed. The manifest must already be signed (call
/// [`sign_manifest`] first). Use [`write_tnpkg_bytes`] for the in-memory
/// variant.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidConfig`] if the manifest is unsigned,
/// [`crate::Error::Malformed`] if any `body` key is not a valid `body/...`
/// POSIX-relative path, or [`crate::Error::Io`] on filesystem / zip failures.
pub fn write_tnpkg(out_path: &Path, manifest: &Manifest, body: &BodyContents) -> Result<()> {
    if manifest.manifest_signature_b64.is_none() {
        return Err(Error::InvalidConfig(
            "write_tnpkg: manifest is unsigned. Call sign_manifest before writing.".into(),
        ));
    }
    for name in body.keys() {
        validate_tnpkg_body_name(name)?;
    }
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file = std::fs::File::create(out_path)?;
    let mut zw = zip::ZipWriter::new(file);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // manifest.json — pretty-printed, sorted keys, trailing newline. Python
    // uses `json.dumps(..., sort_keys=True, indent=2) + "\n"`. We mirror.
    let manifest_json = manifest_pretty_json(&manifest.to_json())?;
    zw.start_file("manifest.json", opts).map_err(zip_err)?;
    zw.write_all(manifest_json.as_bytes())?;

    for (name, data) in body {
        zw.start_file(name, opts).map_err(zip_err)?;
        zw.write_all(data)?;
    }
    zw.finish().map_err(zip_err)?;
    Ok(())
}

/// Encode a signed `.tnpkg` zip into memory and return the bytes.
///
/// The filesystem-free sibling of [`write_tnpkg`], used by WASM and other
/// bindings that operate on byte arrays rather than paths. Same zip layout and
/// same signed-manifest precondition.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidConfig`] if the manifest is unsigned,
/// [`crate::Error::Malformed`] if any `body` key is not a valid `body/...`
/// POSIX-relative path, or a zip-serialization error.
pub fn write_tnpkg_bytes(manifest: &Manifest, body: &BodyContents) -> Result<Vec<u8>> {
    if manifest.manifest_signature_b64.is_none() {
        return Err(Error::InvalidConfig(
            "write_tnpkg_bytes: manifest is unsigned. Call sign_manifest before writing.".into(),
        ));
    }
    for name in body.keys() {
        validate_tnpkg_body_name(name)?;
    }

    let cursor = Cursor::new(Vec::new());
    let mut zw = zip::ZipWriter::new(cursor);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let manifest_json = manifest_pretty_json(&manifest.to_json())?;
    zw.start_file("manifest.json", opts).map_err(zip_err)?;
    zw.write_all(manifest_json.as_bytes())?;

    for (name, data) in body {
        zw.start_file(name, opts).map_err(zip_err)?;
        zw.write_all(data)?;
    }
    let cursor = zw.finish().map_err(zip_err)?;
    Ok(cursor.into_inner())
}

fn validate_tnpkg_body_name(name: &str) -> Result<()> {
    if !name.starts_with("body/") || name == "body/" {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!("invalid package member {name:?}; expected manifest.json or body/..."),
        });
    }
    if name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "invalid package member {name:?}; only POSIX relative body paths are allowed"
            ),
        });
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn zip_err(e: zip::result::ZipError) -> Error {
    Error::Malformed {
        kind: "tnpkg zip",
        reason: e.to_string(),
    }
}

/// Pretty-print a JSON value with `sort_keys=True, indent=2` semantics.
/// Matches Python's `json.dumps(value, sort_keys=True, indent=2) + "\n"`.
fn manifest_pretty_json(v: &Value) -> Result<String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    let sorted = sort_keys_recursive(v);
    sorted.serialize(&mut ser)?;
    let mut s = String::from_utf8(buf).map_err(|e| Error::Malformed {
        kind: "manifest json",
        reason: e.to_string(),
    })?;
    s.push('\n');
    Ok(s)
}

fn sort_keys_recursive(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out: BTreeMap<String, Value> = BTreeMap::new();
            for (k, vv) in m {
                out.insert(k.clone(), sort_keys_recursive(vv));
            }
            // Convert back to serde_json::Map preserving sorted order.
            let mut new_m = Map::new();
            for (k, vv) in out {
                new_m.insert(k, vv);
            }
            Value::Object(new_m)
        }
        Value::Array(a) => Value::Array(a.iter().map(sort_keys_recursive).collect()),
        _ => v.clone(),
    }
}

/// Read a `.tnpkg` and return the parsed manifest plus its body map (entry name
/// → bytes).
///
/// Parses `manifest.json` and collects every `body/...` entry, validating that
/// the archive contains exactly one `manifest.json` and only well-formed body
/// paths. Does **not** verify the signature — the caller runs [`verify_manifest`]
/// on the returned manifest (as [`crate::Runtime::absorb`] does). Inverse of
/// [`write_tnpkg`] / [`write_tnpkg_bytes`].
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if a [`TnpkgSource::Path`] does not exist or
/// cannot be read, or [`crate::Error::Malformed`] if the bytes are not a valid
/// zip, lack exactly one `manifest.json`, carry an illegal body path, or hold a
/// manifest that fails [`Manifest::from_json`].
#[allow(clippy::needless_pass_by_value)]
pub fn read_tnpkg(source: TnpkgSource<'_>) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let bytes = match source {
        TnpkgSource::Path(p) => {
            if !p.exists() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("absorb: source path does not exist: {}", p.display()),
                )));
            }
            std::fs::read(p)?
        }
        TnpkgSource::Bytes(b) => b.to_vec(),
    };
    validate_zip_manifest_entry_count(&bytes)?;
    read_tnpkg_inner(Cursor::new(bytes))
}

fn validate_zip_manifest_entry_count(bytes: &[u8]) -> Result<()> {
    let Some(eocd_offset) = find_eocd(bytes) else {
        return Ok(());
    };
    if eocd_offset + 22 > bytes.len() {
        return Ok(());
    }
    let entry_count = u16::from_le_bytes([bytes[eocd_offset + 10], bytes[eocd_offset + 11]]);
    let cd_size = u32::from_le_bytes([
        bytes[eocd_offset + 12],
        bytes[eocd_offset + 13],
        bytes[eocd_offset + 14],
        bytes[eocd_offset + 15],
    ]) as usize;
    let cd_offset = u32::from_le_bytes([
        bytes[eocd_offset + 16],
        bytes[eocd_offset + 17],
        bytes[eocd_offset + 18],
        bytes[eocd_offset + 19],
    ]) as usize;
    if cd_offset
        .checked_add(cd_size)
        .is_none_or(|end| end > bytes.len())
    {
        return Ok(());
    }

    let mut cur = cd_offset;
    let mut manifest_count = 0usize;
    for _ in 0..entry_count {
        if cur.checked_add(46).is_none_or(|end| end > bytes.len()) {
            return Ok(());
        }
        if u32::from_le_bytes([bytes[cur], bytes[cur + 1], bytes[cur + 2], bytes[cur + 3]])
            != 0x0201_4b50
        {
            return Ok(());
        }
        let name_len = u16::from_le_bytes([bytes[cur + 28], bytes[cur + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[cur + 30], bytes[cur + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[cur + 32], bytes[cur + 33]]) as usize;
        let name_start = cur + 46;
        let name_end = match name_start.checked_add(name_len) {
            Some(end) if end <= bytes.len() => end,
            _ => return Ok(()),
        };
        if bytes.get(name_start..name_end) == Some(b"manifest.json".as_slice()) {
            manifest_count += 1;
        }
        cur = match name_end
            .checked_add(extra_len)
            .and_then(|n| n.checked_add(comment_len))
        {
            Some(next) => next,
            None => return Ok(()),
        };
    }
    if manifest_count > 1 {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "zip contains {manifest_count} manifest.json entries; the .tnpkg format requires exactly one"
            ),
        });
    }
    Ok(())
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    let min_start = bytes.len().saturating_sub(22 + 0xffff);
    (min_start..=bytes.len() - 22)
        .rev()
        .find(|&i| bytes[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
}

fn read_tnpkg_inner<R: Read + Seek>(reader: R) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let mut zip_r = zip::ZipArchive::new(reader).map_err(|e| Error::Malformed {
        kind: "tnpkg zip",
        reason: e.to_string(),
    })?;
    let names: Vec<String> = (0..zip_r.len())
        .filter_map(|i| zip_r.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();
    let manifest_count = names
        .iter()
        .filter(|name| name.as_str() == "manifest.json")
        .count();
    if manifest_count == 0 {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: "missing manifest.json".into(),
        });
    }
    if manifest_count != 1 {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "zip contains {manifest_count} manifest.json entries; the .tnpkg format requires exactly one"
            ),
        });
    }
    // Pull manifest first.
    let manifest_doc: Value = {
        let mut mf = zip_r
            .by_name("manifest.json")
            .map_err(|e| Error::Malformed {
                kind: "tnpkg zip",
                reason: e.to_string(),
            })?;
        let mut buf = Vec::new();
        mf.read_to_end(&mut buf)?;
        serde_json::from_slice(&buf)?
    };
    let manifest = Manifest::from_json(&manifest_doc)?;

    // Pull every other entry into the body map.
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for name in names {
        if name == "manifest.json" {
            continue;
        }
        validate_tnpkg_body_name(&name)?;
        let mut entry = zip_r.by_name(&name).map_err(|e| Error::Malformed {
            kind: "tnpkg zip",
            reason: e.to_string(),
        })?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        body.insert(name, buf);
    }
    Ok((manifest, body))
}

// --------------------------------------------------------------------------
// Vector clock helpers
// --------------------------------------------------------------------------

/// Return `true` iff `a` is at or ahead of `b` on every `(did, event_type)`
/// coordinate.
///
/// A coordinate absent from `a` counts as sequence `0`. Absorb uses this to
/// short-circuit: if the receiver's local clock dominates an incoming
/// manifest's clock, the package carries nothing new and absorb is a no-op.
/// Pure; not symmetric — equal clocks dominate each other, but a clock that is
/// behind on any single coordinate does not dominate.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use tn_core::VectorClock;
/// use tn_core::tnpkg::clock_dominates;
///
/// let mut ahead: VectorClock = BTreeMap::new();
/// ahead.entry("did:key:zA".into()).or_default().insert("tn.recipient.added".into(), 5);
///
/// let mut behind: VectorClock = BTreeMap::new();
/// behind.entry("did:key:zA".into()).or_default().insert("tn.recipient.added".into(), 3);
///
/// assert!(clock_dominates(&ahead, &behind));   // 5 >= 3
/// assert!(!clock_dominates(&behind, &ahead));  // 3 <  5
/// ```
pub fn clock_dominates(a: &VectorClock, b: &VectorClock) -> bool {
    for (did, et_map) in b {
        let a_map = a.get(did);
        for (event_type, seq) in et_map {
            let a_seq = a_map.and_then(|m| m.get(event_type)).copied().unwrap_or(0);
            if a_seq < *seq {
                return false;
            }
        }
    }
    true
}

/// Merge two vector clocks by taking the pointwise maximum on every coordinate.
///
/// The least-upper-bound of `a` and `b`: the result holds, for each
/// `(did, event_type)`, the larger of the two sequences (or whichever clock has
/// the coordinate at all). This is how a receiver advances its clock after
/// accepting a package. Pure; neither input is mutated. Commutative and
/// idempotent.
pub fn clock_merge(a: &VectorClock, b: &VectorClock) -> VectorClock {
    let mut out = a.clone();
    for (did, et_map) in b {
        let slot = out.entry(did.clone()).or_default();
        for (et, seq) in et_map {
            let cur = slot.get(et).copied().unwrap_or(0);
            if *seq > cur {
                slot.insert(et.clone(), *seq);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
