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
//! against `from_did`'s Ed25519 public key over the RFC 8785-style canonical
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
/// `BTreeMap` for deterministic JSON serialization (sorted keys), matching
/// Python's `dict` + canonical_bytes serialization exactly.
pub type VectorClock = BTreeMap<String, BTreeMap<String, u64>>;

/// Kind discriminator on the wire. Snake-case to match Python's
/// `KNOWN_KINDS` set exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ManifestKind {
    AdminLogSnapshot,
    Offer,
    Enrolment,
    RecipientInvite,
    KitBundle,
    FullKeystore,
    /// Session 8 (plan `2026-04-29-contact-update-tnpkg.md`,
    /// spec §4.6 / D-11): vault-emitted notification that a
    /// counterparty claimed a share-link or backup-link. Rust core
    /// recognizes the kind so manifests round-trip through
    /// `read_manifest`; absorb is not implemented yet.
    ContactUpdate,
}

impl ManifestKind {
    /// Wire form of the kind (snake_case).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdminLogSnapshot => "admin_log_snapshot",
            Self::Offer => "offer",
            Self::Enrolment => "enrolment",
            Self::RecipientInvite => "recipient_invite",
            Self::KitBundle => "kit_bundle",
            Self::FullKeystore => "full_keystore",
            Self::ContactUpdate => "contact_update",
        }
    }

    /// Parse a wire string back into a `ManifestKind`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "admin_log_snapshot" => Some(Self::AdminLogSnapshot),
            "offer" => Some(Self::Offer),
            "enrolment" => Some(Self::Enrolment),
            "recipient_invite" => Some(Self::RecipientInvite),
            "kit_bundle" => Some(Self::KitBundle),
            "full_keystore" => Some(Self::FullKeystore),
            "contact_update" => Some(Self::ContactUpdate),
            _ => None,
        }
    }
}

/// Decoded `.tnpkg` manifest. Mirrors Python's `TnpkgManifest` shape.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Dispatch discriminator.
    pub kind: ManifestKind,
    /// Schema version (currently 1).
    pub version: u32,
    /// Producer DID — signature is verified against this DID's Ed25519 key.
    pub from_did: String,
    /// Optional point-to-point recipient DID.
    pub to_did: Option<String>,
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
    /// Build a JSON object whose key set matches Python's `to_dict()`. Skips
    /// optional fields when `None` so the canonical form is stable across
    /// tiny variations in caller code.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), Value::String(self.kind.as_str().into()));
        out.insert("version".into(), Value::Number(self.version.into()));
        out.insert("from_did".into(), Value::String(self.from_did.clone()));
        out.insert(
            "ceremony_id".into(),
            Value::String(self.ceremony_id.clone()),
        );
        out.insert("as_of".into(), Value::String(self.as_of.clone()));
        out.insert("scope".into(), Value::String(self.scope.clone()));
        out.insert("clock".into(), clock_to_json(&self.clock));
        out.insert("event_count".into(), Value::Number(self.event_count.into()));
        if let Some(td) = &self.to_did {
            out.insert("to_did".into(), Value::String(td.clone()));
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

    /// Parse a manifest from a JSON object. Required fields must be present.
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
        let version = obj
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing version".into(),
            })?;
        let from_did = obj
            .get("from_did")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg manifest",
                reason: "missing from_did".into(),
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
        let to_did = obj
            .get("to_did")
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
            from_did,
            to_did,
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

    /// Canonical bytes the producer signs (manifest minus the signature).
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

/// Sign a manifest in place, populating `manifest_signature_b64` over the
/// canonical bytes of the manifest minus that field.
pub fn sign_manifest(manifest: &mut Manifest, sk: &SigningKey) -> Result<()> {
    let bytes = manifest.signing_bytes()?;
    let sig = sk.sign(&bytes);
    manifest.manifest_signature_b64 = Some(B64_STANDARD.encode(sig.to_bytes()));
    Ok(())
}

/// Verify a manifest's `manifest_signature_b64` against `from_did`'s
/// Ed25519 public key. Returns `Ok(())` on success, `Err` on any failure.
pub fn verify_manifest(manifest: &Manifest) -> Result<()> {
    let sig_b64 = manifest
        .manifest_signature_b64
        .as_deref()
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest",
            reason: "manifest is unsigned".into(),
        })?;
    let pub_bytes = did_key_pub(&manifest.from_did)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest pubkey",
        reason: e.to_string(),
    })?;
    let sig_bytes = B64_STANDARD.decode(sig_b64).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest signature",
        reason: e.to_string(),
    })?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| Error::Malformed {
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
pub(crate) fn did_key_pub(did: &str) -> Result<[u8; 32]> {
    let rest = did.strip_prefix("did:key:z").ok_or_else(|| Error::Malformed {
        kind: "tnpkg manifest from_did",
        reason: format!("unsupported DID form: {did:?}"),
    })?;
    let multi = bs58::decode(rest)
        .into_vec()
        .map_err(|e| Error::Malformed {
            kind: "tnpkg manifest from_did",
            reason: e.to_string(),
        })?;
    if multi.len() < 2 || multi[..2] != ED25519_MULTICODEC {
        return Err(Error::Malformed {
            kind: "tnpkg manifest from_did",
            reason: "manifest signing key must be Ed25519 (multicodec 0xed)".into(),
        });
    }
    let pub_bytes: [u8; 32] = multi[2..].try_into().map_err(|_| Error::Malformed {
        kind: "tnpkg manifest from_did",
        reason: "DID pub bytes are not 32-byte Ed25519".into(),
    })?;
    Ok(pub_bytes)
}

// --------------------------------------------------------------------------
// Body contents — caller-supplied logical path -> bytes mapping.
// --------------------------------------------------------------------------

/// Body contents for a `.tnpkg`. Caller is responsible for prefixing entries
/// with `body/` per the format. Manifest is added by `write_tnpkg`.
pub type BodyContents = BTreeMap<String, Vec<u8>>;

/// Source of bytes to read a `.tnpkg` from.
pub enum TnpkgSource<'a> {
    /// On-disk path.
    Path(&'a Path),
    /// In-memory bytes.
    Bytes(&'a [u8]),
}

// --------------------------------------------------------------------------
// Zip writer / reader
// --------------------------------------------------------------------------

/// Write a `.tnpkg` zip to `out_path`. Manifest must already be signed.
pub fn write_tnpkg(out_path: &Path, manifest: &Manifest, body: &BodyContents) -> Result<()> {
    if manifest.manifest_signature_b64.is_none() {
        return Err(Error::InvalidConfig(
            "write_tnpkg: manifest is unsigned. Call sign_manifest before writing.".into(),
        ));
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

/// Read a `.tnpkg` and return the parsed manifest plus a body map (entry name
/// → bytes). Does **not** verify the signature; the caller must call
/// `verify_manifest` on the returned manifest.
#[allow(clippy::needless_pass_by_value)]
pub fn read_tnpkg(source: TnpkgSource<'_>) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    match source {
        TnpkgSource::Path(p) => {
            if !p.exists() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("absorb: source path does not exist: {}", p.display()),
                )));
            }
            let f = std::fs::File::open(p)?;
            read_tnpkg_inner(f)
        }
        TnpkgSource::Bytes(b) => {
            let cursor = Cursor::new(b.to_vec());
            read_tnpkg_inner(cursor)
        }
    }
}

fn read_tnpkg_inner<R: Read + Seek>(reader: R) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let mut zip_r = zip::ZipArchive::new(reader).map_err(|e| Error::Malformed {
        kind: "tnpkg zip",
        reason: e.to_string(),
    })?;
    // Pull manifest first.
    let manifest_doc: Value = {
        let mut mf = zip_r.by_name("manifest.json").map_err(|_| Error::Malformed {
            kind: "tnpkg zip",
            reason: "missing manifest.json".into(),
        })?;
        let mut buf = Vec::new();
        mf.read_to_end(&mut buf)?;
        serde_json::from_slice(&buf)?
    };
    let manifest = Manifest::from_json(&manifest_doc)?;

    // Pull every other entry into the body map.
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let names: Vec<String> = (0..zip_r.len())
        .filter_map(|i| zip_r.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();
    for name in names {
        if name == "manifest.json" {
            continue;
        }
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

/// True iff `a` dominates `b` on every `(did, event_type)` coordinate.
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

/// Pointwise max of two vector clocks. Pure; does not mutate inputs.
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
            from_did: "did:key:zABC".into(),
            to_did: None,
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
        m.from_did = did;
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
        m.from_did = did;
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
