//! Local invitation inbox helpers.
//!
//! Python and TypeScript accept recipient invitations as `tn-invite-*.zip`
//! files rather than as `recipient_invite` `.tnpkg` packages. This module
//! mirrors that real flow: list local invitation archives, inspect their
//! `manifest.json`, find the inner kit entry, and verify the optional
//! `kit_sha256` binding before installing the kit into the active ceremony.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zip::write::SimpleFileOptions;
use zip::ZipArchive;

use crate::tn::Tn;
use crate::{Error, Result};

/// Runtime inbox namespace for a [`Tn`] handle.
pub struct Inbox<'a> {
    tn: &'a Tn,
}

impl<'a> Inbox<'a> {
    pub(crate) fn new(tn: &'a Tn) -> Self {
        Self { tn }
    }

    /// List `tn-invite-*.zip` files in `dir`.
    ///
    /// Missing directories return an empty list, matching Python and
    /// TypeScript. Results are sorted by full path string.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the directory exists but cannot be read.
    pub fn list_local(&self, dir: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
        list_local(dir)
    }

    /// Inspect an invitation zip from disk.
    ///
    /// This validates the zip shape, parses `manifest.json`, locates the
    /// inner kit (`<group>.btn.mykit`, legacy `kit.tnpkg`, or a single
    /// kit-shaped fallback), and verifies `kit_sha256` when present.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the zip is malformed, missing required
    /// invite members, or the kit hash does not match the manifest.
    pub fn inspect_path(&self, path: impl AsRef<Path>) -> Result<InvitationInfo> {
        let _ = self.tn;
        inspect_invitation_path(path)
    }

    /// Inspect an invitation zip from in-memory bytes.
    ///
    /// See [`Inbox::inspect_path`] for validation behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the bytes are not a valid invitation zip.
    pub fn inspect_bytes(&self, bytes: &[u8]) -> Result<InvitationInfo> {
        let _ = self.tn;
        inspect_invitation_bytes(bytes)
    }

    /// Accept an invitation zip from disk into this ceremony.
    ///
    /// The inner kit is verified, installed as `<group>.btn.mykit` in the
    /// active ceremony keystore, and any existing kit for that group is moved
    /// aside with a `.previous.<UTC_TS>` suffix. Rust also emits
    /// `tn.enrolment.absorbed` to the active log, matching Python/TypeScript.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the invitation cannot be validated, the
    /// keystore cannot be resolved from `tn.yaml`, the kit cannot be written,
    /// or the attestation cannot be emitted.
    pub fn accept_path(&self, path: impl AsRef<Path>) -> Result<InvitationAcceptResult> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::InvalidArgument(format!(
                "invitation zip not found: {}",
                path.display()
            )));
        }
        self.accept_bytes(&fs::read(path)?)
    }

    /// Accept an invitation zip from in-memory bytes into this ceremony.
    ///
    /// See [`Inbox::accept_path`] for install and attestation behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the invitation cannot be validated or
    /// installed.
    pub fn accept_bytes(&self, bytes: &[u8]) -> Result<InvitationAcceptResult> {
        let parsed = parse_invitation_bytes(bytes)?;
        let group_name = parsed.info.group_name();
        let keystore_dir = resolve_keystore_path(self.tn.yaml_path())?;
        fs::create_dir_all(&keystore_dir)?;

        let kit_path = keystore_dir.join(format!("{group_name}.btn.mykit"));
        let backup_path = if kit_path.exists() {
            let ts = backup_stamp()?;
            let backup = kit_path.with_file_name(format!("{group_name}.btn.mykit.previous.{ts}"));
            fs::rename(&kit_path, &backup)?;
            Some(backup)
        } else {
            None
        };
        tn_core::keystore_backend::atomic_write_bytes(&kit_path, &parsed.kit_bytes)?;

        let absorbed_at = now_rfc3339()?;
        self.tn.info(
            "tn.enrolment.absorbed",
            json!({
                "group": group_name,
                "publisher_identity": parsed.info.manifest.from_account_did.clone().unwrap_or_default(),
                "package_sha256": parsed.info.manifest.kit_sha256.clone().unwrap_or_default(),
                "absorbed_at": absorbed_at,
            }),
        )?;

        Ok(InvitationAcceptResult {
            info: parsed.info,
            kit_path,
            backup_path,
            absorbed_at,
        })
    }

    /// Mint a `tn-invite-*.zip` for a recipient and write it to `out_path`.
    ///
    /// This mirrors Python's `tn invite`: it mints a raw reader kit using the
    /// active ceremony's admin machinery, wraps the kit with `manifest.json`,
    /// writes the zip, and removes the temporary raw kit. A `recipient` that
    /// starts with `did:` is used as-is; otherwise Rust records the same
    /// friendly-label placeholder DID shape as Python,
    /// `did:key:zLabel-<recipient>`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the recipient/group/out path is invalid,
    /// the reader kit cannot be minted, or the invite zip cannot be written.
    pub fn mint_invite_path(
        &self,
        recipient: &str,
        out_path: impl AsRef<Path>,
        options: MintInvitationOptions,
    ) -> Result<MintInvitationResult> {
        let recipient_did = normalize_recipient_did(recipient)?;
        let group_name = options.group_name();
        let out_path = out_path.as_ref().to_path_buf();
        let out_dir = out_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&out_dir)?;

        let temp_kit = out_dir.join(format!(".tn-invite-kit-{}.btn.mykit", random_hex::<12>()));
        let add_result =
            self.tn
                .runtime()
                .admin_add_recipient(&group_name, &temp_kit, Some(&recipient_did));
        let leaf_index = match add_result {
            Ok(leaf_index) => leaf_index,
            Err(err) => {
                let _ = fs::remove_file(&temp_kit);
                return Err(err.into());
            }
        };
        let kit_bytes = match fs::read(&temp_kit) {
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = fs::remove_file(&temp_kit);
                return Err(err.into());
            }
        };
        let _ = fs::remove_file(&temp_kit);

        let kit_sha256 = format!("sha256:{}", sha256_hex(&kit_bytes));
        let manifest = InvitationManifest {
            invitation_id: Some(
                options
                    .invitation_id
                    .unwrap_or_else(|| format!("rust-{}", random_hex::<16>())),
            ),
            from_account_did: Some(self.tn.did().to_string()),
            from_email: Some(
                options
                    .from_email
                    .unwrap_or_else(|| self.tn.did().to_string()),
            ),
            project_id: options.project_id,
            project_name: Some(options.project_name.unwrap_or_default()),
            group_name: Some(group_name.clone()),
            leaf_index: Some(Value::Number(leaf_index.into())),
            kit_sha256: Some(kit_sha256),
            event_id: None,
            created_at: Some(now_rfc3339()?),
            note: options.note,
            provenance: Some(options.provenance.unwrap_or_else(|| "rust-sdk".to_string())),
            extra: Map::new(),
        };
        let zip_bytes = make_invitation_zip(&group_name, &kit_bytes, &manifest)?;
        tn_core::keystore_backend::atomic_write_bytes(&out_path, &zip_bytes)?;

        Ok(MintInvitationResult {
            path: out_path,
            recipient_did,
            manifest,
            kit_entry_name: kit_entry_name(&group_name),
            zip_len: zip_bytes.len(),
        })
    }
}

/// List `tn-invite-*.zip` files in `dir`.
///
/// Missing directories return an empty list, matching Python and TypeScript.
///
/// # Errors
///
/// Returns [`crate::Error`] if the directory exists but cannot be read.
pub fn list_local(dir: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("tn-invite-") && name.ends_with(".zip") {
            matches.push(path);
        }
    }
    matches.sort();
    Ok(matches)
}

/// Inspect an invitation zip from disk.
///
/// # Errors
///
/// Returns [`crate::Error`] when the zip cannot be read or validated.
pub fn inspect_invitation_path(path: impl AsRef<Path>) -> Result<InvitationInfo> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(Error::InvalidArgument(format!(
            "invitation zip not found: {}",
            path.display()
        )));
    }
    inspect_invitation_bytes(&fs::read(path)?)
}

/// Inspect an invitation zip from bytes.
///
/// # Errors
///
/// Returns [`crate::Error`] when the bytes are not a valid invitation zip.
pub fn inspect_invitation_bytes(bytes: &[u8]) -> Result<InvitationInfo> {
    Ok(parse_invitation_bytes(bytes)?.info)
}

fn parse_invitation_bytes(bytes: &[u8]) -> Result<ParsedInvitation> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|err| Error::InvalidArgument(format!("invalid invitation zip: {err}")))?;
    if archive.is_empty() {
        return Err(Error::InvalidArgument(
            "invalid invitation zip: no zip entries found".into(),
        ));
    }

    let names = archive
        .file_names()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if !names.iter().any(|name| name == "manifest.json") {
        return Err(Error::InvalidArgument(
            "invalid invitation zip: missing manifest.json".into(),
        ));
    }

    let manifest_bytes = read_zip_member(&mut archive, "manifest.json")?;
    let manifest: InvitationManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| Error::InvalidArgument(format!("invalid invitation manifest: {err}")))?;
    let group_name = manifest.group_name();
    let kit_entry_name = find_kit_entry(&names, &group_name).ok_or_else(|| {
        Error::InvalidArgument("invalid invitation zip: missing kit.tnpkg".into())
    })?;
    let kit_bytes = read_zip_member(&mut archive, &kit_entry_name)?;
    let actual = sha256_hex(&kit_bytes);
    let hash = verify_kit_hash(&actual, manifest.kit_sha256.as_deref())?;

    Ok(ParsedInvitation {
        info: InvitationInfo {
            manifest,
            kit_entry_name,
            kit_len: kit_bytes.len(),
            kit_sha256_actual: actual,
            kit_hash: hash,
        },
        kit_bytes,
    })
}

fn read_zip_member<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>> {
    let mut file = archive.by_name(name).map_err(|err| {
        Error::InvalidArgument(format!("invalid invitation zip member {name}: {err}"))
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn find_kit_entry(names: &[String], group_name: &str) -> Option<String> {
    let preferred = [format!("{group_name}.btn.mykit"), "kit.tnpkg".to_string()];
    for candidate in preferred {
        if names.iter().any(|name| name == &candidate) {
            return Some(candidate);
        }
    }

    let mut kit_shaped = names
        .iter()
        .filter(|name| name.as_str() != "manifest.json")
        .filter(|name| name.ends_with(".tnpkg") || name.ends_with(".btn.mykit"));
    let only = kit_shaped.next()?;
    if kit_shaped.next().is_none() {
        return Some(only.clone());
    }
    None
}

fn verify_kit_hash(actual: &str, expected: Option<&str>) -> Result<InvitationKitHash> {
    let Some(expected) = expected.filter(|expected| !expected.is_empty()) else {
        return Ok(InvitationKitHash::NotPresent);
    };
    let expected_hex = expected.strip_prefix("sha256:").unwrap_or(expected);
    if actual != expected_hex {
        return Err(Error::InvalidArgument(format!(
            "kit hash mismatch: expected {expected_hex}, got {actual}"
        )));
    }
    Ok(InvitationKitHash::Verified {
        expected: expected.to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn make_invitation_zip(
    group_name: &str,
    kit_bytes: &[u8],
    manifest: &InvitationManifest,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer.start_file(kit_entry_name(group_name), opts)?;
        writer.write_all(kit_bytes)?;
        writer.start_file("manifest.json", opts)?;
        writer.write_all(&serde_json::to_vec_pretty(manifest)?)?;
        writer.finish()?;
    }
    Ok(buf)
}

fn kit_entry_name(group_name: &str) -> String {
    format!("{group_name}.btn.mykit")
}

fn normalize_recipient_did(recipient: &str) -> Result<String> {
    let recipient = recipient.trim();
    if recipient.is_empty() {
        return Err(Error::InvalidArgument("recipient must not be empty".into()));
    }
    if recipient.starts_with("did:") {
        Ok(recipient.to_string())
    } else {
        Ok(format!("did:key:zLabel-{recipient}"))
    }
}

fn random_hex<const N: usize>() -> String {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn resolve_keystore_path(yaml_path: &Path) -> Result<PathBuf> {
    let raw = fs::read_to_string(yaml_path)?;
    let doc: serde_yml::Value = serde_yml::from_str(&raw)?;
    let keystore_path = doc
        .get("keystore")
        .and_then(serde_yml::Value::as_mapping)
        .and_then(|keystore| keystore.get(serde_yml::Value::String("path".to_string())))
        .and_then(serde_yml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidArgument("tn.yaml is missing keystore.path".into()))?;
    Ok(resolve_yaml_relative_path(yaml_path, keystore_path))
}

fn resolve_yaml_relative_path(yaml_path: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        yaml_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(path)
    }
}

fn now_rfc3339() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| Error::InvalidArgument(format!("could not format timestamp: {err}")))
}

fn backup_stamp() -> Result<String> {
    let description =
        time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
    OffsetDateTime::now_utc()
        .format(&description)
        .map_err(|err| Error::InvalidArgument(format!("could not format backup timestamp: {err}")))
}

struct ParsedInvitation {
    info: InvitationInfo,
    kit_bytes: Vec<u8>,
}

/// Parsed metadata and kit validation result for a `tn-invite-*.zip`.
#[derive(Debug, Clone, PartialEq)]
pub struct InvitationInfo {
    /// Parsed `manifest.json`.
    pub manifest: InvitationManifest,
    /// Inner kit entry selected from the zip.
    pub kit_entry_name: String,
    /// Inner kit size in bytes.
    pub kit_len: usize,
    /// Actual SHA-256 hex digest of the inner kit bytes.
    pub kit_sha256_actual: String,
    /// Manifest hash verification status.
    pub kit_hash: InvitationKitHash,
}

impl InvitationInfo {
    /// Group name from the manifest, defaulting to `default`.
    pub fn group_name(&self) -> String {
        self.manifest.group_name()
    }

    /// True when `kit_sha256` was present and matched the inner kit.
    pub fn kit_hash_verified(&self) -> bool {
        matches!(self.kit_hash, InvitationKitHash::Verified { .. })
    }
}

/// Result of accepting a `tn-invite-*.zip` into a local ceremony.
#[derive(Debug, Clone, PartialEq)]
pub struct InvitationAcceptResult {
    /// Parsed and verified invitation metadata.
    pub info: InvitationInfo,
    /// Destination `<group>.btn.mykit` path written under the active keystore.
    pub kit_path: PathBuf,
    /// Previous kit backup path when one was replaced.
    pub backup_path: Option<PathBuf>,
    /// Timestamp recorded on the `tn.enrolment.absorbed` attestation.
    pub absorbed_at: String,
}

impl InvitationAcceptResult {
    /// Group name installed by this accept operation.
    pub fn group_name(&self) -> String {
        self.info.group_name()
    }

    /// Sender label from the invitation, defaulting to `unknown`.
    pub fn from_email(&self) -> &str {
        self.info
            .manifest
            .from_email
            .as_deref()
            .unwrap_or("unknown")
    }

    /// Recipient leaf index from the invitation manifest.
    pub fn leaf_index(&self) -> Option<&Value> {
        self.info.manifest.leaf_index.as_ref()
    }
}

/// Options for [`Inbox::mint_invite_path`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MintInvitationOptions {
    /// Group to mint the reader kit for. Defaults to `default`.
    pub group: Option<String>,
    /// Sender label/email recorded in the manifest. Defaults to this
    /// ceremony's device DID.
    pub from_email: Option<String>,
    /// Linked vault project id, when available.
    pub project_id: Option<String>,
    /// Human project name, when available.
    pub project_name: Option<String>,
    /// Free-form note the recipient sees alongside the invitation.
    pub note: Option<String>,
    /// Optional caller-supplied opaque invitation id.
    pub invitation_id: Option<String>,
    /// Producer marker. Defaults to `rust-sdk`.
    pub provenance: Option<String>,
}

impl MintInvitationOptions {
    fn group_name(&self) -> String {
        self.group
            .as_deref()
            .map(str::trim)
            .filter(|group| !group.is_empty())
            .unwrap_or("default")
            .to_string()
    }
}

/// Result of minting a `tn-invite-*.zip`.
#[derive(Debug, Clone, PartialEq)]
pub struct MintInvitationResult {
    /// Path to the written invite zip.
    pub path: PathBuf,
    /// Recipient DID used for kit minting and admin attestation.
    pub recipient_did: String,
    /// Manifest written into the zip.
    pub manifest: InvitationManifest,
    /// Inner kit entry name written into the zip.
    pub kit_entry_name: String,
    /// Size of the written zip bytes.
    pub zip_len: usize,
}

/// Hash status for an invitation's inner kit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationKitHash {
    /// Manifest omitted `kit_sha256`; Python/TypeScript accept this legacy
    /// shape and skip hash validation.
    NotPresent,
    /// Manifest hash was present and matched the inner kit.
    Verified {
        /// Original manifest value, preserving a possible `sha256:` prefix.
        expected: String,
    },
}

/// Parsed `manifest.json` from a `tn-invite-*.zip`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvitationManifest {
    /// Opaque invitation identifier.
    pub invitation_id: Option<String>,
    /// Sender account/device DID.
    pub from_account_did: Option<String>,
    /// Sender email or label shown to the recipient.
    pub from_email: Option<String>,
    /// Linked vault project id, when present.
    pub project_id: Option<String>,
    /// Human project name, when present.
    pub project_name: Option<String>,
    /// Target group name. Missing values default to `default`.
    pub group_name: Option<String>,
    /// Recipient leaf index returned by kit minting.
    pub leaf_index: Option<Value>,
    /// Optional `sha256:<hex>` or raw hex digest for the inner kit.
    pub kit_sha256: Option<String>,
    /// Optional source event id.
    pub event_id: Option<Value>,
    /// Manifest creation timestamp.
    pub created_at: Option<String>,
    /// Optional invitation note.
    pub note: Option<String>,
    /// Producer marker such as `cli-minted`.
    pub provenance: Option<String>,
    /// Future manifest fields preserved for callers.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl InvitationManifest {
    /// Group name from the manifest, defaulting to `default`.
    pub fn group_name(&self) -> String {
        self.group_name
            .as_deref()
            .filter(|group| !group.is_empty())
            .unwrap_or("default")
            .to_string()
    }
}
