//! Zip writer for the `.tnpkg` container.
//!
//! Serializes a signed [`Manifest`](super::Manifest) plus its
//! [`BodyContents`](super::BodyContents) into the `.tnpkg` zip layout:
//! `manifest.json` (pretty-printed, sorted keys, trailing newline — byte-for-
//! byte with Python's `json.dumps(..., sort_keys=True, indent=2) + "\n"`)
//! followed by every `body/...` entry, all stored uncompressed.
//! [`write_tnpkg`] targets a path; [`write_tnpkg_bytes`] returns the bytes for
//! filesystem-free hosts. The path-validation and error helpers
//! ([`validate_tnpkg_body_name`], [`zip_err`]) are shared with the reader.

use std::io::{Cursor, Write};
use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use super::{BodyContents, Manifest};
use crate::{Error, Result};

/// Write a signed `.tnpkg` zip to `out_path`.
///
/// Emits `manifest.json` (pretty-printed, sorted keys, trailing newline — byte-
/// for-byte with Python's `json.dumps(..., sort_keys=True, indent=2) + "\n"`)
/// followed by every `body/...` entry, all stored uncompressed. Creates parent
/// directories as needed. The manifest must already be signed (call
/// [`sign_manifest`](super::sign_manifest) first). Use [`write_tnpkg_bytes`] for
/// the in-memory variant.
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

pub(super) fn validate_tnpkg_body_name(name: &str) -> Result<()> {
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
pub(super) fn zip_err(e: zip::result::ZipError) -> Error {
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
