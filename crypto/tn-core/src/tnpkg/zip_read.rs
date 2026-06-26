//! Zip reader for the `.tnpkg` container.
//!
//! The inverse of [`zip_write`](super::zip_write): [`read_tnpkg`] parses
//! `manifest.json` plus every `body/...` entry out of a `.tnpkg` archive
//! (from a path or in-memory bytes via [`TnpkgSource`](super::TnpkgSource)),
//! enforcing that the archive holds exactly one `manifest.json` and only
//! well-formed body paths. It does **not** verify the signature — the caller
//! runs [`verify_manifest`](super::verify_manifest) on the returned manifest.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};

use serde_json::Value;

use super::zip_write::validate_tnpkg_body_name;
use super::{Manifest, TnpkgSource};
use crate::{Error, Result};

// --------------------------------------------------------------------------
// `.tnpkg` resource limits
//
// An untrusted `.tnpkg` reaches [`read_tnpkg`] through watched `fs.scan`
// inboxes, the vault-push path, and the Python `absorb` wheel, so a malicious
// archive must not be able to exhaust memory before its manifest signature is
// even checked. These caps mirror `_enforce_zip_limits` in `tn/tnpkg.py`
// one-for-one; keep the two in lockstep. They are deliberately generous
// relative to real packages (a full_keystore backup is a manifest plus a
// handful of small key files) — the point is to bound blast radius, not to be
// tight.
// --------------------------------------------------------------------------

/// Max number of zip entries. A real `.tnpkg` is a manifest plus a small
/// handful of body members; thousands of entries is an attack, not a backup.
pub const MAX_PKG_ENTRY_COUNT: usize = 2000;

/// Max uncompressed size of `manifest.json`. Real manifests are a few KiB even
/// with a per-recipient `recipient_wraps` array; 2 MiB is far past any honest
/// manifest while still cheap to parse.
pub const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Max uncompressed size of any single entry. Bounds the largest single
/// allocation a body read can trigger.
pub const MAX_PKG_ENTRY_BYTES: u64 = 128 * 1024 * 1024;

/// Max total uncompressed size across all entries. Bounds the aggregate memory
/// a full read of the archive can consume.
pub const MAX_PKG_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// Max per-entry compression ratio (uncompressed / compressed). `.tnpkg` is
/// written `Stored`, so legitimate packages have a ratio of ~1.0. A high ratio
/// is the signature of a zip bomb: a few KiB on disk inflating to gigabytes.
pub const MAX_PKG_COMPRESSION_RATIO: u64 = 200;

/// Read a `.tnpkg` and return the parsed manifest plus its body map (entry name
/// → bytes).
///
/// Parses `manifest.json` and collects every `body/...` entry, validating that
/// the archive contains exactly one `manifest.json` and only well-formed body
/// paths. Does **not** verify the signature — the caller runs [`verify_manifest`](super::verify_manifest)
/// on the returned manifest (as [`crate::Runtime::absorb`] does). Inverse of
/// [`write_tnpkg`](super::write_tnpkg) / [`write_tnpkg_bytes`](super::write_tnpkg_bytes).
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

/// Bound a `.tnpkg` using zip central-directory metadata **only** — reads no
/// entry bytes. Every check is against the uncompressed/compressed sizes the
/// `zip` crate exposes from the central directory without inflating anything,
/// so this is the cheap pre-flight that stops zip bombs, oversized entries, and
/// entry floods before any read allocates memory. Mirrors `_enforce_zip_limits`
/// in `tn/tnpkg.py`; keep the two in lockstep.
fn enforce_zip_limits<R: Read + Seek>(zip_r: &mut zip::ZipArchive<R>) -> Result<()> {
    let count = zip_r.len();
    if count > MAX_PKG_ENTRY_COUNT {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "`.tnpkg` has {count} entries, exceeding the limit of \
                 {MAX_PKG_ENTRY_COUNT} (possible zip bomb / malformed archive)"
            ),
        });
    }
    let mut total: u64 = 0;
    for i in 0..count {
        let entry = zip_r.by_index(i).map_err(|e| Error::Malformed {
            kind: "tnpkg zip",
            reason: e.to_string(),
        })?;
        let size = entry.size();
        let compressed = entry.compressed_size();
        if entry.name() == "manifest.json" && size > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: format!(
                    "`.tnpkg` manifest.json declares an uncompressed size of \
                     {size} bytes, exceeding the manifest size limit of \
                     {MAX_MANIFEST_BYTES} bytes"
                ),
            });
        }
        if size > MAX_PKG_ENTRY_BYTES {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: format!(
                    "`.tnpkg` entry {:?} declares an uncompressed size of {size} \
                     bytes, exceeding the per-entry limit of {MAX_PKG_ENTRY_BYTES} \
                     bytes (possible zip bomb)",
                    entry.name()
                ),
            });
        }
        // Compression-ratio guard: a tiny compressed blob inflating to a huge
        // buffer is the classic zip-bomb shape. Legitimate `.tnpkg` files are
        // Stored (ratio ~1).
        let ratio = size / compressed.max(1);
        if ratio > MAX_PKG_COMPRESSION_RATIO {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: format!(
                    "`.tnpkg` entry {:?} has a compression ratio of {ratio}x \
                     ({size} bytes from {compressed}), exceeding the limit of \
                     {MAX_PKG_COMPRESSION_RATIO}x (possible zip bomb)",
                    entry.name()
                ),
            });
        }
        total = total.saturating_add(size);
        if total > MAX_PKG_TOTAL_BYTES {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: format!(
                    "`.tnpkg` total uncompressed size exceeds the limit of \
                     {MAX_PKG_TOTAL_BYTES} bytes at entry {:?} (possible zip bomb)",
                    entry.name()
                ),
            });
        }
    }
    Ok(())
}

fn read_tnpkg_inner<R: Read + Seek>(reader: R) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let mut zip_r = zip::ZipArchive::new(reader).map_err(|e| Error::Malformed {
        kind: "tnpkg zip",
        reason: e.to_string(),
    })?;

    // Cheap metadata-only pre-flight: reject bombs / floods before any read.
    enforce_zip_limits(&mut zip_r)?;

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
    // Pull manifest first. The `.take` is belt-and-suspenders beyond the
    // metadata sweep: if a malicious central directory under-declares a size,
    // the read still cannot allocate past the cap (it truncates, and the parse
    // / signature check downstream then fails).
    let manifest_doc: Value = {
        let mf = zip_r
            .by_name("manifest.json")
            .map_err(|e| Error::Malformed {
                kind: "tnpkg zip",
                reason: e.to_string(),
            })?;
        let mut buf = Vec::new();
        mf.take(MAX_MANIFEST_BYTES).read_to_end(&mut buf)?;
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
        let entry = zip_r.by_name(&name).map_err(|e| Error::Malformed {
            kind: "tnpkg zip",
            reason: e.to_string(),
        })?;
        let mut buf = Vec::new();
        entry.take(MAX_PKG_ENTRY_BYTES).read_to_end(&mut buf)?;
        body.insert(name, buf);
    }
    Ok((manifest, body))
}
