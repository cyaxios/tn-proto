//! Zip reader for the `.tnpkg` container.
//!
//! The inverse of [`zip_write`](super::zip_write): [`read_tnpkg`] parses
//! `manifest.json` plus every `body/...` entry out of a `.tnpkg` archive
//! (from a path or in-memory bytes via [`TnpkgSource`](super::TnpkgSource)),
//! enforcing that the archive holds exactly one `manifest.json` and only
//! well-formed body paths. [`read_tnpkg_verified`] is the fail-closed boundary
//! for consumers; [`read_tnpkg`] remains only for named legacy inspection that
//! does not parse, decrypt, or apply body state.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};

use serde_json::Value;

use super::zip_write::validate_tnpkg_body_name;
use super::{verify_manifest, verify_manifest_body_index, Manifest, TnpkgSource};
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

const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;

/// Read a `.tnpkg` and return the parsed manifest plus its body map (entry name
/// → bytes).
///
/// Parses `manifest.json` and collects every `body/...` entry, validating that
/// the archive contains exactly one `manifest.json` and only well-formed body
/// paths. Does **not** verify the signature or body index and must not be used
/// by code that parses, decrypts, or applies body state. Use
/// [`read_tnpkg_verified`] for that trust boundary. Inverse of
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
    match source {
        TnpkgSource::Path(p) => {
            if !p.exists() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("absorb: source path does not exist: {}", p.display()),
                )));
            }
            let mut file = File::open(p)?;
            validate_zip_metadata(&mut file)?;
            file.seek(SeekFrom::Start(0))?;
            read_tnpkg_inner(file, false)
        }
        TnpkgSource::Bytes(b) => {
            let mut cursor = Cursor::new(b);
            validate_zip_metadata(&mut cursor)?;
            cursor.seek(SeekFrom::Start(0))?;
            read_tnpkg_inner(cursor, false)
        }
    }
}

/// Read a `.tnpkg` through the fail-closed trust boundary.
///
/// Central-directory limits and member names are checked first, then only the
/// bounded manifest is read and its signature verified. Body entries are read
/// only after that signature succeeds, and the exact body index is verified
/// before any body bytes are returned to a caller.
#[allow(clippy::needless_pass_by_value)]
pub fn read_tnpkg_verified(
    source: TnpkgSource<'_>,
) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    match source {
        TnpkgSource::Path(p) => {
            if !p.exists() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("absorb: source path does not exist: {}", p.display()),
                )));
            }
            let mut file = File::open(p)?;
            validate_zip_metadata(&mut file)?;
            file.seek(SeekFrom::Start(0))?;
            read_tnpkg_inner(file, true)
        }
        TnpkgSource::Bytes(b) => {
            let mut cursor = Cursor::new(b);
            validate_zip_metadata(&mut cursor)?;
            cursor.seek(SeekFrom::Start(0))?;
            read_tnpkg_inner(cursor, true)
        }
    }
}

fn validate_zip_metadata<R: Read + Seek>(reader: &mut R) -> Result<()> {
    const EOCD_FIXED_BYTES: u64 = 22;
    const MAX_EOCD_BYTES: u64 = EOCD_FIXED_BYTES + u16::MAX as u64;
    const CENTRAL_HEADER_FIXED_BYTES: u64 = 46;

    let file_len = reader.seek(SeekFrom::End(0))?;
    let tail_len = file_len.min(MAX_EOCD_BYTES);
    reader.seek(SeekFrom::End(-(tail_len as i64)))?;
    let mut tail = vec![0u8; tail_len as usize];
    reader.read_exact(&mut tail)?;
    let relative_eocd = find_eocd(&tail).ok_or_else(|| Error::Malformed {
        kind: "tnpkg zip",
        reason: "missing EOCD with a comment that ends exactly at archive end".into(),
    })?;
    let eocd_offset = file_len - tail_len + relative_eocd as u64;

    let disk_number = read_u16(&tail, relative_eocd + 4);
    let central_directory_disk = read_u16(&tail, relative_eocd + 6);
    let entries_on_disk = read_u16(&tail, relative_eocd + 8);
    let entry_count = read_u16(&tail, relative_eocd + 10);
    let central_directory_size = read_u32(&tail, relative_eocd + 12);
    let central_directory_offset = read_u32(&tail, relative_eocd + 16);

    if disk_number == u16::MAX
        || central_directory_disk == u16::MAX
        || entries_on_disk == u16::MAX
        || entry_count == u16::MAX
        || central_directory_size == u32::MAX
        || central_directory_offset == u32::MAX
    {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: "ZIP64 sentinel metadata is unsupported for `.tnpkg` archives".into(),
        });
    }
    if disk_number != 0 || central_directory_disk != 0 {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: "multi-disk ZIP metadata is unsupported for `.tnpkg` archives".into(),
        });
    }
    if entries_on_disk != entry_count {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "inconsistent EOCD entry counts: disk declares {entries_on_disk}, archive declares {entry_count}"
            ),
        });
    }
    if entry_count as usize > MAX_PKG_ENTRY_COUNT {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "EOCD entry count declares {entry_count} entries, exceeding the limit of {MAX_PKG_ENTRY_COUNT}"
            ),
        });
    }

    let central_directory_size = u64::from(central_directory_size);
    let central_directory_offset = u64::from(central_directory_offset);
    if central_directory_size > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "central directory size {central_directory_size} exceeds the limit of {MAX_CENTRAL_DIRECTORY_BYTES} bytes"
            ),
        });
    }
    let central_directory_end = central_directory_offset
        .checked_add(central_directory_size)
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg zip",
            reason: "central directory metadata offset and size overflow".into(),
        })?;
    if central_directory_end > eocd_offset {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: "central directory metadata extends past the EOCD".into(),
        });
    }
    let minimum_directory_size = u64::from(entry_count) * CENTRAL_HEADER_FIXED_BYTES;
    if central_directory_size < minimum_directory_size {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "central directory metadata is truncated: {entry_count} entries require at least {minimum_directory_size} bytes, declared {central_directory_size}"
            ),
        });
    }

    reader.seek(SeekFrom::Start(central_directory_offset))?;
    let mut cursor = central_directory_offset;
    let mut manifest_count = 0usize;
    let mut names = HashSet::with_capacity(entry_count as usize);
    for _ in 0..entry_count {
        let fixed_end = cursor
            .checked_add(CENTRAL_HEADER_FIXED_BYTES)
            .filter(|end| *end <= central_directory_end)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg zip",
                reason: "central directory metadata is truncated within an entry header".into(),
            })?;
        let mut fixed = [0u8; CENTRAL_HEADER_FIXED_BYTES as usize];
        reader.read_exact(&mut fixed)?;
        if fixed[..4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: "central directory metadata has an invalid entry signature".into(),
            });
        }

        let name_len = u64::from(read_u16(&fixed, 28));
        let extra_len = u64::from(read_u16(&fixed, 30));
        let comment_len = u64::from(read_u16(&fixed, 32));
        let record_end = fixed_end
            .checked_add(name_len)
            .and_then(|end| end.checked_add(extra_len))
            .and_then(|end| end.checked_add(comment_len))
            .filter(|end| *end <= central_directory_end)
            .ok_or_else(|| Error::Malformed {
                kind: "tnpkg zip",
                reason: "central directory metadata is truncated within an entry".into(),
            })?;

        let mut name = vec![0u8; name_len as usize];
        reader.read_exact(&mut name)?;
        if !names.insert(name.clone()) {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: if name == b"manifest.json" {
                    "zip contains duplicate manifest.json entries; the .tnpkg format requires exactly one"
                        .into()
                } else {
                    format!(
                        "duplicate package member {:?}",
                        String::from_utf8_lossy(&name)
                    )
                },
            });
        }
        if name == b"manifest.json" {
            manifest_count += 1;
        }
        reader.seek(SeekFrom::Start(record_end))?;
        cursor = record_end;
    }
    if cursor != central_directory_end {
        return Err(Error::Malformed {
            kind: "tnpkg zip",
            reason: format!(
                "central directory metadata size is inconsistent: parsed {} bytes, declared {central_directory_size}",
                cursor - central_directory_offset
            ),
        });
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    const EOCD_FIXED_BYTES: usize = 22;

    if bytes.len() < EOCD_FIXED_BYTES {
        return None;
    }
    let min_start = bytes
        .len()
        .saturating_sub(EOCD_FIXED_BYTES + u16::MAX as usize);
    (min_start..=bytes.len() - EOCD_FIXED_BYTES)
        .rev()
        .find(|&i| {
            bytes[i..i + 4] == [0x50, 0x4b, 0x05, 0x06]
                && i.checked_add(EOCD_FIXED_BYTES)
                    .and_then(|end| end.checked_add(read_u16(bytes, i + 20) as usize))
                    == Some(bytes.len())
        })
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

fn read_tnpkg_inner<R: Read + Seek>(
    reader: R,
    verified: bool,
) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let mut zip_r = zip::ZipArchive::new(reader).map_err(|e| Error::Malformed {
        kind: "tnpkg zip",
        reason: e.to_string(),
    })?;

    // Cheap metadata-only pre-flight: reject bombs / floods before any read.
    enforce_zip_limits(&mut zip_r)?;

    let mut names = Vec::with_capacity(zip_r.len());
    let mut unique_names = HashSet::with_capacity(zip_r.len());
    for i in 0..zip_r.len() {
        let name = zip_r
            .by_index(i)
            .map_err(|e| Error::Malformed {
                kind: "tnpkg zip",
                reason: e.to_string(),
            })?
            .name()
            .to_string();
        if !unique_names.insert(name.clone()) {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: if name == "manifest.json" {
                    "zip contains duplicate manifest.json entries; the .tnpkg format requires exactly one"
                        .into()
                } else {
                    format!("duplicate package member {name:?}")
                },
            });
        }
        if name != "manifest.json" {
            validate_tnpkg_body_name(&name)?;
        }
        names.push(name);
    }
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
        mf.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: "manifest.json exceeded the bounded read limit".into(),
            });
        }
        serde_json::from_slice(&buf)?
    };
    let manifest = Manifest::from_json(&manifest_doc)?;
    if verified {
        verify_manifest(&manifest)?;
    }

    // Pull every other entry into the body map.
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for name in names {
        if name == "manifest.json" {
            continue;
        }
        let entry = zip_r.by_name(&name).map_err(|e| Error::Malformed {
            kind: "tnpkg zip",
            reason: e.to_string(),
        })?;
        let mut buf = Vec::new();
        entry.take(MAX_PKG_ENTRY_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_PKG_ENTRY_BYTES {
            return Err(Error::Malformed {
                kind: "tnpkg zip",
                reason: format!("body member {name:?} exceeded the bounded read limit"),
            });
        }
        body.insert(name, buf);
    }
    if verified {
        verify_manifest_body_index(&manifest, &body, true)?;
    }
    Ok((manifest, body))
}
