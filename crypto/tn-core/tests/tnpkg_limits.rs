//! Resource-limit guards for the `.tnpkg` reader.
//!
//! Mirrors the Python `_enforce_zip_limits` caps (see `python/tn/tnpkg.py`):
//! an untrusted package reaches `read_tnpkg` via watched `fs.scan` inboxes,
//! `vault_push`, and the Python `absorb` wheel, so a malicious archive must
//! not be able to exhaust memory before its manifest signature is checked.

use std::io::{Cursor, Write};

use tn_core::tnpkg::{read_tnpkg, TnpkgSource};
use tn_core::Error;
use zip::write::SimpleFileOptions;

fn stored() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
}

fn deflated() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)
}

/// Build a zip whose central directory advertises `n` entries.
fn zip_with_entry_count(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        for i in 0..n {
            zw.start_file(format!("body/e{i}.bin"), stored()).unwrap();
            zw.write_all(b"x").unwrap();
        }
        zw.finish().unwrap();
    }
    buf
}

#[test]
fn rejects_entry_flood() {
    // One past the cap must be refused on metadata alone (no manifest needed —
    // the sweep runs before the manifest is parsed).
    let bytes = zip_with_entry_count(tn_core::tnpkg::MAX_PKG_ENTRY_COUNT + 1);
    let err = read_tnpkg(TnpkgSource::Bytes(&bytes)).unwrap_err();
    match err {
        Error::Malformed { reason, .. } => {
            assert!(
                reason.contains("entries"),
                "expected an entry-count rejection, got: {reason}"
            );
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn accepts_entry_count_at_cap() {
    // Exactly at the cap must pass the entry-count check (it then fails later
    // for a different reason — missing manifest — which proves the count guard
    // did not trip).
    let bytes = zip_with_entry_count(tn_core::tnpkg::MAX_PKG_ENTRY_COUNT);
    let err = read_tnpkg(TnpkgSource::Bytes(&bytes)).unwrap_err();
    match err {
        Error::Malformed { reason, .. } => assert!(
            reason.contains("manifest"),
            "at the cap the count guard must not trip; expected a manifest error, got: {reason}"
        ),
        other => panic!("expected Malformed (missing manifest), got {other:?}"),
    }
}

#[test]
fn rejects_compression_ratio_bomb() {
    // A few MiB of zeros DEFLATE down to a tiny blob: the classic zip bomb.
    // Must be refused before the body is inflated into memory.
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        zw.start_file("body/bomb.bin", deflated()).unwrap();
        zw.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        zw.finish().unwrap();
    }
    let err = read_tnpkg(TnpkgSource::Bytes(&buf)).unwrap_err();
    match err {
        Error::Malformed { reason, .. } => assert!(
            reason.contains("ratio") || reason.contains("compression"),
            "expected a compression-ratio rejection, got: {reason}"
        ),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_oversized_manifest() {
    // A manifest larger than the manifest cap must be refused before parse.
    let big = vec![b' '; tn_core::tnpkg::MAX_MANIFEST_BYTES as usize + 1];
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        // Store (not deflate) so the ratio guard does not trip first; this
        // isolates the manifest-size cap.
        zw.start_file("manifest.json", stored()).unwrap();
        zw.write_all(&big).unwrap();
        zw.finish().unwrap();
    }
    let err = read_tnpkg(TnpkgSource::Bytes(&buf)).unwrap_err();
    match err {
        Error::Malformed { reason, .. } => {
            let mentions_manifest_size = reason.contains("manifest") && reason.contains("size");
            let mentions_exceeds = reason.contains("exceeds");
            assert!(
                mentions_manifest_size || mentions_exceeds,
                "expected a manifest-size rejection, got: {reason}"
            );
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}
