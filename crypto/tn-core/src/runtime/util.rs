//! Small leaf helpers shared across the `runtime` submodules: timestamp
//! formatting, the SHA-256 digest used for kit fingerprints, event-type
//! validation, and the cross-platform path helpers.
//!
//! None of these touch [`Runtime`](super::Runtime) state; they are pure
//! functions factored out so the init / write / read / admin modules can
//! all reach them without duplicating the logic.

use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::{Error, Result};

pub(crate) fn current_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    // "2026-04-21T12:00:00.000000Z": microseconds, Z suffix. Matches Python.
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    );
    now.format(&fmt).expect("formatting infallible")
}

/// RFC-3339 timestamp matching Python's `datetime.now(tz.utc).isoformat()`
/// shape with offset suffix `+00:00`. Used by vault_link / vault_unlink so
/// the canonical row matches the Python emitter.
pub(crate) fn current_timestamp_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]+00:00"
    );
    now.format(&fmt).expect("formatting infallible")
}

pub(crate) fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub(crate) fn validate_event_type(et: &str) -> Result<()> {
    if et.is_empty() {
        return Err(Error::InvalidConfig("event_type empty".into()));
    }
    if !et
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(Error::InvalidConfig(format!(
            "event_type has invalid chars: {et:?}"
        )));
    }
    Ok(())
}

pub(crate) fn resolve(base: &Path, p: &Path) -> PathBuf {
    if is_absolute_xplat_path(p) {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Cross-platform absolute-path test. Mirrors
/// `config::is_absolute_xplat` but works on `&Path` so callers in the
/// runtime don't have to round-trip through a string. Required for
/// wasm32 hosts on Windows where `Path::is_absolute()` follows Unix
/// rules and would mis-classify `C:\…` as relative, causing
/// `extends:`-resolved paths to double-join.
pub(crate) fn is_absolute_xplat_path(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    let s = p.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() >= 3 {
        let drive = bytes[0];
        if drive.is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\')
        {
            return true;
        }
    }
    false
}
