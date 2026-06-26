//! Small leaf helpers shared across the `runtime` submodules: timestamp
//! formatting, the SHA-256 digest used for kit fingerprints, and
//! event-type validation.
//!
//! The cross-platform path helpers (`resolve`, `is_absolute_xplat_path`)
//! moved to [`crate::pathutil`] once non-runtime modules needed them; they
//! are re-exported here so the runtime submodules keep importing them via
//! `super::util`.
//!
//! None of these touch [`Runtime`](super::Runtime) state; they are pure
//! functions factored out so the init / write / read / admin modules can
//! all reach them without duplicating the logic.

use time::OffsetDateTime;

use crate::{Error, Result};

// Path resolution is host-agnostic and shared beyond `runtime`, so it
// lives in `crate::pathutil`. Re-exported so `super::util::{resolve,
// is_absolute_xplat_path}` keeps resolving for the runtime submodules.
pub(crate) use crate::pathutil::{is_absolute_xplat_path, resolve};

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
