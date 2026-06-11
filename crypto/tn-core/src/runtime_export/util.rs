//! Small shared utilities for the export / absorb body builders.
//!
//! [`now_iso_millis`] formats the manifest timestamp; [`sha2_256`] hashes kit
//! bytes for the bundle manifest. Both are pure and stateless, factored out so
//! the seed builders and the front-door `impl` can share one implementation.

use time::OffsetDateTime;

pub(super) fn now_iso_millis() -> String {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]+00:00"
    );
    now.format(&fmt)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000+00:00".into())
}

pub(super) fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
