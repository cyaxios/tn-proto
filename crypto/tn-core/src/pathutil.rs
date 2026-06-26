//! Cross-platform path resolution shared across the core.
//!
//! [`std::path::Path::is_absolute`] follows the *host* target's rules, so
//! on wasm32 (and on Unix) a Windows `C:\…` path is mis-classified as
//! relative. A ceremony authored on Windows records an absolute
//! `logs.path` / handler path; when that ceremony runs from the wasm
//! runtime the stdlib check would treat that path as relative and join it
//! onto `yaml_dir`, producing a doubled `…/streams/C:\…/logs`. These
//! helpers treat a leading `<drive>:[\\/]` as absolute on every target so
//! such paths resolve correctly regardless of where the runtime runs.
//! Symmetrically, a leading `/` (Unix root) is treated as absolute on
//! Windows too, where `Path::is_absolute()` rejects it for lacking a
//! drive.
//!
//! Both functions are pure and host-agnostic, which is why they live at
//! the crate root rather than inside `runtime`: `path_template`,
//! `handlers`, `admin_cache`, and the runtime all resolve yaml-relative
//! paths and must agree.

use std::path::{Path, PathBuf};

/// Resolve `p` against `base`, honoring absolute paths cross-platform: an
/// absolute `p` (Unix `/…` or Windows `<drive>:[\\/]…`) is returned
/// unchanged; a relative `p` is joined onto `base`.
pub(crate) fn resolve(base: &Path, p: &Path) -> PathBuf {
    if is_absolute_xplat_path(p) {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Cross-platform absolute-path test. Accepts anything the host stdlib
/// considers absolute, plus two forms the stdlib only recognizes on
/// *some* targets:
///   - a leading `/` (Unix root): `Path::is_absolute()` rejects this on
///     Windows for lacking a drive, so a Unix-authored `/var/…` path
///     would otherwise be re-joined when the ceremony runs there;
///   - a Windows `<drive>:[\\/]` prefix (e.g. `C:\` or `C:/`): wasm32 and
///     Unix hosts reject this, which is the double-join bug this module
///     exists to prevent.
///
/// A bare drive-relative path like `c:foo` (no separator after the colon)
/// stays relative, matching the platform definition.
pub(crate) fn is_absolute_xplat_path(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    let s = p.to_string_lossy();
    let bytes = s.as_bytes();
    // Unix root: `/…` (absolute on Unix/wasm; a valid root on Windows).
    if bytes.first() == Some(&b'/') {
        return true;
    }
    // Windows drive-absolute: `<drive>:[\\/]…`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_absolute_is_absolute() {
        assert!(is_absolute_xplat_path(Path::new("/var/log/tn.ndjson")));
    }

    #[test]
    fn windows_drive_absolute_on_every_target() {
        // The whole point of this helper: these are absolute even on Unix
        // and wasm32, where `Path::is_absolute()` returns false for them.
        assert!(is_absolute_xplat_path(Path::new("C:\\Users\\x\\logs")));
        assert!(is_absolute_xplat_path(Path::new("D:/data/logs")));
    }

    #[test]
    fn relative_paths_are_not_absolute() {
        assert!(!is_absolute_xplat_path(Path::new("logs/tn.ndjson")));
        assert!(!is_absolute_xplat_path(Path::new("./logs")));
        // Drive-relative (no separator after the colon) is not absolute.
        assert!(!is_absolute_xplat_path(Path::new("c:relative")));
    }

    #[test]
    fn resolve_joins_relative() {
        assert_eq!(
            resolve(Path::new("/cer"), Path::new("logs/tn.ndjson")),
            PathBuf::from("/cer/logs/tn.ndjson"),
        );
    }

    #[test]
    fn resolve_keeps_windows_absolute() {
        // Regression guard for the wasm32/Windows double-join bug: the
        // stdlib-only check would join this onto `base` on Unix/wasm.
        assert_eq!(
            resolve(Path::new("/cer"), Path::new("C:\\logs\\tn.ndjson")),
            PathBuf::from("C:\\logs\\tn.ndjson"),
        );
    }
}
