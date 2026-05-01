//! `fs.drop` handler — write `.tnpkg` admin snapshots to a watched dir.
//!
//! Mirrors `python/tn/handlers/fs_drop.py`. On each accepted emit (an
//! envelope whose `event_type` starts with `tn.`), build an admin-log
//! snapshot via [`crate::Runtime::export`] and place it in `out_dir`.
//! A peer's [`super::FsScanHandler`] (or any other process) consumes
//! it via `tn.absorb`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value as JsonValue;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::handlers::spec::{self, FilterSpec, HandlerSpec};
use crate::runtime_export::ExportOptions;
use crate::tnpkg::{read_tnpkg, ManifestKind, TnpkgSource};
use crate::{Error, Result, Runtime};

use super::TnHandler;

/// Default filename template (mirrors Python `DEFAULT_FILENAME_TEMPLATE`).
pub const DEFAULT_FILENAME_TEMPLATE: &str =
    "snapshot_{ceremony_id}_{date}_{head_row_hash:short}.tnpkg";

const DATE_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

const TMP_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second][subsecond digits:6]");

/// Drop `.tnpkg` admin snapshots into a local watched directory.
pub struct FsDropHandler {
    name: String,
    out_dir: PathBuf,
    on_types: Option<HashSet<String>>,
    scope: String,
    filename_template: String,
    filter: FilterSpec,
    runtime: Arc<Runtime>,
    state: Mutex<DropState>,
}

#[derive(Default)]
struct DropState {
    last_shipped_head: Option<String>,
}

impl FsDropHandler {
    /// Build from a parsed [`HandlerSpec`].
    ///
    /// # Errors
    /// `Error::InvalidConfig` when `trigger` is unsupported (only
    /// `on_emit` is implemented today, mirroring Python).
    pub fn from_spec(
        spec: &HandlerSpec,
        runtime: Arc<Runtime>,
        yaml_dir: &Path,
    ) -> Result<Self> {
        let trigger = spec::str_field(&spec.raw, "trigger").unwrap_or("on_emit");
        if trigger != "on_emit" {
            return Err(Error::InvalidConfig(format!(
                "fs.drop: trigger={trigger:?} not supported yet; only 'on_emit' is implemented."
            )));
        }
        let out_dir_str = spec::str_field(&spec.raw, "out_dir").unwrap_or("./.tn/outbox");
        let out_dir = spec::resolve_path(out_dir_str, yaml_dir);
        let scope = spec::str_field(&spec.raw, "scope")
            .unwrap_or("admin")
            .to_string();
        let filename_template = spec::str_field(&spec.raw, "filename_template")
            .unwrap_or(DEFAULT_FILENAME_TEMPLATE)
            .to_string();
        let on_types = spec
            .raw
            .get("on")
            .and_then(JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect::<HashSet<_>>()
            });
        Ok(Self {
            name: spec.name.clone(),
            out_dir,
            on_types,
            scope,
            filename_template,
            filter: spec.filter.clone(),
            runtime,
            state: Mutex::new(DropState::default()),
        })
    }

    /// Direct constructor used by tests.
    pub fn new(
        name: impl Into<String>,
        out_dir: PathBuf,
        runtime: Arc<Runtime>,
        on_types: Option<Vec<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            out_dir,
            on_types: on_types.map(|v| v.into_iter().collect()),
            scope: "admin".into(),
            filename_template: DEFAULT_FILENAME_TEMPLATE.into(),
            filter: FilterSpec::default(),
            runtime,
            state: Mutex::new(DropState::default()),
        }
    }

    /// Set a custom filename template (test seam).
    #[must_use]
    pub fn with_filename_template(mut self, tpl: impl Into<String>) -> Self {
        self.filename_template = tpl.into();
        self
    }

    fn drop_snapshot_inner(&self, _envelope: &JsonValue) -> Result<Option<PathBuf>> {
        std::fs::create_dir_all(&self.out_dir).map_err(Error::Io)?;
        let now = OffsetDateTime::now_utc();
        let tmp_stamp = now
            .format(TMP_FMT)
            .map_err(|e| Error::InvalidConfig(format!("fs.drop: tmp filename format: {e}")))?;
        let tmp_path = self.out_dir.join(format!("snapshot_inflight_{tmp_stamp}.tnpkg"));

        let opts = ExportOptions {
            kind: Some(ManifestKind::AdminLogSnapshot),
            scope: Some(self.scope.clone()),
            ..ExportOptions::default()
        };
        // export writes the file at tmp_path; on failure, mirror Python
        // and propagate.
        if let Err(e) = self.runtime.export(&tmp_path, opts) {
            log::warn!("[{}] fs.drop: export failed: {e}", self.name);
            return Err(e);
        }

        let bytes = std::fs::read(&tmp_path).map_err(Error::Io)?;
        let (manifest, _body) = read_tnpkg(TnpkgSource::Bytes(&bytes))?;

        let head = manifest.head_row_hash.clone();
        {
            let mut guard = self.state.lock().expect("fs_drop state mutex");
            if let (Some(last), Some(current)) = (&guard.last_shipped_head, &head) {
                if last == current {
                    let _ = std::fs::remove_file(&tmp_path);
                    log::debug!("[{}] fs.drop: head {current} unchanged; skip", self.name);
                    return Ok(None);
                }
            }
            // We're going to ship — reserve the head value before we lose
            // the lock so a concurrent emit can't double-ship.
            guard.last_shipped_head.clone_from(&head);
        }

        let final_name = format_filename(
            &self.filename_template,
            &manifest.ceremony_id,
            head.as_deref(),
            &manifest.from_did,
        );
        let mut final_path = self.out_dir.join(&final_name);
        if final_path.exists() {
            let suffix = OffsetDateTime::now_utc()
                .format(TMP_FMT)
                .map_err(|e| Error::InvalidConfig(format!("fs.drop: collision suffix: {e}")))?;
            let stem = final_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("snapshot");
            let ext = final_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("tnpkg");
            final_path = self.out_dir.join(format!("{stem}__{suffix}.{ext}"));
        }
        std::fs::rename(&tmp_path, &final_path).map_err(Error::Io)?;

        log::info!(
            "[{}] fs.drop: wrote snapshot {} (head={:?})",
            self.name,
            final_path.display(),
            head
        );
        Ok(Some(final_path))
    }

    /// Public test seam: trigger one snapshot manually.
    ///
    /// # Errors
    /// Surfaces export / IO errors.
    pub fn drop_snapshot(&self, envelope: &JsonValue) -> Result<Option<PathBuf>> {
        self.drop_snapshot_inner(envelope)
    }

    fn passes_on_allowlist(&self, envelope: &JsonValue) -> bool {
        let et = envelope
            .get("event_type")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if !et.starts_with("tn.") {
            return false;
        }
        if let Some(set) = &self.on_types {
            if !set.contains(et) {
                return false;
            }
        }
        true
    }
}

impl TnHandler for FsDropHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, envelope: &JsonValue) -> bool {
        self.filter.matches(envelope) && self.passes_on_allowlist(envelope)
    }
    fn emit(&self, envelope: &JsonValue, _raw_line: &[u8]) {
        if let Err(e) = self.drop_snapshot_inner(envelope) {
            log::warn!("[{}] fs.drop emit failed: {e}", self.name);
        }
    }
    fn close(&self) {}
}

fn short_hash(rh: Option<&str>) -> String {
    match rh {
        Some(r) if !r.is_empty() => r
            .strip_prefix("sha256:")
            .unwrap_or(r)
            .chars()
            .take(12)
            .collect(),
        _ => "noop".into(),
    }
}

fn format_filename(
    template: &str,
    ceremony_id: &str,
    head_row_hash: Option<&str>,
    from_did: &str,
) -> String {
    let head = head_row_hash.unwrap_or("").to_string();
    let head_short = short_hash(head_row_hash);
    let date = OffsetDateTime::now_utc()
        .format(DATE_FMT)
        .unwrap_or_else(|_| "00000000T000000Z".into());
    let mut out = template.to_string();
    // Order matters: `{head_row_hash:short}` is a strict superset of
    // `{head_row_hash}`, replace the longer form first.
    out = out.replace("{head_row_hash:short}", &head_short);
    out = out.replace("{head_row_hash}", &head);
    out = out.replace("{ceremony_id}", ceremony_id);
    out = out.replace("{date}", &date);
    out = out.replace("{from_did}", from_did);
    sanitize_filename(&out)
}

const DISALLOWED: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if DISALLOWED.contains(&c) { '_' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_handles_sha256_prefix() {
        assert_eq!(
            short_hash(Some("sha256:abcdef0123456789ffff")),
            "abcdef012345"
        );
        assert_eq!(short_hash(None), "noop");
        assert_eq!(short_hash(Some("")), "noop");
    }

    #[test]
    fn template_substitutes_known_placeholders() {
        let head = "sha256:deadbeefcafebabe1234";
        let name = format_filename(
            "snap_{ceremony_id}_{head_row_hash:short}.tnpkg",
            "cer1",
            Some(head),
            "did:key:zABC",
        );
        assert!(name.starts_with("snap_cer1_deadbeefcafe"), "{name}");
        assert!(
            std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tnpkg"))
        );
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize_filename("a/b\\c:d.tnpkg"), "a_b_c_d.tnpkg");
    }
}
