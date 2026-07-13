//! Read orchestration for verified, cipher-neutral TN log access.

use std::path::Path;

use serde_json::{Map, Value};

use crate::{Error, Result};

use super::{
    FlatEntry, OnInvalid, ReadContext, ReadCursorV1, ReadDecision, ReadEntry, ReadRejectReason,
    ReadReport, ReadTrustPolicy, Runtime, SecureEntry, SecureReadOptions, ValidFlags, VerifyMode,
};

mod decrypt;
mod foreign;
mod policy;
mod projection;
mod record;
mod source;

use decrypt::GroupDecryptors;
use foreign::{
    is_foreign_log, read_foreign_log, read_foreign_with_validity, read_log_with_decryptors,
};
pub(crate) use foreign::{read_recipient_rows, RecipientRow};
use projection::{flat_in_current_run, insert_validity_metadata, secure_entry_from_flat};

pub use projection::flatten_raw_entry;
pub(crate) use projection::{apply_schema_defaults, merge_envelope};
pub use source::{canonical_file_source_id, canonical_source_id, file_source_id};

impl Runtime {
    /// Read verified current-run entries in the flat SDK shape.
    pub fn read(&self) -> Result<Vec<FlatEntry>> {
        Ok(self
            .read_verified_flat()?
            .into_iter()
            .filter(|entry| flat_in_current_run(entry, &self.run_id))
            .collect())
    }

    /// Read verified entries from every run in the flat SDK shape.
    pub fn read_all_runs(&self) -> Result<Vec<FlatEntry>> {
        self.read_verified_flat()
    }

    fn read_verified_flat(&self) -> Result<Vec<FlatEntry>> {
        let options = SecureReadOptions::default();
        let context = self.read_context_for_path(&self.log_path, None);
        let policy = self.default_read_policy(VerifyMode::Auto)?;
        let mut entries = self
            .read_with_policy(&options, &policy, &context, None)?
            .entries;
        for entry in &mut entries {
            entry.remove("_valid");
        }
        Ok(entries)
    }

    /// Read all runs with validity metadata while retaining invalid rows.
    pub fn read_with_verify(&self) -> Result<Vec<FlatEntry>> {
        let options = SecureReadOptions::default();
        let context = self.read_context_for_path(&self.log_path, None);
        let policy = self.default_read_policy(VerifyMode::Disabled)?;
        Ok(self
            .read_with_policy(&options, &policy, &context, None)?
            .entries)
    }

    /// Scan one source under a frozen trust policy.
    pub fn read_with_policy(
        &self,
        options: &SecureReadOptions,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<FlatEntry>> {
        let path = self.resolve_read_source_path(options.log_path.as_deref());
        let context = self.read_context_for_path(&path, context.required_group.clone());
        let raw = self.read_policy_records(&path, policy, &context, cursor)?;
        Ok(project_read_report(raw))
    }

    fn read_policy_records(
        &self,
        path: &Path,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
        if self.foreign_source(path)? {
            return read_foreign_with_validity(self, path, policy, context, cursor);
        }
        self.scan_file_with_policy(path, policy, context, cursor)
    }

    /// Snapshot receiver-local facts used to resolve the attached log policy.
    pub fn local_read_context(&self) -> ReadContext {
        self.read_context_for_path(&self.log_path, None)
    }

    /// Read verified entries with the strict/skip/forensic compatibility API.
    #[allow(clippy::needless_pass_by_value)]
    pub fn secure_read(&self, options: SecureReadOptions) -> Result<Vec<SecureEntry>> {
        let path = self.resolve_read_source_path(options.log_path.as_deref());
        let context = self.read_context_for_path(&path, None);
        let verify = verify_mode_for_invalid_action(options.on_invalid);
        let policy = self.default_read_policy(verify)?;
        let report = self.read_with_policy(&options, &policy, &context, None)?;
        let forensic = options.on_invalid == OnInvalid::Forensic;
        Ok(report
            .entries
            .into_iter()
            .map(|entry| secure_entry_from_flat(entry, forensic))
            .collect())
    }

    /// Read every entry as envelope plus plaintext-per-group without applying
    /// writer trust. Prefer [`Runtime::read`] for application data.
    pub fn read_raw(&self) -> Result<Vec<ReadEntry>> {
        self.read_from(&self.log_path)
    }

    /// Read every entry paired with validity flags.
    pub fn read_raw_with_validity(&self) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        self.read_from_with_validity(&self.log_path)
    }

    /// Read an explicit source and attach validity flags.
    pub fn read_from_with_validity(&self, path: &Path) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        if !self.storage.exists(path) {
            return Ok(Vec::new());
        }
        let context = self.read_context_for_path(path, None);
        let policy = self.default_read_policy(VerifyMode::Disabled)?;
        Ok(self
            .read_policy_records(path, &policy, &context, None)?
            .entries)
    }

    /// Read an explicit source without applying writer trust, selecting
    /// configured or foreign decryptors. This is a low-level forensic helper;
    /// application reads should use [`Runtime::read_with_policy`].
    pub fn read_from(&self, path: &Path) -> Result<Vec<ReadEntry>> {
        if !self.storage.exists(path) {
            return Ok(Vec::new());
        }
        if self.foreign_source(path)? {
            return read_foreign_log(path, &self.keystore, &self.storage);
        }
        let decryptors = GroupDecryptors::from_runtime(self);
        read_log_with_decryptors(path, &self.storage, &decryptors)
    }

    fn foreign_source(&self, path: &Path) -> Result<bool> {
        is_foreign_log(
            path,
            &self.log_path,
            self.device.did(),
            &self.keystore,
            &self.storage,
        )
    }

    fn emit_tampered_row_skipped(
        &self,
        entry: &ReadEntry,
        reasons: &[ReadRejectReason],
    ) -> Result<()> {
        let mut fields = tampered_row_fields(entry);
        fields.insert(
            "invalid_reasons".into(),
            Value::Array(
                reasons
                    .iter()
                    .map(|reason| Value::String(reason.as_str().to_owned()))
                    .collect(),
            ),
        );
        self.emit("warning", "tn.read.tampered_row_skipped", fields)
    }
}

fn verify_mode_for_invalid_action(action: OnInvalid) -> VerifyMode {
    match action {
        OnInvalid::Raise => VerifyMode::Raise,
        OnInvalid::Skip => VerifyMode::Skip,
        OnInvalid::Forensic => VerifyMode::Disabled,
    }
}

fn project_read_report(report: ReadReport<(ReadEntry, ValidFlags)>) -> ReadReport<FlatEntry> {
    let entries = report
        .entries
        .into_iter()
        .map(|(entry, validity)| {
            let mut flat = flatten_raw_entry(&entry, false);
            insert_validity_metadata(&mut flat, &validity);
            flat
        })
        .collect();
    ReadReport {
        entries,
        scanned: report.scanned,
        yielded: report.yielded,
        skipped: report.skipped,
        cursor: report.cursor,
    }
}

pub(super) fn emit_skip_event_best_effort(
    runtime: &Runtime,
    entry: &ReadEntry,
    reasons: &[ReadRejectReason],
) {
    let event_type = envelope_string(entry, "event_type");
    if event_type == "tn.read.tampered_row_skipped" {
        return;
    }
    if let Err(error) = runtime.emit_tampered_row_skipped(entry, reasons) {
        log::warn!("tn.read.tampered_row_skipped emit failed: {error}");
    }
}

fn tampered_row_fields(entry: &ReadEntry) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert(
        "envelope_event_id".into(),
        Value::String(envelope_string(entry, "event_id").to_owned()),
    );
    fields.insert(
        "envelope_device_identity".into(),
        Value::String(envelope_string(entry, "device_identity").to_owned()),
    );
    fields.insert(
        "envelope_event_type".into(),
        Value::String(envelope_string(entry, "event_type").to_owned()),
    );
    fields.insert(
        "envelope_sequence".into(),
        entry
            .envelope
            .get("sequence")
            .cloned()
            .unwrap_or(Value::Null),
    );
    fields
}

fn envelope_string<'a>(entry: &'a ReadEntry, name: &str) -> &'a str {
    entry
        .envelope
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
}

pub(super) fn read_rejection_error(entry: &ReadEntry, decision: &ReadDecision) -> Error {
    let reason = decision
        .first_reason()
        .map_or("record_invalid", ReadRejectReason::as_str);
    Error::Malformed {
        kind: "verification",
        reason: format!(
            "tn.read_with_policy: envelope event_type={:?} event_id={:?} rejected: {reason}",
            envelope_string(entry, "event_type"),
            envelope_string(entry, "event_id")
        ),
    }
}
