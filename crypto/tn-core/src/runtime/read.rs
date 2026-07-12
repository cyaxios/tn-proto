//! The read path: decode, decrypt, verify, and flatten the log back into
//! caller-facing entries.
//!
//! Holds the everyday reads ([`Runtime::read`] / [`Runtime::read_all_runs`]
//! / [`Runtime::read_with_verify`]), the audit-grade raw reads
//! ([`Runtime::read_raw`] / [`Runtime::read_raw_with_validity`] /
//! [`Runtime::read_from`] / [`Runtime::read_from_with_validity`]), the
//! fail-closed [`Runtime::secure_read`], and the projection helpers
//! ([`flatten_raw_entry`] and friends). The write side lives in the `emit`
//! submodule.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde_json::{Map, Value};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::{
    chain::{compute_row_hash, GroupInput, RowHashInput},
    log_file::LogFileReader,
    sealed_object::aad_bytes_for,
    signing::{signature_from_b64, DeviceKey},
    Error, Result,
};

use super::{
    CursorKind, FlatEntry, Instructions, OnInvalid, ReadContext, ReadCursorV1, ReadDecision,
    ReadEntry, ReadRecordState, ReadRejectReason, ReadReport, ReadTrustPolicy, Runtime,
    SecureEntry, SecureReadOptions, SourceCursorV1, ValidFlags, VerifyMode,
};

impl ReadTrustPolicy {
    /// Resolve context-sensitive defaults once, before scanning any rows.
    pub fn resolve(&self, context: &ReadContext) -> Result<Self> {
        let verify = match self.verify {
            VerifyMode::Auto => VerifyMode::Raise,
            mode => mode,
        };
        if verify == VerifyMode::Disabled && self.trusted_writers_supplied {
            return Err(Error::InvalidConfig(
                "verify=False cannot be combined with trusted_writers".into(),
            ));
        }

        let inferred_unsigned_profile = context.active
            && context.local_log
            && !context.detached
            && context.profile_sign == Some(false);
        let require_signature = self.require_signature.unwrap_or_else(|| {
            self.allow_unauthenticated
                .map_or(!inferred_unsigned_profile, |allow| !allow)
        });
        let allow_unauthenticated = self.allow_unauthenticated.unwrap_or(!require_signature);
        if require_signature == allow_unauthenticated {
            return Err(Error::InvalidConfig(
                "require_signature and allow_unauthenticated must express one consistent policy"
                    .into(),
            ));
        }
        for did in &self.trusted_writers {
            validate_trusted_writer_did(did)?;
        }

        Ok(Self {
            verify,
            require_signature: Some(require_signature),
            allow_unauthenticated: Some(allow_unauthenticated),
            trusted_writers: self.trusted_writers.clone(),
            trusted_writers_supplied: self.trusted_writers_supplied,
            allow_unknown_writers: self.allow_unknown_writers,
        })
    }

    /// Apply the frozen policy to one already-scanned record.
    #[must_use]
    pub fn evaluate(&self, record: &ReadRecordState, context: &ReadContext) -> ReadDecision {
        let mut reasons = Vec::new();
        if !record.record_valid {
            push_once(&mut reasons, ReadRejectReason::RecordInvalid);
            return ReadDecision {
                accepted: false,
                reasons,
                writer_authenticated: false,
                writer_authorized: false,
            };
        }

        let chain_required = read_chain_required(context);
        let row_hash_valid = !chain_required || (record.row_hash_present && record.row_hash_valid);
        if !row_hash_valid {
            push_once(&mut reasons, ReadRejectReason::RowHashInvalid);
        }
        let chain_valid = !chain_required || record.chain_valid;
        if !chain_valid {
            push_once(&mut reasons, ReadRejectReason::ChainInvalid);
        }

        let mut writer_authenticated = record.signature_present && record.signature_valid;
        if !record.signature_present {
            if self.require_signature == Some(true) {
                push_once(&mut reasons, ReadRejectReason::SignatureRequired);
            }
        } else if !record.signature_valid {
            push_once(&mut reasons, ReadRejectReason::SignatureInvalid);
        }

        let writer_trusted = record
            .writer_did
            .as_ref()
            .is_some_and(|did| self.trusted_writers.contains(did));
        if !writer_trusted && !self.allow_unknown_writers {
            push_once(&mut reasons, ReadRejectReason::WriterUntrusted);
        }
        if !record.aad_valid {
            push_once(&mut reasons, ReadRejectReason::AadInvalid);
        }
        if context
            .required_group
            .as_ref()
            .is_some_and(|group| !record.recipient_groups.contains(group))
        {
            push_once(&mut reasons, ReadRejectReason::NotARecipient);
        }

        let mut writer_authorized =
            writer_authenticated && writer_trusted && row_hash_valid && chain_valid;
        let accepted = match self.verify {
            VerifyMode::Disabled => {
                writer_authenticated = false;
                writer_authorized = false;
                reasons.iter().all(|reason| {
                    matches!(
                        reason,
                        ReadRejectReason::RowHashInvalid
                            | ReadRejectReason::ChainInvalid
                            | ReadRejectReason::SignatureRequired
                            | ReadRejectReason::SignatureInvalid
                            | ReadRejectReason::WriterUntrusted
                    )
                })
            }
            VerifyMode::Auto | VerifyMode::Raise | VerifyMode::Skip => {
                let allow_unauthenticated = self.allow_unauthenticated == Some(true);
                reasons.iter().all(|reason| {
                    allow_unauthenticated && *reason == ReadRejectReason::SignatureRequired
                })
            }
        };
        ReadDecision {
            accepted,
            reasons,
            writer_authenticated,
            writer_authorized,
        }
    }
}

fn push_once(reasons: &mut Vec<ReadRejectReason>, reason: ReadRejectReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn read_chain_required(context: &ReadContext) -> bool {
    !(context.active
        && context.local_log
        && !context.detached
        && context.profile_chain == Some(false))
}

fn validate_trusted_writer_did(did: &str) -> Result<()> {
    let Some(encoded) = did.strip_prefix("did:key:z") else {
        return Err(Error::InvalidConfig(format!(
            "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
        )));
    };
    let decoded = bs58::decode(encoded).into_vec().map_err(|_| {
        Error::InvalidConfig(format!(
            "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
        ))
    })?;
    if decoded.len() != 34
        || decoded[..2] != [0xed, 0x01]
        || bs58::encode(&decoded).into_string() != encoded
    {
        return Err(Error::InvalidConfig(format!(
            "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
        )));
    }
    Ok(())
}

/// Hash a canonical NUL-delimited source descriptor into its stable ID.
#[must_use]
pub fn canonical_source_id(descriptor: &[u8]) -> String {
    format!("source:sha256:{}", hex::encode(Sha256::digest(descriptor)))
}

/// Build the stable source ID for an already-joined file path.
///
/// Normalization is lexical and host-independent: both slash styles are
/// accepted, `.` / `..` components are folded, and only a Windows drive
/// letter is case-normalized. Filesystem canonicalization is deliberately
/// avoided so symlinks and nonexistent cursor sources remain deterministic.
#[must_use]
pub fn canonical_file_source_id(path: &str) -> String {
    let normalized = normalize_file_source_path(path);
    let mut descriptor = b"file\0".to_vec();
    descriptor.extend_from_slice(normalized.as_bytes());
    canonical_source_id(&descriptor)
}

fn normalize_file_source_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let slashed = slashed.strip_prefix("//?/").unwrap_or(&slashed);
    let (prefix, remainder) = if slashed.len() >= 3
        && slashed.as_bytes()[0].is_ascii_alphabetic()
        && slashed.as_bytes()[1] == b':'
        && slashed.as_bytes()[2] == b'/'
    {
        (
            format!("{}:/", slashed[..1].to_ascii_lowercase()),
            &slashed[3..],
        )
    } else if let Some(remainder) = slashed.strip_prefix("//") {
        ("//".to_owned(), remainder)
    } else if let Some(remainder) = slashed.strip_prefix('/') {
        ("/".to_owned(), remainder)
    } else {
        (String::new(), slashed)
    };

    let mut components: Vec<&str> = Vec::new();
    for component in remainder.split('/') {
        match component {
            ".." if components.last().is_some_and(|last| *last != "..") => {
                components.pop();
            }
            ".." if prefix.is_empty() => components.push(component),
            "" | "." | ".." => {}
            _ => components.push(component),
        }
    }
    format!("{prefix}{}", components.join("/"))
}

impl Runtime {
    /// Read this runtime's log, decrypting every group it holds a kit
    /// for, and return the entries as flat dicts. Backs `tn.read()`.
    ///
    /// **Default shape: flat dicts** ([`FlatEntry`]) per the 2026-04-25
    /// read-ergonomics spec. The six envelope basics (`timestamp`,
    /// `event_type`, `level`, `did`, `sequence`, `event_id`) plus every
    /// readable group's decrypted fields land at the top level.
    /// `_hidden_groups` / `_decrypt_errors` markers surface only when
    /// non-empty. The six reserved `tn.agents` field names DO appear in
    /// the flat dict by default; use [`Runtime::secure_read`] to lift them
    /// into a separate `instructions` block instead.
    ///
    /// **Scoped to the current run.** Only entries stamped with this
    /// process's `run_id` are returned, so a naive filter doesn't pick up
    /// rows from prior runs; use [`Runtime::read_all_runs`] for the full
    /// log history. This call verifies nothing — use
    /// [`Runtime::read_with_verify`] for the flat shape plus a `_valid`
    /// block, [`Runtime::secure_read`] for the fail-closed verified path,
    /// or [`Runtime::read_raw`] for the audit-grade `{envelope,
    /// plaintext_per_group}` shape.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::Error::Io) if the log can't be read, plus
    /// cipher / JSON errors. A malformed individual row does not abort the
    /// read — it surfaces as a `<parse-error>` sentinel entry.
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state lock is poisoned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::Runtime;
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::ephemeral()?;
    /// rt.info("page.viewed", serde_json::Map::new())?;
    /// for entry in rt.read()? {
    ///     println!("{} @ {}", entry["event_type"], entry["timestamp"]);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn read(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw()?;
        Ok(raw
            .into_iter()
            .map(|r| flatten_raw_entry(&r, false))
            .filter(|flat| flat_in_current_run(flat, &self.run_id))
            .collect())
    }

    /// Like [`Runtime::read`] but returns entries from EVERY run (not
    /// just the current process's `run_id`). Use for audit / compliance
    /// reports that span the whole log lifetime; everyday "show me what
    /// just happened" queries should stick with [`Runtime::read`] so a
    /// naive filter doesn't pull in entries from prior runs.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`].
    pub fn read_all_runs(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw()?;
        Ok(raw
            .into_iter()
            .map(|r| flatten_raw_entry(&r, false))
            .collect())
    }

    /// Like [`Runtime::read`] but adds a `_valid: {signature, row_hash,
    /// chain}` block to each flat dict per spec §1.3, so the caller can
    /// see per-entry verification results without dropping rows. Unlike
    /// [`Runtime::secure_read`] this is fail-*open*: invalid entries are
    /// still returned, just flagged. Spans every run.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`].
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_with_verify(&self) -> Result<Vec<FlatEntry>> {
        let options = SecureReadOptions::default();
        let context = self.read_context_for_path(&self.log_path, None);
        let policy = self.default_read_policy(VerifyMode::Disabled)?;
        Ok(self
            .read_with_policy(&options, &policy, &context, None)?
            .entries)
    }

    /// Scan one file source under a frozen trust policy and return accepted
    /// flat entries plus bounded accounting and a lossless byte cursor.
    pub fn read_with_policy(
        &self,
        options: &SecureReadOptions,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<FlatEntry>> {
        let path = self.resolve_read_source_path(options.log_path.as_deref());
        let effective_context = self.read_context_for_path(&path, context.required_group.clone());
        let raw = self.scan_file_with_policy(&path, policy, &effective_context, cursor)?;
        let entries = raw
            .entries
            .into_iter()
            .map(|(entry, validity)| {
                let mut flat = flatten_raw_entry(&entry, false);
                insert_validity_metadata(&mut flat, &validity);
                flat
            })
            .collect();
        Ok(ReadReport {
            entries,
            scanned: raw.scanned,
            yielded: raw.yielded,
            skipped: raw.skipped,
            cursor: raw.cursor,
        })
    }

    fn scan_file_with_policy(
        &self,
        path: &Path,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
        let policy = policy.resolve(context)?;
        let source_id = file_source_id(path)?;
        let (mut next_cursor, start_u64) = file_cursor_start(cursor, &source_id)?;

        if !self.storage.exists(path) {
            return Ok(empty_file_read_report(source_id, next_cursor));
        }
        let snapshot = open_storage_read_snapshot(self.storage.as_ref(), path)?;
        let snapshot_len = snapshot.len;
        if start_u64 > snapshot_len {
            return Err(Error::InvalidConfig(format!(
                "byte-offset cursor {start_u64} exceeds source length {snapshot_len}"
            )));
        }
        let mut reader = BufReader::new(snapshot.reader.take(snapshot_len));
        let public_set: HashSet<&str> = self.cfg.public_fields.iter().map(String::as_str).collect();
        let configured_groups: HashSet<&str> = self.cfg.groups.keys().map(String::as_str).collect();
        let mut prev_hash_by_event: HashMap<String, String> = HashMap::new();
        let mut entries = Vec::new();
        let mut scanned = 0usize;
        let mut skipped = 0usize;
        let mut offset = 0u64;
        let mut line = Vec::new();

        while let Some(line_meta) = read_bounded_line(&mut reader, &mut line).map_err(Error::Io)? {
            let line_start = offset;
            offset = offset.checked_add(line_meta.physical_len).ok_or_else(|| {
                Error::InvalidConfig("read source byte offset overflowed u64".into())
            })?;
            let line_end = offset;
            while line
                .last()
                .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
            {
                line.pop();
            }
            if !line_meta.overflowed && line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let line_text = (!line_meta.overflowed)
                .then(|| std::str::from_utf8(&line).ok())
                .flatten();
            if line_end <= start_u64 {
                if let Some(line_text) = line_text {
                    seed_chain_from_line(line_text, &mut prev_hash_by_event);
                }
                continue;
            }
            if start_u64 > line_start {
                return Err(Error::InvalidConfig(
                    "byte-offset cursor must point to a record boundary".into(),
                ));
            }
            scanned += 1;

            let prepared = line_text.map_or_else(
                || invalid_record(serde_json::json!({"event_type": "<parse-error>"})),
                |line_text| {
                    prepare_record(
                        line_text,
                        &public_set,
                        &configured_groups,
                        &mut prev_hash_by_event,
                    )
                },
            );
            match self.evaluate_prepared_record(prepared, &policy, context) {
                EvaluatedRecord::Accepted(entry, validity) => entries.push((entry, validity)),
                EvaluatedRecord::Rejected(entry, decision) => {
                    skipped += 1;
                    if policy.verify == VerifyMode::Raise {
                        return Err(read_rejection_error(&entry, &decision));
                    }
                    if policy.verify == VerifyMode::Skip && context.writable {
                        self.emit_skip_event_best_effort(&entry, &decision.reasons);
                    }
                }
            }
        }
        if offset != snapshot_len {
            return Err(Error::Malformed {
                kind: "log file",
                reason: "read source ended before its captured snapshot length".into(),
            });
        }
        next_cursor.sources.insert(
            source_id,
            SourceCursorV1 {
                kind: CursorKind::ByteOffset,
                value: snapshot_len.to_string(),
            },
        );
        let yielded = entries.len();
        Ok(ReadReport {
            entries,
            scanned,
            yielded,
            skipped,
            cursor: next_cursor,
        })
    }

    fn evaluate_prepared_record(
        &self,
        prepared: PreparedRecord,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
    ) -> EvaluatedRecord {
        let mut record = prepared.record;
        let pre_decrypt = policy.evaluate(&record, context);
        if !pre_decrypt.accepted {
            return EvaluatedRecord::Rejected(prepared.entry, pre_decrypt);
        }

        let mut entry = prepared.entry;
        let (plaintext, _, row_parse_error) = self.decrypt_groups_for_row(&entry.envelope);
        if row_parse_error.is_some() {
            record.record_valid = false;
        }
        entry.plaintext_per_group = plaintext;
        record.recipient_groups = successfully_decrypted_groups(&entry);
        let local_authentication_failure = context.active
            && context.local_log
            && !context.detached
            && entry
                .plaintext_per_group
                .iter()
                .any(|(group, value)| self.groups.contains_key(group) && is_no_read_key(value));
        record.aad_valid = !local_authentication_failure
            && !entry.plaintext_per_group.values().any(is_decrypt_error);
        let decision = policy.evaluate(&record, context);
        if !decision.accepted {
            return EvaluatedRecord::Rejected(entry, decision);
        }

        let validity = ValidFlags {
            signature: record.signature_present && record.signature_valid,
            row_hash: record.row_hash_present && record.row_hash_valid,
            chain: !read_chain_required(context) || record.chain_valid,
            writer_authenticated: decision.writer_authenticated,
            writer_authorized: decision.writer_authorized,
            reasons: decision.reasons,
        };
        EvaluatedRecord::Accepted(entry, validity)
    }

    fn emit_skip_event_best_effort(&self, entry: &ReadEntry, reasons: &[ReadRejectReason]) {
        let event_type = entry
            .envelope
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        if event_type == "tn.read.tampered_row_skipped" {
            return;
        }
        if let Err(error) = self.emit_tampered_row_skipped(entry, reasons) {
            log::warn!("tn.read.tampered_row_skipped emit failed: {error}");
        }
    }

    fn read_context_for_path(&self, path: &Path, required_group: Option<String>) -> ReadContext {
        ReadContext {
            active: true,
            local_log: paths_equivalent(path, &self.log_path),
            detached: false,
            writable: true,
            profile_sign: Some(self.cfg.ceremony.sign),
            profile_chain: Some(self.cfg.ceremony.chain),
            local_device_did: Some(self.device.did().to_owned()),
            required_group,
        }
    }

    fn resolve_read_source_path(&self, requested: Option<&Path>) -> PathBuf {
        let path = match requested {
            None => self.log_path.clone(),
            Some(path) => {
                let yaml_directory = self.yaml_path.parent().unwrap_or_else(|| Path::new("."));
                crate::pathutil::resolve(yaml_directory, path)
            }
        };
        lexical_normalize(&path)
    }

    fn default_read_policy(&self, verify: VerifyMode) -> Result<ReadTrustPolicy> {
        let mut trusted_writers = BTreeSet::from([self.device.did().to_owned()]);
        trusted_writers.extend(self.configured_trusted_writers()?);
        trusted_writers.extend(self.verified_publisher_writers()?);
        Ok(ReadTrustPolicy {
            verify,
            require_signature: None,
            allow_unauthenticated: None,
            trusted_writers,
            trusted_writers_supplied: false,
            allow_unknown_writers: false,
        })
    }

    fn configured_trusted_writers(&self) -> Result<BTreeSet<String>> {
        let bytes = self
            .storage
            .read_bytes(&self.yaml_path)
            .map_err(Error::Io)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            Error::InvalidConfig("tn.yaml is not valid UTF-8 while loading trust.writers".into())
        })?;
        let document: Value = serde_yml::from_str(text).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid tn.yaml while loading trust.writers: {error}"
            ))
        })?;
        let Some(trust) = document.get("trust") else {
            return Ok(BTreeSet::new());
        };
        let trust = trust
            .as_object()
            .ok_or_else(|| Error::InvalidConfig("trust must be a mapping when present".into()))?;
        let Some(writers) = trust.get("writers") else {
            return Ok(BTreeSet::new());
        };
        let writers = writers
            .as_array()
            .ok_or_else(|| Error::InvalidConfig("trust.writers must be a list".into()))?;
        writers
            .iter()
            .map(|writer| {
                writer.as_str().map(str::to_owned).ok_or_else(|| {
                    Error::InvalidConfig("trust.writers entries must be strings".into())
                })
            })
            .collect()
    }

    fn verified_publisher_writers(&self) -> Result<BTreeSet<String>> {
        let path = self
            .keystore
            .join("trust")
            .join("verified_publishers.v1.json");
        if !self.storage.exists(&path) {
            return Ok(BTreeSet::new());
        }
        let bytes = self.storage.read_bytes(&path).map_err(Error::Io)?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid verified publisher record {}: {error}",
                path.display()
            ))
        })?;
        let publishers = document.get("publishers").unwrap_or(&document);
        let publishers = publishers.as_object().ok_or_else(|| {
            Error::InvalidConfig(format!(
                "invalid verified publisher record {}: publishers must be an object",
                path.display()
            ))
        })?;
        for (did, metadata) in publishers {
            if !metadata.is_object() {
                return Err(Error::InvalidConfig(format!(
                    "invalid verified publisher record {}: {did:?} metadata must be an object",
                    path.display()
                )));
            }
        }
        Ok(publishers.keys().cloned().collect())
    }

    /// Read all entries (every run) in the audit-grade [`ReadEntry`]
    /// shape — verbatim envelope plus per-group decrypted plaintext.
    /// Mirrors the pre-2026-04-25 `Runtime::read()` return. Reach for this
    /// when you need the crypto plumbing the flat shape drops.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`].
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_raw(&self) -> Result<Vec<ReadEntry>> {
        let log_path = self.log_path.clone();
        self.read_from(&log_path)
    }

    /// Read verified entries — fail-closed on any (signature, row_hash,
    /// chain) failure. Backs `tn.secure_read()`. Per the 2026-04-25
    /// read-ergonomics spec §3.
    ///
    /// This is the read path to use when the integrity of each row
    /// matters: every entry is verified, and a non-verifying one is
    /// handled per [`SecureReadOptions::on_invalid`] — silently dropped
    /// ([`OnInvalid::Skip`], the default), turned into an error
    /// ([`OnInvalid::Raise`]), or surfaced with its failure reasons for an
    /// auditor ([`OnInvalid::Forensic`]).
    ///
    /// Returns [`SecureEntry`] values: the flat decrypted `fields` in the
    /// same default shape as [`Runtime::read`], plus an `instructions`
    /// block when the caller holds the `tn.agents` kit and the entry
    /// carries a populated `tn.agents` group. The six `tn.agents` field
    /// names are NOT flattened into `fields` — they land in
    /// `instructions` as a separate concern.
    ///
    /// Side effect: under [`OnInvalid::Skip`], a
    /// `tn.read.tampered_row_skipped` admin event (public fields only —
    /// never the bad row's payload) is appended to the local log for each
    /// dropped row so monitoring can surface tampering.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`](crate::Error::Malformed) on the first
    /// non-verifying entry when `on_invalid` is [`OnInvalid::Raise`], plus
    /// the [`Runtime::read`] error set from reading + decrypting the log.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::{Runtime, SecureReadOptions, OnInvalid};
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::ephemeral()?;
    /// let opts = SecureReadOptions { on_invalid: OnInvalid::Raise, ..Default::default() };
    /// for entry in rt.secure_read(opts)? {
    ///     // entry.fields is the verified flat dict; entry.instructions
    ///     // carries the tn.agents policy when the kit is held.
    ///     let _ = entry.fields;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn secure_read(&self, opts: SecureReadOptions) -> Result<Vec<SecureEntry>> {
        let path = self.resolve_read_source_path(opts.log_path.as_deref());
        if self.storage.exists(&path)
            && is_foreign_log(
                &path,
                &self.log_path,
                self.device.did(),
                &self.keystore,
                &self.storage,
            )?
        {
            reject_unsupported_foreign_log_with_validity(&self.keystore, &self.storage)?;
        }
        let context = self.read_context_for_path(&path, None);
        let verify = match opts.on_invalid {
            OnInvalid::Raise => VerifyMode::Raise,
            OnInvalid::Skip => VerifyMode::Skip,
            OnInvalid::Forensic => VerifyMode::Disabled,
        };
        let policy = self.default_read_policy(verify)?;
        let report = self.read_with_policy(&opts, &policy, &context, None)?;
        Ok(report
            .entries
            .into_iter()
            .map(|flat| secure_entry_from_flat(flat, opts.on_invalid == OnInvalid::Forensic))
            .collect())
    }

    /// Append a `tn.read.tampered_row_skipped` admin event with public
    /// fields only. The bad row's payload is NOT exposed.
    fn emit_tampered_row_skipped(
        &self,
        entry: &ReadEntry,
        reasons: &[ReadRejectReason],
    ) -> Result<()> {
        let env = entry.envelope.as_object();
        let event_id = env
            .and_then(|o| o.get("event_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let did = env
            .and_then(|o| o.get("device_identity"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let event_type = env
            .and_then(|o| o.get("event_type"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let sequence = env.and_then(|o| o.get("sequence")).cloned();

        let mut fields = Map::new();
        fields.insert("envelope_event_id".into(), Value::String(event_id));
        fields.insert("envelope_device_identity".into(), Value::String(did));
        fields.insert("envelope_event_type".into(), Value::String(event_type));
        fields.insert("envelope_sequence".into(), sequence.unwrap_or(Value::Null));
        fields.insert(
            "invalid_reasons".into(),
            Value::Array(
                reasons
                    .iter()
                    .map(|reason| Value::String(reason.as_str().to_string()))
                    .collect(),
            ),
        );
        self.emit("warning", "tn.read.tampered_row_skipped", fields)
    }

    /// Read all entries in the audit-grade [`ReadEntry`] shape, each
    /// paired with its [`ValidFlags`] `(signature, row_hash, chain)`. The
    /// low-level building block behind [`Runtime::read_with_verify`] and
    /// [`Runtime::secure_read`].
    ///
    /// Verification mirrors Python `tn.reader._read`: chain integrity
    /// per event_type, row_hash recomputed from canonical inputs,
    /// signature checked against the envelope's `did`.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`].
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_raw_with_validity(&self) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        let log_path = self.log_path.clone();
        self.read_from_with_validity(&log_path)
    }

    /// As [`Runtime::read_raw_with_validity`] but reads an explicit
    /// `log_path` instead of this runtime's own log.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`].
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_from_with_validity(&self, log_path: &Path) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        if !self.storage.exists(log_path) {
            return Ok(Vec::new());
        }
        if is_foreign_log(
            log_path,
            &self.log_path,
            self.device.did(),
            &self.keystore,
            &self.storage,
        )? {
            reject_unsupported_foreign_log_with_validity(&self.keystore, &self.storage)?;
        }
        let context = self.read_context_for_path(log_path, None);
        let policy = self.default_read_policy(VerifyMode::Disabled)?;
        Ok(self
            .scan_file_with_policy(log_path, &policy, &context, None)?
            .entries)
    }

    /// Decrypt every group block in one envelope that this runtime holds a
    /// kit for, building both the plaintext map and the `GroupInput` map
    /// the row-hash recompute needs. The per-row building block inside
    /// [`Runtime::read_from_with_validity`].
    ///
    /// Per-row resilient (DX review 0.4.2a3 follow-up): a corrupt
    /// ciphertext base64 or a post-decrypt JSON parse failure stops the
    /// scan and is returned as `Some(reason)` so the caller can surface a
    /// `<parse-error>` sentinel instead of aborting iteration. Groups with
    /// no held kit, or that decrypt to a not-entitled / decrypt error, get
    /// the `$no_read_key` / `$decrypt_error` sentinel plaintext.
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state `RwLock` is poisoned.
    fn decrypt_groups_for_row(
        &self,
        env: &Value,
    ) -> (
        BTreeMap<String, Value>,
        BTreeMap<String, GroupInput>,
        Option<String>,
    ) {
        let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
        let mut groups_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
        let mut row_parse_error: Option<String> = None;
        if let Value::Object(env_map) = env {
            'group_loop: for (k, v) in env_map {
                if let Some(g_obj) = v.as_object() {
                    if let Some(ct_str) = g_obj.get("ciphertext").and_then(Value::as_str) {
                        let ct = match STANDARD.decode(ct_str) {
                            Ok(b) => b,
                            Err(e) => {
                                row_parse_error =
                                    Some(format!("ciphertext base64 in group {k:?}: {e}"));
                                break 'group_loop;
                            }
                        };
                        let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
                        if let Some(fh_obj) = g_obj.get("field_hashes").and_then(Value::as_object) {
                            for (fname, fv) in fh_obj {
                                if let Some(s) = fv.as_str() {
                                    field_hashes.insert(fname.clone(), s.to_string());
                                }
                            }
                        }
                        groups_for_hash.insert(
                            k.clone(),
                            GroupInput {
                                ciphertext: ct.clone(),
                                field_hashes,
                            },
                        );
                        // Decrypt if we hold a kit for this group, binding the
                        // reconstructed AAD marker (empty when none was bound).
                        if let Some(gstate_arc) = self.groups.get(k) {
                            let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                            let aad = aad_bytes_for(env, k);
                            match gstate.cipher.decrypt_with_aad(&ct, &aad) {
                                Ok(pt) => {
                                    match serde_json::from_slice::<Value>(&pt) {
                                        Ok(pv) => {
                                            plaintext_per_group.insert(k.clone(), pv);
                                        }
                                        Err(e) => {
                                            // Bad plaintext bytes after decrypt;
                                            // treat as a per-row parse error rather
                                            // than aborting the iterator.
                                            row_parse_error =
                                                Some(format!("plaintext json in group {k:?}: {e}"));
                                            break 'group_loop;
                                        }
                                    }
                                }
                                Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => {
                                    plaintext_per_group.insert(
                                        k.clone(),
                                        serde_json::json!({"$no_read_key": true}),
                                    );
                                }
                                Err(_) => {
                                    plaintext_per_group.insert(
                                        k.clone(),
                                        serde_json::json!({"$decrypt_error": true}),
                                    );
                                }
                            }
                        } else {
                            plaintext_per_group
                                .insert(k.clone(), serde_json::json!({"$no_read_key": true}));
                        }
                    }
                }
            }
        }
        (plaintext_per_group, groups_for_hash, row_parse_error)
    }

    /// Read all entries from a specific log path (for cross-party reads).
    ///
    /// FINDINGS S6.2 cross-binding parity: when `log_path` points at a
    /// foreign publisher's ndjson, the runtime's own group state can't
    /// decrypt the ciphertexts. Detect by peeking at the first
    /// envelope's `did` and route through
    /// [`crate::read_as_recipient::read_as_recipient`] using this
    /// runtime's keystore (where `Runtime::absorb` placed the foreign
    /// kit). The exemption: when `log_path` is exactly our own
    /// `log_path` (the post-flush "reading my own log" case), skip the
    /// foreign route and use the regular self-decrypt path.
    ///
    /// Returns an empty vec when `log_path` does not exist.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`], plus any error from the foreign-reader
    /// route when `log_path` is another publisher's log.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned (another thread panicked while
    /// holding a write lock on group state).
    pub fn read_from(&self, log_path: &Path) -> Result<Vec<ReadEntry>> {
        if !self.storage.exists(log_path) {
            return Ok(Vec::new());
        }
        if is_foreign_log(
            log_path,
            &self.log_path,
            self.device.did(),
            &self.keystore,
            &self.storage,
        )? {
            return read_foreign_log(log_path, &self.keystore, &self.storage);
        }
        let mut out = Vec::new();
        for res in LogFileReader::open(log_path, &self.storage)? {
            // DX review 0.4.2a3 follow-up: per-row resilience. A bad
            // row (malformed JSON, corrupt base64 ciphertext, bad
            // post-decrypt plaintext) yields a sentinel envelope so
            // the caller's verify='skip' path can count it as
            // ``skipped_parse`` and continue. Without this, a single
            // disk-corrupt row killed the iterator and clean rows
            // after it never reached the caller.
            let env = match res {
                Ok(e) => e,
                Err(e) => {
                    out.push(ReadEntry {
                        envelope: serde_json::json!({
                            "event_type": "<parse-error>",
                            "_parse_error": e.to_string(),
                        }),
                        plaintext_per_group: BTreeMap::new(),
                    });
                    continue;
                }
            };
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            let mut row_parse_error: Option<String> = None;
            'group_loop: for (gname, gstate_arc) in &self.groups {
                let Some(group_v) = env.get(gname) else {
                    continue;
                };
                let Some(ct_b64) = group_v.get("ciphertext").and_then(|v| v.as_str()) else {
                    continue;
                };
                let ct = match STANDARD.decode(ct_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        row_parse_error =
                            Some(format!("ciphertext base64 in group {gname:?}: {e}"));
                        break 'group_loop;
                    }
                };
                let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                let aad = aad_bytes_for(&env, gname);
                match gstate.cipher.decrypt_with_aad(&ct, &aad) {
                    Ok(pt) => match serde_json::from_slice::<Value>(&pt) {
                        Ok(v) => {
                            plaintext_per_group.insert(gname.clone(), v);
                        }
                        Err(e) => {
                            row_parse_error =
                                Some(format!("plaintext json in group {gname:?}: {e}"));
                            break 'group_loop;
                        }
                    },
                    Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => {
                        // Skip groups we can't read.
                    }
                    Err(e) => return Err(e),
                }
            }
            if let Some(err) = row_parse_error {
                out.push(ReadEntry {
                    envelope: serde_json::json!({
                        "event_type": "<parse-error>",
                        "_parse_error": err,
                    }),
                    plaintext_per_group: BTreeMap::new(),
                });
                continue;
            }
            out.push(ReadEntry {
                envelope: env,
                plaintext_per_group,
            });
        }
        Ok(out)
    }
}

struct PreparedRecord {
    entry: ReadEntry,
    record: ReadRecordState,
}

const MAX_POLICY_LINE_BYTES: usize = 8 * 1024 * 1024;

struct BoundedLine {
    physical_len: u64,
    overflowed: bool,
}

fn open_storage_read_snapshot(
    storage: &dyn crate::storage::Storage,
    path: &Path,
) -> Result<crate::storage::StorageReadSnapshot> {
    if let Some(snapshot) = storage.open_read_snapshot(path).map_err(Error::Io)? {
        return Ok(snapshot);
    }
    let bytes = storage.read_bytes(path).map_err(Error::Io)?;
    let len = u64::try_from(bytes.len()).map_err(|_| {
        Error::InvalidConfig("read source is too large for a u64 byte cursor".into())
    })?;
    Ok(crate::storage::StorageReadSnapshot {
        reader: Box::new(std::io::Cursor::new(bytes)),
        len,
    })
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Option<BoundedLine>> {
    buffer.clear();
    let mut physical_len = 0u64;
    let mut overflowed = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if physical_len == 0 {
                Ok(None)
            } else {
                Ok(Some(BoundedLine {
                    physical_len,
                    overflowed,
                }))
            };
        }
        let chunk_len = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let line_ended = available[chunk_len - 1] == b'\n';
        let remaining = MAX_POLICY_LINE_BYTES.saturating_sub(buffer.len());
        let retained = remaining.min(chunk_len);
        buffer.extend_from_slice(&available[..retained]);
        overflowed |= retained < chunk_len;
        let increment = u64::try_from(chunk_len)
            .map_err(|_| std::io::Error::other("line byte count does not fit u64"))?;
        physical_len = physical_len
            .checked_add(increment)
            .ok_or_else(|| std::io::Error::other("line byte count overflowed u64"))?;
        reader.consume(chunk_len);
        if line_ended {
            return Ok(Some(BoundedLine {
                physical_len,
                overflowed,
            }));
        }
    }
}

enum EvaluatedRecord {
    Accepted(ReadEntry, ValidFlags),
    Rejected(ReadEntry, ReadDecision),
}

fn empty_file_read_report(
    source_id: String,
    mut cursor: ReadCursorV1,
) -> ReadReport<(ReadEntry, ValidFlags)> {
    cursor.sources.insert(
        source_id,
        SourceCursorV1 {
            kind: CursorKind::ByteOffset,
            value: "0".into(),
        },
    );
    ReadReport {
        entries: Vec::new(),
        scanned: 0,
        yielded: 0,
        skipped: 0,
        cursor,
    }
}

fn file_cursor_start(
    cursor: Option<&ReadCursorV1>,
    source_id: &str,
) -> Result<(ReadCursorV1, u64)> {
    let next_cursor = cursor.cloned().unwrap_or_default();
    if next_cursor.version != 1 {
        return Err(Error::InvalidConfig(format!(
            "unsupported read cursor version {}; expected 1",
            next_cursor.version
        )));
    }
    let start = match next_cursor.sources.get(source_id) {
        None => 0,
        Some(source) if source.kind == CursorKind::ByteOffset => source
            .value
            .parse::<u64>()
            .map_err(|_| Error::InvalidConfig("byte-offset cursor must be a u64 string".into()))?,
        Some(_) => {
            return Err(Error::InvalidConfig(
                "file source cursor must use kind=byte_offset".into(),
            ));
        }
    };
    Ok((next_cursor, start))
}

fn invalid_record(envelope: Value) -> PreparedRecord {
    PreparedRecord {
        entry: ReadEntry {
            envelope,
            plaintext_per_group: BTreeMap::new(),
        },
        record: ReadRecordState {
            record_valid: false,
            row_hash_present: false,
            row_hash_valid: false,
            chain_valid: false,
            signature_present: false,
            signature_valid: false,
            writer_did: None,
            aad_valid: true,
            recipient_groups: BTreeSet::new(),
        },
    }
}

fn prepare_record(
    line: &str,
    public_set: &HashSet<&str>,
    configured_groups: &HashSet<&str>,
    prev_hash_by_event: &mut HashMap<String, String>,
) -> PreparedRecord {
    let Ok(envelope) = serde_json::from_str::<Value>(line) else {
        return invalid_record(serde_json::json!({"event_type": "<parse-error>"}));
    };
    let Some(object) = envelope.as_object() else {
        return invalid_record(envelope);
    };

    let string_field = |name: &str| object.get(name).and_then(Value::as_str);
    let writer_did = string_field("device_identity").map(str::to_owned);
    let timestamp = string_field("timestamp");
    let event_id = string_field("event_id");
    let event_type = string_field("event_type");
    let level = string_field("level");
    let prev_hash = string_field("prev_hash");
    let row_hash = string_field("row_hash");
    let signature = string_field("signature");
    let sequence_present = object.get("sequence").and_then(Value::as_u64).is_some();
    let mut record_valid = writer_did.as_deref().is_some_and(|did| !did.is_empty())
        && timestamp.is_some()
        && event_id.is_some_and(|id| !id.is_empty())
        && event_type.is_some_and(|kind| !kind.is_empty())
        && level.is_some()
        && sequence_present;

    let (groups_for_hash, recipient_groups, groups_valid) = extract_group_inputs(object);
    record_valid &= groups_valid;

    let chain_valid = match (event_type, prev_hash) {
        (Some(kind), Some(previous)) => prev_hash_by_event
            .get(kind)
            .is_none_or(|last| last == previous),
        _ => false,
    };
    if let (Some(kind), Some(hash)) = (event_type, row_hash) {
        prev_hash_by_event.insert(kind.to_owned(), hash.to_owned());
    }

    let row_hash_present = row_hash.is_some_and(|hash| !hash.is_empty());
    let row_hash_valid = if record_valid && row_hash_present {
        let public_fields = recompute_public_fields(&envelope, public_set, configured_groups);
        let expected = compute_row_hash(&RowHashInput {
            device_identity: writer_did.as_deref().unwrap_or(""),
            timestamp: timestamp.unwrap_or(""),
            event_id: event_id.unwrap_or(""),
            event_type: event_type.unwrap_or(""),
            level: level.unwrap_or(""),
            prev_hash: prev_hash.unwrap_or(""),
            public_fields: &public_fields,
            groups: &groups_for_hash,
        });
        row_hash == Some(expected.as_str())
    } else {
        false
    };
    let signature_present = signature.is_some_and(|value| !value.is_empty());
    let signature_valid = if record_valid && signature_present && row_hash_present {
        signature
            .and_then(|value| signature_from_b64(value).ok())
            .and_then(|bytes| {
                writer_did.as_deref().map(|did| {
                    DeviceKey::verify_did(did, row_hash.unwrap_or("").as_bytes(), &bytes)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    } else {
        false
    };

    PreparedRecord {
        entry: ReadEntry {
            envelope,
            plaintext_per_group: BTreeMap::new(),
        },
        record: ReadRecordState {
            record_valid,
            row_hash_present,
            row_hash_valid,
            chain_valid,
            signature_present,
            signature_valid,
            writer_did,
            aad_valid: true,
            recipient_groups,
        },
    }
}

fn extract_group_inputs(
    object: &Map<String, Value>,
) -> (BTreeMap<String, GroupInput>, BTreeSet<String>, bool) {
    let mut groups_for_hash = BTreeMap::new();
    let mut recipient_groups = BTreeSet::new();
    let mut groups_valid = true;
    for (name, value) in object {
        let Some(group) = value.as_object() else {
            continue;
        };
        if !group.contains_key("ciphertext") {
            continue;
        }
        recipient_groups.insert(name.clone());
        let Some(ciphertext) = group.get("ciphertext").and_then(Value::as_str) else {
            groups_valid = false;
            continue;
        };
        let Ok(ciphertext) = STANDARD.decode(ciphertext) else {
            groups_valid = false;
            continue;
        };
        let Some(field_hash_values) = group.get("field_hashes").and_then(Value::as_object) else {
            groups_valid = false;
            continue;
        };
        let mut field_hashes = BTreeMap::new();
        for (field, value) in field_hash_values {
            let Some(value) = value.as_str() else {
                groups_valid = false;
                continue;
            };
            field_hashes.insert(field.clone(), value.to_owned());
        }
        groups_for_hash.insert(
            name.clone(),
            GroupInput {
                ciphertext,
                field_hashes,
            },
        );
    }
    (groups_for_hash, recipient_groups, groups_valid)
}

fn seed_chain_from_line(line: &str, prev_hash_by_event: &mut HashMap<String, String>) {
    let Ok(envelope) = serde_json::from_str::<Value>(line) else {
        return;
    };
    let Some(object) = envelope.as_object() else {
        return;
    };
    if let (Some(event_type), Some(row_hash)) = (
        object.get("event_type").and_then(Value::as_str),
        object.get("row_hash").and_then(Value::as_str),
    ) {
        prev_hash_by_event.insert(event_type.to_owned(), row_hash.to_owned());
    }
}

fn successfully_decrypted_groups(entry: &ReadEntry) -> BTreeSet<String> {
    entry
        .plaintext_per_group
        .iter()
        .filter(|(_, plaintext)| !is_no_read_key(plaintext) && !is_decrypt_error(plaintext))
        .map(|(group, _)| group.clone())
        .collect()
}

fn is_no_read_key(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.get("$no_read_key") == Some(&Value::Bool(true)))
}

fn is_decrypt_error(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.get("$decrypt_error") == Some(&Value::Bool(true)))
}

fn insert_validity_metadata(flat: &mut FlatEntry, validity: &ValidFlags) {
    flat.insert(
        "_valid".into(),
        serde_json::json!({
            "signature": validity.signature,
            "row_hash": validity.row_hash,
            "chain": validity.chain,
            "writer_authenticated": validity.writer_authenticated,
            "writer_authorized": validity.writer_authorized,
            "reasons": validity
                .reasons
                .iter()
                .map(|reason| reason.as_str())
                .collect::<Vec<_>>(),
        }),
    );
}

fn secure_entry_from_flat(mut flat: FlatEntry, forensic: bool) -> SecureEntry {
    let validity = flat.remove("_valid");
    if forensic {
        if let Some(validity) = validity {
            let reasons = validity
                .get("reasons")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            flat.insert("_valid".into(), validity);
            if reasons.as_array().is_some_and(|items| !items.is_empty()) {
                flat.insert("_invalid_reasons".into(), reasons);
            }
        }
    }

    let hidden_groups = take_string_array(&mut flat, "_hidden_groups");
    let decrypt_errors = take_string_array(&mut flat, "_decrypt_errors");
    let instructions = Instructions {
        instruction: take_string(&mut flat, "instruction"),
        use_for: take_string(&mut flat, "use_for"),
        do_not_use_for: take_string(&mut flat, "do_not_use_for"),
        consequences: take_string(&mut flat, "consequences"),
        on_violation_or_error: take_string(&mut flat, "on_violation_or_error"),
        policy: take_string(&mut flat, "policy"),
    };
    let instructions = if instructions.instruction.is_empty()
        && instructions.use_for.is_empty()
        && instructions.do_not_use_for.is_empty()
        && instructions.consequences.is_empty()
        && instructions.on_violation_or_error.is_empty()
        && instructions.policy.is_empty()
    {
        None
    } else {
        Some(instructions)
    };
    SecureEntry {
        fields: flat,
        instructions,
        hidden_groups,
        decrypt_errors,
    }
}

fn take_string(flat: &mut FlatEntry, name: &str) -> String {
    flat.remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn take_string_array(flat: &mut FlatEntry, name: &str) -> Vec<String> {
    flat.remove(name)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn read_rejection_error(entry: &ReadEntry, decision: &ReadDecision) -> Error {
    let reason = decision
        .first_reason()
        .map_or("record_invalid", ReadRejectReason::as_str);
    let event_type = entry
        .envelope
        .get("event_type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let event_id = entry
        .envelope
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    Error::Malformed {
        kind: "verification",
        reason: format!(
            "tn.read_with_policy: envelope event_type={event_type:?} event_id={event_id:?} rejected: {reason}"
        ),
    }
}

fn file_source_id(path: &Path) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(Error::Io)?.join(path)
    };
    let normalized = lexical_normalize(&absolute);
    let rendered = normalized
        .to_str()
        .ok_or_else(|| Error::InvalidConfig("read source path must be UTF-8".into()))?;
    Ok(canonical_file_source_id(rendered))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
        }
    };
    lexical_normalize(&absolute(left)) == lexical_normalize(&absolute(right))
}

/// Project a `ReadEntry` to the flat shape used by `Runtime::read()` per
/// the 2026-04-25 read-ergonomics spec.
///
/// - Six envelope basics (`timestamp`, `event_type`, `level`, `did`,
///   `sequence`, `event_id`) surface as top-level keys.
/// - Public fields beyond envelope basics surface flat.
/// - Decrypted fields from every readable group are merged in
///   alphabetical group order so last-write-wins on collision is
///   deterministic across runs.
/// - Crypto plumbing (`prev_hash`, `row_hash`, `signature`, ciphertext,
///   `field_hashes`) is excluded.
/// - `_hidden_groups` lists groups present in the envelope with no
///   readable plaintext. Omitted when empty.
/// - `_decrypt_errors` lists groups whose decrypt threw. Omitted when
///   empty.
///
/// `_include_valid` is wired through from the spec but the actual
/// `_valid` block is added by the caller (`read_with_verify`) since
/// validity flags don't live on `ReadEntry` itself.
pub fn flatten_raw_entry(entry: &ReadEntry, _include_valid: bool) -> FlatEntry {
    const FLAT_ENVELOPE_KEYS: [&str; 6] = [
        "timestamp",
        "event_type",
        "level",
        "did",
        "sequence",
        "event_id",
    ];
    const CRYPTO_KEYS: [&str; 3] = ["prev_hash", "row_hash", "signature"];

    let env_obj: &Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m,
        _ => return Map::new(),
    };

    let mut out: FlatEntry = Map::new();

    // 1. Envelope basics.
    for k in FLAT_ENVELOPE_KEYS {
        if let Some(v) = env_obj.get(k) {
            out.insert(k.into(), v.clone());
        }
    }

    let mut reserved: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for k in FLAT_ENVELOPE_KEYS {
        reserved.insert(k);
    }
    for k in CRYPTO_KEYS {
        reserved.insert(k);
    }

    // 2. Public fields beyond envelope basics: anything in env that
    //    isn't an envelope basic, isn't crypto plumbing, and isn't a
    //    group payload (dict with "ciphertext").
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }

    // 3. Decrypted group fields, merged in alphabetical group order.
    let mut decrypt_errors = flat_merge_group_plaintext(entry, &mut out);

    // 4. _hidden_groups: groups in envelope with ciphertext but no
    //    readable plaintext.
    let mut hidden = flat_collect_hidden_groups(entry, env_obj, &reserved);
    if !hidden.is_empty() {
        hidden.sort();
        out.insert(
            "_hidden_groups".into(),
            Value::Array(hidden.into_iter().map(Value::String).collect()),
        );
    }
    if !decrypt_errors.is_empty() {
        decrypt_errors.sort();
        out.insert(
            "_decrypt_errors".into(),
            Value::Array(decrypt_errors.into_iter().map(Value::String).collect()),
        );
    }

    out
}

/// Merge every readable group's decrypted fields into `out` (alphabetical
/// group order, last-write-wins on collision) and return the names of any
/// groups whose decrypt threw. Groups carrying the `$no_read_key`
/// sentinel contribute nothing; the `$decrypt_error` sentinel is
/// collected into the returned list. Step 3 of [`flatten_raw_entry`].
fn flat_merge_group_plaintext(entry: &ReadEntry, out: &mut FlatEntry) -> Vec<String> {
    let mut decrypt_errors: Vec<String> = Vec::new();
    // BTreeMap iteration is alphabetical.
    for (gname, body) in &entry.plaintext_per_group {
        if let Some(obj) = body.as_object() {
            if obj.get("$decrypt_error") == Some(&Value::Bool(true)) {
                decrypt_errors.push(gname.clone());
                continue;
            }
            if obj.get("$no_read_key") == Some(&Value::Bool(true)) {
                continue;
            }
            for (k, v) in obj {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    decrypt_errors
}

/// List groups present in the envelope with a ciphertext block but no
/// readable plaintext (kit absent / `$no_read_key`). Step 4 of
/// [`flatten_raw_entry`]; the caller sorts and inserts the result.
fn flat_collect_hidden_groups(
    entry: &ReadEntry,
    env_obj: &Map<String, Value>,
    reserved: &std::collections::BTreeSet<&str>,
) -> Vec<String> {
    let mut hidden: Vec<String> = Vec::new();
    for (k, v) in env_obj {
        if reserved.contains(k.as_str()) {
            continue;
        }
        if !v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
            continue;
        }
        let body = entry.plaintext_per_group.get(k);
        let no_read = body.is_none()
            || body.is_some_and(|b| {
                b.as_object()
                    .is_some_and(|o| o.get("$no_read_key") == Some(&Value::Bool(true)))
            });
        if no_read {
            hidden.push(k.clone());
        }
    }
    hidden
}

/// Rebuild the public-field map that the row-hash recompute hashes, from
/// a parsed envelope. A field is included only when it is not a reserved
/// scalar, not a group ciphertext block, present in the ceremony's
/// `public_fields`, and not also a group name.
///
/// The reserved set MUST exclude the same scalars the writer treats as
/// scalars. The wire key for the publisher identity is `device_identity`
/// (0.4.3a1 flipped it from the legacy `did`); leaving the stale
/// `did` here let the `device_identity` scalar leak into the public map
/// for a ceremony whose yaml lists it under public_fields, double-hashing
/// it relative to the corrected writer. Mirrors
/// `python/tn/reader.py::_envelope_reserved` and
/// `ts-sdk/.../node_runtime.ts::_ENVELOPE_RESERVED`.
fn recompute_public_fields(
    env: &Value,
    public_set: &HashSet<&str>,
    group_names: &HashSet<&str>,
) -> BTreeMap<String, Value> {
    let envelope_reserved: HashSet<&'static str> = [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "prev_hash",
        "row_hash",
        "signature",
        "sequence",
    ]
    .iter()
    .copied()
    .collect();
    let mut public_out: BTreeMap<String, Value> = BTreeMap::new();
    if let Value::Object(env_map) = env {
        for (k, v) in env_map {
            if envelope_reserved.contains(k.as_str()) {
                continue;
            }
            // `tn_aad` is the auto-injected authenticated AAD echo (a
            // canonical string). The writer put it in the public fields that
            // feed row_hash, but it is NOT in the user's `public_fields`
            // list, so the recompute must fold it back in explicitly or the
            // row_hash would diverge. Mirrors the pure pipeline's fold-back.
            if k == "tn_aad" {
                if v.is_string() {
                    public_out.insert(k.clone(), v.clone());
                }
                continue;
            }
            if v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
                continue;
            }
            if !public_set.contains(k.as_str()) {
                continue;
            }
            if group_names.contains(k.as_str()) {
                continue;
            }
            public_out.insert(k.clone(), v.clone());
        }
    }
    public_out
}

// `aad_bytes_for` (the `tn_aad` echo → AAD bytes reconstruction) moved to
// `crate::sealed_object::aad_bytes_for` so the sealed-object decrypt walk
// and this log read path share one implementation. Imported at the top of
// this module.

/// Flatten a `ReadEntry` into a single JSON object: envelope fields plus
/// every per-group plaintext dict merged on top. Mirrors Python's
/// `recipients()` / `admin_state()` and TS `_mergeEnvelope` exactly.
pub(crate) fn merge_envelope(entry: &ReadEntry) -> Map<String, Value> {
    let mut merged: Map<String, Value> = match &entry.envelope {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    for v in entry.plaintext_per_group.values() {
        if let Value::Object(group_fields) = v {
            for (k, vv) in group_fields {
                merged.insert(k.clone(), vv.clone());
            }
        }
    }
    merged
}

/// Apply schema defaults the Rust emitter omits but the catalog requires
/// at reduce time. Mirrors Python and TS `_applySchemaDefaults`.
pub(crate) fn apply_schema_defaults(event_type: &str, mut merged: Map<String, Value>) -> Value {
    if event_type == "tn.recipient.added" && !merged.contains_key("cipher") {
        merged.insert("cipher".into(), Value::String("btn".into()));
    }
    if event_type == "tn.recipient.revoked" && !merged.contains_key("recipient_identity") {
        merged.insert("recipient_identity".into(), Value::Null);
    }
    Value::Object(merged)
}

/// Predicate for `Runtime::read`: does this flat entry belong to the
/// current process's run? True iff the entry's `run_id` is a string
/// matching the runtime's. Entries with no `run_id` (or a non-string
/// value) are EXCLUDED — for cross-session safety, the default is
/// "this run only." Use [`Runtime::read_all_runs`] for the full
/// history.
pub(crate) fn flat_in_current_run(flat: &FlatEntry, current_run_id: &str) -> bool {
    matches!(flat.get("run_id"), Some(Value::String(s)) if s == current_run_id)
}

/// True iff `log_path` is a foreign publisher's log (different `did`
/// on the first envelope) AND we have a kit on disk that could decrypt
/// it. Used by [`Runtime::read_from`] to auto-route cross-publisher
/// reads through the foreign-decrypt path. Mirrors Python's
/// `_is_foreign_log` and TS's `_isForeignLog`.
///
/// Conservative on log-peek failure: if the file is unreadable, has no
/// parseable line, lacks BTN reader material, or is exactly our own log,
/// return false so the regular path runs and surfaces the underlying log
/// error itself. Keystore listing errors propagate because otherwise kit
/// discovery failures could silently choose the wrong read path.
pub(crate) fn is_foreign_log(
    log_path: &Path,
    own_log: &Path,
    own_did: &str,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    // Exempt exactly our own log path — post-flush "reading my own log"
    // case where the auto-discovery cfg may have a different device but
    // the log is conceptually own. Narrowed per AVL J7.1 Bug 2.
    // `canonicalize` is filesystem-only (resolves symlinks) and has
    // no Storage equivalent; we keep it as a native shortcut. On wasm
    // it'll just fail (no symlinks) and we fall through to comparing
    // raw paths via the rest of the logic.
    if let (Ok(a), Ok(b)) = (log_path.canonicalize(), own_log.canonicalize()) {
        if a == b {
            return Ok(false);
        }
    }

    // No BTN recipient kit on disk → the BTN foreign-recipient route is not
    // useful. HIBE groups can still be opened by the regular configured
    // runtime path, so let that path run when no BTN material exists.
    if !has_btn_reader_material(keystore, storage)? {
        return Ok(false);
    }

    // Peek the first parseable envelope's DID through the same fixed-length
    // snapshot path used by the policy scanner. This avoids whole-file reads
    // on native storage and prevents concurrent appends changing the peek.
    let Ok(snapshot) = open_storage_read_snapshot(storage.as_ref(), log_path) else {
        return Ok(false);
    };
    let snapshot_len = snapshot.len;
    let mut reader = BufReader::new(snapshot.reader.take(snapshot_len));
    let mut line = Vec::new();
    loop {
        let line_meta = match read_bounded_line(&mut reader, &mut line) {
            Ok(Some(line_meta)) => line_meta,
            Ok(None) => break,
            Err(_) => return Ok(false),
        };
        while line
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            line.pop();
        }
        if line_meta.overflowed || line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(line) = std::str::from_utf8(&line) else {
            continue;
        };
        let Ok(env) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(env_did) = env.get("device_identity").and_then(Value::as_str) {
            if !env_did.is_empty() {
                return Ok(env_did != own_did);
            }
        }
        // First non-empty line had no did — give up; let regular path run.
        return Ok(false);
    }
    Ok(false)
}

#[derive(Debug, Default)]
struct ForeignReaderMaterial {
    btn_groups: Vec<String>,
    hibe_groups: Vec<String>,
    jwe_groups: Vec<String>,
}

impl ForeignReaderMaterial {
    fn sort_and_dedup(&mut self) {
        self.btn_groups.sort();
        self.btn_groups.dedup();
        self.hibe_groups.sort();
        self.hibe_groups.dedup();
        self.jwe_groups.sort();
        self.jwe_groups.dedup();
    }

    fn unsupported_error(&self, verb: &str) -> Option<Error> {
        match (
            self.hibe_groups.is_empty(),
            self.jwe_groups.is_empty(),
            verb,
        ) {
            (true, true, _) => None,
            (false, true, "read_from") => Some(Error::NotImplemented(
                "read_from: foreign recipient-kit dispatch for cipher=hibe is not implemented; \
                 HIBE reads are supported by configured HIBE runtimes, not by the BTN shortcut",
            )),
            (true, false, "read_from") => Some(Error::NotImplemented(
                "read_from: foreign recipient-kit dispatch for cipher=jwe is not implemented in \
                 tn-core; JWE reads are pure JS/Python today",
            )),
            (false, false, "read_from") => Some(Error::NotImplemented(
                "read_from: foreign recipient-kit dispatch for cipher=hibe and cipher=jwe is not \
                 implemented; only cipher=btn is supported by this shortcut",
            )),
            (false, true, _) => Some(Error::NotImplemented(
                "read_from_with_validity: foreign recipient-kit dispatch for cipher=hibe is not \
                 implemented; HIBE reads are supported by configured HIBE runtimes, not by the \
                 BTN shortcut",
            )),
            (true, false, _) => Some(Error::NotImplemented(
                "read_from_with_validity: foreign recipient-kit dispatch for cipher=jwe is not \
                 implemented in tn-core; JWE reads are pure JS/Python today",
            )),
            (false, false, _) => Some(Error::NotImplemented(
                "read_from_with_validity: foreign recipient-kit dispatch for cipher=hibe and \
                 cipher=jwe is not implemented; only configured-runtime reads are supported",
            )),
        }
    }
}

fn discover_foreign_reader_material(
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<ForeignReaderMaterial> {
    let entries = storage.list(keystore).map_err(Error::Io)?;
    let mut material = ForeignReaderMaterial::default();
    for path in entries {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(group) = name.strip_suffix(".btn.mykit") {
            if !group.is_empty() {
                material.btn_groups.push(group.to_string());
            }
        } else if let Some(group) = name.strip_suffix(".hibe.sk") {
            if !group.is_empty() {
                material.hibe_groups.push(group.to_string());
            }
        } else if let Some(group) = name.strip_suffix(".jwe.mykey") {
            if !group.is_empty() {
                material.jwe_groups.push(group.to_string());
            }
        }
    }
    material.sort_and_dedup();
    Ok(material)
}

fn has_btn_reader_material(
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    let entries = storage.list(keystore).map_err(Error::Io)?;
    Ok(entries.into_iter().any(|p| {
        p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.strip_suffix(".btn.mykit")
                .is_some_and(|group| !group.is_empty())
        })
    }))
}

/// Decrypt a foreign publisher's log, attempting EVERY group for which
/// the local keystore holds a `<group>.btn.mykit` kit. Mirrors what the
/// regular `read_from` path does (try every group the runtime knows
/// about) so `secure_read`'s `tn.agents` instructions splice surfaces
/// correctly even when the log is foreign.
///
/// Calls [`crate::read_as_recipient::read_as_recipient`] once per
/// kit-bearing group, then merges the per-group results back into a
/// single per-envelope `ReadEntry`. The signature/chain `valid` block
/// is dropped here; `secure_read` recomputes verification from the
/// envelope itself.
pub(crate) fn read_foreign_log(
    log_path: &Path,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<ReadEntry>> {
    use crate::read_as_recipient::ReadAsRecipientOptions;

    let material = discover_foreign_reader_material(keystore, storage)?;
    if let Some(err) = material.unsupported_error("read_from") {
        return Err(err);
    }
    let mut groups = material.btn_groups;
    if groups.is_empty() {
        // No kits at all — fall through to the single-group default
        // path so the underlying error message is "no recipient kit
        // for group 'default'" rather than a silently-empty result.
        groups.push("default".to_string());
    }
    groups.sort();

    // Run the foreign-decrypt iterator once per group. Each pass
    // produces a list of `ForeignReadEntry`s in log order; merge them
    // by envelope into a single `ReadEntry` whose `plaintext_per_group`
    // carries one decrypted block per kit-holding group.
    let mut envelopes: Vec<Map<String, Value>> = Vec::new();
    let mut merged_plaintext: Vec<BTreeMap<String, Value>> = Vec::new();
    for (idx, group) in groups.iter().enumerate() {
        let opts = ReadAsRecipientOptions {
            group: group.clone(),
            verify_signatures: true,
        };
        let foreign = read_btn_as_recipient_with_storage(log_path, keystore, storage, opts)?;
        if idx == 0 {
            envelopes.reserve(foreign.len());
            merged_plaintext.reserve(foreign.len());
            for e in foreign {
                envelopes.push(e.envelope);
                let mut pt: BTreeMap<String, Value> = BTreeMap::new();
                for (gname, val) in e.plaintext {
                    pt.insert(gname, val);
                }
                merged_plaintext.push(pt);
            }
        } else {
            for (i, e) in foreign.into_iter().enumerate() {
                if i >= merged_plaintext.len() {
                    break;
                }
                for (gname, val) in e.plaintext {
                    merged_plaintext[i].insert(gname, val);
                }
            }
        }
    }

    let mut out = Vec::with_capacity(envelopes.len());
    for (env, pt) in envelopes.into_iter().zip(merged_plaintext.into_iter()) {
        out.push(ReadEntry {
            envelope: Value::Object(env),
            plaintext_per_group: pt,
        });
    }
    Ok(out)
}

pub(crate) fn reject_unsupported_foreign_log_with_validity(
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<()> {
    let material = discover_foreign_reader_material(keystore, storage)?;
    if let Some(err) = material.unsupported_error("read_from_with_validity") {
        return Err(err);
    }
    Err(Error::NotImplemented(
        "read_from_with_validity: foreign recipient-kit reads are not implemented in tn-core; \
         use read_from for BTN plaintext or a native configured runtime for same-ceremony reads",
    ))
}

fn read_btn_as_recipient_with_storage(
    log_path: &Path,
    keystore_path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
    opts: crate::read_as_recipient::ReadAsRecipientOptions,
) -> Result<Vec<crate::read_as_recipient::ForeignReadEntry>> {
    use crate::cipher::btn::BtnReaderCipher;
    use crate::read_as_recipient::{ForeignReadEntry, ForeignValid};

    let group = opts.group;
    let btn_kit_path = keystore_path.join(format!("{group}.btn.mykit"));
    if !storage.exists(&btn_kit_path) {
        return Err(Error::InvalidConfig(format!(
            "read_as_recipient: no recipient kit for group {group:?} in {}. \
             Looked for {} (btn). If you absorbed a kit_bundle, the kit lands \
             in your ceremony's keystore — point keystore_path there.",
            keystore_path.display(),
            btn_kit_path.display(),
        )));
    }

    let kit_bytes = storage.read_bytes(&btn_kit_path).map_err(Error::Io)?;
    let cipher = BtnReaderCipher::from_kit_bytes(&kit_bytes)?;
    let bytes = storage.read_bytes(log_path).map_err(Error::Io)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| Error::Malformed {
        kind: "foreign log",
        reason: format!("not valid UTF-8: {e}"),
    })?;
    let mut entries = Vec::new();
    let mut prev_hash_by_type: BTreeMap<String, String> = BTreeMap::new();

    for raw_line in text.split('\n') {
        let s = raw_line.trim();
        if s.is_empty() {
            continue;
        }
        let env: Value = serde_json::from_str(s).map_err(Error::Json)?;
        let env_map = env
            .as_object()
            .ok_or_else(|| Error::Malformed {
                kind: "envelope",
                reason: "expected JSON object".into(),
            })?
            .clone();

        let event_type = env_map
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        if event_type.is_empty() {
            continue;
        }

        let env_prev = env_map.get("prev_hash").and_then(Value::as_str);
        let env_row = env_map.get("row_hash").and_then(Value::as_str);
        let last = prev_hash_by_type.get(event_type);
        let chain_ok = match (last, env_prev) {
            (None, _) => true,
            (Some(prev), Some(env)) => prev == env,
            _ => false,
        };
        if let Some(rh) = env_row {
            prev_hash_by_type.insert(event_type.to_string(), rh.to_string());
        }

        let mut plaintext: Map<String, Value> = Map::new();
        if let Some(g_block) = env_map.get(&group).and_then(Value::as_object) {
            if let Some(ct) = g_block.get("ciphertext").and_then(Value::as_str) {
                plaintext.insert(group.clone(), decrypt_btn_foreign_ciphertext(&cipher, ct));
            }
        }

        let mut sig_ok = true;
        if opts.verify_signatures {
            let did = env_map.get("device_identity").and_then(Value::as_str);
            let sig_str = env_map.get("signature").and_then(Value::as_str);
            match (did, sig_str, env_row) {
                (Some(did), Some(sig_b64), Some(row)) => {
                    sig_ok = match signature_from_b64(sig_b64) {
                        Ok(sig_bytes) => {
                            DeviceKey::verify_did(did, row.as_bytes(), &sig_bytes).unwrap_or(false)
                        }
                        Err(_) => false,
                    };
                }
                _ => sig_ok = false,
            }
        }

        entries.push(ForeignReadEntry {
            envelope: env_map,
            plaintext,
            valid: ForeignValid {
                signature: sig_ok,
                chain: chain_ok,
            },
        });
    }

    Ok(entries)
}

fn decrypt_btn_foreign_ciphertext(
    cipher: &crate::cipher::btn::BtnReaderCipher,
    ct_b64: &str,
) -> Value {
    use crate::cipher::GroupCipher as _;

    let sentinel = |key: &str| -> Value {
        let mut m = Map::new();
        m.insert(key.to_string(), Value::Bool(true));
        Value::Object(m)
    };

    let Ok(ct_bytes) = STANDARD.decode(ct_b64) else {
        return sentinel("$decrypt_error");
    };
    let Ok(pt_bytes) = cipher.decrypt(&ct_bytes) else {
        return sentinel("$no_read_key");
    };
    let Ok(pt) = serde_json::from_slice::<Value>(&pt_bytes) else {
        return sentinel("$decrypt_error");
    };
    pt
}
