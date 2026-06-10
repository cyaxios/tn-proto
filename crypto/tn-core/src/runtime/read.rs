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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::{
    chain::{compute_row_hash, GroupInput, RowHashInput},
    log_file::LogFileReader,
    signing::{signature_from_b64, DeviceKey},
    Error, Result,
};

use super::{
    FlatEntry, Instructions, OnInvalid, ReadEntry, Runtime, SecureEntry, SecureReadOptions,
    ValidFlags,
};

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
    /// naive filter doesn't pull in entries from prior runs (FINDINGS.md
    /// #12).
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
        let raw = self.read_raw_with_validity()?;
        Ok(raw
            .into_iter()
            .map(|(entry, valid)| {
                let mut flat = flatten_raw_entry(&entry, false);
                let mut v = Map::new();
                v.insert("signature".into(), Value::Bool(valid.signature));
                v.insert("row_hash".into(), Value::Bool(valid.row_hash));
                v.insert("chain".into(), Value::Bool(valid.chain));
                flat.insert("_valid".into(), Value::Object(v));
                flat
            })
            .collect())
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
        let raw_with_valid = match opts.log_path.as_deref() {
            Some(p) => self.read_from_with_validity(p)?,
            None => self.read_raw_with_validity()?,
        };
        let mut out: Vec<SecureEntry> = Vec::new();
        for (entry, valid) in raw_with_valid {
            let all_valid = valid.signature && valid.row_hash && valid.chain;
            if !all_valid {
                let reasons = invalid_reasons(valid);
                match opts.on_invalid {
                    OnInvalid::Raise => {
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
                        return Err(Error::Malformed {
                            kind: "verification",
                            reason: format!(
                                "tn.secure_read: envelope event_type={event_type:?} \
                                 event_id={event_id:?} failed verification: {reasons:?}"
                            ),
                        });
                    }
                    OnInvalid::Skip => {
                        // Don't loop our own tampered-row event back through
                        // secure_read — that would emit an event for the
                        // very event we're verifying. Skip silently.
                        let event_type = entry
                            .envelope
                            .get("event_type")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if event_type == "tn.read.tampered_row_skipped" {
                            continue;
                        }
                        if let Err(e) = self.emit_tampered_row_skipped(&entry, &reasons) {
                            log::warn!("tn.read.tampered_row_skipped emit failed: {e}");
                        }
                        continue;
                    }
                    OnInvalid::Forensic => {
                        let mut flat = flatten_raw_entry(&entry, false);
                        let mut v = Map::new();
                        v.insert("signature".into(), Value::Bool(valid.signature));
                        v.insert("row_hash".into(), Value::Bool(valid.row_hash));
                        v.insert("chain".into(), Value::Bool(valid.chain));
                        flat.insert("_valid".into(), Value::Object(v));
                        flat.insert(
                            "_invalid_reasons".into(),
                            Value::Array(
                                reasons
                                    .iter()
                                    .map(|s| Value::String((*s).to_string()))
                                    .collect(),
                            ),
                        );
                        let (instructions, hidden, errs) = attach_instructions(&mut flat, &entry);
                        out.push(SecureEntry {
                            fields: flat,
                            instructions,
                            hidden_groups: hidden,
                            decrypt_errors: errs,
                        });
                        continue;
                    }
                }
            }

            let mut flat = flatten_raw_entry(&entry, false);
            let (instructions, hidden, errs) = attach_instructions(&mut flat, &entry);
            out.push(SecureEntry {
                fields: flat,
                instructions,
                hidden_groups: hidden,
                decrypt_errors: errs,
            });
        }
        Ok(out)
    }

    /// Append a `tn.read.tampered_row_skipped` admin event with public
    /// fields only. The bad row's payload is NOT exposed.
    fn emit_tampered_row_skipped(&self, entry: &ReadEntry, reasons: &[&'static str]) -> Result<()> {
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
                    .map(|s| Value::String((*s).to_string()))
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
        let mut out: Vec<(ReadEntry, ValidFlags)> = Vec::new();
        let mut prev_hash_by_event: HashMap<String, String> = HashMap::new();
        let public_set: HashSet<&str> = self.cfg.public_fields.iter().map(String::as_str).collect();
        let group_names: HashSet<&str> = self.cfg.groups.keys().map(String::as_str).collect();

        for res in LogFileReader::open(log_path, &self.storage)? {
            // DX review 0.4.2a3 follow-up: a single malformed row (bad
            // base64 ciphertext, JSON parse failure, etc.) must not
            // halt iteration. Skip the row and emit a sentinel triple
            // with the special event_type "<parse-error>" + all-false
            // validity flags; the reader's verify='skip' path
            // recognises this and counts it as ``skipped_parse``.
            let env = match res {
                Ok(e) => e,
                Err(e) => {
                    out.push((
                        ReadEntry {
                            envelope: serde_json::json!({
                                "event_type": "<parse-error>",
                                "_parse_error": e.to_string(),
                            }),
                            plaintext_per_group: BTreeMap::new(),
                        },
                        ValidFlags {
                            signature: false,
                            row_hash: false,
                            chain: false,
                        },
                    ));
                    continue;
                }
            };

            let event_type = env
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let prev = env
                .get("prev_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let row_hash = env
                .get("row_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let sequence = env.get("sequence").and_then(Value::as_u64).unwrap_or(0);
            let did = env
                .get("device_identity")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let signature = env
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            // Chain-disabled ceremonies (telemetry / secure_log /
            // stdout — anything with `ceremony.chain: false`) emit
            // every row with `prev_hash=""` + `sequence=1` sentinels.
            // The writer never advances the chain; the on-disk shape
            // is "N independent attestations" rather than a linked
            // list. A byte-for-byte `prev_hash == prior.row_hash`
            // compare always fails from row 2 onward. Skip the
            // per-row chain check entirely for such ceremonies — the
            // chain claim isn't being made, so there's nothing to
            // verify against. We could check the sentinel pattern is
            // intact (`prev == ""` + `sequence == 1`) and fail
            // otherwise; for now treat chain=false as "chain is not
            // a load-bearing field," matching the writer's contract.
            //
            // sequence is read for parity with the writer's sentinel
            // contract and to make this branch self-documenting in
            // a future tightening.
            let _ = sequence;
            let last = prev_hash_by_event.get(&event_type).cloned();
            let chain_ok = if !self.cfg.ceremony.chain {
                true
            } else {
                match last {
                    None => true,
                    Some(l) => l == prev,
                }
            };
            // Track the row_hash forward only for chained ceremonies.
            // Chain-disabled rows have nothing to chain, and carrying
            // their row_hash forward would just confuse a future
            // tightening of this branch.
            if self.cfg.ceremony.chain {
                prev_hash_by_event.insert(event_type.clone(), row_hash.clone());
            }

            // Decrypt every group we hold a kit for.
            let (plaintext_per_group, groups_for_hash, row_parse_error) =
                self.decrypt_groups_for_row(&env);

            // DX review 0.4.2a3 follow-up: if any per-row error fired
            // during the group/ciphertext loop above, surface a
            // sentinel triple and move on. Don't update
            // ``prev_hash_by_event`` — subsequent rows that chain
            // through this one will fail chain verify, which is the
            // correct semantics (the chain branched at this row, and
            // we can't tell which fork is real).
            if let Some(err) = row_parse_error {
                out.push((
                    ReadEntry {
                        envelope: serde_json::json!({
                            "event_type": "<parse-error>",
                            "_parse_error": err,
                        }),
                        plaintext_per_group: BTreeMap::new(),
                    },
                    ValidFlags {
                        signature: false,
                        row_hash: false,
                        chain: false,
                    },
                ));
                continue;
            }

            // Recompute row_hash from envelope + decrypted/raw groups.
            let public_out = recompute_public_fields(&env, &public_set, &group_names);
            let timestamp = env
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let event_id = env
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let level = env
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            // Row-hash sentinel: when the writer's ceremony has both
            // `chain: false` AND `sign: false` (telemetry, stdout),
            // `need_row_hash` was false at emit time and the
            // envelope's `row_hash` field is the documented empty
            // sentinel. Recomputing would produce a non-empty hash
            // and the byte compare would always fail. Accept the
            // sentinel as "row_hash is not a load-bearing field for
            // this ceremony shape" — same shape the writer
            // documents at emit time.
            let row_hash_ok =
                if !self.cfg.ceremony.chain && !self.cfg.ceremony.sign && row_hash.is_empty() {
                    true
                } else {
                    let expected = compute_row_hash(&RowHashInput {
                        device_identity: &did,
                        timestamp: &timestamp,
                        event_id: &event_id,
                        event_type: &event_type,
                        level: &level,
                        prev_hash: &prev,
                        public_fields: &public_out,
                        groups: &groups_for_hash,
                    });
                    expected == row_hash
                };

            // Signature: empty signature counts as `false` (unsigned mode
            // is intentionally fail-closed for verifiers — matches Python).
            let sig_ok = if signature.is_empty() {
                false
            } else {
                match signature_from_b64(&signature) {
                    Ok(sig_bytes) => DeviceKey::verify_did(&did, row_hash.as_bytes(), &sig_bytes)
                        .unwrap_or(false),
                    Err(_) => false,
                }
            };

            out.push((
                ReadEntry {
                    envelope: env,
                    plaintext_per_group,
                },
                ValidFlags {
                    signature: sig_ok,
                    row_hash: row_hash_ok,
                    chain: chain_ok,
                },
            ));
        }
        Ok(out)
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
                        // Decrypt if we hold a kit for this group.
                        if let Some(gstate_arc) = self.groups.get(k) {
                            let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                            match gstate.cipher.decrypt(&ct) {
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
                                    plaintext_per_group
                                        .insert(k.clone(), serde_json::json!({"$no_read_key": true}));
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
        ) {
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
                match gstate.cipher.decrypt(&ct) {
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

/// Map a [`ValidFlags`] to the public ``invalid_reasons`` shape.
pub(crate) fn invalid_reasons(valid: ValidFlags) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if !valid.signature {
        out.push("signature");
    }
    if !valid.row_hash {
        out.push("row_hash");
    }
    if !valid.chain {
        out.push("chain");
    }
    out
}

/// Lift the six tn.agents fields out of `flat` into a typed
/// `Instructions` block. Returns the instructions plus the
/// `(hidden_groups, decrypt_errors)` lists already computed by
/// [`flatten_raw_entry`].
pub(crate) fn attach_instructions(
    flat: &mut FlatEntry,
    raw: &ReadEntry,
) -> (Option<Instructions>, Vec<String>, Vec<String>) {
    // Pull hidden_groups / decrypt_errors out so we can return them as
    // typed Vec<String>. They were inserted by flatten_raw_entry.
    let hidden = match flat.remove("_hidden_groups") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let errs = match flat.remove("_decrypt_errors") {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };

    let body = raw.plaintext_per_group.get("tn.agents");
    let Some(obj) = body.and_then(Value::as_object) else {
        return (None, hidden, errs);
    };
    if obj.get("$no_read_key") == Some(&Value::Bool(true))
        || obj.get("$decrypt_error") == Some(&Value::Bool(true))
    {
        return (None, hidden, errs);
    }

    // Both fetch the field for the Instructions block AND remove it
    // from the flat top level. flat already had these (flatten_raw_entry
    // merges every readable group's fields).
    let take = |flat: &mut FlatEntry, k: &str| -> String {
        flat.remove(k);
        obj.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    };
    let instr = Instructions {
        instruction: take(flat, "instruction"),
        use_for: take(flat, "use_for"),
        do_not_use_for: take(flat, "do_not_use_for"),
        consequences: take(flat, "consequences"),
        on_violation_or_error: take(flat, "on_violation_or_error"),
        policy: take(flat, "policy"),
    };
    if instr.instruction.is_empty()
        && instr.use_for.is_empty()
        && instr.do_not_use_for.is_empty()
        && instr.consequences.is_empty()
        && instr.on_violation_or_error.is_empty()
        && instr.policy.is_empty()
    {
        return (None, hidden, errs);
    }
    (Some(instr), hidden, errs)
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
/// (0.4.3a1 phase G flipped it from the legacy `did`); leaving the stale
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
/// history. (FINDINGS.md #12.)
pub(crate) fn flat_in_current_run(flat: &FlatEntry, current_run_id: &str) -> bool {
    matches!(flat.get("run_id"), Some(Value::String(s)) if s == current_run_id)
}

/// True iff `log_path` is a foreign publisher's log (different `did`
/// on the first envelope) AND we have a kit on disk that could decrypt
/// it. Used by [`Runtime::read_from`] to auto-route cross-publisher
/// reads through the foreign-decrypt path. Mirrors Python's
/// `_is_foreign_log` and TS's `_isForeignLog`.
///
/// Conservative on failure: if the file is unreadable, has no
/// parseable line, lacks our default kit, or is exactly our own log,
/// return false so the regular path runs and surfaces the underlying
/// error itself.
pub(crate) fn is_foreign_log(
    log_path: &Path,
    own_log: &Path,
    own_did: &str,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> bool {
    // Exempt exactly our own log path — post-flush "reading my own log"
    // case where the auto-discovery cfg may have a different device but
    // the log is conceptually own. Narrowed per AVL J7.1 Bug 2.
    // `canonicalize` is filesystem-only (resolves symlinks) and has
    // no Storage equivalent; we keep it as a native shortcut. On wasm
    // it'll just fail (no symlinks) and we fall through to comparing
    // raw paths via the rest of the logic.
    if let (Ok(a), Ok(b)) = (log_path.canonicalize(), own_log.canonicalize()) {
        if a == b {
            return false;
        }
    }

    // No kit on disk → foreign route guaranteed to yield $no_read_key
    // for every entry. Regular path's "kit not entitled" is more
    // actionable, so let it run.
    if !storage.exists(&keystore.join("default.btn.mykit")) {
        return false;
    }

    // Peek the first parseable envelope's `did`.
    let Ok(bytes) = storage.read_bytes(log_path) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    for raw_line in text.split('\n') {
        let s = raw_line.trim();
        if s.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<Value>(s) else {
            continue;
        };
        if let Some(env_did) = env.get("device_identity").and_then(Value::as_str) {
            if !env_did.is_empty() {
                return env_did != own_did;
            }
        }
        // First non-empty line had no did — give up; let regular path run.
        return false;
    }
    false
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
    use crate::read_as_recipient::{read_as_recipient, ReadAsRecipientOptions};

    // Discover every group the keystore has a kit for. The foreign
    // route is btn-only today (read_as_recipient errors out on JWE
    // keys) so we only scan `<group>.btn.mykit`.
    let mut groups: Vec<String> = Vec::new();
    if let Ok(entries) = storage.list(keystore) {
        for path in entries {
            let Some(s) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(stem) = s.strip_suffix(".btn.mykit") {
                if !stem.is_empty() {
                    groups.push(stem.to_string());
                }
            }
        }
    }
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
        let foreign = read_as_recipient(log_path, keystore, opts)?;
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
