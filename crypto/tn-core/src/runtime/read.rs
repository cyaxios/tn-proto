//! Read paths: flat/raw/verify reads, secure_read, and the
//! read_from_with_validity verify loop. Split out of `runtime.rs`; this
//! is one of `Runtime`'s impl blocks.

use super::*;

impl Runtime {
    /// Read all entries from this runtime's log file, decrypting every group
    /// this runtime can decrypt.
    ///
    /// **Default shape: flat dicts** per the 2026-04-25 read-ergonomics
    /// spec. The six envelope basics (`timestamp`, `event_type`, `level`,
    /// `did`, `sequence`, `event_id`) plus every readable group's
    /// decrypted fields land at the top level. `_hidden_groups` /
    /// `_decrypt_errors` markers surface only when non-empty. The six
    /// reserved `tn.agents` field names DO appear in the flat dict by
    /// default; use [`Runtime::secure_read`] to lift them into a separate
    /// `instructions` block instead.
    ///
    /// Use [`Runtime::read_raw`] for the audit-grade `{envelope,
    /// plaintext_per_group}` shape, [`Runtime::read_with_verify`] for the
    /// flat shape plus a `_valid` block.
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
    pub fn read_all_runs(&self) -> Result<Vec<FlatEntry>> {
        let raw = self.read_raw()?;
        Ok(raw.into_iter().map(|r| flatten_raw_entry(&r, false)).collect())
    }

    /// Like [`Runtime::read`] but adds a `_valid: {signature, row_hash,
    /// chain}` block to each flat dict per spec §1.3.
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

    /// Read all entries as the audit-grade `ReadEntry` shape (envelope +
    /// per-group decrypted plaintext). Mirrors the pre-2026-04-25
    /// `Runtime::read()` return.
    pub fn read_raw(&self) -> Result<Vec<ReadEntry>> {
        let log_path = self.log_path.clone();
        self.read_from(&log_path)
    }

    /// Iterate verified entries — fail-closed on any (signature,
    /// row_hash, chain) failure. Per the 2026-04-25 read-ergonomics spec §3.
    ///
    /// Returns flat dicts in the same default shape as [`Runtime::read`],
    /// plus an `instructions` block when the caller holds the
    /// `tn.agents` kit and the entry carries a populated `tn.agents`
    /// group. The six `tn.agents` field names are NOT flattened into
    /// `fields` — they land in `instructions` as a separate concern.
    ///
    /// `on_invalid` controls the failure mode (skip / raise / forensic).
    /// Under `Skip` (default), a `tn.read.tampered_row_skipped` admin
    /// event is appended to the local log for each dropped row.
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
    fn emit_tampered_row_skipped(
        &self,
        entry: &ReadEntry,
        reasons: &[&'static str],
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
        fields.insert(
            "envelope_sequence".into(),
            sequence.unwrap_or(Value::Null),
        );
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

    /// Read all entries plus per-entry validity flags
    /// `(signature, row_hash, chain)`.
    ///
    /// Verification mirrors Python `tn.reader._read`: chain integrity
    /// per event_type, row_hash recomputed from canonical inputs,
    /// signature checked against the envelope's `did`.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    pub fn read_raw_with_validity(&self) -> Result<Vec<(ReadEntry, ValidFlags)>> {
        let log_path = self.log_path.clone();
        self.read_from_with_validity(&log_path)
    }

    /// As [`Runtime::read_raw_with_validity`] but for an explicit log path.
    ///
    /// # Panics
    ///
    /// Panics if an internal `RwLock` is poisoned.
    #[allow(clippy::too_many_lines)]
    // cognitive_complexity: the read+verify loop walks one envelope at
    // a time and decides per-envelope whether each integrity check
    // (signature, row_hash, chain) passes. Splitting "per-check"
    // helpers would force ValidFlags re-aggregation per row, which
    // breaks the audit-grade trace the reader produces in one pass.
    #[allow(clippy::cognitive_complexity)]
    pub fn read_from_with_validity(
        &self,
        log_path: &Path,
    ) -> Result<Vec<(ReadEntry, ValidFlags)>> {
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
            let sequence = env
                .get("sequence")
                .and_then(Value::as_u64)
                .unwrap_or(0);
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
            let mut plaintext_per_group: BTreeMap<String, Value> = BTreeMap::new();
            let mut groups_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
            // DX review 0.4.2a3 follow-up: per-row resilience for the
            // base64-decode + post-decrypt JSON-parse paths. A row
            // whose ciphertext is corrupt or whose plaintext doesn't
            // parse becomes a sentinel rather than killing iteration.
            let mut row_parse_error: Option<String> = None;
            if let Value::Object(env_map) = &env {
                'group_loop: for (k, v) in env_map {
                    if let Some(g_obj) = v.as_object() {
                        if let Some(ct_str) = g_obj.get("ciphertext").and_then(Value::as_str) {
                            let ct = match STANDARD.decode(ct_str) {
                                Ok(b) => b,
                                Err(e) => {
                                    row_parse_error = Some(format!(
                                        "ciphertext base64 in group {k:?}: {e}"
                                    ));
                                    break 'group_loop;
                                }
                            };
                            let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
                            if let Some(fh_obj) =
                                g_obj.get("field_hashes").and_then(Value::as_object)
                            {
                                for (fname, fv) in fh_obj {
                                    if let Some(s) = fv.as_str() {
                                        field_hashes
                                            .insert(fname.clone(), s.to_string());
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
                                let gstate = gstate_arc
                                    .read()
                                    .expect("group state RwLock poisoned");
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
                                                row_parse_error = Some(format!(
                                                    "plaintext json in group {k:?}: {e}"
                                                ));
                                                break 'group_loop;
                                            }
                                        }
                                    }
                                    Err(
                                        Error::NotEntitled { .. } | Error::NotAPublisher { .. },
                                    ) => {
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
                                plaintext_per_group.insert(
                                    k.clone(),
                                    serde_json::json!({"$no_read_key": true}),
                                );
                            }
                        }
                    }
                }
            }

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
            // The reserved set MUST exclude the same scalars the writer
            // treats as scalars. The wire key for the publisher identity
            // is `device_identity` (0.4.3a1 phase G flipped it from the
            // legacy `did`); leaving the stale `did` here let the
            // `device_identity` scalar leak into `public_out` for a
            // ceremony whose yaml lists it under public_fields, double-
            // hashing it relative to the corrected writer. Mirrors
            // `python/tn/reader.py::_envelope_reserved` and
            // `ts-sdk/.../node_runtime.ts::_ENVELOPE_RESERVED`.
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
            if let Value::Object(env_map) = &env {
                for (k, v) in env_map {
                    if envelope_reserved.contains(k.as_str()) {
                        continue;
                    }
                    if v.as_object()
                        .is_some_and(|o| o.contains_key("ciphertext"))
                    {
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
            let row_hash_ok = if !self.cfg.ceremony.chain
                && !self.cfg.ceremony.sign
                && row_hash.is_empty()
            {
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
                    Ok(sig_bytes) => DeviceKey::verify_did(
                        &did,
                        row_hash.as_bytes(),
                        &sig_bytes,
                    )
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
                        row_parse_error = Some(format!(
                            "ciphertext base64 in group {gname:?}: {e}"
                        ));
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
                            row_parse_error = Some(format!(
                                "plaintext json in group {gname:?}: {e}"
                            ));
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
