//! Admin verbs: cipher-agnostic recipient management (add/revoke/count,
//! recipients listing, admin_state projection) plus vault link/unlink.
//! Split out of `runtime.rs`; this is one of `Runtime`'s impl blocks.

use super::*;

impl Runtime {
    // ------------------------------------------------------------------
    // Admin verbs: cipher-agnostic recipient management.
    //
    // Public names follow the SDK parity matrix (tn-protocol/docs/sdk-parity.md):
    // `admin_add_recipient`, `admin_revoke_recipient`, `admin_revoked_count`.
    // Today only btn ceremonies are supported; JWE support lands alongside the
    // second cipher and reuses these same public names.
    // ------------------------------------------------------------------

    /// Mint a new reader kit for `group`, write it to `out_kit_path`, persist
    /// the updated publisher state, and return the recipient identifier (leaf
    /// index for btn).
    ///
    /// When `recipient_did` is `Some`, a `tn.recipient.added` event is
    /// appended to the log carrying the leaf index + recipient DID + kit SHA.
    /// Readers can replay these events to reconstruct the recipient map
    /// without any sidecar state file; the attested log is the source of truth.
    ///
    /// Matches Python `tn.admin_add_recipient(group, out_path, recipient_did)`.
    ///
    /// # Errors
    /// - `InvalidConfig` if `group` is not a btn group in this runtime.
    /// - `Io` if the state or kit file cannot be written.
    /// - `Btn` if the tree is exhausted or minting fails.
    ///
    /// # Panics
    ///
    /// Panics if the group's `PublisherState` mutex is poisoned by a prior panic
    /// while holding it. The runtime treats a poisoned admin mutex as an
    /// unrecoverable invariant violation.
    pub fn admin_add_recipient(
        &self,
        group: &str,
        out_kit_path: &Path,
        recipient_did: Option<&str>,
    ) -> Result<u64> {
        // FINDINGS #5 cross-binding parity: reject suffix-mismatched
        // filenames up front. The kit_bundle exporter regex requires
        // `.btn.mykit`; non-matching files get silently skipped on
        // export and the publisher's own self-kit ships in their
        // place — a critical identity-leak path. Mirrors Python
        // `tn.admin_add_recipient` and TS `client.adminAddRecipient`.
        let basename = out_kit_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !basename.ends_with(".btn.mykit") || basename == ".btn.mykit" {
            return Err(Error::InvalidConfig(format!(
                "admin_add_recipient: out_kit_path basename must end with \
                 '.btn.mykit' (e.g. {group:?}.btn.mykit, or \
                 {group:?}_alt.btn.mykit for a second kit in the same group), \
                 got {basename:?}. The kit_bundle exporter regex requires the \
                 .btn.mykit suffix; non-matching files get silently skipped \
                 and the publisher's own self-kit ships in their place \
                 (FINDINGS #5). For ergonomic per-recipient bundling, use \
                 Runtime::bundle_for_recipient — it handles minting + \
                 canonical filename + export in one call."
            )));
        }
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_add_recipient: group {group:?} is not a btn publisher group in this runtime"
            ))
        })?;
        let mut pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");

        // Snapshot the pre-mutation state bytes as the CAS prior.
        // We READ THE FILE rather than re-serialising the in-memory
        // cipher because PublisherState::from_bytes(x).to_bytes() is
        // not guaranteed byte-stable: a load + re-serialise can
        // produce different bytes than the originals (set ordering,
        // internal layout). Comparing in-memory bytes against disk
        // would false-positive on every admin verb in single-process
        // mode. The Python BtnGroupCipher caches _last_persisted_bytes
        // for the same reason.
        //
        // The keystore now routes through `self.storage` so wasm
        // consumers can satisfy these reads + the CAS write below via
        // their `JsStorageAdapter`. Native `FsStorage` retains the
        // tmp+fsync+rename + flock dance under the hood.
        let keystore_backend = crate::keystore_backend::LocalKeystore::new(
            self.keystore.clone(),
            self.storage.clone(),
        );
        let prior_state_bytes = keystore_backend.read_state(group).map_err(Error::Io)?;

        // Mint the new reader kit. After this point the in-memory
        // cipher is ahead of disk; if the CAS write below fails the
        // caller MUST treat the in-memory state as stale and re-load
        // from disk before any further admin op (the runtime's
        // KeystoreConflict error is the signal).
        let kit = pub_cipher.state_mut().mint()?;
        let leaf_index = kit.leaf().0;
        let kit_bytes = kit.to_bytes();
        let state_bytes = pub_cipher.state_to_bytes();

        // Persist state first (fail before writing kit if state write
        // fails). Atomic + flock + CAS via LocalKeystore: torn-write
        // proof, multi-process serialised, lost-update detected.
        keystore_backend.write_state(group, prior_state_bytes.as_deref(), &state_bytes)?;

        // Kit file is per-recipient — no concurrent writer to race
        // against. Route through `self.storage.write_bytes` so wasm
        // consumers can satisfy the write via their JS callback set;
        // native `FsStorage::write_bytes` creates parents + writes the
        // file directly. (We previously used `atomic_write_bytes`
        // here for the crash-safety tmp+fsync+rename; on native that
        // guarantee was nice but not load-bearing — a torn `.mykit`
        // is recoverable by re-running the admin verb. The wasm path
        // can't realistically replay `fsync` semantics anyway, so
        // moving to `write_bytes` is the right unification.)
        self.storage
            .write_bytes(out_kit_path, &kit_bytes)
            .map_err(Error::Io)?;

        // Rebuild cipher from updated state and swap into the groups table.
        let mykit_bytes = self.btn_mykit.get(group).and_then(Option::as_deref);
        let new_cipher: Arc<dyn GroupCipher> = rebuild_btn_cipher(&pub_cipher, mykit_bytes)?;
        drop(pub_cipher); // release Mutex before taking RwLock write

        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = new_cipher;
        }

        // Emit attested `tn.recipient.added` event so readers/subscribers
        // can reconstruct the recipient map by replaying the log.
        let mut fields = Map::new();
        fields.insert("group".into(), Value::String(group.to_string()));
        fields.insert("leaf_index".into(), Value::Number(leaf_index.into()));
        // recipient_identity is OptionalString; include null when not provided
        // so validate_emit can confirm the field is present.
        fields.insert(
            "recipient_identity".into(),
            recipient_did.map_or(Value::Null, |d| Value::String(d.to_string())),
        );
        fields.insert(
            "kit_sha256".into(),
            Value::String(format!("sha256:{}", hex::encode(sha2_256(&kit_bytes)))),
        );
        // cipher is required by the catalog schema.
        fields.insert("cipher".into(), Value::String("btn".to_string()));
        // Emission failures don't roll back the mint (the kit is already on
        // disk and the state is persisted). Log-and-continue.
        if let Err(e) = self.emit("info", "tn.recipient.added", fields) {
            log::warn!(
                "admin state persisted but attestation emit failed: event_type={} error={}",
                "tn.recipient.added",
                e
            );
        }

        Ok(leaf_index)
    }

    /// Revoke the reader identified by `leaf_index` in `group`.
    ///
    /// Persists the updated publisher state to disk and swaps the cipher so
    /// subsequent `emit` calls exclude the revoked leaf. Emits a
    /// `tn.recipient.revoked` attested event.
    ///
    /// Matches Python `tn.admin_revoke_recipient(group, leaf_index)`.
    ///
    /// # Errors
    /// - `InvalidConfig` if `group` is not a btn publisher group.
    /// - `Io` if the state file cannot be written.
    /// - `Btn` if `leaf_index` is out of range.
    ///
    /// # Panics
    ///
    /// Panics if an internal `Mutex` or `RwLock` is poisoned.
    pub fn admin_revoke_recipient(&self, group: &str, leaf_index: u64) -> Result<()> {
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_revoke_recipient: group {group:?} is not a btn publisher group"
            ))
        })?;
        let mut pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");

        // Pre-mutation snapshot for CAS — read the file rather than
        // re-serialise the in-memory cipher (see comment in
        // admin_add_recipient: PublisherState round-trip is not
        // byte-stable). On KeystoreConflict the in-memory state is
        // ahead of disk and must be discarded by the caller.
        //
        // Routes through `self.storage` for wasm parity (admin verbs
        // on wasm would otherwise short-circuit the storage abstraction
        // and hit a stubbed `std::fs::read`).
        let keystore_backend = crate::keystore_backend::LocalKeystore::new(
            self.keystore.clone(),
            self.storage.clone(),
        );
        let prior_state_bytes = keystore_backend.read_state(group).map_err(Error::Io)?;

        pub_cipher
            .state_mut()
            .revoke_by_leaf(tn_btn::LeafIndex(leaf_index))?;
        let state_bytes = pub_cipher.state_to_bytes();

        // Atomic + flock + CAS write.
        keystore_backend.write_state(group, prior_state_bytes.as_deref(), &state_bytes)?;

        // Rebuild cipher with revocation applied.
        let mykit_bytes = self.btn_mykit.get(group).and_then(Option::as_deref);
        let new_cipher: Arc<dyn GroupCipher> = rebuild_btn_cipher(&pub_cipher, mykit_bytes)?;
        drop(pub_cipher);

        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = new_cipher;
        }

        // Emit attested `tn.recipient.revoked` event.
        let mut fields = Map::new();
        fields.insert("group".into(), Value::String(group.to_string()));
        fields.insert("leaf_index".into(), Value::Number(leaf_index.into()));
        // recipient_identity is OptionalString in the catalog schema; include
        // null so validate_emit can confirm the field is present.
        fields.insert("recipient_identity".into(), Value::Null);
        if let Err(e) = self.emit("info", "tn.recipient.revoked", fields) {
            log::warn!(
                "admin state persisted but attestation emit failed: event_type={} error={}",
                "tn.recipient.revoked",
                e
            );
        }

        Ok(())
    }

    /// Return the number of revoked recipients in `group`'s publisher state.
    ///
    /// Matches Python `tn.admin_revoked_count(group)`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `group` is not a btn publisher group.
    ///
    /// # Panics
    ///
    /// Panics if an internal `Mutex` is poisoned.
    pub fn admin_revoked_count(&self, group: &str) -> Result<usize> {
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_revoked_count: group {group:?} is not a btn publisher group"
            ))
        })?;
        let pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");
        Ok(pub_cipher.state().revoked_count())
    }

    /// Return the current recipient roster for `group` by replaying the log
    /// through the admin reducer. Mirrors Python `tn.recipients(group, …)`
    /// and TypeScript `client.recipients(group, …)`.
    ///
    /// Active recipients are returned sorted by `leaf_index`; when
    /// `include_revoked` is true, revoked entries are appended after the
    /// active ones (also sorted by leaf_index).
    ///
    /// Reducer errors on a single envelope are warn-logged and skipped — a
    /// single corrupt admin event does not abort the whole replay.
    ///
    /// **Divergence from Python/TS:** Rust's `read()` does not currently
    /// produce per-event signature/row_hash/chain validity flags, so
    /// tampered admin events cannot be filtered out the way Python and TS
    /// do via `valid.{signature, row_hash, chain}`. Until `ReadEntry`
    /// carries validity flags, this function trusts whatever `read()`
    /// returned. Tampered envelopes that still parse and pass schema will
    /// be reflected in the roster.
    pub fn recipients(
        &self,
        group: &str,
        include_revoked: bool,
    ) -> Result<Vec<RecipientEntry>> {
        let mut active: BTreeMap<u64, RecipientEntry> = BTreeMap::new();
        let mut revoked: BTreeMap<u64, RecipientEntry> = BTreeMap::new();

        for entry in self.read_raw()? {
            let event_type = entry
                .envelope
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !event_type.starts_with("tn.recipient.") {
                continue;
            }

            let merged = merge_envelope(&entry);
            let merged_v = apply_schema_defaults(event_type, merged);
            let ts = entry
                .envelope
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string);

            let delta = match admin_reduce_envelope(&merged_v) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!(
                        "tn.recipients: admin event failed reduce: event={event_type:?}: {e}"
                    );
                    continue;
                }
            };

            match delta {
                StateDelta::RecipientAdded {
                    group: g,
                    leaf_index: Some(leaf),
                    recipient_identity,
                    kit_sha256,
                    ..
                } if g == group => {
                    active.insert(
                        leaf,
                        RecipientEntry {
                            leaf_index: leaf,
                            recipient_identity,
                            minted_at: ts.clone(),
                            kit_sha256: Some(kit_sha256),
                            revoked: false,
                            revoked_at: None,
                        },
                    );
                }
                StateDelta::RecipientRevoked {
                    group: g,
                    leaf_index: Some(leaf),
                    ..
                } if g == group => {
                    let mut rec = active.remove(&leaf).unwrap_or(RecipientEntry {
                        leaf_index: leaf,
                        recipient_identity: None,
                        minted_at: None,
                        kit_sha256: None,
                        revoked: false,
                        revoked_at: None,
                    });
                    rec.revoked = true;
                    rec.revoked_at.clone_from(&ts);
                    revoked.insert(leaf, rec);
                }
                // Other groups, deltas without a leaf index, or non-recipient
                // deltas — ignored.
                _ => {}
            }
        }

        let mut out: Vec<RecipientEntry> = active.into_values().collect();
        if include_revoked {
            out.extend(revoked.into_values());
        }
        Ok(out)
    }

    /// Return the full local admin state by replaying the log through the
    /// admin reducer. Mirrors Python `tn.admin_state(group=…)`.
    ///
    /// When `group` is `Some`, the `groups`, `recipients`, `rotations`,
    /// `coupons`, and `enrolments` lists are filtered to that group.
    /// `ceremony` and `vault_links` are not filtered.
    ///
    /// If no `tn.ceremony.init` event is present in the log (common for
    /// btn ceremonies — the publisher state lives on disk, not the
    /// attested log), the ceremony record is reconstructed from the
    /// active config with `created_at == None`.
    #[allow(clippy::too_many_lines)] // single replay loop; splitting fragments invariants
    pub fn admin_state(&self, group: Option<&str>) -> Result<AdminState> {
        let mut state = AdminState::default();

        // Active+lifecycle recipient rows keyed by (group, leaf_index).
        let mut by_leaf: BTreeMap<(String, u64), AdminRecipientRecord> = BTreeMap::new();
        // Enrolment rows keyed by (group, peer_did).
        let mut enrolments_by_peer: BTreeMap<(String, String), AdminEnrolment> = BTreeMap::new();
        // Vault links keyed by vault_did.
        let mut vault_links_by_did: BTreeMap<String, AdminVaultLink> = BTreeMap::new();

        for entry in self.read_raw()? {
            let event_type = entry
                .envelope
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            if !(event_type.starts_with("tn.ceremony.")
                || event_type.starts_with("tn.group.")
                || event_type.starts_with("tn.recipient.")
                || event_type.starts_with("tn.rotation.")
                || event_type.starts_with("tn.coupon.")
                || event_type.starts_with("tn.enrolment.")
                || event_type.starts_with("tn.vault."))
            {
                continue;
            }

            let merged = merge_envelope(&entry);
            let merged_v = apply_schema_defaults(&event_type, merged);
            let ts = merged_v
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string);

            let delta = match admin_reduce_envelope(&merged_v) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!(
                        "tn.admin_state: admin event failed reduce: event={event_type:?}: {e}"
                    );
                    continue;
                }
            };

            match delta {
                StateDelta::CeremonyInit {
                    ceremony_id,
                    cipher,
                    device_identity,
                    created_at,
                } => {
                    state.ceremony = Some(AdminCeremony {
                        ceremony_id,
                        cipher,
                        device_identity,
                        created_at: Some(created_at),
                    });
                }
                StateDelta::GroupAdded {
                    group: g,
                    cipher,
                    publisher_identity,
                    added_at,
                } => {
                    state.groups.push(AdminGroupRecord {
                        group: g,
                        cipher,
                        publisher_identity,
                        added_at,
                    });
                }
                StateDelta::RecipientAdded {
                    group: g,
                    leaf_index: Some(leaf),
                    recipient_identity,
                    kit_sha256,
                    ..
                } => {
                    by_leaf.insert(
                        (g.clone(), leaf),
                        AdminRecipientRecord {
                            group: g,
                            leaf_index: leaf,
                            recipient_identity,
                            kit_sha256,
                            minted_at: ts.clone(),
                            active_status: "active".to_string(),
                            revoked_at: None,
                            retired_at: None,
                        },
                    );
                }
                StateDelta::RecipientRevoked {
                    group: g,
                    leaf_index: Some(leaf),
                    ..
                } => {
                    if let Some(rec) = by_leaf.get_mut(&(g, leaf)) {
                        rec.active_status = "revoked".to_string();
                        rec.revoked_at.clone_from(&ts);
                    }
                }
                StateDelta::RotationCompleted {
                    group: g,
                    cipher,
                    generation,
                    previous_kit_sha256,
                    rotated_at,
                    ..
                } => {
                    state.rotations.push(AdminRotation {
                        group: g.clone(),
                        cipher,
                        generation,
                        previous_kit_sha256,
                        rotated_at,
                    });
                    // Retire any currently-active recipients in this group.
                    for ((rg, _leaf), rec) in &mut by_leaf {
                        if rg == &g && rec.active_status == "active" {
                            rec.active_status = "retired".to_string();
                            rec.retired_at.clone_from(&ts);
                        }
                    }
                }
                StateDelta::CouponIssued {
                    group: g,
                    slot,
                    recipient_identity,
                    issued_to,
                } => {
                    state.coupons.push(AdminCoupon {
                        group: g,
                        slot,
                        recipient_identity,
                        issued_to,
                        issued_at: ts.clone(),
                    });
                }
                StateDelta::EnrolmentCompiled {
                    group: g,
                    peer_identity,
                    package_sha256,
                    compiled_at,
                } => {
                    enrolments_by_peer.insert(
                        (g.clone(), peer_identity.clone()),
                        AdminEnrolment {
                            group: g,
                            peer_identity,
                            package_sha256,
                            status: "offered".to_string(),
                            compiled_at: Some(compiled_at),
                            absorbed_at: None,
                        },
                    );
                }
                StateDelta::EnrolmentAbsorbed {
                    group: g,
                    publisher_identity,
                    package_sha256,
                    absorbed_at,
                } => {
                    let key = (g.clone(), publisher_identity.clone());
                    if let Some(existing) = enrolments_by_peer.get_mut(&key) {
                        existing.status = "absorbed".to_string();
                        existing.absorbed_at = Some(absorbed_at);
                    } else {
                        enrolments_by_peer.insert(
                            key,
                            AdminEnrolment {
                                group: g,
                                peer_identity: publisher_identity,
                                package_sha256,
                                status: "absorbed".to_string(),
                                compiled_at: None,
                                absorbed_at: Some(absorbed_at),
                            },
                        );
                    }
                }
                StateDelta::VaultLinked {
                    vault_identity,
                    project_id,
                    linked_at,
                } => {
                    vault_links_by_did.insert(
                        vault_identity.clone(),
                        AdminVaultLink {
                            vault_identity,
                            project_id,
                            linked_at,
                            unlinked_at: None,
                        },
                    );
                }
                StateDelta::VaultUnlinked {
                    vault_identity,
                    unlinked_at,
                    ..
                } => {
                    if let Some(link) = vault_links_by_did.get_mut(&vault_identity) {
                        link.unlinked_at = Some(unlinked_at);
                    }
                }
                // Unknown deltas + RecipientAdded/Revoked with
                // leaf_index == None are catalog-valid but useless to
                // admin_state.
                StateDelta::Unknown { .. }
                | StateDelta::RecipientAdded { .. }
                | StateDelta::RecipientRevoked { .. } => {}
            }
        }

        state.recipients = by_leaf.into_values().collect();
        state.enrolments = enrolments_by_peer.into_values().collect();
        state.vault_links = vault_links_by_did.into_values().collect();

        // Fallback: derive ceremony from active config when no
        // tn.ceremony.init landed in the log (the btn case).
        if state.ceremony.is_none() {
            state.ceremony = Some(AdminCeremony {
                ceremony_id: self.cfg.ceremony.id.clone(),
                cipher: self.cfg.ceremony.cipher.clone(),
                device_identity: self.device.did().to_string(),
                created_at: None,
            });
        }

        if let Some(g) = group {
            state.groups.retain(|x| x.group == g);
            state.recipients.retain(|x| x.group == g);
            state.rotations.retain(|x| x.group == g);
            state.coupons.retain(|x| x.group == g);
            state.enrolments.retain(|x| x.group == g);
        }

        Ok(state)
    }

    /// Emit a signed `tn.vault.linked` admin event, recording that this
    /// ceremony is paired with `vault_did`'s project `project_id`.
    ///
    /// Idempotent: if `admin_state` already shows an active link to
    /// `vault_did` (i.e. an entry whose `unlinked_at` is `None`), this is a
    /// no-op. Mirrors Python `tn.vault_link(vault_did, project_id)`,
    /// which returns `None`.
    pub fn vault_link(&self, vault_did: &str, project_id: &str) -> Result<()> {
        // Idempotency check — match Python: an active link to the same
        // vault_did short-circuits. admin_state failures do NOT block the
        // emit (Python catches blanket `Exception`); on error we proceed.
        if let Ok(state) = self.admin_state(None) {
            for link in &state.vault_links {
                if link.vault_identity == vault_did
                    && link.project_id == project_id
                    && link.unlinked_at.is_none()
                {
                    return Ok(());
                }
            }
        }

        let mut fields = Map::new();
        fields.insert("vault_identity".into(), Value::String(vault_did.to_string()));
        fields.insert("project_id".into(), Value::String(project_id.to_string()));
        fields.insert(
            "linked_at".into(),
            Value::String(current_timestamp_rfc3339()),
        );
        self.emit("info", "tn.vault.linked", fields)
    }

    /// Emit a signed `tn.vault.unlinked` admin event, recording that the
    /// pairing between this ceremony and `vault_did`'s project
    /// `project_id` has been severed.
    ///
    /// `reason` is an optional free-form string forwarded into the event.
    ///
    /// Mirrors Python `tn.vault_unlink(vault_did, project_id, reason)`.
    pub fn vault_unlink(
        &self,
        vault_did: &str,
        project_id: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut fields = Map::new();
        fields.insert("vault_identity".into(), Value::String(vault_did.to_string()));
        fields.insert("project_id".into(), Value::String(project_id.to_string()));
        fields.insert(
            "unlinked_at".into(),
            Value::String(current_timestamp_rfc3339()),
        );
        // Only include reason when provided; the catalog schema treats it as
        // OptionalString so absent vs null both validate, but matching
        // Python's "reason: None when unset" requires emitting null.
        // Python passes `reason: None` unconditionally; mirror that so the
        // canonical row matches across SDKs.
        match reason {
            Some(r) => fields.insert("reason".into(), Value::String(r.to_string())),
            None => fields.insert("reason".into(), Value::Null),
        };
        self.emit("info", "tn.vault.unlinked", fields)
    }
}
