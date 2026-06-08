//! Admin-log envelope handlers: per-event-type state application.
//!
//! Split out of `admin_cache.rs` (file-size refactor). A further
//! `impl AdminStateCache` block; `use super::*` re-imports the parent's
//! types, and the struct's private fields are visible to this child.

use super::*;

impl AdminStateCache {
    /// Apply one admin envelope to the materialised state.
    ///
    /// Thin orchestrator: extract identity fields, run cross-cutting
    /// checks (coordinate-fork detection, dedupe, vector clock,
    /// head pointer), then dispatch to a per-event-type handler. The
    /// shape mirrors the Python ``AdminStateCache._apply_envelope``
    /// refactor (PR #41) — same prelude, same handler set, same
    /// behaviour.
    pub(super) fn apply_envelope(&mut self, env: &Value) {
        let Some(rh) = env.get("row_hash").and_then(Value::as_str) else {
            return;
        };

        let did = env.get("device_identity").and_then(Value::as_str);
        let et = env.get("event_type").and_then(Value::as_str);
        let seq = env.get("sequence").and_then(Value::as_u64);

        // Coord-fork detection runs BEFORE dedupe — we want to surface
        // the conflict even if the second envelope is one we'd skip.
        self.record_coord_fork_if_any(did, et, seq, rh);

        if self.row_hashes.contains(rh) {
            return;
        }
        self.row_hashes.insert(rh.to_string());

        self.update_clock(did, et, seq);
        self.head_row_hash = Some(rh.to_string());

        let ts = env.get("timestamp").and_then(Value::as_str);
        match et.unwrap_or("") {
            "tn.ceremony.init"      => self.on_ceremony_init(env, ts),
            "tn.group.added"        => self.on_group_added(env, ts),
            "tn.recipient.added"    => self.on_recipient_added(env, ts, rh),
            "tn.recipient.revoked"  => self.on_recipient_revoked(env, ts, rh),
            "tn.rotation.completed" => self.on_rotation_completed(env, ts),
            "tn.coupon.issued"      => self.on_coupon_issued(env, ts),
            "tn.enrolment.compiled" => self.on_enrolment_compiled(env, ts),
            "tn.enrolment.absorbed" => self.on_enrolment_absorbed(env, ts),
            "tn.vault.linked"       => self.on_vault_linked(env, ts),
            "tn.vault.unlinked"     => self.on_vault_unlinked(env, ts),
            _ => { /* unknown admin event_type — clock updates only */ }
        }
    }

    /// Record a ``SameCoordinateFork`` conflict iff we've already seen
    /// a different envelope at the same ``(did, event_type, sequence)``
    /// coordinate. Idempotent — won't double-record a conflict that's
    /// already in ``head_conflicts``.
    fn record_coord_fork_if_any(
        &mut self,
        did: Option<&str>,
        et: Option<&str>,
        seq: Option<u64>,
        rh: &str,
    ) {
        let (Some(d), Some(e), Some(s)) = (did, et, seq) else {
            return;
        };
        let key = (d.to_string(), e.to_string(), s);
        let Some(existing_rh) = self.coord_to_row_hash.get(&key) else {
            self.coord_to_row_hash.insert(key, rh.to_string());
            return;
        };
        if existing_rh == rh {
            return;
        }
        let already = self.head_conflicts.iter().any(|c| {
            matches!(
                c,
                ChainConflict::SameCoordinateFork {
                    did: cd,
                    event_type: ce,
                    sequence: cs,
                    ..
                } if cd == d && ce == e && *cs == s
            )
        });
        if !already {
            self.head_conflicts.push(ChainConflict::SameCoordinateFork {
                did: d.to_string(),
                event_type: e.to_string(),
                sequence: s,
                row_hash_a: existing_rh.clone(),
                row_hash_b: rh.to_string(),
            });
        }
    }

    /// Bump the vector clock entry for ``(did, event_type)`` to
    /// ``max(current, seq)``. No-op when any of the three are missing
    /// (envelope predates the clock-bearing schema).
    fn update_clock(&mut self, did: Option<&str>, et: Option<&str>, seq: Option<u64>) {
        let (Some(d), Some(e), Some(s)) = (did, et, seq) else {
            return;
        };
        let slot = self.clock.entry(d.to_string()).or_default();
        let cur = slot.get(e).copied().unwrap_or(0);
        if s > cur {
            slot.insert(e.to_string(), s);
        }
    }

    // ------------------------------------------------------------------
    // Per-event-type handlers. Each one owns the projection for its
    // event_type onto ``self.state``. Same arm bodies as before; broken
    // out so each is independently readable and the dispatch table in
    // ``apply_envelope`` reads as a literal table of contents.
    // ------------------------------------------------------------------

    fn on_ceremony_init(&mut self, env: &Value, ts: Option<&str>) {
        let mut o = Map::new();
        o.insert(
            "ceremony_id".into(),
            env.get("ceremony_id").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "cipher".into(),
            env.get("cipher").cloned().unwrap_or(Value::Null),
        );
        let dd = env
            .get("device_identity")
            .cloned()
            .or_else(|| env.get("device_identity").cloned())
            .unwrap_or(Value::Null);
        o.insert("device_identity".into(), dd);
        o.insert(
            "created_at".into(),
            env.get("created_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        self.state["ceremony"] = Value::Object(o);
    }

    fn on_group_added(&mut self, env: &Value, ts: Option<&str>) {
        let mut o = Map::new();
        o.insert(
            "group".into(),
            env.get("group").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "cipher".into(),
            env.get("cipher").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "publisher_identity".into(),
            env.get("publisher_identity").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "added_at".into(),
            env.get("added_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        if let Some(arr) = self.state.get_mut("groups").and_then(Value::as_array_mut) {
            arr.push(Value::Object(o));
        }
    }

    fn on_recipient_added(&mut self, env: &Value, ts: Option<&str>, rh: &str) {
        let group = env.get("group").and_then(Value::as_str).unwrap_or("");
        let Some(leaf) = env.get("leaf_index").and_then(Value::as_u64) else {
            return;
        };
        // Revoked-then-re-added: leaf reuse, record and bail.
        let key = (group.to_string(), leaf);
        if let Some(rev_rh) = self.revoked_leaves.get(&key).cloned() {
            self.head_conflicts.push(ChainConflict::LeafReuseAttempt {
                group: group.to_string(),
                leaf_index: leaf,
                attempted_row_hash: rh.to_string(),
                originally_revoked_at_row_hash: rev_rh,
            });
            return;
        }
        // Already-active double-add: also leaf reuse.
        let existing_active = self
            .state
            .get("recipients")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter().any(|r| {
                    r.get("group").and_then(Value::as_str) == Some(group)
                        && r.get("leaf_index").and_then(Value::as_u64) == Some(leaf)
                })
            });
        if existing_active {
            self.head_conflicts.push(ChainConflict::LeafReuseAttempt {
                group: group.to_string(),
                leaf_index: leaf,
                attempted_row_hash: rh.to_string(),
                originally_revoked_at_row_hash: None,
            });
            return;
        }
        let mut o = Map::new();
        o.insert("group".into(), Value::String(group.to_string()));
        o.insert("leaf_index".into(), Value::Number(leaf.into()));
        o.insert(
            "recipient_identity".into(),
            env.get("recipient_identity").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "kit_sha256".into(),
            env.get("kit_sha256").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "minted_at".into(),
            ts.map_or(Value::Null, |s| Value::String(s.to_string())),
        );
        o.insert("active_status".into(), Value::String("active".into()));
        o.insert("revoked_at".into(), Value::Null);
        o.insert("retired_at".into(), Value::Null);
        if let Some(arr) = self
            .state
            .get_mut("recipients")
            .and_then(Value::as_array_mut)
        {
            arr.push(Value::Object(o));
        }
    }

    fn on_recipient_revoked(&mut self, env: &Value, ts: Option<&str>, rh: &str) {
        let group = env.get("group").and_then(Value::as_str).unwrap_or("");
        let Some(leaf) = env.get("leaf_index").and_then(Value::as_u64) else {
            return;
        };
        self.revoked_leaves
            .insert((group.to_string(), leaf), Some(rh.to_string()));
        let Some(arr) = self
            .state
            .get_mut("recipients")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        for rec in arr.iter_mut() {
            if rec.get("group").and_then(Value::as_str) == Some(group)
                && rec.get("leaf_index").and_then(Value::as_u64) == Some(leaf)
                && rec.get("active_status").and_then(Value::as_str) == Some("active")
            {
                rec["active_status"] = Value::String("revoked".into());
                rec["revoked_at"] = ts.map_or(Value::Null, |s| Value::String(s.to_string()));
            }
        }
    }

    fn on_rotation_completed(&mut self, env: &Value, ts: Option<&str>) {
        let group = env.get("group").and_then(Value::as_str).unwrap_or("");
        let generation = env.get("generation").and_then(Value::as_u64);
        let prev_kit = env
            .get("previous_kit_sha256")
            .and_then(Value::as_str)
            .unwrap_or("");
        self.record_rotation_conflict_if_any(group, generation, prev_kit);
        self.append_rotation_record(env, ts, group, generation, prev_kit);
        self.retire_active_recipients_in_group(group, ts);
    }

    fn record_rotation_conflict_if_any(
        &mut self,
        group: &str,
        generation: Option<u64>,
        prev_kit: &str,
    ) {
        let Some(gen) = generation else { return };
        let rkey = (group.to_string(), gen);
        if let Some(prev_a) = self.rotations_seen.get(&rkey).cloned() {
            if prev_a != prev_kit && !prev_kit.is_empty() {
                self.head_conflicts.push(ChainConflict::RotationConflict {
                    group: group.to_string(),
                    generation: gen,
                    previous_kit_sha256_a: prev_a,
                    previous_kit_sha256_b: prev_kit.to_string(),
                });
            }
        } else if !prev_kit.is_empty() {
            self.rotations_seen.insert(rkey, prev_kit.to_string());
        }
    }

    fn append_rotation_record(
        &mut self,
        env: &Value,
        ts: Option<&str>,
        group: &str,
        generation: Option<u64>,
        prev_kit: &str,
    ) {
        let mut o = Map::new();
        o.insert("group".into(), Value::String(group.to_string()));
        o.insert(
            "cipher".into(),
            env.get("cipher").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "generation".into(),
            generation.map_or(Value::Null, |g| Value::Number(g.into())),
        );
        o.insert(
            "previous_kit_sha256".into(),
            Value::String(prev_kit.to_string()),
        );
        o.insert(
            "rotated_at".into(),
            env.get("rotated_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        if let Some(arr) = self.state.get_mut("rotations").and_then(Value::as_array_mut) {
            arr.push(Value::Object(o));
        }
    }

    fn retire_active_recipients_in_group(&mut self, group: &str, ts: Option<&str>) {
        let Some(arr) = self
            .state
            .get_mut("recipients")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        for rec in arr.iter_mut() {
            if rec.get("group").and_then(Value::as_str) == Some(group)
                && rec.get("active_status").and_then(Value::as_str) == Some("active")
            {
                rec["active_status"] = Value::String("retired".into());
                rec["retired_at"] = ts.map_or(Value::Null, |s| Value::String(s.to_string()));
            }
        }
    }

    fn on_coupon_issued(&mut self, env: &Value, ts: Option<&str>) {
        let mut o = Map::new();
        o.insert(
            "group".into(),
            env.get("group").cloned().unwrap_or(Value::Null),
        );
        o.insert("slot".into(), env.get("slot").cloned().unwrap_or(Value::Null));
        o.insert(
            "recipient_identity".into(),
            env.get("recipient_identity").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "issued_to".into(),
            env.get("issued_to").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "issued_at".into(),
            ts.map_or(Value::Null, |s| Value::String(s.to_string())),
        );
        if let Some(arr) = self.state.get_mut("coupons").and_then(Value::as_array_mut) {
            arr.push(Value::Object(o));
        }
    }

    fn on_enrolment_compiled(&mut self, env: &Value, ts: Option<&str>) {
        let mut o = Map::new();
        o.insert(
            "group".into(),
            env.get("group").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "peer_identity".into(),
            env.get("peer_identity").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "package_sha256".into(),
            env.get("package_sha256").cloned().unwrap_or(Value::Null),
        );
        o.insert("status".into(), Value::String("offered".into()));
        o.insert(
            "compiled_at".into(),
            env.get("compiled_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        o.insert("absorbed_at".into(), Value::Null);
        if let Some(arr) = self
            .state
            .get_mut("enrolments")
            .and_then(Value::as_array_mut)
        {
            arr.push(Value::Object(o));
        }
    }

    fn on_enrolment_absorbed(&mut self, env: &Value, ts: Option<&str>) {
        let publisher_identity = env
            .get("publisher_identity")
            .and_then(Value::as_str)
            .unwrap_or("");
        let group = env.get("group").and_then(Value::as_str).unwrap_or("");
        if self.update_existing_enrolment(env, ts, group, publisher_identity) {
            return;
        }
        self.append_absorbed_enrolment(env, ts, group, publisher_identity);
    }

    /// Returns true iff an existing ``offered`` enrolment was upgraded
    /// to ``absorbed`` in place. False signals the caller should
    /// append a synthetic record.
    fn update_existing_enrolment(
        &mut self,
        env: &Value,
        ts: Option<&str>,
        group: &str,
        from_did: &str,
    ) -> bool {
        let Some(arr) = self
            .state
            .get_mut("enrolments")
            .and_then(Value::as_array_mut)
        else {
            return false;
        };
        for enr in arr.iter_mut() {
            if enr.get("group").and_then(Value::as_str) == Some(group)
                && enr.get("peer_identity").and_then(Value::as_str) == Some(from_did)
            {
                enr["status"] = Value::String("absorbed".into());
                enr["absorbed_at"] = env
                    .get("absorbed_at")
                    .cloned()
                    .or_else(|| ts.map(|s| Value::String(s.to_string())))
                    .unwrap_or(Value::Null);
                return true;
            }
        }
        false
    }

    fn append_absorbed_enrolment(
        &mut self,
        env: &Value,
        ts: Option<&str>,
        group: &str,
        from_did: &str,
    ) {
        let mut o = Map::new();
        o.insert("group".into(), Value::String(group.to_string()));
        o.insert("peer_identity".into(), Value::String(from_did.to_string()));
        o.insert(
            "package_sha256".into(),
            env.get("package_sha256").cloned().unwrap_or(Value::Null),
        );
        o.insert("status".into(), Value::String("absorbed".into()));
        o.insert("compiled_at".into(), Value::Null);
        o.insert(
            "absorbed_at".into(),
            env.get("absorbed_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        if let Some(arr) = self
            .state
            .get_mut("enrolments")
            .and_then(Value::as_array_mut)
        {
            arr.push(Value::Object(o));
        }
    }

    fn on_vault_linked(&mut self, env: &Value, ts: Option<&str>) {
        let vd = env.get("vault_identity").and_then(Value::as_str).unwrap_or("");
        if vd.is_empty() {
            return;
        }
        let Some(arr) = self
            .state
            .get_mut("vault_links")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        // Vault link is "last write wins" per-vault_identity.
        arr.retain(|l| l.get("vault_identity").and_then(Value::as_str) != Some(vd));
        let mut o = Map::new();
        o.insert("vault_identity".into(), Value::String(vd.to_string()));
        o.insert(
            "project_id".into(),
            env.get("project_id").cloned().unwrap_or(Value::Null),
        );
        o.insert(
            "linked_at".into(),
            env.get("linked_at")
                .cloned()
                .or_else(|| ts.map(|s| Value::String(s.to_string())))
                .unwrap_or(Value::Null),
        );
        o.insert("unlinked_at".into(), Value::Null);
        arr.push(Value::Object(o));
    }

    fn on_vault_unlinked(&mut self, env: &Value, ts: Option<&str>) {
        let vd = env.get("vault_identity").and_then(Value::as_str).unwrap_or("");
        let Some(arr) = self
            .state
            .get_mut("vault_links")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        for link in arr.iter_mut() {
            if link.get("vault_identity").and_then(Value::as_str) == Some(vd) {
                link["unlinked_at"] = env
                    .get("unlinked_at")
                    .cloned()
                    .or_else(|| ts.map(|s| Value::String(s.to_string())))
                    .unwrap_or(Value::Null);
            }
        }
    }
}
