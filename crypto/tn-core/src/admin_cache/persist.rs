//! Admin-state cache persistence: last-known-value snapshot save/load.
//!
//! Split out of `admin_cache.rs` (file-size refactor). A further
//! `impl AdminStateCache` block; `use super::*` re-imports the parent's
//! types, and the struct's private fields are visible to this child.

use super::*;

impl AdminStateCache {
    // ------------------------------------------------------------------
    // Persistence (atomic temp+rename)
    // ------------------------------------------------------------------

    pub(super) fn save_to_disk(&self) -> Result<()> {
        if let Some(parent) = self.lkv_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut clock_obj = Map::new();
        for (did, et_map) in &self.clock {
            let mut inner = Map::new();
            for (et, seq) in et_map {
                inner.insert(et.clone(), Value::Number((*seq).into()));
            }
            clock_obj.insert(did.clone(), Value::Object(inner));
        }

        let row_hashes: Vec<String> = {
            let mut v: Vec<String> = self.row_hashes.iter().cloned().collect();
            v.sort();
            v
        };

        let mut revoked_arr = Vec::new();
        for ((g, li), rh) in &self.revoked_leaves {
            let mut o = Map::new();
            o.insert("group".into(), Value::String(g.clone()));
            o.insert("leaf_index".into(), Value::Number((*li).into()));
            o.insert(
                "row_hash".into(),
                rh.clone()
                    .map_or(Value::Null, Value::String),
            );
            revoked_arr.push(Value::Object(o));
        }
        let mut rotations_arr = Vec::new();
        for ((g, gen), prev) in &self.rotations_seen {
            let mut o = Map::new();
            o.insert("group".into(), Value::String(g.clone()));
            o.insert("generation".into(), Value::Number((*gen).into()));
            o.insert(
                "previous_kit_sha256".into(),
                Value::String(prev.clone()),
            );
            rotations_arr.push(Value::Object(o));
        }
        let mut coord_arr = Vec::new();
        for ((d, e, s), rh) in &self.coord_to_row_hash {
            let mut o = Map::new();
            o.insert("did".into(), Value::String(d.clone()));
            o.insert("event_type".into(), Value::String(e.clone()));
            o.insert("sequence".into(), Value::Number((*s).into()));
            o.insert("row_hash".into(), Value::String(rh.clone()));
            coord_arr.push(Value::Object(o));
        }

        let head_conflicts_v: Vec<Value> = self
            .head_conflicts
            .iter()
            .map(|c| serde_json::to_value(c).expect("conflict serializable"))
            .collect();

        let mut doc = Map::new();
        doc.insert("version".into(), Value::Number(LKV_VERSION.into()));
        doc.insert(
            "ceremony_id".into(),
            Value::String(self.cfg.ceremony.id.clone()),
        );
        doc.insert("clock".into(), Value::Object(clock_obj));
        doc.insert(
            "head_row_hash".into(),
            self.head_row_hash
                .clone()
                .map_or(Value::Null, Value::String),
        );
        doc.insert("at_offset".into(), Value::Number(self.at_offset.into()));
        doc.insert("state".into(), self.state.clone());
        doc.insert("head_conflicts".into(), Value::Array(head_conflicts_v));
        doc.insert(
            "_row_hashes".into(),
            Value::Array(row_hashes.into_iter().map(Value::String).collect()),
        );
        doc.insert("_revoked_leaves".into(), Value::Array(revoked_arr));
        doc.insert("_rotations_seen".into(), Value::Array(rotations_arr));
        doc.insert("_coord_to_row_hash".into(), Value::Array(coord_arr));

        let serialized = serde_json::to_string_pretty(&Value::Object(doc))?;
        let tmp = self
            .lkv_path
            .with_file_name(format!("{}.tmp", file_name_or(&self.lkv_path, "admin.lkv.json")));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(serialized.as_bytes())?;
            f.flush()?;
        }
        std::fs::rename(&tmp, &self.lkv_path)?;
        Ok(())
    }

    /// Rehydrate from the LKV cache file. Thin orchestrator that
    /// short-circuits on every validation failure and otherwise
    /// delegates each field's deserialisation to a small helper. Each
    /// helper is independently readable, and ``load_from_disk`` reads
    /// as the literal sequence of stored fields it loads.
    pub(super) fn load_from_disk(&mut self) {
        let Some(m) = self.read_lkv_doc() else {
            return;
        };
        if !self.lkv_doc_is_current(&m) {
            return;
        }
        self.load_state(&m);
        self.load_clock(&m);
        self.head_row_hash = m
            .get("head_row_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        self.at_offset = m
            .get("at_offset")
            .and_then(Value::as_u64)
            .and_then(|x| usize::try_from(x).ok())
            .unwrap_or(0);
        self.load_head_conflicts(&m);
        self.load_row_hashes(&m);
        self.load_revoked_leaves(&m);
        self.load_rotations_seen(&m);
        self.load_coord_to_row_hash(&m);
    }

    /// Read + JSON-parse the LKV file. Returns ``None`` for every
    /// failure mode (missing file, unreadable, malformed JSON,
    /// non-object root) — the caller falls back to a fresh replay
    /// from the admin log.
    fn read_lkv_doc(&self) -> Option<Map<String, Value>> {
        if !self.lkv_path.exists() {
            return None;
        }
        let text = std::fs::read_to_string(&self.lkv_path).ok()?;
        let doc: Value = serde_json::from_str(&text).ok()?;
        match doc {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    /// True iff the LKV doc matches the current schema version AND
    /// the ceremony we're loading into. A version skew or a
    /// ceremony mismatch means the file is stale; the caller drops
    /// it and rebuilds.
    fn lkv_doc_is_current(&self, m: &Map<String, Value>) -> bool {
        let version_ok =
            m.get("version").and_then(Value::as_u64) == Some(u64::from(LKV_VERSION));
        let ceremony_ok = m.get("ceremony_id").and_then(Value::as_str)
            == Some(self.cfg.ceremony.id.as_str());
        version_ok && ceremony_ok
    }

    fn load_state(&mut self, m: &Map<String, Value>) {
        let Some(state) = m.get("state") else { return };
        let mut base = empty_state();
        if let (Value::Object(base_m), Value::Object(in_m)) = (&mut base, state) {
            for k in [
                "ceremony",
                "groups",
                "recipients",
                "rotations",
                "coupons",
                "enrolments",
                "vault_links",
            ] {
                if let Some(v) = in_m.get(k) {
                    base_m.insert(k.to_string(), v.clone());
                }
            }
        }
        self.state = base;
    }

    fn load_clock(&mut self, m: &Map<String, Value>) {
        let Some(Value::Object(clock_m)) = m.get("clock") else {
            return;
        };
        for (did, v) in clock_m {
            let Value::Object(et_m) = v else { continue };
            let mut inner = BTreeMap::new();
            for (et, seq_v) in et_m {
                if let Some(s) = seq_v.as_u64() {
                    inner.insert(et.clone(), s);
                }
            }
            self.clock.insert(did.clone(), inner);
        }
    }

    fn load_head_conflicts(&mut self, m: &Map<String, Value>) {
        let Some(Value::Array(arr)) = m.get("head_conflicts") else {
            return;
        };
        for c in arr {
            if let Ok(parsed) = serde_json::from_value::<ChainConflict>(c.clone()) {
                self.head_conflicts.push(parsed);
            }
        }
    }

    fn load_row_hashes(&mut self, m: &Map<String, Value>) {
        let Some(Value::Array(arr)) = m.get("_row_hashes") else {
            return;
        };
        for rh in arr {
            if let Some(s) = rh.as_str() {
                self.row_hashes.insert(s.to_string());
            }
        }
    }

    fn load_revoked_leaves(&mut self, m: &Map<String, Value>) {
        let Some(Value::Array(arr)) = m.get("_revoked_leaves") else {
            return;
        };
        for entry in arr {
            let g = entry.get("group").and_then(Value::as_str);
            let li = entry.get("leaf_index").and_then(Value::as_u64);
            let rh = entry.get("row_hash").and_then(Value::as_str);
            if let (Some(g), Some(li)) = (g, li) {
                self.revoked_leaves
                    .insert((g.to_string(), li), rh.map(str::to_string));
            }
        }
    }

    fn load_rotations_seen(&mut self, m: &Map<String, Value>) {
        let Some(Value::Array(arr)) = m.get("_rotations_seen") else {
            return;
        };
        for entry in arr {
            let g = entry.get("group").and_then(Value::as_str);
            let gen = entry.get("generation").and_then(Value::as_u64);
            let prev = entry.get("previous_kit_sha256").and_then(Value::as_str);
            if let (Some(g), Some(gen), Some(prev)) = (g, gen, prev) {
                self.rotations_seen
                    .insert((g.to_string(), gen), prev.to_string());
            }
        }
    }

    fn load_coord_to_row_hash(&mut self, m: &Map<String, Value>) {
        let Some(Value::Array(arr)) = m.get("_coord_to_row_hash") else {
            return;
        };
        for entry in arr {
            let d = entry.get("device_identity").and_then(Value::as_str);
            let e = entry.get("event_type").and_then(Value::as_str);
            let s = entry.get("sequence").and_then(Value::as_u64);
            let rh = entry.get("row_hash").and_then(Value::as_str);
            if let (Some(d), Some(e), Some(s), Some(rh)) = (d, e, s, rh) {
                self.coord_to_row_hash
                    .insert((d.to_string(), e.to_string(), s), rh.to_string());
            }
        }
    }
}
