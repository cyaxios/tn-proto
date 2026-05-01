//! `Runtime::export` and `Runtime::absorb` — the new universal `.tnpkg`
//! producer / consumer (Section 3.2 of the 2026-04-24 admin log architecture
//! plan). Mirrors `tn/export.py` and `tn/absorb.py`.

#![cfg(feature = "fs")]

use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::admin_cache::{
    is_admin_event_type, resolve_admin_log_path, ChainConflict,
};
use crate::runtime::{AdminState, Runtime};
use crate::signing::DeviceKey;
use crate::tnpkg::{
    clock_dominates, read_tnpkg, sign_manifest, write_tnpkg, Manifest, ManifestKind,
    TnpkgSource, VectorClock,
};
use crate::{Error, Result};

/// Options for `Runtime::export`. Mirrors Python's keyword args.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Manifest kind / dispatch discriminator.
    pub kind: Option<ManifestKind>,
    /// Optional point-to-point recipient DID.
    pub to_did: Option<String>,
    /// Optional scope override.
    pub scope: Option<String>,
    /// Required `true` for `kind=full_keystore`.
    pub confirm_includes_secrets: bool,
    /// For `kit_bundle` / `full_keystore`: optional list of group names. None
    /// means all groups.
    pub groups: Option<Vec<String>>,
    /// For `offer` / `enrolment`: pre-built JSON `Package` body bytes. The
    /// caller is responsible for the canonical JSON layout (sorted keys,
    /// indented). Mirrors Python's `package=<Package>` arg.
    pub package_body: Option<Vec<u8>>,
}

/// Receipt returned from `Runtime::absorb`.
#[derive(Debug, Clone)]
pub struct AbsorbReceipt {
    /// Manifest kind that drove dispatch.
    pub kind: String,
    /// Envelopes / units newly applied.
    pub accepted_count: usize,
    /// Envelopes / units skipped because we already had them.
    pub deduped_count: usize,
    /// True iff receiver's clock dominates manifest's clock.
    pub noop: bool,
    /// For admin snapshots: the AdminState reduced from the local log
    /// (best-effort; may be `None` for non-admin kinds or errors).
    pub derived_state: Option<AdminState>,
    /// Equivocation signals (leaf-reuse, same-coordinate fork, rotation).
    pub conflicts: Vec<ChainConflict>,
    /// For non-admin kinds: legacy status string (`"offer_stashed"`,
    /// `"enrolment_applied"`, etc).
    pub legacy_status: String,
    /// Free-text explanation when status is `"rejected"`.
    pub legacy_reason: String,
    /// Paths in the local keystore whose existing contents were renamed
    /// to a `.previous.<UTC_TS>` sidecar to make room for kits from the
    /// absorbed package. Empty when nothing was overwritten.
    ///
    /// Mirrors Python `AbsorbReceipt.replaced_kit_paths` and TS
    /// `AbsorbReceipt.replacedKitPaths` (FINDINGS #6 cross-binding
    /// parity). Iterate this field after absorb to decide whether to
    /// alert / restore / accept the swap rather than relying on a
    /// printed warning.
    pub replaced_kit_paths: Vec<PathBuf>,
}

impl Runtime {
    /// Pack a `.tnpkg` from local ceremony state.
    ///
    /// # Errors
    /// Returns `Error::InvalidConfig` for `kind=FullKeystore` without
    /// `confirm_includes_secrets=true` (the foot-gun gate). Other errors
    /// surface from filesystem writes or zip serialization.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn export(&self, out_path: &Path, opts: ExportOptions) -> Result<PathBuf> {
        let kind = opts.kind.ok_or_else(|| {
            Error::InvalidConfig("export: ExportOptions.kind is required".into())
        })?;

        if matches!(kind, ManifestKind::FullKeystore) && !opts.confirm_includes_secrets {
            return Err(Error::InvalidConfig(
                "export(kind=FullKeystore) writes the publisher's raw private keys \
                 (local.private + index_master.key) into the zip. Pass \
                 confirm_includes_secrets=true to acknowledge."
                    .into(),
            ));
        }

        let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut clock: VectorClock = BTreeMap::new();
        let mut event_count: u64 = 0;
        let mut head_row_hash: Option<String> = None;
        let mut state_value: Option<Value> = None;
        let mut scope_default: &'static str = "admin";

        match kind {
            ManifestKind::AdminLogSnapshot => {
                let yaml_dir = self.yaml_dir();
                let admin_log_path = resolve_admin_log_path(&yaml_dir, &self.cfg);
                let main_log = self.log_path().to_path_buf();
                let mut sources = vec![main_log.clone()];
                if admin_log_path != main_log {
                    sources.push(admin_log_path);
                }
                let (ndjson, c, count, head) = scan_admin_envelopes(&sources)?;
                body.insert("body/admin.ndjson".into(), ndjson);
                clock = c;
                event_count = count;
                head_row_hash = head;
                if let Ok(s) = self.admin_state(None) {
                    state_value = Some(serde_json::to_value(s)?);
                }
            }
            ManifestKind::Offer | ManifestKind::Enrolment => {
                let pkg = opts.package_body.clone().ok_or_else(|| {
                    Error::InvalidConfig(
                        "export(kind=Offer|Enrolment) requires opts.package_body=<bytes>".into(),
                    )
                })?;
                body.insert("body/package.json".into(), pkg);
                scope_default = "admin";
            }
            ManifestKind::KitBundle | ManifestKind::FullKeystore => {
                let full = matches!(kind, ManifestKind::FullKeystore);
                let (b, kits_meta) =
                    build_kit_bundle_body(&self.keystore_path(), full, opts.groups.as_deref())?;
                body = b;
                let mut state_obj = Map::new();
                state_obj.insert("kits".into(), Value::Array(kits_meta));
                state_obj.insert(
                    "kind".into(),
                    Value::String(if full { "full-keystore".into() } else { "readers-only".into() }),
                );
                state_value = Some(Value::Object(state_obj));
                scope_default = if full { "full" } else { "kit_bundle" };
            }
            ManifestKind::RecipientInvite => {
                return Err(Error::NotImplemented(
                    "export(kind=RecipientInvite) not yet wired in Rust",
                ));
            }
            ManifestKind::ContactUpdate => {
                return Err(Error::NotImplemented(
                    "export(kind=ContactUpdate) not yet wired in Rust",
                ));
            }
        }

        // Assemble + sign manifest.
        let mut manifest = Manifest {
            kind,
            version: crate::tnpkg::MANIFEST_VERSION,
            from_did: self.did().to_string(),
            to_did: opts.to_did.clone(),
            ceremony_id: self.cfg.ceremony.id.clone(),
            as_of: now_iso_millis(),
            scope: opts.scope.clone().unwrap_or_else(|| scope_default.into()),
            clock,
            event_count,
            head_row_hash,
            state: state_value,
            manifest_signature_b64: None,
        };
        // Python signs with the device's Ed25519 key. We hold a `DeviceKey`;
        // build an `ed25519_dalek::SigningKey` from its private bytes.
        let priv_bytes = self.device_private_bytes();
        let sk = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
        sign_manifest(&mut manifest, &sk)?;

        write_tnpkg(out_path, &manifest, &body)?;
        Ok(out_path.to_path_buf())
    }

    /// Apply a `.tnpkg` to local state. Validates manifest signature, dedupes
    /// admin envelopes by row_hash, advances LKV state. Idempotent.
    #[allow(clippy::needless_pass_by_value)]
    pub fn absorb(&self, source: AbsorbSource<'_>) -> Result<AbsorbReceipt> {
        let tn_source = match source {
            AbsorbSource::Path(p) => TnpkgSource::Path(p),
            AbsorbSource::Bytes(b) => TnpkgSource::Bytes(b),
        };
        let (manifest, body) = match read_tnpkg(tn_source) {
            Ok(v) => v,
            Err(e) => {
                return Ok(AbsorbReceipt {
                    kind: "unknown".into(),
                    accepted_count: 0,
                    deduped_count: 0,
                    noop: false,
                    derived_state: None,
                    conflicts: Vec::new(),
                    legacy_status: "rejected".into(),
                    legacy_reason: format!("absorb: not a valid `.tnpkg` zip: {e}"),
                    replaced_kit_paths: Vec::new(),
                });
            }
        };

        if let Err(e) = crate::tnpkg::verify_manifest(&manifest) {
            return Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "rejected".into(),
                legacy_reason: format!(
                    "manifest signature does not verify against from_did {:?}: {e}",
                    manifest.from_did
                ),
                replaced_kit_paths: Vec::new(),
            });
        }

        match manifest.kind {
            ManifestKind::AdminLogSnapshot => self.absorb_admin_log_snapshot(&manifest, &body),
            ManifestKind::KitBundle | ManifestKind::FullKeystore => {
                self.absorb_kit_bundle(&manifest, &body)
            }
            ManifestKind::Offer | ManifestKind::Enrolment => Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 1,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                // Rust does not implement the offer/enrolment side handlers
                // (those live on the Python side today). Surface the package
                // for the caller to route however they want.
                legacy_status: "stashed".into(),
                legacy_reason: format!(
                    "Rust runtime does not yet apply {} packages locally; \
                     decode body/package.json to act on it.",
                    manifest.kind.as_str()
                ),
                replaced_kit_paths: Vec::new(),
            }),
            ManifestKind::RecipientInvite => Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "rejected".into(),
                legacy_reason: format!(
                    "absorb: kind {:?} is reserved but not implemented in Rust",
                    manifest.kind.as_str()
                ),
                replaced_kit_paths: Vec::new(),
            }),
            ManifestKind::ContactUpdate => Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "stashed".into(),
                legacy_reason: format!(
                    "absorb: kind {:?} round-trips through read_manifest but \
                     Rust runtime has no handler yet (per spec §4.6 / D-11). \
                     Decode body/package.json on the Python side to act on it.",
                    manifest.kind.as_str()
                ),
                replaced_kit_paths: Vec::new(),
            }),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn absorb_admin_log_snapshot(
        &self,
        manifest: &Manifest,
        body: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AbsorbReceipt> {
        let yaml_dir = self.yaml_dir();
        let admin_log = resolve_admin_log_path(&yaml_dir, &self.cfg);

        // Build receiver's local clock + row-hash set + revoked leaves from
        // the existing admin log.
        let mut local_clock: VectorClock = BTreeMap::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut revoked_leaves: BTreeMap<(String, u64), Option<String>> = BTreeMap::new();

        if admin_log.exists() {
            let text = std::fs::read_to_string(&admin_log)?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(env) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let did = env.get("did").and_then(Value::as_str);
                let et = env.get("event_type").and_then(Value::as_str);
                let seq = env.get("sequence").and_then(Value::as_u64);
                let rh = env.get("row_hash").and_then(Value::as_str);
                if let Some(rh) = rh {
                    seen.insert(rh.to_string());
                }
                if let (Some(d), Some(e), Some(s)) = (did, et, seq) {
                    let slot = local_clock.entry(d.to_string()).or_default();
                    let cur = slot.get(e).copied().unwrap_or(0);
                    if s > cur {
                        slot.insert(e.to_string(), s);
                    }
                }
                if et == Some("tn.recipient.revoked") {
                    let g = env.get("group").and_then(Value::as_str);
                    let li = env.get("leaf_index").and_then(Value::as_u64);
                    if let (Some(g), Some(li)) = (g, li) {
                        revoked_leaves
                            .insert((g.to_string(), li), rh.map(str::to_string));
                    }
                }
            }
        }

        if clock_dominates(&local_clock, &manifest.clock) {
            // Receiver already has everything the manifest claims.
            return Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: true,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: String::new(),
                legacy_reason: String::new(),
            replaced_kit_paths: Vec::new(),
            });
        }

        let Some(raw) = body.get("body/admin.ndjson") else {
            return Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "rejected".into(),
                legacy_reason: "admin_log_snapshot body missing `body/admin.ndjson`".into(),
            replaced_kit_paths: Vec::new(),
            });
        };

        let mut accepted: Vec<Value> = Vec::new();
        let mut deduped = 0usize;
        let mut conflicts: Vec<ChainConflict> = Vec::new();

        let text = std::str::from_utf8(raw).map_err(|e| Error::Malformed {
            kind: "admin.ndjson body",
            reason: e.to_string(),
        })?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(env) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if !envelope_well_formed(&env) {
                continue;
            }
            if !verify_envelope_signature(&env) {
                continue;
            }
            let rh = env
                .get("row_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if rh.is_empty() {
                continue;
            }
            if seen.contains(&rh) {
                deduped += 1;
                continue;
            }

            let event_type = env.get("event_type").and_then(Value::as_str);
            if event_type == Some("tn.recipient.added") {
                let g = env.get("group").and_then(Value::as_str);
                let li = env.get("leaf_index").and_then(Value::as_u64);
                if let (Some(g), Some(li)) = (g, li) {
                    let key = (g.to_string(), li);
                    if let Some(rev_rh) = revoked_leaves.get(&key).cloned() {
                        conflicts.push(ChainConflict::LeafReuseAttempt {
                            group: g.to_string(),
                            leaf_index: li,
                            attempted_row_hash: rh.clone(),
                            originally_revoked_at_row_hash: rev_rh,
                        });
                    }
                }
            }
            if event_type == Some("tn.recipient.revoked") {
                let g = env.get("group").and_then(Value::as_str);
                let li = env.get("leaf_index").and_then(Value::as_u64);
                if let (Some(g), Some(li)) = (g, li) {
                    revoked_leaves.insert((g.to_string(), li), Some(rh.clone()));
                }
            }
            accepted.push(env);
            seen.insert(rh);
        }

        if !accepted.is_empty() {
            append_admin_envelopes(&admin_log, &accepted)?;
        }

        // Derive state from manifest; if absorb caller wants a fresh local
        // replay they call admin_state() themselves.
        let derived_state: Option<AdminState> = manifest
            .state
            .clone()
            .and_then(|v| serde_json::from_value::<AdminState>(v).ok());

        Ok(AbsorbReceipt {
            kind: manifest.kind.as_str().into(),
            accepted_count: accepted.len(),
            deduped_count: deduped,
            noop: false,
            derived_state,
            conflicts,
            legacy_status: String::new(),
            legacy_reason: String::new(),
            replaced_kit_paths: Vec::new(),
        })
    }

    fn absorb_kit_bundle(
        &self,
        manifest: &Manifest,
        body: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AbsorbReceipt> {
        let keystore = self.keystore_path();
        std::fs::create_dir_all(&keystore)?;
        let ts = OffsetDateTime::now_utc()
            .format(&time::macros::format_description!(
                "[year][month][day]T[hour][minute][second]Z"
            ))
            .unwrap_or_else(|_| "19700101T000000Z".into());
        let mut accepted = 0usize;
        let mut skipped = 0usize;
        let mut replaced: Vec<PathBuf> = Vec::new();
        for (name, data) in body {
            let Some(rel) = name.strip_prefix("body/") else {
                continue;
            };
            if rel.is_empty() || rel.contains('/') || rel.contains('\\') {
                continue;
            }
            let dest = keystore.join(rel);
            if dest.exists() {
                if let Ok(existing) = std::fs::read(&dest) {
                    if existing == *data {
                        skipped += 1;
                        continue;
                    }
                }
                let backup = keystore.join(format!("{rel}.previous.{ts}"));
                std::fs::rename(&dest, &backup)?;
                // Surface the swap on the receipt (FINDINGS #6 cross-
                // binding parity with Python and TS). Original bytes
                // are preserved at `backup`; the destination path is
                // recorded so callers can map back to the .previous
                // sidecar by appending the same UTC timestamp suffix.
                replaced.push(dest.clone());
            }
            std::fs::write(&dest, data)?;
            accepted += 1;
        }
        Ok(AbsorbReceipt {
            kind: manifest.kind.as_str().into(),
            accepted_count: accepted,
            deduped_count: skipped,
            noop: false,
            derived_state: None,
            conflicts: Vec::new(),
            legacy_status: if accepted > 0 { "enrolment_applied".into() } else { "no_op".into() },
            legacy_reason: String::new(),
            replaced_kit_paths: replaced,
        })
    }

    /// Path to the yaml this runtime was initialized from.
    pub fn yaml_path(&self) -> &Path {
        &self.yaml_path
    }

    /// Return every admin envelope from the runtime's logs as merged JSON
    /// objects (envelope root + decrypted group plaintexts merged on top).
    /// Used by `AdminStateCache` to drive its reducer without re-implementing
    /// envelope decryption.
    pub fn admin_envelopes_merged(&self) -> Result<Vec<Value>> {
        let entries = self.read_raw()?;
        let mut out = Vec::new();
        for entry in entries {
            let et = entry
                .envelope
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !is_admin_event_type(et) {
                continue;
            }
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
            out.push(Value::Object(merged));
        }
        Ok(out)
    }

    fn yaml_dir(&self) -> PathBuf {
        self.yaml_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    }

    fn keystore_path(&self) -> PathBuf {
        self.keystore.clone()
    }

    fn device_private_bytes(&self) -> [u8; 32] {
        self.device.private_bytes()
    }
}

/// Source of bytes to read a `.tnpkg` from for `Runtime::absorb`.
pub enum AbsorbSource<'a> {
    /// On-disk path.
    Path(&'a Path),
    /// In-memory bytes.
    Bytes(&'a [u8]),
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn now_iso_millis() -> String {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]+00:00"
    );
    now.format(&fmt)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000+00:00".into())
}

fn scan_admin_envelopes(
    sources: &[PathBuf],
) -> Result<(Vec<u8>, VectorClock, u64, Option<String>)> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    let mut clock: VectorClock = BTreeMap::new();
    let mut head_row_hash: Option<String> = None;

    for path in sources {
        if !path.exists() {
            continue;
        }
        let raw = std::fs::read_to_string(path)?;
        for line in raw.lines() {
            let stripped = line.trim();
            if stripped.is_empty() {
                continue;
            }
            let Ok(env) = serde_json::from_str::<Value>(stripped) else {
                continue;
            };
            let et = env.get("event_type").and_then(Value::as_str).unwrap_or("");
            if !is_admin_event_type(et) {
                continue;
            }
            let rh = env.get("row_hash").and_then(Value::as_str).unwrap_or("");
            if rh.is_empty() || seen.contains(rh) {
                continue;
            }
            let did = env.get("did").and_then(Value::as_str).unwrap_or("");
            let seq = env.get("sequence").and_then(Value::as_u64);
            let Some(seq) = seq else { continue };
            seen.insert(rh.to_string());
            out.extend_from_slice(stripped.as_bytes());
            out.push(b'\n');
            let slot = clock.entry(did.to_string()).or_default();
            let cur = slot.get(et).copied().unwrap_or(0);
            if seq > cur {
                slot.insert(et.to_string(), seq);
            }
            head_row_hash = Some(rh.to_string());
        }
    }

    let count = u64::try_from(seen.len()).unwrap_or(u64::MAX);
    Ok((out, clock, count, head_row_hash))
}

type KitBundleBody = (BTreeMap<String, Vec<u8>>, Vec<Value>);

fn build_kit_bundle_body(
    keystore: &Path,
    full: bool,
    groups_filter: Option<&[String]>,
) -> Result<KitBundleBody> {
    if !keystore.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("kit_bundle: keystore directory not found: {}", keystore.display()),
        )));
    }
    let group_set: Option<HashSet<String>> = groups_filter.map(|gs| gs.iter().cloned().collect());
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut kits_meta: Vec<Value> = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(keystore)?.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Some(group) = name_str.strip_suffix(".btn.mykit").and_then(|g| {
            // Reject `<g>.btn.mykit.revoked.N` style — the strip above would
            // already fail on those (suffix mismatch).
            if g.is_empty() {
                None
            } else {
                Some(g)
            }
        }) {
            if let Some(filter) = &group_set {
                if !filter.contains(group) {
                    continue;
                }
            }
            let data = std::fs::read(entry.path())?;
            let mut o = Map::new();
            o.insert("name".into(), Value::String(name_str.to_string()));
            o.insert(
                "sha256".into(),
                Value::String(format!("sha256:{}", hex::encode(sha2_256(&data)))),
            );
            o.insert("bytes".into(), Value::Number(data.len().into()));
            kits_meta.push(Value::Object(o));
            body.insert(format!("body/{name_str}"), data);
        } else if full
            && (name_str == "local.private"
                || name_str == "local.public"
                || name_str == "index_master.key")
        {
            body.insert(format!("body/{name_str}"), std::fs::read(entry.path())?);
        } else if full {
            if let Some(group) = name_str.strip_suffix(".btn.state") {
                if group_set
                    .as_ref()
                    .map_or(true, |f| f.contains(group))
                {
                    body.insert(format!("body/{name_str}"), std::fs::read(entry.path())?);
                }
            }
        }
    }

    if kits_meta.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "kit_bundle: no *.btn.mykit files in {}",
            keystore.display()
        )));
    }

    if full {
        body.insert("body/WARNING_CONTAINS_PRIVATE_KEYS".into(), Vec::new());
    }

    Ok((body, kits_meta))
}

fn append_admin_envelopes(admin_log: &Path, envelopes: &[Value]) -> Result<()> {
    if let Some(parent) = admin_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(admin_log)?;
    for env in envelopes {
        let line = serde_json::to_string(env)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    Ok(())
}

fn envelope_well_formed(env: &Value) -> bool {
    for k in [
        "did",
        "timestamp",
        "event_id",
        "event_type",
        "row_hash",
        "signature",
    ] {
        if env.get(k).and_then(Value::as_str).is_none() {
            return false;
        }
    }
    true
}

fn verify_envelope_signature(env: &Value) -> bool {
    let did = env.get("did").and_then(Value::as_str).unwrap_or("");
    let row_hash = env.get("row_hash").and_then(Value::as_str).unwrap_or("");
    let sig_b64 = env.get("signature").and_then(Value::as_str).unwrap_or("");
    if sig_b64.is_empty() {
        // Unsigned mode: envelopes ride the chain on row_hash alone. Treat as
        // valid for absorb purposes — the chain hash is the integrity check.
        return true;
    }
    let Ok(sig) = crate::signing::signature_from_b64(sig_b64) else {
        return false;
    };
    DeviceKey::verify_did(did, row_hash.as_bytes(), &sig).unwrap_or(false)
}

fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
