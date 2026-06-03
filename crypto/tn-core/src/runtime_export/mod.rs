//! `.tnpkg` producer / consumer: [`Runtime::export`] and [`Runtime::absorb`].
//!
//! The universal package path (Section 3.2 of the 2026-04-24 admin log
//! architecture plan), behind the `tn export` / `tn absorb` CLI verbs.
//! [`Runtime::export`] packs local ceremony state into a signed `.tnpkg`
//! described by [`ExportOptions`]; [`Runtime::absorb`] reads one back, verifies
//! its manifest, applies it, and returns an [`AbsorbReceipt`]. The wire format
//! itself lives in [`crate::tnpkg`]; this module is the runtime-side glue that
//! gathers what goes in the body and folds what comes out. Mirrors
//! `tn/export.py` and `tn/absorb.py`.

#![cfg(feature = "fs")]

mod admin_clock;
mod receipts;
mod seed_builders;
mod util;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::admin_cache::{is_admin_event_type, resolve_admin_log_path, ChainConflict};
use crate::runtime::{AdminState, Runtime};
use crate::tnpkg::{
    clock_dominates, read_tnpkg, sign_manifest, write_tnpkg, Manifest, ManifestKind, TnpkgSource,
    VectorClock,
};
use crate::{Error, Result};

use admin_clock::{
    append_admin_envelopes, build_local_admin_clock, scan_admin_envelopes, try_accept_admin_envelope,
};
use receipts::{noop_receipt, rejected_receipt};
use seed_builders::{build_identity_seed_body, build_kit_bundle_body, build_project_seed_body};
use util::now_iso_millis;

/// What to pack and how, for [`Runtime::export`].
///
/// [`kind`](Self::kind) is the one required field — it selects the package kind
/// and thus which of the other fields matter. `Offer` / `Enrolment` need
/// [`package_body`](Self::package_body); `KitBundle` / `FullKeystore` /
/// `ProjectSeed` honor [`groups`](Self::groups); `FullKeystore` and
/// `ProjectSeed` additionally require
/// [`confirm_includes_secrets`](Self::confirm_includes_secrets) because they
/// write raw private keys. Defaults are all-empty / `None`, so build with
/// `ExportOptions { kind: Some(...), ..Default::default() }`. Mirrors Python's
/// keyword args.
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

/// Outcome of a [`Runtime::absorb`] call.
///
/// Absorb is total — it returns a receipt rather than erroring on a bad or
/// rejected package — so the *receipt* is where you learn what happened. For
/// admin snapshots, [`accepted_count`](Self::accepted_count) /
/// [`deduped_count`](Self::deduped_count) / [`noop`](Self::noop) describe how
/// many envelopes were new, and [`conflicts`](Self::conflicts) surfaces any
/// equivocation detected. For other kinds,
/// [`legacy_status`](Self::legacy_status) / [`legacy_reason`](Self::legacy_reason)
/// carry the disposition (`"rejected"`, `"stashed"`, …). Always inspect
/// [`replaced_kit_paths`](Self::replaced_kit_paths) after a kit absorb to see
/// whether existing keystore files were swapped aside.
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
    /// Pack a signed `.tnpkg` from local ceremony state and write it to
    /// `out_path`.
    ///
    /// Gathers the body for `opts.kind` (admin envelopes, reader kits, an
    /// identity/project seed, or a caller-supplied package payload), assembles
    /// and Ed25519-signs the manifest with this runtime's device key, and writes
    /// the archive via [`crate::tnpkg::write_tnpkg`]. The package is
    /// self-describing and verifiable by any holder of the producer's
    /// `did:key`. Returns the path written (the same `out_path`). This is the
    /// engine behind `tn export`.
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidConfig`] when `opts.kind` is unset, when a
    /// `FullKeystore` / `ProjectSeed` export omits
    /// `confirm_includes_secrets = true` (the foot-gun gate on exporting raw
    /// private keys), or when a kind's required inputs are missing (e.g. an
    /// `Offer` without `package_body`, or a kit bundle over an empty keystore).
    /// Returns [`crate::Error::NotImplemented`] for kinds Rust does not yet
    /// produce (`RecipientInvite`, `ContactUpdate`). Filesystem and zip failures
    /// surface as their underlying [`crate::Error`] variants.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use tn_core::{Runtime, ManifestKind, ExportOptions};
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::init(Path::new("tn.yaml"))?;
    /// let written = rt.export(
    ///     Path::new("snapshot.tnpkg"),
    ///     ExportOptions {
    ///         kind: Some(ManifestKind::AdminLogSnapshot),
    ///         ..Default::default()
    ///     },
    /// )?;
    /// assert_eq!(written, Path::new("snapshot.tnpkg"));
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn export(&self, out_path: &Path, opts: ExportOptions) -> Result<PathBuf> {
        let kind = opts
            .kind
            .ok_or_else(|| Error::InvalidConfig("export: ExportOptions.kind is required".into()))?;

        if matches!(kind, ManifestKind::FullKeystore | ManifestKind::ProjectSeed)
            && !opts.confirm_includes_secrets
        {
            return Err(Error::InvalidConfig(
                "export(kind=FullKeystore|ProjectSeed) writes the publisher's raw private keys \
                 into the zip. Pass \
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
                    Value::String(if full {
                        "full-keystore".into()
                    } else {
                        "readers-only".into()
                    }),
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
            ManifestKind::IdentitySeed => {
                body = build_identity_seed_body(&self.device);
                let mut identity = Map::new();
                identity.insert("schema".into(), Value::String("tn-identity-seed-v1".into()));
                identity.insert("nickname".into(), Value::Null);
                identity.insert("minted_at".into(), Value::String(now_iso_millis()));
                let mut state = Map::new();
                state.insert("identity".into(), Value::Object(identity));
                state_value = Some(Value::Object(state));
                scope_default = "identity";
            }
            ManifestKind::ProjectSeed => {
                let (b, keys_meta) = build_project_seed_body(
                    &self.yaml_path,
                    &self.keystore_path(),
                    &self.device,
                    opts.groups.as_deref(),
                )?;
                body = b;
                let mut project = Map::new();
                project.insert(
                    "ceremony_id".into(),
                    Value::String(self.cfg.ceremony.id.clone()),
                );
                project.insert("project_name".into(), Value::String(self.project_name()));
                project.insert(
                    "keys".into(),
                    Value::Array(keys_meta.into_iter().map(Value::String).collect()),
                );
                let mut state = Map::new();
                state.insert("project".into(), Value::Object(project));
                state.insert("kind".into(), Value::String("project-seed".into()));
                state_value = Some(Value::Object(state));
                scope_default = "project";
            }
        }

        // Assemble + sign manifest.
        let mut manifest = Manifest {
            kind,
            version: crate::tnpkg::MANIFEST_VERSION,
            publisher_identity: self.did().to_string(),
            recipient_identity: if matches!(
                kind,
                ManifestKind::IdentitySeed | ManifestKind::ProjectSeed
            ) {
                Some(self.did().to_string())
            } else {
                opts.to_did.clone()
            },
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

    /// Apply a `.tnpkg` to local state and return a receipt.
    ///
    /// Reads the package, verifies its manifest signature against the declared
    /// producer, then dispatches on [`crate::ManifestKind`]: admin snapshots are
    /// deduped by `row_hash` and appended to the admin log (advancing LKV
    /// state); kit bundles are written into the keystore (existing files moved
    /// aside to `.previous.<UTC>` sidecars); other kinds are stashed for the
    /// caller. Idempotent — re-absorbing the same package is a no-op (see
    /// [`AbsorbReceipt::noop`]) — and total: a malformed, unverifiable, or
    /// unsupported package yields a rejected/stashed [`AbsorbReceipt`] rather
    /// than an `Err`. The engine behind `tn absorb`.
    ///
    /// # Errors
    /// Returns [`crate::Error`] only on a genuine local failure while applying
    /// an *accepted* package (e.g. an I/O error appending to the admin log or
    /// writing a kit). Bad input — not a zip, signature mismatch, missing body —
    /// is reported on the returned receipt, not as an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use tn_core::{Runtime, AbsorbSource};
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::init(Path::new("tn.yaml"))?;
    /// let receipt = rt.absorb(AbsorbSource::Path(Path::new("snapshot.tnpkg")))?;
    /// if receipt.legacy_status == "rejected" {
    ///     eprintln!("package rejected: {}", receipt.legacy_reason);
    /// } else {
    ///     println!("accepted {} new envelope(s)", receipt.accepted_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
                    "manifest signature does not verify against publisher_identity {:?}: {e}",
                    manifest.publisher_identity
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
            ManifestKind::IdentitySeed | ManifestKind::ProjectSeed => Ok(AbsorbReceipt {
                kind: manifest.kind.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "stashed".into(),
                legacy_reason: format!(
                    "absorb: kind {:?} round-trips through read_manifest but \
                     Rust runtime has no bootstrap handler yet.",
                    manifest.kind.as_str()
                ),
                replaced_kit_paths: Vec::new(),
            }),
        }
    }

    /// Absorb an ``admin_log_snapshot`` .tnpkg into the receiver's
    /// admin log.
    ///
    /// Thin orchestrator: build receiver's local state, short-circuit
    /// when the manifest is already dominated, parse the body, accept
    /// each envelope through the per-line helper, append the
    /// accepted set. Mirrors the Python ``_absorb_admin_log_snapshot``
    /// decomposition (PR #40).
    fn absorb_admin_log_snapshot(
        &self,
        manifest: &Manifest,
        body: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AbsorbReceipt> {
        let yaml_dir = self.yaml_dir();
        let admin_log = resolve_admin_log_path(&yaml_dir, &self.cfg);

        let (local_clock, mut seen, mut revoked_leaves) = build_local_admin_clock(&admin_log)?;

        if clock_dominates(&local_clock, &manifest.clock) {
            return Ok(noop_receipt(manifest));
        }

        let Some(raw) = body.get("body/admin.ndjson") else {
            return Ok(rejected_receipt(
                manifest,
                "admin_log_snapshot body missing `body/admin.ndjson`",
            ));
        };
        let text = std::str::from_utf8(raw).map_err(|e| Error::Malformed {
            kind: "admin.ndjson body",
            reason: e.to_string(),
        })?;

        let mut accepted: Vec<Value> = Vec::new();
        let mut deduped: usize = 0;
        let mut conflicts: Vec<ChainConflict> = Vec::new();
        for line in text.lines() {
            try_accept_admin_envelope(
                line,
                &mut seen,
                &mut revoked_leaves,
                &mut accepted,
                &mut conflicts,
                &mut deduped,
            );
        }

        if !accepted.is_empty() {
            append_admin_envelopes(&admin_log, &accepted)?;
        }

        // Derive state from manifest; if absorb caller wants a fresh
        // local replay they call admin_state() themselves.
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
            legacy_status: if accepted > 0 {
                "enrolment_applied".into()
            } else {
                "no_op".into()
            },
            legacy_reason: String::new(),
            replaced_kit_paths: replaced,
        })
    }

    /// Borrow the path to the `tn.yaml` this runtime was initialized from.
    ///
    /// The ceremony's config file; its parent directory is the anchor for the
    /// runtime's `.tn/` log and keystore tree.
    pub fn yaml_path(&self) -> &Path {
        &self.yaml_path
    }

    /// Collect every admin envelope from the runtime's logs as merged JSON
    /// objects.
    ///
    /// Each entry is the envelope root with its decrypted per-group plaintexts
    /// merged on top, so admin fields read at the top level regardless of which
    /// group carried them. This is the decryption-aware feed
    /// [`crate::AdminStateCache`] folds to build admin state — it lets the cache
    /// avoid re-implementing envelope decryption. Non-admin event types are
    /// filtered out.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if reading or decrypting the underlying log
    /// entries fails.
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

    fn project_name(&self) -> String {
        self.yaml_dir()
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("default")
            .to_string()
    }
}

/// Where [`Runtime::absorb`] reads a `.tnpkg` from.
///
/// The absorb-side mirror of [`crate::tnpkg::TnpkgSource`].
pub enum AbsorbSource<'a> {
    /// On-disk path to the `.tnpkg` archive.
    Path(&'a Path),
    /// In-memory `.tnpkg` bytes (the byte-array path for non-fs hosts).
    Bytes(&'a [u8]),
}
