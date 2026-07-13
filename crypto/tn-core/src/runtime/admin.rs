//! Admin / governance verbs: recipient management, state replay, kit
//! bundling, and vault linkage.
//!
//! Holds the cipher-agnostic recipient verbs ([`Runtime::admin_add_recipient`]
//! / [`Runtime::admin_revoke_recipient`] / [`Runtime::admin_revoked_count`]),
//! the log-replay views ([`Runtime::recipients`] / [`Runtime::admin_state`]),
//! the ergonomic bundling paths ([`Runtime::bundle_for_recipient`] /
//! [`Runtime::admin_add_agent_runtime`]), and the vault-link attestations
//! ([`Runtime::vault_link`] / [`Runtime::vault_unlink`]). The export /
//! absorb verbs they lean on live in the sibling `runtime_export` module.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand_core::RngCore;
use serde_json::{Map, Value};
use serde_yml::Value as YamlValue;

use crate::admin_reduce::{reduce as admin_reduce_envelope, StateDelta};
use crate::cipher::btn::BtnPublisherCipher;
use crate::cipher::GroupCipher;
use crate::{Error, Result};

use super::cipher_build::{
    build_cipher_with_admin_with_storage, collect_btn_kit_bytes_with_storage, rebuild_btn_cipher,
};
use super::read::{apply_schema_defaults, merge_envelope};
use super::util::{current_timestamp_rfc3339, sha2_256};
use super::{
    AdminCeremony, AdminCoupon, AdminEnrolment, AdminGroupRecord, AdminRecipientRecord,
    AdminRotation, AdminState, AdminVaultLink, RecipientEntry, Runtime, RuntimeInitOptions,
};

/// Result from [`Runtime::admin_ensure_group`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureGroupResult {
    /// Group that was ensured or updated.
    pub group: String,
    /// Fields routed into the group by this call.
    pub fields: Vec<String>,
    /// True when the group did not exist and was created by this call.
    pub created: bool,
    /// True when `tn.yaml` was changed.
    pub changed: bool,
}

/// Result from [`Runtime::admin_rotate_group`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateGroupResult {
    /// Group whose publisher keys were rotated.
    pub group: String,
    /// New key generation/epoch.
    pub generation: u32,
    /// `sha256:` digest of the self-kit retired by this rotation.
    pub previous_kit_sha256: String,
    /// `sha256:` digest of the newly minted self-kit.
    pub new_kit_sha256: String,
    /// RFC3339 timestamp emitted on `tn.rotation.completed`.
    pub rotated_at: String,
}

/// Result from [`Runtime::admin_grant_reader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantReaderResult {
    /// The hibe group the reader was granted access to.
    pub group: String,
    /// Reader DID recorded in the grant registry, when supplied.
    pub reader_did: Option<String>,
    /// Identity path the minted reader key is keyed to (the group's
    /// sealing path unless a custom ancestor path was requested).
    pub id_path: String,
    /// Path of the written `.tnpkg` kit bundle.
    pub path: PathBuf,
}

/// Result from [`Runtime::admin_rotate_id_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateIdPathResult {
    /// The hibe group whose identity path was rotated.
    pub group: String,
    /// The outgoing sealing path (now first in the idpath history).
    pub previous_path: String,
    /// The path future seals target.
    pub new_path: String,
}

impl Runtime {
    /// Rebuild a group's cipher from the current on-disk keystore material
    /// and swap it into the live group table.
    ///
    /// Needed when an admin mutation happened outside this runtime's own
    /// native admin verbs, notably Python-side hibe admin verbs that rewrite
    /// `<group>.hibe.*` material on disk. The runtime caches each cipher at
    /// init, so without a reload the next emit can still seal to stale
    /// material.
    pub fn reload_group_cipher(&self, group: &str) -> Result<()> {
        let Some(spec) = self.cfg.groups.get(group) else {
            return Ok(());
        };
        let (cipher, _btn_admin, _mykit) = build_cipher_with_admin_with_storage(
            spec,
            &self.keystore,
            group,
            &self.storage,
            &self.device,
        )?;
        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = cipher;
        }
        Ok(())
    }

    /// Ensure a btn group exists and route fields into it.
    ///
    /// If the group is not already declared, this mints publisher state and a
    /// self-reader kit in the active keystore, writes the group declaration and
    /// field routes into `tn.yaml`, reloads the runtime, and emits
    /// `tn.group.added`. Existing groups only update routing and reload when
    /// the yaml changes.
    ///
    /// This method is native-filesystem only: it edits the ceremony yaml and
    /// keystore directly, so wasm/browser callers should use their host SDK's
    /// config management path instead.
    pub fn admin_ensure_group(
        &mut self,
        group: &str,
        fields: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<EnsureGroupResult> {
        let fields = normalize_fields(fields)?;
        if fields.is_empty() {
            return Ok(EnsureGroupResult {
                group: group.to_string(),
                fields,
                created: false,
                changed: false,
            });
        }

        let yaml_path = self.yaml_path().to_path_buf();
        let raw = std::fs::read_to_string(&yaml_path)?;
        let mut doc: YamlValue = serde_yml::from_str(&raw)?;

        let created = !group_declared(&doc, group)?;
        if created {
            let keystore = resolve_keystore_path(&doc, &yaml_path)?;
            mint_btn_group(&keystore, group)?;
        }

        let changed = ensure_yaml_group(&mut doc, group, self.did(), &fields)?;
        if changed {
            let rendered = serde_yml::to_string(&doc)?;
            std::fs::write(&yaml_path, rendered)?;
            self.reload_with_options(
                self.storage.clone(),
                RuntimeInitOptions {
                    skip_ceremony_init_emit: true,
                    skip_policy_published_emit: true,
                },
            )?;
        }
        if created {
            let mut event = Map::new();
            event.insert("group".into(), Value::String(group.to_string()));
            event.insert("cipher".into(), Value::String("btn".to_string()));
            event.insert(
                "publisher_identity".into(),
                Value::String(self.did().to_string()),
            );
            event.insert(
                "added_at".into(),
                Value::String(current_timestamp_rfc3339()),
            );
            self.info("tn.group.added", event)?;
        }

        Ok(EnsureGroupResult {
            group: group.to_string(),
            fields,
            created,
            changed,
        })
    }

    /// Mint a fresh kit for `recipient_did` across one or more groups
    /// and bundle them into a single `.tnpkg` at `out_path`. Backs
    /// `tn.bundle_for_recipient()`.
    ///
    /// The ergonomic one-call path for handing a recipient their reader
    /// kits: it mints (via [`Runtime::admin_add_recipient`], so each mint
    /// also writes a `tn.recipient.added` attestation), names the kit
    /// files canonically, and exports the bundle. Mirrors Python's
    /// `tn.bundle_for_recipient` and TS's `client.bundleForRecipient` —
    /// closes the cross-binding parity gap surfaced by the cash-register
    /// survey (Rust callers had no equivalent ergonomic verb and faced the
    /// canonical-filename + temp-dir + export dance by hand).
    ///
    /// `groups = None` defaults to every NON-internal group declared in
    /// the active ceremony (excludes `tn.agents` — that group is for
    /// LLM-runtime bundles via [`Runtime::admin_add_agent_runtime`]).
    /// Passing an explicit slice scopes the bundle.
    ///
    /// Returns the absolute path to the written `.tnpkg`.
    ///
    /// # Errors
    ///
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if no real groups
    ///   are available, or a requested group is not declared in the yaml.
    /// - Filesystem errors from minting kits or writing the bundle, plus
    ///   any error propagated from [`Runtime::admin_add_recipient`].
    ///
    /// # Panics
    ///
    /// Panics if an internal admin lock is poisoned (see
    /// [`Runtime::admin_add_recipient`]).
    pub fn bundle_for_recipient(
        &self,
        recipient_did: &str,
        out_path: &Path,
        groups: Option<&[&str]>,
    ) -> Result<PathBuf> {
        self.bundle_for_recipient_with_options(recipient_did, out_path, groups, false)
    }

    /// Mint and bundle reader kits, optionally sealing the bundle body for the
    /// recipient DID.
    pub fn bundle_for_recipient_with_options(
        &self,
        recipient_did: &str,
        out_path: &Path,
        groups: Option<&[&str]>,
        seal_for_recipient: bool,
    ) -> Result<PathBuf> {
        if seal_for_recipient {
            crate::recipient_seal::normalize_recipient_dids(&[recipient_did.to_string()])?;
        }

        let mut requested: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        match groups {
            Some(list) => {
                for g in list {
                    let s = (*g).to_string();
                    if seen.insert(s.clone()) {
                        requested.push(s);
                    }
                }
            }
            None => {
                // Default: every group except tn.agents (the internal
                // LLM-policy channel doesn't make sense to ship to a
                // human reader).
                for k in self.cfg.groups.keys() {
                    if k == "tn.agents" {
                        continue;
                    }
                    requested.push(k.clone());
                }
            }
        }

        if requested.is_empty() {
            return Err(Error::InvalidConfig(
                "bundle_for_recipient: no groups to bundle. The ceremony \
                 has only the internal tn.agents group; declare a \
                 regular group first or pass an explicit groups slice."
                    .to_string(),
            ));
        }

        for g in &requested {
            if !self.cfg.groups.contains_key(g) {
                return Err(Error::InvalidConfig(format!(
                    "bundle_for_recipient: unknown group {g:?}; this \
                     ceremony declares {:?}",
                    self.cfg.groups.keys().collect::<Vec<_>>()
                )));
            }
        }

        let td = tempfile::Builder::new()
            .prefix("tn-bundle-")
            .tempdir()
            .map_err(Error::Io)?;
        for gname in &requested {
            let spec = self
                .cfg
                .groups
                .get(gname)
                .expect("requested groups were validated above");
            match spec.cipher.as_str() {
                "btn" => {
                    let kit_path = td.path().join(format!("{gname}.btn.mykit"));
                    self.admin_add_recipient(gname, &kit_path, Some(recipient_did))?;
                }
                "hibe" => {
                    self.stage_hibe_reader_bundle_material(
                        gname,
                        Some(recipient_did),
                        td.path(),
                        None,
                    )?;
                }
                "jwe" | "bearer" => {
                    return Err(Error::NotImplemented(
                        "bundle_for_recipient: cipher=jwe kit minting is not implemented in \
                         tn-core; use the Python runtime or pure JS JWE pipeline",
                    ));
                }
                other => {
                    return Err(Error::InvalidConfig(format!(
                        "bundle_for_recipient: group {gname:?} uses unknown cipher {other:?}"
                    )));
                }
            }
        }

        let opts = crate::runtime_export::ExportOptions {
            kind: Some(crate::tnpkg::ManifestKind::KitBundle),
            to_did: Some(recipient_did.to_string()),
            scope: None,
            confirm_includes_secrets: false,
            groups: Some(requested.clone()),
            keystore: Some(td.path().to_path_buf()),
            encrypt_body_with: None,
            seal_for_recipients: if seal_for_recipient {
                vec![recipient_did.to_string()]
            } else {
                Vec::new()
            },
            package_body: None,
        };
        let out = self.export(out_path, opts)?;
        drop(td);
        Ok(out)
    }

    /// Mint and stage one hibe reader's kit files into `out_dir`, and record
    /// the grant when the reader has a DID.
    ///
    /// `id_path: None` keys the fresh reader key to the group's CURRENT
    /// sealing path; `Some(path)` keys it to a caller-chosen (typically
    /// ancestor) path, mirroring Python `tn.admin.grant_reader(id_path=...)`.
    /// Either way the staged `<group>.hibe.idpath` file carries the group's
    /// sealing path — the reader derives an ancestor key down locally.
    /// Returns the path the minted key is keyed to.
    #[cfg(feature = "hibe")]
    fn stage_hibe_reader_bundle_material(
        &self,
        group: &str,
        recipient_did: Option<&str>,
        out_dir: &Path,
        id_path: Option<&str>,
    ) -> Result<String> {
        let read_required = |suffix: &str| -> Result<Vec<u8>> {
            let path = self.keystore.join(format!("{group}.{suffix}"));
            self.storage.read_bytes(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Error::InvalidConfig(format!(
                        "bundle_for_recipient: cipher=hibe group {group:?} requires {} \
                         authority material in {}",
                        path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("<unknown>"),
                        self.keystore.display()
                    ))
                } else {
                    Error::Io(e)
                }
            })
        };

        let mpk = read_required("hibe.mpk")?;
        let msk_bytes = read_required("hibe.msk")?;
        let idpath_bytes = read_required("hibe.idpath")?;
        let group_path = String::from_utf8(idpath_bytes).map_err(|_| {
            Error::InvalidConfig(format!(
                "bundle_for_recipient: cipher=hibe group {group:?} idpath is not utf-8"
            ))
        })?;
        // Either path passes the boundary validation Python's
        // mint_reader_key applies (no root grants without the flag —
        // grant_reader never sets it, so none here either).
        let target_path = crate::cipher::hibe::normalize_hibe_path(
            id_path.unwrap_or(&group_path),
            "id_path",
            false,
        )?;

        let pp = tn_hibe::PublicParams::from_bytes(&mpk)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let msk = tn_hibe::MasterKey::from_bytes(&msk_bytes)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let id = tn_hibe::Identity::try_from_str_path(&target_path)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let sk = tn_hibe::keygen(&pp, &msk, &id, rand_core::OsRng)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?
            .to_bytes();

        self.storage
            .write_bytes(&out_dir.join(format!("{group}.hibe.mpk")), &mpk)
            .map_err(Error::Io)?;
        self.storage
            .write_bytes(
                &out_dir.join(format!("{group}.hibe.idpath")),
                group_path.as_bytes(),
            )
            .map_err(Error::Io)?;
        self.storage
            .write_bytes(&out_dir.join(format!("{group}.hibe.sk")), &sk)
            .map_err(Error::Io)?;
        if let Some(did) = recipient_did {
            self.record_hibe_grant(group, did, &target_path)?;
        }
        Ok(target_path)
    }

    #[cfg(not(feature = "hibe"))]
    fn stage_hibe_reader_bundle_material(
        &self,
        _group: &str,
        _recipient_did: Option<&str>,
        _out_dir: &Path,
        _id_path: Option<&str>,
    ) -> Result<String> {
        Err(Error::NotImplemented(
            "bundle_for_recipient: cipher=hibe kit minting requires tn-core's hibe feature",
        ))
    }

    /// Append/replace one reader's row in `<group>.hibe.grants`.
    ///
    /// The file is the authority-side grant registry Python's
    /// `tn.admin.revoke_reader` re-issues kits from, so the bytes follow
    /// Python's normative writer (`_hibe_grants_update`:
    /// `json.dumps(grants, indent=1)`): one-space indent, `reader_did`
    /// before `id_path`, no trailing newline.
    #[cfg(feature = "hibe")]
    fn record_hibe_grant(&self, group: &str, recipient_did: &str, id_path: &str) -> Result<()> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct HibeGrantRecord {
            reader_did: String,
            id_path: String,
        }

        let path = self.keystore.join(format!("{group}.hibe.grants"));
        let mut grants: Vec<HibeGrantRecord> = if self.storage.exists(&path) {
            serde_json::from_slice(&self.storage.read_bytes(&path).map_err(Error::Io)?)?
        } else {
            Vec::new()
        };
        grants.retain(|g| g.reader_did != recipient_did);
        grants.push(HibeGrantRecord {
            reader_did: recipient_did.to_string(),
            id_path: id_path.to_string(),
        });
        let mut bytes = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut ser = serde_json::Serializer::with_formatter(&mut bytes, formatter);
        serde::Serialize::serialize(&grants, &mut ser)?;
        self.storage.write_bytes(&path, &bytes).map_err(Error::Io)
    }

    /// HIBE's add_recipient: mint a delegated identity key for `reader_did`
    /// and export it as an absorbable `.tnpkg` kit at `out_path`.
    ///
    /// Verb-for-verb port of Python `tn.admin.grant_reader`. The kit carries
    /// the authority mpk, the group's sealing path, and a fresh
    /// (independently randomized) identity key — the authority master secret
    /// NEVER rides a kit. `id_path: None` keys the reader to the group's own
    /// sealing path; pass an ancestor path to hand out a key the reader can
    /// delegate further down. When `reader_did` resolves to a real
    /// `did:key:z...` Ed25519 DID the bundle body is sealed to it (a
    /// plaintext kit is a bearer token); a placeholder DID stays plaintext by
    /// necessity, exactly like Python's `recipient_key_is_resolvable` gate.
    /// A supplied DID is recorded in `<group>.hibe.grants`.
    ///
    /// Granting is native to the cipher — no re-keying, no envelope rewrite,
    /// and no forward revocation of an admitted reader (rotate the identity
    /// path for new seals, or use btn for groups that need real forward
    /// revocation).
    ///
    /// # Errors
    ///
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if the group is
    ///   unknown, is not a hibe group (grant_reader is hibe-only — use
    ///   add_recipient for btn/jwe groups), or `id_path` fails the boundary
    ///   validation.
    /// - [`Cipher`](crate::Error::Cipher) when the scheme rejects the key
    ///   material or path, plus I/O errors from staging or writing the kit.
    #[cfg(feature = "hibe")]
    pub fn admin_grant_reader(
        &self,
        group: &str,
        reader_did: Option<&str>,
        out_path: &Path,
        id_path: Option<&str>,
    ) -> Result<GrantReaderResult> {
        let spec = self.cfg.groups.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!("tn.admin.grant_reader: unknown group: {group:?}"))
        })?;
        if spec.cipher != "hibe" {
            return Err(Error::InvalidConfig(format!(
                "tn.admin.grant_reader: group {group:?} uses cipher {:?}; \
                 grant_reader is hibe-only. Use add_recipient for btn/jwe groups.",
                spec.cipher
            )));
        }

        let td = tempfile::Builder::new()
            .prefix("tn-grant-reader-")
            .tempdir()
            .map_err(Error::Io)?;
        let target_path =
            self.stage_hibe_reader_bundle_material(group, reader_did, td.path(), id_path)?;

        // Seal the bundle body to the reader's device key when the DID
        // resolves (Python: recipient_key_is_resolvable). A stub DID with no
        // embedded key can't be sealed to, so it stays plaintext.
        let seal_for_recipients = match reader_did {
            Some(did)
                if crate::recipient_seal::normalize_recipient_dids(&[did.to_string()]).is_ok() =>
            {
                vec![did.to_string()]
            }
            _ => Vec::new(),
        };

        let opts = crate::runtime_export::ExportOptions {
            kind: Some(crate::tnpkg::ManifestKind::KitBundle),
            to_did: reader_did.map(str::to_string),
            scope: None,
            confirm_includes_secrets: false,
            groups: Some(vec![group.to_string()]),
            keystore: Some(td.path().to_path_buf()),
            encrypt_body_with: None,
            seal_for_recipients,
            package_body: None,
        };
        let written = self.export(out_path, opts)?;
        drop(td);
        Ok(GrantReaderResult {
            group: group.to_string(),
            reader_did: reader_did.map(str::to_string),
            id_path: target_path,
            path: written,
        })
    }

    /// HIBE's add_recipient — unavailable in this build: the `hibe` feature
    /// is off, so the verb yields a clear `NotImplemented` instead of a
    /// build error.
    ///
    /// # Errors
    ///
    /// Always returns [`NotImplemented`](crate::Error::NotImplemented).
    #[cfg(not(feature = "hibe"))]
    pub fn admin_grant_reader(
        &self,
        _group: &str,
        _reader_did: Option<&str>,
        _out_path: &Path,
        _id_path: Option<&str>,
    ) -> Result<GrantReaderResult> {
        Err(Error::NotImplemented(
            "admin_grant_reader: cipher=hibe kit minting requires tn-core's hibe feature",
        ))
    }

    /// Rotate a hibe group's identity path so FUTURE seals use `new_path`
    /// (the policy-path rotation).
    ///
    /// File-for-file port of Python `HibeGroupCipher.rotate_id_path` behind
    /// the `tn.admin.rotate_reader_path` driver, producing a keystore a
    /// Python authority opens unchanged: the outgoing path is prepended to
    /// `<group>.hibe.idpath.history` (one path per line, LF, root sentinel
    /// encoding), a held reader key is archived as
    /// `<group>.hibe.sk.previous.<ns>`, a fresh msk-minted key and the new
    /// path replace `<group>.hibe.sk` / `<group>.hibe.idpath`, and the root
    /// marker file is maintained. Write order matches the Python contract
    /// (history and archive land before the active swap).
    ///
    /// This is admission rotation, not revocation: pre-rotation seals stay
    /// open forever for whoever held a key on the old path, and a grantee
    /// holding an ANCESTOR of the new path keeps access to new seals too.
    /// Pick a sibling path to cut off exact-path grantees going forward.
    ///
    /// After rewriting the keystore the live group cipher is rebuilt in
    /// place ([`Runtime::reload_group_cipher`]) so the very next emit/seal
    /// from THIS runtime lands on the new path — a stale cached cipher would
    /// keep sealing to the audience the caller just rotated away from.
    ///
    /// # Errors
    ///
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if the group is
    ///   unknown or not hibe, `new_path` fails validation (the root path
    ///   requires `allow_root_path`), or `new_path` equals the current path.
    /// - [`NotAPublisher`](crate::Error::NotAPublisher) when this keystore
    ///   holds no `<group>.hibe.msk` — only the authority rotates.
    /// - [`Cipher`](crate::Error::Cipher) when the scheme rejects the path
    ///   (the root path is currently rejected at this layer, matching the
    ///   Python native boundary) — nothing is written in that case.
    #[cfg(feature = "hibe")]
    pub fn admin_rotate_id_path(
        &self,
        group: &str,
        new_path: &str,
        allow_root_path: bool,
    ) -> Result<RotateIdPathResult> {
        use crate::cipher::hibe::{
            decode_hibe_history_line, encode_hibe_history_path, normalize_hibe_path,
        };

        let spec = self.cfg.groups.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!("tn.admin.rotate_id_path: unknown group: {group:?}"))
        })?;
        if spec.cipher != "hibe" {
            return Err(Error::InvalidConfig(format!(
                "tn.admin.rotate_id_path: group {group:?} uses cipher {:?}; \
                 this rotation is hibe-only (btn groups rotate via tn rotate).",
                spec.cipher
            )));
        }

        let read_opt = |suffix: &str| -> Result<Option<Vec<u8>>> {
            let path = self.keystore.join(format!("{group}.{suffix}"));
            if self.storage.exists(&path) {
                Ok(Some(self.storage.read_bytes(&path).map_err(Error::Io)?))
            } else {
                Ok(None)
            }
        };

        let mpk = read_opt("hibe.mpk")?.ok_or_else(|| {
            Error::InvalidConfig(format!(
                "hibe group {group}: no {group}.hibe.mpk in keystore"
            ))
        })?;
        let msk_bytes = read_opt("hibe.msk")?.ok_or_else(|| Error::NotAPublisher {
            group: group.to_string(),
            reason: "HIBE: only the authority (msk holder) can rotate the identity path".into(),
        })?;
        let idpath_bytes = read_opt("hibe.idpath")?.ok_or_else(|| {
            Error::InvalidConfig(format!(
                "hibe group {group}: no {group}.hibe.idpath in keystore"
            ))
        })?;
        let idpath_raw = String::from_utf8(idpath_bytes).map_err(|_| {
            Error::InvalidConfig(format!("hibe group {group}: idpath is not utf-8"))
        })?;

        let root_marker = self.keystore.join(format!("{group}.hibe.idpath.root"));
        let allow_root_current = self.storage.exists(&root_marker);
        let current_path = normalize_hibe_path(&idpath_raw, "current id_path", allow_root_current)?;

        let new_path = normalize_hibe_path(new_path, "id_path", allow_root_path)?;
        if new_path == current_path {
            return Err(Error::InvalidConfig(format!(
                "HIBE: new path equals the current path {new_path:?}"
            )));
        }

        // Prior sealing paths recorded by earlier rotations, newest first.
        let mut prior_paths: Vec<String> = Vec::new();
        if let Some(bytes) = read_opt("hibe.idpath.history")? {
            let text = String::from_utf8(bytes).map_err(|_| {
                Error::InvalidConfig(format!("hibe group {group}: idpath history is not utf-8"))
            })?;
            for (idx, line) in text.lines().enumerate() {
                prior_paths.push(decode_hibe_history_line(
                    line,
                    &format!("{group}.hibe.idpath.history line {}", idx + 1),
                )?);
            }
        }

        // Fresh key for the new path, minted BEFORE any file is touched: a
        // scheme-level rejection (e.g. the root path, or exceeding the
        // authority's max depth) must leave the keystore unchanged.
        let pp = tn_hibe::PublicParams::from_bytes(&mpk)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let msk = tn_hibe::MasterKey::from_bytes(&msk_bytes)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let id = tn_hibe::Identity::try_from_str_path(&new_path)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?;
        let new_sk = tn_hibe::keygen(&pp, &msk, &id, rand_core::OsRng)
            .map_err(|e| Error::Cipher(format!("hibe: {e}")))?
            .to_bytes();

        // Write order pinned by the Python contract (history and the
        // superseded-key archive land before the active sk/idpath swap, so
        // a crash mid-rotation never strands an epoch's material).
        prior_paths.insert(0, current_path.clone());
        let history_text = prior_paths
            .iter()
            .map(|p| encode_hibe_history_path(p))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        self.storage
            .write_bytes(
                &self.keystore.join(format!("{group}.hibe.idpath.history")),
                history_text.as_bytes(),
            )
            .map_err(Error::Io)?;

        if let Some(current_sk) = read_opt("hibe.sk")? {
            self.storage
                .write_bytes(&self.previous_hibe_sk_path(group), &current_sk)
                .map_err(Error::Io)?;
        }

        self.storage
            .write_bytes(&self.keystore.join(format!("{group}.hibe.sk")), &new_sk)
            .map_err(Error::Io)?;
        self.storage
            .write_bytes(
                &self.keystore.join(format!("{group}.hibe.idpath")),
                new_path.as_bytes(),
            )
            .map_err(Error::Io)?;
        if new_path.is_empty() {
            self.storage
                .write_bytes(&root_marker, b"root\n")
                .map_err(Error::Io)?;
        } else if self.storage.exists(&root_marker) {
            self.storage.remove(&root_marker).map_err(Error::Io)?;
        }

        // The runtime caches each group cipher at init (see
        // reload_group_cipher): rebuild NOW or the next emit still seals
        // under the pre-rotation path. A failed rebuild is a security
        // failure, not a DX nit — propagate it.
        self.reload_group_cipher(group)?;

        Ok(RotateIdPathResult {
            group: group.to_string(),
            previous_path: current_path,
            new_path,
        })
    }

    /// HIBE identity-path rotation — unavailable in this build: the `hibe`
    /// feature is off, so the verb yields a clear `NotImplemented` instead
    /// of a build error.
    ///
    /// # Errors
    ///
    /// Always returns [`NotImplemented`](crate::Error::NotImplemented).
    #[cfg(not(feature = "hibe"))]
    pub fn admin_rotate_id_path(
        &self,
        _group: &str,
        _new_path: &str,
        _allow_root_path: bool,
    ) -> Result<RotateIdPathResult> {
        Err(Error::NotImplemented(
            "admin_rotate_id_path: cipher=hibe rotation requires tn-core's hibe feature",
        ))
    }

    /// An unused archive path for a superseded HIBE identity key. Mirrors
    /// Python `_previous_hibe_sk_path`: `<group>.hibe.sk.previous.<ns>`,
    /// appending a counter suffix on the (nanosecond-resolution) collision.
    #[cfg(feature = "hibe")]
    fn previous_hibe_sk_path(&self, group: &str) -> PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base_name = format!("{group}.hibe.sk.previous.{ns}");
        let mut candidate = self.keystore.join(&base_name);
        let mut counter = 1u32;
        while self.storage.exists(&candidate) {
            candidate = self.keystore.join(format!("{base_name}.{counter}"));
            counter += 1;
        }
        candidate
    }

    /// Mint kits for an LLM-runtime DID across all named groups + the
    /// reserved `tn.agents` group, then export a `kit_bundle` `.tnpkg`
    /// at `out_path`.
    ///
    /// Per the 2026-04-25 read-ergonomics spec §2.8. The `tn.agents`
    /// group is always implicitly added (de-duplicated if the caller
    /// passed it). `label` is written to a `.label` sidecar next to the
    /// output `.tnpkg` for downstream identification — best-effort,
    /// never fails the call.
    ///
    /// Returns the absolute `.tnpkg` path.
    ///
    /// # Errors
    ///
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if a requested
    ///   group is not declared in this ceremony's yaml.
    /// - Filesystem errors from minting kits or writing the bundle, plus
    ///   any error propagated from [`Runtime::admin_add_recipient`].
    ///
    /// # Panics
    ///
    /// Panics if an internal admin lock is poisoned (see
    /// [`Runtime::admin_add_recipient`]).
    pub fn admin_add_agent_runtime(
        &self,
        runtime_did: &str,
        groups: &[&str],
        out_path: &Path,
        label: Option<&str>,
    ) -> Result<PathBuf> {
        // Dedup: tn.agents is always added; if the caller passed it,
        // don't double-mint. Preserve order for the others.
        let mut requested: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for g in groups {
            if *g == "tn.agents" {
                continue;
            }
            let s = (*g).to_string();
            if seen.insert(s.clone()) {
                requested.push(s);
            }
        }
        requested.push("tn.agents".to_string());

        for g in &requested {
            if !self.cfg.groups.contains_key(g) {
                return Err(Error::InvalidConfig(format!(
                    "admin_add_agent_runtime: group {g:?} is not declared in this \
                     ceremony's yaml (known: {:?})",
                    self.cfg.groups.keys().collect::<Vec<_>>()
                )));
            }
        }

        // Mint kits into a temp directory using the canonical filename
        // so export(kind='kit_bundle') picks them up.
        let td = tempfile::Builder::new()
            .prefix("tn-agent-bundle-")
            .tempdir()
            .map_err(Error::Io)?;
        for gname in &requested {
            let kit_path = td.path().join(format!("{gname}.btn.mykit"));
            self.admin_add_recipient(gname, &kit_path, Some(runtime_did))?;
        }

        let opts = crate::runtime_export::ExportOptions {
            kind: Some(crate::tnpkg::ManifestKind::KitBundle),
            to_did: Some(runtime_did.to_string()),
            scope: None,
            confirm_includes_secrets: false,
            groups: Some(requested.clone()),
            keystore: Some(td.path().to_path_buf()),
            encrypt_body_with: None,
            seal_for_recipients: Vec::new(),
            package_body: None,
        };
        // Keep the tempdir alive until export completes; `keystore` above
        // points export at the freshly minted recipient kits.
        let out = self.export(out_path, opts)?;

        // Best-effort label sidecar. Routed through `self.storage` so
        // wasm consumers satisfy the write via their JS callback set;
        // failure is logged + swallowed either way.
        if let Some(lbl) = label {
            let mut sidecar_str = out.as_os_str().to_owned();
            sidecar_str.push(".label");
            let sidecar = PathBuf::from(sidecar_str);
            if let Err(e) = self.storage.write_bytes(&sidecar, lbl.as_bytes()) {
                log::warn!("admin_add_agent_runtime: failed to write label sidecar: {e}");
            }
        }

        // Keep tempdir alive until export completes.
        drop(td);
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Admin verbs: cipher-agnostic recipient management.
    //
    // Public names follow the SDK parity matrix (tn_proto/docs/sdk-parity.md):
    // `admin_add_recipient`, `admin_revoke_recipient`, `admin_revoked_count`.
    // Today only btn ceremonies are supported; JWE support lands alongside the
    // second cipher and reuses these same public names.
    // ------------------------------------------------------------------

    /// Mint a new reader kit for `group`, write it to `out_kit_path`,
    /// persist the updated publisher state, and return the recipient
    /// identifier (the btn leaf index). Backs `tn.admin_add_recipient()`.
    ///
    /// `out_kit_path`'s basename MUST end with `.btn.mykit` (e.g.
    /// `default.btn.mykit`) — the bundle exporter's regex requires it, and
    /// a mismatched name would silently ship the publisher's own self-kit
    /// in its place. For per-recipient bundling use
    /// [`Runtime::bundle_for_recipient`], which handles minting + the
    /// canonical filename + export in one call.
    ///
    /// The publisher state write is atomic and compare-and-swap guarded:
    /// state is persisted before the kit file, and a concurrent writer
    /// that moved the on-disk state out from under us surfaces as
    /// [`Error::KeystoreConflict`](crate::Error::KeystoreConflict) (re-read
    /// and retry). After the swap, subsequent writes encrypt to the
    /// enlarged recipient set.
    ///
    /// When `recipient_did` is `Some`, a `tn.recipient.added` event is
    /// appended to the log carrying the leaf index + recipient DID + kit
    /// SHA. Readers can replay these events to reconstruct the recipient
    /// map without any sidecar state file; the attested log is the source
    /// of truth. (The attestation is best-effort: a write failure is
    /// logged, not returned — the kit is already minted and persisted.)
    ///
    /// Matches Python `tn.admin_add_recipient(group, out_path, recipient_did)`.
    ///
    /// # Errors
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if `out_kit_path`
    ///   lacks the `.btn.mykit` suffix or `group` is not a btn publisher
    ///   group in this runtime.
    /// - [`KeystoreConflict`](crate::Error::KeystoreConflict) if another
    ///   writer raced the state CAS — re-read and retry.
    /// - [`Io`](crate::Error::Io) if the state or kit file cannot be written.
    /// - [`Btn`](crate::Error::Btn) if the tree is exhausted or minting fails.
    ///
    /// # Panics
    ///
    /// Panics if the group's `PublisherState` mutex is poisoned by a prior panic
    /// while holding it. The runtime treats a poisoned admin mutex as an
    /// unrecoverable invariant violation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::Runtime;
    /// use std::path::Path;
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::init(Path::new("tn.yaml"))?;
    /// let leaf = rt.admin_add_recipient(
    ///     "default",
    ///     Path::new("default.btn.mykit"),
    ///     Some("did:key:zRecipient"),
    /// )?;
    /// println!("minted leaf {leaf}");
    /// # Ok(())
    /// # }
    /// ```
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

    /// Revoke the reader identified by `leaf_index` in `group`. Backs
    /// `tn.admin_revoke_recipient()`.
    ///
    /// Persists the updated publisher state to disk under the same atomic
    /// CAS guard as [`Runtime::admin_add_recipient`], swaps the cipher so
    /// subsequent writes exclude the revoked leaf, and writes a
    /// `tn.recipient.revoked` attested event (best-effort — a failed
    /// attestation is logged, not returned, since the state is already
    /// persisted). Revocation does not re-key existing readers; only a
    /// rotation retires the generation.
    ///
    /// Matches Python `tn.admin_revoke_recipient(group, leaf_index)`.
    ///
    /// # Errors
    /// - [`InvalidConfig`](crate::Error::InvalidConfig) if `group` is not
    ///   a btn publisher group.
    /// - [`KeystoreConflict`](crate::Error::KeystoreConflict) if another
    ///   writer raced the state CAS — re-read and retry.
    /// - [`Io`](crate::Error::Io) if the state file cannot be written.
    /// - [`Btn`](crate::Error::Btn) if `leaf_index` is out of range.
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

    /// Rotate a btn publisher group to a fresh key generation.
    ///
    /// The previous publisher state and self-kit are preserved under
    /// `.retired.<epoch>` siblings so historical entries remain readable by
    /// this project. The active state and self-kit are replaced atomically
    /// enough for the state file to retain the same CAS protection used by
    /// recipient add/revoke. A `tn.rotation.completed` attestation is emitted
    /// after the in-memory cipher swap, so subsequent writes use the new
    /// generation immediately.
    pub fn admin_rotate_group(&self, group: &str) -> Result<RotateGroupResult> {
        let pub_cipher_arc = self.btn_admin.get(group).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_rotate_group: group {group:?} is not a btn publisher group"
            ))
        })?;
        let mut pub_cipher = pub_cipher_arc.lock().expect("btn_admin Mutex poisoned");

        let keystore_backend = crate::keystore_backend::LocalKeystore::new(
            self.keystore.clone(),
            self.storage.clone(),
        );
        let prior_state_bytes = keystore_backend.read_state(group).map_err(Error::Io)?;
        let previous_mykit_bytes = self
            .storage
            .read_bytes(&self.keystore.join(format!("{group}.btn.mykit")))
            .map_err(Error::Io)?;
        let previous_kit_sha256 =
            format!("sha256:{}", hex::encode(sha2_256(&previous_mykit_bytes)));

        let outcome = tn_btn::PublisherState::from_bytes(&pub_cipher.state_to_bytes())?.rotate()?;
        let mut active = outcome.active;
        let new_self_kit = active.mint()?;
        let new_self_kit_bytes = new_self_kit.to_bytes();
        let new_state_bytes = active.to_bytes();
        let generation = active.epoch();
        let new_kit_sha256 = format!("sha256:{}", hex::encode(sha2_256(&new_self_kit_bytes)));

        let retired_state_path = self.keystore.join(format!(
            "{group}.btn.state.retired.{}",
            outcome.retired.epoch()
        ));
        let retired_mykit_path = self.keystore.join(format!(
            "{group}.btn.mykit.retired.{}",
            outcome.retired.epoch()
        ));
        self.storage
            .write_bytes(&retired_state_path, &outcome.retired.to_bytes())
            .map_err(Error::Io)?;
        self.storage
            .write_bytes(&retired_mykit_path, &previous_mykit_bytes)
            .map_err(Error::Io)?;

        keystore_backend.write_state(group, prior_state_bytes.as_deref(), &new_state_bytes)?;
        self.storage
            .write_bytes(
                &self.keystore.join(format!("{group}.btn.mykit")),
                &new_self_kit_bytes,
            )
            .map_err(Error::Io)?;

        *pub_cipher = BtnPublisherCipher::from_state(active);

        let all_kits = collect_btn_kit_bytes_with_storage(&self.keystore, group, &self.storage)?;
        let new_cipher = rebuild_btn_cipher_with_kits(&pub_cipher, &all_kits)?;
        drop(pub_cipher);

        if let Some(gstate_arc) = self.groups.get(group) {
            let mut gstate = gstate_arc.write().expect("group state RwLock poisoned");
            gstate.cipher = new_cipher;
        }

        let _ = bump_group_index_epoch(&self.yaml_path, group, generation as u64);

        let rotated_at = current_timestamp_rfc3339();
        let mut fields = Map::new();
        fields.insert("group".into(), Value::String(group.to_string()));
        fields.insert("cipher".into(), Value::String("btn".to_string()));
        fields.insert("generation".into(), Value::Number(generation.into()));
        fields.insert(
            "previous_kit_sha256".into(),
            Value::String(previous_kit_sha256.clone()),
        );
        fields.insert("old_pool_size".into(), Value::Null);
        fields.insert("new_pool_size".into(), Value::Null);
        fields.insert("rotated_at".into(), Value::String(rotated_at.clone()));
        if let Err(e) = self.emit("info", "tn.rotation.completed", fields) {
            log::warn!(
                "admin state persisted but attestation emit failed: event_type={} error={}",
                "tn.rotation.completed",
                e
            );
        }

        Ok(RotateGroupResult {
            group: group.to_string(),
            generation,
            previous_kit_sha256,
            new_kit_sha256,
            rotated_at,
        })
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

    /// Read admin/governance events from every log source this ceremony may
    /// have used.
    ///
    /// Everyday reads intentionally default to the active session log. Admin
    /// replay is different: recipient and vault lifecycle state must survive
    /// process boundaries and log splitting. That means replay needs to scan
    /// the main log, protocol-events-location logs, and templated log siblings
    /// when the ceremony routes events by type/date/id.
    fn read_admin_replay_raw(&self) -> Result<Vec<super::ReadEntry>> {
        let mut entries = Vec::new();
        for path in self.admin_replay_log_paths() {
            let mut from_path = self.read_from(&path)?;
            entries.append(&mut from_path);
        }
        entries.sort_by(|a, b| {
            let a_ts = a
                .envelope
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("");
            let b_ts = b
                .envelope
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("");
            a_ts.cmp(b_ts).then_with(|| {
                let a_event_id = a
                    .envelope
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let b_event_id = b
                    .envelope
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                a_event_id.cmp(b_event_id)
            })
        });
        Ok(entries)
    }

    fn admin_replay_log_paths(&self) -> Vec<PathBuf> {
        let mut seen = BTreeSet::new();
        let mut paths = Vec::new();
        self.push_existing_log_path(&mut paths, &mut seen, self.log_path.clone());

        let yaml_dir = self.yaml_path.parent().unwrap_or(Path::new("."));
        if let Ok(template) = crate::path_template::PathTemplate::parse(
            &self.cfg.logs.path,
            yaml_dir,
            &self.cfg.ceremony.id,
            self.device.did(),
        ) {
            self.push_template_log_paths(&mut paths, &mut seen, &template);
        }

        let pel = &self.cfg.ceremony.protocol_events_location;
        if pel != "main_log" {
            if let Ok(template) = crate::path_template::PathTemplate::parse(
                pel,
                yaml_dir,
                &self.cfg.ceremony.id,
                self.device.did(),
            ) {
                self.push_template_log_paths(&mut paths, &mut seen, &template);
            }
        }

        paths
    }

    fn push_template_log_paths(
        &self,
        paths: &mut Vec<PathBuf>,
        seen: &mut BTreeSet<PathBuf>,
        template: &crate::path_template::PathTemplate,
    ) {
        if !template.is_templated() {
            self.push_existing_log_path(paths, seen, template.render("", ""));
            return;
        }

        let sample = template.render("__admin_probe__", "__admin_probe__");
        let Some(parent_dir) = sample.parent() else {
            return;
        };
        let Ok(entries) = self.storage.list(parent_dir) else {
            return;
        };
        for entry in entries {
            if entry.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
                self.push_existing_log_path(paths, seen, entry);
            }
        }
    }

    fn push_existing_log_path(
        &self,
        paths: &mut Vec<PathBuf>,
        seen: &mut BTreeSet<PathBuf>,
        path: PathBuf,
    ) {
        if !self.storage.exists(&path) {
            return;
        }
        let key = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.insert(key) {
            paths.push(path);
        }
    }

    /// Return the current recipient roster for `group` by replaying the
    /// log through the admin reducer. Backs `tn.recipients()`; mirrors
    /// Python `tn.recipients(group, …)` and TypeScript
    /// `client.recipients(group, …)`.
    ///
    /// Each [`RecipientEntry`] compresses the lifecycle into a single
    /// `revoked` boolean (use [`Runtime::admin_state`] for the full
    /// active/revoked/retired status). Active recipients are returned
    /// sorted by `leaf_index`; when `include_revoked` is true, revoked
    /// entries are appended after the active ones (also sorted by
    /// leaf_index).
    ///
    /// Reducer errors on a single envelope are warn-logged and skipped — a
    /// single corrupt admin event does not abort the whole replay.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`] (this replays the log to build the
    /// roster).
    ///
    /// **Divergence from Python/TS:** Rust's `read()` does not currently
    /// produce per-event signature/row_hash/chain validity flags, so
    /// tampered admin events cannot be filtered out the way Python and TS
    /// do via `valid.{signature, row_hash, chain}`. Until `ReadEntry`
    /// carries validity flags, this function trusts whatever `read()`
    /// returned. Tampered envelopes that still parse and pass schema will
    /// be reflected in the roster.
    pub fn recipients(&self, group: &str, include_revoked: bool) -> Result<Vec<RecipientEntry>> {
        let mut active: BTreeMap<u64, RecipientEntry> = BTreeMap::new();
        let mut revoked: BTreeMap<u64, RecipientEntry> = BTreeMap::new();

        for entry in self.read_admin_replay_raw()? {
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

    /// Return the full local [`AdminState`] by replaying the log through
    /// the admin reducer. Backs `tn.admin_state()`; mirrors Python
    /// `tn.admin_state(group=…)`.
    ///
    /// When `group` is `Some`, the `groups`, `recipients`, `rotations`,
    /// `coupons`, and `enrolments` lists are filtered to that group.
    /// `ceremony` and `vault_links` are not filtered.
    ///
    /// If no `tn.ceremony.init` event is present in the log (common for
    /// btn ceremonies — the publisher state lives on disk, not the
    /// attested log), the ceremony record is reconstructed from the
    /// active config with `created_at == None`.
    ///
    /// A single admin event that fails to reduce is warn-logged and
    /// skipped rather than aborting the replay.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::read`] (this replays the log to build the
    /// state).
    #[allow(clippy::too_many_lines)] // single replay loop; splitting fragments invariants
    pub fn admin_state(&self, group: Option<&str>) -> Result<AdminState> {
        let mut state = AdminState::default();

        // Active+lifecycle recipient rows keyed by (group, leaf_index).
        let mut by_leaf: BTreeMap<(String, u64), AdminRecipientRecord> = BTreeMap::new();
        // Enrolment rows keyed by (group, peer_did).
        let mut enrolments_by_peer: BTreeMap<(String, String), AdminEnrolment> = BTreeMap::new();
        // Vault links keyed by vault_did.
        let mut vault_links_by_did: BTreeMap<String, AdminVaultLink> = BTreeMap::new();

        for entry in self.read_admin_replay_raw()? {
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
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`]. (The idempotency pre-check tolerates a
    /// failed `admin_state` read and proceeds to the write.)
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
        fields.insert(
            "vault_identity".into(),
            Value::String(vault_did.to_string()),
        );
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
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::emit`].
    pub fn vault_unlink(
        &self,
        vault_did: &str,
        project_id: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut fields = Map::new();
        fields.insert(
            "vault_identity".into(),
            Value::String(vault_did.to_string()),
        );
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

#[cfg(all(test, feature = "fs", feature = "hibe"))]
mod tests {
    use std::path::{Path, PathBuf};

    use rand_core::OsRng;
    use tn_hibe::{keygen, setup, Identity};

    use crate::runtime::Runtime;
    use crate::tnpkg::{read_tnpkg, ManifestKind, TnpkgSource};

    struct HibeCeremony {
        yaml_path: PathBuf,
    }

    fn setup_minimal_hibe_ceremony(root: &Path) -> HibeCeremony {
        let keystore = root.join(".tn").join("keys");
        std::fs::create_dir_all(&keystore).unwrap();

        let dk = crate::DeviceKey::generate();
        std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
        std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

        let (pp, msk) = setup(2, OsRng).unwrap();
        let id_path = "team/audit";
        let sk = keygen(&pp, &msk, &Identity::from_str_path(id_path), OsRng)
            .unwrap()
            .to_bytes();
        std::fs::write(keystore.join("default.hibe.mpk"), pp.to_bytes()).unwrap();
        std::fs::write(keystore.join("default.hibe.msk"), msk.to_bytes()).unwrap();
        std::fs::write(keystore.join("default.hibe.idpath"), id_path).unwrap();
        std::fs::write(keystore.join("default.hibe.sk"), sk).unwrap();

        let did = dk.did().to_string();
        let yaml = format!(
            "ceremony: {{id: cer_hibe_test, mode: local, cipher: hibe, protocol_events_location: main_log}}\n\
             keystore: {{path: ./.tn/keys}}\n\
             device: {{device_identity: \"{did}\"}}\n\
             public_fields: []\n\
             default_policy: private\n\
             groups:\n\
             \x20 default:\n\
             \x20   policy: private\n\
             \x20   cipher: hibe\n\
             \x20   recipients:\n\
             \x20     - {{recipient_identity: \"{did}\"}}\n\
             \x20   index_epoch: 0\n\
             fields: {{}}\n\
             llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
        );
        let yaml_path = root.join("tn.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();

        HibeCeremony { yaml_path }
    }

    #[test]
    fn bundle_for_recipient_stages_hibe_reader_material() {
        let td = tempfile::tempdir().unwrap();
        let cer = setup_minimal_hibe_ceremony(td.path());
        let rt = Runtime::init(&cer.yaml_path).unwrap();

        let out = td.path().join("reader-hibe.tnpkg");
        rt.bundle_for_recipient("did:key:zRecipient", &out, Some(&["default"]))
            .unwrap();

        let (manifest, body) = read_tnpkg(TnpkgSource::Path(&out)).unwrap();
        assert_eq!(manifest.kind, ManifestKind::KitBundle);
        assert_eq!(
            manifest.recipient_identity.as_deref(),
            Some("did:key:zRecipient")
        );
        assert!(body.contains_key("body/default.hibe.mpk"));
        assert!(body.contains_key("body/default.hibe.idpath"));
        assert!(body.contains_key("body/default.hibe.sk"));
        assert!(!body.contains_key("body/default.btn.mykit"));
    }
}

fn normalize_fields(fields: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for field in fields {
        let field = field.as_ref().trim();
        if field.is_empty() {
            return Err(Error::InvalidConfig(
                "admin_ensure_group: field names must not be empty".into(),
            ));
        }
        if seen.insert(field.to_string()) {
            out.push(field.to_string());
        }
    }
    Ok(out)
}

fn group_declared(doc: &YamlValue, group: &str) -> Result<bool> {
    let root = doc
        .as_mapping()
        .ok_or_else(|| Error::InvalidConfig("tn.yaml root must be a mapping".into()))?;
    let Some(groups) = root
        .get(YamlValue::String("groups".into()))
        .and_then(YamlValue::as_mapping)
    else {
        return Ok(false);
    };
    Ok(groups.contains_key(YamlValue::String(group.to_string())))
}

#[allow(clippy::similar_names)]
fn ensure_yaml_group(
    doc: &mut YamlValue,
    group: &str,
    publisher_did: &str,
    fields: &[String],
) -> Result<bool> {
    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| Error::InvalidConfig("tn.yaml root must be a mapping".into()))?;
    let groups_yaml_key = YamlValue::String("groups".into());
    if !root.contains_key(&groups_yaml_key) {
        root.insert(
            groups_yaml_key.clone(),
            YamlValue::Mapping(Default::default()),
        );
    }
    let groups = root
        .get_mut(&groups_yaml_key)
        .and_then(YamlValue::as_mapping_mut)
        .ok_or_else(|| Error::InvalidConfig("tn.yaml groups must be a mapping".into()))?;

    let mut changed = false;
    let group_yaml_key = YamlValue::String(group.to_string());
    if !groups.contains_key(&group_yaml_key) {
        groups.insert(group_yaml_key.clone(), btn_group_spec(publisher_did)?);
        changed = true;
    }
    let group_spec = groups
        .get_mut(&group_yaml_key)
        .and_then(YamlValue::as_mapping_mut)
        .ok_or_else(|| Error::InvalidConfig(format!("groups[{group:?}] must be a mapping")))?;

    let fields_yaml_key = YamlValue::String("fields".into());
    if !group_spec.contains_key(&fields_yaml_key) {
        group_spec.insert(fields_yaml_key.clone(), YamlValue::Sequence(Vec::new()));
        changed = true;
    }
    let routed = group_spec
        .get_mut(&fields_yaml_key)
        .and_then(YamlValue::as_sequence_mut)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "admin_ensure_group: groups[{group:?}].fields must be a list when present"
            ))
        })?;
    for field in fields {
        if !routed
            .iter()
            .any(|item| item.as_str() == Some(field.as_str()))
        {
            routed.push(YamlValue::String(field.clone()));
            changed = true;
        }
    }

    let flat_key = YamlValue::String("fields".into());
    if !root.contains_key(&flat_key) {
        root.insert(flat_key.clone(), YamlValue::Mapping(Default::default()));
        changed = true;
    }
    let flat = root
        .get_mut(&flat_key)
        .and_then(YamlValue::as_mapping_mut)
        .ok_or_else(|| Error::InvalidConfig("tn.yaml top-level fields must be a mapping".into()))?;
    for field in fields {
        let field_yaml_key = YamlValue::String(field.clone());
        let route_value = serde_yml::to_value(serde_json::json!({ "group": group }))?;
        match flat.get(&field_yaml_key) {
            Some(existing) if yaml_to_json(existing) == yaml_to_json(&route_value) => {}
            _ => {
                flat.insert(field_yaml_key, route_value);
                changed = true;
            }
        }
    }

    Ok(changed)
}

fn btn_group_spec(publisher_did: &str) -> Result<YamlValue> {
    serde_yml::to_value(serde_json::json!({
        "policy": "private",
        "cipher": "btn",
        "recipients": [
            { "recipient_identity": publisher_did }
        ],
        "index_epoch": 0
    }))
    .map_err(Error::from)
}

fn rebuild_btn_cipher_with_kits(
    pub_cipher: &BtnPublisherCipher,
    kit_bytes: &[Vec<u8>],
) -> Result<Arc<dyn GroupCipher>> {
    let state_bytes = pub_cipher.state_to_bytes();
    let new_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
    let cipher: Arc<dyn GroupCipher> = if kit_bytes.is_empty() {
        Arc::new(new_pc)
    } else {
        Arc::new(new_pc.with_reader_kits(kit_bytes)?)
    };
    Ok(cipher)
}

fn bump_group_index_epoch(yaml_path: &Path, group: &str, generation: u64) -> Result<()> {
    let raw = std::fs::read_to_string(yaml_path)?;
    let mut doc: YamlValue = serde_yml::from_str(&raw)?;
    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| Error::InvalidConfig("tn.yaml root must be a mapping".into()))?;
    let groups_key = YamlValue::String("groups".into());
    let groups = root
        .get_mut(&groups_key)
        .and_then(YamlValue::as_mapping_mut)
        .ok_or_else(|| Error::InvalidConfig("tn.yaml groups must be a mapping".into()))?;
    let group_key = YamlValue::String(group.to_string());
    let group_spec = groups
        .get_mut(&group_key)
        .and_then(YamlValue::as_mapping_mut)
        .ok_or_else(|| Error::InvalidConfig(format!("groups[{group:?}] must be a mapping")))?;
    group_spec.insert(
        YamlValue::String("index_epoch".into()),
        serde_yml::to_value(generation)?,
    );
    let updated = serde_yml::to_string(&doc)?;
    std::fs::write(yaml_path, updated)?;
    Ok(())
}

fn resolve_keystore_path(doc: &YamlValue, yaml_path: &Path) -> Result<PathBuf> {
    let root = doc
        .as_mapping()
        .ok_or_else(|| Error::InvalidConfig("tn.yaml root must be a mapping".into()))?;
    let rel = root
        .get(YamlValue::String("keystore".into()))
        .and_then(YamlValue::as_mapping)
        .and_then(|keystore| keystore.get(YamlValue::String("path".into())))
        .and_then(YamlValue::as_str)
        .ok_or_else(|| Error::InvalidConfig("tn.yaml is missing keystore.path".into()))?;
    let path = PathBuf::from(rel);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(yaml_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path))
    }
}

fn mint_btn_group(keystore: &Path, group: &str) -> Result<()> {
    std::fs::create_dir_all(keystore)?;
    let state_path = keystore.join(format!("{group}.btn.state"));
    let mykit_path = keystore.join(format!("{group}.btn.mykit"));

    if state_path.exists() && mykit_path.exists() {
        return Ok(());
    }
    if state_path.exists() != mykit_path.exists() {
        return Err(Error::InvalidConfig(format!(
            "admin_ensure_group: partial btn key material exists for group {group:?}"
        )));
    }

    let mut seed = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let mut publisher = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed)?;
    let kit = publisher.mint()?;

    std::fs::write(state_path, publisher.to_bytes())?;
    std::fs::write(mykit_path, kit.to_bytes())?;
    Ok(())
}

fn yaml_to_json(value: &YamlValue) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}
