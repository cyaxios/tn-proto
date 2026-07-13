//! Per-group cipher construction from keystore material, plus the
//! fresh-ceremony minting used by [`Runtime::ephemeral`](super::Runtime::ephemeral).
//!
//! [`Runtime::init`](super::Runtime::init) calls these once per declared
//! group to turn the on-disk `<group>.btn.state` / `<group>.btn.mykit`
//! files (current + rotation-archived) into a live [`GroupCipher`], and
//! the admin verbs reuse [`rebuild_btn_cipher`] after mutating publisher
//! state. The storage-aware variants route their reads through the
//! injected [`Storage`](crate::storage::Storage) handle; the bare
//! `std::fs` reference impls are retained for parity.
//!
//! [`GroupCipher`]: crate::cipher::GroupCipher

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use uuid::Uuid;

use crate::cipher::{
    btn::{BtnPublisherCipher, BtnReaderCipher},
    jwe::JweCipher,
    GroupCipher,
};
use crate::config::{Config, GroupSpec};
use crate::{DeviceKey, Error, Result};

use super::GroupState;

/// Return value of `build_cipher_with_admin`: (cipher, optional pub cipher for admin, optional mykit bytes).
type BuildCipherResult = (
    Arc<dyn GroupCipher>,
    Option<BtnPublisherCipher>,
    Option<Vec<u8>>,
);

/// The per-group tables [`Runtime::init`](super::Runtime) holds: the live
/// [`GroupState`] map (cipher + HMAC template), the btn admin side-table,
/// and the remembered mykit bytes per group.
type GroupTables = (
    BTreeMap<String, Arc<RwLock<GroupState>>>,
    BTreeMap<String, Arc<Mutex<BtnPublisherCipher>>>,
    BTreeMap<String, Option<Vec<u8>>>,
);

/// Build the per-group state tables for every declared group: derive each
/// group's index key, construct its cipher from keystore material, and
/// pre-initialize the HMAC template. The group-construction loop lifted
/// out of [`Runtime::init`](super::Runtime).
///
/// Returns `(groups, btn_admin, btn_mykit)`: the live [`GroupState`] map,
/// the typed btn-publisher side-table admin verbs mutate, and the
/// remembered current mykit bytes per group (for rebuilding the cipher
/// after an admin mutation).
///
/// # Errors
///
/// Propagates index-key derivation, HMAC-template, and cipher-construction
/// errors (see [`build_cipher_with_admin_with_storage`]).
pub(crate) fn build_group_states(
    cfg: &Config,
    master_index_key: &[u8; 32],
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
    device: &DeviceKey,
) -> Result<GroupTables> {
    let mut groups: BTreeMap<String, Arc<RwLock<GroupState>>> = BTreeMap::new();
    let mut btn_admin: BTreeMap<String, Arc<Mutex<BtnPublisherCipher>>> = BTreeMap::new();
    let mut btn_mykit: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();

    for (name, spec) in &cfg.groups {
        let index_key = crate::indexing::derive_group_index_key(
            master_index_key,
            &cfg.ceremony.id,
            name,
            spec.index_epoch,
        )?;
        // Call site 4: cipher construction reads `<group>.btn.state`
        // and `<group>.btn.mykit` through storage.
        let (cipher, maybe_pub_cipher, mykit_bytes) =
            build_cipher_with_admin_with_storage(spec, keystore, name, storage, device)?;
        let hmac_template = crate::indexing::build_hmac_template(&index_key)?;
        groups.insert(
            name.clone(),
            Arc::new(RwLock::new(GroupState {
                cipher,
                hmac_template,
                aad_default: spec.aad.clone(),
            })),
        );
        if let Some(pub_cipher) = maybe_pub_cipher {
            btn_admin.insert(name.clone(), Arc::new(Mutex::new(pub_cipher)));
        }
        btn_mykit.insert(name.clone(), mykit_bytes);
    }

    Ok((groups, btn_admin, btn_mykit))
}

/// Returns `(cipher, Option<BtnPublisherCipher for admin>, Option<mykit_bytes>)`.
///
/// The `BtnPublisherCipher` returned for admin still reflects the **current**
/// state (no reader kit attached; admin only needs the PublisherState).  The
/// mykit bytes are kept separately so `rebuild_btn_cipher` can re-attach them.
#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
pub(crate) fn build_cipher_with_admin(
    spec: &GroupSpec,
    keystore: &Path,
    group_name: &str,
    device: &DeviceKey,
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin(keystore, group_name),
        "jwe" | "bearer" => build_jwe_cipher(spec, device),
        "hibe" => Err(Error::NotImplemented(
            "HIBE groups run through the Python runtime in this plan (tn-hibe backs them)",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

/// Storage-aware variant of [`build_cipher_with_admin`] used by
/// [`Runtime::init_with_storage`]. Reads the publisher state file and
/// kit bytes through the supplied [`Storage`] handle so a wasm
/// `JsStorageAdapter` can satisfy the loads from its JS callbacks.
///
/// Publisher-state, current-kit, and historical-kit discovery all route
/// through storage. Backends must return an empty list when a directory has
/// no archived material; listing errors are propagated so hidden historical
/// reader material does not get silently dropped.
///
/// [`Storage`]: crate::storage::Storage
#[allow(dead_code)]
pub(crate) fn build_cipher_with_admin_with_storage(
    spec: &GroupSpec,
    keystore: &Path,
    group_name: &str,
    storage: &Arc<dyn crate::storage::Storage>,
    device: &DeviceKey,
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin_with_storage(keystore, group_name, storage),
        "jwe" | "bearer" => build_jwe_cipher(spec, device),
        #[cfg(feature = "hibe")]
        "hibe" => build_hibe_cipher_with_storage(keystore, group_name, storage),
        #[cfg(not(feature = "hibe"))]
        "hibe" => Err(Error::NotImplemented(
            "HIBE support is not built into this tn-core (the `hibe` feature is off)",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

fn build_jwe_cipher(spec: &GroupSpec, device: &DeviceKey) -> Result<BuildCipherResult> {
    let recipients = spec
        .recipients
        .iter()
        .map(|recipient| recipient.recipient_identity.clone())
        .collect::<Vec<_>>();
    let cipher = JweCipher::new(&recipients, device)?;
    Ok((Arc::new(cipher), None, None))
}

/// Storage-aware btn cipher builder. Reads `<group>.btn.state` and
/// `<group>.btn.mykit` through `storage`; `*.btn.mykit.retired.<epoch>`
/// and legacy `*.btn.mykit.revoked.<ts>` siblings are discovered through
/// `Storage::list` and read through the same backend.
pub(crate) fn build_btn_cipher_with_admin_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<BuildCipherResult> {
    let state_path = keystore.join(format!("{group}.btn.state"));
    let state_exists = storage.exists(&state_path);
    let all_kits = collect_btn_kit_bytes_with_storage(keystore, group, storage)?;
    let has_any_kit = !all_kits.is_empty();

    match (state_exists, has_any_kit) {
        (true, _) => {
            let state_bytes = storage.read_bytes(&state_path).map_err(Error::Io)?;
            let pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            let admin_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            let current_mykit = all_kits.first().cloned();
            let cipher: Arc<dyn GroupCipher> = if has_any_kit {
                Arc::new(pc.with_reader_kits(&all_kits)?)
            } else {
                Arc::new(pc)
            };
            Ok((cipher, Some(admin_pc), current_mykit))
        }
        (false, true) => {
            let current_mykit = all_kits.first().cloned();
            let cipher = Arc::new(BtnReaderCipher::from_multi_kit_bytes(&all_kits)?);
            Ok((cipher, None, current_mykit))
        }
        (false, false) => Err(Error::InvalidConfig(format!(
            "btn group {group}: no {group}.btn.state and no {group}.btn.mykit in keystore"
        ))),
    }
}

/// Storage-aware hibe cipher builder. Reads the group's hibe key files
/// (`<group>.hibe.{mpk,idpath,sk,msk,idpath.history}` plus superseded
/// `<group>.hibe.sk.previous.*`) through `storage` and constructs a native
/// [`HibeCipher`](crate::cipher::hibe::HibeCipher) that seals/opens via the
/// `tn-hibe` scheme. `mpk` and `idpath` are required; the rest are optional
/// (a write-only party holds neither `sk` nor `msk`). Returns the cipher
/// with no btn admin side-table.
///
/// `pub(crate)`: also the hibe candidate loader for the sealed-object
/// key-bag walk (runtime/seal.rs).
#[cfg(feature = "hibe")]
pub(crate) fn build_hibe_cipher_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<BuildCipherResult> {
    let read_opt = |name: String| -> Result<Option<Vec<u8>>> {
        let p = keystore.join(name);
        if storage.exists(&p) {
            Ok(Some(storage.read_bytes(&p).map_err(Error::Io)?))
        } else {
            Ok(None)
        }
    };

    let mpk = read_opt(format!("{group}.hibe.mpk"))?.ok_or_else(|| {
        Error::InvalidConfig(format!(
            "hibe group {group}: no {group}.hibe.mpk in keystore"
        ))
    })?;
    let idpath_bytes = read_opt(format!("{group}.hibe.idpath"))?.ok_or_else(|| {
        Error::InvalidConfig(format!(
            "hibe group {group}: no {group}.hibe.idpath in keystore"
        ))
    })?;
    let id_path = String::from_utf8(idpath_bytes)
        .map_err(|_| Error::InvalidConfig(format!("hibe group {group}: idpath is not utf-8")))?;

    let sk = read_opt(format!("{group}.hibe.sk"))?;
    let msk = read_opt(format!("{group}.hibe.msk"))?;

    let prior_paths: Vec<String> = match read_opt(format!("{group}.hibe.idpath.history"))? {
        Some(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| {
                Error::InvalidConfig(format!("hibe group {group}: idpath history is not utf-8"))
            })?;
            let mut out = Vec::new();
            let lines: Vec<&str> = text.split('\n').collect();
            let last = lines.len().saturating_sub(1);
            for (idx, line) in lines.into_iter().enumerate() {
                if line.is_empty() && idx == last {
                    continue;
                }
                if line.ends_with('\r') {
                    return Err(Error::InvalidConfig(format!(
                        "hibe group {group}: idpath history line {} contains CR",
                        idx + 1
                    )));
                }
                let id = crate::cipher::hibe::validate_identity_path(line)?;
                out.push(crate::cipher::hibe::identity_to_path(&id)?);
            }
            out
        }
        None => Vec::new(),
    };

    // Superseded reader keys, newest first (same order the Python loader
    // uses: reverse-sorted `.previous.<ts>` siblings).
    let prev_prefix = format!("{group}.hibe.sk.previous.");
    let mut prev_paths: Vec<PathBuf> = storage
        .list(keystore)
        .map_err(Error::Io)?
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prev_prefix))
        })
        .collect();
    prev_paths.sort();
    prev_paths.reverse();
    let mut prior_sks: Vec<Vec<u8>> = Vec::with_capacity(prev_paths.len());
    for p in prev_paths {
        prior_sks.push(storage.read_bytes(&p).map_err(Error::Io)?);
    }

    let cipher =
        crate::cipher::hibe::HibeCipher::new(&mpk, &id_path, sk, msk, prior_paths, prior_sks)?;
    Ok((Arc::new(cipher), None, None))
}

/// Storage-aware kit-bytes collection. Mirrors
/// [`collect_btn_kit_bytes`] but routes the current-kit read through
/// `storage`. Archived-kit discovery uses `Storage::list`; listing errors
/// propagate because treating them as "no archived kits" can hide the only
/// material capable of opening historical rows.
pub(crate) fn collect_btn_kit_bytes_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if storage.exists(&current) {
        kits.push(storage.read_bytes(&current).map_err(Error::Io)?);
    }

    // Retired + revoked kit discovery: list directory through storage. A
    // backend with no archived kits must return an empty list; an error here
    // is load-bearing because old rows may only decrypt with archived kits.
    let entries = storage.list(keystore).map_err(Error::Io)?;

    // 0.4.3a1 introduces `.btn.mykit.retired.<epoch>` as the canonical
    // post-rotation archive name (epoch-indexed). The legacy
    // `.btn.mykit.revoked.<unix_ts>` shape from 0.4.2-line keystores is
    // still loaded so pre-rename keystores keep reading. Sort each
    // family by its own index descending so newer kits are tried first.
    let retired_prefix = format!("{group}.btn.mykit.retired.");
    let revoked_prefix = format!("{group}.btn.mykit.revoked.");
    let mut retired: Vec<(std::path::PathBuf, u32)> = Vec::new();
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    for path in entries {
        let Some(name_str) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(n_str) = name_str.strip_prefix(&retired_prefix) {
            if let Ok(n) = n_str.parse::<u32>() {
                retired.push((path, n));
            }
        } else if let Some(ts_str) = name_str.strip_prefix(&revoked_prefix) {
            let ts: u64 = ts_str.parse().unwrap_or(0);
            revoked.push((path, ts));
        }
    }
    retired.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in retired {
        kits.push(storage.read_bytes(&path).map_err(Error::Io)?);
    }
    revoked.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in revoked {
        kits.push(storage.read_bytes(&path).map_err(Error::Io)?);
    }

    Ok(kits)
}

/// Collect all kit files for a group: the current `<group>.btn.mykit` first,
/// followed by any `<group>.btn.mykit.revoked.<ts>` siblings sorted by
/// timestamp descending (most recent first). Returned as a vec of byte
/// blobs in try-first order. Empty vec if no kit files exist.
///
/// Rotation preserves previous kits under `.revoked.<ts>` so pre-rotation
/// entries stay readable. `BtnReaderCipher` tries each kit in order and
/// the first successful decrypt wins.
#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
pub(crate) fn collect_btn_kit_bytes(keystore: &Path, group: &str) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if current.exists() {
        kits.push(std::fs::read(&current).map_err(Error::Io)?);
    }

    // Gather both archived-kit families:
    //   `<group>.btn.mykit.retired.<epoch>` (0.4.3a1+, epoch-indexed)
    //   `<group>.btn.mykit.revoked.<unix_ts>` (legacy 0.4.2-line)
    let retired_prefix = format!("{group}.btn.mykit.retired.");
    let revoked_prefix = format!("{group}.btn.mykit.revoked.");
    let mut retired: Vec<(std::path::PathBuf, u32)> = Vec::new();
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(keystore) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Some(n_str) = name_str.strip_prefix(&retired_prefix) {
                if let Ok(n) = n_str.parse::<u32>() {
                    retired.push((entry.path(), n));
                }
            } else if let Some(ts_str) = name_str.strip_prefix(&revoked_prefix) {
                // Expect ts_str to be a unix timestamp like "1776797973"; tolerate
                // non-numeric suffixes by falling back to 0 (gets sorted last).
                let ts: u64 = ts_str.parse().unwrap_or(0);
                revoked.push((entry.path(), ts));
            }
        }
    }
    // Newest first within each family — most likely era for any given older
    // entry to belong to.
    retired.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in retired {
        kits.push(std::fs::read(&path).map_err(Error::Io)?);
    }
    revoked.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, _) in revoked {
        kits.push(std::fs::read(&path).map_err(Error::Io)?);
    }

    Ok(kits)
}

#[allow(dead_code)] // retained as the non-storage reference impl; init now goes through *_with_storage.
pub(crate) fn build_btn_cipher_with_admin(
    keystore: &Path,
    group: &str,
) -> Result<BuildCipherResult> {
    // Filenames verified against tn/cipher.py::BtnGroupCipher:
    //   <keystore>/<group>.btn.state                  - serialized PublisherState (SECRET)
    //   <keystore>/<group>.btn.mykit                  - current self-kit (for decrypt)
    //   <keystore>/<group>.btn.mykit.revoked.<ts>     - preserved kits from previous rotations
    let state_path = keystore.join(format!("{group}.btn.state"));
    let all_kits = collect_btn_kit_bytes(keystore, group)?;
    let has_any_kit = !all_kits.is_empty();

    match (state_path.exists(), has_any_kit) {
        (true, _) => {
            let state_bytes = std::fs::read(&state_path).map_err(Error::Io)?;
            let pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            // Admin side-table holds the raw publisher cipher (no kit attached).
            // We need a second copy for admin, so deserialize again.
            let admin_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
            // Remember the CURRENT kit bytes only (admin flows rebuild the
            // publisher using this as the "latest" kit; rotation-preserved
            // kits are discovered fresh on each init via collect_btn_kit_bytes).
            let current_mykit = all_kits.first().cloned();
            let cipher: Arc<dyn GroupCipher> = if has_any_kit {
                Arc::new(pc.with_reader_kits(&all_kits)?)
            } else {
                Arc::new(pc)
            };
            Ok((cipher, Some(admin_pc), current_mykit))
        }
        (false, true) => {
            let current_mykit = all_kits.first().cloned();
            let cipher = Arc::new(BtnReaderCipher::from_multi_kit_bytes(&all_kits)?);
            // Reader-only: no admin capability.
            Ok((cipher, None, current_mykit))
        }
        (false, false) => Err(Error::InvalidConfig(format!(
            "btn group {group}: no {group}.btn.state and no {group}.btn.mykit in keystore"
        ))),
    }
}

/// Rebuild a `BtnPublisherCipher` trait object from the current admin cipher state,
/// re-attaching the mykit if available.
pub(crate) fn rebuild_btn_cipher(
    pub_cipher: &BtnPublisherCipher,
    mykit_bytes: Option<&[u8]>,
) -> Result<Arc<dyn GroupCipher>> {
    let state_bytes = pub_cipher.state_to_bytes();
    let new_pc = BtnPublisherCipher::from_state_bytes(&state_bytes)?;
    let cipher: Arc<dyn GroupCipher> = if let Some(kit) = mykit_bytes {
        Arc::new(new_pc.with_reader_kit(kit)?)
    } else {
        Arc::new(new_pc)
    };
    Ok(cipher)
}

/// Options for minting a fresh btn ceremony on disk.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FreshBtnCeremonyOptions {
    /// Prefix used for the generated ceremony id.
    pub ceremony_id_prefix: &'static str,
}

impl FreshBtnCeremonyOptions {
    pub(crate) const fn ephemeral() -> Self {
        Self {
            ceremony_id_prefix: "cer_eph",
        }
    }
}

/// Mint a fresh btn ceremony at `root`. Layout matches the test helper
/// in `tests/common/mod.rs::setup_minimal_btn_ceremony`:
///
/// ```text
/// <root>/
///   .tn/
///     keys/
///       local.private        — 32-byte Ed25519 seed
///       index_master.key     — 32 random bytes
///       default.btn.state    — serialized PublisherState
///       default.btn.mykit    — minted ReaderKit
///       tn.agents.btn.state  — serialized PublisherState (reserved policy group)
///       tn.agents.btn.mykit  — minted ReaderKit (reserved policy group)
///   tn.yaml
/// ```
///
/// Used by [`Runtime::ephemeral`]. Lives in the public crate so
/// downstream tests + benches don't have to duplicate it.
///
/// Auto-injects the reserved `tn.agents` group per the 2026-04-25
/// read-ergonomics spec §2.3. Pure-logging users pay nothing — the
/// group's plaintext stays empty when no policy file exists.
pub(crate) fn write_fresh_btn_ceremony(
    root: &Path,
    options: FreshBtnCeremonyOptions,
) -> std::io::Result<PathBuf> {
    use crate::keystore_backend::atomic_write_bytes;
    use rand_core::{OsRng, RngCore};

    let yaml_path = root.join("tn.yaml");
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore)?;

    // Every write below uses atomic_write_bytes (tmp + fsync +
    // rename) so a crash mid-mint never leaves a half-formed
    // keystore on disk — partial state files would fail to parse on
    // next load and burn the ceremony silently. No CAS here because
    // this is fresh-ceremony init: by construction nobody else is
    // writing to this keystore yet.

    // Device key — 32-byte Ed25519 seed.
    let dk = crate::DeviceKey::generate();
    atomic_write_bytes(&keystore.join("local.private"), &dk.private_bytes())?;

    // Master index key — 32 random bytes from the OS.
    let mut master = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    atomic_write_bytes(&keystore.join("index_master.key"), &master)?;

    // default group: btn publisher state + self-reader kit.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut pub_state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, seed)
        .map_err(|e| std::io::Error::other(format!("btn setup failed: {e:?}")))?;
    let kit = pub_state
        .mint()
        .map_err(|e| std::io::Error::other(format!("btn mint failed: {e:?}")))?;
    atomic_write_bytes(&keystore.join("default.btn.state"), &pub_state.to_bytes())?;
    atomic_write_bytes(&keystore.join("default.btn.mykit"), &kit.to_bytes())?;

    // tn.agents reserved group: btn publisher state + self-reader kit.
    let mut agents_seed = [0u8; 32];
    OsRng.fill_bytes(&mut agents_seed);
    let mut agents_state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, agents_seed)
        .map_err(|e| std::io::Error::other(format!("btn setup (tn.agents) failed: {e:?}")))?;
    let agents_kit = agents_state
        .mint()
        .map_err(|e| std::io::Error::other(format!("btn mint (tn.agents) failed: {e:?}")))?;
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.state"),
        &agents_state.to_bytes(),
    )?;
    atomic_write_bytes(
        &keystore.join("tn.agents.btn.mykit"),
        &agents_kit.to_bytes(),
    )?;

    let did = dk.did().to_string();
    let id = format!(
        "{}_{}",
        options.ceremony_id_prefix,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let yaml = format!(
        "ceremony: {{id: {id}, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20 \"tn.agents\":\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{recipient_identity: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         \x20   fields: [instruction, use_for, do_not_use_for, consequences, on_violation_or_error, policy]\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    crate::keystore_backend::atomic_write_bytes(&yaml_path, yaml.as_bytes())?;
    Ok(yaml_path)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use crate::storage::Storage;

    use super::collect_btn_kit_bytes_with_storage;

    struct ListingFailsStorage;

    impl Storage for ListingFailsStorage {
        fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "default.btn.mykit")
            {
                return Ok(b"current-kit".to_vec());
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
        }

        fn write_bytes(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn append_bytes(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn exists(&self, path: &Path) -> bool {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "default.btn.mykit")
        }

        fn list(&self, _dir: &Path) -> io::Result<Vec<PathBuf>> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "listing denied",
            ))
        }

        fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
            Ok(())
        }

        fn remove(&self, _path: &Path) -> io::Result<()> {
            Ok(())
        }

        fn create_dir_all(&self, _dir: &Path) -> io::Result<()> {
            Ok(())
        }

        fn cas_write(&self, _path: &Path, _prior: Option<&[u8]>, _new: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn btn_kit_collection_propagates_storage_listing_errors() {
        let storage: Arc<dyn Storage> = Arc::new(ListingFailsStorage);
        let err = collect_btn_kit_bytes_with_storage(Path::new("/keys"), "default", &storage)
            .expect_err("storage.list errors must not hide archived kit material");
        match err {
            crate::Error::Io(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            other => panic!("expected Io(PermissionDenied), got {other:?}"),
        }
    }
}
