//! Group-cipher construction helpers (standard + BTN, admin variants).
//!
//! Split out of `runtime.rs` (file-size refactor). Behavior unchanged;
//! `use super::*` re-imports everything these helpers need from the parent.

use super::*;

/// Return value of `build_cipher_with_admin`: (cipher, optional pub cipher for admin, optional mykit bytes).
pub(crate) type BuildCipherResult = (
    Arc<dyn GroupCipher>,
    Option<BtnPublisherCipher>,
    Option<Vec<u8>>,
);

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
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin(keystore, group_name),
        "jwe" | "bearer" => Err(Error::NotImplemented(
            "JWE groups run through the Python runtime in this plan; migrate to btn for Rust",
        )),
        "bgw" => Err(Error::NotImplemented(
            "BGW groups run through the Python runtime; FFI not wired in tn-core",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

/// Storage-aware variant of [`build_cipher_with_admin`] used by
/// [`Runtime::init_with_storage`]. Reads the publisher state file and
/// kit bytes through the supplied [`Storage`] handle so a wasm
/// `JsStorageAdapter` can satisfy the loads from its JS callbacks.
///
/// Today (Phase 7 landing) only the publisher-state load is routed
/// through storage; the kit-bytes collection still goes through
/// `std::fs::read_dir` because the directory-listing storage hook is
/// part of the trait but not yet wired here. The wasm path therefore
/// still hits a runtime error when groups need kit-bytes from disk;
/// see the remaining-work notes in the Phase 7 implementation report.
///
/// [`Storage`]: crate::storage::Storage
#[allow(dead_code)]
pub(crate) fn build_cipher_with_admin_with_storage(
    spec: &GroupSpec,
    keystore: &Path,
    group_name: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<BuildCipherResult> {
    match spec.cipher.as_str() {
        "btn" => build_btn_cipher_with_admin_with_storage(keystore, group_name, storage),
        "jwe" | "bearer" => Err(Error::NotImplemented(
            "JWE groups run through the Python runtime in this plan; migrate to btn for Rust",
        )),
        "bgw" => Err(Error::NotImplemented(
            "BGW groups run through the Python runtime; FFI not wired in tn-core",
        )),
        other => Err(Error::InvalidConfig(format!("unknown cipher {other:?}"))),
    }
}

/// Storage-aware btn cipher builder. Reads `<group>.btn.state` and
/// `<group>.btn.mykit` through `storage`; `*.btn.mykit.revoked.<ts>`
/// rotation siblings are still discovered via `std::fs::read_dir`
/// pending Phase 7 follow-up on the directory-listing call sites.
fn build_btn_cipher_with_admin_with_storage(
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

/// Storage-aware kit-bytes collection. Mirrors
/// [`collect_btn_kit_bytes`] but routes the current-kit read through
/// `storage`. Revoked-kit discovery still falls back to
/// `std::fs::read_dir` because directory listing through storage is
/// part of the trait but not yet wired into all of init's helpers
/// (Phase 7 follow-up).
fn collect_btn_kit_bytes_with_storage(
    keystore: &Path,
    group: &str,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<Vec<u8>>> {
    let mut kits: Vec<Vec<u8>> = Vec::new();

    let current = keystore.join(format!("{group}.btn.mykit"));
    if storage.exists(&current) {
        kits.push(storage.read_bytes(&current).map_err(Error::Io)?);
    }

    // Retired + revoked kit discovery: list directory through storage if
    // the backend supports it; absent / errored listing means "no
    // archived kits" rather than a hard failure. That keeps a wasm
    // `JsStorageAdapter` whose `list()` returns an empty array from
    // breaking init when no rotations have happened.
    //
    // 0.4.3a1 introduces `.btn.mykit.retired.<epoch>` as the canonical
    // post-rotation archive name (epoch-indexed). The legacy
    // `.btn.mykit.revoked.<unix_ts>` shape from 0.4.2-line keystores is
    // still loaded so pre-rename keystores keep reading. Sort each
    // family by its own index descending so newer kits are tried first.
    let retired_prefix = format!("{group}.btn.mykit.retired.");
    let revoked_prefix = format!("{group}.btn.mykit.revoked.");
    let mut retired: Vec<(std::path::PathBuf, u32)> = Vec::new();
    let mut revoked: Vec<(std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = storage.list(keystore) {
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

/// Scan `keystore` for files of the form `<group>.btn.state.retired.<N>`
/// (where N is a u32 — the epoch the state served as active). Returns
/// each as `(epoch, bytes)`. Files whose suffix doesn't parse as u32
/// are skipped silently. Used by the publisher-side init path to
/// archive retired states alongside the active one, so historical
/// keywalk decryption has the seed material available.
///
/// 0.4.3a1 only. Pre-rename keystores use `<group>.btn.state.revoked.<ts>`
/// which intentionally is NOT picked up here — those entries archived
/// the prior PublisherState (kind 0x03), not the new lightweight
/// RetiredPublisherState (kind 0x04), so attempting to deserialize them
/// as retired states would error.
pub(crate) fn discover_retired_btn_states(
    keystore: &Path,
    group: &str,
) -> std::io::Result<Vec<(u32, Vec<u8>)>> {
    let prefix = format!("{group}.btn.state.retired.");
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(keystore) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(rest) = name_str.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(epoch) = rest.parse::<u32>() else {
            continue;
        };
        let bytes = std::fs::read(entry.path())?;
        out.push((epoch, bytes));
    }
    Ok(out)
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
fn collect_btn_kit_bytes(keystore: &Path, group: &str) -> Result<Vec<Vec<u8>>> {
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
fn build_btn_cipher_with_admin(keystore: &Path, group: &str) -> Result<BuildCipherResult> {
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

