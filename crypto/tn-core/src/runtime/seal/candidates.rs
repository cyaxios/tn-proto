//! Reader-cipher candidates used by portable-object unseal.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::cipher::{btn::BtnReaderCipher, jwe::JweCipher, GroupCipher};
use crate::{DeviceKey, Error, Result};

use super::super::cipher_build::collect_btn_kit_bytes;

pub(super) fn jwe_reader_candidate(device: &DeviceKey) -> Result<Arc<dyn GroupCipher>> {
    let recipients = vec![device.did().to_owned()];
    Ok(Arc::new(JweCipher::new(&recipients, device)?))
}

pub(super) fn load_recipient_candidates(
    keystore: &Path,
    group: &str,
) -> Result<Vec<Arc<dyn GroupCipher>>> {
    let btn_kit = keystore.join(format!("{group}.btn.mykit"));
    let legacy_jwe_key = keystore.join(format!("{group}.jwe.mykey"));
    let hibe_key = keystore.join(format!("{group}.hibe.sk"));
    let device_key = keystore.join(crate::identity::DEVICE_SEED_FILENAME);
    let mut ciphers: Vec<Arc<dyn GroupCipher>> = Vec::new();
    let mut found_material = false;

    if btn_kit.exists() {
        found_material = true;
        let kits = collect_btn_kit_bytes(keystore, group)?;
        ciphers.push(Arc::new(BtnReaderCipher::from_multi_kit_bytes(&kits)?));
    }
    if device_key.exists() {
        found_material = true;
        let device = crate::identity::load_device(keystore)?;
        ciphers.push(jwe_reader_candidate(&device)?);
    }
    if legacy_jwe_key.exists() {
        found_material = true;
    }
    if hibe_key.exists() {
        found_material = true;
        push_hibe_candidate(&mut ciphers, keystore, group)?;
    }
    if !found_material {
        return Err(missing_recipient_key(keystore, group));
    }
    Ok(ciphers)
}

fn missing_recipient_key(keystore: &Path, group: &str) -> Error {
    Error::InvalidConfig(format!(
        "unseal: no recipient key found for group={group:?} in {}. \
         Looked for {group}.btn.mykit (btn), local.private (jwe), and \
         {group}.hibe.sk (hibe). If you absorbed a kit_bundle, the kit \
         lands in your ceremony's keystore — point as_recipient there.",
        keystore.display()
    ))
}

#[cfg(feature = "hibe")]
fn push_hibe_candidate(
    ciphers: &mut Vec<Arc<dyn GroupCipher>>,
    keystore: &Path,
    group: &str,
) -> Result<()> {
    let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
    let (cipher, _, _) =
        super::super::cipher_build::build_hibe_cipher_with_storage(keystore, group, &storage)?;
    ciphers.push(cipher);
    Ok(())
}

#[cfg(not(feature = "hibe"))]
fn push_hibe_candidate(
    _ciphers: &mut Vec<Arc<dyn GroupCipher>>,
    _keystore: &Path,
    _group: &str,
) -> Result<()> {
    Ok(())
}

pub(super) fn discover_keybag(keystore: &Path) -> BTreeMap<String, Vec<Arc<dyn GroupCipher>>> {
    let mut bag = BTreeMap::new();
    let names = keystore_file_names(keystore);
    add_btn_candidates(&mut bag, keystore, &names);
    add_hibe_candidates(&mut bag, keystore, &names);
    bag
}

fn keystore_file_names(keystore: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(keystore) else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().to_str().map(String::from))
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn add_btn_candidates(
    bag: &mut BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
    keystore: &Path,
    names: &[String],
) {
    for name in names {
        let Some(group) = name.strip_suffix(".btn.mykit") else {
            continue;
        };
        let Ok(kits) = collect_btn_kit_bytes(keystore, group) else {
            continue;
        };
        let Ok(cipher) = BtnReaderCipher::from_multi_kit_bytes(&kits) else {
            continue;
        };
        bag.entry(group.to_owned())
            .or_default()
            .push(Arc::new(cipher));
    }
}

#[cfg(feature = "hibe")]
fn add_hibe_candidates(
    bag: &mut BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
    keystore: &Path,
    names: &[String],
) {
    let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
    for name in names {
        let Some(group) = name.strip_suffix(".hibe.sk") else {
            continue;
        };
        let Ok((cipher, _, _)) =
            super::super::cipher_build::build_hibe_cipher_with_storage(keystore, group, &storage)
        else {
            continue;
        };
        bag.entry(group.to_owned()).or_default().push(cipher);
    }
}

#[cfg(not(feature = "hibe"))]
fn add_hibe_candidates(
    _bag: &mut BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
    _keystore: &Path,
    _names: &[String],
) {
}

pub(super) fn unusable_keystore_kinds(keystore: &Path, group: &str) -> Vec<String> {
    let mut kinds = Vec::new();
    if keystore.join(format!("{group}.jwe.mykey")).exists() {
        kinds.push("jwe".to_owned());
    }
    #[cfg(not(feature = "hibe"))]
    if keystore.join(format!("{group}.hibe.sk")).exists() {
        kinds.push("hibe".to_owned());
    }
    kinds
}
