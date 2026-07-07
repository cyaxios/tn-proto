//! Body builders for the seed / bundle export kinds.
//!
//! Each function gathers the `body/...` entries (and any sidecar metadata) for
//! one [`crate::ManifestKind`]: [`build_kit_bundle_body`] for
//! `kit_bundle` / `full_keystore`, [`build_identity_seed_body`] for
//! `identity_seed`, and [`build_project_seed_body`] for `project_seed`. The
//! front-door [`Runtime::export`](crate::Runtime::export) calls these to fill
//! the archive it then signs.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde_json::{Map, Value};

use super::util::sha2_256;
use crate::signing::DeviceKey;
use crate::{Error, Result};

type KitBundleBody = (BTreeMap<String, Vec<u8>>, Vec<Value>);

pub(super) fn build_kit_bundle_body(
    keystore: &Path,
    full: bool,
    groups_filter: Option<&[String]>,
) -> Result<KitBundleBody> {
    if !keystore.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "kit_bundle: keystore directory not found: {}",
                keystore.display()
            ),
        )));
    }
    let group_set: Option<HashSet<String>> = groups_filter.map(|gs| gs.iter().cloned().collect());
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut kits_meta: Vec<Value> = Vec::new();
    let mut saw_reader_secret = false;

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
        if let Some(group) = reader_material_group(name_str) {
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
            if is_reader_secret_material(name_str) {
                saw_reader_secret = true;
            }
            body.insert(format!("body/{name_str}"), data);
        } else if full
            && (name_str == "local.private"
                || name_str == "local.public"
                || name_str == "index_master.key")
        {
            body.insert(format!("body/{name_str}"), std::fs::read(entry.path())?);
        } else if full
            && full_group_material_group(name_str)
                .is_some_and(|group| group_set.as_ref().map_or(true, |f| f.contains(group)))
        {
            body.insert(format!("body/{name_str}"), std::fs::read(entry.path())?);
        }
    }

    if !saw_reader_secret {
        return Err(Error::InvalidConfig(format!(
            "kit_bundle: no reader kit material (*.btn.mykit, *.jwe.mykey, \
             *.hibe.mpk/*.hibe.idpath/*.hibe.sk) in {}",
            keystore.display()
        )));
    }

    if full {
        body.insert("body/WARNING_CONTAINS_PRIVATE_KEYS".into(), Vec::new());
    }

    Ok((body, kits_meta))
}

fn reader_material_group(name: &str) -> Option<&str> {
    for suffix in [
        ".btn.mykit",
        ".jwe.mykey",
        ".hibe.mpk",
        ".hibe.idpath",
        ".hibe.sk",
    ] {
        if let Some(group) = name.strip_suffix(suffix) {
            if !group.is_empty() {
                return Some(group);
            }
        }
    }
    None
}

fn is_reader_secret_material(name: &str) -> bool {
    [".btn.mykit", ".jwe.mykey", ".hibe.sk"]
        .iter()
        .any(|suffix| name.strip_suffix(suffix).is_some_and(|g| !g.is_empty()))
}

fn full_group_material_group(name: &str) -> Option<&str> {
    if let Some(group) = reader_material_group(name) {
        return Some(group);
    }
    for suffix in [
        ".btn.state",
        ".jwe.sender",
        ".jwe.recipients",
        ".hibe.msk",
        ".hibe.idpath.history",
        ".hibe.grants",
    ] {
        if let Some(group) = name.strip_suffix(suffix) {
            if !group.is_empty() {
                return Some(group);
            }
        }
    }
    if let Some((group, _)) = name.split_once(".hibe.sk.previous.") {
        if !group.is_empty() {
            return Some(group);
        }
    }
    None
}

pub(super) fn build_identity_seed_body(device: &DeviceKey) -> BTreeMap<String, Vec<u8>> {
    let stub_yaml = format!(
        "# Identity seed stub written by tn-core export(kind='identity_seed').\n\
         # Replace this file with a real ceremony tn.yaml when joining one.\n\
         identity:\n\
           did: {}\n",
        device.did()
    );
    let mut body = BTreeMap::new();
    body.insert("body/local.private".into(), device.private_bytes().to_vec());
    body.insert("body/local.public".into(), device.did().as_bytes().to_vec());
    body.insert("body/tn.yaml".into(), stub_yaml.into_bytes());
    body
}

type ProjectSeedBody = (BTreeMap<String, Vec<u8>>, Vec<String>);

pub(super) fn build_project_seed_body(
    yaml_path: &Path,
    keystore: &Path,
    device: &DeviceKey,
    groups_filter: Option<&[String]>,
) -> Result<ProjectSeedBody> {
    if !yaml_path.is_file() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("project_seed: yaml file not found: {}", yaml_path.display()),
        )));
    }
    if !keystore.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "project_seed: keystore directory not found: {}",
                keystore.display()
            ),
        )));
    }

    let group_set: Option<HashSet<String>> = groups_filter.map(|gs| gs.iter().cloned().collect());
    let mut body: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut keys_meta: Vec<String> = Vec::new();
    body.insert("body/tn.yaml".into(), std::fs::read(yaml_path)?);

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
        let include = match name_str {
            "local.private" | "local.public" | "index_master.key" => true,
            _ => {
                if let Some(group) = name_str.strip_suffix(".btn.mykit") {
                    group_set.as_ref().map_or(true, |f| f.contains(group))
                } else if let Some(group) = name_str.strip_suffix(".btn.state") {
                    group_set.as_ref().map_or(true, |f| f.contains(group))
                } else {
                    false
                }
            }
        };
        if include {
            body.insert(
                format!("body/keys/{name_str}"),
                std::fs::read(entry.path())?,
            );
            keys_meta.push(name_str.to_string());
        }
    }

    if !body.contains_key("body/keys/local.private") {
        body.insert(
            "body/keys/local.private".into(),
            device.private_bytes().to_vec(),
        );
        keys_meta.push("local.private".into());
    }
    if !body.contains_key("body/keys/local.public") {
        body.insert(
            "body/keys/local.public".into(),
            device.did().as_bytes().to_vec(),
        );
        keys_meta.push("local.public".into());
    }

    keys_meta.sort();
    keys_meta.dedup();
    body.insert("body/WARNING_CONTAINS_PRIVATE_KEYS".into(), Vec::new());
    Ok((body, keys_meta))
}
