use std::collections::{BTreeMap, HashMap};
use std::io::{BufReader, Read as _};
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::cipher::{btn::BtnReaderCipher, jwe::JweCipher};
use crate::log_file::LogFileReader;
use crate::{Error, Result};

use super::super::{
    ReadContext, ReadCursorV1, ReadEntry, ReadReport, ReadTrustPolicy, Runtime, ValidFlags,
};
use super::decrypt::{decrypt_entry, GroupDecryptors};
use super::record::{decode_group_inputs, prepare_envelope};
use super::source::{open_storage_read_snapshot, read_bounded_line, scan_file_with_decryptors};

#[derive(Debug, Default)]
struct ForeignReaderMaterial {
    btn: Vec<String>,
    hibe: Vec<String>,
    jwe: Vec<String>,
}

impl ForeignReaderMaterial {
    fn sort_and_dedup(&mut self) {
        sort_and_dedup(&mut self.btn);
        sort_and_dedup(&mut self.hibe);
        sort_and_dedup(&mut self.jwe);
    }

    fn is_empty(&self) -> bool {
        self.btn.is_empty() && self.hibe.is_empty() && self.jwe.is_empty()
    }
}

fn sort_and_dedup(groups: &mut Vec<String>) {
    groups.sort();
    groups.dedup();
}

pub(super) fn is_foreign_log(
    log_path: &Path,
    own_log: &Path,
    own_did: &str,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<bool> {
    if same_file(log_path, own_log) {
        return Ok(false);
    }
    if discover_reader_material(keystore, storage)?.is_empty() {
        return Ok(false);
    }
    Ok(peek_writer_did(log_path, storage)?.is_some_and(|did| did != own_did))
}

fn same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    matches!((left.canonicalize(), right.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

fn peek_writer_did(
    path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Option<String>> {
    let Ok(snapshot) = open_storage_read_snapshot(storage.as_ref(), path) else {
        return Ok(None);
    };
    let mut reader = BufReader::new(snapshot.reader.take(snapshot.len));
    let mut line = Vec::new();
    loop {
        let Some(meta) = read_bounded_line(&mut reader, &mut line).map_err(Error::Io)? else {
            return Ok(None);
        };
        trim_line_end(&mut line);
        if meta.overflowed || line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match writer_did_from_line(&line) {
            Ok(did) => return Ok(did),
            Err(()) => continue,
        }
    }
}

fn trim_line_end(line: &mut Vec<u8>) {
    while line
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        line.pop();
    }
}

fn writer_did_from_line(line: &[u8]) -> std::result::Result<Option<String>, ()> {
    let text = std::str::from_utf8(line).map_err(|_| ())?;
    let envelope: Value = serde_json::from_str(text).map_err(|_| ())?;
    Ok(envelope
        .get("device_identity")
        .and_then(Value::as_str)
        .filter(|did| !did.is_empty())
        .map(str::to_owned))
}

pub(super) fn read_foreign_log(
    log_path: &Path,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<Vec<ReadEntry>> {
    let decryptors = load_foreign_decryptors(keystore, storage)?;
    read_log_with_decryptors(log_path, storage, &decryptors)
}

pub(super) fn read_log_with_decryptors(
    log_path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
    decryptors: &GroupDecryptors,
) -> Result<Vec<ReadEntry>> {
    let mut entries = Vec::new();
    for result in LogFileReader::open(log_path, storage)? {
        entries.push(decrypt_foreign_row(result, decryptors)?);
    }
    Ok(entries)
}

fn decrypt_foreign_row(result: Result<Value>, decryptors: &GroupDecryptors) -> Result<ReadEntry> {
    let envelope = match result {
        Ok(envelope) => envelope,
        Err(error) => return Ok(parse_error_entry(&error.to_string())),
    };
    let Some(inputs) = decode_group_inputs(&envelope) else {
        return Ok(parse_error_entry("invalid encrypted group block"));
    };
    let mut entry = ReadEntry {
        envelope,
        plaintext_per_group: BTreeMap::new(),
    };
    Ok(match decrypt_entry(&mut entry, &inputs, decryptors)? {
        Some(error) => parse_error_entry(&error),
        None => entry,
    })
}

fn parse_error_entry(reason: &str) -> ReadEntry {
    ReadEntry {
        envelope: serde_json::json!({
            "event_type": "<parse-error>",
            "_parse_error": reason,
        }),
        plaintext_per_group: BTreeMap::new(),
    }
}

pub(crate) struct RecipientRow {
    pub(crate) entry: ReadEntry,
    pub(crate) signature: bool,
    pub(crate) chain: bool,
}

pub(crate) fn read_recipient_rows(
    log_path: &Path,
    keystore: &Path,
    group: &str,
) -> Result<Vec<RecipientRow>> {
    let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
    let decryptors = load_foreign_decryptors(keystore, &storage)?;
    if !decryptors.contains_group(group) {
        return Err(Error::InvalidConfig(format!(
            "read_as_recipient: no recipient material for group {group:?} in {}",
            keystore.display()
        )));
    }
    scan_recipient_rows(log_path, &storage, &decryptors, group)
}

fn scan_recipient_rows(
    log_path: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
    decryptors: &GroupDecryptors,
    group: &str,
) -> Result<Vec<RecipientRow>> {
    let snapshot = open_storage_read_snapshot(storage.as_ref(), log_path)?;
    let mut reader = BufReader::new(snapshot.reader.take(snapshot.len));
    let mut previous = HashMap::new();
    let mut line = Vec::new();
    let mut rows = Vec::new();
    while let Some(meta) = read_bounded_line(&mut reader, &mut line).map_err(Error::Io)? {
        trim_line_end(&mut line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if meta.overflowed {
            return Err(Error::Malformed {
                kind: "log file",
                reason: "record exceeds the read line limit".into(),
            });
        }
        if let Some(row) = prepare_recipient_line(&line, decryptors, group, &mut previous)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn prepare_recipient_line(
    line: &[u8],
    decryptors: &GroupDecryptors,
    group: &str,
    previous: &mut HashMap<String, String>,
) -> Result<Option<RecipientRow>> {
    let text = std::str::from_utf8(line).map_err(|error| Error::Malformed {
        kind: "log file",
        reason: format!("record is not valid UTF-8: {error}"),
    })?;
    let envelope: Value = serde_json::from_str(text)?;
    if !envelope
        .get("event_type")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(None);
    }
    let prepared = prepare_envelope(envelope, previous);
    let signature = prepared.record.row_hash_valid && prepared.record.signature_valid;
    let chain = prepared.record.chain_valid;
    let mut entry = prepared.entry;
    let selected_inputs = prepared
        .group_inputs
        .get(group)
        .map(|input| BTreeMap::from([(group.to_owned(), input.clone())]))
        .unwrap_or_default();
    if decrypt_entry(&mut entry, &selected_inputs, decryptors)?.is_some() {
        entry.plaintext_per_group.insert(
            group.to_owned(),
            serde_json::json!({"$decrypt_error": true}),
        );
    }
    Ok(Some(RecipientRow {
        entry,
        signature,
        chain,
    }))
}

pub(super) fn read_foreign_with_validity(
    runtime: &Runtime,
    log_path: &Path,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
    cursor: Option<&ReadCursorV1>,
) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
    let decryptors = load_foreign_decryptors(&runtime.keystore, &runtime.storage)?;
    scan_file_with_decryptors(runtime, log_path, policy, context, cursor, &decryptors)
}

fn load_foreign_decryptors(
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<GroupDecryptors> {
    let material = discover_reader_material(keystore, storage)?;
    let mut decryptors = GroupDecryptors::new();
    load_btn_decryptors(&mut decryptors, &material, keystore, storage)?;
    load_hibe_decryptors(&mut decryptors, &material, keystore, storage)?;
    load_jwe_decryptors(&mut decryptors, &material, keystore, storage)?;
    Ok(decryptors)
}

fn load_jwe_decryptors(
    decryptors: &mut GroupDecryptors,
    material: &ForeignReaderMaterial,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<()> {
    for group in &material.jwe {
        let keys =
            super::super::cipher_build::load_jwe_reader_private_keys(keystore, group, storage)?;
        match JweCipher::new_with_owned_reader_keys(group, &[], keys) {
            Ok(cipher) => decryptors.insert(group.clone(), Arc::new(cipher)),
            Err(error) => insert_broken_material(decryptors, group, "jwe", &error),
        }
    }
    Ok(())
}

fn load_btn_decryptors(
    decryptors: &mut GroupDecryptors,
    material: &ForeignReaderMaterial,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<()> {
    for group in &material.btn {
        let kits = super::super::cipher_build::collect_btn_kit_bytes_with_storage(
            keystore, group, storage,
        )?;
        if !kits.is_empty() {
            match BtnReaderCipher::from_multi_kit_bytes(&kits) {
                Ok(cipher) => decryptors.insert(group.clone(), Arc::new(cipher)),
                Err(error) => insert_broken_material(decryptors, group, "btn", &error),
            }
        }
    }
    Ok(())
}

#[cfg(feature = "hibe")]
fn load_hibe_decryptors(
    decryptors: &mut GroupDecryptors,
    material: &ForeignReaderMaterial,
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<()> {
    for group in &material.hibe {
        match super::super::cipher_build::build_hibe_cipher_with_storage(keystore, group, storage) {
            Ok((cipher, _, _)) => decryptors.insert(group.clone(), cipher),
            Err(error) => insert_broken_material(decryptors, group, "hibe", &error),
        }
    }
    Ok(())
}

#[cfg(not(feature = "hibe"))]
fn load_hibe_decryptors(
    decryptors: &mut GroupDecryptors,
    material: &ForeignReaderMaterial,
    _keystore: &Path,
    _storage: &Arc<dyn crate::storage::Storage>,
) -> Result<()> {
    load_unavailable_decryptors(decryptors, &material.hibe, "hibe");
    Ok(())
}

#[cfg(not(feature = "hibe"))]
fn load_unavailable_decryptors(
    decryptors: &mut GroupDecryptors,
    groups: &[String],
    kind: &'static str,
) {
    for group in groups {
        decryptors.insert_unavailable(
            group.clone(),
            format!("read_from: cipher={kind} is not implemented in tn-core; group={group:?}"),
        );
    }
}

fn insert_broken_material(
    decryptors: &mut GroupDecryptors,
    group: &str,
    kind: &str,
    error: &Error,
) {
    decryptors.insert_unavailable(
        group.to_owned(),
        format!("read_from: cipher={kind} material for group {group:?} is invalid: {error}"),
    );
}

fn discover_reader_material(
    keystore: &Path,
    storage: &Arc<dyn crate::storage::Storage>,
) -> Result<ForeignReaderMaterial> {
    let mut material = ForeignReaderMaterial::default();
    for path in storage.list(keystore).map_err(Error::Io)? {
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        classify_material_name(name, &mut material);
    }
    material.sort_and_dedup();
    Ok(material)
}

fn classify_material_name(name: &str, material: &mut ForeignReaderMaterial) {
    if let Some(group) = btn_material_group(name) {
        material.btn.push(group.to_owned());
    } else if let Some(group) = name.strip_suffix(".hibe.sk") {
        push_nonempty(&mut material.hibe, group);
    } else if let Some(group) = name.strip_suffix(".jwe.mykey") {
        push_nonempty(&mut material.jwe, group);
    } else if let Some((group, _)) = name.split_once(".jwe.mykey.revoked.") {
        push_nonempty(&mut material.jwe, group);
    }
}

fn btn_material_group(name: &str) -> Option<&str> {
    name.strip_suffix(".btn.mykit")
        .or_else(|| name.split_once(".btn.mykit.retired.").map(|item| item.0))
        .or_else(|| name.split_once(".btn.mykit.revoked.").map(|item| item.0))
        .filter(|group| !group.is_empty())
}

fn push_nonempty(groups: &mut Vec<String>, group: &str) {
    if !group.is_empty() {
        groups.push(group.to_owned());
    }
}
