use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::Value;

use crate::chain::GroupInput;
use crate::cipher::GroupCipher;
use crate::sealed_object::aad_bytes_for;
use crate::Error;

use super::super::{ReadContext, ReadDecision, ReadEntry, ReadTrustPolicy, Runtime, ValidFlags};
use super::policy::read_chain_required;
use super::record::PreparedRecord;

pub(super) enum EvaluatedRecord {
    Accepted(ReadEntry, ValidFlags),
    Rejected(ReadEntry, ReadDecision),
}

pub(super) struct GroupDecryptors {
    groups: BTreeMap<String, Vec<DecryptCandidate>>,
}

enum DecryptCandidate {
    Cipher(Arc<dyn GroupCipher>),
    Unavailable(String),
}

impl GroupDecryptors {
    pub(super) fn from_runtime(runtime: &Runtime) -> Self {
        let mut decryptors = Self::new();
        for (group, state) in &runtime.groups {
            let cipher = state
                .read()
                .expect("group state RwLock poisoned")
                .cipher
                .clone();
            decryptors.insert(group.clone(), cipher);
        }
        decryptors
    }

    pub(super) fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
        }
    }

    pub(super) fn insert(&mut self, group: String, cipher: Arc<dyn GroupCipher>) {
        self.groups
            .entry(group)
            .or_default()
            .push(DecryptCandidate::Cipher(cipher));
    }

    pub(super) fn insert_unavailable(&mut self, group: String, reason: String) {
        self.groups
            .entry(group)
            .or_default()
            .push(DecryptCandidate::Unavailable(reason));
    }

    pub(super) fn contains_group(&self, group: &str) -> bool {
        self.groups.contains_key(group)
    }

    fn decrypt(&self, group: &str, ciphertext: &[u8], aad: &[u8]) -> GroupDecryptOutcome {
        let Some(candidates) = self.groups.get(group) else {
            return GroupDecryptOutcome::NoReaderCapability;
        };
        let mut authentication_failed = false;
        let mut malformed = None;
        let mut unavailable = None;
        for candidate in candidates {
            match candidate {
                DecryptCandidate::Unavailable(reason) => {
                    unavailable.get_or_insert(reason);
                }
                DecryptCandidate::Cipher(cipher) => {
                    match decrypt_candidate(cipher.as_ref(), ciphertext, aad) {
                        GroupDecryptOutcome::NoReaderCapability => {}
                        GroupDecryptOutcome::AuthenticationFailed => authentication_failed = true,
                        GroupDecryptOutcome::MalformedPlaintext(error) => malformed = Some(error),
                        outcome @ GroupDecryptOutcome::Decrypted(_) => return outcome,
                        GroupDecryptOutcome::Unavailable(_) => {
                            unreachable!("only registry entries are unavailable")
                        }
                    }
                }
            }
        }
        if let Some(reason) = unavailable {
            GroupDecryptOutcome::Unavailable(reason.clone())
        } else if let Some(error) = malformed {
            GroupDecryptOutcome::MalformedPlaintext(error)
        } else if authentication_failed {
            GroupDecryptOutcome::AuthenticationFailed
        } else {
            GroupDecryptOutcome::NoReaderCapability
        }
    }
}

enum GroupDecryptOutcome {
    Decrypted(Value),
    NoReaderCapability,
    AuthenticationFailed,
    MalformedPlaintext(String),
    Unavailable(String),
}

fn decrypt_candidate(
    cipher: &dyn GroupCipher,
    ciphertext: &[u8],
    aad: &[u8],
) -> GroupDecryptOutcome {
    match cipher.decrypt_with_aad(ciphertext, aad) {
        Ok(plaintext) => serde_json::from_slice(&plaintext).map_or_else(
            |error| GroupDecryptOutcome::MalformedPlaintext(error.to_string()),
            GroupDecryptOutcome::Decrypted,
        ),
        Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => {
            GroupDecryptOutcome::NoReaderCapability
        }
        Err(_) => GroupDecryptOutcome::AuthenticationFailed,
    }
}

pub(super) fn evaluate_prepared_record(
    prepared: PreparedRecord,
    decryptors: &GroupDecryptors,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
) -> crate::Result<EvaluatedRecord> {
    let mut record = prepared.record;
    let pre_decrypt = policy.evaluate(&record, context);
    if !pre_decrypt.accepted {
        return Ok(EvaluatedRecord::Rejected(prepared.entry, pre_decrypt));
    }
    let mut entry = prepared.entry;
    let parse_error = decrypt_entry(&mut entry, &prepared.group_inputs, decryptors)?;
    record.record_valid &= parse_error.is_none();
    record.recipient_groups = successfully_decrypted_groups(&entry);
    record.aad_valid = !entry.plaintext_per_group.values().any(is_decrypt_error);
    Ok(finish_evaluation(entry, &record, policy, context))
}

fn finish_evaluation(
    entry: ReadEntry,
    record: &super::super::ReadRecordState,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
) -> EvaluatedRecord {
    let decision = policy.evaluate(&record, context);
    if !decision.accepted {
        return EvaluatedRecord::Rejected(entry, decision);
    }
    let validity = ValidFlags {
        signature: record.signature_present && record.signature_valid,
        row_hash: record.row_hash_present && record.row_hash_valid,
        chain: !read_chain_required(context) || record.chain_valid,
        writer_authenticated: decision.writer_authenticated,
        writer_authorized: decision.writer_authorized,
        reasons: decision.reasons,
    };
    EvaluatedRecord::Accepted(entry, validity)
}

pub(super) fn decrypt_entry(
    entry: &mut ReadEntry,
    inputs: &BTreeMap<String, GroupInput>,
    decryptors: &GroupDecryptors,
) -> crate::Result<Option<String>> {
    for (group, input) in inputs {
        let aad = aad_bytes_for(&entry.envelope, group);
        let outcome = decryptors.decrypt(group, &input.ciphertext, &aad);
        match outcome {
            GroupDecryptOutcome::Decrypted(value) => {
                entry.plaintext_per_group.insert(group.clone(), value);
            }
            GroupDecryptOutcome::NoReaderCapability => {
                insert_sentinel(entry, group, "$no_read_key");
            }
            GroupDecryptOutcome::AuthenticationFailed => {
                insert_sentinel(entry, group, "$decrypt_error");
            }
            GroupDecryptOutcome::MalformedPlaintext(error) => {
                return Ok(Some(format!("plaintext json in group {group:?}: {error}")));
            }
            GroupDecryptOutcome::Unavailable(reason) => {
                return Err(Error::InvalidConfig(reason));
            }
        }
    }
    Ok(None)
}

fn insert_sentinel(entry: &mut ReadEntry, group: &str, marker: &str) {
    entry
        .plaintext_per_group
        .insert(group.to_owned(), serde_json::json!({marker: true}));
}

fn successfully_decrypted_groups(entry: &ReadEntry) -> BTreeSet<String> {
    entry
        .plaintext_per_group
        .iter()
        .filter(|(_, value)| !is_no_read_key(value) && !is_decrypt_error(value))
        .map(|(group, _)| group.clone())
        .collect()
}

pub(super) fn is_no_read_key(value: &Value) -> bool {
    has_sentinel(value, "$no_read_key")
}

pub(super) fn is_decrypt_error(value: &Value) -> bool {
    has_sentinel(value, "$decrypt_error")
}

fn has_sentinel(value: &Value, marker: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.get(marker) == Some(&Value::Bool(true)))
}
