use std::collections::BTreeSet;

use serde_json::Value;

use crate::{Error, Result};

use super::super::{
    ReadContext, ReadDecision, ReadRecordState, ReadRejectReason, ReadTrustPolicy, Runtime,
    VerifyMode,
};

impl ReadTrustPolicy {
    /// Resolve context-sensitive defaults once before scanning source records.
    pub fn resolve(&self, context: &ReadContext) -> Result<Self> {
        let verify = match self.verify {
            VerifyMode::Auto => VerifyMode::Raise,
            mode => mode,
        };
        if verify == VerifyMode::Disabled && self.trusted_writers_supplied {
            return Err(Error::InvalidConfig(
                "verify=False cannot be combined with trusted_writers".into(),
            ));
        }
        let inferred_unsigned = context.active
            && context.local_log
            && !context.detached
            && context.profile_sign == Some(false);
        let require_signature = self.require_signature.unwrap_or_else(|| {
            self.allow_unauthenticated
                .map_or(!inferred_unsigned, |allow| !allow)
        });
        let allow_unauthenticated = self.allow_unauthenticated.unwrap_or(!require_signature);
        if require_signature == allow_unauthenticated {
            return Err(Error::InvalidConfig(
                "require_signature and allow_unauthenticated must express one consistent policy"
                    .into(),
            ));
        }
        for did in &self.trusted_writers {
            validate_trusted_writer_did(did)?;
        }
        Ok(Self {
            verify,
            require_signature: Some(require_signature),
            allow_unauthenticated: Some(allow_unauthenticated),
            trusted_writers: self.trusted_writers.clone(),
            trusted_writers_supplied: self.trusted_writers_supplied,
            allow_unknown_writers: self.allow_unknown_writers,
        })
    }

    /// Apply this frozen policy to one parsed record state.
    #[must_use]
    pub fn evaluate(&self, record: &ReadRecordState, context: &ReadContext) -> ReadDecision {
        if !record.record_valid {
            return invalid_record_decision();
        }
        let mut reasons = Vec::new();
        let (row_hash_valid, chain_valid) = add_integrity_reasons(record, context, &mut reasons);
        let writer_authenticated = add_signature_reasons(self, record, &mut reasons);
        let writer_trusted = add_access_reasons(self, record, context, &mut reasons);
        let writer_authorized =
            writer_authenticated && writer_trusted && row_hash_valid && chain_valid;
        let accepted = self.accepts(&reasons);
        ReadDecision {
            accepted,
            reasons,
            writer_authenticated: writer_authenticated && self.verify != VerifyMode::Disabled,
            writer_authorized: writer_authorized && self.verify != VerifyMode::Disabled,
        }
    }

    fn accepts(&self, reasons: &[ReadRejectReason]) -> bool {
        match self.verify {
            VerifyMode::Disabled => reasons.iter().all(|reason| {
                matches!(
                    reason,
                    ReadRejectReason::RowHashInvalid
                        | ReadRejectReason::ChainInvalid
                        | ReadRejectReason::SignatureRequired
                        | ReadRejectReason::SignatureInvalid
                        | ReadRejectReason::WriterUntrusted
                )
            }),
            VerifyMode::Auto | VerifyMode::Raise | VerifyMode::Skip => {
                let allow_unauthenticated = self.allow_unauthenticated == Some(true);
                reasons.iter().all(|reason| {
                    allow_unauthenticated && *reason == ReadRejectReason::SignatureRequired
                })
            }
        }
    }
}

fn invalid_record_decision() -> ReadDecision {
    ReadDecision {
        accepted: false,
        reasons: vec![ReadRejectReason::RecordInvalid],
        writer_authenticated: false,
        writer_authorized: false,
    }
}

fn add_integrity_reasons(
    record: &ReadRecordState,
    context: &ReadContext,
    reasons: &mut Vec<ReadRejectReason>,
) -> (bool, bool) {
    let chain_required = read_chain_required(context);
    let row_hash_required = chain_required || record.signature_present;
    let row_hash_valid = !row_hash_required || (record.row_hash_present && record.row_hash_valid);
    if !row_hash_valid {
        push_once(reasons, ReadRejectReason::RowHashInvalid);
    }
    let chain_valid = !chain_required || record.chain_valid;
    if !chain_valid {
        push_once(reasons, ReadRejectReason::ChainInvalid);
    }
    (row_hash_valid, chain_valid)
}

fn add_signature_reasons(
    policy: &ReadTrustPolicy,
    record: &ReadRecordState,
    reasons: &mut Vec<ReadRejectReason>,
) -> bool {
    if !record.signature_present {
        if policy.require_signature == Some(true) {
            push_once(reasons, ReadRejectReason::SignatureRequired);
        }
        return false;
    }
    if !record.signature_valid {
        push_once(reasons, ReadRejectReason::SignatureInvalid);
    }
    record.signature_valid
}

fn add_access_reasons(
    policy: &ReadTrustPolicy,
    record: &ReadRecordState,
    context: &ReadContext,
    reasons: &mut Vec<ReadRejectReason>,
) -> bool {
    let writer_trusted = record
        .writer_did
        .as_ref()
        .is_some_and(|did| policy.trusted_writers.contains(did));
    if !writer_trusted && !policy.allow_unknown_writers {
        push_once(reasons, ReadRejectReason::WriterUntrusted);
    }
    if !record.aad_valid {
        push_once(reasons, ReadRejectReason::AadInvalid);
    }
    if context
        .required_group
        .as_ref()
        .is_some_and(|group| !record.recipient_groups.contains(group))
    {
        push_once(reasons, ReadRejectReason::NotARecipient);
    }
    writer_trusted
}

fn push_once(reasons: &mut Vec<ReadRejectReason>, reason: ReadRejectReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

pub(super) fn read_chain_required(context: &ReadContext) -> bool {
    !(context.active
        && context.local_log
        && !context.detached
        && context.profile_chain == Some(false))
}

fn validate_trusted_writer_did(did: &str) -> Result<()> {
    let Some(encoded) = did.strip_prefix("did:key:z") else {
        return Err(invalid_writer(did));
    };
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| invalid_writer(did))?;
    if decoded.len() != 34
        || decoded[..2] != [0xed, 0x01]
        || bs58::encode(&decoded).into_string() != encoded
    {
        return Err(invalid_writer(did));
    }
    Ok(())
}

fn invalid_writer(did: &str) -> Error {
    Error::InvalidConfig(format!(
        "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
    ))
}

impl Runtime {
    pub(super) fn default_read_policy(&self, verify: VerifyMode) -> Result<ReadTrustPolicy> {
        let mut trusted_writers = BTreeSet::from([self.device.did().to_owned()]);
        trusted_writers.extend(self.configured_trusted_writers());
        trusted_writers.extend(self.verified_publisher_writers()?);
        Ok(ReadTrustPolicy {
            verify,
            require_signature: None,
            allow_unauthenticated: None,
            trusted_writers,
            trusted_writers_supplied: false,
            allow_unknown_writers: false,
        })
    }

    fn configured_trusted_writers(&self) -> BTreeSet<String> {
        self.cfg.trust.writers.iter().cloned().collect()
    }

    fn verified_publisher_writers(&self) -> Result<BTreeSet<String>> {
        let path = self
            .keystore
            .join("trust")
            .join("verified_publishers.v1.json");
        if !self.storage.exists(&path) {
            return Ok(BTreeSet::new());
        }
        let bytes = self.storage.read_bytes(&path).map_err(Error::Io)?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid verified publisher record {}: {error}",
                path.display()
            ))
        })?;
        let publishers = document.get("publishers").unwrap_or(&document);
        let publishers = publishers.as_object().ok_or_else(|| {
            Error::InvalidConfig(format!(
                "invalid verified publisher record {}: publishers must be an object",
                path.display()
            ))
        })?;
        validate_publisher_metadata(publishers, &path)?;
        Ok(publishers.keys().cloned().collect())
    }
}

fn validate_publisher_metadata(
    publishers: &serde_json::Map<String, Value>,
    path: &std::path::Path,
) -> Result<()> {
    for (did, metadata) in publishers {
        if !metadata.is_object() {
            return Err(Error::InvalidConfig(format!(
                "invalid verified publisher record {}: {did:?} metadata must be an object",
                path.display()
            )));
        }
    }
    Ok(())
}
