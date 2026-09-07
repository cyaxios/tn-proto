use std::collections::BTreeMap;
use std::sync::Arc;

use hmac::Hmac;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::canonical::canonical_bytes;
use crate::chain::{compute_row_hash, GroupInput, RowHashInput};
use crate::cipher::GroupCipher;
use crate::envelope::{build_envelope, EnvelopeInput, GroupPayload};
use crate::indexing::{build_hmac_template, index_token_with_template};
use crate::{DeviceKey, Result};

use super::{invalid, validate_group, validate_name, Governance, GovernedObject, GOVERNANCE_GROUP};

/// Data and its contract before encryption. Group assignment is explicit.
#[derive(Debug, Clone)]
pub struct GovernedDraft {
    pub(super) object_type: String,
    pub(super) governance: Governance,
    groups: BTreeMap<String, Map<String, Value>>,
}

impl GovernedDraft {
    /// Create a draft with its required use contract.
    pub fn new(object_type: &str, governance: Governance) -> Result<Self> {
        validate_name(object_type)?;
        Ok(Self {
            object_type: object_type.to_owned(),
            governance,
            groups: BTreeMap::new(),
        })
    }

    /// Assign a JSON object of fields to an encrypted business group.
    /// `tn.agents` is populated from the contract by the writer.
    pub fn group(mut self, name: &str, fields: impl Serialize) -> Result<Self> {
        validate_group(name)?;
        if name == GOVERNANCE_GROUP || self.groups.contains_key(name) {
            return Err(invalid(format!(
                "group {name:?} already supplied or reserved for governance"
            )));
        }
        let value = serde_json::to_value(fields)?;
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("group fields must be a JSON object"))?;
        for field in fields.keys() {
            super::validate_field(field)?;
        }
        self.groups.insert(name.to_owned(), fields.clone());
        Ok(self)
    }

    /// Contract selected for this draft.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
}

struct GroupSealer {
    cipher: Arc<dyn GroupCipher>,
    index: Hmac<Sha256>,
}

/// Seals governed objects using the writer identity and group cipher material.
///
/// No logging configuration or filesystem is required. Each call returns an
/// independently signed object; the caller chooses its transport and storage.
pub struct GovernedWriter<'a> {
    device: &'a DeviceKey,
    groups: BTreeMap<String, GroupSealer>,
}

impl<'a> GovernedWriter<'a> {
    /// Use an existing signing identity.
    pub fn new(device: &'a DeviceKey) -> Self {
        Self {
            device,
            groups: BTreeMap::new(),
        }
    }

    /// Attach a group's encryption cipher and its separate derived index key.
    pub fn with_group(
        self,
        name: &str,
        cipher: Arc<dyn GroupCipher>,
        index_key: &[u8],
    ) -> Result<Self> {
        self.with_material(name, cipher, build_hmac_template(index_key)?)
    }

    pub(crate) fn with_material(
        mut self,
        name: &str,
        cipher: Arc<dyn GroupCipher>,
        index: Hmac<Sha256>,
    ) -> Result<Self> {
        validate_group(name)?;
        if self.groups.contains_key(name) {
            return Err(invalid(format!("duplicate writer group {name:?}")));
        }
        self.groups
            .insert(name.to_owned(), GroupSealer { cipher, index });
        Ok(self)
    }

    /// Encrypt data and governance, authenticate their common marker, and sign.
    pub fn seal(&self, mut draft: GovernedDraft) -> Result<GovernedObject> {
        draft
            .groups
            .insert(GOVERNANCE_GROUP.to_owned(), draft.governance.fields.clone());
        for name in draft.groups.keys() {
            if !self.groups.contains_key(name) {
                return Err(invalid(format!(
                    "writer requires cipher material for {name:?}"
                )));
            }
        }
        let marker = draft.governance.marker();
        let aad = canonical_bytes(&marker)?;
        let mut inputs = BTreeMap::new();
        let mut payloads = BTreeMap::new();
        let mut markers = Map::new();
        for (name, fields) in draft.groups {
            let group = &self.groups[&name];
            let mut field_hashes = BTreeMap::new();
            for (field, value) in &fields {
                field_hashes.insert(
                    field.clone(),
                    index_token_with_template(&group.index, field, value)?,
                );
            }
            let ciphertext = group
                .cipher
                .encrypt_with_aad(&canonical_bytes(&Value::Object(fields))?, &aad)?;
            inputs.insert(
                name.clone(),
                GroupInput {
                    ciphertext: ciphertext.clone(),
                    field_hashes: field_hashes.clone(),
                },
            );
            payloads.insert(
                name.clone(),
                serde_json::to_string(&GroupPayload {
                    ciphertext,
                    field_hashes,
                })?,
            );
            markers.insert(name, marker.clone());
        }
        let mut public = Map::new();
        public.insert("tn_sealed".to_owned(), Value::from(1));
        public.insert(
            "tn_aad".to_owned(),
            Value::String(
                String::from_utf8(canonical_bytes(&Value::Object(markers))?)
                    .map_err(|_| invalid("canonical AAD must be UTF-8"))?,
            ),
        );
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| invalid("timestamp formatting failed"))?;
        let event_id = uuid::Uuid::new_v4().to_string();
        let public_hash = public.clone().into_iter().collect();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type: &draft.object_type,
            level: "",
            prev_hash: "",
            public_fields: &public_hash,
            groups: &inputs,
        });
        let signature = crate::signing::signature_b64(&self.device.sign(row_hash.as_bytes()));
        let mut wire = build_envelope(EnvelopeInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type: &draft.object_type,
            level: "",
            sequence: 0,
            prev_hash: "",
            row_hash: &row_hash,
            signature_b64: &signature,
            public_fields: public,
            group_payloads: payloads,
        })?;
        if wire.ends_with('\n') {
            wire.pop();
        }
        GovernedObject::parse(&wire)
    }
}
