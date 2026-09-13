use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::canonical::canonical_bytes;
use crate::sealed_object::{extract_group_blocks, verify_sealed, GroupBlock, ENVELOPE_RESERVED};
use crate::{Error, Result};

use super::policy::{string_field, validate_marker};
use super::{invalid, validate_group, validate_name, GOVERNANCE_GROUP};

/// An integrity-verified governed envelope with its exact transport bytes.
///
/// Verification authenticates the writer and the carried binding. Applications
/// apply their authority and permitted-use rules when admitting the contract.
#[derive(Clone)]
pub struct GovernedObject {
    wire: String,
    envelope: Map<String, Value>,
    pub(super) groups: BTreeMap<String, GroupBlock>,
    pub(super) marker: Map<String, Value>,
}

impl GovernedObject {
    /// Read and integrity-verify an exact publication from a byte stream.
    pub fn read(mut source: impl std::io::Read) -> Result<Self> {
        let mut wire = String::new();
        source.read_to_string(&mut wire)?;
        Self::parse(&wire)
    }
    /// Write the retained signed bytes without resealing or serialization.
    pub fn write(&self, mut destination: impl std::io::Write) -> Result<()> {
        destination.write_all(self.forward())?;
        Ok(())
    }
    /// Exact signed bytes for the application's transport.
    pub fn forward(&self) -> &[u8] {
        self.wire.as_bytes()
    }
    /// Inspect authenticated envelope metadata and encrypted group blocks.
    pub fn inspect(&self) -> &Map<String, Value> {
        self.envelope()
    }
    /// Verify a standalone object or signed emitted row and its governance AAD.
    /// The source is retained unchanged for subsequent forwarding.
    pub fn parse(wire: &str) -> Result<Self> {
        let value = parse_json(wire)?;
        let env = value
            .as_object()
            .ok_or_else(|| invalid("envelope must be a JSON object"))?;
        for key in [
            "device_identity",
            "timestamp",
            "event_id",
            "event_type",
            "row_hash",
            "signature",
        ] {
            string_field(env, key)?;
        }
        validate_name(string_field(env, "event_type")?)?;
        for key in ["prev_hash", "level"] {
            if !env.get(key).is_some_and(Value::is_string) {
                return Err(invalid(format!("required string {key:?}")));
            }
        }
        let sequence = env
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("sequence requires an unsigned integer"))?;
        let groups = extract_group_blocks(env)?;
        validate_public_shape(env, &groups)?;
        validate_groups(env, &groups)?;
        let valid = verify_sealed(env, &groups);
        if !valid.signature || !valid.row_hash {
            let mut failed_checks = Vec::new();
            if !valid.signature {
                failed_checks.push("signature".into());
            }
            if !valid.row_hash {
                failed_checks.push("row_hash".into());
            }
            return Err(Error::SealedObjectVerify {
                failed_checks,
                sequence,
                event_type: string_field(env, "event_type")?.to_owned(),
            });
        }
        let aad = string_field(env, "tn_aad")?;
        let aad_value = parse_json(aad)?;
        if canonical_bytes(&aad_value)? != aad.as_bytes() {
            return Err(invalid("tn_aad requires canonical JSON bytes"));
        }
        let aad_groups = aad_value
            .as_object()
            .ok_or_else(|| invalid("tn_aad requires a group map"))?;
        if aad_groups.len() != groups.len() || !groups.keys().all(|g| aad_groups.contains_key(g)) {
            return Err(invalid("tn_aad must bind every encrypted group"));
        }
        let marker = aad_groups[GOVERNANCE_GROUP]
            .as_object()
            .ok_or_else(|| invalid("governance marker requires an object"))?;
        if marker.len() != 2 {
            return Err(invalid("governance marker requires governed_by and policy"));
        }
        validate_marker(
            string_field(marker, "governed_by")?,
            string_field(marker, "policy")?,
        )?;
        if !aad_groups
            .values()
            .all(|value| value.as_object() == Some(marker))
        {
            return Err(invalid(
                "all encrypted groups must carry the same governance marker",
            ));
        }
        Ok(Self {
            wire: wire.to_owned(),
            envelope: env.clone(),
            groups,
            marker: marker.clone(),
        })
    }

    /// Exact verified input, ready for transport or retention as exhaust.
    pub fn wire(&self) -> &str {
        &self.wire
    }
    /// Immutable envelope, including every opened or unopened group's ciphertext.
    pub fn envelope(&self) -> &Map<String, Value> {
        &self.envelope
    }
    /// Signed content identity of this object.
    pub fn id(&self) -> &str {
        self.verified_header("row_hash")
    }
    /// Object/event type.
    pub fn object_type(&self) -> &str {
        self.verified_header("event_type")
    }
    /// Writer whose signature was verified.
    pub fn writer(&self) -> &str {
        self.verified_header("device_identity")
    }

    fn verified_header(&self, name: &str) -> &str {
        // parse establishes these strings; callers cannot mutate the envelope.
        self.envelope[name]
            .as_str()
            .expect("verified immutable header")
    }
    /// Encrypted groups present in the object, in sorted order.
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(String::as_str).collect()
    }
}

fn validate_groups(env: &Map<String, Value>, groups: &BTreeMap<String, GroupBlock>) -> Result<()> {
    if !groups.contains_key(GOVERNANCE_GROUP) {
        return Err(invalid("required encrypted tn.agents group"));
    }
    for name in groups.keys() {
        validate_group(name)?;
        let block = env[name]
            .as_object()
            .ok_or_else(|| invalid("group requires an object"))?;
        if block.len() != 2 || !block.get("field_hashes").is_some_and(Value::is_object) {
            return Err(invalid("group requires ciphertext and field_hashes"));
        }
        for (field, token) in &groups[name].field_hashes {
            super::validate_field(field)?;
            let digest = token
                .strip_prefix(crate::indexing::INDEX_TOKEN_PREFIX)
                .ok_or_else(|| invalid("field hash requires an HMAC-SHA256 v1 token"))?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("field hash requires a lowercase SHA-256 digest"));
            }
        }
    }
    Ok(())
}

// The TN hash preimage retains the established wire encoding. The governed
// interface fixes public types and delimiters so its admitted interpretation
// is unique; typed business values belong in encrypted group JSON.
fn validate_public_shape(
    env: &Map<String, Value>,
    groups: &BTreeMap<String, GroupBlock>,
) -> Result<()> {
    for key in ENVELOPE_RESERVED {
        if env
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains('\0'))
        {
            return Err(invalid("envelope strings must exclude NUL delimiters"));
        }
    }
    for (key, value) in env {
        if ENVELOPE_RESERVED.contains(&key.as_str()) || groups.contains_key(key) {
            continue;
        }
        if key == "tn_sealed" {
            if value.as_u64() != Some(1) {
                return Err(invalid("tn_sealed requires integer 1"));
            }
        } else {
            validate_name(key)?;
            if value.as_str().is_none_or(|s| s.contains('\0')) {
                return Err(invalid("public metadata requires NUL-free strings; assign typed data to encrypted groups"));
            }
        }
    }
    Ok(())
}

impl fmt::Debug for GovernedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GovernedObject")
            .field("id", &self.id())
            .field("object_type", &self.object_type())
            .field("groups", &self.group_names())
            .finish()
    }
}

impl fmt::Display for GovernedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire())
    }
}

// A single interpretation of every JSON object, including AAD and decrypted
// policy values, is part of admission. serde_json::Value alone keeps the last
// duplicate member; this visitor requires each name to occur once.
pub(super) fn parse_json(source: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|e| invalid(format!("invalid JSON: {e}")))?;
    deserializer
        .end()
        .map_err(|e| invalid(format!("invalid JSON: {e}")))?;
    Ok(value.0)
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = a.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
                    }
                    values.insert(key, a.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
