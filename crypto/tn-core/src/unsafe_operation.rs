//! Shared value contract for explicitly weakened security operations.
//!
//! Language-facing SDKs use these types to produce the same structured warning
//! and `tn.security.unsafe_operation` administrative payload. This module owns
//! only the value and wire contract; warning delivery and best-effort audit
//! emission belong to the calling SDK/runtime layer.

use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Operation whose normal security guarantees were explicitly weakened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeOperation {
    /// Read one or more existing log sources.
    Read,
    /// Watch a log source for new entries.
    Watch,
    /// Register a raw JWE recipient without a verified key binding.
    JweAddRecipient,
    /// Deliver a HIBE reader grant through an unsafe compatibility path.
    HibeGrant,
    /// Import a legacy package without current identity/binding guarantees.
    LegacyPackageImport,
}

/// Individual guarantee relaxed for an [`UnsafeOperation`].
///
/// Variants are declared in their canonical wire-string order so derived
/// ordering produces the required sorted relaxation array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeRelaxation {
    /// Accept a legacy package whose claimed and actual signers differ.
    LegacySignerMismatch,
    /// Deliver a bearer artifact without recipient sealing.
    PlaintextBearerDelivery,
    /// Permit an unsigned record or package where signing is normally required.
    SignatureNotRequired,
    /// Permit records that are not authenticated.
    UnauthenticatedAllowed,
    /// Permit a writer that is not in the receiver's trust policy.
    UnknownWriterAllowed,
    /// Register or use a public key without a verified DID binding.
    UnverifiedKeyBinding,
    /// Disable cryptographic verification.
    VerificationDisabled,
}

/// Canonical five-field payload shared by warnings and admin audit events.
///
/// Serialization always emits fields in lexical order and relaxations in
/// sorted, de-duplicated order. Deserialization rejects additional fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeOperationNotice {
    /// Optional digest of the artifact involved in the unsafe operation.
    pub artifact_digest: Option<String>,
    /// Optional affected encryption group.
    pub group: Option<String>,
    /// Operation whose guarantees were weakened.
    pub operation: UnsafeOperation,
    /// Sorted, de-duplicated guarantees that were relaxed.
    pub relaxations: Vec<UnsafeRelaxation>,
    /// Optional DID of the principal affected by the operation.
    pub subject_did: Option<String>,
}

struct RequiredNullableString(Option<String>);

impl<'de> Deserialize<'de> for RequiredNullableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NullableStringVisitor;

        impl<'de> serde::de::Visitor<'de> for NullableStringVisitor {
            type Value = RequiredNullableString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string or null")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(RequiredNullableString(None))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(RequiredNullableString(None))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(RequiredNullableString(Some(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(RequiredNullableString(Some(value)))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer).map(|value| RequiredNullableString(Some(value)))
            }
        }

        deserializer.deserialize_any(NullableStringVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsafeOperationNoticeWire {
    artifact_digest: RequiredNullableString,
    group: RequiredNullableString,
    operation: UnsafeOperation,
    #[serde(deserialize_with = "deserialize_relaxations")]
    relaxations: Vec<UnsafeRelaxation>,
    subject_did: RequiredNullableString,
}

impl UnsafeOperationNotice {
    /// Construct a notice with no optional context fields.
    pub fn new(
        operation: UnsafeOperation,
        relaxations: impl IntoIterator<Item = UnsafeRelaxation>,
    ) -> Self {
        let mut relaxations: Vec<_> = relaxations.into_iter().collect();
        normalize_relaxations(&mut relaxations);
        Self {
            artifact_digest: None,
            group: None,
            operation,
            relaxations,
            subject_did: None,
        }
    }
}

impl Serialize for UnsafeOperationNotice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut relaxations = self.relaxations.clone();
        normalize_relaxations(&mut relaxations);

        let mut state = serializer.serialize_struct("UnsafeOperationNotice", 5)?;
        state.serialize_field("artifact_digest", &self.artifact_digest)?;
        state.serialize_field("group", &self.group)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("relaxations", &relaxations)?;
        state.serialize_field("subject_did", &self.subject_did)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for UnsafeOperationNotice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UnsafeOperationNoticeWire::deserialize(deserializer)?;
        Ok(Self {
            artifact_digest: wire.artifact_digest.0,
            group: wire.group.0,
            operation: wire.operation,
            relaxations: wire.relaxations,
            subject_did: wire.subject_did.0,
        })
    }
}

fn deserialize_relaxations<'de, D>(deserializer: D) -> Result<Vec<UnsafeRelaxation>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut relaxations = Vec::<UnsafeRelaxation>::deserialize(deserializer)?;
    normalize_relaxations(&mut relaxations);
    Ok(relaxations)
}

fn normalize_relaxations(relaxations: &mut Vec<UnsafeRelaxation>) {
    relaxations.sort_unstable();
    relaxations.dedup();
}
