use std::fs;
use std::path::Path;
use std::time::Duration;

use super::{BundleForRecipientOptions, BundleForRecipientResult, CompiledPackage, Package};
use crate::enrollment::{AcceptedOffer, CompileEnrolmentOptionsV1};
use crate::{Error, Result};

const DEFAULT_ACTIVATION_TTL: Duration = Duration::from_secs(600);

/// Inputs for [`Package::prepare_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareRecipientOptions {
    /// Optional group subset. Defaults to all non-internal groups.
    pub groups: Option<Vec<String>>,
    /// Seal the BTN/HIBE kit bundle body to the recipient DID.
    pub seal_kit_bundle_for_recipient: bool,
    /// Atomically accepted JWE offers available as verified enrollment evidence.
    pub accepted_offers: Vec<AcceptedOffer>,
    /// Validity window for each signed JWE activation response.
    pub activation_ttl: Duration,
}

impl Default for PrepareRecipientOptions {
    fn default() -> Self {
        Self {
            groups: None,
            seal_kit_bundle_for_recipient: false,
            accepted_offers: Vec::new(),
            activation_ttl: DEFAULT_ACTIVATION_TTL,
        }
    }
}

/// One public-only JWE activation artifact produced for a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweActivationResult {
    /// JWE group activated by the signed enrollment response.
    pub group: String,
    /// Signed enrollment response package containing no reader private key.
    pub package: CompiledPackage,
}

/// Typed outputs from public-only recipient preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareRecipientResult {
    /// Recipient DID all outputs are addressed to.
    pub recipient_did: String,
    /// Deduplicated requested groups in caller order.
    pub requested_groups: Vec<String>,
    /// BTN/HIBE kit bundle, absent for a JWE-only request.
    pub kit_bundle: Option<BundleForRecipientResult>,
    /// One signed, public-only activation package per requested JWE group.
    pub jwe_activations: Vec<JweActivationResult>,
}

struct ActivationEvidence {
    group: String,
    accepted_offer: AcceptedOffer,
}

impl Package<'_> {
    /// Prepare BTN/HIBE reader kits and public-only JWE activations.
    ///
    /// JWE private keys remain reader-local. Each requested JWE group requires
    /// an atomically accepted offer that binds the recipient DID to its public
    /// X25519 key; the resulting artifact is a signed enrollment response.
    pub fn prepare_recipient(
        &self,
        recipient_did: impl Into<String>,
        out_dir: impl AsRef<Path>,
        options: PrepareRecipientOptions,
    ) -> Result<PrepareRecipientResult> {
        let recipient_did = require_recipient_did(recipient_did.into())?;
        let group_refs = group_refs(options.groups.as_ref());
        let plan = self
            .tn
            .runtime()
            .plan_recipient_preparation(group_refs.as_deref())?;
        let evidence = resolve_activation_evidence(
            self.tn,
            &recipient_did,
            &plan.jwe_groups,
            &options.accepted_offers,
        )?;
        fs::create_dir_all(out_dir.as_ref())?;
        let kit_bundle = self.prepare_kit_bundle(
            &recipient_did,
            out_dir.as_ref(),
            &plan.kit_groups,
            options.seal_kit_bundle_for_recipient,
        )?;
        let jwe_activations = self.write_jwe_activations(
            &recipient_did,
            out_dir.as_ref(),
            options.activation_ttl,
            evidence,
        )?;
        Ok(PrepareRecipientResult {
            recipient_did,
            requested_groups: plan.requested_groups,
            kit_bundle,
            jwe_activations,
        })
    }

    fn prepare_kit_bundle(
        &self,
        recipient_did: &str,
        out_dir: &Path,
        groups: &[String],
        seal_for_recipient: bool,
    ) -> Result<Option<BundleForRecipientResult>> {
        if groups.is_empty() {
            return Ok(None);
        }
        self.bundle_for_recipient(
            recipient_did,
            out_dir.join("reader-bundle.tnpkg"),
            BundleForRecipientOptions {
                groups: Some(groups.to_vec()),
                seal_for_recipient,
            },
        )
        .map(Some)
    }

    fn write_jwe_activations(
        &self,
        recipient_did: &str,
        out_dir: &Path,
        ttl: Duration,
        evidence: Vec<ActivationEvidence>,
    ) -> Result<Vec<JweActivationResult>> {
        evidence
            .into_iter()
            .map(|evidence| self.write_jwe_activation(recipient_did, out_dir, ttl, evidence))
            .collect()
    }

    fn write_jwe_activation(
        &self,
        recipient_did: &str,
        out_dir: &Path,
        ttl: Duration,
        evidence: ActivationEvidence,
    ) -> Result<JweActivationResult> {
        crate::admin::register_jwe_offer_for_tn(
            self.tn,
            &evidence.group,
            &evidence.accepted_offer,
        )?;
        let package = self.compile_enrolment_v1(CompileEnrolmentOptionsV1 {
            group: evidence.group.clone(),
            reader_did: recipient_did.to_string(),
            out_path: out_dir.join(format!("{}.jwe-enrolment.tnpkg", evidence.group)),
            accepted_offer: evidence.accepted_offer,
            ttl,
        })?;
        Ok(JweActivationResult {
            group: evidence.group,
            package,
        })
    }
}

fn require_recipient_did(recipient_did: String) -> Result<String> {
    if recipient_did.trim().is_empty() {
        Err(Error::InvalidArgument(
            "recipient DID must not be empty".into(),
        ))
    } else {
        Ok(recipient_did)
    }
}

fn group_refs(groups: Option<&Vec<String>>) -> Option<Vec<&str>> {
    groups.map(|groups| groups.iter().map(String::as_str).collect())
}

fn resolve_activation_evidence(
    tn: &crate::Tn,
    recipient_did: &str,
    groups: &[String],
    accepted_offers: &[AcceptedOffer],
) -> Result<Vec<ActivationEvidence>> {
    groups
        .iter()
        .map(|group| {
            let accepted_offer = crate::enrollment::accepted_offer_for_preparation(
                accepted_offers,
                recipient_did,
                group,
            )?
            .clone();
            crate::admin::validate_jwe_offer_for_tn(tn, group, &accepted_offer)?;
            Ok(ActivationEvidence {
                group: group.clone(),
                accepted_offer,
            })
        })
        .collect()
}
