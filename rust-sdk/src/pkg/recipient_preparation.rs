use std::fs;
use std::path::Path;
use std::time::Duration;

use super::{BundleForRecipientOptions, BundleForRecipientResult, CompiledPackage, Package};
use crate::enrollment::AcceptedOffer;
use crate::{Error, Result};
use tn_core::jwe_binding::VerifiedJweRecipient;

const DEFAULT_ACTIVATION_TTL: Duration = Duration::from_secs(600);

/// Inputs for [`Package::prepare_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareRecipientOptions {
    /// Optional group subset. Defaults to all non-internal groups.
    pub groups: Option<Vec<String>>,
    /// Atomically accepted JWE offers available as verified enrollment evidence.
    pub accepted_offers: Vec<AcceptedOffer>,
    /// Safe normalized JWE bindings from DID resolution or fingerprint pinning.
    pub verified_bindings: Vec<VerifiedJweRecipient>,
    /// Validity window for each signed JWE activation response.
    pub activation_ttl: Duration,
}

impl Default for PrepareRecipientOptions {
    fn default() -> Self {
        Self {
            groups: None,
            accepted_offers: Vec::new(),
            verified_bindings: Vec::new(),
            activation_ttl: DEFAULT_ACTIVATION_TTL,
        }
    }
}

/// One public-only JWE activation artifact produced for a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweActivationResult {
    /// JWE group named by the signed enrollment response.
    pub group: String,
    /// Exact authenticated binding acknowledged by the response.
    pub binding_digest: String,
    /// Correlation digest carried by the signed enrollment response.
    pub activation_reference_digest: String,
    /// Digest of the reader's admitted public X25519 key.
    pub x25519_public_key_sha256: String,
    /// Signed enrollment response package containing no reader private key.
    pub package: CompiledPackage,
}

/// Reader-local public JWE key information; private bytes never leave storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweReaderKeyInfo {
    /// Reader DID owning the local key.
    pub reader_did: String,
    /// JWE group the key is stored under.
    pub group: String,
    /// Raw public X25519 key.
    pub public_key: [u8; 32],
    /// Digest of `public_key`.
    pub public_key_sha256: String,
}

/// Explicit reader approval for a direct public-only activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveJweActivationOptions {
    /// Publisher DID whose signed response may be installed.
    pub publisher_did: String,
    /// Publisher ceremony scope.
    pub ceremony_id: String,
    /// JWE group scope.
    pub group: String,
    /// Exact normalized binding digest approved out of band.
    pub binding_digest: String,
    /// Expected digest of this reader's local public key.
    pub x25519_public_key_sha256: String,
    /// Maximum lifetime of this approval.
    pub ttl: Duration,
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
    binding: VerifiedJweRecipient,
    activation_reference_digest: String,
}

impl Package<'_> {
    /// Prepare BTN/HIBE reader kits and public-only JWE activations.
    ///
    /// BTN/HIBE bearer kits are always recipient-sealed to the complete
    /// Ed25519 `did:key`. JWE private keys remain reader-local. Each requested
    /// JWE group requires exactly one atomically accepted offer or
    /// authenticated direct binding for the recipient's public X25519 key.
    /// The resulting artifact is a signed enrollment response that the reader
    /// must approve and absorb.
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
        if !plan.jwe_groups.is_empty() && options.activation_ttl.is_zero() {
            return Err(Error::InvalidArgument(
                "JWE activation ttl must be greater than zero".into(),
            ));
        }
        let evidence = resolve_activation_evidence(
            self.tn,
            &recipient_did,
            &plan.jwe_groups,
            &options.accepted_offers,
            &options.verified_bindings,
        )?;
        fs::create_dir_all(out_dir.as_ref())?;
        let kit_bundle =
            self.prepare_kit_bundle(&recipient_did, out_dir.as_ref(), &plan.kit_groups)?;
        let jwe_activations =
            self.write_jwe_activations(out_dir.as_ref(), options.activation_ttl, evidence)?;
        Ok(PrepareRecipientResult {
            recipient_did,
            requested_groups: plan.requested_groups,
            kit_bundle,
            jwe_activations,
        })
    }

    /// Create or reuse a reader-local JWE key and return only its public half.
    pub fn prepare_jwe_reader_key(&self, group: &str) -> Result<JweReaderKeyInfo> {
        require_jwe_group(self, group)?;
        let public_key = crate::enrollment::ensure_reader_mykey(self.tn, group)?;
        Ok(reader_key_info(self, group, public_key))
    }

    /// Create or reuse the X25519 key deterministically bound to this
    /// Ed25519 `did:key` for authenticated DID-document enrollment.
    ///
    /// # Security
    ///
    /// Unlike [`Self::prepare_jwe_reader_key`], this opt-in key is shared by
    /// every group that uses it and by recipient-sealed package delivery. It
    /// therefore does not provide independent per-group key separation or
    /// rotation. Use it only when a writer must verify the standard
    /// `did:key` keyAgreement expansion; prefer the random per-group method
    /// for fingerprint, challenge, and other authenticated binding routes.
    pub fn prepare_jwe_did_key_agreement_key(&self, group: &str) -> Result<JweReaderKeyInfo> {
        require_jwe_group(self, group)?;
        log::warn!(
            target: "tn.security",
            "using identity-derived JWE keyAgreement material for group {group:?}; the key is shared across groups and recipient-sealed package delivery"
        );
        let public_key = crate::enrollment::ensure_did_key_reader_mykey(self.tn, group)?;
        Ok(reader_key_info(self, group, public_key))
    }

    /// Approve one exact direct activation before its signed package is absorbed.
    pub fn approve_jwe_activation(&self, options: ApproveJweActivationOptions) -> Result<()> {
        require_jwe_group(self, &options.group)?;
        crate::enrollment::approve_jwe_activation(self.tn, &options)
    }

    fn prepare_kit_bundle(
        &self,
        recipient_did: &str,
        out_dir: &Path,
        groups: &[String],
    ) -> Result<Option<BundleForRecipientResult>> {
        if groups.is_empty() {
            return Ok(None);
        }
        self.bundle_for_recipient(
            recipient_did,
            out_dir.join("reader-bundle.tnpkg"),
            BundleForRecipientOptions {
                groups: Some(groups.to_vec()),
                seal_for_recipient: true,
            },
        )
        .map(Some)
    }

    fn write_jwe_activations(
        &self,
        out_dir: &Path,
        ttl: Duration,
        evidence: Vec<ActivationEvidence>,
    ) -> Result<Vec<JweActivationResult>> {
        evidence
            .into_iter()
            .map(|evidence| self.write_jwe_activation(out_dir, ttl, evidence))
            .collect()
    }

    fn write_jwe_activation(
        &self,
        out_dir: &Path,
        ttl: Duration,
        evidence: ActivationEvidence,
    ) -> Result<JweActivationResult> {
        crate::admin::register_jwe_binding_for_tn(self.tn, &evidence.group, &evidence.binding)?;
        let package = self.compile_jwe_activation_v1(
            &evidence.binding,
            &evidence.activation_reference_digest,
            out_dir.join(format!("{}.jwe-enrolment.tnpkg", evidence.group)),
            ttl,
        )?;
        Ok(JweActivationResult {
            group: evidence.group,
            binding_digest: evidence.binding.binding_digest,
            activation_reference_digest: evidence.activation_reference_digest,
            x25519_public_key_sha256: evidence.binding.public_key_sha256,
            package,
        })
    }
}

fn reader_key_info(package: &Package<'_>, group: &str, public_key: [u8; 32]) -> JweReaderKeyInfo {
    JweReaderKeyInfo {
        reader_did: package.tn.did().to_string(),
        group: group.to_string(),
        public_key,
        public_key_sha256: crate::enrollment::sha256_tagged(&public_key),
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
    verified_bindings: &[VerifiedJweRecipient],
) -> Result<Vec<ActivationEvidence>> {
    groups
        .iter()
        .map(|group| {
            let binding =
                binding_for_group(accepted_offers, verified_bindings, recipient_did, group)?;
            let activation_reference_digest = binding.activation_reference_digest().to_string();
            crate::admin::validate_jwe_binding_for_tn(tn, group, &binding)?;
            Ok(ActivationEvidence {
                group: group.clone(),
                binding,
                activation_reference_digest,
            })
        })
        .collect()
}

fn binding_for_group(
    accepted_offers: &[AcceptedOffer],
    verified_bindings: &[VerifiedJweRecipient],
    reader_did: &str,
    group: &str,
) -> Result<VerifiedJweRecipient> {
    let offers = accepted_offers.iter().filter(|offer| {
        offer.binding.principal.did == reader_did && offer.binding.principal.group == group
    });
    let direct = verified_bindings
        .iter()
        .filter(|binding| binding.reader_did == reader_did && binding.group == group);
    let mut sources: Vec<VerifiedJweRecipient> = offers
        .map(|offer| {
            VerifiedJweRecipient::from_accepted_offer(offer).map_err(crate::enrollment::trust_err)
        })
        .collect::<Result<_>>()?;
    sources.extend(direct.cloned());
    if sources.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "prepare_recipient requires exactly one verified JWE binding source for reader {reader_did:?} in group {group:?}"
        )));
    }
    if sources.len() > 1 {
        return Err(Error::InvalidArgument(format!(
            "prepare_recipient received multiple verified JWE binding sources for reader {reader_did:?} in group {group:?}"
        )));
    }
    Ok(sources.remove(0))
}

fn require_jwe_group(package: &Package<'_>, group: &str) -> Result<()> {
    let plan = package
        .tn
        .runtime()
        .plan_recipient_preparation(Some(&[group]))?;
    if plan.jwe_groups == [group] {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "group {group:?} is not configured for JWE"
        )))
    }
}
