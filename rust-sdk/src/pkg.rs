//! `.tnpkg` package export and absorb helpers.
//!
//! Packages are the portable handoff format for admin snapshots, reader kits,
//! and ceremony bootstrap material. Access them from a [`Tn`](crate::Tn)
//! handle:
//!
//! ```no_run
//! use tn_proto::{Result, Tn};
//!
//! # fn main() -> Result<()> {
//! let tn = Tn::init("tn.yaml")?;
//! let written = tn.pkg().export_admin_snapshot("admin-snapshot.tnpkg")?;
//!
//! let peer = Tn::init("peer/tn.yaml")?;
//! let receipt = peer.pkg().absorb_path(&written)?;
//! assert_ne!(receipt.legacy_status, "rejected");
//! # Ok(())
//! # }
//! ```
//!
//! Secret-bearing exports require an explicit acknowledgement at the call site:
//!
//! ```no_run
//! use tn_proto::{Result, SecretExportConsent, Tn};
//!
//! # fn main() -> Result<()> {
//! let tn = Tn::init("tn.yaml")?;
//! tn.pkg().export_project_seed(
//!     "project-seed.tnpkg",
//!     None,
//!     SecretExportConsent::acknowledge(),
//! )?;
//! # Ok(())
//! # }
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::tn::Tn;
use crate::{Error, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

mod recipient_preparation;
pub use recipient_preparation::{
    JweActivationResult, PrepareRecipientOptions, PrepareRecipientResult,
};

/// Runtime package namespace for a [`Tn`] handle.
pub struct Package<'a> {
    tn: &'a Tn,
}

impl<'a> Package<'a> {
    pub(crate) fn new(tn: &'a Tn) -> Self {
        Self { tn }
    }

    /// Export an admin-log snapshot `.tnpkg`.
    ///
    /// This is the safest first package kind: it contains governance/admin
    /// envelopes, not raw private key material.
    ///
    /// Use this to synchronize admin state between runtimes before reaching
    /// for key-bearing bundles.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be written.
    pub fn export_admin_snapshot(&self, out_path: impl AsRef<Path>) -> Result<PathBuf> {
        self.export_with(
            out_path,
            ExportOptions {
                kind: ManifestKind::AdminLogSnapshot,
                ..ExportOptions::default()
            },
        )
    }

    /// Export existing reader kits from this runtime's keystore as a
    /// `kit_bundle` `.tnpkg`.
    ///
    /// This packages kits that already exist locally. The `to_did` value is
    /// manifest recipient metadata; it does not mint a new recipient kit.
    /// Use [`crate::Admin::add_recipient`] first when you need to mint a new
    /// reader kit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the bundle cannot be written, the requested
    /// group subset has no matching kits, or the local keystore has no kits.
    pub fn export_kit_bundle(
        &self,
        out_path: impl AsRef<Path>,
        groups: Option<Vec<String>>,
        to_did: Option<String>,
    ) -> Result<PathBuf> {
        self.export_with(
            out_path,
            ExportOptions {
                kind: ManifestKind::KitBundle,
                to_did,
                groups,
                ..ExportOptions::default()
            },
        )
    }

    /// Mint reader kits for one recipient and export them as a `kit_bundle`.
    ///
    /// Unlike [`Package::export_kit_bundle`], this helper creates fresh kits
    /// for `recipient_did` first and packages those kits from a temporary
    /// directory. That avoids accidentally shipping the publisher's own
    /// self-kit.
    ///
    /// Admin-log state is intentionally not folded into this package. Export
    /// and absorb an [`Package::export_admin_snapshot`] artifact separately
    /// when the recipient also needs governance state.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the recipient DID is empty, a requested group
    /// is unknown, no non-internal groups are available, minting fails, or the
    /// package cannot be written.
    pub fn bundle_for_recipient(
        &self,
        recipient_did: impl Into<String>,
        out_path: impl AsRef<Path>,
        options: BundleForRecipientOptions,
    ) -> Result<BundleForRecipientResult> {
        let recipient_did = recipient_did.into();
        if recipient_did.trim().is_empty() {
            return Err(crate::Error::InvalidArgument(
                "recipient DID must not be empty".into(),
            ));
        }

        let groups = resolve_bundle_groups(self.tn, options.groups);
        let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
        let written = self.tn.runtime().bundle_for_recipient_with_options(
            &recipient_did,
            out_path.as_ref(),
            Some(&group_refs),
            options.seal_for_recipient,
        )?;

        Ok(BundleForRecipientResult {
            path: written,
            recipient_did,
            groups,
        })
    }

    /// Compile a recipient enrolment handoff package.
    ///
    /// This mirrors the current TypeScript `tn.pkg.compileEnrolment` public
    /// flow: the artifact is a signed `kit_bundle` addressed to one recipient
    /// and narrowed to the requested group. It is intentionally not the legacy
    /// Python JWE-only `enrolment` body shape.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the recipient DID or group is empty, the
    /// group is unknown, the bundle cannot be minted, or the output cannot be
    /// inspected for receipt hashes.
    pub fn compile_enrolment(&self, options: CompileEnrolmentOptions) -> Result<CompiledPackage> {
        if options.group.trim().is_empty() {
            return Err(Error::InvalidArgument("group must not be empty".into()));
        }
        if options.recipient_did.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "recipient DID must not be empty".into(),
            ));
        }

        let result = self.bundle_for_recipient(
            options.recipient_did.clone(),
            &options.out_path,
            BundleForRecipientOptions {
                groups: Some(vec![options.group.clone()]),
                seal_for_recipient: options.seal_for_recipient,
            },
        )?;
        compiled_package_receipt(&result.path, result.recipient_did, result.groups)
    }

    /// Offer a recipient access to one group.
    ///
    /// This compiles the same recipient handoff package as
    /// [`Package::compile_enrolment`], then emits `tn.offer.compiled` to the
    /// local log so dashboards and wallet flows can track the offer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if package compilation fails, package hashing
    /// fails, or the attested offer event cannot be emitted.
    pub fn offer(&self, options: OfferOptions) -> Result<OfferReceipt> {
        let compiled = self.compile_enrolment(CompileEnrolmentOptions {
            group: options.group.clone(),
            recipient_did: options.peer_did.clone(),
            out_path: options.out_path,
            seal_for_recipient: options.seal_for_recipient,
        })?;

        let package_sha256 = compiled.package_sha256.clone();
        self.tn.info(
            "tn.offer.compiled",
            json!({
                "group": options.group,
                "peer_identity": options.peer_did,
                "package_sha256": format!("sha256:{package_sha256}"),
                "package_path": compiled.path.to_string_lossy(),
            }),
        )?;

        Ok(OfferReceipt {
            path: compiled.path,
            group: compiled.groups.first().cloned().unwrap_or_default(),
            peer_did: compiled.recipient_did,
            package_sha256,
            status: "offered".into(),
        })
    }

    /// Issue and durably retain a signed one-time enrollment challenge for
    /// `reader_did` on `group`, pre-authorizing that exact reader.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidArgument`] with a stable
    /// `"<reason>: <detail>"` message for scope or identity failures.
    pub fn issue_enrollment_challenge(
        &self,
        reader_did: &str,
        group: &str,
        ttl: Duration,
    ) -> Result<crate::enrollment::EnrollmentChallengeV1> {
        let store = crate::enrollment::enrollment_store(self.tn)?;
        let challenge = store
            .issue_challenge(reader_did, group, ttl, SystemTime::now())
            .map_err(crate::enrollment::trust_err)?;
        // Issuing a challenge is the publisher's pre-authorization act: the
        // exact reader/ceremony/group is recorded so a challenged offer can
        // later reconcile without a second manual approval.
        store
            .preauthorize(reader_did, group)
            .map_err(crate::enrollment::trust_err)?;
        Ok(challenge)
    }

    /// Reverify and promote one retained pending offer that is already
    /// authorized (challenged and pre-authorized, or exact-digest approved).
    ///
    /// # Errors
    ///
    /// `untrusted_principal` when nothing authorizes the offer, plus the full
    /// verification reason set for corrupt retained state.
    pub fn reconcile_pending(
        &self,
        offer_digest: &str,
    ) -> Result<crate::enrollment::AcceptedOffer> {
        crate::enrollment::enrollment_store(self.tn)?
            .reconcile(offer_digest, SystemTime::now())
            .map_err(crate::enrollment::trust_err)
    }

    /// Approve an exact offer digest and atomically reverify, consume the
    /// challenge, and promote it to accepted state.
    ///
    /// # Errors
    ///
    /// `untrusted_principal` for an unknown digest, `replay_conflict` for
    /// conflicting retained state, plus the verification reason set.
    pub fn approve_and_reconcile(
        &self,
        offer_digest: &str,
    ) -> Result<crate::enrollment::AcceptedOffer> {
        crate::enrollment::enrollment_store(self.tn)?
            .approve_and_reconcile(offer_digest, SystemTime::now())
            .map_err(crate::enrollment::trust_err)
    }

    /// Build and sign a version-1 reader offer artifact for one group,
    /// binding this ceremony's static X25519 reader key (created on first
    /// use, then reused exactly) and, when supplied, the publisher challenge.
    ///
    /// # Errors
    ///
    /// `did_invalid` for a placeholder publisher DID, challenge-verification
    /// failures, and I/O errors writing the artifact.
    pub fn offer_v1(&self, options: crate::enrollment::OfferOptionsV1) -> Result<OfferReceipt> {
        if options.group.trim().is_empty() {
            return Err(Error::InvalidArgument("group must not be empty".into()));
        }
        let device = crate::enrollment::device_key(self.tn)?;
        let (_private, public) = crate::enrollment::ensure_reader_mykey(self.tn, &options.group)?;
        let ceremony_id = match &options.challenge {
            Some(challenge) => challenge.ceremony_id.clone(),
            None => crate::enrollment::ceremony_id(self.tn)?,
        };
        let artifact = tn_core::trusted_enrollment::build_offer_artifact(
            &tn_core::trusted_enrollment::OfferArtifactSpec {
                ceremony_id: &ceremony_id,
                group: &options.group,
                publisher_did: &options.publisher_did,
                reader_key: &device,
                reader_public_key: public,
                challenge: options.challenge.as_ref(),
                now: SystemTime::now(),
            },
        )
        .map_err(crate::enrollment::trust_err)?;
        if let Some(parent) = options.out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        tn_core::keystore_backend::atomic_write_bytes(&options.out_path, &artifact.tnpkg)?;
        crate::enrollment::retain_sent_offer(
            self.tn,
            &options.publisher_did,
            &ceremony_id,
            &options.group,
            &artifact.offer_digest,
            &crate::enrollment::sha256_tagged(&public),
            &artifact.proof.expires_at,
        )?;
        let package_sha256 = sha256_hex(&artifact.tnpkg);
        let _ = self.tn.info(
            "tn.offer.compiled",
            json!({
                "group": options.group,
                "peer_identity": options.publisher_did,
                "package_sha256": format!("sha256:{package_sha256}"),
                "package_path": options.out_path.to_string_lossy(),
                "offer_digest": artifact.offer_digest,
            }),
        );
        Ok(OfferReceipt {
            path: options.out_path,
            group: options.group,
            peer_did: options.publisher_did,
            package_sha256,
            status: "offered".into(),
        })
    }

    /// Compile the signed version-1 enrollment response for one atomically
    /// accepted offer and write it as an `enrolment` `.tnpkg` addressed to
    /// the reader.
    ///
    /// # Errors
    ///
    /// Scope mismatches between the accepted offer and this ceremony/reader
    /// surface as stable trust reasons; I/O errors surface as
    /// [`crate::Error::Io`].
    pub fn compile_enrolment_v1(
        &self,
        options: crate::enrollment::CompileEnrolmentOptionsV1,
    ) -> Result<CompiledPackage> {
        use crate::enrollment::{trust_err, TrustError, TrustReason};

        let device = crate::enrollment::device_key(self.tn)?;
        let ceremony_id = crate::enrollment::ceremony_id(self.tn)?;
        let accepted = &options.accepted_offer;
        let principal = &accepted.binding.principal;
        if principal.audience_did != device.did() {
            return Err(trust_err(TrustError::new(
                TrustReason::WrongRecipient,
                "accepted offer is addressed to a different publisher",
            )));
        }
        if principal.ceremony_id != ceremony_id
            || principal.group != options.group
            || !self.tn.group_names().contains(&options.group)
        {
            return Err(trust_err(TrustError::new(
                TrustReason::ScopeMismatch,
                "accepted offer ceremony or group does not match",
            )));
        }
        if principal.did != options.reader_did {
            return Err(trust_err(TrustError::new(
                TrustReason::DidSignerMismatch,
                "accepted offer binds a different reader DID",
            )));
        }

        let now = SystemTime::now();
        let issued_at = crate::enrollment::canonical_utc_timestamp(now).map_err(trust_err)?;
        let expires_at =
            crate::enrollment::canonical_utc_timestamp(now + options.ttl).map_err(trust_err)?;
        let response = crate::enrollment::EnrollmentResponseV1 {
            version: 1,
            kind: "tn-enrollment-response".into(),
            publisher_did: device.did().to_string(),
            reader_did: options.reader_did.clone(),
            ceremony_id,
            group: options.group.clone(),
            accepted_offer_digest: accepted.offer_digest.clone(),
            x25519_public_key_sha256: accepted.binding.public_key_sha256.clone(),
            // The first admitted epoch for this reader. A managed-JWE
            // publisher runtime stamps its live group epoch here.
            group_epoch: 1,
            issued_at,
            expires_at,
            signature_b64: String::new(),
        }
        .signed(&device)
        .map_err(trust_err)?;

        let bytes =
            tn_core::trusted_enrollment::build_enrollment_response_artifact(&response, &device)
                .map_err(trust_err)?;
        if let Some(parent) = options.out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        tn_core::keystore_backend::atomic_write_bytes(&options.out_path, &bytes)?;
        compiled_package_receipt(&options.out_path, options.reader_did, vec![options.group])
    }

    /// Absorb a `.tnpkg` with explicit version-1 trust options.
    ///
    /// Offers route into the locked enrollment pending state after complete
    /// verification (`legacy_status == "offer_stashed"`), never through the
    /// legacy import. Other kinds go through the runtime's verified absorb;
    /// with [`AbsorbOptionsV1::unsafe_legacy_signer`] a legacy package that
    /// fails the strict path is retained as unverified material and the one
    /// warning plus one best-effort audit event are emitted.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] only for local I/O failures; malformed or
    /// rejected input is reported on the returned receipt.
    pub fn absorb_with_options(
        &self,
        source: tn_core::AbsorbSource<'_>,
        options: crate::enrollment::AbsorbOptionsV1,
    ) -> Result<AbsorbReceipt> {
        let bytes: Vec<u8> = match source {
            tn_core::AbsorbSource::Path(path) => fs::read(path)?,
            tn_core::AbsorbSource::Bytes(bytes) => bytes.to_vec(),
        };
        let kind = tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(&bytes))
            .ok()
            .map(|(manifest, _)| manifest.kind);
        if kind == Some(ManifestKind::Offer) {
            // Security-sensitive version-1 statements always fail closed;
            // the unsafe legacy path never applies to them.
            return Ok(self.stage_offer_receipt(&bytes));
        }
        if kind == Some(ManifestKind::Enrolment) && carries_enrollment_response(&bytes) {
            return Ok(self.absorb_enrollment_response(&bytes));
        }
        // Keep parity with `absorb_bytes`: signed contact updates apply.
        if let Some(receipt) = self.try_absorb_contact_update_bytes(&bytes)? {
            return Ok(receipt);
        }
        let receipt = self
            .tn
            .runtime()
            .absorb(tn_core::AbsorbSource::Bytes(&bytes))?;
        if receipt.legacy_status != "rejected"
            || !options.unsafe_legacy_signer
            || kind == Some(ManifestKind::Enrolment)
        {
            return Ok(receipt);
        }
        self.import_legacy_unverified(&bytes, kind)
    }

    fn absorb_enrollment_response(&self, bytes: &[u8]) -> AbsorbReceipt {
        let installed = crate::enrollment::read_enrollment_response(bytes).and_then(|response| {
            let expected = crate::enrollment::retained_response_expectation(
                self.tn,
                &response,
                SystemTime::now(),
            )?;
            crate::enrollment::install_publisher_response(self.tn, &response, &expected)
        });
        match installed {
            Ok(outcome) => enrollment_response_accepted(&outcome.publisher_did),
            Err(error) => enrollment_response_rejected(error.to_string()),
        }
    }

    fn stage_offer_receipt(&self, bytes: &[u8]) -> AbsorbReceipt {
        let staged = crate::enrollment::enrollment_store(self.tn)
            .map_err(|error| error.to_string())
            .and_then(|store| {
                store
                    .stage_offer(bytes, SystemTime::now())
                    .map_err(|error| error.to_string())
            });
        match staged {
            Ok(pending) => AbsorbReceipt {
                kind: ManifestKind::Offer.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "offer_stashed".into(),
                legacy_reason: format!(
                    "offer retained pending approval; offer_digest {}",
                    pending.offer_digest
                ),
                replaced_kit_paths: Vec::new(),
            },
            Err(reason) => AbsorbReceipt {
                kind: ManifestKind::Offer.as_str().into(),
                accepted_count: 0,
                deduped_count: 0,
                noop: false,
                derived_state: None,
                conflicts: Vec::new(),
                legacy_status: "rejected".into(),
                legacy_reason: reason,
                replaced_kit_paths: Vec::new(),
            },
        }
    }

    fn import_legacy_unverified(
        &self,
        bytes: &[u8],
        kind: Option<ManifestKind>,
    ) -> Result<AbsorbReceipt> {
        // The named unsafe legacy-import path: the manifest signature must
        // still verify, but the missing signed body index is tolerated. The
        // package is retained as unverified material only — it is never
        // applied to keystores or trusted state.
        let (manifest, _body) =
            match tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(bytes)) {
                Ok(parts) => parts,
                Err(error) => {
                    return Ok(legacy_import_rejected(kind, &error.to_string()));
                }
            };
        if let Err(error) = tn_core::tnpkg::verify_manifest(&manifest) {
            return Ok(legacy_import_rejected(
                Some(manifest.kind),
                &format!("legacy import still requires a valid manifest signature: {error}"),
            ));
        }
        let digest = crate::enrollment::sha256_tagged(bytes);
        let notice = tn_core::UnsafeOperationNotice {
            artifact_digest: Some(digest.clone()),
            group: None,
            operation: tn_core::UnsafeOperation::LegacyPackageImport,
            relaxations: vec![tn_core::UnsafeRelaxation::LegacySignerMismatch],
            subject_did: Some(manifest.publisher_identity.clone()),
        };
        crate::enrollment::warn_and_audit_unsafe(self.tn, &notice);
        let stash_dir = self
            .tn
            .yaml_path()
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(".tn")
            .join(
                self.tn
                    .yaml_path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("tn"),
            )
            .join("inbox")
            .join("legacy");
        let stash_path = stash_dir.join(format!("{}.tnpkg", &digest["sha256:".len()..]));
        tn_core::keystore_backend::atomic_write_bytes(&stash_path, bytes)?;
        Ok(AbsorbReceipt {
            kind: manifest.kind.as_str().into(),
            accepted_count: 0,
            deduped_count: 0,
            noop: false,
            derived_state: None,
            conflicts: Vec::new(),
            legacy_status: "stashed".into(),
            legacy_reason: format!(
                "legacy package retained unverified at {}; it was not applied and is never \
                 marked verified",
                stash_path.display()
            ),
            replaced_kit_paths: Vec::new(),
        })
    }

    /// Export the full local keystore as a `full_keystore` `.tnpkg`.
    ///
    /// This writes raw private key material into the package. Callers must pass
    /// [`SecretExportConsent::acknowledge`] to make that choice explicit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be written or the
    /// requested group subset has no matching key material.
    pub fn export_full_keystore(
        &self,
        out_path: impl AsRef<Path>,
        groups: Option<Vec<String>>,
        _consent: SecretExportConsent,
    ) -> Result<PathBuf> {
        self.export_with(
            out_path,
            ExportOptions {
                kind: ManifestKind::FullKeystore,
                confirm_includes_secrets: true,
                groups,
                ..ExportOptions::default()
            },
        )
    }

    /// Export the current ceremony as a `project_seed` backup `.tnpkg`.
    ///
    /// This writes `tn.yaml` plus raw private key material into the package.
    /// Callers must pass [`SecretExportConsent::acknowledge`] to make that
    /// choice explicit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be written or the
    /// requested group subset has no matching key material.
    pub fn export_project_seed(
        &self,
        out_path: impl AsRef<Path>,
        groups: Option<Vec<String>>,
        _consent: SecretExportConsent,
    ) -> Result<PathBuf> {
        self.export_with(
            out_path,
            ExportOptions {
                kind: ManifestKind::ProjectSeed,
                confirm_includes_secrets: true,
                groups,
                ..ExportOptions::default()
            },
        )
    }

    /// Export this runtime's device identity as an `identity_seed` `.tnpkg`.
    ///
    /// The package contains the raw device private seed. Callers must pass
    /// [`SecretExportConsent::acknowledge`] to make that choice explicit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be written.
    pub fn export_identity_seed(
        &self,
        out_path: impl AsRef<Path>,
        _consent: SecretExportConsent,
    ) -> Result<PathBuf> {
        self.export_with(
            out_path,
            ExportOptions {
                kind: ManifestKind::IdentitySeed,
                confirm_includes_secrets: true,
                ..ExportOptions::default()
            },
        )
    }

    /// Export a two-device group-key sync snapshot.
    ///
    /// The wire package matches Python/TypeScript wallet sync:
    /// `kind = full_keystore`, `scope = group_keys`, self-addressed to this
    /// runtime's device DID, carrying only `body/keys/<group>.btn.state` and
    /// `body/keys/<group>.btn.mykit` entries plus the manifest
    /// `state.groups` YAML blocks. It does not include device-private key
    /// material.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when no requested BTN group has key material or
    /// the package cannot be written.
    pub fn export_group_keys(
        &self,
        out_path: impl AsRef<Path>,
        groups: Option<Vec<String>>,
    ) -> Result<PathBuf> {
        Ok(self
            .tn
            .runtime()
            .export_group_keys(out_path.as_ref(), groups.as_deref())?)
    }

    /// Export a `.tnpkg` with explicit options.
    ///
    /// Prefer the typed helper methods when one exists. This lower-level entry
    /// point is useful for less common package kinds and for parity tests.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be written or the
    /// selected kind requires additional options.
    pub fn export_with(
        &self,
        out_path: impl AsRef<Path>,
        options: ExportOptions,
    ) -> Result<PathBuf> {
        Ok(self
            .tn
            .runtime()
            .export(out_path.as_ref(), options.into_core())?)
    }

    /// Absorb a `.tnpkg` from disk.
    ///
    /// Malformed, unsupported, or rejected packages return an
    /// [`AbsorbReceipt`] with `legacy_status == "rejected"` or `"stashed"`;
    /// callers should inspect the receipt rather than treating `Ok` as
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] only for local apply failures; malformed or
    /// rejected input is reported on the returned receipt.
    pub fn absorb_path(&self, source: impl AsRef<Path>) -> Result<AbsorbReceipt> {
        if let Some(receipt) = self.try_absorb_contact_update_path(source.as_ref())? {
            return Ok(receipt);
        }
        Ok(self
            .tn
            .runtime()
            .absorb(tn_core::AbsorbSource::Path(source.as_ref()))?)
    }

    /// Absorb a `.tnpkg` from bytes.
    ///
    /// This is useful when the package arrives over a network or message queue.
    /// As with [`Package::absorb_path`], rejected input is reported on the
    /// returned receipt.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] only for local apply failures; malformed or
    /// rejected input is reported on the returned receipt.
    pub fn absorb_bytes(&self, bytes: &[u8]) -> Result<AbsorbReceipt> {
        if let Some(receipt) = self.try_absorb_contact_update_bytes(bytes)? {
            return Ok(receipt);
        }
        Ok(self
            .tn
            .runtime()
            .absorb(tn_core::AbsorbSource::Bytes(bytes))?)
    }

    /// Inspect a `.tnpkg` from disk without absorbing it.
    ///
    /// This reads the manifest and body member names, then verifies the
    /// manifest signature. Invalid signatures are reported in
    /// [`PackageInfo::signature`] rather than returned as an error so callers
    /// can show package metadata while still refusing to trust the body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be parsed as a `.tnpkg`.
    pub fn inspect_path(&self, source: impl AsRef<Path>) -> Result<PackageInfo> {
        inspect_source(tn_core::tnpkg::TnpkgSource::Path(source.as_ref()))
    }

    /// Inspect a `.tnpkg` from bytes without absorbing it.
    ///
    /// See [`Package::inspect_path`] for signature behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be parsed as a `.tnpkg`.
    pub fn inspect_bytes(&self, bytes: &[u8]) -> Result<PackageInfo> {
        inspect_source(tn_core::tnpkg::TnpkgSource::Bytes(bytes))
    }

    /// Read and parse `body/package.json` from a `.tnpkg` on disk.
    ///
    /// Offer, enrolment, recipient-invite, and contact-update packages use
    /// this conventional JSON body. The returned [`PackageJsonPayload`]
    /// includes package metadata and manifest signature status so callers can
    /// route or display untrusted packages without treating them as verified.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be parsed, does not
    /// contain `body/package.json`, or the JSON payload is malformed.
    pub fn package_json_path(&self, source: impl AsRef<Path>) -> Result<PackageJsonPayload> {
        package_json_source(tn_core::tnpkg::TnpkgSource::Path(source.as_ref()))
    }

    /// Read and parse `body/package.json` from in-memory `.tnpkg` bytes.
    ///
    /// See [`Package::package_json_path`] for signature behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package cannot be parsed, does not
    /// contain `body/package.json`, or the JSON payload is malformed.
    pub fn package_json_bytes(&self, bytes: &[u8]) -> Result<PackageJsonPayload> {
        package_json_source(tn_core::tnpkg::TnpkgSource::Bytes(bytes))
    }

    /// Read and validate `body/contact_update.json` from a `.tnpkg` on disk.
    ///
    /// This mirrors the Python/TypeScript contact-update body schema without
    /// applying it to `contacts.yaml`. Use this for safe routing and previews
    /// before local contact-book mutation is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package is not `contact_update`, is
    /// missing `body/contact_update.json`, or the body fails schema validation.
    pub fn contact_update_path(&self, source: impl AsRef<Path>) -> Result<ContactUpdatePackage> {
        contact_update_source(tn_core::tnpkg::TnpkgSource::Path(source.as_ref()))
    }

    /// Read and validate `body/contact_update.json` from in-memory `.tnpkg`
    /// bytes.
    ///
    /// See [`Package::contact_update_path`] for validation behavior.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package is not `contact_update`, is
    /// missing `body/contact_update.json`, or the body fails schema validation.
    pub fn contact_update_bytes(&self, bytes: &[u8]) -> Result<ContactUpdatePackage> {
        contact_update_source(tn_core::tnpkg::TnpkgSource::Bytes(bytes))
    }

    /// Return the canonical `contacts.yaml` path for this ceremony.
    ///
    /// The path matches Python/TypeScript:
    /// `<yaml_dir>/.tn/<stem>/contacts.yaml`.
    pub fn contacts_path(&self) -> PathBuf {
        contacts_path(self.tn.yaml_path())
    }

    /// Apply a validated contact update body to this ceremony's
    /// `contacts.yaml`.
    ///
    /// Idempotency matches Python/TypeScript: rows are matched by
    /// `(account_id, package_did)`. A match is replaced in place; otherwise the
    /// row is appended. The saved row is projected to the canonical six-field
    /// contact-update shape.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if `contacts.yaml` cannot be read or written.
    pub fn apply_contact_update_body(
        &self,
        body: &ContactUpdateBody,
    ) -> Result<ContactUpdateApplyResult> {
        apply_contact_update_body(self.tn.yaml_path(), body)
    }

    /// Validate and apply a signed `contact_update` package from disk.
    ///
    /// This is the explicit-package counterpart to [`Package::absorb_path`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package is malformed, unsigned/invalid,
    /// not a `contact_update`, or local contact storage cannot be written.
    pub fn apply_contact_update_path(
        &self,
        source: impl AsRef<Path>,
    ) -> Result<ContactUpdateApplyResult> {
        let package = self.contact_update_path(source)?;
        ensure_contact_update_verified(&package)?;
        self.apply_contact_update_body(&package.body)
    }

    /// Validate and apply a signed `contact_update` package from bytes.
    ///
    /// This is the explicit-package counterpart to [`Package::absorb_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the package is malformed, unsigned/invalid,
    /// not a `contact_update`, or local contact storage cannot be written.
    pub fn apply_contact_update_bytes(&self, bytes: &[u8]) -> Result<ContactUpdateApplyResult> {
        let package = self.contact_update_bytes(bytes)?;
        ensure_contact_update_verified(&package)?;
        self.apply_contact_update_body(&package.body)
    }

    fn try_absorb_contact_update_path(&self, source: &Path) -> Result<Option<AbsorbReceipt>> {
        match tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Path(source)) {
            Ok((manifest, body)) => self.try_absorb_contact_update_parts(manifest, body),
            Err(_) => Ok(None),
        }
    }

    fn try_absorb_contact_update_bytes(&self, bytes: &[u8]) -> Result<Option<AbsorbReceipt>> {
        match tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(bytes)) {
            Ok((manifest, body)) => self.try_absorb_contact_update_parts(manifest, body),
            Err(_) => Ok(None),
        }
    }

    fn try_absorb_contact_update_parts(
        &self,
        manifest: PackageManifest,
        body: tn_core::tnpkg::BodyContents,
    ) -> Result<Option<AbsorbReceipt>> {
        if manifest.kind != ManifestKind::ContactUpdate {
            return Ok(None);
        }
        if let Err(err) = tn_core::tnpkg::verify_manifest(&manifest) {
            return Ok(Some(contact_update_rejected(format!(
                "contact_update manifest signature failed verification: {err}"
            ))));
        }
        let Some(raw) = body.get("body/contact_update.json") else {
            return Ok(Some(contact_update_rejected(
                "contact_update body missing `body/contact_update.json`",
            )));
        };
        let value = match serde_json::from_slice::<serde_json::Value>(raw) {
            Ok(value) => value,
            Err(err) => {
                return Ok(Some(contact_update_rejected(format!(
                    "contact_update body is not valid JSON: {err}"
                ))));
            }
        };
        let contact = match ContactUpdateBody::from_json(&value) {
            Ok(contact) => contact,
            Err(err) => return Ok(Some(contact_update_rejected(err.to_string()))),
        };
        self.apply_contact_update_body(&contact)?;
        Ok(Some(AbsorbReceipt {
            kind: ManifestKind::ContactUpdate.as_str().into(),
            accepted_count: 1,
            deduped_count: 0,
            noop: false,
            derived_state: None,
            conflicts: Vec::new(),
            legacy_status: "enrolment_applied".into(),
            legacy_reason: String::new(),
            replaced_kit_paths: Vec::new(),
        }))
    }
}

fn carries_enrollment_response(bytes: &[u8]) -> bool {
    let Ok((manifest, body)) =
        tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(bytes))
    else {
        return false;
    };
    if manifest.kind != ManifestKind::Enrolment {
        return false;
    }
    body.get("body/package.json")
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
        .and_then(|package| package.get("payload").cloned())
        .is_some_and(|payload| payload.get("enrollment_response").is_some())
}

fn enrollment_response_accepted(publisher_did: &str) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: ManifestKind::Enrolment.as_str().into(),
        accepted_count: 1,
        deduped_count: 0,
        noop: false,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: "enrolment_applied".into(),
        legacy_reason: format!("verified publisher {publisher_did} installed"),
        replaced_kit_paths: Vec::new(),
    }
}

fn enrollment_response_rejected(reason: String) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: ManifestKind::Enrolment.as_str().into(),
        accepted_count: 0,
        deduped_count: 0,
        noop: false,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: "rejected".into(),
        legacy_reason: reason,
        replaced_kit_paths: Vec::new(),
    }
}

/// Explicit acknowledgement required by helpers that export private key
/// material.
///
/// This type is intentionally not constructible by fields. Use
/// [`SecretExportConsent::acknowledge`] at the call site so secret-bearing
/// exports stand out during review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretExportConsent {
    _private: (),
}

impl SecretExportConsent {
    /// Acknowledge that the package being exported includes raw private key
    /// material and must be handled as a secret.
    pub fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Package kind.
pub type ManifestKind = tn_core::ManifestKind;

/// Decoded `.tnpkg` manifest.
pub type PackageManifest = tn_core::Manifest;

/// Signature verification status from package inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSignatureStatus {
    /// The manifest signature verifies against `publisher_identity`.
    Verified,
    /// The manifest was parsed, but its signature did not verify.
    Invalid(String),
}

impl PackageSignatureStatus {
    /// True when this status is [`PackageSignatureStatus::Verified`].
    pub fn verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Read-only package metadata returned by [`Package::inspect_path`] and
/// [`Package::inspect_bytes`].
#[derive(Debug, Clone)]
pub struct PackageInfo {
    /// Parsed package manifest.
    pub manifest: PackageManifest,
    /// Manifest signature verification status.
    pub signature: PackageSignatureStatus,
    /// Number of non-manifest body entries.
    pub body_entry_count: usize,
    /// Sorted body member names, such as `body/admin.ndjson`.
    pub body_entry_names: Vec<String>,
}

/// Parsed `body/package.json` payload plus package metadata.
#[derive(Debug, Clone)]
pub struct PackageJsonPayload {
    /// Package metadata from the same `.tnpkg`.
    pub info: PackageInfo,
    /// Parsed JSON document from `body/package.json`.
    pub value: serde_json::Value,
}

/// Parsed and validated `contact_update` package.
#[derive(Debug, Clone)]
pub struct ContactUpdatePackage {
    /// Package metadata from the same `.tnpkg`.
    pub info: PackageInfo,
    /// Canonical contact update body.
    pub body: ContactUpdateBody,
}

/// Result from applying a contact update to `contacts.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactUpdateApplyResult {
    /// Path that was written.
    pub contacts_path: PathBuf,
    /// True when an existing `(account_id, package_did)` row was replaced.
    pub replaced: bool,
    /// Number of rows in `contacts.yaml` after the update.
    pub contacts_len: usize,
    /// Canonical row written to the contact book.
    pub row: ContactUpdateBody,
}

impl ContactUpdatePackage {
    /// True when the package manifest signature verifies.
    pub fn verified(&self) -> bool {
        self.info.verified()
    }

    /// DID that signed/published the package.
    pub fn publisher_did(&self) -> &str {
        self.info.publisher_did()
    }

    /// Optional recipient DID from the manifest.
    pub fn recipient_did(&self) -> Option<&str> {
        self.info.recipient_did()
    }
}

/// Canonical `contact_update` body.
///
/// This is the Rust form of Python/TypeScript's six-field contact row. Unknown
/// JSON fields are ignored during validation so the SDK projects the same
/// stable row shape the other implementations write to `contacts.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactUpdateBody {
    /// Vault account id for the contact.
    pub account_id: String,
    /// Human-readable contact label.
    pub label: String,
    /// DID used for package delivery, if the account has one.
    pub package_did: Option<String>,
    /// Contact X25519 public key in base64, if known.
    pub x25519_pub_b64: Option<String>,
    /// Claim timestamp.
    pub claimed_at: String,
    /// Source share/link id, if known.
    pub source_link_id: Option<String>,
}

impl ContactUpdateBody {
    /// Validate and project a JSON value into the canonical contact-update
    /// body shape.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] with Python/TypeScript-style validation details
    /// when required keys are missing or fields have the wrong type.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        contact_update_body_from_json(value)
    }

    /// Convert this body back to canonical JSON field names.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "account_id": self.account_id,
            "label": self.label,
            "package_did": self.package_did,
            "x25519_pub_b64": self.x25519_pub_b64,
            "claimed_at": self.claimed_at,
            "source_link_id": self.source_link_id,
        })
    }
}

impl PackageJsonPayload {
    /// High-level package category for SDK routing.
    pub fn category(&self) -> PackageCategory {
        self.info.category()
    }

    /// True when the package manifest signature verifies.
    pub fn verified(&self) -> bool {
        self.info.verified()
    }

    /// DID that signed/published the package.
    pub fn publisher_did(&self) -> &str {
        self.info.publisher_did()
    }

    /// Optional recipient DID from the manifest.
    pub fn recipient_did(&self) -> Option<&str> {
        self.info.recipient_did()
    }
}

impl PackageInfo {
    /// Package kind from the manifest.
    pub fn kind(&self) -> ManifestKind {
        self.manifest.kind
    }

    /// DID that signed/published the package.
    pub fn publisher_did(&self) -> &str {
        &self.manifest.publisher_identity
    }

    /// Optional recipient DID from the manifest.
    pub fn recipient_did(&self) -> Option<&str> {
        self.manifest.recipient_identity.as_deref()
    }

    /// Ceremony id from the manifest.
    pub fn ceremony_id(&self) -> &str {
        &self.manifest.ceremony_id
    }

    /// True when this package was published by `did`.
    pub fn is_published_by(&self, did: &str) -> bool {
        self.publisher_did() == did
    }

    /// True when this package is addressed to `did`.
    ///
    /// Packages without a recipient identity return `false`.
    pub fn is_addressed_to(&self, did: &str) -> bool {
        self.recipient_did() == Some(did)
    }

    /// True when the package manifest signature verifies.
    pub fn verified(&self) -> bool {
        self.signature.verified()
    }

    /// High-level package category for SDK routing.
    pub fn category(&self) -> PackageCategory {
        if self.is_group_key_snapshot() {
            return PackageCategory::GroupKeys;
        }
        match self.manifest.kind {
            ManifestKind::AdminLogSnapshot => PackageCategory::AdminSnapshot,
            ManifestKind::Offer => PackageCategory::Offer,
            ManifestKind::Enrolment => PackageCategory::Enrolment,
            ManifestKind::RecipientInvite => PackageCategory::RecipientInvite,
            ManifestKind::KitBundle => PackageCategory::KitBundle,
            ManifestKind::FullKeystore => PackageCategory::FullKeystore,
            ManifestKind::ContactUpdate => PackageCategory::ContactUpdate,
            ManifestKind::IdentitySeed => PackageCategory::IdentitySeed,
            ManifestKind::ProjectSeed => PackageCategory::ProjectSeed,
            ManifestKind::GroupKeys => PackageCategory::GroupKeys,
        }
    }

    /// True when this package is a recipient invite.
    pub fn is_recipient_invite(&self) -> bool {
        self.category() == PackageCategory::RecipientInvite
    }

    /// True when this package is an offer package.
    pub fn is_offer(&self) -> bool {
        self.category() == PackageCategory::Offer
    }

    /// True when this package is an enrolment package.
    pub fn is_enrolment(&self) -> bool {
        self.category() == PackageCategory::Enrolment
    }

    /// True when this package is a contact update package.
    pub fn is_contact_update(&self) -> bool {
        self.category() == PackageCategory::ContactUpdate
    }

    /// True when this package carries group-key sync material.
    ///
    /// Python and TypeScript currently publish group-key snapshots as
    /// `kind = full_keystore` with `scope = "group_keys"`. Rust also
    /// recognizes the explicit `group_keys` catalog kind for future package
    /// producers.
    pub fn is_group_key_snapshot(&self) -> bool {
        self.manifest.kind == ManifestKind::GroupKeys
            || (self.manifest.kind == ManifestKind::FullKeystore
                && self.manifest.scope == "group_keys")
    }

    /// True when the package body includes the conventional JSON payload used
    /// by offer, enrolment, invite, and contact-update packages.
    pub fn has_package_json(&self) -> bool {
        self.has_body_entry("body/package.json")
    }

    /// True when the body has an entry with the exact logical name.
    pub fn has_body_entry(&self, name: &str) -> bool {
        self.body_entry_names.iter().any(|entry| entry == name)
    }

    /// True when this package kind normally carries raw private key material.
    pub fn contains_secret_material(&self) -> bool {
        matches!(
            self.manifest.kind,
            ManifestKind::FullKeystore | ManifestKind::ProjectSeed | ManifestKind::IdentitySeed
        ) || self
            .body_entry_names
            .iter()
            .any(|name| name == "body/WARNING_CONTAINS_PRIVATE_KEYS")
    }

    /// True when the package body includes reader kit material.
    pub fn contains_reader_keys(&self) -> bool {
        matches!(
            self.manifest.kind,
            ManifestKind::KitBundle | ManifestKind::FullKeystore | ManifestKind::ProjectSeed
        ) && self
            .body_entry_names
            .iter()
            .any(|name| name.ends_with(".btn.mykit") || name.ends_with(".jwe.mykey"))
    }
}

/// High-level `.tnpkg` category for application-level routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageCategory {
    /// Admin-log snapshot.
    AdminSnapshot,
    /// Enrolment offer package.
    Offer,
    /// Enrolment response package.
    Enrolment,
    /// Recipient invite package.
    RecipientInvite,
    /// Reader kit bundle.
    KitBundle,
    /// Full keystore package.
    FullKeystore,
    /// Contact update notification.
    ContactUpdate,
    /// Device identity seed.
    IdentitySeed,
    /// Project bootstrap seed.
    ProjectSeed,
    /// Group-key sync snapshot.
    GroupKeys,
}

/// Options for [`Package::bundle_for_recipient`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleForRecipientOptions {
    /// Optional group subset to package. Defaults to all non-internal groups.
    pub groups: Option<Vec<String>>,
    /// Encrypt the bundle body and wrap the body-encryption key for
    /// `recipient_did`.
    ///
    /// This requires a real resolvable `did:key:z...` Ed25519 recipient DID.
    /// Leave false to produce the legacy plaintext kit bundle.
    pub seal_for_recipient: bool,
}

/// Result from [`Package::bundle_for_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleForRecipientResult {
    /// Path to the written `.tnpkg`.
    pub path: PathBuf,
    /// Recipient DID the package was addressed to.
    pub recipient_did: String,
    /// Groups requested for the bundle.
    pub groups: Vec<String>,
}

/// Options for [`Package::compile_enrolment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileEnrolmentOptions {
    /// Group to include in the handoff package.
    pub group: String,
    /// Recipient DID the package is addressed to.
    pub recipient_did: String,
    /// Destination `.tnpkg` path.
    pub out_path: PathBuf,
    /// Encrypt the bundle body and wrap the body-encryption key for
    /// `recipient_did`.
    pub seal_for_recipient: bool,
}

/// Result from [`Package::compile_enrolment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPackage {
    /// Path to the written `.tnpkg`.
    pub path: PathBuf,
    /// Recipient DID the package was addressed to.
    pub recipient_did: String,
    /// Groups included in the package.
    pub groups: Vec<String>,
    /// SHA-256 of the signed package manifest JSON.
    pub manifest_sha256: String,
    /// SHA-256 of the entire `.tnpkg` archive.
    pub package_sha256: String,
}

/// Options for [`Package::offer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferOptions {
    /// Group being offered to the peer.
    pub group: String,
    /// Peer DID the handoff package is addressed to.
    pub peer_did: String,
    /// Destination `.tnpkg` path.
    pub out_path: PathBuf,
    /// Encrypt the bundle body and wrap the body-encryption key for
    /// `peer_did`.
    pub seal_for_recipient: bool,
}

/// Result from [`Package::offer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferReceipt {
    /// Path to the written `.tnpkg`.
    pub path: PathBuf,
    /// Group included in the offer.
    pub group: String,
    /// Peer DID the offer package is addressed to.
    pub peer_did: String,
    /// SHA-256 of the entire `.tnpkg` archive.
    pub package_sha256: String,
    /// Offer status string, currently always `offered`.
    pub status: String,
}

/// Package export options.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Manifest kind to produce.
    pub kind: ManifestKind,
    /// Optional recipient DID for point-to-point package kinds.
    pub to_did: Option<String>,
    /// Optional manifest scope override.
    pub scope: Option<String>,
    /// Required for full-keystore/project-seed exports that include secrets.
    pub confirm_includes_secrets: bool,
    /// Optional group subset for kit/full-keystore style packages.
    pub groups: Option<Vec<String>>,
    /// Advanced source override for kit/full-keystore exports.
    ///
    /// Prefer [`Package::bundle_for_recipient`] for normal recipient bundles.
    pub keystore: Option<PathBuf>,
    /// Optional AES-256-GCM body encryption key.
    ///
    /// When supplied, the package body is replaced by `body/encrypted.bin`
    /// and `manifest.state.body_encryption` is stamped. This is primarily
    /// used by the vault pending-claim onboarding flow.
    pub encrypt_body_with: Option<[u8; 32]>,
    /// Package body for offer/enrolment kinds.
    pub package_body: Option<Vec<u8>>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            kind: ManifestKind::AdminLogSnapshot,
            to_did: None,
            scope: None,
            confirm_includes_secrets: false,
            groups: None,
            keystore: None,
            encrypt_body_with: None,
            package_body: None,
        }
    }
}

impl ExportOptions {
    fn into_core(self) -> tn_core::ExportOptions {
        tn_core::ExportOptions {
            kind: Some(self.kind),
            to_did: self.to_did,
            scope: self.scope,
            confirm_includes_secrets: self.confirm_includes_secrets,
            groups: self.groups,
            keystore: self.keystore,
            encrypt_body_with: self.encrypt_body_with,
            seal_for_recipients: Vec::new(),
            package_body: self.package_body,
        }
    }
}

/// Package absorb receipt.
pub type AbsorbReceipt = tn_core::AbsorbReceipt;

/// High-level disposition for an absorbed package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsorbStatus {
    /// The package applied new material to local state.
    Accepted,
    /// The package was valid but did not change local state.
    NoOp,
    /// The package was parsed but not applied.
    Stashed,
    /// The package was invalid or unsupported for this runtime.
    Rejected,
}

/// Convenience methods for [`AbsorbReceipt`].
///
/// The underlying receipt intentionally exposes the full protocol counters and
/// legacy status string for parity with Python and TypeScript. This trait adds
/// a compact Rust-facing interpretation for common control flow.
pub trait AbsorbReceiptExt {
    /// Return the high-level package disposition.
    fn status(&self) -> AbsorbStatus;

    /// True when [`AbsorbReceiptExt::status`] is [`AbsorbStatus::Accepted`].
    fn accepted(&self) -> bool {
        self.status() == AbsorbStatus::Accepted
    }

    /// True when [`AbsorbReceiptExt::status`] is [`AbsorbStatus::NoOp`].
    fn no_op(&self) -> bool {
        self.status() == AbsorbStatus::NoOp
    }

    /// True when [`AbsorbReceiptExt::status`] is [`AbsorbStatus::Stashed`].
    fn stashed(&self) -> bool {
        self.status() == AbsorbStatus::Stashed
    }

    /// True when [`AbsorbReceiptExt::status`] is [`AbsorbStatus::Rejected`].
    fn rejected(&self) -> bool {
        self.status() == AbsorbStatus::Rejected
    }
}

impl AbsorbReceiptExt for AbsorbReceipt {
    fn status(&self) -> AbsorbStatus {
        match self.legacy_status.as_str() {
            "rejected" => AbsorbStatus::Rejected,
            "stashed" | "offer_stashed" => AbsorbStatus::Stashed,
            "no_op" => AbsorbStatus::NoOp,
            "enrolment_applied" => AbsorbStatus::Accepted,
            _ if self.accepted_count > 0 => AbsorbStatus::Accepted,
            _ if self.noop || self.deduped_count > 0 => AbsorbStatus::NoOp,
            _ => AbsorbStatus::NoOp,
        }
    }
}

fn inspect_source(source: tn_core::tnpkg::TnpkgSource<'_>) -> Result<PackageInfo> {
    let (manifest, body) = tn_core::tnpkg::read_tnpkg(source)?;
    Ok(package_info_from_parts(
        manifest,
        body.keys().cloned().collect(),
    ))
}

fn compiled_package_receipt(
    path: &Path,
    recipient_did: String,
    groups: Vec<String>,
) -> Result<CompiledPackage> {
    let archive_bytes = fs::read(path)?;
    let (manifest, _) = tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Path(path))?;
    let manifest_bytes = serde_json::to_vec(&manifest.to_json())?;
    Ok(CompiledPackage {
        path: path.to_path_buf(),
        recipient_did,
        groups,
        manifest_sha256: sha256_hex(&manifest_bytes),
        package_sha256: sha256_hex(&archive_bytes),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn package_json_source(source: tn_core::tnpkg::TnpkgSource<'_>) -> Result<PackageJsonPayload> {
    let (manifest, body) = tn_core::tnpkg::read_tnpkg(source)?;
    let package_json = body
        .get("body/package.json")
        .ok_or_else(|| Error::InvalidArgument("package is missing body/package.json".into()))?;
    let value = serde_json::from_slice(package_json)?;
    Ok(PackageJsonPayload {
        info: package_info_from_parts(manifest, body.keys().cloned().collect()),
        value,
    })
}

fn contact_update_source(source: tn_core::tnpkg::TnpkgSource<'_>) -> Result<ContactUpdatePackage> {
    let (manifest, body) = tn_core::tnpkg::read_tnpkg(source)?;
    if manifest.kind != ManifestKind::ContactUpdate {
        return Err(Error::InvalidArgument(format!(
            "expected contact_update package, got {}",
            manifest.kind.as_str()
        )));
    }
    let raw = body.get("body/contact_update.json").ok_or_else(|| {
        Error::InvalidArgument("contact_update body missing `body/contact_update.json`".into())
    })?;
    let value = serde_json::from_slice::<serde_json::Value>(raw).map_err(|err| {
        Error::InvalidArgument(format!("contact_update body is not valid JSON: {err}"))
    })?;
    let body_value = ContactUpdateBody::from_json(&value)?;
    Ok(ContactUpdatePackage {
        info: package_info_from_parts(manifest, body.keys().cloned().collect()),
        body: body_value,
    })
}

fn contact_update_body_from_json(value: &serde_json::Value) -> Result<ContactUpdateBody> {
    let Some(object) = value.as_object() else {
        return Err(Error::InvalidArgument(format!(
            "contact_update body must be a JSON object; got {}",
            json_type_name(value)
        )));
    };

    let mut errors = Vec::new();
    for key in [
        "account_id",
        "label",
        "package_did",
        "x25519_pub_b64",
        "claimed_at",
        "source_link_id",
    ] {
        if !object.contains_key(key) {
            errors.push(format!("missing required key {key:?}"));
        }
    }

    let account_id = required_contact_string(object, "account_id", &mut errors);
    let label = required_contact_string(object, "label", &mut errors);
    let claimed_at = required_contact_string(object, "claimed_at", &mut errors);
    let package_did = nullable_contact_string(object, "package_did", &mut errors);
    let x25519_pub_b64 = nullable_contact_string(object, "x25519_pub_b64", &mut errors);
    let source_link_id = nullable_contact_string(object, "source_link_id", &mut errors);

    if !errors.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "contact_update body invalid: {}",
            errors.join("; ")
        )));
    }

    Ok(ContactUpdateBody {
        account_id: account_id.unwrap_or_default(),
        label: label.unwrap_or_default(),
        package_did,
        x25519_pub_b64,
        claimed_at: claimed_at.unwrap_or_default(),
        source_link_id,
    })
}

fn ensure_contact_update_verified(package: &ContactUpdatePackage) -> Result<()> {
    if package.verified() {
        Ok(())
    } else {
        Err(Error::InvalidArgument(
            "contact_update manifest signature did not verify".into(),
        ))
    }
}

fn apply_contact_update_body(
    yaml_path: &Path,
    body: &ContactUpdateBody,
) -> Result<ContactUpdateApplyResult> {
    let path = contacts_path(yaml_path);
    let mut doc = load_contacts_doc(&path)?;
    let incoming = body.to_json();
    let contacts_value = doc
        .entry("contacts".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !contacts_value.is_array() {
        *contacts_value = serde_json::Value::Array(Vec::new());
    }
    let contacts = contacts_value
        .as_array_mut()
        .expect("contacts was just normalized to an array");

    let mut replaced = false;
    for existing in contacts.iter_mut() {
        if contact_row_matches(existing, &incoming) {
            *existing = incoming.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        contacts.push(incoming);
    }
    let contacts_len = contacts.len();
    save_contacts_doc(&path, &doc)?;
    Ok(ContactUpdateApplyResult {
        contacts_path: path,
        replaced,
        contacts_len,
        row: body.clone(),
    })
}

fn contacts_path(yaml_path: &Path) -> PathBuf {
    let parent = yaml_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = yaml_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("tn");
    parent.join(".tn").join(stem).join("contacts.yaml")
}

fn load_contacts_doc(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }
    let raw = std::fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(serde_json::Map::new());
    }
    let value = serde_yml::from_str::<serde_json::Value>(&raw)?;
    Ok(value.as_object().cloned().unwrap_or_default())
}

fn save_contacts_doc(path: &Path, doc: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let value = serde_json::Value::Object(doc.clone());
    let bytes = serde_yml::to_string(&value)?.into_bytes();
    tn_core::keystore_backend::atomic_write_bytes(path, &bytes)?;
    Ok(())
}

fn contact_row_matches(existing: &serde_json::Value, incoming: &serde_json::Value) -> bool {
    existing.get("account_id") == incoming.get("account_id")
        && existing.get("package_did") == incoming.get("package_did")
}

fn legacy_import_rejected(kind: Option<ManifestKind>, reason: &str) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: kind.map_or_else(|| "unknown".to_string(), |kind| kind.as_str().to_string()),
        accepted_count: 0,
        deduped_count: 0,
        noop: false,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: "rejected".into(),
        legacy_reason: reason.to_string(),
        replaced_kit_paths: Vec::new(),
    }
}

fn contact_update_rejected(reason: impl Into<String>) -> AbsorbReceipt {
    AbsorbReceipt {
        kind: ManifestKind::ContactUpdate.as_str().into(),
        accepted_count: 0,
        deduped_count: 0,
        noop: false,
        derived_state: None,
        conflicts: Vec::new(),
        legacy_status: "rejected".into(),
        legacy_reason: reason.into(),
        replaced_kit_paths: Vec::new(),
    }
}

fn required_contact_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match object.get(key) {
        None => None,
        Some(serde_json::Value::Null) => {
            errors.push(format!("required key {key:?} must not be null"));
            None
        }
        Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(_) => {
            errors.push(format!("required key {key:?} must be a non-empty string"));
            None
        }
    }
}

fn nullable_contact_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        Some(_) => {
            errors.push(format!("key {key:?} must be a string or null"));
            None
        }
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn package_info_from_parts(
    manifest: PackageManifest,
    mut body_entry_names: Vec<String>,
) -> PackageInfo {
    let signature = match tn_core::tnpkg::verify_manifest(&manifest) {
        Ok(()) => PackageSignatureStatus::Verified,
        Err(err) => PackageSignatureStatus::Invalid(err.to_string()),
    };
    body_entry_names.sort();
    PackageInfo {
        manifest,
        signature,
        body_entry_count: body_entry_names.len(),
        body_entry_names,
    }
}

fn resolve_bundle_groups(tn: &Tn, groups: Option<Vec<String>>) -> Vec<String> {
    let source = groups.unwrap_or_else(|| {
        tn.group_names()
            .into_iter()
            .filter(|group| group != "tn.agents")
            .collect()
    });
    let mut resolved = Vec::new();
    for group in source {
        if !resolved.contains(&group) {
            resolved.push(group);
        }
    }
    resolved
}
