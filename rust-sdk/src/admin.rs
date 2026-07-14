//! Ceremony administration helpers.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};

use crate::enrollment::{
    self, trust_err, ChallengeLedger as _, GrantReaderOptionsV1, HibeAuthorityUpdate,
    InstallHibeAssertionOptions, TrustError, TrustReason,
};
use crate::tn::Tn;
use crate::{Error, Result};

pub use tn_core::{EnsureGroupResult, GrantReaderResult, RotateIdPathResult};

/// Runtime administration namespace for a [`Tn`] handle.
pub struct Admin<'a> {
    tn: &'a mut Tn,
}

/// Result from [`Admin::add_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRecipientResult {
    /// Group the recipient was added to.
    pub group: String,
    /// Recipient DID recorded in the admin event, when supplied.
    pub recipient_did: Option<String>,
    /// Leaf index minted by the btn publisher.
    pub leaf_index: u64,
    /// Path where the reader kit was written.
    pub kit_path: PathBuf,
}

/// Result from [`Admin::revoke_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeRecipientResult {
    /// Group the recipient was revoked from.
    pub group: String,
    /// Leaf index revoked by the btn publisher.
    pub leaf_index: u64,
}

/// Result from [`Admin::rotate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateGroupResult {
    /// Group whose publisher keys were rotated.
    pub group: String,
    /// New key generation/epoch.
    pub generation: u32,
    /// `sha256:` digest of the self-kit retired by this rotation.
    pub previous_kit_sha256: String,
    /// `sha256:` digest of the newly minted self-kit.
    pub new_kit_sha256: String,
    /// RFC3339 timestamp emitted on `tn.rotation.completed`.
    pub rotated_at: String,
}

impl<'a> Admin<'a> {
    pub(crate) fn new(tn: &'a mut Tn) -> Self {
        Self { tn }
    }

    /// Ensure a btn group exists and route fields into it.
    ///
    /// If the group does not exist, this mints btn publisher state and a
    /// self-reader kit, writes the group block to `tn.yaml`, reloads the
    /// runtime, and emits `tn.group.added`. If it already exists, this only
    /// updates field routing and reloads when needed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group cannot be created, the yaml
    /// cannot be parsed/written, or the runtime cannot be reloaded.
    pub fn ensure_group(
        &mut self,
        group: &str,
        fields: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<EnsureGroupResult> {
        Ok(self.tn.runtime_mut().admin_ensure_group(group, fields)?)
    }

    /// Mint a reader kit for `recipient_did` in `group`.
    ///
    /// The kit is written to `out_kit_path`, which must end with
    /// `.btn.mykit`. The underlying runtime persists the updated publisher
    /// state and emits `tn.recipient.added`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group is not a btn publisher group,
    /// the kit path has an invalid suffix, or the underlying admin operation
    /// fails.
    pub fn add_recipient(
        &mut self,
        group: &str,
        recipient_did: impl Into<Option<String>>,
        out_kit_path: impl AsRef<Path>,
    ) -> Result<AddRecipientResult> {
        let recipient_did = recipient_did.into();
        let kit_path = out_kit_path.as_ref().to_path_buf();
        let leaf_index =
            self.tn
                .runtime()
                .admin_add_recipient(group, &kit_path, recipient_did.as_deref())?;
        Ok(AddRecipientResult {
            group: group.to_string(),
            recipient_did,
            leaf_index,
            kit_path,
        })
    }

    /// Revoke a reader by leaf index.
    ///
    /// The underlying runtime persists the updated publisher state and emits
    /// `tn.recipient.revoked` on a best-effort basis.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group is not a btn publisher group,
    /// the leaf index is invalid, or the underlying admin operation fails.
    pub fn revoke_recipient(
        &mut self,
        group: &str,
        leaf_index: u64,
    ) -> Result<RevokeRecipientResult> {
        self.tn
            .runtime()
            .admin_revoke_recipient(group, leaf_index)?;
        Ok(RevokeRecipientResult {
            group: group.to_string(),
            leaf_index,
        })
    }

    /// HIBE's add_recipient: mint a delegated identity key for `reader_did`
    /// in the hibe group `group` and export it as an absorbable `.tnpkg`
    /// kit at `out_path`.
    ///
    /// `id_path: None` keys the reader to the group's current sealing path;
    /// pass an ancestor path to hand out a key the reader can delegate
    /// further down. The kit body is sealed to `reader_did` when the DID
    /// resolves to a real `did:key:z...` key. The authority master secret
    /// never rides a kit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group is unknown or not hibe
    /// (grant_reader is hibe-only — use [`Admin::add_recipient`] for
    /// btn/jwe groups), the id path fails validation, or the kit cannot
    /// be minted/written.
    pub fn grant_reader(
        &mut self,
        group: &str,
        reader_did: impl Into<Option<String>>,
        out_path: impl AsRef<Path>,
        id_path: impl Into<Option<String>>,
    ) -> Result<GrantReaderResult> {
        let reader_did = reader_did.into();
        let id_path = id_path.into();
        Ok(self.tn.runtime().admin_grant_reader(
            group,
            reader_did.as_deref(),
            out_path.as_ref(),
            id_path.as_deref(),
        )?)
    }

    /// Rotate a hibe group's identity path so FUTURE seals use `new_path`.
    ///
    /// Admission rotation, not revocation: pre-rotation seals stay open for
    /// prior grantees, and the authority keeps opening every epoch via the
    /// recorded path history. The live group cipher is refreshed in place,
    /// so the next emit/seal from this handle lands on the new path. The
    /// root path (empty string) requires `allow_root_path`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group is unknown or not hibe, this
    /// keystore is not the authority (no msk), the path fails validation,
    /// or `new_path` equals the current path.
    pub fn rotate_id_path(
        &mut self,
        group: &str,
        new_path: &str,
        allow_root_path: bool,
    ) -> Result<RotateIdPathResult> {
        Ok(self
            .tn
            .runtime()
            .admin_rotate_id_path(group, new_path, allow_root_path)?)
    }

    /// Rotate a btn publisher group to a fresh key generation.
    ///
    /// Historical self-kits are preserved so the local project can still read
    /// pre-rotation entries, while future writes use the new generation.
    pub fn rotate(&mut self, group: &str) -> Result<RotateGroupResult> {
        let result = self.tn.runtime().admin_rotate_group(group)?;
        Ok(RotateGroupResult {
            group: result.group,
            generation: result.generation,
            previous_kit_sha256: result.previous_kit_sha256,
            new_kit_sha256: result.new_kit_sha256,
            rotated_at: result.rotated_at,
        })
    }

    /// Return the recipient roster for a group.
    ///
    /// By default, pass `include_revoked = false` to list only active
    /// recipients. Pass `true` to include historical revoked recipients too.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the underlying admin replay fails.
    pub fn recipients(
        &self,
        group: &str,
        include_revoked: bool,
    ) -> Result<Vec<tn_core::RecipientEntry>> {
        Ok(self.tn.runtime().recipients(group, include_revoked)?)
    }

    /// Return the number of revoked recipients in a btn group.
    ///
    /// This reads publisher state, not just the admin log.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the group is not a btn publisher group or
    /// the underlying runtime operation fails.
    pub fn revoked_count(&self, group: &str) -> Result<usize> {
        Ok(self.tn.runtime().admin_revoked_count(group)?)
    }

    /// Replay the admin log and return the materialized admin state.
    ///
    /// Pass `Some(group)` to scope group/recipient/rotation lists to one
    /// group. `None` returns the full state.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the underlying log read or replay fails.
    pub fn state(&self, group: Option<&str>) -> Result<tn_core::AdminState> {
        Ok(self.tn.runtime().admin_state(group)?)
    }

    // -----------------------------------------------------------------
    // Trusted JWE recipient registration
    // -----------------------------------------------------------------

    /// Register a JWE recipient from an atomically accepted, verified offer.
    ///
    /// Re-checks the retained scope (this publisher, this ceremony, this
    /// group), persists the authenticated DID-to-X25519 binding into the
    /// Python-compatible `<group>.jwe.recipients` list plus the verified
    /// trust registry, refreshes the live group cipher, and attests
    /// `tn.recipient.added`. The next Rust emit or seal includes the reader.
    ///
    /// # Errors
    ///
    /// An argument error when `group` is missing or is not JWE;
    /// `wrong_recipient` / `scope_mismatch` for an offer accepted by another
    /// scope; `replay_conflict` for a conflicting key under the same DID.
    pub fn register_jwe_offer(
        &self,
        group: &str,
        accepted: &enrollment::AcceptedOffer,
    ) -> Result<AddRecipientResult> {
        register_jwe_offer_for_tn(self.tn, group, accepted)
    }

    /// Register a raw DID-plus-key JWE recipient WITHOUT a verified binding.
    ///
    /// This is the explicitly named legacy compatibility path. The mandatory
    /// `unsafe_unverified` flag must be `true`; the recipient is stored as
    /// unverified (it can never be silently promoted to trusted state), and
    /// the one structured warning plus one best-effort audit event are
    /// emitted.
    ///
    /// # Errors
    ///
    /// A hard parameter error when `unsafe_unverified` is not `true`, or when
    /// `group` is missing or is not JWE; `replay_conflict` for a conflicting
    /// key under the same DID.
    pub fn register_jwe_raw_unsafe(
        &self,
        group: &str,
        reader_did: &str,
        public_key: [u8; 32],
        unsafe_unverified: bool,
    ) -> Result<AddRecipientResult> {
        if !unsafe_unverified {
            return Err(Error::InvalidArgument(
                "register_jwe_raw_unsafe requires unsafe_unverified=true; use \
                 register_jwe_offer with a verified AcceptedOffer instead"
                    .into(),
            ));
        }
        require_jwe_group(self.tn, group)?;
        enrollment::parse_ed25519_did_key(reader_did).map_err(trust_err)?;
        let notice = tn_core::UnsafeOperationNotice {
            artifact_digest: None,
            group: Some(group.to_string()),
            operation: tn_core::UnsafeOperation::JweAddRecipient,
            relaxations: vec![tn_core::UnsafeRelaxation::UnverifiedKeyBinding],
            subject_did: Some(reader_did.to_string()),
        };
        enrollment::warn_and_audit_unsafe(self.tn, &notice);
        self.persist_jwe_recipient(group, reader_did, &public_key, None)?;
        Ok(AddRecipientResult {
            group: group.to_string(),
            recipient_did: Some(reader_did.to_string()),
            leaf_index: 0,
            kit_path: PathBuf::new(),
        })
    }

    fn persist_jwe_recipient(
        &self,
        group: &str,
        reader_did: &str,
        public_key: &[u8; 32],
        accepted: Option<&enrollment::AcceptedOffer>,
    ) -> Result<()> {
        persist_jwe_recipient(self.tn, group, reader_did, public_key, accepted)
    }

    // -----------------------------------------------------------------
    // Trusted HIBE authority surfaces
    // -----------------------------------------------------------------

    /// Issue a signed `hibe-authority` assertion over this ceremony's
    /// current MPK, sealing path, and pinned epoch.
    ///
    /// Requires the authority role: `<group>.hibe.msk`, `<group>.hibe.mpk`,
    /// and `<group>.hibe.idpath` must exist in the keystore.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidArgument`] when the authority key material is
    /// missing or the assertion cannot be signed.
    pub fn issue_hibe_authority_assertion(
        &self,
        group: &str,
        ttl: Duration,
    ) -> Result<enrollment::KeyBindingProofV1> {
        let keystore = enrollment::keystore_dir(self.tn)?;
        let msk_path = keystore.join(format!("{group}.hibe.msk"));
        if !msk_path.exists() {
            return Err(Error::InvalidArgument(format!(
                "issue_hibe_authority_assertion: no {group}.hibe.msk in this keystore; \
                 only the authority issues assertions"
            )));
        }
        let mpk = fs::read(keystore.join(format!("{group}.hibe.mpk")))?;
        let id_path = fs::read_to_string(keystore.join(format!("{group}.hibe.idpath")))?
            .trim()
            .to_string();
        let max_depth = enrollment::hibe_mpk_max_depth(&mpk).map_err(trust_err)?;
        let path_epoch = enrollment::load_hibe_pin(self.tn, group)?.map_or(0, |pin| pin.path_epoch);
        self.sign_authority_assertion(group, &mpk, &id_path, max_depth, path_epoch, ttl)
    }

    fn sign_authority_assertion(
        &self,
        group: &str,
        mpk: &[u8],
        id_path: &str,
        max_depth: u64,
        path_epoch: u64,
        ttl: Duration,
    ) -> Result<enrollment::KeyBindingProofV1> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use rand_core::RngCore as _;

        let device = enrollment::device_key(self.tn)?;
        let now = SystemTime::now();
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        enrollment::KeyBindingProofV1 {
            version: 1,
            purpose: "hibe-authority".into(),
            subject_did: device.did().to_string(),
            audience_did: device.did().to_string(),
            ceremony_id: enrollment::ceremony_id(self.tn)?,
            group: group.to_string(),
            issued_at: enrollment::canonical_utc_timestamp(now).map_err(trust_err)?,
            expires_at: enrollment::canonical_utc_timestamp(now + ttl).map_err(trust_err)?,
            nonce_b64: B64.encode(nonce),
            binding: json!({
                "algorithm": "TN-BBG-HIBE-BLS12-381",
                "mpk_sha256": enrollment::sha256_tagged(mpk),
                "max_depth": max_depth,
                "id_path": id_path,
                "path_epoch": path_epoch,
            }),
            signature_b64: String::new(),
        }
        .signed(&device)
        .map_err(trust_err)
    }

    /// Issue a scoped one-time challenge for a HIBE reader contact.
    ///
    /// # Errors
    ///
    /// Scope and identity failures as stable trust reasons.
    pub fn issue_hibe_reader_challenge(
        &self,
        group: &str,
        reader_did: &str,
        ttl: Duration,
    ) -> Result<enrollment::EnrollmentChallengeV1> {
        let store = enrollment::enrollment_store(self.tn)?;
        let challenge = store
            .issue_challenge(reader_did, group, ttl, SystemTime::now())
            .map_err(trust_err)?;
        store.preauthorize(reader_did, group).map_err(trust_err)?;
        Ok(challenge)
    }

    /// Verify and atomically pin (or monotonically update) a signed HIBE
    /// authority assertion for `group`.
    ///
    /// Verifies the authority DID and signature, the MPK bytes against the
    /// signed digest, the encoded MPK depth against the asserted depth, the
    /// exact ceremony/group scope, and the non-decreasing path epoch before
    /// persisting authority DID, MPK fingerprint, depth, path, epoch, and
    /// assertion digest.
    ///
    /// # Errors
    ///
    /// `did_signer_mismatch`, `binding_invalid`, `epoch_rollback`, and
    /// `epoch_conflict` as pinned by the shared state-transition vectors.
    pub fn install_hibe_authority_assertion(
        &self,
        options: InstallHibeAssertionOptions,
    ) -> Result<()> {
        let assertion = &options.assertion;
        enrollment::ensure_expected_signer(&options.expected_authority_did, &assertion.subject_did)
            .map_err(trust_err)?;
        let principal = enrollment::verify_key_binding_proof(
            assertion,
            &enrollment::ProofExpectation {
                purpose: "hibe-authority".into(),
                audience_did: assertion.audience_did.clone(),
                ceremony_id: assertion.ceremony_id.clone(),
                group: options.group.clone(),
                now: options.now,
            },
            None,
        )
        .map_err(trust_err)?;
        let binding = enrollment::hibe_authority_binding(assertion).map_err(trust_err)?;
        enrollment::ensure_mpk_matches(&binding, &options.mpk).map_err(trust_err)?;

        let pin = enrollment::load_hibe_pin(self.tn, &options.group)?;
        if let Some(pin) = &pin {
            if pin.authority_did != principal.did {
                return Err(trust_err(TrustError::new(
                    TrustReason::UntrustedPrincipal,
                    "a different authority DID is already pinned for this group",
                )));
            }
            let decision = enrollment::classify_hibe_epoch(
                pin.path_epoch,
                &pin.mpk_sha256,
                binding.path_epoch,
                &binding.mpk_sha256,
            )
            .map_err(trust_err)?;
            if decision == enrollment::EpochDecision::Idempotent {
                return Ok(());
            }
        }
        enrollment::store_hibe_pin(
            self.tn,
            &options.group,
            &enrollment::HibeAuthorityPin {
                authority_did: principal.did,
                mpk_sha256: binding.mpk_sha256,
                max_depth: binding.max_depth,
                id_path: binding.id_path,
                path_epoch: binding.path_epoch,
                assertion_digest: assertion.digest().map_err(trust_err)?,
            },
        )
    }

    /// Rotate this authority's sealing path and return the new signed
    /// assertion at the strictly greater epoch.
    ///
    /// When the group runs as a live native HIBE group, the underlying
    /// keystore rotation also runs; a detached authority (assertion-only
    /// custody) updates its declared `idpath` and pinned state.
    ///
    /// # Errors
    ///
    /// `untrusted_principal` when no authority state is pinned for the group
    /// or the pin names a different authority.
    pub fn rotate_hibe_path_with_assertion(
        &self,
        group: &str,
        new_path: &str,
    ) -> Result<HibeAuthorityUpdate> {
        let device = enrollment::device_key(self.tn)?;
        let pin = enrollment::load_hibe_pin(self.tn, group)?.ok_or_else(|| {
            trust_err(TrustError::new(
                TrustReason::UntrustedPrincipal,
                "no pinned authority state for this group; install an assertion first",
            ))
        })?;
        if pin.authority_did != device.did() {
            return Err(trust_err(TrustError::new(
                TrustReason::UntrustedPrincipal,
                "this ceremony is not the pinned authority for the group",
            )));
        }
        let keystore = enrollment::keystore_dir(self.tn)?;
        let mpk = fs::read(keystore.join(format!("{group}.hibe.mpk")))?;
        if enrollment::sha256_tagged(&mpk) != pin.mpk_sha256 {
            return Err(trust_err(TrustError::new(
                TrustReason::EpochConflict,
                "keystore MPK no longer matches the pinned fingerprint",
            )));
        }

        // Live native hibe groups rotate key material through the runtime;
        // a detached authority only re-declares its sealing path.
        let group_is_live_hibe = group_cipher(self.tn, group)?.as_deref() == Some("hibe");
        if group_is_live_hibe {
            self.tn
                .runtime()
                .admin_rotate_id_path(group, new_path, false)?;
        } else {
            tn_core::keystore_backend::atomic_write_bytes(
                &keystore.join(format!("{group}.hibe.idpath")),
                new_path.as_bytes(),
            )?;
        }

        let next_epoch = pin.path_epoch + 1;
        let assertion = self.sign_authority_assertion(
            group,
            &mpk,
            new_path,
            pin.max_depth,
            next_epoch,
            Duration::from_secs(600),
        )?;
        enrollment::store_hibe_pin(
            self.tn,
            group,
            &enrollment::HibeAuthorityPin {
                authority_did: pin.authority_did,
                mpk_sha256: pin.mpk_sha256,
                max_depth: pin.max_depth,
                id_path: new_path.to_string(),
                path_epoch: next_epoch,
                assertion_digest: assertion.digest().map_err(trust_err)?,
            },
        )?;
        Ok(HibeAuthorityUpdate {
            group: group.to_string(),
            id_path: new_path.to_string(),
            path_epoch: next_epoch,
            assertion,
        })
    }

    /// Mint a HIBE reader grant that fails closed: a complete Ed25519
    /// `did:key` plus a valid `hibe-reader` proof are required, the package
    /// body is recipient-sealed, and there is no implicit plaintext fallback.
    ///
    /// Exact-path grants are the default; an ancestor `id_path` mints subtree
    /// delegation and requires `allow_subauthority`. The explicit
    /// `unsafe_plaintext` escape hatch emits the one structured warning and
    /// one best-effort audit event and labels the artifact as unsafe bearer
    /// delivery.
    ///
    /// # Errors
    ///
    /// `did_invalid` for a placeholder DID, `did_signer_mismatch` /
    /// `wrong_recipient` / `scope_mismatch` / `statement_expired` for proof
    /// failures, and a hard parameter error for an ancestor path without
    /// `allow_subauthority`.
    pub fn grant_reader_verified(
        &mut self,
        options: GrantReaderOptionsV1,
    ) -> Result<GrantReaderResult> {
        // Resolve the target identity path first: the grant scope digest and
        // artifact label both bind it.
        let sealing_path = current_hibe_path(self.tn, &options.group)?;
        let target_path = options.id_path.clone().or_else(|| sealing_path.clone());
        let delegated_subauthority = match (&options.id_path, &sealing_path) {
            (Some(id_path), Some(current)) => {
                current != id_path && is_path_ancestor(id_path, current)
            }
            _ => false,
        };

        if options.unsafe_plaintext {
            let notice = tn_core::UnsafeOperationNotice {
                artifact_digest: None,
                group: Some(options.group.clone()),
                operation: tn_core::UnsafeOperation::HibeGrant,
                relaxations: vec![tn_core::UnsafeRelaxation::PlaintextBearerDelivery],
                subject_did: Some(options.reader_did.clone()),
            };
            enrollment::warn_and_audit_unsafe(self.tn, &notice);
        } else {
            enrollment::parse_ed25519_did_key(&options.reader_did).map_err(trust_err)?;
            enrollment::ensure_expected_signer(&options.reader_did, &options.proof.subject_did)
                .map_err(trust_err)?;
            // A normal grant is authorized by an authority-issued one-time
            // challenge: the proof MUST bind its digest, the challenge must
            // still be retained (not consumed), and delivery consumes it.
            let Some(bound_digest) = options
                .proof
                .binding
                .get("challenge_digest")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                return Err(trust_err(TrustError::new(
                    TrustReason::ChallengeMissing,
                    "HIBE reader proof must bind an authority-issued challenge",
                )));
            };
            let target = target_path.clone().ok_or_else(|| {
                Error::InvalidArgument(
                    "grant_reader_verified: cannot resolve the group sealing path".into(),
                )
            })?;
            let proof_digest = options.proof.digest().map_err(trust_err)?;
            let grant_digest = tn_core::trusted_enrollment::hibe_grant_digest(
                &proof_digest,
                &options.reader_did,
                &options.proof.ceremony_id,
                &options.group,
                &target,
            )
            .map_err(trust_err)?;
            let store = enrollment::enrollment_store(self.tn)?;
            let challenge = match store.resolve(&bound_digest).map_err(trust_err)? {
                enrollment::ChallengeState::Retained(challenge) => challenge,
                enrollment::ChallengeState::Missing => {
                    return Err(trust_err(TrustError::new(
                        TrustReason::ChallengeMissing,
                        "challenge digest is not retained",
                    )));
                }
                enrollment::ChallengeState::Expired => {
                    return Err(trust_err(TrustError::new(
                        TrustReason::ChallengeExpired,
                        "grant proof names an expired challenge",
                    )));
                }
                enrollment::ChallengeState::Consumed(challenge) => {
                    // Classify against the consumed ledger: an exact prior
                    // grant or a foreign consumption is a replay; different
                    // grant bytes are a conflict.
                    store
                        .check_hibe_grant_challenge(
                            &challenge.challenge_id,
                            &proof_digest,
                            &grant_digest,
                        )
                        .map_err(trust_err)?;
                    return Err(trust_err(TrustError::new(
                        TrustReason::ChallengeReplayed,
                        "HIBE reader challenge has already been consumed",
                    )));
                }
                _ => {
                    return Err(trust_err(TrustError::new(
                        TrustReason::ChallengeReplayed,
                        "HIBE reader challenge has already been consumed",
                    )));
                }
            };
            store
                .check_hibe_grant_challenge(&challenge.challenge_id, &proof_digest, &grant_digest)
                .map_err(trust_err)?;
            enrollment::verify_key_binding_proof(
                &options.proof,
                &enrollment::ProofExpectation {
                    purpose: "hibe-reader".into(),
                    audience_did: self.tn.did().to_string(),
                    ceremony_id: enrollment::ceremony_id(self.tn)?,
                    group: options.group.clone(),
                    now: SystemTime::now(),
                },
                Some(&challenge),
            )
            .map_err(trust_err)?;
        }
        if delegated_subauthority {
            if !options.allow_subauthority {
                return Err(Error::InvalidArgument(format!(
                    "grant_reader_verified: id_path {:?} is an ancestor of the sealing \
                     path; an ancestor grant delegates the whole subtree and requires \
                     allow_subauthority=true",
                    options.id_path.as_deref().unwrap_or_default()
                )));
            }
            // Record the explicit subtree delegation; no API or event
            // presents an ancestor grant as an ordinary reader grant.
            let _ = self.tn.info(
                "hibe.subauthority.granted",
                json!({
                    "group": options.group,
                    "reader_did": options.reader_did,
                    "id_path": options.id_path,
                }),
            );
        }

        // Mint to a sibling staging path so nothing lands at out_path before
        // verification, labeling, and one-time consumption complete.
        let staging_path = staging_grant_path(&options.out_path);
        let minted = self.tn.runtime().admin_grant_reader(
            &options.group,
            Some(options.reader_did.as_str()),
            &staging_path,
            options.id_path.as_deref(),
        );
        let minted = match minted {
            Ok(result) => result,
            Err(error) => {
                let _ = fs::remove_file(&staging_path);
                return Err(error.into());
            }
        };
        let delivered = self.finish_grant_delivery(&options, &minted, delegated_subauthority);
        let _ = fs::remove_file(&staging_path);
        delivered
    }

    /// Verify sealing, stamp the Python-parity `hibe_grant` label where the
    /// body is plaintext, consume the challenge one-time, and atomically
    /// deliver the artifact to `out_path`.
    fn finish_grant_delivery(
        &self,
        options: &GrantReaderOptionsV1,
        minted: &GrantReaderResult,
        delegated_subauthority: bool,
    ) -> Result<GrantReaderResult> {
        let bytes = fs::read(&minted.path)?;
        let sealed = grant_bytes_are_sealed(&bytes)?;
        let final_bytes = if options.unsafe_plaintext {
            if sealed {
                // The runtime seals for every resolvable DID; a sealed
                // artifact is stronger than the requested plaintext, and a
                // sealed manifest cannot be relabeled without breaking its
                // wrap AAD. Deliver it unmodified.
                bytes
            } else {
                let device = enrollment::device_key(self.tn)?;
                tn_core::trusted_enrollment::label_hibe_grant_artifact(
                    &bytes,
                    &device,
                    "unsafe-plaintext-bearer",
                    delegated_subauthority,
                    &minted.id_path,
                    true,
                )
                .map_err(trust_err)?
            }
        } else {
            // Fail closed: a verified grant must leave recipient-sealed
            // bytes behind, never a plaintext bearer artifact.
            if !sealed {
                return Err(trust_err(TrustError::new(
                    TrustReason::BindingInvalid,
                    "grant artifact was not recipient-sealed; refusing plaintext delivery \
                     (use unsafe_plaintext=true only for the explicit compatibility path)",
                )));
            }
            bytes
        };
        if !options.unsafe_plaintext {
            // One-time challenge consumption: retained and committed under
            // the store lock before anything lands at out_path.
            let proof_digest = options.proof.digest().map_err(trust_err)?;
            let grant_digest = tn_core::trusted_enrollment::hibe_grant_digest(
                &proof_digest,
                &options.reader_did,
                &options.proof.ceremony_id,
                &options.group,
                &minted.id_path,
            )
            .map_err(trust_err)?;
            let store = enrollment::enrollment_store(self.tn)?;
            let bound_digest = options
                .proof
                .binding
                .get("challenge_digest")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let challenge = match store.resolve(bound_digest).map_err(trust_err)? {
                enrollment::ChallengeState::Retained(challenge)
                | enrollment::ChallengeState::Consumed(challenge) => challenge,
                _ => {
                    return Err(trust_err(TrustError::new(
                        TrustReason::ChallengeMissing,
                        "challenge digest is not retained",
                    )));
                }
            };
            store
                .commit_hibe_grant(
                    &challenge.challenge_id,
                    &tn_core::trusted_enrollment::HibeGrantConsumptionV1 {
                        proof_digest,
                        grant_digest,
                        artifact_digest: enrollment::sha256_tagged(&final_bytes),
                    },
                    &final_bytes,
                )
                .map_err(trust_err)?;
        }
        if let Some(parent) = options.out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        tn_core::keystore_backend::atomic_write_bytes(&options.out_path, &final_bytes)?;
        Ok(GrantReaderResult {
            group: minted.group.clone(),
            reader_did: minted.reader_did.clone(),
            id_path: minted.id_path.clone(),
            path: options.out_path.clone(),
        })
    }
}

pub(crate) fn register_jwe_offer_for_tn(
    tn: &Tn,
    group: &str,
    accepted: &enrollment::AcceptedOffer,
) -> Result<AddRecipientResult> {
    validate_jwe_offer_for_tn(tn, group, accepted)?;
    let principal = &accepted.binding.principal;
    persist_jwe_recipient(
        tn,
        group,
        &principal.did,
        &accepted.binding.public_key,
        Some(accepted),
    )?;
    Ok(AddRecipientResult {
        group: group.to_string(),
        recipient_did: Some(principal.did.clone()),
        leaf_index: 0,
        kit_path: PathBuf::new(),
    })
}

pub(crate) fn validate_jwe_offer_for_tn(
    tn: &Tn,
    group: &str,
    accepted: &enrollment::AcceptedOffer,
) -> Result<()> {
    require_jwe_group(tn, group)?;
    let principal = &accepted.binding.principal;
    if principal.audience_did != tn.did() {
        return Err(trust_err(TrustError::new(
            TrustReason::WrongRecipient,
            "accepted offer is addressed to a different publisher",
        )));
    }
    if principal.ceremony_id != enrollment::ceremony_id(tn)? || principal.group != group {
        return Err(trust_err(TrustError::new(
            TrustReason::ScopeMismatch,
            "accepted offer ceremony or group does not match",
        )));
    }
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let recipients_path = enrollment::keystore_dir(tn)?.join(format!("{group}.jwe.recipients"));
    load_compatible_jwe_recipients(
        &recipients_path,
        &principal.did,
        &B64.encode(accepted.binding.public_key),
    )?;
    Ok(())
}

fn persist_jwe_recipient(
    tn: &Tn,
    group: &str,
    reader_did: &str,
    public_key: &[u8; 32],
    accepted: Option<&enrollment::AcceptedOffer>,
) -> Result<()> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let keystore = enrollment::keystore_dir(tn)?;
    let public_key_sha256 = enrollment::sha256_tagged(public_key);
    store_jwe_recipient_list(
        &keystore.join(format!("{group}.jwe.recipients")),
        reader_did,
        &B64.encode(public_key),
    )?;
    if !store_jwe_trust_entry(
        &keystore.join("trust").join("jwe_recipients.v1.json"),
        group,
        reader_did,
        &public_key_sha256,
        accepted,
    )? {
        return Ok(());
    }
    tn.runtime().reload_group_cipher(group)?;
    attest_jwe_recipient(tn, group, reader_did, &public_key_sha256);
    Ok(())
}

fn store_jwe_recipient_list(path: &Path, reader_did: &str, public_b64: &str) -> Result<()> {
    let mut recipients = load_compatible_jwe_recipients(path, reader_did, public_b64)?;
    if recipients
        .iter()
        .any(|entry| entry.get("recipient_identity").and_then(Value::as_str) == Some(reader_did))
    {
        return Ok(());
    }
    recipients.push(json!({
        "recipient_identity": reader_did,
        "pub_b64": public_b64,
    }));
    tn_core::keystore_backend::atomic_write_bytes(path, &serde_json::to_vec(&recipients)?)?;
    Ok(())
}

fn load_compatible_jwe_recipients(
    path: &Path,
    reader_did: &str,
    public_b64: &str,
) -> Result<Vec<Value>> {
    let recipients: Vec<Value> = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else {
        Vec::new()
    };
    let existing = recipients
        .iter()
        .find(|entry| entry.get("recipient_identity").and_then(Value::as_str) == Some(reader_did));
    if existing
        .is_some_and(|entry| entry.get("pub_b64").and_then(Value::as_str) != Some(public_b64))
    {
        return Err(trust_err(TrustError::new(
            TrustReason::ReplayConflict,
            "a different X25519 key is already registered for this reader DID",
        )));
    }
    Ok(recipients)
}

fn store_jwe_trust_entry(
    path: &Path,
    group: &str,
    reader_did: &str,
    public_key_sha256: &str,
    accepted: Option<&enrollment::AcceptedOffer>,
) -> Result<bool> {
    let mut registry: Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else {
        json!({ "version": 1, "recipients": {} })
    };
    let group_map = jwe_trust_group(&mut registry, group)?;
    if group_map.get(reader_did).is_some_and(|previous| {
        previous.get("verified").and_then(Value::as_bool) == Some(true) && accepted.is_none()
    }) {
        return Ok(false);
    }
    let entry = match accepted {
        Some(accepted) => verified_jwe_trust_entry(accepted),
        None => json!({ "verified": false, "public_key_sha256": public_key_sha256 }),
    };
    group_map.insert(reader_did.to_string(), entry);
    tn_core::keystore_backend::atomic_write_bytes(path, &serde_json::to_vec(&registry)?)?;
    Ok(true)
}

fn jwe_trust_group<'a>(
    registry: &'a mut Value,
    group: &str,
) -> Result<&'a mut serde_json::Map<String, Value>> {
    let recipients = registry
        .get_mut("recipients")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::InvalidArgument("jwe recipient registry is malformed".into()))?;
    recipients
        .entry(group.to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            Error::InvalidArgument("jwe recipient registry group entry is malformed".into())
        })
}

fn verified_jwe_trust_entry(accepted: &enrollment::AcceptedOffer) -> Value {
    json!({
        "verified": true,
        "public_key_sha256": accepted.binding.public_key_sha256,
        "proof_digest": accepted.binding.proof_digest,
        "offer_digest": accepted.offer_digest,
        "artifact_digest": accepted.artifact_digest,
    })
}

fn attest_jwe_recipient(tn: &Tn, group: &str, reader_did: &str, key_digest: &str) {
    let _ = tn.info(
        "tn.recipient.added",
        json!({
            "group": group,
            "leaf_index": Value::Null,
            "recipient_identity": reader_did,
            "kit_sha256": key_digest,
            "cipher": "jwe",
        }),
    );
}

fn staging_grant_path(out_path: &Path) -> PathBuf {
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    let name = out_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("grant.tnpkg");
    parent.join(format!(".{name}.minting.{}", std::process::id()))
}

fn grant_bytes_are_sealed(bytes: &[u8]) -> Result<bool> {
    let (manifest, body) = tn_core::tnpkg::read_tnpkg(tn_core::tnpkg::TnpkgSource::Bytes(bytes))?;
    let has_wraps = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .and_then(Value::as_object)
        .is_some_and(|body_encryption| {
            body_encryption.contains_key("recipient_wraps")
                || body_encryption.contains_key("recipient_wrap")
        });
    Ok(has_wraps && body.contains_key("body/encrypted.bin"))
}

fn group_cipher(tn: &Tn, group: &str) -> Result<Option<String>> {
    let raw = fs::read_to_string(tn.yaml_path())?;
    let doc: serde_yml::Value = serde_yml::from_str(&raw)?;
    Ok(doc
        .get("groups")
        .and_then(|groups| groups.get(group))
        .and_then(|spec| spec.get("cipher"))
        .and_then(serde_yml::Value::as_str)
        .map(str::to_string))
}

fn require_jwe_group(tn: &Tn, group: &str) -> Result<()> {
    match group_cipher(tn, group)? {
        Some(cipher) if cipher == "jwe" => Ok(()),
        Some(cipher) => Err(Error::InvalidArgument(format!(
            "JWE group {group:?} uses cipher {cipher:?}"
        ))),
        None => Err(Error::InvalidArgument(format!(
            "JWE group {group:?} does not exist"
        ))),
    }
}

fn current_hibe_path(tn: &Tn, group: &str) -> Result<Option<String>> {
    let path = enrollment::keystore_dir(tn)?.join(format!("{group}.hibe.idpath"));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read_to_string(path)?.trim().to_string()))
}

fn is_path_ancestor(candidate: &str, path: &str) -> bool {
    path.strip_prefix(candidate)
        .is_some_and(|rest| rest.starts_with('/'))
}
