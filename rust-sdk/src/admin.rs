//! Ceremony administration helpers.

use std::path::{Path, PathBuf};

use crate::tn::Tn;
use crate::Result;

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
}
