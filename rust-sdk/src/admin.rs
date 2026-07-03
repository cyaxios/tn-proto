//! Ceremony administration helpers.

use std::path::{Path, PathBuf};

use crate::tn::Tn;
use crate::Result;

pub use tn_core::EnsureGroupResult;

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
