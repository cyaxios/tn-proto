//! Secure-default read options and `Tn` read methods.

use std::collections::BTreeSet;
use std::sync::Arc;

use tn_core::runtime::{ReadContext, ReadCursorV1, ReadTrustPolicy, SecureReadOptions, VerifyMode};

use super::Tn;
use crate::entry::Entry;
use crate::read_trust::ReadTrustProvider;
use crate::{Error, Result};

/// Options for [`Tn::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOptions {
    /// Include entries from every run in the log instead of only this process.
    pub all_runs: bool,
    /// Verify integrity and writer trust. The secure default is `true`.
    pub verify: bool,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            all_runs: false,
            verify: true,
        }
    }
}

/// Advanced policy controls for secure reads and resumable pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPolicyOptions {
    /// Include entries from every run in the log instead of only this process.
    pub all_runs: bool,
    /// Verification behavior. [`VerifyMode::Auto`] is the fail-closed default.
    pub verify: VerifyMode,
    /// Require a writer signature, or infer it from the active profile.
    pub require_signature: Option<bool>,
    /// Permit records without a signature, or infer the complement of
    /// `require_signature` from the active profile.
    pub allow_unauthenticated: Option<bool>,
    /// Exact per-call writer allowlist. When present, this replaces the
    /// receiver-local trust provider's snapshot.
    pub trusted_writers: Option<BTreeSet<String>>,
    /// Permit writers outside the frozen allowlist without marking them as
    /// authorized.
    pub allow_unknown_writers: bool,
}

impl Default for ReadPolicyOptions {
    fn default() -> Self {
        Self {
            all_runs: false,
            verify: VerifyMode::Auto,
            require_signature: None,
            allow_unauthenticated: None,
            trusted_writers: None,
            allow_unknown_writers: false,
        }
    }
}

impl From<ReadOptions> for ReadPolicyOptions {
    fn from(options: ReadOptions) -> Self {
        Self {
            all_runs: options.all_runs,
            verify: if options.verify {
                VerifyMode::Auto
            } else {
                VerifyMode::Disabled
            },
            ..Self::default()
        }
    }
}

/// Materialized secure-read page plus accounting and its lossless cursor.
pub type ReadReport = tn_core::runtime::ReadReport<Entry>;

impl Tn {
    /// Read decrypted entries from the active log.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the log cannot be read, authenticated, authorized,
    /// or decrypted under the requested policy.
    pub fn read(&self, options: ReadOptions) -> Result<Vec<Entry>> {
        self.read_with_policy(options.into())
    }

    /// Read with advanced verification, signature, and writer-trust controls.
    pub fn read_with_policy(&self, options: ReadPolicyOptions) -> Result<Vec<Entry>> {
        self.read_with_policy_options(&options)
            .map(|report| report.entries)
    }

    /// Read under the stable options and return accounting plus a cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for an invalid policy or a rejected source record.
    pub fn read_with_options(&self, options: &ReadOptions) -> Result<ReadReport> {
        self.read_with_policy_options(&(*options).into())
    }

    /// Read under advanced controls and return accounting plus a cursor.
    pub fn read_with_policy_options(&self, options: &ReadPolicyOptions) -> Result<ReadReport> {
        self.validate_read_policy_options(options)?;
        crate::security_warning::warn_and_audit_read_weakening(
            self,
            options,
            tn_core::UnsafeOperation::Read,
        );
        self.read_policy_page(options, None)
    }

    /// Resume an advanced read from a previously returned lossless cursor.
    pub fn read_from_cursor(
        &self,
        options: &ReadPolicyOptions,
        cursor: &ReadCursorV1,
    ) -> Result<ReadReport> {
        self.validate_read_policy_options(options)?;
        crate::security_warning::warn_and_audit_read_weakening(
            self,
            options,
            tn_core::UnsafeOperation::Read,
        );
        self.read_policy_page(options, Some(cursor))
    }

    pub(crate) fn read_with_options_from_cursor(
        &self,
        options: &ReadOptions,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport> {
        let policy = ReadPolicyOptions::from(*options);
        self.validate_read_policy_options(&policy)?;
        self.read_policy_page(&policy, cursor)
    }

    fn read_policy_page(
        &self,
        options: &ReadPolicyOptions,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport> {
        let context = self.read_context();
        let policy = self.read_policy(options, &context);
        let report = self.runtime.read_with_policy(
            &SecureReadOptions::default(),
            &policy,
            &context,
            cursor,
        )?;
        Ok(self.sdk_read_report(options, report))
    }

    pub(crate) fn warn_and_audit_watch_weakening(&self, options: &ReadOptions) -> Result<()> {
        let policy = ReadPolicyOptions::from(*options);
        self.validate_read_policy_options(&policy)?;
        crate::security_warning::warn_and_audit_read_weakening(
            self,
            &policy,
            tn_core::UnsafeOperation::Watch,
        );
        Ok(())
    }

    fn read_context(&self) -> ReadContext {
        self.runtime.local_read_context()
    }

    fn read_policy(&self, options: &ReadPolicyOptions, context: &ReadContext) -> ReadTrustPolicy {
        let trusted_writers = options.trusted_writers.clone().unwrap_or_else(|| {
            self.read_trust_provider
                .read()
                .expect("read-trust provider lock poisoned")
                .trusted_writer_dids(context)
        });
        ReadTrustPolicy {
            verify: options.verify,
            require_signature: options.require_signature,
            allow_unauthenticated: options.allow_unauthenticated,
            trusted_writers,
            trusted_writers_supplied: options.trusted_writers.is_some(),
            allow_unknown_writers: options.allow_unknown_writers,
        }
    }

    fn sdk_read_report(
        &self,
        options: &ReadPolicyOptions,
        report: tn_core::runtime::ReadReport<tn_core::runtime::FlatEntry>,
    ) -> ReadReport {
        let mut entries: Vec<Entry> = report.entries.into_iter().map(Entry::from).collect();
        if !options.all_runs {
            entries.retain(|entry| entry.run_id() == Some(self.runtime.run_id()));
        }
        let yielded = entries.len();
        ReadReport {
            entries,
            scanned: report.scanned,
            yielded,
            skipped: report.skipped,
            cursor: report.cursor,
        }
    }

    fn validate_read_policy_options(&self, options: &ReadPolicyOptions) -> Result<()> {
        if options.verify == VerifyMode::Disabled && options.trusted_writers.is_some() {
            return Err(Error::InvalidArgument(
                "verify=Disabled cannot be combined with trusted_writers".into(),
            ));
        }
        validate_signature_options(options)?;
        validate_trusted_writers(options)
    }

    /// Replace this handle's receiver-local writer-trust provider.
    pub fn set_read_trust_provider(&mut self, provider: Arc<dyn ReadTrustProvider>) {
        *self
            .read_trust_provider
            .write()
            .expect("read-trust provider lock poisoned") = provider;
    }

    /// Atomically refresh config and installed-publisher trust between reads.
    pub(crate) fn reload_read_trust_provider(&self) -> Result<()> {
        let provider: Arc<dyn ReadTrustProvider> = Arc::new(
            crate::read_trust::ConfigReadTrustProvider::load(self.yaml_path())?,
        );
        *self
            .read_trust_provider
            .write()
            .expect("read-trust provider lock poisoned") = provider;
        Ok(())
    }
}

fn validate_signature_options(options: &ReadPolicyOptions) -> Result<()> {
    let (Some(require), Some(allow)) = (options.require_signature, options.allow_unauthenticated)
    else {
        return Ok(());
    };
    if require != allow {
        return Ok(());
    }
    Err(Error::InvalidArgument(
        "require_signature and allow_unauthenticated must express one consistent policy".into(),
    ))
}

fn validate_trusted_writers(options: &ReadPolicyOptions) -> Result<()> {
    let Some(writers) = &options.trusted_writers else {
        return Ok(());
    };
    for did in writers {
        tn_core::trust::parse_ed25519_did_key(did).map_err(|_| {
            Error::InvalidArgument(format!(
                "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
            ))
        })?;
    }
    Ok(())
}
