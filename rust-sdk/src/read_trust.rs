//! Receiver-local trust providers for secure-default reads.
//!
//! Providers snapshot exact canonical writer DIDs when they are constructed.
//! Read scans therefore never consult mutable process-global state or reload a
//! trust file midway through a page.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tn_core::runtime::ReadContext;

use crate::{Error, Result};

/// Receiver-local source that authorized an exact writer DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    /// The active ceremony's own device identity.
    LocalDevice,
    /// A publisher installed by a verified enrollment package.
    VerifiedPackage,
    /// An exact DID listed in `trust.writers` in `tn.yaml`.
    ExplicitConfig,
}

/// Immutable writer-trust boundary consulted once for each read policy.
pub trait ReadTrustProvider: Send + Sync {
    /// Return the exact canonical Ed25519 writer DIDs trusted in `context`.
    fn trusted_writer_dids(&self, context: &ReadContext) -> BTreeSet<String>;

    /// Return the source that authorized `did`, if it is trusted.
    fn source_for(&self, did: &str) -> Option<TrustSource>;
}

/// Immutable exact-DID provider useful for application policy and tests.
#[derive(Debug, Clone)]
pub struct InMemoryReadTrustProvider {
    entries: BTreeMap<String, TrustSource>,
}

impl InMemoryReadTrustProvider {
    /// Validate and snapshot `(writer DID, source)` entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any DID is not a canonical
    /// Ed25519 `did:key`.
    pub fn new(entries: impl IntoIterator<Item = (String, TrustSource)>) -> Result<Self> {
        let mut exact = BTreeMap::new();
        for (did, source) in entries {
            validate_writer_did(&did)?;
            exact.insert(did, source);
        }
        Ok(Self { entries: exact })
    }
}

impl ReadTrustProvider for InMemoryReadTrustProvider {
    fn trusted_writer_dids(&self, _context: &ReadContext) -> BTreeSet<String> {
        self.entries.keys().cloned().collect()
    }

    fn source_for(&self, did: &str) -> Option<TrustSource> {
        self.entries.get(did).copied()
    }
}

/// Snapshot of local device, config, and verified-package writer trust.
#[derive(Debug, Clone)]
pub struct ConfigReadTrustProvider {
    inner: InMemoryReadTrustProvider,
}

impl ConfigReadTrustProvider {
    /// Load receiver-local trust for one ceremony YAML.
    ///
    /// Precedence is local device, then verified package, then explicit
    /// config. Malformed trust files fail closed instead of loading a partial
    /// allowlist.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed YAML, invalid/duplicate configured DIDs,
    /// or a malformed verified-publisher record.
    pub fn load(yaml_path: impl AsRef<Path>) -> Result<Self> {
        let yaml_path = yaml_path.as_ref();
        let config = tn_core::config::load(yaml_path)?;
        let mut entries = BTreeMap::new();

        for did in config.trust.writers {
            validate_writer_did(&did)?;
            entries.insert(did, TrustSource::ExplicitConfig);
        }

        let yaml_dir = yaml_path.parent().unwrap_or_else(|| Path::new("."));
        let keystore = resolve_relative(yaml_dir, &config.keystore.path);
        let verified_path = keystore.join("trust").join("verified_publishers.v1.json");
        for did in verified_publisher_dids(&verified_path)? {
            entries.insert(did, TrustSource::VerifiedPackage);
        }

        validate_writer_did(&config.device.device_identity)?;
        entries.insert(config.device.device_identity, TrustSource::LocalDevice);

        Ok(Self {
            inner: InMemoryReadTrustProvider { entries },
        })
    }
}

impl ReadTrustProvider for ConfigReadTrustProvider {
    fn trusted_writer_dids(&self, context: &ReadContext) -> BTreeSet<String> {
        self.inner.trusted_writer_dids(context)
    }

    fn source_for(&self, did: &str) -> Option<TrustSource> {
        self.inner.source_for(did)
    }
}

fn validate_writer_did(did: &str) -> Result<()> {
    tn_core::trust::parse_ed25519_did_key(did).map_err(|_| {
        Error::InvalidArgument(format!(
            "trusted writer must be a canonical Ed25519 did:key; got {did:?}"
        ))
    })?;
    Ok(())
}

fn resolve_relative(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn verified_publisher_dids(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let document: Value = serde_json::from_str(&fs::read_to_string(path)?).map_err(|error| {
        Error::InvalidArgument(format!(
            "invalid verified publisher record in {}: {error}",
            path.display()
        ))
    })?;
    let root = document.as_object().ok_or_else(|| {
        Error::InvalidArgument(format!(
            "invalid verified publisher record in {}: expected an object",
            path.display()
        ))
    })?;
    let publishers = match root.get("publishers") {
        Some(value) => value.as_object().ok_or_else(|| {
            Error::InvalidArgument(format!(
                "invalid verified publisher record in {}: publishers must be an object",
                path.display()
            ))
        })?,
        None => root,
    };

    let mut dids = BTreeSet::new();
    for (did, metadata) in publishers {
        if !metadata.is_object() {
            return Err(Error::InvalidArgument(format!(
                "invalid verified publisher record in {}: {did:?} metadata must be an object",
                path.display()
            )));
        }
        validate_writer_did(did).map_err(|error| {
            Error::InvalidArgument(format!(
                "invalid verified publisher record in {}: {error}",
                path.display()
            ))
        })?;
        dids.insert(did.clone());
    }
    Ok(dids)
}
