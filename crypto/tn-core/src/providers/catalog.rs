use crate::governed::{DatasetSelection, GovernedObject, UseContext};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Dataset, edition and complete application use to resolve.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogRequest {
    /// Logical dataset name supplied by the caller.
    pub dataset: String,
    /// Explicit dataset edition supplied by the caller.
    pub edition: String,
    /// Complete application, purpose and operation.
    pub use_context: UseContext,
}
impl CatalogRequest {
    /// Construct a dataset edition request with nonempty identifiers.
    pub fn new(
        dataset: impl Into<String>,
        edition: impl Into<String>,
        use_context: UseContext,
    ) -> Result<Self> {
        let request = Self {
            dataset: dataset.into(),
            edition: edition.into(),
            use_context,
        };
        request.validate()?;
        Ok(request)
    }
    /// Validate exact request identifiers without changing their spelling.
    pub fn validate(&self) -> Result<()> {
        super::label(&self.dataset)?;
        super::label(&self.edition)
    }
}
#[derive(Clone)]
/// Accepted native selection paired with its exact source publication.
pub struct CatalogEntry {
    /// Exact signed publication, including its original wire bytes.
    pub publication: GovernedObject,
    /// Native accepted edition selection bound to source and use.
    pub selection: DatasetSelection,
}
impl CatalogEntry {
    /// Require the source identity, dataset, edition and complete use to match the request.
    pub fn validate(&self, request: &CatalogRequest) -> Result<()> {
        request.validate()?;
        if self.publication.id() != self.selection.source_object_id()
            || self.selection.record().dataset() != request.dataset
            || self.selection.record().edition() != request.edition
            || self.selection.use_context() != &request.use_context
        {
            return Err(Error::InvalidConfig(
                "catalog result differs from the requested edition, source or use".into(),
            ));
        }
        Ok(())
    }
}
/// Resolve an accepted edition and its exact publication.
pub trait CatalogProvider: Send + Sync {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, request: &CatalogRequest) -> Result<CatalogEntry>;
}
/// First adapter: retain already accepted native selections with exact publications.
#[derive(Default)]
pub struct EditionCatalog {
    entries: RwLock<BTreeMap<CatalogRequest, CatalogEntry>>,
}
impl EditionCatalog {
    /// Construct this typed provider value from explicit native configuration.
    pub fn new() -> Self {
        Self::default()
    }
    /// Retain an accepted exact edition; reject a duplicate dataset, edition and use.
    pub fn insert(&self, entry: CatalogEntry) -> Result<()> {
        let request = CatalogRequest {
            dataset: entry.selection.record().dataset().into(),
            edition: entry.selection.record().edition().into(),
            use_context: entry.selection.use_context().clone(),
        };
        entry.validate(&request)?;
        let mut entries = self.entries.write().map_err(|_| super::lock_error())?;
        if entries.contains_key(&request) {
            return Err(Error::InvalidConfig(
                "edition and use already registered; select a distinct edition explicitly".into(),
            ));
        }
        entries.insert(request, entry);
        Ok(())
    }
}
impl CatalogProvider for EditionCatalog {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, request: &CatalogRequest) -> Result<CatalogEntry> {
        request.validate()?;
        self.entries
            .read()
            .map_err(|_| super::lock_error())?
            .get(request)
            .cloned()
            .ok_or_else(|| Error::InvalidConfig("no edition for the requested use".into()))
    }
}
