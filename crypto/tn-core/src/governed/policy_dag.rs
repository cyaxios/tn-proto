//! Application-approved, append-only policy history with explicit selection.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::agents_policy::REQUIRED_FIELDS;
use crate::{Error, Result};

use super::revision::invalid_revision;
use super::{Governance, PolicyParent, PolicyRevision};

/// Accepted policy revisions. Parents must be admitted before children.
///
/// Nodes are immutable and cannot be replaced. Requiring already accepted
/// parents preserves a DAG by construction without recursion or implicit
/// version selection. Rebuild history by reopening retained signed revision
/// objects and admitting them in parent-first order under current trust rules.
#[derive(Debug, Default, Clone)]
pub struct PolicyDag {
    revisions: BTreeMap<String, PolicyRevision>,
}

impl PolicyDag {
    /// Start an empty accepted history.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of accepted revision objects.
    pub fn len(&self) -> usize {
        self.revisions.len()
    }
    /// Whether the accepted history is empty.
    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }
    /// Read an already accepted revision by its exact row hash.
    pub fn get(&self, revision_id: &str) -> Option<&PolicyRevision> {
        self.revisions.get(revision_id)
    }

    /// Atomically admit a revision after parent resolution and authority checks.
    ///
    /// The callback runs once with `None` for a root, or once for each parent
    /// with its signed edge and accepted revision. It must approve the writer,
    /// governing authority, scope, and policy change for that root/edge. Every
    /// callback must return `true`. This checks the application's explicit
    /// decision; policy text is interpreted by the application. Callback errors
    /// propagate and the DAG changes only after every check succeeds.
    pub fn admit<F>(&mut self, revision: PolicyRevision, mut authorize: F) -> Result<()>
    where
        F: FnMut(&PolicyRevision, Option<(&PolicyParent, &PolicyRevision)>) -> Result<bool>,
    {
        if self.revisions.contains_key(revision.id()) {
            return Err(invalid_revision(
                "revision already admitted; accepted history is immutable",
            ));
        }
        let mut parents = Vec::with_capacity(revision.parents().len());
        for edge in revision.parents() {
            let parent = self
                .revisions
                .get(edge.revision_id())
                .ok_or_else(|| invalid_revision("admit every parent before its child revision"))?;
            parents.push((edge, parent));
        }
        let denied = || Error::UseDenied {
            operation: "policy.update".to_owned(),
        };
        if parents.is_empty() {
            if !authorize(&revision, None)? {
                return Err(denied());
            }
        } else {
            for parent in parents {
                if !authorize(&revision, Some(parent))? {
                    return Err(denied());
                }
            }
        }
        self.revisions.insert(revision.id().to_owned(), revision);
        Ok(())
    }

    /// Select an exact accepted revision and scope for a new governed object.
    ///
    /// The application approves applicability using its current accepted state
    /// and operation requirements. No timestamp, highest version, or branch tip
    /// is selected implicitly. The returned contract carries `policy_revision`
    /// inside encrypted, signed `tn.agents`; the existing AAD remains unchanged.
    pub fn select<F>(&self, revision_id: &str, scope: &str, applicable: F) -> Result<Governance>
    where
        F: FnOnce(&PolicyRevision) -> Result<bool>,
    {
        let revision = self.in_scope(revision_id, scope)?;
        if !applicable(revision)? {
            return Err(Error::UseDenied {
                operation: "policy.select".to_owned(),
            });
        }
        let mut governance = revision.governance().clone();
        governance.fields.insert(
            "policy_revision".to_owned(),
            Value::String(revision.id().to_owned()),
        );
        Ok(governance)
    }

    /// Resolve a carried revision binding against this accepted history.
    /// Checks exact scope, governing authority, policy reference, and all five
    /// contract fields. Computation lineage and other extensions remain carried
    /// with the object. The application separately admits the intended use.
    pub fn resolve(&self, governance: &Governance, scope: &str) -> Result<&PolicyRevision> {
        let id = governance
            .revision_id()
            .ok_or_else(|| invalid_revision("contract requires a policy_revision identity"))?;
        let revision = self.in_scope(id, scope)?;
        let expected = revision.governance();
        if governance.governed_by() != expected.governed_by()
            || governance.policy_ref() != expected.policy_ref()
            || REQUIRED_FIELDS
                .iter()
                .any(|field| governance.get(field) != expected.get(field))
        {
            return Err(invalid_revision(
                "carried contract must match its accepted policy revision",
            ));
        }
        Ok(revision)
    }

    fn in_scope(&self, revision_id: &str, scope: &str) -> Result<&PolicyRevision> {
        let revision = self
            .revisions
            .get(revision_id)
            .ok_or_else(|| invalid_revision("select an admitted revision by its exact identity"))?;
        if revision.scope() != scope {
            return Err(invalid_revision(
                "selected revision must match the requested scope",
            ));
        }
        Ok(revision)
    }
}
