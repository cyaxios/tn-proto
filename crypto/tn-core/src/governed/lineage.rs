//! Bounded verification of exact signed computation parents and selected origins.

use std::collections::{BTreeMap, BTreeSet};

use super::data::base_contract;
use super::{invalid, DatasetBinding, DatasetCatalog, GovernanceView, PolicyDag};
use crate::Result;

/// The exact object identities reached by a successful lineage verification.
#[derive(Clone, Debug)]
pub struct VerifiedLineage {
    object_ids: Vec<String>,
    source_object_ids: Vec<String>,
}

impl VerifiedLineage {
    /// All verified publication identities, sorted for reproducible inspection.
    pub fn object_ids(&self) -> &[String] {
        &self.object_ids
    }

    /// Selected source publication identities reached by the signed graph.
    pub fn source_object_ids(&self) -> &[String] {
        &self.source_object_ids
    }
}

/// Follows retained publications without opening ancestor business groups.
///
/// The resolver supplies governance views accepted under the application's
/// writer trust rules. This verifier checks their exact identities, contract
/// continuity and selected origins; it does not grant a new permitted use.
#[derive(Clone, Debug)]
pub struct LineageVerifier {
    max_objects: usize,
    max_depth: usize,
}

impl Default for LineageVerifier {
    fn default() -> Self {
        Self {
            max_objects: 1024,
            max_depth: 64,
        }
    }
}

impl LineageVerifier {
    /// Bound resolver work and traversal depth independently of application input.
    pub fn new(max_objects: usize, max_depth: usize) -> Result<Self> {
        if max_objects == 0 || max_objects > 65536 || max_depth == 0 || max_depth > 256 {
            return Err(invalid(
                "lineage limits require 1..65536 objects and 1..256 depth",
            ));
        }
        Ok(Self {
            max_objects,
            max_depth,
        })
    }

    /// Verify exact parent identities, contract preservation, and selected origins.
    /// The resolver supplies only ancestor governance, never business plaintext.
    pub fn verify<F>(
        &self,
        view: &GovernanceView,
        catalog: &DatasetCatalog,
        dag: &PolicyDag,
        mut resolve: F,
    ) -> Result<VerifiedLineage>
    where
        F: FnMut(&str) -> Result<GovernanceView>,
    {
        let bindings = view.governance().dataset_bindings()?;
        for binding in &bindings {
            catalog.verify_binding(binding, dag)?;
        }
        let mut walk = Walk {
            limits: self,
            catalog,
            dag,
            origins: &bindings,
            resolve: &mut resolve,
            visiting: BTreeSet::new(),
            visited: BTreeMap::new(),
            heights: BTreeMap::new(),
            views: BTreeMap::new(),
        };
        walk.views
            .insert(view.object().id().to_owned(), view.clone());
        let roots = walk.visit(view, 0)?;
        let expected: BTreeSet<_> = bindings
            .iter()
            .map(|b| b.source_object_id().to_owned())
            .collect();
        if roots != expected {
            return Err(invalid(
                "declared dataset origins must be reached through signed parents",
            ));
        }
        Ok(VerifiedLineage {
            object_ids: walk.visited.into_keys().collect(),
            source_object_ids: roots.into_iter().collect(),
        })
    }
}

struct Walk<'a, F> {
    limits: &'a LineageVerifier,
    catalog: &'a DatasetCatalog,
    dag: &'a PolicyDag,
    origins: &'a [DatasetBinding],
    resolve: &'a mut F,
    visiting: BTreeSet<String>,
    visited: BTreeMap<String, BTreeSet<String>>,
    heights: BTreeMap<String, usize>,
    views: BTreeMap<String, GovernanceView>,
}

impl<F: FnMut(&str) -> Result<GovernanceView>> Walk<'_, F> {
    fn visit(&mut self, view: &GovernanceView, depth: usize) -> Result<BTreeSet<String>> {
        if depth > self.limits.max_depth {
            return Err(invalid("lineage depth limit exceeded"));
        }
        let id = view.object().id();
        if self.visiting.contains(id) {
            return Err(invalid("source lineage contains a cycle"));
        }
        if let Some(roots) = self.visited.get(id) {
            if depth + self.heights[id] > self.limits.max_depth {
                return Err(invalid("lineage depth limit exceeded"));
            }
            return Ok(roots.clone());
        }
        if self.views.len() > self.limits.max_objects {
            return Err(invalid("lineage object limit exceeded"));
        }
        self.visiting.insert(id.to_owned());
        let policies = view.governance().policies()?;
        let bindings = view.governance().dataset_bindings()?;
        for binding in &bindings {
            self.catalog.verify_binding(binding, self.dag)?;
        }

        let mut roots = BTreeSet::new();
        let mut height = 0;
        // A catalog selection is the explicit traversal boundary. It authenticates
        // the origin's complete contract without requiring its creation history.
        for binding in self.origins.iter().filter(|b| b.source_object_id() == id) {
            let edition = self
                .catalog
                .get(binding.edition_record_id())
                .ok_or_else(|| invalid("lineage origin requires its accepted edition record"))?;
            if view.object().writer() != edition.source_writer()
                || view.object().object_type() != edition.source_type()
                || !edition
                    .source_groups()
                    .iter()
                    .all(|group| view.object().group_names().contains(&group.as_str()))
                || policies.len() != edition.contracts().len()
            {
                return Err(invalid(
                    "selected origin must match its edition's source and contracts",
                ));
            }
            for binding in edition.contracts() {
                let expected = self
                    .dag
                    .select(binding.revision_id(), binding.scope(), |_| Ok(true))?;
                if !policies
                    .iter()
                    .any(|policy| base_contract(policy) == base_contract(&expected))
                {
                    return Err(invalid(
                        "selected origin contract differs from its accepted revision",
                    ));
                }
            }
            roots.insert(id.to_owned());
        }
        if roots.is_empty() {
            for reference in view.governance().source_references()? {
                let parent_id = reference.object_id();
                let parent = match self.views.get(parent_id) {
                    Some(parent) => parent.clone(),
                    None => {
                        if self.views.len() >= self.limits.max_objects {
                            return Err(invalid("lineage object limit exceeded"));
                        }
                        let parent = (self.resolve)(parent_id)?;
                        if parent.object().id() != parent_id {
                            return Err(invalid(
                                "lineage resolver returned a different publication",
                            ));
                        }
                        self.views.insert(parent_id.to_owned(), parent.clone());
                        parent
                    }
                };
                if !reference.references_with_policy(parent.object(), parent.governance())
                    || !reference
                        .groups()
                        .iter()
                        .all(|group| parent.object().group_names().contains(&group.as_str()))
                {
                    return Err(invalid(
                        "source reference must match the exact signed parent",
                    ));
                }
                for inherited in parent.governance().policies()? {
                    if !policies
                        .iter()
                        .any(|policy| base_contract(policy) == base_contract(&inherited))
                    {
                        return Err(invalid("child must retain every parent contract"));
                    }
                }
                for inherited in parent.governance().dataset_bindings()? {
                    if !bindings.contains(&inherited) {
                        return Err(invalid("child must retain every parent dataset binding"));
                    }
                }
                roots.extend(self.visit(&parent, depth + 1)?);
                height = height.max(self.heights[parent_id] + 1);
            }
            let declared: BTreeSet<_> = bindings
                .iter()
                .map(|b| b.source_object_id().to_owned())
                .collect();
            if roots != declared {
                return Err(invalid(
                    "dataset bindings must describe the reached origins",
                ));
            }
        }
        self.visiting.remove(id);
        self.heights.insert(id.to_owned(), height);
        self.visited.insert(id.to_owned(), roots.clone());
        Ok(roots)
    }
}
