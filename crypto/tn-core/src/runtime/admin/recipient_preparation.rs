use std::collections::HashSet;

use crate::runtime::Runtime;
use crate::{Error, Result};

/// Read-only partition of groups requested for recipient preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPreparationPlan {
    /// Deduplicated requested groups in caller order.
    pub requested_groups: Vec<String>,
    /// BTN and HIBE groups that produce a reader kit bundle.
    pub kit_groups: Vec<String>,
    /// JWE groups that require public-only enrollment activation artifacts.
    pub jwe_groups: Vec<String>,
}

impl Runtime {
    /// Validate and partition groups without minting keys or writing packages.
    pub fn plan_recipient_preparation(
        &self,
        groups: Option<&[&str]>,
    ) -> Result<RecipientPreparationPlan> {
        let requested_groups = self.resolve_preparation_groups(groups)?;
        let mut kit_groups = Vec::new();
        let mut jwe_groups = Vec::new();
        for group in &requested_groups {
            let cipher = self.cfg.groups[group].cipher.as_str();
            match cipher {
                "btn" | "hibe" => kit_groups.push(group.clone()),
                "jwe" | "bearer" => jwe_groups.push(group.clone()),
                other => return Err(unknown_cipher(group, other)),
            }
        }
        Ok(RecipientPreparationPlan {
            requested_groups,
            kit_groups,
            jwe_groups,
        })
    }

    fn resolve_preparation_groups(&self, groups: Option<&[&str]>) -> Result<Vec<String>> {
        let source: Vec<&str> = match groups {
            Some(groups) => groups.to_vec(),
            None => self
                .cfg
                .groups
                .keys()
                .filter(|group| group.as_str() != "tn.agents")
                .map(String::as_str)
                .collect(),
        };
        let mut seen = HashSet::new();
        let mut requested = Vec::new();
        for group in source {
            if !self.cfg.groups.contains_key(group) {
                return Err(unknown_group(group, self.cfg.groups.keys()));
            }
            if seen.insert(group.to_string()) {
                requested.push(group.to_string());
            }
        }
        if requested.is_empty() {
            return Err(Error::InvalidConfig(
                "prepare_recipient: no non-internal groups to prepare".into(),
            ));
        }
        Ok(requested)
    }
}

fn unknown_group<'a>(group: &str, declared: impl Iterator<Item = &'a String>) -> Error {
    Error::InvalidConfig(format!(
        "prepare_recipient: unknown group {group:?}; this ceremony declares {:?}",
        declared.collect::<Vec<_>>()
    ))
}

fn unknown_cipher(group: &str, cipher: &str) -> Error {
    Error::InvalidConfig(format!(
        "prepare_recipient: group {group:?} uses unknown cipher {cipher:?}"
    ))
}
