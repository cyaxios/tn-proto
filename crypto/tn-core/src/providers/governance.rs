use super::ApplicationIdentity;
use crate::governed::{
    AdmissionContext, AttachmentContext, Governance, ReleaseContext, UseContext,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

/// Object type and complete use requesting an origination contract.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyRequest {
    /// Signed object type selected for origination.
    pub object_type: String,
    /// Complete application, purpose and operation.
    pub use_context: UseContext,
}
/// Complete input and output uses for an application workflow.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkflowRequest {
    /// Use to accept before opening input data.
    pub input: UseContext,
    /// Use to authorize when publishing results.
    pub output: UseContext,
}
#[derive(Clone)]
/// Signed object type and business groups opened by an input route.
pub struct InputRule {
    /// Signed object type, or any type when an optional route is absent.
    pub object_type: Option<String>,
    /// Business groups opened after governance acceptance.
    pub groups: Vec<String>,
}
#[derive(Clone)]
/// Input routes and publication settings returned by governance.
pub struct WorkflowPolicy {
    /// Receiving routes, each with its selected business groups.
    pub inputs: Vec<InputRule>,
    /// Signed type assigned to a released result.
    pub output_type: String,
    /// Resolved destination or audience for release.
    pub destination: String,
}
impl PolicyRequest {
    /// Construct a request for a valid signed object type and complete use.
    pub fn new(object_type: impl Into<String>, use_context: UseContext) -> Result<Self> {
        let request = Self {
            object_type: object_type.into(),
            use_context,
        };
        request.validate()?;
        Ok(request)
    }
    /// Validate callers that construct or modify the public Rust fields directly.
    pub fn validate(&self) -> Result<()> {
        crate::governed::validate_name(&self.object_type)
    }
}
impl WorkflowRequest {
    /// Construct input and output uses belonging to the same application.
    pub fn new(input: UseContext, output: UseContext) -> Result<Self> {
        let request = Self { input, output };
        request.validate()?;
        Ok(request)
    }
    /// Require a single application to own this workflow's two uses.
    pub fn validate(&self) -> Result<()> {
        if self.input.application() != self.output.application() {
            return Err(Error::InvalidConfig(
                "workflow uses must belong to the same application".into(),
            ));
        }
        Ok(())
    }
}
impl InputRule {
    /// Construct a unique selection of business groups for an optional signed type.
    pub fn new(groups: Vec<String>, object_type: Option<String>) -> Result<Self> {
        let rule = Self {
            groups,
            object_type,
        };
        rule.validate()?;
        Ok(rule)
    }
    /// Reject empty, repeated and reserved business group selections.
    pub fn validate(&self) -> Result<()> {
        if let Some(name) = &self.object_type {
            crate::governed::validate_name(name)?;
        }
        if self.groups.is_empty() {
            return Err(Error::InvalidConfig(
                "input route requires business groups".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for group in &self.groups {
            crate::governed::validate_group(group)?;
            if group == crate::governed::GOVERNANCE_GROUP || !seen.insert(group) {
                return Err(Error::InvalidConfig(
                    "input route requires unique business groups; governance is automatic".into(),
                ));
            }
        }
        Ok(())
    }
}
impl WorkflowPolicy {
    /// Construct input routes and the type and destination for publication.
    pub fn new(
        inputs: Vec<InputRule>,
        output_type: impl Into<String>,
        destination: impl Into<String>,
    ) -> Result<Self> {
        let policy = Self {
            inputs,
            output_type: output_type.into(),
            destination: destination.into(),
        };
        policy.validate()?;
        Ok(policy)
    }
    /// Check all routes and publication settings before registering the workflow.
    pub fn validate(&self) -> Result<()> {
        crate::governed::validate_name(&self.output_type)?;
        super::label(&self.destination)?;
        if self.inputs.is_empty() {
            return Err(Error::InvalidConfig(
                "workflow requires input routes".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for rule in &self.inputs {
            rule.validate()?;
            if !seen.insert(&rule.object_type) {
                return Err(Error::InvalidConfig(
                    "workflow contains duplicate input routes".into(),
                ));
            }
        }
        Ok(())
    }
}
/// Resolve contracts and evaluate acceptance, attachment and release.
pub trait GovernanceProvider: Send + Sync {
    /// Resolve the default origination contract for the exact requested use and type.
    fn policy(&self, request: &PolicyRequest) -> Result<Governance>;
    /// Resolve input routes and output publication settings for both requested uses.
    fn workflow(&self, request: &WorkflowRequest) -> Result<WorkflowPolicy>;
    /// Decide whether to accept the complete carried contract set before opening data.
    fn accept(&self, context: &AdmissionContext<'_>) -> Result<bool>;
    /// Decide whether the requesting authority may add the proposed contract.
    fn attach(&self, context: &AttachmentContext<'_>) -> Result<bool>;
    /// Decide whether the complete carried contract set permits this publication.
    fn release(&self, context: &ReleaseContext<'_>) -> Result<bool>;
}
/// First adapter: an explicitly provisioned directory of contracts and complete uses.
/// It evaluates listed contracts and uses, not natural-language policy interpretation.
#[derive(Default)]
pub struct PolicyDirectory {
    policies: RwLock<BTreeMap<PolicyRequest, Governance>>,
    workflows: RwLock<BTreeMap<WorkflowRequest, WorkflowPolicy>>,
    writers: RwLock<BTreeSet<String>>,
    accepted: RwLock<Vec<(UseContext, Governance)>>,
}
impl PolicyDirectory {
    /// Construct this typed provider value from explicit native configuration.
    pub fn new() -> Self {
        Self::default()
    }
    /// Accept this resolved signing identity for local governance decisions.
    pub fn trust(&self, identity: &ApplicationIdentity) -> Result<()> {
        self.writers
            .write()
            .map_err(|_| super::lock_error())?
            .insert(identity.did().into());
        Ok(())
    }
    /// Set an origination default and approve that exact contract for the requested use.
    pub fn add_policy(&self, request: &PolicyRequest, policy: Governance) -> Result<()> {
        if policy.selected_object_type() != Some(request.object_type.as_str()) {
            return Err(Error::InvalidConfig(
                "policy must select the requested object type".into(),
            ));
        }
        let mut policies = self.policies.write().map_err(|_| super::lock_error())?;
        request.validate()?;
        let key = request.clone();
        if policies.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "policy request already registered".into(),
            ));
        }
        self.approve_contract(request, policy.clone())?;
        policies.insert(key, policy);
        Ok(())
    }
    /// Register the complete workflow once; duplicate requests are rejected.
    pub fn add_workflow(&self, request: &WorkflowRequest, policy: WorkflowPolicy) -> Result<()> {
        let mut plans = self.workflows.write().map_err(|_| super::lock_error())?;
        request.validate()?;
        policy.validate()?;
        let key = request.clone();
        if plans.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "workflow request already registered".into(),
            ));
        }
        plans.insert(key, policy);
        Ok(())
    }
    /// Accept an additional exact contract for a use without replacing the origination default.
    pub fn approve_contract(&self, request: &PolicyRequest, policy: Governance) -> Result<()> {
        if policy.selected_object_type() != Some(request.object_type.as_str()) {
            return Err(Error::InvalidConfig(
                "contract must select the requested object type".into(),
            ));
        }
        let mut accepted = self.accepted.write().map_err(|_| super::lock_error())?;
        if !accepted
            .iter()
            .any(|(u, p)| u == &request.use_context && p == &policy)
        {
            accepted.push((request.use_context.clone(), policy));
        }
        Ok(())
    }
    fn allowed(&self, policies: &[Governance], use_context: &UseContext) -> Result<bool> {
        let known = self.accepted.read().map_err(|_| super::lock_error())?;
        Ok(!policies.is_empty()
            && policies.iter().all(|p| {
                known
                    .iter()
                    .any(|(u, accepted)| u == use_context && p == accepted)
            }))
    }
}
impl GovernanceProvider for PolicyDirectory {
    /// Resolve the default origination contract for the exact requested use and type.
    fn policy(&self, request: &PolicyRequest) -> Result<Governance> {
        request.validate()?;
        self.policies
            .read()
            .map_err(|_| super::lock_error())?
            .get(request)
            .cloned()
            .ok_or_else(|| Error::InvalidConfig("no applicable policy".into()))
    }
    /// Resolve input routes and output publication settings for both requested uses.
    fn workflow(&self, request: &WorkflowRequest) -> Result<WorkflowPolicy> {
        request.validate()?;
        self.workflows
            .read()
            .map_err(|_| super::lock_error())?
            .get(request)
            .cloned()
            .ok_or_else(|| Error::InvalidConfig("no applicable workflow".into()))
    }
    /// Decide whether to accept the complete carried contract set before opening data.
    fn accept(&self, context: &AdmissionContext<'_>) -> Result<bool> {
        let Some(use_context) = context.use_context() else {
            return Ok(false);
        };
        Ok(self
            .writers
            .read()
            .map_err(|_| super::lock_error())?
            .contains(context.object().writer())
            && self.allowed(&context.policies()?, use_context)?)
    }
    /// Decide whether the requesting authority may add the proposed contract.
    fn attach(&self, context: &AttachmentContext<'_>) -> Result<bool> {
        Ok(self
            .writers
            .read()
            .map_err(|_| super::lock_error())?
            .contains(context.authority())
            && self
                .accepted
                .read()
                .map_err(|_| super::lock_error())?
                .iter()
                .any(|(_, p)| p == context.policy()))
    }
    /// Decide whether the complete carried contract set permits this publication.
    fn release(&self, context: &ReleaseContext<'_>) -> Result<bool> {
        let Some(use_context) = context.use_context() else {
            return Ok(false);
        };
        Ok(self
            .writers
            .read()
            .map_err(|_| super::lock_error())?
            .contains(context.writer())
            && self.allowed(&context.data().policies()?, use_context)?)
    }
}
