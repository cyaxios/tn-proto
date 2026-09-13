//! Application-facing governed sessions with reusable admission configuration.
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use super::Objects;
use crate::governed::{
    AdmissionContext, AttachmentContext, DataObject, DatasetSelection, Governance, GovernedObject,
    ReleaseContext, UseContext,
};
use crate::{Error, Result};

type Decision = dyn Fn(&AdmissionContext<'_>) -> Result<bool> + Send + Sync;

type AttachmentDecision = dyn Fn(&AttachmentContext<'_>) -> Result<bool> + Send + Sync;
type ReleaseDecision = dyn Fn(&ReleaseContext<'_>) -> Result<bool> + Send + Sync;

/// Immutable settings for a configured output purpose.
pub struct ReleasePlan {
    use_context: UseContext,
    destination: String,
    object_type: String,
    decide: Arc<ReleaseDecision>,
}
impl ReleasePlan {
    /// Complete application use attached to the released object.
    pub fn use_context(&self) -> &UseContext {
        &self.use_context
    }
    /// Configured output destination.
    pub fn destination(&self) -> &str {
        &self.destination
    }
    /// Configured output object type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }
    /// Check the configured decision against matching release settings.
    pub fn authorize(&self, context: &ReleaseContext<'_>) -> Result<bool> {
        if context.use_context() != Some(&self.use_context)
            || context.destination() != self.destination
            || context.object_type() != self.object_type
        {
            return Ok(false);
        }
        (self.decide)(context)
    }
}

struct ReceiveRoute {
    use_context: UseContext,
    groups: Vec<String>,
    decide: Arc<Decision>,
}

/// A value that can supply an exact signed publication for receipt.
pub trait Publication {
    /// Return the signed object; unpublished working changes must be released first.
    fn publication(&self) -> Result<&GovernedObject>;
}
impl Publication for GovernedObject {
    fn publication(&self) -> Result<&GovernedObject> {
        Ok(self)
    }
}
impl Publication for DataObject {
    fn publication(&self) -> Result<&GovernedObject> {
        if self.has_unreleased_changes() {
            return Err(Error::InvalidConfig(
                "release working changes before receiving this object".into(),
            ));
        }
        self.snapshot()
            .ok_or_else(|| Error::InvalidConfig("object has no signed publication".into()))
    }
}

/// Independent session. Configure each receiving purpose once during application setup.
/// Protocol primitives remain available through [`Self::objects`].
pub struct Session<'a> {
    objects: Arc<Objects<'a>>,
    routes: RwLock<BTreeMap<(String, Option<String>), Arc<ReceiveRoute>>>,
    releases: RwLock<BTreeMap<String, Arc<ReleasePlan>>>,
    attachment: RwLock<Option<Arc<AttachmentDecision>>>,
}
impl Session<'static> {
    /// Create an independent in-memory session with a default business group.
    pub fn ephemeral(policy: &str) -> Result<Self> {
        Ok(Self::new(Objects::ephemeral(
            policy,
            "agents.md",
            &["default"],
        )?))
    }
    /// Load identity, group material and policies from existing configuration.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        Ok(Self::new(Objects::open(path)?))
    }
}
impl<'a> Session<'a> {
    /// Use existing identity, group keys, policies and optional creation/release registers.
    pub fn new(objects: Objects<'a>) -> Self {
        Self {
            objects: Arc::new(objects),
            routes: RwLock::new(BTreeMap::new()),
            releases: RwLock::new(BTreeMap::new()),
            attachment: RwLock::new(None),
        }
    }
    /// Access explicit group, dataset, and release operations.
    pub fn objects(&self) -> &Objects<'a> {
        &self.objects
    }
    /// Bind input and output configuration once for a programming workflow.
    /// The binding keeps its routes even if additional routes are registered later.
    /// Evaluators still execute for every operation against current application state.
    pub fn workflow(&self, receive: &str, release: &str) -> Result<Workflow<'a>> {
        let routes = self
            .routes
            .read()
            .map_err(|_| Error::InvalidConfig("session routes lock poisoned".into()))?
            .iter()
            .filter(|((purpose, _), _)| purpose == receive)
            .map(|((_, kind), route)| (kind.clone(), route.clone()))
            .collect::<BTreeMap<_, _>>();
        if routes.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "receiving purpose {receive:?} is not configured"
            )));
        }
        Ok(Workflow {
            objects: self.objects.clone(),
            routes,
            release: self.release_plan(release)?,
            attachment: self
                .attachment
                .read()
                .map_err(|_| Error::InvalidConfig("session attachment lock poisoned".into()))?
                .clone(),
        })
    }
    /// Select a contract from the session policy document.
    pub fn policy(&self, name: &str) -> Result<Governance> {
        Ok(self.objects.draft(name)?.governance().clone())
    }
    /// Verify publication integrity without accepting its use or decrypting data.
    pub fn verify(&self, wire: &str) -> Result<GovernedObject> {
        GovernedObject::parse(wire)
    }
    /// Create an initial signed publication under the selected contract.
    pub fn create(&self, fields: impl serde::Serialize, policy: Governance) -> Result<DataObject> {
        self.objects.create_selected(fields, policy, "default")
    }
    /// Create the initial signed object using the selected policy's type and default group.
    pub fn create_obj(
        &self,
        fields: impl serde::Serialize,
        policy: Governance,
    ) -> Result<DataObject> {
        self.create(fields, policy)
    }
    /// Bind a purpose to a complete use, selected groups and admission evaluator.
    /// Duplicate purposes are rejected so startup cannot silently replace a decision.
    pub fn configure_receive<I, S, F>(
        &self,
        use_context: UseContext,
        groups: I,
        decide: F,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: Fn(&AdmissionContext<'_>) -> Result<bool> + Send + Sync + 'static,
    {
        self.configure_receive_for(None, use_context, groups, decide)
    }
    /// Register a receiving purpose for a particular signed object type.
    /// Exact type registrations take precedence over an untyped registration.
    pub fn configure_receive_for<I, S, F>(
        &self,
        object_type: Option<&str>,
        use_context: UseContext,
        groups: I,
        decide: F,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: Fn(&AdmissionContext<'_>) -> Result<bool> + Send + Sync + 'static,
    {
        if let Some(name) = object_type {
            crate::governed::validate_name(name)?;
        }
        let groups: Vec<String> = groups.into_iter().map(|s| s.as_ref().to_owned()).collect();
        if groups.is_empty() || groups.iter().any(|s| s == "tn.agents") {
            return Err(Error::InvalidConfig(
                "configure at least one business group; governance is automatic".into(),
            ));
        }
        self.objects.reader_for(&groups)?;
        let mut routes = self
            .routes
            .write()
            .map_err(|_| Error::InvalidConfig("session routes lock poisoned".into()))?;
        let key = (
            use_context.purpose().to_owned(),
            object_type.map(str::to_owned),
        );
        if routes.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "receiving purpose is already configured".into(),
            ));
        }
        routes.insert(
            key,
            Arc::new(ReceiveRoute {
                use_context,
                groups,
                decide: Arc::new(decide),
            }),
        );
        Ok(())
    }
    fn receive_route(&self, purpose: &str, object_type: &str) -> Result<Arc<ReceiveRoute>> {
        let routes = self
            .routes
            .read()
            .map_err(|_| Error::InvalidConfig("session routes lock poisoned".into()))?;
        routes
            .get(&(purpose.to_owned(), Some(object_type.to_owned())))
            .or_else(|| routes.get(&(purpose.to_owned(), None)))
            .cloned()
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "receiving purpose {purpose:?} for {object_type:?} is not configured"
                ))
            })
    }
    /// Verify, accept the configured use and open selected data from a signed object.
    pub fn receive(&self, source: &impl Publication, purpose: &str) -> Result<DataObject> {
        self.receive_selected(source, purpose, None)
    }
    /// Receive with an exact dataset edition selected for this application request.
    pub fn receive_selected(
        &self,
        source: &impl Publication,
        purpose: &str,
        selection: Option<&DatasetSelection>,
    ) -> Result<DataObject> {
        let publication = source.publication()?;
        let route = self.receive_route(purpose, publication.object_type())?;
        self.objects.receive_for(
            publication.wire(),
            &route.use_context,
            &route.groups,
            selection,
            |context| (route.decide)(context),
        )
    }
    /// Primary business group selected by a purpose and the received object's type.
    pub fn primary_group(&self, purpose: &str, object_type: &str) -> Result<String> {
        Ok(self.receive_route(purpose, object_type)?.groups[0].clone())
    }
    /// Configure one output purpose, its destination, object type and evaluator.
    pub fn configure_release<F>(
        &self,
        use_context: UseContext,
        destination: &str,
        object_type: &str,
        decide: F,
    ) -> Result<()>
    where
        F: Fn(&ReleaseContext<'_>) -> Result<bool> + Send + Sync + 'static,
    {
        crate::governed::validate_name(object_type)?;
        if destination.trim().is_empty() || destination.chars().any(char::is_control) {
            return Err(Error::InvalidConfig(
                "release destination must be nonblank and exclude control characters".into(),
            ));
        }
        let mut plans = self
            .releases
            .write()
            .map_err(|_| Error::InvalidConfig("session release lock poisoned".into()))?;
        if plans.contains_key(use_context.purpose()) {
            return Err(Error::InvalidConfig(
                "release purpose is already configured".into(),
            ));
        }
        plans.insert(
            use_context.purpose().to_owned(),
            Arc::new(ReleasePlan {
                use_context,
                destination: destination.into(),
                object_type: object_type.into(),
                decide: Arc::new(decide),
            }),
        );
        Ok(())
    }
    /// Obtain the immutable release settings and decision for a purpose.
    pub fn release_plan(&self, purpose: &str) -> Result<Arc<ReleasePlan>> {
        self.releases
            .read()
            .map_err(|_| Error::InvalidConfig("session release lock poisoned".into()))?
            .get(purpose)
            .cloned()
            .ok_or_else(|| {
                Error::InvalidConfig(format!("release purpose {purpose:?} is not configured"))
            })
    }
    /// Evaluate current data and sign its configured output, retaining contracts and sources.
    pub fn release(&self, data: &mut DataObject, purpose: &str) -> Result<GovernedObject> {
        self.release_checked(data, purpose, |_| Ok(true))
    }
    /// Require an additional request-specific check as well as the configured decision.
    pub fn release_checked<F>(
        &self,
        data: &mut DataObject,
        purpose: &str,
        check: F,
    ) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        let plan = self.release_plan(purpose)?;
        self.objects.release_for(
            data,
            plan.object_type(),
            plan.use_context(),
            plan.destination(),
            |ctx| Ok(plan.authorize(ctx)? && check(ctx)?),
        )
    }
    /// Configure this session's policy-attachment authority evaluator once.
    pub fn configure_attach<F>(&self, decide: F) -> Result<()>
    where
        F: Fn(&AttachmentContext<'_>) -> Result<bool> + Send + Sync + 'static,
    {
        let mut evaluator = self
            .attachment
            .write()
            .map_err(|_| Error::InvalidConfig("session attachment lock poisoned".into()))?;
        if evaluator.is_some() {
            return Err(Error::InvalidConfig(
                "attachment evaluator is already configured".into(),
            ));
        }
        *evaluator = Some(Arc::new(decide));
        Ok(())
    }
    /// Add a policy under configured authority; existing obligations remain attached.
    pub fn attach(&self, data: &mut DataObject, policy: Governance) -> Result<()> {
        let evaluator = self
            .attachment
            .read()
            .map_err(|_| Error::InvalidConfig("session attachment lock poisoned".into()))?
            .clone()
            .ok_or_else(|| Error::InvalidConfig("attachment evaluator is not configured".into()))?;
        self.objects.attach(data, policy, |ctx| evaluator(ctx))
    }
}

impl<'a> Deref for Session<'a> {
    type Target = Objects<'a>;
    fn deref(&self) -> &Self::Target {
        &self.objects
    }
}

/// A reusable input/output contract for application code.
/// Business computation mutates ordinary DataObjects between receive and release.
/// Configuration is captured at binding; authority decisions remain live callbacks.
pub struct Workflow<'a> {
    objects: Arc<Objects<'a>>,
    routes: BTreeMap<Option<String>, Arc<ReceiveRoute>>,
    release: Arc<ReleasePlan>,
    attachment: Option<Arc<AttachmentDecision>>,
}
impl Workflow<'_> {
    fn route(&self, object_type: &str) -> Result<&ReceiveRoute> {
        self.routes
            .get(&Some(object_type.to_owned()))
            .or_else(|| self.routes.get(&None))
            .map(Arc::as_ref)
            .ok_or_else(|| {
                Error::InvalidConfig(format!("workflow has no input route for {object_type:?}"))
            })
    }
    /// Primary business group for a supported publication type.
    pub fn primary_group(&self, object_type: &str) -> Result<&str> {
        Ok(&self.route(object_type)?.groups[0])
    }
    /// Verify, accept the complete use contract, then open selected business groups.
    pub fn receive(&self, source: &impl Publication) -> Result<DataObject> {
        self.receive_selected(source, None)
    }
    /// Receive a publication with a request-specific dataset selection.
    pub fn receive_selected(
        &self,
        source: &impl Publication,
        selection: Option<&DatasetSelection>,
    ) -> Result<DataObject> {
        let publication = source.publication()?;
        let route = self.route(publication.object_type())?;
        self.objects.receive_for(
            publication.wire(),
            &route.use_context,
            &route.groups,
            selection,
            |ctx| (route.decide)(ctx),
        )
    }
    /// Add a contract under the bound attachment authority.
    pub fn attach(&self, data: &mut DataObject, policy: Governance) -> Result<()> {
        let decide = self.attachment.as_ref().ok_or_else(|| {
            Error::InvalidConfig("workflow attachment evaluator is not configured".into())
        })?;
        self.objects.attach(data, policy, |ctx| decide(ctx))
    }
    /// Inspect the immutable output contract used by this workflow.
    pub fn release_plan(&self) -> Arc<ReleasePlan> {
        self.release.clone()
    }
    /// Evaluate and publish current data, carrying its contracts and sources.
    pub fn release(&self, data: &mut DataObject) -> Result<GovernedObject> {
        self.release_checked(data, |_| Ok(true))
    }
    /// Require a request-specific decision in addition to the configured evaluator.
    pub fn release_checked<F>(&self, data: &mut DataObject, check: F) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        let plan = &self.release;
        self.objects.release_for(
            data,
            plan.object_type(),
            plan.use_context(),
            plan.destination(),
            |ctx| Ok(plan.authorize(ctx)? && check(ctx)?),
        )
    }
}
