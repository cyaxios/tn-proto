//! Signed edition records and explicit, application-approved dataset selection.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Error, Result};

use super::data::base_contract;
use super::revision::validate_revision_id;
use super::{
    validate_group, validate_name, AdmissionContext, Governance, GovernanceView, GovernedDraft,
    GovernedObject, OpenedObject, PolicyDag, UseContext, GOVERNANCE_GROUP,
};

/// Ordinary TN object type used for signed dataset edition records.
pub const DATASET_EDITION_TYPE: &str = "tn.dataset.edition";
/// Encrypted group containing the edition record.
pub const DATASET_EDITION_GROUP: &str = "dataset_edition";
const EDITION_SCHEMA: &str = "tn-dataset-edition@v1";
const MAX_ITEMS: usize = 256;
const MAX_CONTRACTS: usize = 64;
const MAX_USES: usize = 1024;
const MAX_LABEL_BYTES: usize = 256;
const MAX_GRANT_BYTES: usize = 2048;

fn invalid(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "dataset edition",
        reason: reason.into(),
    }
}

fn label(value: &str) -> Result<()> {
    if value.len() > MAX_LABEL_BYTES {
        return Err(invalid(
            "dataset, edition, scope, type and group labels are bounded to 256 bytes",
        ));
    }
    validate_name(value)
}

fn bounded_nonempty<T>(items: &[T], max: usize, name: &str) -> Result<()> {
    if items.is_empty() || items.len() > max {
        return Err(invalid(format!(
            "{name} requires between 1 and {max} entries"
        )));
    }
    Ok(())
}

/// Exact signed policy revision and the scope under which it applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ContractBinding {
    revision_id: String,
    scope: String,
}

impl ContractBinding {
    /// Validate a lowercase TN row hash and explicit policy scope.
    pub fn new(revision_id: &str, scope: &str) -> Result<Self> {
        validate_revision_id(revision_id)?;
        label(scope)?;
        Ok(Self {
            revision_id: revision_id.to_owned(),
            scope: scope.to_owned(),
        })
    }
    /// Exact signed revision identity.
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }
    /// Explicit scope; no scope inference or wildcard matching occurs.
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl<'de> Deserialize<'de> for ContractBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            revision_id: String,
            scope: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(&fields.revision_id, &fields.scope).map_err(serde::de::Error::custom)
    }
}

fn validate_contracts(contracts: &[ContractBinding]) -> Result<()> {
    bounded_nonempty(contracts, MAX_CONTRACTS, "contracts")?;
    let mut identities = BTreeSet::new();
    for contract in contracts {
        validate_revision_id(contract.revision_id())?;
        label(contract.scope())?;
        if !identities.insert(contract.revision_id()) {
            return Err(invalid(
                "each policy revision must occur once in the contract set",
            ));
        }
    }
    Ok(())
}

/// Digests binding one policy revision to the evaluator's complete artifact set.
/// Digests use exactly 64 lowercase hexadecimal characters, without a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluatorArtifactSet {
    policy_revision: String,
    compiled_policy_sha256: String,
    profile_sha256: String,
    wasm_sha256: String,
    data_sha256: String,
}

impl EvaluatorArtifactSet {
    /// Validate the revision identity and all four artifact digests.
    pub fn new(
        policy_revision: &str,
        compiled_policy_sha256: &str,
        profile_sha256: &str,
        wasm_sha256: &str,
        data_sha256: &str,
    ) -> Result<Self> {
        validate_revision_id(policy_revision)?;
        for digest in [
            compiled_policy_sha256,
            profile_sha256,
            wasm_sha256,
            data_sha256,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid(
                    "artifact digests require 64 lowercase hexadecimal characters",
                ));
            }
        }
        Ok(Self {
            policy_revision: policy_revision.to_owned(),
            compiled_policy_sha256: compiled_policy_sha256.to_owned(),
            profile_sha256: profile_sha256.to_owned(),
            wasm_sha256: wasm_sha256.to_owned(),
            data_sha256: data_sha256.to_owned(),
        })
    }
    /// Policy revision evaluated by these artifacts.
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
    /// Digest of the compiled policy source or representation.
    pub fn compiled_policy_sha256(&self) -> &str {
        &self.compiled_policy_sha256
    }
    /// Digest of the evaluator's schema/profile.
    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
    /// Digest of the exact executable evaluator module.
    pub fn wasm_sha256(&self) -> &str {
        &self.wasm_sha256
    }
    /// Digest of the evaluator's accompanying data.
    pub fn data_sha256(&self) -> &str {
        &self.data_sha256
    }
}

impl<'de> Deserialize<'de> for EvaluatorArtifactSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            policy_revision: String,
            compiled_policy_sha256: String,
            profile_sha256: String,
            wasm_sha256: String,
            data_sha256: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            &fields.policy_revision,
            &fields.compiled_policy_sha256,
            &fields.profile_sha256,
            &fields.wasm_sha256,
            &fields.data_sha256,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Portable declaration of an edition's origin, not an accepted capability.
/// A receiving catalog validates this declaration against an admitted signed record.
#[derive(Debug, Clone, Serialize)]
pub struct DatasetBinding {
    dataset: String,
    edition: String,
    source_object_id: String,
    edition_record_id: String,
    contracts: Vec<ContractBinding>,
}

impl PartialEq for DatasetBinding {
    fn eq(&self, other: &Self) -> bool {
        self.dataset == other.dataset
            && self.edition == other.edition
            && self.source_object_id == other.source_object_id
            && self.edition_record_id == other.edition_record_id
            && same_bindings(&self.contracts, &other.contracts)
    }
}

impl Eq for DatasetBinding {}

impl DatasetBinding {
    /// Stable dataset identifier.
    pub fn dataset(&self) -> &str {
        &self.dataset
    }
    /// Explicit edition identifier.
    pub fn edition(&self) -> &str {
        &self.edition
    }
    /// Exact released source publication.
    pub fn source_object_id(&self) -> &str {
        &self.source_object_id
    }
    /// Exact signed, separately admitted edition record.
    pub fn edition_record_id(&self) -> &str {
        &self.edition_record_id
    }
    /// Required policy revisions and scopes.
    pub fn contracts(&self) -> &[ContractBinding] {
        &self.contracts
    }
    pub(super) fn validate(&self) -> Result<()> {
        label(&self.dataset)?;
        label(&self.edition)?;
        validate_revision_id(&self.source_object_id)?;
        validate_revision_id(&self.edition_record_id)?;
        if self.source_object_id == self.edition_record_id {
            return Err(invalid(
                "edition record must identify a separate earlier source publication",
            ));
        }
        validate_contracts(&self.contracts)
    }
}

impl<'de> Deserialize<'de> for DatasetBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            dataset: String,
            edition: String,
            source_object_id: String,
            edition_record_id: String,
            contracts: Vec<ContractBinding>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let binding = Self {
            dataset: fields.dataset,
            edition: fields.edition,
            source_object_id: fields.source_object_id,
            edition_record_id: fields.edition_record_id,
            contracts: fields.contracts,
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditionBody {
    schema: String,
    dataset: String,
    edition: String,
    source_object_id: String,
    source_writer: String,
    source_type: String,
    source_groups: Vec<String>,
    contracts: Vec<ContractBinding>,
    eligible_uses: Vec<UseContext>,
    grant_ref: String,
    evaluator_artifacts: Vec<EvaluatorArtifactSet>,
}

impl EditionBody {
    fn validate(&self) -> Result<()> {
        if self.schema != EDITION_SCHEMA {
            return Err(invalid("required tn-dataset-edition@v1 schema"));
        }
        label(&self.dataset)?;
        label(&self.edition)?;
        label(&self.source_type)?;
        validate_revision_id(&self.source_object_id)?;
        crate::trust::parse_ed25519_did_key(&self.source_writer)
            .map_err(|_| invalid("source writer requires an Ed25519 did:key"))?;
        validate_groups(&self.source_groups)?;
        validate_contracts(&self.contracts)?;
        bounded_nonempty(&self.eligible_uses, MAX_USES, "eligible uses")?;
        let mut uses = BTreeSet::new();
        for use_context in &self.eligible_uses {
            // Revalidation also protects this record if UseContext's decoding changes.
            UseContext::new(
                use_context.application(),
                use_context.purpose(),
                use_context.operation(),
            )?;
            if !uses.insert((
                use_context.application(),
                use_context.purpose(),
                use_context.operation(),
            )) {
                return Err(invalid("each complete eligible-use tuple must occur once"));
            }
        }
        if self.grant_ref.trim().is_empty()
            || self.grant_ref.len() > MAX_GRANT_BYTES
            || self.grant_ref.chars().any(char::is_control)
        {
            return Err(invalid(
                "grant reference requires 1 to 2048 bytes without control characters",
            ));
        }
        if self.evaluator_artifacts.len() > MAX_ITEMS {
            return Err(invalid("evaluator artifacts exceeds 256 entries"));
        }
        let revisions: BTreeSet<_> = self
            .contracts
            .iter()
            .map(ContractBinding::revision_id)
            .collect();
        let mut artifacts = BTreeSet::new();
        for artifact in &self.evaluator_artifacts {
            if !revisions.contains(artifact.policy_revision())
                || !artifacts.insert(artifact.policy_revision())
            {
                return Err(invalid(
                    "each artifact set must identify a distinct required contract",
                ));
            }
        }
        if !artifacts.is_empty() && artifacts != revisions {
            return Err(invalid(
                "every required contract needs exactly one evaluator artifact set",
            ));
        }
        Ok(())
    }
}

fn validate_groups(groups: &[String]) -> Result<()> {
    bounded_nonempty(groups, MAX_ITEMS, "source groups")?;
    let mut names = BTreeSet::new();
    for group in groups {
        label(group)?;
        validate_group(group)?;
        if group == GOVERNANCE_GROUP || !names.insert(group) {
            return Err(invalid("source groups must be distinct business groups"));
        }
    }
    Ok(())
}

/// An edition record prepared after its source publication has been signed.
#[derive(Debug, Clone)]
pub struct DatasetEditionDraft {
    body: EditionBody,
}

impl DatasetEditionDraft {
    /// Bind an already verified publication to explicit contracts and eligible-use tuples.
    /// Policy authority and actual source contracts are checked by the catalog and receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new<I, S>(
        dataset: &str,
        edition: &str,
        source: &GovernedObject,
        source_groups: I,
        contracts: Vec<ContractBinding>,
        eligible_uses: Vec<UseContext>,
        grant_ref: &str,
        evaluator_artifacts: Vec<EvaluatorArtifactSet>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let body = EditionBody {
            schema: EDITION_SCHEMA.to_owned(),
            dataset: dataset.to_owned(),
            edition: edition.to_owned(),
            source_object_id: source.id().to_owned(),
            source_writer: source.writer().to_owned(),
            source_type: source.object_type().to_owned(),
            source_groups: source_groups
                .into_iter()
                .map(|s| s.as_ref().to_owned())
                .collect(),
            contracts,
            eligible_uses,
            grant_ref: grant_ref.to_owned(),
            evaluator_artifacts,
        };
        body.validate()?;
        if body
            .source_groups
            .iter()
            .any(|group| !source.group_names().contains(&group.as_str()))
        {
            return Err(invalid(
                "edition source groups must occur in the verified source publication",
            ));
        }
        Ok(Self { body })
    }

    /// Build the existing governed draft under the record's administration contract.
    pub fn into_draft(self, administration_contract: Governance) -> Result<GovernedDraft> {
        self.body.validate()?;
        GovernedDraft::new(DATASET_EDITION_TYPE, administration_contract)?
            .group(DATASET_EDITION_GROUP, self.body)
    }
}

/// Structurally validated edition record opened through ordinary TN governance admission.
#[derive(Debug, Clone)]
pub struct DatasetEdition {
    object: GovernedObject,
    body: EditionBody,
}

impl DatasetEdition {
    /// Decode an edition only after ordinary governance acceptance and group opening.
    pub fn from_opened(opened: &OpenedObject) -> Result<Self> {
        if opened.object().object_type() != DATASET_EDITION_TYPE {
            return Err(invalid("required tn.dataset.edition object type"));
        }
        let payload = opened
            .groups()
            .get(DATASET_EDITION_GROUP)
            .ok_or_else(|| invalid("open the dataset_edition group before decoding its record"))?;
        let body: EditionBody = serde_json::from_value(payload.clone())
            .map_err(|e| invalid(format!("invalid edition record: {e}")))?;
        body.validate()?;
        if body.source_object_id == opened.object().id() {
            return Err(invalid(
                "edition record must identify a separate earlier source publication",
            ));
        }
        Ok(Self {
            object: opened.object().clone(),
            body,
        })
    }
    /// Signed edition-record identity.
    pub fn id(&self) -> &str {
        self.object.id()
    }
    /// Authenticated catalog writer; admission applies the application's authority rule.
    pub fn writer(&self) -> &str {
        self.object.writer()
    }
    /// Stable dataset identifier.
    pub fn dataset(&self) -> &str {
        &self.body.dataset
    }
    /// Explicit edition; no ordering is inferred.
    pub fn edition(&self) -> &str {
        &self.body.edition
    }
    /// Exact released source identity.
    pub fn source_object_id(&self) -> &str {
        &self.body.source_object_id
    }
    /// Expected source signer.
    pub fn source_writer(&self) -> &str {
        &self.body.source_writer
    }
    /// Expected source object type.
    pub fn source_type(&self) -> &str {
        &self.body.source_type
    }
    /// Business groups that this edition may supply.
    pub fn source_groups(&self) -> &[String] {
        &self.body.source_groups
    }
    /// Complete required policy revision bindings.
    pub fn contracts(&self) -> &[ContractBinding] {
        &self.body.contracts
    }
    /// Allowed tuples; separate tuple values may not be recombined.
    pub fn eligible_uses(&self) -> &[UseContext] {
        &self.body.eligible_uses
    }
    /// Catalog authority's entitlement reference.
    pub fn grant_ref(&self) -> &str {
        &self.body.grant_ref
    }
    /// Per-revision artifact digests to verify before external evaluator loading.
    /// An explicitly empty list supports consumers that use native callbacks.
    /// A nonempty list covers every required contract revision exactly once.
    pub fn evaluator_artifacts(&self) -> &[EvaluatorArtifactSet] {
        &self.body.evaluator_artifacts
    }
    /// Exact signed envelope for retention and forwarding.
    pub fn object(&self) -> &GovernedObject {
        &self.object
    }

    fn binding(&self) -> DatasetBinding {
        DatasetBinding {
            dataset: self.dataset().to_owned(),
            edition: self.edition().to_owned(),
            source_object_id: self.source_object_id().to_owned(),
            edition_record_id: self.id().to_owned(),
            contracts: self.contracts().to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
struct AcceptedEdition {
    edition: DatasetEdition,
    policies: Vec<Governance>,
}

/// Append-only catalog of authority-approved exact edition records.
#[derive(Debug, Clone, Default)]
pub struct DatasetCatalog {
    records: BTreeMap<String, AcceptedEdition>,
}

impl DatasetCatalog {
    /// Start an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of accepted immutable records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether no records have been accepted.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Resolve only an exact already accepted record identity.
    pub fn get(&self, record_id: &str) -> Option<&DatasetEdition> {
        self.records.get(record_id).map(|record| &record.edition)
    }

    /// Resolve all required revisions, then atomically apply catalog authority admission.
    /// Duplicate identities are errors, even when the signed content is identical.
    pub fn admit<F>(&mut self, edition: DatasetEdition, dag: &PolicyDag, authorize: F) -> Result<()>
    where
        F: FnOnce(&DatasetEdition) -> Result<bool>,
    {
        edition.body.validate()?;
        if self.records.contains_key(edition.id()) {
            return Err(invalid(
                "edition record already admitted; accepted catalog is immutable",
            ));
        }
        let policies = selected_policies(edition.contracts(), dag)?;
        if !authorize(&edition)? {
            return Err(Error::UseDenied {
                operation: "dataset.admit".to_owned(),
            });
        }
        self.records.insert(
            edition.id().to_owned(),
            AcceptedEdition { edition, policies },
        );
        Ok(())
    }

    /// Pin dataset, edition, signed record, and one complete allowed-use tuple.
    /// Friendly labels never choose between records or infer the latest revision.
    pub fn select(
        &self,
        dataset: &str,
        edition: &str,
        record_id: &str,
        use_context: &UseContext,
    ) -> Result<DatasetSelection> {
        label(dataset)?;
        label(edition)?;
        validate_revision_id(record_id)?;
        let record = self
            .records
            .get(record_id)
            .ok_or_else(|| invalid("select an admitted edition record by its exact identity"))?;
        if record.edition.dataset() != dataset || record.edition.edition() != edition {
            return Err(invalid(
                "selected record must match the explicit dataset and edition",
            ));
        }
        if !record.edition.eligible_uses().contains(use_context) {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        Ok(DatasetSelection {
            accepted: record.clone(),
            use_context: use_context.clone(),
        })
    }

    /// Verify a carried declaration against an accepted record and current accepted revisions.
    /// This does not by itself establish ancestry or permission for the receiving use.
    pub fn verify_binding(&self, binding: &DatasetBinding, dag: &PolicyDag) -> Result<()> {
        binding.validate()?;
        let record = self
            .records
            .get(binding.edition_record_id())
            .ok_or_else(|| invalid("dataset binding requires an admitted edition record"))?;
        if binding.dataset() != record.edition.dataset()
            || binding.edition() != record.edition.edition()
            || binding.source_object_id() != record.edition.source_object_id()
            || !same_bindings(binding.contracts(), record.edition.contracts())
        {
            return Err(invalid(
                "dataset binding must match its exact accepted edition record",
            ));
        }
        let current = selected_policies(binding.contracts(), dag)?;
        exact_contracts(&current, &record.policies)
    }

    /// Check every carried dataset against the receiving use and every current contract.
    /// Additional contracts require accepted revisions and complete contractual equality.
    /// Callers separately verify ancestry and authenticate the requested application identity.
    pub fn accepts(&self, context: &AdmissionContext<'_>, dag: &PolicyDag) -> Result<bool> {
        let use_context = context
            .use_context()
            .ok_or_else(|| invalid("dataset acceptance requires a complete use context"))?;
        let bindings = context.governance().dataset_bindings()?;
        if bindings.is_empty() {
            return Err(invalid(
                "dataset acceptance requires at least one carried dataset binding",
            ));
        }
        let policies = context.policies()?;
        for binding in &bindings {
            self.verify_binding(binding, dag)?;
            let record = &self.records[binding.edition_record_id()];
            if !record.edition.eligible_uses().contains(use_context) {
                return Ok(false);
            }
            for expected in &record.policies {
                if !policies
                    .iter()
                    .any(|policy| base_contract(policy) == base_contract(expected))
                {
                    return Err(invalid(
                        "every dataset contract must remain present in full",
                    ));
                }
            }
        }
        let mut revisions = BTreeSet::new();
        for policy in &policies {
            let id = policy
                .revision_id()
                .ok_or_else(|| invalid("every current contract needs an accepted revision"))?;
            if !revisions.insert(id) {
                return Err(invalid("each current policy revision must occur once"));
            }
            let revision = dag
                .get(id)
                .ok_or_else(|| invalid("current contract revision has not been admitted"))?;
            let expected = dag.select(id, revision.scope(), |_| Ok(true))?;
            if base_contract(policy) != base_contract(&expected) {
                return Err(invalid(
                    "current contract must match its complete accepted revision",
                ));
            }
        }
        Ok(true)
    }
}

fn same_bindings(left: &[ContractBinding], right: &[ContractBinding]) -> bool {
    left.len() == right.len()
        && left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

fn selected_policies(contracts: &[ContractBinding], dag: &PolicyDag) -> Result<Vec<Governance>> {
    contracts
        .iter()
        .map(|binding| dag.select(binding.revision_id(), binding.scope(), |_| Ok(true)))
        .collect()
}

fn exact_contracts(carried: &[Governance], expected: &[Governance]) -> Result<()> {
    if carried.len() != expected.len() {
        return Err(invalid(
            "source must carry exactly the selected edition's complete contract set",
        ));
    }
    let mut identities = BTreeSet::new();
    for policy in carried {
        let id = policy
            .revision_id()
            .ok_or_else(|| invalid("selected source contract requires a policy revision"))?;
        if !identities.insert(id)
            || !expected
                .iter()
                .any(|candidate| base_contract(candidate) == base_contract(policy))
        {
            return Err(invalid("source contract must exactly match the accepted revision, including all machine rules"));
        }
    }
    Ok(())
}

/// Native accepted state pinned to one signed record and one allowed-use tuple.
/// It has no public constructor or deserializer; only catalog selection creates it.
#[derive(Debug, Clone)]
pub struct DatasetSelection {
    accepted: AcceptedEdition,
    use_context: UseContext,
}

impl DatasetSelection {
    /// Accepted signed record retained by this selection.
    pub fn record(&self) -> &DatasetEdition {
        &self.accepted.edition
    }
    /// Exact use accepted at selection time.
    pub fn use_context(&self) -> &UseContext {
        &self.use_context
    }
    /// Origin declaration to install only after strict source receipt succeeds.
    pub fn binding(&self) -> DatasetBinding {
        self.record().binding()
    }
    /// Exact source publication selected.
    pub fn source_object_id(&self) -> &str {
        self.record().source_object_id()
    }
    /// Exact signed edition record selected.
    pub fn edition_record_id(&self) -> &str {
        self.record().id()
    }

    /// Verify identity, groups, use, and the complete contracts before business opening.
    pub fn verify_source(
        &self,
        view: &GovernanceView,
        use_context: &UseContext,
        groups: &[String],
    ) -> Result<()> {
        self.verify(view.object(), view.governance(), use_context, groups)
    }

    /// Verify the strict admission context without exposing mutable accepted state.
    pub fn verify_context(&self, context: &AdmissionContext<'_>) -> Result<()> {
        let use_context = context
            .use_context()
            .ok_or_else(|| invalid("dataset selection requires a complete use context"))?;
        let groups = context
            .groups()
            .ok_or_else(|| invalid("dataset selection requires pinned business groups"))?;
        self.verify(context.object(), context.governance(), use_context, groups)
    }

    fn verify(
        &self,
        object: &GovernedObject,
        governance: &Governance,
        use_context: &UseContext,
        groups: &[String],
    ) -> Result<()> {
        if use_context != &self.use_context {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        let record = self.record();
        if object.id() != record.source_object_id()
            || object.writer() != record.source_writer()
            || object.object_type() != record.source_type()
        {
            return Err(invalid(
                "received publication must match the selected source identity, writer and type",
            ));
        }
        validate_groups(groups)?;
        if record
            .source_groups()
            .iter()
            .any(|name| !object.group_names().contains(&name.as_str()))
        {
            return Err(invalid(
                "every group declared by the edition must occur in its exact source publication",
            ));
        }
        if groups.iter().any(|name| {
            !record.source_groups().contains(name) || !object.group_names().contains(&name.as_str())
        }) {
            return Err(invalid(
                "requested groups must be supplied by the selected edition",
            ));
        }
        exact_contracts(&governance.policies()?, &self.accepted.policies)?;
        // Receipt installs the selection after opening. Check that insertion can
        // succeed now, while the business groups are still ciphertext.
        let bindings = governance.dataset_bindings()?;
        let selected = self.binding();
        if let Some(existing) = bindings
            .iter()
            .find(|binding| binding.edition_record_id() == selected.edition_record_id())
        {
            if existing != &selected {
                return Err(invalid(
                    "source carries a conflicting declaration for the selected edition",
                ));
            }
        } else if bindings.len() >= 1024 {
            return Err(invalid(
                "source dataset bindings have no capacity for the selected edition",
            ));
        }
        Ok(())
    }
}
