use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use serde_json::{json, Map, Value};
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    ContractBinding, DatasetBinding, DatasetCatalog, DatasetEdition, DatasetEditionDraft,
    DatasetSelection, EvaluatorArtifactSet, Governance, GovernanceView, GovernedDraft,
    GovernedObject, GovernedReader, GovernedWriter, LineageVerifier, PolicyDag, PolicyRevision,
    PolicyRevisionDraft, UseContext, DATASET_EDITION_GROUP, POLICY_REVISION_GROUP,
};
use tn_core::{DeviceKey, Error, Result};

const POLICY: &str = "## finance.input\n### instruction\nCalculate the aggregate.\n### use_for\nPortfolio analysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

struct CountingCipher {
    inner: Arc<dyn GroupCipher>,
    decrypts: AtomicUsize,
}

impl CountingCipher {
    fn new() -> Arc<Self> {
        let mut publisher = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
        let kit = publisher.mint().unwrap();
        Arc::new(Self {
            inner: Arc::new(
                BtnPublisherCipher::from_state(publisher)
                    .with_reader_kit(&kit.to_bytes())
                    .unwrap(),
            ),
            decrypts: AtomicUsize::new(0),
        })
    }
    fn count(&self) -> usize {
        self.decrypts.load(Ordering::SeqCst)
    }
    fn reset(&self) {
        self.decrypts.store(0, Ordering::SeqCst);
    }
}

impl GroupCipher for CountingCipher {
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(bytes)
    }
    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(bytes)
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn encrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt_with_aad(bytes, aad)
    }
    fn decrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_with_aad(bytes, aad)
    }
}

fn ingest_use() -> UseContext {
    UseContext::new("analytics", "portfolio_analysis", "join").unwrap()
}

fn calculation_use() -> UseContext {
    UseContext::new("deepvest", "portfolio_analysis", "calculate").unwrap()
}

struct Fixture {
    device: DeviceKey,
    governance: Arc<CountingCipher>,
    metadata: Arc<CountingCipher>,
    business: Arc<CountingCipher>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            device: DeviceKey::generate(),
            governance: CountingCipher::new(),
            metadata: CountingCipher::new(),
            business: CountingCipher::new(),
        }
    }
    fn writer(&self) -> GovernedWriter<'_> {
        GovernedWriter::new(&self.device)
            .with_group("tn.agents", self.governance.clone(), &[1; 32])
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.metadata.clone(), &[2; 32])
            .unwrap()
            .with_group(DATASET_EDITION_GROUP, self.metadata.clone(), &[3; 32])
            .unwrap()
            .with_group("finance", self.business.clone(), &[4; 32])
            .unwrap()
    }
    fn reader(&self) -> GovernedReader {
        GovernedReader::new()
            .with_group("tn.agents", self.governance.clone())
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.metadata.clone())
            .unwrap()
            .with_group(DATASET_EDITION_GROUP, self.metadata.clone())
            .unwrap()
            .with_group("finance", self.business.clone())
            .unwrap()
    }
    fn reset(&self) {
        self.governance.reset();
        self.metadata.reset();
        self.business.reset();
    }
    fn selection(
        &self,
        dataset: &str,
        amount: u64,
        dag: &mut PolicyDag,
        catalog: &mut DatasetCatalog,
    ) -> (GovernedObject, DatasetSelection) {
        let administration =
            Governance::from_markdown(self.device.did(), POLICY, "admin.md", "finance.input")
                .unwrap();
        let revision = self
            .writer()
            .seal(
                PolicyRevisionDraft::from_markdown(
                    self.device.did(),
                    &POLICY.replace("the aggregate", dataset),
                    dataset,
                    "finance.input",
                    dataset,
                )
                .unwrap()
                .into_draft(administration.clone())
                .unwrap(),
            )
            .unwrap();
        let reader = self.reader();
        let metadata_use = UseContext::new("catalog", "administration", "inspect").unwrap();
        let admitted = reader
            .governance(&revision)
            .unwrap()
            .accept(metadata_use.clone(), [POLICY_REVISION_GROUP], |_| Ok(true))
            .unwrap();
        let revision =
            PolicyRevision::from_opened(&reader.open(&admitted, [POLICY_REVISION_GROUP]).unwrap())
                .unwrap();
        let revision_id = revision.id().to_owned();
        dag.admit(revision, |record, _| {
            Ok(record.writer() == self.device.did())
        })
        .unwrap();
        let contract = dag.select(&revision_id, dataset, |_| Ok(true)).unwrap();
        let source = self
            .writer()
            .seal(
                GovernedDraft::new("finance.input", contract)
                    .unwrap()
                    .group("finance", json!({"amount": amount}))
                    .unwrap(),
            )
            .unwrap();
        let artifact = EvaluatorArtifactSet::new(
            &revision_id,
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            &"4".repeat(64),
        )
        .unwrap();
        let edition = self
            .writer()
            .seal(
                DatasetEditionDraft::new(
                    dataset,
                    "edition-1",
                    &source,
                    ["finance"],
                    vec![ContractBinding::new(&revision_id, dataset).unwrap()],
                    vec![ingest_use(), calculation_use()],
                    "grant:fixture",
                    vec![artifact],
                )
                .unwrap()
                .into_draft(administration)
                .unwrap(),
            )
            .unwrap();
        let admitted = reader
            .governance(&edition)
            .unwrap()
            .accept(metadata_use, [DATASET_EDITION_GROUP], |_| Ok(true))
            .unwrap();
        let edition =
            DatasetEdition::from_opened(&reader.open(&admitted, [DATASET_EDITION_GROUP]).unwrap())
                .unwrap();
        let record_id = edition.id().to_owned();
        catalog
            .admit(edition, dag, |record| {
                Ok(record.writer() == self.device.did())
            })
            .unwrap();
        let selection = catalog
            .select(dataset, "edition-1", &record_id, &ingest_use())
            .unwrap();
        (source, selection)
    }

    // Retain a correctly signed test publication while deliberately changing its
    // declared lineage. Refusals must reach lineage checks, not signature failure.
    fn rewrite_governance(
        &self,
        object: &GovernedObject,
        edit: impl FnOnce(&mut Map<String, Value>),
    ) -> GovernedObject {
        use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
        use tn_core::sealed_object::{extract_group_blocks, ENVELOPE_RESERVED};

        let mut envelope = object.envelope().clone();
        let mut fields = self
            .reader()
            .governance(object)
            .unwrap()
            .governance()
            .fields()
            .clone();
        edit(&mut fields);
        let aad: Value = serde_json::from_str(envelope["tn_aad"].as_str().unwrap()).unwrap();
        let marker = tn_core::canonical::canonical_bytes(&aad["tn.agents"]).unwrap();
        let tokens: Map<String, Value> = fields
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    json!(tn_core::indexing::index_token(&[1; 32], name, value).unwrap()),
                )
            })
            .collect();
        let ciphertext = self
            .governance
            .encrypt_with_aad(
                &tn_core::canonical::canonical_bytes(&json!(fields)).unwrap(),
                &marker,
            )
            .unwrap();
        envelope["tn.agents"] = json!({
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext),
            "field_hashes": tokens,
        });
        let blocks = extract_group_blocks(&envelope).unwrap();
        let public = envelope
            .iter()
            .filter(|(name, _)| {
                !ENVELOPE_RESERVED.contains(&name.as_str()) && !blocks.contains_key(*name)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let groups = blocks
            .into_iter()
            .map(|(name, block)| {
                (
                    name,
                    GroupInput {
                        ciphertext: block.ciphertext,
                        field_hashes: block.field_hashes,
                    },
                )
            })
            .collect();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: envelope["device_identity"].as_str().unwrap(),
            timestamp: envelope["timestamp"].as_str().unwrap(),
            event_id: envelope["event_id"].as_str().unwrap(),
            event_type: envelope["event_type"].as_str().unwrap(),
            level: envelope["level"].as_str().unwrap(),
            prev_hash: envelope["prev_hash"].as_str().unwrap(),
            public_fields: &public,
            groups: &groups,
        });
        envelope["signature"] = json!(tn_core::signing::signature_b64(
            &self.device.sign(row_hash.as_bytes())
        ));
        envelope["row_hash"] = json!(row_hash);
        GovernedObject::parse(&serde_json::to_string(&envelope).unwrap()).unwrap()
    }
}

struct Workflow {
    fixture: Fixture,
    dag: PolicyDag,
    catalog: DatasetCatalog,
    sources: Vec<GovernedObject>,
    bindings: Vec<DatasetBinding>,
    joined: GovernedObject,
    policies: Vec<Governance>,
}

impl Workflow {
    fn new() -> Self {
        let fixture = Fixture::new();
        let mut dag = PolicyDag::new();
        let mut catalog = DatasetCatalog::new();
        let (a, select_a) = fixture.selection("market.accounts", 20, &mut dag, &mut catalog);
        let (b, select_b) = fixture.selection("market.prices", 30, &mut dag, &mut catalog);
        let reader = fixture.reader();
        let source_a = reader
            .receive_for(
                a.wire(),
                &ingest_use(),
                ["finance"],
                Some(&select_a),
                |_| Ok(true),
            )
            .unwrap();
        let source_b = reader
            .receive_for(
                b.wire(),
                &ingest_use(),
                ["finance"],
                Some(&select_b),
                |_| Ok(true),
            )
            .unwrap();
        let mut output = source_a.clone();
        output.include(&source_b).unwrap();
        output.set_field("finance", "amount", json!(50)).unwrap();
        let bindings = vec![select_a.binding(), select_b.binding()];
        let policies = vec![
            source_a.policies().unwrap()[0].clone(),
            source_b.policies().unwrap()[0].clone(),
        ];
        assert_eq!(output.dataset_bindings().unwrap(), bindings);
        assert_eq!(output.policies().unwrap(), policies);
        assert_eq!(source_a.dataset_bindings().unwrap(), [select_a.binding()]);
        assert_eq!(source_a.group("finance").unwrap()["amount"], json!(20));
        assert_eq!(source_a.policies().unwrap().len(), 1);
        let joined = fixture
            .writer()
            .release_for(
                &mut output,
                "finance.joined",
                &ingest_use(),
                "deepvest",
                |_| Ok(true),
            )
            .unwrap();
        let view = reader.governance(&joined).unwrap();
        assert_eq!(view.governance().dataset_bindings().unwrap(), bindings);
        assert_eq!(view.governance().policies().unwrap(), policies);
        let parents = view.governance().source_references().unwrap();
        assert_eq!(parents.len(), 2);
        assert!(parents[0].references(&a));
        assert!(parents[1].references(&b));
        Self {
            fixture,
            dag,
            catalog,
            sources: vec![a, b],
            bindings,
            joined,
            policies,
        }
    }
    fn retained(&self) -> BTreeMap<String, GovernedObject> {
        self.sources
            .iter()
            .chain([&self.joined])
            .map(|object| (object.id().to_owned(), object.clone()))
            .collect()
    }
    fn verify(&self, view: &GovernanceView) -> Result<tn_core::governed::VerifiedLineage> {
        let reader = self.fixture.reader();
        let retained = self.retained();
        LineageVerifier::default().verify(view, &self.catalog, &self.dag, |id| {
            reader.governance(retained.get(id).ok_or_else(|| Error::Malformed {
                kind: "test resolver",
                reason: "missing retained parent".to_owned(),
            })?)
        })
    }
}

#[test]
fn two_datasets_keep_contracts_bindings_and_immediate_parents_through_two_releases() {
    let workflow = Workflow::new();
    let reader = workflow.fixture.reader();
    let joined_view = reader.governance(&workflow.joined).unwrap();
    workflow.fixture.reset();
    let lineage = workflow.verify(&joined_view).unwrap();
    assert_eq!(lineage.object_ids().len(), 3);
    assert_eq!(lineage.source_object_ids().len(), 2);
    assert_eq!(workflow.fixture.governance.count(), 2);
    assert_eq!(workflow.fixture.business.count(), 0);
    assert_eq!(workflow.fixture.metadata.count(), 0);

    let mut calculation = reader
        .receive_for(
            workflow.joined.wire(),
            &calculation_use(),
            ["finance"],
            None,
            |context| workflow.catalog.accepts(context, &workflow.dag),
        )
        .unwrap();
    assert_eq!(calculation.dataset_bindings().unwrap(), workflow.bindings);
    assert_eq!(calculation.policies().unwrap(), workflow.policies);
    let sibling = calculation.clone();
    calculation
        .set_field("finance", "amount", json!(75))
        .unwrap();
    calculation
        .set_field("finance", "dataset_bindings", json!([]))
        .unwrap();
    assert!(calculation.set_group("tn.agents", json!({})).is_err());
    assert_eq!(calculation.dataset_bindings().unwrap(), workflow.bindings);
    assert_eq!(sibling.group("finance").unwrap()["amount"], json!(50));
    let report = workflow
        .fixture
        .writer()
        .release_for(
            &mut calculation,
            "finance.calculation",
            &calculation_use(),
            "model",
            |_| Ok(true),
        )
        .unwrap();
    let view = reader.governance(&report).unwrap();
    assert_eq!(
        view.governance().dataset_bindings().unwrap(),
        workflow.bindings
    );
    assert_eq!(view.governance().policies().unwrap(), workflow.policies);
    let parents = view.governance().source_references().unwrap();
    assert_eq!(parents.len(), 1);
    assert!(parents[0].references(&workflow.joined));
    workflow.fixture.reset();
    let proof = workflow.verify(&view).unwrap();
    assert_eq!(proof.object_ids().len(), 4);
    for source in &workflow.sources {
        assert!(proof.source_object_ids().contains(&source.id().to_owned()));
    }
    assert_eq!(workflow.fixture.governance.count(), 3);
    assert_eq!(workflow.fixture.business.count(), 0);
    assert_eq!(workflow.fixture.metadata.count(), 0);
    let reopened = reader
        .receive_for(
            report.wire(),
            &calculation_use(),
            ["finance"],
            None,
            |context| workflow.catalog.accepts(context, &workflow.dag),
        )
        .unwrap();
    assert_eq!(reopened.group("finance").unwrap()["amount"], json!(75));
    assert_eq!(reopened.dataset_bindings().unwrap(), workflow.bindings);
    assert_eq!(reopened.policies().unwrap(), workflow.policies);
}

#[test]
fn missing_binding_parent_or_declared_origin_is_refused_without_business_decryption() {
    let workflow = Workflow::new();
    let reader = workflow.fixture.reader();
    let valid = reader.governance(&workflow.joined).unwrap();
    let reopened = reader
        .receive_for(
            workflow.joined.wire(),
            &calculation_use(),
            ["finance"],
            None,
            |context| workflow.catalog.accepts(context, &workflow.dag),
        )
        .unwrap();
    let mut output = reopened;
    let report = workflow
        .fixture
        .writer()
        .release_for(
            &mut output,
            "finance.result",
            &calculation_use(),
            "model",
            |_| Ok(true),
        )
        .unwrap();
    let dropped = workflow.fixture.rewrite_governance(&report, |fields| {
        fields["dataset_bindings"].as_array_mut().unwrap().pop();
    });
    let unreachable = workflow
        .fixture
        .rewrite_governance(&workflow.joined, |fields| {
            fields["source_lineage"].as_array_mut().unwrap().pop();
        });
    let lost_contract = workflow.fixture.rewrite_governance(&report, |fields| {
        fields["attached_policies"] = json!([]);
    });
    for (object, expected_reason) in [
        (&dropped, "child must retain every parent dataset binding"),
        (
            &unreachable,
            "dataset bindings must describe the reached origins",
        ),
        (&lost_contract, "child must retain every parent contract"),
    ] {
        let view = reader.governance(object).unwrap();
        workflow.fixture.reset();
        let error = workflow.verify(&view).unwrap_err();
        assert!(error.to_string().contains(expected_reason), "{error}");
        assert_eq!(workflow.fixture.business.count(), 0);
        assert_eq!(workflow.fixture.metadata.count(), 0);
        let refused = reader.receive_for(
            object.wire(),
            &calculation_use(),
            ["finance"],
            None,
            |context| {
                assert_eq!(context.object().id(), view.object().id());
                workflow.verify(&view)?;
                workflow.catalog.accepts(context, &workflow.dag)
            },
        );
        assert!(refused.is_err());
        assert_eq!(workflow.fixture.business.count(), 0);
    }
    workflow.fixture.reset();
    let wrong = LineageVerifier::default()
        .verify(&valid, &workflow.catalog, &workflow.dag, |_| {
            reader.governance(&workflow.joined)
        })
        .unwrap_err();
    assert!(wrong.to_string().contains("different publication"));
    assert_eq!(workflow.fixture.business.count(), 0);
    let missing =
        LineageVerifier::default().verify(&valid, &workflow.catalog, &workflow.dag, |_| {
            Err(Error::Malformed {
                kind: "test resolver",
                reason: "missing retained parent".to_owned(),
            })
        });
    assert!(missing
        .unwrap_err()
        .to_string()
        .contains("missing retained parent"));
    assert_eq!(workflow.fixture.business.count(), 0);
}

#[test]
fn a_failed_binding_merge_and_refused_attachment_leave_the_working_object_unchanged() {
    let workflow = Workflow::new();
    let reader = workflow.fixture.reader();
    let original_binding = &workflow.bindings[0];
    let original_selection = workflow
        .catalog
        .select(
            original_binding.dataset(),
            original_binding.edition(),
            original_binding.edition_record_id(),
            &ingest_use(),
        )
        .unwrap();
    let mut target = reader
        .receive_for(
            workflow.sources[0].wire(),
            &ingest_use(),
            ["finance"],
            Some(&original_selection),
            |_| Ok(true),
        )
        .unwrap();
    let snapshot = target.snapshot().unwrap().id().to_owned();
    let sources = target.sources().to_vec();
    let conflicting = workflow
        .fixture
        .rewrite_governance(&workflow.joined, |fields| {
            fields["dataset_bindings"][0]["edition"] = json!("different-edition");
        });
    let other = reader
        .receive_for(
            conflicting.wire(),
            &calculation_use(),
            ["finance"],
            None,
            |_| Ok(true),
        )
        .unwrap();
    assert!(target.include(&other).is_err());
    let additional = Governance::from_markdown(
        workflow.fixture.device.did(),
        &POLICY.replace("the aggregate", "an approved report"),
        "report.md",
        "finance.input",
    )
    .unwrap();
    assert!(target
        .attach(workflow.fixture.device.did(), additional, |_| Ok(false))
        .is_err());
    assert_eq!(
        target.dataset_bindings().unwrap(),
        [original_binding.clone()]
    );
    assert_eq!(target.policies().unwrap(), [workflow.policies[0].clone()]);
    assert_eq!(target.sources(), sources);
    assert_eq!(target.snapshot().unwrap().id(), snapshot);
    assert_eq!(target.group("finance").unwrap()["amount"], json!(20));
}
