use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    ContractBinding, DataObject, DatasetBinding, DatasetCatalog, DatasetEdition,
    DatasetEditionDraft, DatasetSelection, EvaluatorArtifactSet, Governance, GovernedDraft,
    GovernedObject, GovernedReader, GovernedWriter, OpenedObject, PolicyDag, PolicyRevision,
    PolicyRevisionDraft, UseContext, DATASET_EDITION_GROUP, DATASET_EDITION_TYPE,
    POLICY_REVISION_GROUP,
};
use tn_core::{DeviceKey, Error, Result};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## market.prices\n### instruction\nPrepare approved prices.\n### use_for\nPortfolio research.\n### do_not_use_for\nRedistribution.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

fn cipher() -> Arc<dyn GroupCipher> {
    let mut publisher = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
    let kit = publisher.mint().unwrap();
    Arc::new(
        BtnPublisherCipher::from_state(publisher)
            .with_reader_kit(&kit.to_bytes())
            .unwrap(),
    )
}

struct CountingCipher {
    inner: Arc<dyn GroupCipher>,
    decrypts: AtomicUsize,
}
impl CountingCipher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: cipher(),
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

fn approved_use() -> UseContext {
    UseContext::new("analytics", "portfolio_analysis", "join_prices").unwrap()
}
fn later_use() -> UseContext {
    UseContext::new("deepvest", "portfolio_analysis", "calculate").unwrap()
}

struct Fixture {
    device: DeviceKey,
    rules: Arc<dyn GroupCipher>,
    metadata: Arc<dyn GroupCipher>,
    business: Arc<CountingCipher>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            device: DeviceKey::generate(),
            rules: cipher(),
            metadata: cipher(),
            business: CountingCipher::new(),
        }
    }
    fn governance(&self) -> Governance {
        Governance::from_markdown(self.device.did(), POLICY, "agents.md", "market.prices").unwrap()
    }
    fn writer_with<'a>(&self, device: &'a DeviceKey) -> GovernedWriter<'a> {
        GovernedWriter::new(device)
            .with_group("tn.agents", self.rules.clone(), &[1; 32])
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.metadata.clone(), &[2; 32])
            .unwrap()
            .with_group(DATASET_EDITION_GROUP, self.metadata.clone(), &[3; 32])
            .unwrap()
            .with_group("finance", self.business.clone(), &[4; 32])
            .unwrap()
            .with_group("audit", self.business.clone(), &[5; 32])
            .unwrap()
    }
    fn writer(&self) -> GovernedWriter<'_> {
        self.writer_with(&self.device)
    }
    fn reader(&self) -> GovernedReader {
        GovernedReader::new()
            .with_group("tn.agents", self.rules.clone())
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.metadata.clone())
            .unwrap()
            .with_group(DATASET_EDITION_GROUP, self.metadata.clone())
            .unwrap()
            .with_group("finance", self.business.clone())
            .unwrap()
            .with_group("audit", self.business.clone())
            .unwrap()
    }
    fn open(&self, object: &GovernedObject, group: &str) -> OpenedObject {
        let reader = self.reader();
        let admitted = reader
            .governance(object)
            .unwrap()
            .authorize("inspect", |_, _| Ok(true))
            .unwrap();
        reader.open(&admitted, [group]).unwrap()
    }
    fn revision(&self, version: &str) -> PolicyRevision {
        let draft = PolicyRevisionDraft::from_markdown(
            self.device.did(),
            &POLICY.replace("version: 1", &format!("version: {version}")),
            "agents.md",
            "market.prices",
            "market.prices",
        )
        .unwrap();
        let object = self
            .writer()
            .seal(draft.into_draft(self.governance()).unwrap())
            .unwrap();
        PolicyRevision::from_opened(&self.open(&object, POLICY_REVISION_GROUP)).unwrap()
    }
    fn policy(&self, dag: &PolicyDag, revision: &str) -> Governance {
        dag.select(revision, "market.prices", |_| Ok(true)).unwrap()
    }
    fn source(&self, policy: Governance) -> GovernedObject {
        self.writer()
            .seal(
                GovernedDraft::new("market.prices", policy)
                    .unwrap()
                    .group("finance", json!({"symbol": "TEST", "last_price": 100}))
                    .unwrap()
                    .group("audit", json!({"batch": "fixed"}))
                    .unwrap(),
            )
            .unwrap()
    }
    fn artifacts(&self, revisions: &[String]) -> Vec<EvaluatorArtifactSet> {
        revisions
            .iter()
            .map(|id| {
                EvaluatorArtifactSet::new(
                    id,
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &"c".repeat(64),
                    &"d".repeat(64),
                )
                .unwrap()
            })
            .collect()
    }
    fn edition(&self, name: &str, source: &GovernedObject, revisions: &[String]) -> DatasetEdition {
        let contracts = revisions
            .iter()
            .map(|id| ContractBinding::new(id, "market.prices").unwrap())
            .collect();
        let draft = DatasetEditionDraft::new(
            "market.prices",
            name,
            source,
            ["finance"],
            contracts,
            vec![approved_use(), later_use()],
            "grant:approved",
            self.artifacts(revisions),
        )
        .unwrap();
        let object = self
            .writer()
            .seal(draft.into_draft(self.governance()).unwrap())
            .unwrap();
        DatasetEdition::from_opened(&self.open(&object, DATASET_EDITION_GROUP)).unwrap()
    }
    fn rewrite_edition(
        &self,
        edition: &DatasetEdition,
        writer: &DeviceKey,
        edit: impl FnOnce(&mut Value),
    ) -> Result<DatasetEdition> {
        let mut body = self.open(edition.object(), DATASET_EDITION_GROUP).groups()
            [DATASET_EDITION_GROUP]
            .clone();
        edit(&mut body);
        let object = self.writer_with(writer).seal(
            GovernedDraft::new(DATASET_EDITION_TYPE, self.governance())?
                .group(DATASET_EDITION_GROUP, body)?,
        )?;
        DatasetEdition::from_opened(&self.open(&object, DATASET_EDITION_GROUP))
    }
    fn select(&self, dag: &PolicyDag, record: DatasetEdition) -> DatasetSelection {
        let id = record.id().to_owned();
        let edition = record.edition().to_owned();
        let mut catalog = DatasetCatalog::new();
        catalog
            .admit(record, dag, |record| {
                Ok(record.writer() == self.device.did())
            })
            .unwrap();
        catalog
            .select("market.prices", &edition, &id, &approved_use())
            .unwrap()
    }
    fn assert_refused_before_business(
        &self,
        object: &GovernedObject,
        selection: &DatasetSelection,
        use_context: &UseContext,
        groups: &[&str],
    ) {
        self.business.reset();
        let callbacks = AtomicUsize::new(0);
        assert!(self
            .reader()
            .receive_for(object.wire(), use_context, groups, Some(selection), |_| {
                callbacks.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            })
            .is_err());
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert_eq!(self.business.count(), 0);
    }

    // Construct a valid signed declaration with changed encrypted contractual fields.
    // The test must reach policy checks, rather than merely failing the TN signature.
    fn rewrite_governance(
        &self,
        object: &GovernedObject,
        edit: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> GovernedObject {
        use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
        use tn_core::sealed_object::{extract_group_blocks, ENVELOPE_RESERVED};
        let mut env = object.envelope().clone();
        let mut fields = self
            .reader()
            .governance(object)
            .unwrap()
            .governance()
            .fields()
            .clone();
        edit(&mut fields);
        let aad: Value = serde_json::from_str(env["tn_aad"].as_str().unwrap()).unwrap();
        let marker = tn_core::canonical::canonical_bytes(&aad["tn.agents"]).unwrap();
        let tokens: serde_json::Map<String, Value> = fields
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    json!(tn_core::indexing::index_token(&[1; 32], name, value).unwrap()),
                )
            })
            .collect();
        let ciphertext = self
            .rules
            .encrypt_with_aad(
                &tn_core::canonical::canonical_bytes(&json!(fields)).unwrap(),
                &marker,
            )
            .unwrap();
        env["tn.agents"] = json!({"ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext), "field_hashes": tokens});
        let blocks = extract_group_blocks(&env).unwrap();
        let public = env
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
            device_identity: env["device_identity"].as_str().unwrap(),
            timestamp: env["timestamp"].as_str().unwrap(),
            event_id: env["event_id"].as_str().unwrap(),
            event_type: env["event_type"].as_str().unwrap(),
            level: env["level"].as_str().unwrap(),
            prev_hash: env["prev_hash"].as_str().unwrap(),
            public_fields: &public,
            groups: &groups,
        });
        env["signature"] = json!(tn_core::signing::signature_b64(
            &self.device.sign(row_hash.as_bytes())
        ));
        env["row_hash"] = json!(row_hash);
        GovernedObject::parse(&serde_json::to_string(&env).unwrap()).unwrap()
    }
}

fn history(fixture: &Fixture) -> (PolicyDag, String, String) {
    let first = fixture.revision("1");
    let second = fixture.revision("2");
    let first_id = first.id().to_owned();
    let second_id = second.id().to_owned();
    let mut dag = PolicyDag::new();
    dag.admit(first, |_, _| Ok(true)).unwrap();
    dag.admit(second, |_, _| Ok(true)).unwrap();
    (dag, first_id, second_id)
}

#[test]
fn typed_bindings_reject_invalid_identities_scopes_and_unknown_fields() {
    let revision = format!("sha256:{}", "a".repeat(64));
    let binding = ContractBinding::new(&revision, "market.prices").unwrap();
    assert_eq!(binding.revision_id(), revision);
    assert!(ContractBinding::new("latest", "market.prices").is_err());
    assert!(ContractBinding::new(&revision, "").is_err());
    assert!(
        serde_json::from_value::<ContractBinding>(serde_json::json!({
            "revision_id": revision, "scope": "market.prices", "latest": true
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<DatasetBinding>(serde_json::json!({
        "dataset": "market.prices", "edition": "yesterday", "source_object_id": "alias",
        "edition_record_id": revision, "contracts": [binding]
    }))
    .is_err());
    assert!(EvaluatorArtifactSet::new(&revision, "bad", "bad", "bad", "bad").is_err());
}

#[test]
fn equally_valued_editions_keep_independent_exact_publications_and_revisions() {
    let fixture = Fixture::new();
    let (dag, first, second) = history(&fixture);
    let old_source = fixture.source(fixture.policy(&dag, &first));
    let new_source = fixture.source(fixture.policy(&dag, &second));
    assert_ne!(old_source.id(), new_source.id());
    let old = fixture.edition("close-2026-09-07", &old_source, &[first.clone()]);
    let new = fixture.edition("close-2026-09-08", &new_source, &[second.clone()]);
    let mut catalog = DatasetCatalog::new();
    catalog
        .admit(old.clone(), &dag, |record| {
            Ok(record.writer() == fixture.device.did())
        })
        .unwrap();
    catalog
        .admit(new.clone(), &dag, |record| {
            Ok(record.writer() == fixture.device.did())
        })
        .unwrap();
    assert_eq!(catalog.len(), 2);
    assert!(catalog.admit(old.clone(), &dag, |_| Ok(true)).is_err());
    assert_eq!(catalog.len(), 2);
    assert!(catalog
        .select("market.prices", old.edition(), new.id(), &approved_use())
        .is_err());
    let old_selection = catalog
        .select("market.prices", old.edition(), old.id(), &approved_use())
        .unwrap();
    let new_selection = catalog
        .select("market.prices", new.edition(), new.id(), &approved_use())
        .unwrap();
    let reader = fixture.reader();
    let older = reader
        .receive_for(
            old_source.wire(),
            &approved_use(),
            ["finance"],
            Some(&old_selection),
            |_| Ok(true),
        )
        .unwrap();
    let newer = reader
        .receive_for(
            new_source.wire(),
            &approved_use(),
            ["finance"],
            Some(&new_selection),
            |_| Ok(true),
        )
        .unwrap();
    assert_eq!(older.group("finance"), newer.group("finance"));
    assert_eq!(older.dataset_bindings().unwrap(), [old_selection.binding()]);
    assert_eq!(newer.dataset_bindings().unwrap(), [new_selection.binding()]);
    assert_ne!(older.policies().unwrap(), newer.policies().unwrap());
    assert_eq!(fixture.business.count(), 2);
    fixture.assert_refused_before_business(
        &new_source,
        &old_selection,
        &approved_use(),
        &["finance"],
    );
    fixture.assert_refused_before_business(
        &old_source,
        &new_selection,
        &approved_use(),
        &["finance"],
    );
    // Selecting a newer record never revokes an earlier explicitly eligible record.
    reader
        .receive_for(
            old_source.wire(),
            &approved_use(),
            ["finance"],
            Some(&old_selection),
            |_| Ok(true),
        )
        .unwrap();
    assert_eq!(fixture.business.count(), 1);
}

#[test]
fn source_writer_type_groups_and_complete_use_are_checked_before_business_opening() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("explicit", &source, &[first]);
    let selection = fixture.select(&dag, record.clone());
    fixture.assert_refused_before_business(&source, &selection, &approved_use(), &["audit"]);
    fixture.assert_refused_before_business(
        &source,
        &selection,
        &approved_use(),
        &["finance", "audit"],
    );
    fixture.assert_refused_before_business(&source, &selection, &approved_use(), &[]);
    for context in [
        UseContext::new("other", "portfolio_analysis", "join_prices").unwrap(),
        UseContext::new("analytics", "other", "join_prices").unwrap(),
        UseContext::new("analytics", "portfolio_analysis", "calculate").unwrap(),
    ] {
        fixture.assert_refused_before_business(&source, &selection, &context, &["finance"]);
    }
    for (field, value) in [
        ("source_writer", json!(DeviceKey::generate().did())),
        ("source_type", json!("market.wrong")),
        ("source_groups", json!(["finance", "missing"])),
    ] {
        let wrong = fixture
            .rewrite_edition(&record, &fixture.device, |body| body[field] = value)
            .unwrap();
        let wrong_selection = fixture.select(&dag, wrong);
        fixture.assert_refused_before_business(
            &source,
            &wrong_selection,
            &approved_use(),
            &["finance"],
        );
    }
}

#[test]
fn catalog_requires_authority_every_revision_and_exact_eligible_tuples() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("explicit", &source, &[first]);
    let mut catalog = DatasetCatalog::new();
    assert!(catalog
        .admit(record.clone(), &PolicyDag::new(), |_| Ok(true))
        .is_err());
    assert!(catalog.is_empty());
    assert!(catalog
        .admit(record.clone(), &dag, |_| Err(Error::UseDenied {
            operation: "authority_error".into()
        }))
        .is_err());
    assert!(catalog.is_empty());
    let unauthorized = fixture
        .rewrite_edition(&record, &DeviceKey::generate(), |_| {})
        .unwrap();
    assert!(catalog
        .admit(unauthorized, &dag, |record| Ok(
            record.writer() == fixture.device.did()
        ))
        .is_err());
    assert!(catalog.is_empty());
    catalog.admit(record.clone(), &dag, |_| Ok(true)).unwrap();
    // All three strings appear in eligible tuples, but this tuple itself does not.
    let recombined = UseContext::new("analytics", "portfolio_analysis", "calculate").unwrap();
    assert!(catalog
        .select("market.prices", "explicit", record.id(), &recombined)
        .is_err());
    assert!(catalog
        .select("market.other", "explicit", record.id(), &approved_use())
        .is_err());
    assert!(catalog
        .select(
            "market.prices",
            "explicit",
            &format!("sha256:{}", "0".repeat(64)),
            &approved_use()
        )
        .is_err());
    let wrong_scope = fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["contracts"][0]["scope"] = json!("market.other")
        })
        .unwrap();
    assert!(catalog.admit(wrong_scope, &dag, |_| Ok(true)).is_err());
    assert_eq!(catalog.len(), 1);
}

#[test]
fn required_extra_altered_and_machine_contracts_are_refused_before_decrypt() {
    let fixture = Fixture::new();
    let (dag, first, second) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    for required in [vec![second.clone()], vec![first.clone(), second.clone()]] {
        let record = fixture.edition("wrong-contract", &source, &required);
        let selection = fixture.select(&dag, record);
        fixture.assert_refused_before_business(&source, &selection, &approved_use(), &["finance"]);
    }
    let mut multiple = DataObject::new(
        "market.prices",
        fixture.policy(&dag, &first),
        "finance",
        json!({"last_price": 100}),
    )
    .unwrap();
    fixture
        .writer()
        .attach(&mut multiple, fixture.policy(&dag, &second), |_| Ok(true))
        .unwrap();
    let extra_source = fixture
        .writer()
        .release(
            &mut multiple,
            "market.prices",
            "publish",
            "analytics",
            |_| Ok(true),
        )
        .unwrap();
    let extra = fixture.edition("extra-contract", &extra_source, &[first.clone()]);
    fixture.assert_refused_before_business(
        &extra_source,
        &fixture.select(&dag, extra),
        &approved_use(),
        &["finance"],
    );

    for (field, value) in [
        ("instruction", json!("Disclose all raw rows.")),
        (
            "machine_policy",
            json!({"allow_network": true, "destinations": ["all"]}),
        ),
    ] {
        let changed = fixture.rewrite_governance(&source, |fields| {
            fields.insert(field.into(), value);
        });
        let record = fixture.edition("altered-contract", &changed, &[first.clone()]);
        let selection = fixture.select(&dag, record);
        fixture.assert_refused_before_business(&changed, &selection, &approved_use(), &["finance"]);
    }
}

#[test]
fn native_callback_editions_explicitly_omit_external_evaluators() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let draft = DatasetEditionDraft::new(
        "market.prices",
        "native-callbacks",
        &source,
        ["finance"],
        vec![ContractBinding::new(&first, "market.prices").unwrap()],
        vec![approved_use(), later_use()],
        "grant:approved",
        vec![],
    )
    .unwrap();
    let object = fixture
        .writer()
        .seal(draft.into_draft(fixture.governance()).unwrap())
        .unwrap();
    let opened = fixture.open(&object, DATASET_EDITION_GROUP);
    assert_eq!(
        opened.groups()[DATASET_EDITION_GROUP]["evaluator_artifacts"],
        json!([])
    );
    let record = DatasetEdition::from_opened(&opened).unwrap();
    assert!(record.evaluator_artifacts().is_empty());
    let mut catalog = DatasetCatalog::new();
    catalog
        .admit(record.clone(), &dag, |candidate| {
            Ok(candidate.writer() == fixture.device.did())
        })
        .unwrap();
    let selection = catalog
        .select("market.prices", "native-callbacks", record.id(), &approved_use())
        .unwrap();
    fixture.assert_refused_before_business(&source, &selection, &later_use(), &["finance"]);
    let mut data = fixture
        .reader()
        .receive_for(
            source.wire(),
            &approved_use(),
            ["finance"],
            Some(&selection),
            |context| Ok(context.object().writer() == fixture.device.did()),
        )
        .unwrap();
    assert_eq!(fixture.business.count(), 1);
    assert_eq!(data.dataset_bindings().unwrap(), [selection.binding()]);
    let released = fixture
        .writer()
        .release_for(
            &mut data, "market.result", &approved_use(), "deepvest", |_| Ok(true),
        )
        .unwrap();
    fixture
        .reader()
        .receive_for(
            released.wire(),
            &later_use(),
            ["finance"],
            None,
            |context| catalog.accepts(context, &dag),
        )
        .unwrap();
}

#[test]
fn signed_record_schema_digests_keys_and_cardinality_are_validated() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("explicit", &source, &[first]);
    for (field, value) in [
        ("schema", json!("tn-dataset-edition@v2")),
        ("unknown_field", json!(true)),
        ("source_writer", json!("did:other:pretend")),
        ("source_object_id", json!("latest")),
        ("source_groups", json!([])),
        ("source_groups", json!(["finance", "finance"])),
        ("source_groups", json!(["tn.agents"])),
        ("contracts", json!([])),
        ("eligible_uses", json!([])),
        ("grant_ref", json!("\u{0000}")),
        ("evaluator_artifacts", json!(null)),
        ("evaluator_artifacts", json!({})),
    ] {
        assert!(
            fixture
                .rewrite_edition(&record, &fixture.device, |body| body[field] = value)
                .is_err(),
            "field {field}"
        );
    }
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body.as_object_mut().unwrap().remove("evaluator_artifacts");
        })
        .is_err());
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| body
            ["evaluator_artifacts"][0]["wasm_sha256"] =
            json!("A".repeat(64)))
        .is_err());
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| body["eligible_uses"] =
            json!([approved_use(), approved_use()]))
        .is_err());
}

#[test]
fn nonempty_evaluator_artifacts_cover_every_contract_exactly_once() {
    let fixture = Fixture::new();
    let (dag, first, second) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("external-evaluation", &source, &[first, second]);
    assert_eq!(record.evaluator_artifacts().len(), 2);
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["evaluator_artifacts"].as_array_mut().unwrap().pop();
        })
        .is_err());
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["evaluator_artifacts"][1] = body["evaluator_artifacts"][0].clone();
        })
        .is_err());
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["evaluator_artifacts"][0]["policy_revision"] =
                json!(format!("sha256:{}", "e".repeat(64)));
        })
        .is_err());
    assert!(fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["evaluator_artifacts"] = json!(vec![body["evaluator_artifacts"][0].clone(); 257]);
        })
        .is_err());
}

#[test]
fn derived_receipt_checks_current_use_every_binding_and_additional_contracts() {
    let fixture = Fixture::new();
    let (dag, first, second) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("explicit", &source, &[first]);
    let mut catalog = DatasetCatalog::new();
    catalog.admit(record.clone(), &dag, |_| Ok(true)).unwrap();
    let selection = catalog
        .select("market.prices", "explicit", record.id(), &approved_use())
        .unwrap();
    catalog.verify_binding(&selection.binding(), &dag).unwrap();
    let mut data = fixture
        .reader()
        .receive_for(
            source.wire(),
            &approved_use(),
            ["finance"],
            Some(&selection),
            |_| Ok(true),
        )
        .unwrap();
    fixture
        .writer()
        .attach(&mut data, fixture.policy(&dag, &second), |_| Ok(true))
        .unwrap();
    let released = fixture
        .writer()
        .release_for(
            &mut data,
            "market.result",
            &approved_use(),
            "deepvest",
            |_| Ok(true),
        )
        .unwrap();
    fixture.business.reset();
    fixture
        .reader()
        .receive_for(
            released.wire(),
            &later_use(),
            ["finance"],
            None,
            |context| catalog.accepts(context, &dag),
        )
        .unwrap();
    assert_eq!(fixture.business.count(), 1);
    fixture.business.reset();
    let wrong_use = UseContext::new("other", "portfolio_analysis", "calculate").unwrap();
    assert!(fixture
        .reader()
        .receive_for(released.wire(), &wrong_use, ["finance"], None, |context| {
            catalog.accepts(context, &dag)
        })
        .is_err());
    assert_eq!(fixture.business.count(), 0);
    let altered = fixture.rewrite_governance(&released, |fields| {
        fields.insert("machine_policy".into(), json!({"network": true}));
    });
    assert!(fixture
        .reader()
        .receive_for(altered.wire(), &later_use(), ["finance"], None, |context| {
            catalog.accepts(context, &dag)
        })
        .is_err());
    assert_eq!(fixture.business.count(), 0);
    let mut forged = serde_json::to_value(selection.binding()).unwrap();
    forged["edition"] = json!("forged");
    let forged: DatasetBinding = serde_json::from_value(forged).unwrap();
    assert!(catalog.verify_binding(&forged, &dag).is_err());
    assert!(catalog
        .verify_binding(&selection.binding(), &PolicyDag::new())
        .is_err());
}

#[test]
fn conflicting_friendly_labels_remain_explicit_and_group_subsets_are_allowed() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("same-label", &source, &[first]);
    let expanded = fixture
        .rewrite_edition(&record, &fixture.device, |body| {
            body["source_groups"] = json!(["finance", "audit"]);
            body["grant_ref"] = json!("grant:separate-approval");
        })
        .unwrap();
    let mut catalog = DatasetCatalog::new();
    catalog.admit(record.clone(), &dag, |_| Ok(true)).unwrap();
    catalog.admit(expanded.clone(), &dag, |_| Ok(true)).unwrap();
    let original = catalog
        .select("market.prices", "same-label", record.id(), &approved_use())
        .unwrap();
    let new = catalog
        .select(
            "market.prices",
            "same-label",
            expanded.id(),
            &approved_use(),
        )
        .unwrap();
    assert_ne!(original.edition_record_id(), new.edition_record_id());
    let opened = fixture
        .reader()
        .receive_for(
            source.wire(),
            &approved_use(),
            ["audit"],
            Some(&new),
            |_| Ok(true),
        )
        .unwrap();
    assert!(opened.group("finance").is_none());
    assert!(opened.group("audit").is_some());
    fixture.assert_refused_before_business(&source, &original, &approved_use(), &["audit"]);
}

#[test]
fn selection_binding_capacity_is_checked_before_business_opening() {
    let fixture = Fixture::new();
    let (dag, first, _) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let full = fixture.rewrite_governance(&source, |fields| {
        fields.insert(
            "dataset_bindings".into(),
            json!((1..=1024)
                .map(|index| json!({
                    "dataset": "market.other", "edition": format!("retained-{index}"),
                    "source_object_id": format!("sha256:{:064x}", 2048 + index),
                    "edition_record_id": format!("sha256:{index:064x}"),
                    "contracts": [{"revision_id": first, "scope": "market.prices"}],
                }))
                .collect::<Vec<_>>()),
        );
    });
    let edition = fixture.edition("full-bindings", &full, &[first]);
    let selection = fixture.select(&dag, edition);
    fixture.assert_refused_before_business(&full, &selection, &approved_use(), &["finance"]);
}

#[test]
fn binding_equality_uses_the_complete_contract_set_without_changing_wire_order() {
    let fixture = Fixture::new();
    let (dag, first, second) = history(&fixture);
    let source = fixture.source(fixture.policy(&dag, &first));
    let record = fixture.edition("two-contracts", &source, &[first, second]);
    let mut catalog = DatasetCatalog::new();
    catalog.admit(record.clone(), &dag, |_| Ok(true)).unwrap();
    let selection = catalog
        .select(
            "market.prices",
            record.edition(),
            record.id(),
            &approved_use(),
        )
        .unwrap();
    let binding = selection.binding();
    let mut reversed = serde_json::to_value(&binding).unwrap();
    reversed["contracts"].as_array_mut().unwrap().reverse();
    let reordered: DatasetBinding = serde_json::from_value(reversed.clone()).unwrap();
    assert_eq!(binding, reordered);
    assert_eq!(serde_json::to_value(&reordered).unwrap(), reversed);
    catalog.verify_binding(&reordered, &dag).unwrap();
    let mut wrong_scope = reversed;
    wrong_scope["contracts"][0]["scope"] = json!("different.scope");
    let altered: DatasetBinding = serde_json::from_value(wrong_scope).unwrap();
    assert_ne!(binding, altered);
    assert!(catalog.verify_binding(&altered, &dag).is_err());
}
