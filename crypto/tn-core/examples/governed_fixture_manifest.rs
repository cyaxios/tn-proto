//! Export retained M1 test publications, or replay their native acceptance checks.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tn_core::cipher::{btn::BtnPublisherCipher, btn::BtnReaderCipher, GroupCipher};
use tn_core::governed::*;
use tn_core::{DeviceKey, Error, Result};

const SCHEMA: &str = "tn-governed-m1-fixtures@v1";
const CEREMONY: &str = "cer_governed_m1_test_fixture";
const GROUPS: [&str; 5] = [
    "tn.agents",
    "policy_revision",
    "dataset_edition",
    "finance",
    "audit",
];
const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## finance.wealth_path\n### instruction\nCalculate approved portfolio drawdown.\n### use_for\nPortfolio research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";
const TEST_SEED: [u8; 32] = [0x51; 32];
const INDEX_MASTER: [u8; 32] = [0x37; 32];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupMaterial {
    publisher_state_base64: String,
    reader_kit_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    object_id: String,
    writer: String,
    object_type: String,
    wire: String,
}

impl From<&GovernedObject> for Publication {
    fn from(object: &GovernedObject) -> Self {
        Self {
            object_id: object.id().into(),
            writer: object.writer().into(),
            object_type: object.object_type().into(),
            wire: object.wire().into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    publication: String,
    selection: Option<String>,
    use_name: String,
    groups: Vec<String>,
    decision: String,
    allowed: bool,
    decision_calls: usize,
    business_decrypts: usize,
    error_contains: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRelease {
    contracts: Vec<String>,
    dataset_bindings: Vec<DatasetBinding>,
    parent_ids: Vec<String>,
    lineage_object_ids: Vec<String>,
    finance: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    test_only: bool,
    producer: Value,
    private_seed_hex: String,
    index_master_hex: String,
    writer: String,
    groups: BTreeMap<String, GroupMaterial>,
    uses: BTreeMap<String, UseContext>,
    publications: BTreeMap<String, Publication>,
    expected_releases: BTreeMap<String, ExpectedRelease>,
    cases: Vec<Case>,
}

fn writer<'a>(
    device: &'a DeviceKey,
    groups: &BTreeMap<String, GroupMaterial>,
) -> Result<GovernedWriter<'a>> {
    let mut writer = GovernedWriter::new(device);
    for name in GROUPS {
        let group = &groups[name];
        let cipher = BtnPublisherCipher::from_state_bytes(
            &STANDARD.decode(&group.publisher_state_base64).unwrap(),
        )?
        .with_reader_kit(&STANDARD.decode(&group.reader_kit_base64).unwrap())?;
        let index = tn_core::indexing::derive_group_index_key(&INDEX_MASTER, CEREMONY, name, 0)?;
        writer = writer.with_group(name, Arc::new(cipher), &index)?;
    }
    Ok(writer)
}

struct Probe {
    inner: BtnReaderCipher,
    calls: Arc<AtomicUsize>,
}
impl GroupCipher for Probe {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(bytes)
    }
    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(bytes)
    }
    fn encrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt_with_aad(bytes, aad)
    }
    fn decrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_with_aad(bytes, aad)
    }
}

fn reader(groups: &BTreeMap<String, GroupMaterial>) -> Result<(GovernedReader, Arc<AtomicUsize>)> {
    let business = Arc::new(AtomicUsize::new(0));
    let mut reader = GovernedReader::new();
    for name in GROUPS {
        let cipher = BtnReaderCipher::from_kit_bytes(
            &STANDARD.decode(&groups[name].reader_kit_base64).unwrap(),
        )?;
        let counter = if matches!(name, "finance" | "audit") {
            business.clone()
        } else {
            Arc::new(AtomicUsize::new(0))
        };
        reader = reader.with_group(
            name,
            Arc::new(Probe {
                inner: cipher,
                calls: counter,
            }),
        )?;
    }
    Ok((reader, business))
}

fn metadata(reader: &GovernedReader, object: &GovernedObject, group: &str) -> Result<OpenedObject> {
    let admitted = reader.governance(object)?.accept(
        UseContext::new("fixture.catalog", "administration", "inspect")?,
        [group],
        |_| Ok(true),
    )?;
    reader.open(&admitted, [group])
}

fn make_case(
    name: &str,
    publication: &str,
    selection: Option<&str>,
    use_name: &str,
    decision: &str,
    allowed: bool,
    calls: usize,
    error: Option<&str>,
) -> Case {
    Case {
        name: name.into(),
        publication: publication.into(),
        selection: selection.map(str::to_owned),
        use_name: use_name.into(),
        groups: vec!["finance".into()],
        decision: decision.into(),
        allowed,
        decision_calls: calls,
        business_decrypts: usize::from(allowed),
        error_contains: error.map(str::to_owned),
    }
}

fn export() -> Result<Manifest> {
    let device = DeviceKey::from_private_bytes(&TEST_SEED)?;
    let mut groups = BTreeMap::new();
    for name in GROUPS {
        let mut state = tn_btn::PublisherState::setup(tn_btn::Config)?;
        let kit = state.mint()?;
        groups.insert(
            name.to_owned(),
            GroupMaterial {
                publisher_state_base64: STANDARD.encode(state.to_bytes()),
                reader_kit_base64: STANDARD.encode(kit.to_bytes()),
            },
        );
    }
    let writer = writer(&device, &groups)?;
    let (reader, _) = reader(&groups)?;
    let mut uses = BTreeMap::new();
    for (name, application, purpose, operation) in [
        (
            "source",
            "analytics",
            "portfolio_analysis",
            "compare_editions",
        ),
        ("deepvest", "deepvest", "portfolio_analysis", "calculate"),
        ("model", "tn-llama", "portfolio_analysis", "generate_report"),
        (
            "wrong_application",
            "unapproved-app",
            "portfolio_analysis",
            "compare_editions",
        ),
        (
            "wrong_purpose",
            "analytics",
            "advertising",
            "compare_editions",
        ),
        (
            "wrong_operation",
            "analytics",
            "portfolio_analysis",
            "redistribute",
        ),
    ] {
        uses.insert(
            name.into(),
            UseContext::new(application, purpose, operation)?,
        );
    }
    let administration = Governance::from_markdown(
        device.did(),
        POLICY,
        "fixture.admin.md",
        "finance.wealth_path",
    )?;
    let mut dag = PolicyDag::new();
    let mut catalog = DatasetCatalog::new();
    let mut objects = BTreeMap::<String, GovernedObject>::new();
    let mut inputs = Vec::new();
    let finance = json!({"wealth_path": [100,120,90,135], "units":"index", "synthetic":true});
    for (name, version, edition) in [
        ("earlier", "1", "history-2026-09-08"),
        ("later", "2", "close-2026-09-09"),
    ] {
        let policy_object = writer.seal(
            PolicyRevisionDraft::from_markdown(
                device.did(),
                &POLICY.replace("version: 1", &format!("version: {version}")),
                "fixture.wealth.md",
                "finance.wealth_path",
                "finance.wealth_path",
            )?
            .into_draft(administration.clone())?,
        )?;
        let revision = PolicyRevision::from_opened(&metadata(
            &reader,
            &policy_object,
            POLICY_REVISION_GROUP,
        )?)?;
        let revision_id = revision.id().to_owned();
        dag.admit(revision, |record, _| Ok(record.writer() == device.did()))?;
        let policy = dag.select(&revision_id, "finance.wealth_path", |_| Ok(true))?;
        let source = writer.seal(
            GovernedDraft::new("finance.wealth_path", policy)?
                .group("finance", finance.clone())?
                .group("audit", json!({"fixture":"M1", "edition":edition}))?,
        )?;
        let artifacts = EvaluatorArtifactSet::new(
            &revision_id,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
        )?;
        let edition_object = writer.seal(
            DatasetEditionDraft::new(
                "finance.wealth_path",
                edition,
                &source,
                ["finance"],
                vec![ContractBinding::new(&revision_id, "finance.wealth_path")?],
                vec![
                    uses["source"].clone(),
                    uses["deepvest"].clone(),
                    uses["model"].clone(),
                ],
                "grant:synthetic-m1",
                vec![artifacts],
            )?
            .into_draft(administration.clone())?,
        )?;
        let record = DatasetEdition::from_opened(&metadata(
            &reader,
            &edition_object,
            DATASET_EDITION_GROUP,
        )?)?;
        catalog.admit(record, &dag, |record| Ok(record.writer() == device.did()))?;
        let selection = catalog.select(
            "finance.wealth_path",
            edition,
            edition_object.id(),
            &uses["source"],
        )?;
        inputs.push(reader.receive_for(
            source.wire(),
            &uses["source"],
            ["finance"],
            Some(&selection),
            |_| Ok(true),
        )?);
        objects.insert(format!("policy_{name}"), policy_object);
        objects.insert(format!("edition_{name}"), edition_object);
        objects.insert(format!("source_{name}"), source);
    }
    let mut joined_data = inputs[0].clone();
    joined_data.include(&inputs[1])?;
    joined_data.set_field("finance", "editions_compared", json!(2))?;
    let joined = writer.release_for(
        &mut joined_data,
        "finance.prepared",
        &uses["source"],
        "deepvest",
        |_| Ok(true),
    )?;
    let mut calculation = reader.receive_for(
        joined.wire(),
        &uses["deepvest"],
        ["finance"],
        None,
        |context| catalog.accepts(context, &dag),
    )?;
    calculation.set_group(
        "finance",
        json!({"calculation":{
        "function":"max_drawdown", "engine":"m1-fixture-arithmetic", "version":"1",
        "method":"maximum peak-to-trough fractional decline", "units":"fraction",
        "arguments":{"wealth_path":[100,120,90,135]}, "result":0.25
    }, "synthetic":true}),
    )?;
    let deepvest = writer.release_for(
        &mut calculation,
        "deepvest.calculation",
        &uses["deepvest"],
        "tn-llama",
        |_| Ok(true),
    )?;

    // Ordinary signing of deliberate negative declarations. These remain valid
    // TN objects; their failures must occur at lineage/admission, not signature verification.
    let opened_joined = metadata(&reader, &joined, "finance")?;
    let lost_contract = writer.seal(
        opened_joined
            .derive_under("deepvest.calculation", inputs[0].governance().clone())?
            .group("finance", json!({"result":0.25}))?,
    )?;
    let policies = calculation.policies()?;
    let mut unbound = DataObject::new(
        "deepvest.calculation",
        policies[0].clone(),
        "finance",
        json!({"result":0.25}),
    )?;
    for policy in &policies[1..] {
        unbound.attach(device.did(), policy.clone(), |_| Ok(true))?;
    }
    let lost_binding = writer.seal(
        opened_joined
            .derive_under("deepvest.calculation", unbound.governance().clone())?
            .group("finance", json!({"result":0.25}))?,
    )?;
    let unreached = writer.seal(
        GovernedDraft::new("finance.prepared", joined_data.governance().clone())?
            .group("finance", json!({"wealth_path":[100,120,90,135]}))?,
    )?;
    objects.insert("joined".into(), joined);
    objects.insert("deepvest".into(), deepvest);
    objects.insert("lost_contract".into(), lost_contract);
    objects.insert("lost_binding".into(), lost_binding);
    objects.insert("unreached_origins".into(), unreached);

    let mut expected_releases = BTreeMap::new();
    for name in ["joined", "deepvest"] {
        let object = &objects[name];
        let view = reader.governance(object)?;
        let proof = LineageVerifier::default().verify(&view, &catalog, &dag, |id| {
            reader.governance(
                objects
                    .values()
                    .find(|object| object.id() == id)
                    .expect("retained parent"),
            )
        })?;
        expected_releases.insert(
            name.into(),
            ExpectedRelease {
                contracts: view
                    .governance()
                    .policies()?
                    .iter()
                    .map(|p| p.revision_id().unwrap().into())
                    .collect(),
                dataset_bindings: view.governance().dataset_bindings()?,
                parent_ids: view
                    .governance()
                    .source_references()?
                    .iter()
                    .map(|r| r.object_id().into())
                    .collect(),
                lineage_object_ids: proof.object_ids().to_vec(),
                finance: metadata(&reader, object, "finance")?.groups()["finance"].clone(),
            },
        );
    }
    let mut cases = vec![
        make_case(
            "earlier_edition",
            "source_earlier",
            Some("earlier"),
            "source",
            "accept",
            true,
            1,
            None,
        ),
        make_case(
            "later_edition",
            "source_later",
            Some("later"),
            "source",
            "accept",
            true,
            1,
            None,
        ),
        make_case(
            "source_substitution",
            "source_later",
            Some("earlier"),
            "source",
            "accept",
            false,
            0,
            Some("selected source identity"),
        ),
        make_case(
            "wrong_application",
            "source_earlier",
            Some("earlier"),
            "wrong_application",
            "accept",
            false,
            0,
            Some("application refused operation"),
        ),
        make_case(
            "wrong_purpose",
            "source_earlier",
            Some("earlier"),
            "wrong_purpose",
            "accept",
            false,
            0,
            Some("application refused operation"),
        ),
        make_case(
            "wrong_operation",
            "source_earlier",
            Some("earlier"),
            "wrong_operation",
            "accept",
            false,
            0,
            Some("application refused operation"),
        ),
        make_case(
            "callback_refusal",
            "source_earlier",
            Some("earlier"),
            "source",
            "refuse",
            false,
            1,
            Some("application refused operation"),
        ),
        make_case(
            "callback_error",
            "source_earlier",
            Some("earlier"),
            "source",
            "error",
            false,
            1,
            Some("fixture callback error"),
        ),
        make_case(
            "deepvest_receives_joined",
            "joined",
            None,
            "deepvest",
            "accept",
            true,
            1,
            None,
        ),
        make_case(
            "model_receives_exact_deepvest",
            "deepvest",
            None,
            "model",
            "accept",
            true,
            1,
            None,
        ),
        make_case(
            "derived_wrong_use",
            "deepvest",
            None,
            "wrong_application",
            "accept",
            false,
            1,
            Some("application refused operation"),
        ),
        make_case(
            "omitted_contributing_contract",
            "lost_contract",
            None,
            "model",
            "accept",
            false,
            1,
            Some("every parent contract"),
        ),
        make_case(
            "omitted_dataset_binding",
            "lost_binding",
            None,
            "model",
            "accept",
            false,
            1,
            Some("every parent dataset binding"),
        ),
        make_case(
            "unreached_declared_origins",
            "unreached_origins",
            None,
            "model",
            "accept",
            false,
            1,
            Some("reached origins"),
        ),
    ];
    let mut wrong_group = make_case(
        "unselected_business_group",
        "source_earlier",
        Some("earlier"),
        "source",
        "accept",
        false,
        0,
        Some("supplied by the selected edition"),
    );
    wrong_group.groups = vec!["audit".into()];
    cases.push(wrong_group);
    Ok(Manifest {
        schema: SCHEMA.into(),
        test_only: true,
        producer: json!({"example":"crypto/tn-core/examples/governed_fixture_manifest.rs",
            "example_sha256":hex::encode(Sha256::digest(include_bytes!("governed_fixture_manifest.rs"))),
            "sdk_commit": std::process::Command::new("git").args(["rev-parse", "HEAD"])
                .output().ok().filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok()).map(|head| head.trim().to_owned()),
            "tn_core_version":env!("CARGO_PKG_VERSION"),
            "regeneration":"fresh randomized publications; replay this retained manifest with --verify"}),
        private_seed_hex: hex::encode(TEST_SEED),
        index_master_hex: hex::encode(INDEX_MASTER),
        writer: device.did().into(),
        groups,
        uses,
        publications: objects
            .iter()
            .map(|(name, object)| (name.clone(), Publication::from(object)))
            .collect(),
        expected_releases,
        cases,
    })
}

fn verify(manifest: &Manifest) -> Result<()> {
    assert_eq!(manifest.schema, SCHEMA);
    assert!(manifest.test_only);
    assert_eq!(manifest.private_seed_hex, hex::encode(TEST_SEED));
    assert_eq!(manifest.index_master_hex, hex::encode(INDEX_MASTER));
    assert_eq!(
        manifest.writer,
        DeviceKey::from_private_bytes(&TEST_SEED)?.did()
    );
    let (reader, business) = reader(&manifest.groups)?;
    let objects: BTreeMap<String, GovernedObject> = manifest
        .publications
        .iter()
        .map(|(name, publication)| {
            let object = GovernedObject::parse(&publication.wire)?;
            assert_eq!(object.id(), publication.object_id);
            assert_eq!(object.writer(), publication.writer);
            assert_eq!(object.object_type(), publication.object_type);
            assert_eq!(object.writer(), manifest.writer);
            Ok((name.clone(), object))
        })
        .collect::<Result<_>>()?;
    let mut dag = PolicyDag::new();
    let mut catalog = DatasetCatalog::new();
    let mut selections = BTreeMap::new();
    for name in ["earlier", "later"] {
        let revision = PolicyRevision::from_opened(&metadata(
            &reader,
            &objects[&format!("policy_{name}")],
            POLICY_REVISION_GROUP,
        )?)?;
        dag.admit(revision, |record, _| Ok(record.writer() == manifest.writer))?;
        let edition = DatasetEdition::from_opened(&metadata(
            &reader,
            &objects[&format!("edition_{name}")],
            DATASET_EDITION_GROUP,
        )?)?;
        let (dataset, edition_name, record_id) = (
            edition.dataset().to_owned(),
            edition.edition().to_owned(),
            edition.id().to_owned(),
        );
        catalog.admit(edition, &dag, |record| {
            Ok(record.writer() == manifest.writer)
        })?;
        selections.insert(
            name,
            catalog.select(
                &dataset,
                &edition_name,
                &record_id,
                &manifest.uses["source"],
            )?,
        );
    }
    let resolve = |id: &str| {
        reader.governance(
            objects
                .values()
                .find(|object| object.id() == id)
                .expect("retained parent"),
        )
    };
    for (name, expected) in &manifest.expected_releases {
        let view = reader.governance(&objects[name])?;
        let proof = LineageVerifier::default().verify(&view, &catalog, &dag, resolve)?;
        assert_eq!(proof.object_ids(), expected.lineage_object_ids);
        assert_eq!(
            view.governance().dataset_bindings()?,
            expected.dataset_bindings
        );
        assert_eq!(
            view.governance()
                .policies()?
                .iter()
                .map(|p| p.revision_id().unwrap().to_owned())
                .collect::<Vec<_>>(),
            expected.contracts
        );
        assert_eq!(
            view.governance()
                .source_references()?
                .iter()
                .map(|r| r.object_id().to_owned())
                .collect::<Vec<_>>(),
            expected.parent_ids
        );
    }
    for case in &manifest.cases {
        let object = &objects[&case.publication];
        let view = reader.governance(object)?;
        let selection = case
            .selection
            .as_ref()
            .map(|name| &selections[name.as_str()]);
        business.store(0, Ordering::SeqCst);
        let mut calls = 0;
        let opened = reader.receive_for(
            object.wire(),
            &manifest.uses[&case.use_name],
            &case.groups,
            selection,
            |context| {
                calls += 1;
                if case.decision == "error" {
                    return Err(Error::Malformed {
                        kind: "fixture",
                        reason: "fixture callback error".into(),
                    });
                }
                if case.decision == "refuse" {
                    return Ok(false);
                }
                assert_eq!(case.decision, "accept");
                if selection.is_none() {
                    LineageVerifier::default().verify(&view, &catalog, &dag, resolve)?;
                    return catalog.accepts(context, &dag);
                }
                Ok(context.object().writer() == manifest.writer)
            },
        );
        assert_eq!(
            opened.is_ok(),
            case.allowed,
            "{}: {:?}",
            case.name,
            opened.as_ref().err()
        );
        assert_eq!(calls, case.decision_calls, "{} decision calls", case.name);
        assert_eq!(
            business.load(Ordering::SeqCst),
            case.business_decrypts,
            "{} business decrypts",
            case.name
        );
        match opened {
            Ok(data) => {
                if let Some(selection) = selection {
                    assert_eq!(data.dataset_bindings()?, [selection.binding()]);
                }
                if let Some(expected) = manifest.expected_releases.get(&case.publication) {
                    assert_eq!(
                        Value::Object(data.group("finance").unwrap().clone()),
                        expected.finance
                    );
                }
            }
            Err(error) => assert!(
                error
                    .to_string()
                    .contains(case.error_contains.as_ref().expect("refusal reason")),
                "{}: {error}",
                case.name
            ),
        }
    }
    Ok(())
}

fn materialize(
    manifest: &Manifest,
    directory: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    verify(manifest)?;
    // Require a fresh named directory; never replace an existing session's material.
    std::fs::create_dir(directory)?;
    let keys = directory.join("keys");
    std::fs::create_dir(&keys)?;
    std::fs::write(keys.join("local.private"), TEST_SEED)?;
    std::fs::write(keys.join("index_master.key"), INDEX_MASTER)?;
    for name in GROUPS {
        std::fs::write(
            keys.join(format!("{name}.btn.state")),
            STANDARD.decode(&manifest.groups[name].publisher_state_base64)?,
        )?;
        std::fs::write(
            keys.join(format!("{name}.btn.mykit")),
            STANDARD.decode(&manifest.groups[name].reader_kit_base64)?,
        )?;
    }
    let groups: BTreeMap<_, _> = GROUPS
        .iter()
        .map(|name| {
            (
                *name,
                json!({"cipher":"btn", "policy":"private", "index_epoch":0}),
            )
        })
        .collect();
    let config = json!({"ceremony":{"id":CEREMONY, "cipher":"btn", "mode":"local"},
        "keystore":{"path":"keys"}, "device":{"device_identity":manifest.writer}, "groups":groups});
    std::fs::write(
        directory.join("tn.yaml"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    std::fs::write(directory.join("tn.agents.md"), POLICY)?;
    let session = tn_core::runtime::Objects::open(&directory.join("tn.yaml"))?;
    let source = &manifest.publications["source_earlier"];
    let opened = session.receive_for(
        &source.wire,
        &manifest.uses["source"],
        ["finance"],
        None,
        |_| Ok(true),
    )?;
    assert_eq!(
        opened.group("finance").unwrap()["wealth_path"],
        json!([100, 120, 90, 135])
    );
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_] => { let manifest = export()?; verify(&manifest)?; println!("{}", serde_json::to_string_pretty(&manifest)?); }
        [_, flag, path] if flag == "--export" => {
            let manifest = export()?;
            verify(&manifest)?;
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&manifest)?))?;
            println!("Exported and verified {} publications and {} admission cases.", manifest.publications.len(), manifest.cases.len());
        }
        [_, flag, path] if flag == "--verify" => {
            let manifest: Manifest = serde_json::from_slice(&std::fs::read(path)?)?;
            verify(&manifest)?;
            println!("Verified {} exact publications, {} release graphs and {} admission cases.", manifest.publications.len(), manifest.expected_releases.len(), manifest.cases.len());
        }
        [_, flag, path, directory] if flag == "--materialize" => {
            let manifest = serde_json::from_slice(&std::fs::read(path)?)?;
            materialize(&manifest, Path::new(directory))?;
            println!("Materialized and reopened the test session at {directory}.");
        }
        _ => return Err("usage: governed_fixture_manifest [--export manifest.json | --verify manifest.json | --materialize manifest.json NEW_DIRECTORY]".into()),
    }
    Ok(())
}
