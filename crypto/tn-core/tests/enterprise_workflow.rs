#![cfg(feature = "fs")]
use serde_json::json;
use tn_core::governed::{Governance, SourceReference};
use tn_core::runtime::Objects;

const POLICY: &str = "## account\n### instruction\nCalculate totals.\n### use_for\nAnalysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

fn setup() -> (Objects<'static>, Governance) {
    let objects = Objects::ephemeral(POLICY, "unity/accounts", &["data", "private"]).unwrap();
    let policy =
        Governance::from_markdown(objects.did(), POLICY, "unity/accounts", "account").unwrap();
    (objects, policy)
}

#[test]
fn complete_origin_has_one_snapshot_and_no_partial_causal_input() {
    let (objects, policy) = setup();
    let data = objects
        .create_obj_with_groups(
            "account",
            policy.clone(),
            [
                ("data", json!({"balance": 1200})),
                ("private", json!({"owner": "Ada"})),
            ],
        )
        .unwrap();
    assert_eq!(data.history().len(), 1);
    let snapshot = data.snapshot().unwrap();
    assert_eq!(snapshot.group_names(), ["data", "private", "tn.agents"]);
    let reader = objects.reader().unwrap();
    assert!(reader
        .governance(snapshot)
        .unwrap()
        .governance()
        .source_references()
        .unwrap()
        .is_empty());
    let received =
        objects
            .receive(snapshot.wire(), "analysis", ["data", "private"], |ctx| {
                Ok(ctx.object().writer() == objects.did()
                    && ctx.governance().matches_contract(&policy))
            })
            .unwrap();
    assert_eq!(received.group("data").unwrap()["balance"], 1200);
    assert_eq!(received.group("private").unwrap()["owner"], "Ada");
}

#[test]
fn invalid_group_collection_creates_no_register_entry() {
    let (objects, policy) = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("created.jsonl");
    let objects = objects.with_registers(tn_core::runtime::ObjectRegisters::new(
        Some(path.clone()),
        None,
    ));
    for groups in [
        vec![],
        vec![("data", json!({})), ("data", json!({"x": 1}))],
        vec![("data", json!({})), ("tn.agents", json!({}))],
        vec![("data", json!(7))],
        vec![("missing", json!({}))],
    ] {
        assert!(objects
            .create_obj_with_groups("account", policy.clone(), groups)
            .is_err());
        assert!(!path.exists());
    }
}

#[test]
fn unreleased_changes_track_mutation_refusal_and_successful_release() {
    let (objects, policy) = setup();
    let mut data = objects
        .create_obj("account", policy, "data", json!({"balance": 1200}))
        .unwrap();
    assert!(!data.has_unreleased_changes());
    let original = data.snapshot().unwrap().clone();
    assert!(data.set_group("tn.agents", json!({})).is_err());
    assert!(!data.has_unreleased_changes());
    data.set_field("data", "balance", json!(400)).unwrap();
    assert!(data.has_unreleased_changes());
    assert!(objects
        .release(&mut data, "account", "analysis", "public", |_| Ok(false))
        .is_err());
    assert!(data.has_unreleased_changes());
    assert_eq!(data.snapshot().unwrap().wire(), original.wire());
    let released = objects
        .release(&mut data, "account", "analysis", "internal", |ctx| {
            assert!(ctx.data().has_unreleased_changes());
            Ok(true)
        })
        .unwrap();
    assert!(!data.has_unreleased_changes());
    let received = objects
        .receive(released.wire(), "analysis", ["data"], |_| Ok(true))
        .unwrap();
    assert!(!received.has_unreleased_changes());
    assert_eq!(data.history()[0].wire(), original.wire());
}

#[test]
fn source_association_checks_the_accepted_revision_and_contract_identity() {
    let (objects, policy) = setup();
    let data = objects
        .create_obj("account", policy.clone(), "data", json!({}))
        .unwrap();
    let object = data.snapshot().unwrap();
    let source = &data.sources()[0];
    assert!(source.references_with_policy(object, &policy));
    let mut altered = serde_json::to_value(source).unwrap();
    altered["policy_revision"] = json!(format!("sha256:{}", "a".repeat(64)));
    let altered: SourceReference = serde_json::from_value(altered).unwrap();
    assert!(altered.references(object));
    assert!(!altered.references_with_policy(object, &policy));
    let different =
        Governance::from_markdown(objects.did(), POLICY, "unity/different", "account").unwrap();
    assert!(!source.references_with_policy(object, &different));
}

#[test]
fn projection_validates_before_removing_plaintext_or_hidden_groups() {
    let (objects, policy) = setup();
    let source = objects
        .create_obj_with_groups(
            "account",
            policy.clone(),
            [
                ("data", json!({"balance": 5})),
                ("private", json!({"owner": "Ada"})),
            ],
        )
        .unwrap();
    let original = source.snapshot().unwrap();
    let mut data = objects
        .receive(original.wire(), "analysis", ["data"], |_| Ok(true))
        .unwrap();
    let generation = data.revision();
    assert!(data.retain_groups(["data", "missing"]).is_err());
    assert!(data.retain_groups(["tn.agents"]).is_err());
    assert_eq!(data.revision(), generation);
    assert_eq!(data.hidden_groups(), ["private"]);
    assert!(!data.has_unreleased_changes());
    data.retain_groups(["private"]).unwrap();
    assert!(data.groups().is_empty());
    assert_eq!(data.hidden_groups(), ["private"]);
    let released = objects
        .release(&mut data, "account", "archive", "internal", |_| Ok(true))
        .unwrap();
    assert_eq!(released.group_names(), ["private", "tn.agents"]);
    assert_eq!(
        released.envelope()["private"],
        original.envelope()["private"]
    );
    assert_eq!(data.history()[0].wire(), original.wire());
    assert!(data.governance().matches_contract(&policy));
}

#[test]
fn source_matches_the_exact_admitted_signed_policy_revision() {
    use tn_core::governed::{
        PolicyDag, PolicyRevision, PolicyRevisionDraft, POLICY_REVISION_GROUP,
    };
    let objects =
        Objects::ephemeral(POLICY, "unity/accounts", &["data", POLICY_REVISION_GROUP]).unwrap();
    let admin =
        Governance::from_markdown(objects.did(), POLICY, "unity/accounts", "account").unwrap();
    let reader = objects.reader().unwrap();
    let mut dag = PolicyDag::new();
    let mut selected = Vec::new();
    // Equal content can belong to different signed historical publications.
    for _ in 0..2 {
        let draft = PolicyRevisionDraft::from_markdown(
            objects.did(),
            POLICY,
            "unity/accounts",
            "account",
            "accounts",
        )
        .unwrap();
        let sealed = objects
            .seal(draft.into_draft(admin.clone()).unwrap())
            .unwrap();
        let admitted = reader
            .governance(&sealed)
            .unwrap()
            .authorize("policy.accept", |policy, _| {
                Ok(policy.matches_contract(&admin))
            })
            .unwrap();
        let revision =
            PolicyRevision::from_opened(&reader.open(&admitted, [POLICY_REVISION_GROUP]).unwrap())
                .unwrap();
        let id = revision.id().to_owned();
        dag.admit(revision, |node, parent| {
            Ok(parent.is_none() && node.writer() == objects.did() && node.scope() == "accounts")
        })
        .unwrap();
        selected.push(dag.select(&id, "accounts", |_| Ok(true)).unwrap());
    }
    let data = objects
        .create_obj("account", selected[0].clone(), "data", json!({}))
        .unwrap();
    let source = &data.sources()[0];
    assert!(source.references_with_policy(data.snapshot().unwrap(), &selected[0]));
    assert!(!source.references_with_policy(data.snapshot().unwrap(), &selected[1]));
    assert!(!source.references_with_policy(data.snapshot().unwrap(), &admin));
}
