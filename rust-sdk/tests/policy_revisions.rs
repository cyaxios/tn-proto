use tn_proto::{
    Governance, Objects, PolicyDag, PolicyRelation, PolicyRevision, PolicyRevisionDraft,
    POLICY_REVISION_GROUP, POLICY_REVISION_TYPE,
};

const POLICY: &str = "---\nversion: 1\n---\n## tn.policy.revision\n### instruction\nPublish approved rules.\n### use_for\nPolicy administration.\n### do_not_use_for\nUnapproved updates.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

#[test]
fn sdk_exports_signed_revision_construction_and_explicit_selection() {
    let objects = Objects::ephemeral(POLICY, "policy-admin.md", &[POLICY_REVISION_GROUP]).unwrap();
    let admin = Governance::from_markdown(
        objects.did(),
        POLICY,
        "policy-admin.md",
        POLICY_REVISION_TYPE,
    )
    .unwrap();
    let draft = PolicyRevisionDraft::from_markdown(
        objects.did(),
        POLICY,
        "agents.md",
        POLICY_REVISION_TYPE,
        "research",
    )
    .unwrap();
    let object = objects
        .seal(draft.into_draft(admin.clone()).unwrap())
        .unwrap();
    let reader = objects.reader().unwrap();
    let view = reader.governance(&object).unwrap();
    let admitted = view
        .authorize("publish-policy", |contract, _| Ok(contract == &admin))
        .unwrap();
    let opened = reader.open(&admitted, [POLICY_REVISION_GROUP]).unwrap();
    let revision = PolicyRevision::from_opened(&opened).unwrap();
    let id = revision.id().to_owned();
    let mut dag = PolicyDag::new();
    dag.admit(revision, |revision, parent| {
        Ok(parent.is_none() && revision.writer() == objects.did())
    })
    .unwrap();
    let contract = dag.select(&id, "research", |_| Ok(true)).unwrap();
    assert_eq!(contract.revision_id(), Some(id.as_str()));
    assert_eq!(dag.resolve(&contract, "research").unwrap().id(), id);
    assert_eq!(
        serde_json::to_value(PolicyRelation::Combine).unwrap(),
        "combine"
    );
}
