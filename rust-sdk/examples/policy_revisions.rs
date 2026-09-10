//! Run with `cargo run --offline -p tn-proto --example policy_revisions`.

use serde_json::json;
use tn_proto::{
    Governance, GovernedDraft, Objects, PolicyDag, PolicyParent, PolicyRelation, PolicyRevision,
    PolicyRevisionDraft, POLICY_REVISION_GROUP, POLICY_REVISION_TYPE,
};

const ADMIN: &str = r#"---
version: 1
schema: tn-agents-policy@v1
---
## tn.policy.revision
### instruction
Publish and verify the approved policy revision.
### use_for
Research policy administration.
### do_not_use_for
Unapproved policy changes.
### consequences
Authority review.
### on_violation_or_error
Refuse the update.
"#;

const POLICY: &str = r#"---
version: 1
schema: tn-agents-policy@v1
---
## research.sample
### instruction
Compute an aggregate.
### use_for
Aggregate research.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
"#;

fn publish(
    objects: &Objects<'_>,
    admin: &Governance,
    draft: PolicyRevisionDraft,
) -> tn_core::Result<PolicyRevision> {
    let object = objects.seal(draft.into_draft(admin.clone())?)?;
    let reader = objects.reader_for(["tn.agents", POLICY_REVISION_GROUP])?;
    let view = reader.governance(&object)?;
    let writer_ok = view.object().writer() == objects.did();
    let admitted = view.authorize("publish-policy", |contract, operation| {
        Ok(writer_ok && contract == admin && operation == "publish-policy")
    })?;
    PolicyRevision::from_opened(&reader.open(&admitted, [POLICY_REVISION_GROUP])?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let objects = Objects::ephemeral(
        ADMIN,
        "policy-admin.md",
        &[POLICY_REVISION_GROUP, "observations", "reports"],
    )?;
    let admin = Governance::from_markdown(
        objects.did(),
        ADMIN,
        "policy-admin.md",
        POLICY_REVISION_TYPE,
    )?;
    let draft = |document: &str| {
        PolicyRevisionDraft::from_markdown(
            objects.did(),
            document,
            "agents.md",
            "research.sample",
            "research",
        )
    };
    let root = publish(&objects, &admin, draft(POLICY)?)?;
    let cohort_policy = POLICY.replace("version: 1", "version: 2").replace(
        "Aggregate research.",
        "Aggregate research with cohorts of at least ten.",
    );
    let review_policy = POLICY.replace("version: 1", "version: 3").replace(
        "Compute an aggregate.",
        "Compute an aggregate and require release review.",
    );
    let merged_policy = cohort_policy.replace("version: 2", "version: 4").replace(
        "Compute an aggregate.",
        "Compute an aggregate and require release review.",
    );
    let cohort = publish(
        &objects,
        &admin,
        draft(&cohort_policy)?.parent(root.id(), PolicyRelation::Extend)?,
    )?;
    let review = publish(
        &objects,
        &admin,
        draft(&review_policy)?.parent(root.id(), PolicyRelation::Extend)?,
    )?;
    let merged = publish(
        &objects,
        &admin,
        draft(&merged_policy)?
            .parent(cohort.id(), PolicyRelation::Combine)?
            .parent(review.id(), PolicyRelation::Combine)?,
    )?;

    // The application explicitly approves these authored effective contracts.
    let approved: Vec<String> = [POLICY, &cohort_policy, &review_policy, &merged_policy]
        .iter()
        .map(|document| {
            Ok(
                Governance::from_markdown(objects.did(), document, "agents.md", "research.sample")?
                    .policy_ref()
                    .to_owned(),
            )
        })
        .collect::<tn_core::Result<_>>()?;
    let authorize = |candidate: &PolicyRevision,
                     parent: Option<(&PolicyParent, &PolicyRevision)>| {
        Ok(candidate.writer() == objects.did()
            && candidate.governance().governed_by() == objects.did()
            && candidate.scope() == "research"
            && approved
                .iter()
                .any(|p| p == candidate.governance().policy_ref())
            && parent.is_none_or(|(_, p)| {
                p.scope() == "research" && p.governance().governed_by() == objects.did()
            }))
    };
    let mut dag = PolicyDag::new();
    dag.admit(root.clone(), authorize)?;
    let original_policy = dag.select(root.id(), "research", |_| Ok(true))?;
    let source = objects.seal(
        GovernedDraft::new("research.sample", original_policy)?
            .group("observations", json!({"count": 30}))?,
    )?;
    let original_wire = source.wire().to_owned();
    for revision in [&cohort, &review, &merged] {
        dag.admit(revision.clone(), authorize)?;
    }

    let reader = objects.reader_for(["tn.agents", "observations", "reports"])?;
    let view = reader.governance(&source)?;
    let admitted = view.authorize("aggregate", |contract, operation| {
        Ok(dag.resolve(contract, "research")?.id() == root.id() && operation == "aggregate")
    })?;
    let opened = reader.open(&admitted, ["observations"])?;
    let count = opened.groups()["observations"]["count"]
        .as_u64()
        .ok_or("required count")?;
    let selected = dag.select(merged.id(), "research", |r| {
        Ok(r.id() == merged.id() && count >= 10)
    })?;
    // This local example's release review accepts the checked aggregate value.
    assert_eq!(count, 30);
    let result = objects.seal(
        opened
            .derive_under("research.aggregate", selected)?
            .group("reports", json!({"total": count}))?,
    )?;
    let released = reader.governance(&result)?;
    assert_eq!(
        dag.resolve(released.governance(), "research")?.id(),
        merged.id()
    );
    assert_eq!(
        released.governance().get("source_lineage").unwrap()[0]["policy_revision"],
        root.id()
    );
    assert_eq!(source.wire(), original_wire);
    assert_eq!(dag.len(), 4);
    println!("PASS: signed root, two branches, authorized merge, selected revision, preserved source policy and exhaust");
    Ok(())
}
