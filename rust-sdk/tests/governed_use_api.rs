use serde_json::json;
use tn_proto::prelude::{DatasetCatalog, PolicyDag, UseContext};
use tn_proto::{LineageVerifier, Objects};

const POLICY: &str = "## finance.account\n### instruction\nCalculate totals.\n### use_for\nPortfolio analysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

#[test]
fn application_uses_the_governed_workflow_through_the_public_sdk() {
    let session = Objects::ephemeral(POLICY, "agents.md", &["finance"]).unwrap();
    let policy = session
        .draft("finance.account")
        .unwrap()
        .governance()
        .clone();
    let source = session
        .create_obj("finance.account", policy, "finance", json!({"amount": 42}))
        .unwrap();
    let use_context = UseContext::new("analytics", "portfolio_analysis", "calculate").unwrap();
    let mut received = session
        .receive_for(
            source.snapshot().unwrap().wire(),
            &use_context,
            ["finance"],
            None,
            |ctx| Ok(ctx.use_context() == Some(&use_context)),
        )
        .unwrap();
    received.set_field("finance", "amount", json!(84)).unwrap();
    let output = session
        .release_for(
            &mut received,
            "finance.result",
            &use_context,
            "reporting",
            |_| Ok(true),
        )
        .unwrap();
    let reader = session.reader().unwrap();
    let view = reader.governance(&output).unwrap();
    let source_view = reader.governance(source.snapshot().unwrap()).unwrap();
    let lineage = LineageVerifier::default()
        .verify(&view, &DatasetCatalog::new(), &PolicyDag::new(), |_| {
            Ok(source_view.clone())
        })
        .unwrap();
    assert!(lineage
        .object_ids()
        .contains(&source.snapshot().unwrap().id().to_owned()));
}
