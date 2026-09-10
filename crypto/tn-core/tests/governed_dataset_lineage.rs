#![cfg(feature = "fs")]

use serde_json::json;
use tn_core::governed::{DatasetCatalog, Governance, LineageVerifier, PolicyDag, UseContext};
use tn_core::runtime::Objects;

const POLICY: &str = "## finance.input\n### instruction\nCalculate the aggregate.\n### use_for\nPortfolio analysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

#[test]
fn shared_ancestor_reuse_still_checks_the_full_path_depth() {
    let session = Objects::ephemeral(POLICY, "portfolio.md", &["finance"]).unwrap();
    let policy = session.draft("finance.input").unwrap().governance().clone();
    let mut data = session
        .create_obj("finance.input", policy, "finance", json!({"total": 12}))
        .unwrap();
    let leaf = data.snapshot().unwrap().clone();
    let shared = session
        .release(&mut data, "finance.result", "analysis", "next", |_| {
            Ok(true)
        })
        .unwrap();
    let mut first = session
        .receive(shared.wire(), "analysis", ["finance"], |_| Ok(true))
        .unwrap();
    let deep = session
        .release(&mut data, "finance.result", "analysis", "next", |_| {
            Ok(true)
        })
        .unwrap();
    let second = session
        .receive(deep.wire(), "analysis", ["finance"], |_| Ok(true))
        .unwrap();
    first.include(&second).unwrap();
    let output = session
        .release(&mut first, "finance.result", "analysis", "next", |_| {
            Ok(true)
        })
        .unwrap();
    let objects = [leaf, shared, deep]
        .into_iter()
        .map(|object| (object.id().to_owned(), object))
        .collect::<std::collections::BTreeMap<_, _>>();
    let reader = session.reader().unwrap();
    let view = reader.governance(&output).unwrap();
    let catalog = DatasetCatalog::new();
    let dag = PolicyDag::new();
    let resolve = |id: &str| reader.governance(&objects[id]);
    assert!(LineageVerifier::new(1024, 2)
        .unwrap()
        .verify(&view, &catalog, &dag, resolve)
        .is_err());
    assert_eq!(
        LineageVerifier::new(1024, 3)
            .unwrap()
            .verify(&view, &catalog, &dag, resolve)
            .unwrap()
            .object_ids()
            .len(),
        4
    );
}

#[test]
fn release_carries_explicit_use_without_changing_parent_identity() {
    let session = Objects::ephemeral(POLICY, "portfolio.md", &["finance"]).unwrap();
    let policy = session.draft("finance.input").unwrap().governance().clone();
    let mut data = session
        .create_obj("finance.input", policy, "finance", json!({"total": 12}))
        .unwrap();
    let parent = data.snapshot().unwrap().clone();
    let use_context =
        UseContext::new("analytics", "portfolio_analysis", "release_calculation").unwrap();
    let released = session
        .release_for(
            &mut data,
            "finance.result",
            &use_context,
            "deepvest",
            |ctx| {
                assert_eq!(ctx.use_context(), Some(&use_context));
                assert_eq!(ctx.purpose(), "portfolio_analysis");
                Ok(true)
            },
        )
        .unwrap();
    let view = session.reader().unwrap().governance(&released).unwrap();
    assert_eq!(
        view.governance().get("release_context"),
        Some(&json!({
            "application": "analytics", "purpose": "portfolio_analysis",
            "operation": "release_calculation", "destination": "deepvest"
        }))
    );
    assert!(view.governance().source_references().unwrap()[0].references(&parent));
    assert!(view.governance().dataset_bindings().unwrap().is_empty());
    assert_eq!(data.history().len(), 2);
}

#[test]
fn refused_release_and_independent_copy_preserve_original_state() {
    let session = Objects::ephemeral(POLICY, "portfolio.md", &["finance"]).unwrap();
    let policy = session.draft("finance.input").unwrap().governance().clone();
    let mut original = session
        .create_obj("finance.input", policy, "finance", json!({"total": 12}))
        .unwrap();
    let snapshot = original.snapshot().unwrap().clone();
    let mut sibling = original.clone();
    sibling.set_field("finance", "total", json!(99)).unwrap();
    assert_eq!(
        original
            .get_path(&[json!("finance"), json!("total")])
            .unwrap(),
        json!(12)
    );
    let use_context = UseContext::new("analytics", "analysis", "release").unwrap();
    assert!(session
        .release_for(
            &mut original,
            "finance.result",
            &use_context,
            "deepvest",
            |_| Ok(false)
        )
        .is_err());
    assert_eq!(original.snapshot().unwrap().wire(), snapshot.wire());
    assert_eq!(original.history().len(), 1);
}

#[test]
fn lineage_follows_exact_parents_and_rejects_contract_loss_and_wrong_resolution() {
    let session = Objects::ephemeral(POLICY, "portfolio.md", &["finance"]).unwrap();
    let policy = session.draft("finance.input").unwrap().governance().clone();
    let mut data = session
        .create_obj("finance.input", policy, "finance", json!({"total": 12}))
        .unwrap();
    let parent = data.snapshot().unwrap().clone();
    let output = session
        .release(&mut data, "finance.result", "analysis", "deepvest", |_| {
            Ok(true)
        })
        .unwrap();
    let reader = session.reader().unwrap();
    let view = reader.governance(&output).unwrap();
    let catalog = DatasetCatalog::new();
    let dag = PolicyDag::new();
    let proof = LineageVerifier::default()
        .verify(&view, &catalog, &dag, |id| {
            assert_eq!(id, parent.id());
            reader.governance(&parent)
        })
        .unwrap();
    assert_eq!(proof.object_ids().len(), 2);
    assert!(LineageVerifier::default()
        .verify(&view, &catalog, &dag, |_| reader.governance(&output))
        .is_err());
    assert!(LineageVerifier::new(1, 64)
        .unwrap()
        .verify(&view, &catalog, &dag, |_| reader.governance(&parent))
        .is_err());

    let opened = reader
        .open(
            &reader
                .governance(&parent)
                .unwrap()
                .authorize("analysis", |_, _| Ok(true))
                .unwrap(),
            ["finance"],
        )
        .unwrap();
    let changed = Governance::from_markdown(
        session.did(),
        &POLICY.replace("Calculate the aggregate.", "Different rules."),
        "other.md",
        "finance.input",
    )
    .unwrap();
    let lost_contract = session
        .seal(
            opened
                .derive_under("finance.result", changed)
                .unwrap()
                .group("finance", json!({"total":12}))
                .unwrap(),
        )
        .unwrap();
    assert!(LineageVerifier::default()
        .verify(
            &reader.governance(&lost_contract).unwrap(),
            &catalog,
            &dag,
            |_| reader.governance(&parent)
        )
        .is_err());
}
