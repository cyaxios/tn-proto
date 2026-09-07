//! The complete governed lifecycle also compiles without the SDK filesystem feature.
use std::sync::Arc;

use serde_json::json;
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::DeviceKey;
use tn_proto::{Governance, GovernedDraft, GovernedReader, GovernedWriter};

const POLICY: &str = "## finance.rows\n### instruction\nCompute totals.\n### use_for\nAnalysis.\n### do_not_use_for\nPersonal disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

fn cipher() -> Arc<dyn GroupCipher> {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
    let kit = state.mint().unwrap();
    Arc::new(
        BtnPublisherCipher::from_state(state)
            .with_reader_kit(&kit.to_bytes())
            .unwrap(),
    )
}

#[test]
fn a_service_releases_mutated_data_and_retains_unopened_ciphertext() {
    let origin = DeviceKey::generate();
    let worker = DeviceKey::generate();
    let policy =
        Governance::from_markdown(origin.did(), POLICY, "unity/finance", "finance.rows").unwrap();
    let rules = cipher();
    let data = cipher();
    let private = cipher();
    let origin_writer = GovernedWriter::new(&origin)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("data", data.clone(), &[2; 32])
        .unwrap()
        .with_group("private", private.clone(), &[3; 32])
        .unwrap();
    let source = origin_writer
        .seal(
            GovernedDraft::new("finance.rows", policy.clone())
                .unwrap()
                .group("data", json!({"amount": 10}))
                .unwrap()
                .group("private", json!({"account": "held at origin"}))
                .unwrap(),
        )
        .unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules.clone())
        .unwrap()
        .with_group("data", data.clone())
        .unwrap();
    let writer = GovernedWriter::new(&worker)
        .with_group("tn.agents", rules, &[1; 32])
        .unwrap()
        .with_group("data", data, &[2; 32])
        .unwrap();
    writer.require_groups(["data"]).unwrap();
    let mut working = reader
        .receive(source.wire(), "analysis", ["data"], |ctx| {
            Ok(ctx.object().writer() == origin.did()
                && ctx.object().object_type() == "finance.rows"
                && ctx.governance().matches_contract(&policy)
                && ctx.policies()?.len() == 1)
        })
        .unwrap();
    assert_eq!(working.hidden_groups(), vec!["private"]);
    working.set_field("data", "amount", json!(30)).unwrap();
    let released = writer
        .release(&mut working, "finance.total", "analysis", "llm", |ctx| {
            Ok(ctx.destination() == "llm" && ctx.data().sources()[0].references(&source))
        })
        .unwrap();
    assert_eq!(released.writer(), worker.did());
    let before = tn_core::sealed_object::extract_group_blocks(source.envelope()).unwrap();
    let after = tn_core::sealed_object::extract_group_blocks(released.envelope()).unwrap();
    assert_eq!(before["private"].ciphertext, after["private"].ciphertext);
    assert_eq!(
        before["private"].field_hashes,
        after["private"].field_hashes
    );
    let complete_reader = reader.with_group("private", private).unwrap();
    let received = complete_reader
        .receive(released.wire(), "analysis", ["data", "private"], |_| {
            Ok(true)
        })
        .unwrap();
    assert_eq!(received.group("data").unwrap()["amount"], 30);
    assert_eq!(
        received.group("private").unwrap()["account"],
        "held at origin"
    );
    assert_eq!(working.history()[0].wire(), source.wire());
    assert_eq!(working.snapshot().unwrap().wire(), released.wire());
}

#[test]
fn denied_use_or_failed_sealing_keeps_the_current_snapshot() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "unity/finance", "finance.rows").unwrap();
    let rules = cipher();
    let data = cipher();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("data", data.clone(), &[2; 32])
        .unwrap();
    let mut object = writer
        .create_obj("finance.rows", policy, "data", json!({"amount": 7}))
        .unwrap();
    let original = object.snapshot().unwrap().clone();
    let revision = object.revision();
    assert!(writer
        .release(&mut object, "finance.total", "analysis", "llm", |_| Ok(
            false
        ))
        .is_err());
    assert_eq!(object.revision(), revision);
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap()
        .with_group("data", data)
        .unwrap();
    assert!(reader
        .receive(original.wire(), "analysis", ["data"], |ctx| Ok(ctx
            .object()
            .writer()
            == "unaccepted"))
        .is_err());
    object.set_group("missing", json!({"amount": 9})).unwrap();
    let revised = object.revision();
    assert!(writer
        .release(&mut object, "finance.total", "analysis", "llm", |_| Ok(
            true
        ))
        .is_err());
    assert_eq!(object.revision(), revised);
    assert_eq!(object.history().len(), 1);
    assert_eq!(object.snapshot().unwrap().wire(), original.wire());
    assert_eq!(object.group("missing").unwrap()["amount"], 9);
}

#[test]
fn aggregation_retains_distinct_authorities_and_all_causal_inputs() {
    let device = DeviceKey::generate();
    let authority = DeviceKey::generate();
    let first =
        Governance::from_markdown(device.did(), POLICY, "unity/first", "finance.rows").unwrap();
    let second =
        Governance::from_markdown(authority.did(), POLICY, "unity/second", "finance.rows").unwrap();
    let rules = cipher();
    let data = cipher();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("data", data.clone(), &[2; 32])
        .unwrap();
    let mut total = writer
        .create_obj("finance.rows", first.clone(), "data", json!({"total": 1}))
        .unwrap();
    let other = writer
        .create_obj("finance.rows", second.clone(), "data", json!({"total": 2}))
        .unwrap();
    let a = total.snapshot().unwrap().clone();
    let b = other.snapshot().unwrap().clone();
    total.include(&other).unwrap();
    total.include(&other).unwrap();
    total.set_field("data", "total", json!(3)).unwrap();
    assert_eq!(total.policies().unwrap().len(), 2);
    assert_eq!(total.sources().len(), 2);
    let result = writer
        .release(&mut total, "finance.total", "analysis", "reports", |ctx| {
            Ok(ctx
                .data()
                .policies()?
                .iter()
                .all(|p| p.matches_contract(&first) || p.matches_contract(&second)))
        })
        .unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap()
        .with_group("data", data)
        .unwrap();
    let view = reader.governance(&result).unwrap();
    assert_eq!(view.governance().policies().unwrap().len(), 2);
    let refs = view.governance().source_references().unwrap();
    assert_eq!(refs.len(), 2);
    assert!(refs.iter().any(|r| r.references(&a)));
    assert!(refs.iter().any(|r| r.references(&b)));
    assert_eq!(
        view.governance().get("release_context").unwrap(),
        &json!({"purpose":"analysis","destination":"reports"})
    );
}
