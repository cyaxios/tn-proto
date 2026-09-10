#![cfg(feature = "fs")]

use serde_json::json;
use tn_core::governed::{DataObject, Governance};
use tn_core::runtime::Objects;

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## finance.rows\n### instruction\nProduce approved totals.\n### use_for\nFinancial analysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn context() -> Objects<'static> {
    Objects::ephemeral(POLICY, "unity/finance", &["data", "identities", "report"]).unwrap()
}

fn create(context: &Objects<'_>, n: i64) -> DataObject {
    let policy =
        Governance::from_markdown(context.did(), POLICY, "unity/finance", "finance.rows").unwrap();
    context
        .create_obj(
            "finance.rows",
            policy,
            "data",
            json!({"amount": n, "nested": {"values": [1, 2]}}),
        )
        .unwrap()
}

#[test]
fn mutable_object_keeps_its_contract_and_signed_versions() {
    let context = context();
    let mut data = create(&context, 7);
    let original = data.snapshot().unwrap().clone();
    let contract = data.governance().clone();
    data.set_path(
        &[json!("data"), json!("nested"), json!("values"), json!(1)],
        json!(8),
    )
    .unwrap();
    data.set_field("data", "amount", json!(42)).unwrap();
    let output = context
        .release(&mut data, "finance.total", "analysis", "internal", |ctx| {
            assert_eq!(ctx.writer(), context.did());
            assert_eq!(ctx.destination(), "internal");
            assert_eq!(ctx.data().group("data").unwrap()["amount"], 42);
            Ok(ctx.data().governance().matches_contract(&contract))
        })
        .unwrap();
    assert_ne!(original.id(), output.id());
    assert_eq!(data.history()[0].wire(), original.wire());
    let view = context.reader().unwrap().governance(&output).unwrap();
    assert_eq!(
        view.governance().source_references().unwrap()[0].object_id(),
        original.id()
    );
    let opened = context
        .receive(output.wire(), "analysis", ["data"], |ctx| {
            Ok(ctx.object().writer() == context.did()
                && ctx.operation() == "analysis"
                && ctx.governance().matches_contract(&contract))
        })
        .unwrap();
    assert_eq!(
        opened.group("data").unwrap()["nested"]["values"],
        json!([1, 8])
    );
}

#[test]
fn combining_inputs_carries_both_sources_and_policies() {
    let context = context();
    let first = create(&context, 10);
    let second = create(&context, 20);
    let first_wire = first.snapshot().unwrap();
    let second_wire = second.snapshot().unwrap();
    let mut total = context
        .receive(first_wire.wire(), "sum", ["data"], |_| Ok(true))
        .unwrap();
    let other = context
        .receive(second_wire.wire(), "sum", ["data"], |_| Ok(true))
        .unwrap();
    total.include(&other).unwrap();
    total.set_group("report", json!({"total": 30})).unwrap();
    let output = context
        .release(&mut total, "finance.total", "sum", "internal", |_| Ok(true))
        .unwrap();
    let view = context.reader().unwrap().governance(&output).unwrap();
    let sources = view.governance().source_references().unwrap();
    assert_eq!(sources.len(), 2);
    assert!(sources.iter().any(|source| source.references(first_wire)));
    assert!(sources.iter().any(|source| source.references(second_wire)));
}

#[test]
fn policy_attachment_requires_authority_decision_and_is_append_only() {
    let context = context();
    let mut data = create(&context, 10);
    let extra =
        Governance::from_markdown(context.did(), POLICY, "unity/internal", "finance.rows").unwrap();
    assert!(context
        .attach(&mut data, extra.clone(), |_| Ok(false))
        .is_err());
    assert_eq!(data.policies().unwrap().len(), 1);
    context
        .attach(&mut data, extra.clone(), |ctx| {
            Ok(ctx.authority() == context.did())
        })
        .unwrap();
    data.set_group("data", json!({"amount": 99})).unwrap();
    assert_eq!(data.policies().unwrap().len(), 2);
    assert!(data.set_group("tn.agents", json!({})).is_err());
    assert!(data.remove_group("tn.agents").is_err());
    let output = context
        .release(&mut data, "finance.total", "analysis", "internal", |_| {
            Ok(true)
        })
        .unwrap();
    let contracts = context
        .reader()
        .unwrap()
        .governance(&output)
        .unwrap()
        .governance()
        .policies()
        .unwrap();
    assert_eq!(contracts.len(), 2);
    assert!(contracts[1].matches_contract(&extra));
}

#[test]
#[cfg(feature = "fs-locking")]
fn optional_registers_record_only_successful_signed_versions() {
    use tn_core::runtime::ObjectRegisters;
    let directory = tempfile::tempdir().unwrap();
    let create_path = directory.path().join("created.jsonl");
    let release_path = directory.path().join("released.jsonl");
    let context = context().with_registers(ObjectRegisters::new(
        Some(create_path.clone()),
        Some(release_path.clone()),
    ));
    let mut data = create(&context, 9384221);
    assert!(data.register_error().is_none());
    let created = std::fs::read_to_string(&create_path).unwrap();
    assert!(created.contains(data.snapshot().unwrap().id()));
    assert!(!created.contains("9384221"));
    assert!(context
        .release(&mut data, "finance.total", "analysis", "llm", |_| Ok(false))
        .is_err());
    assert!(!release_path.exists());
    let result = context
        .release(&mut data, "finance.total", "analysis", "llm", |_| Ok(true))
        .unwrap();
    let released = std::fs::read_to_string(&release_path).unwrap();
    assert!(released.contains(result.id()));
    assert!(!released.contains("9384221"));
    assert!(data.register_error().is_none());
}

#[test]
fn optional_register_failure_preserves_the_successful_object() {
    use tn_core::runtime::ObjectRegisters;
    let directory = tempfile::tempdir().unwrap();
    let context = context().with_registers(ObjectRegisters::new(
        Some(directory.path().to_owned()),
        Some(directory.path().to_owned()),
    ));
    let mut data = create(&context, 7);
    assert!(data.register_error().is_some());
    let source = data.snapshot().unwrap().clone();
    let result = context
        .release(&mut data, "finance.total", "analysis", "llm", |_| Ok(true))
        .unwrap();
    assert!(data.register_error().is_some());
    assert_eq!(data.snapshot().unwrap().wire(), result.wire());
    assert_eq!(data.history()[0].wire(), source.wire());
}
