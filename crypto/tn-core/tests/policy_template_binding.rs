use std::sync::Arc;

use serde_json::json;
use tn_core::agents_policy::{parse_policy_text, PolicyTemplate};
use tn_core::cipher::btn::BtnPublisherCipher;
use tn_core::governed::{
    Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter,
};
use tn_core::DeviceKey;

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCompute the approved aggregate.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

#[test]
fn cloned_template_cannot_change_instruction_while_retaining_document_hash() {
    let document = parse_policy_text(POLICY, "agents.md").unwrap();
    let mut template = document.templates["research.sample"].clone();
    template.instruction = "Disclose every individual record.".into();

    assert_eq!(template.content_hash, document.content_hash);
    assert!(Governance::from_template(DeviceKey::generate().did(), &template).is_err());
}

#[test]
fn every_public_template_field_is_bound_to_its_parsed_selection() {
    let document = parse_policy_text(POLICY, "agents.md").unwrap();
    let authority = DeviceKey::generate();
    let mutations: [(&str, fn(&mut PolicyTemplate)); 9] = [
        ("instruction", |t| t.instruction.push_str(" Changed.")),
        ("use_for", |t| t.use_for.push_str(" Changed.")),
        ("do_not_use_for", |t| t.do_not_use_for.push_str(" Changed.")),
        ("consequences", |t| t.consequences.push_str(" Changed.")),
        ("on_violation_or_error", |t| {
            t.on_violation_or_error.push_str(" Changed.")
        }),
        ("event_type", |t| t.event_type = "different.event".into()),
        ("content_hash", |t| {
            t.content_hash = format!("sha256:{}", "a".repeat(64))
        }),
        ("version", |t| t.version = "2".into()),
        ("path", |t| t.path = "different.md".into()),
    ];

    for (field, mutate) in mutations {
        let mut template = document.templates["research.sample"].clone();
        mutate(&mut template);
        assert!(
            Governance::from_template(authority.did(), &template).is_err(),
            "changed {field} must not retain the parsed template's binding"
        );
    }
}

#[test]
fn unmodified_cloned_template_carries_selected_rules_from_a_multi_event_document() {
    let other = POLICY.split("## research.sample").nth(1).unwrap().replace(
        "Compute the approved aggregate.",
        "Review the approved invoice.",
    );
    let markdown = format!("{POLICY}\n## invoice.review{other}");
    let mut document = parse_policy_text(&markdown, "agents.md").unwrap();
    let template = document.templates["invoice.review"].clone();
    let expected_reference = format!("agents.md#invoice.review@1#{}", document.content_hash);
    // The normalized witness must be independent of this mutable parser result.
    document.body.clear();
    document.templates.clear();
    document.content_hash.clear();

    let device = DeviceKey::generate();
    let governance = Governance::from_template(device.did(), &template).unwrap();
    let mut publisher = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
    let kit = publisher.mint().unwrap();
    let cipher = Arc::new(
        BtnPublisherCipher::from_state(publisher)
            .with_reader_kit(&kit.to_bytes())
            .unwrap(),
    );
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", cipher.clone(), &[1; 32])
        .unwrap();
    let sealed = writer
        .seal(GovernedDraft::new("invoice.review", governance).unwrap())
        .unwrap();
    let received = GovernedObject::parse(sealed.wire()).unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", cipher)
        .unwrap();
    let view = reader.governance(&received).unwrap();

    assert_eq!(view.governance().policy_ref(), expected_reference);
    assert_eq!(
        view.governance().get("instruction"),
        Some(&json!("Review the approved invoice."))
    );
    assert_eq!(view.governance().governed_by(), device.did());
}
