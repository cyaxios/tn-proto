use serde_json::json;
use std::sync::Arc;
use tn_core::governed::{Governance, UseContext};
use tn_core::providers::*;
const POLICY: &str = "## example.value\n### instruction\nRead the value.\n### use_for\nAnalysis.\n### do_not_use_for\nOther uses.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";
#[test]
fn provider_session_uses_assigned_keys_and_live_policy_decisions() {
    let identity = Arc::new(LocalIdentity::generate("analysis-service").unwrap());
    let actor = identity.resolve("analysis-service").unwrap();
    let keys = Arc::new(LocalKeys::generate(&["default"]).unwrap());
    assert!(keys.resolve(&actor).is_err());
    keys.assign(&actor, &["default"], &["default", "tn.agents"])
        .unwrap();
    let governance = Arc::new(PolicyDirectory::new());
    governance.trust(&actor).unwrap();
    let input = UseContext::new(actor.application(), "analysis", "calculate").unwrap();
    let output = UseContext::new(actor.application(), "report", "publish").unwrap();
    let contract =
        Governance::from_markdown(actor.did(), POLICY, "agents.md", "example.value").unwrap();
    let request = PolicyRequest {
        object_type: "example.value".into(),
        use_context: input.clone(),
    };
    governance.add_policy(&request, contract.clone()).unwrap();
    governance
        .add_policy(
            &PolicyRequest {
                object_type: "example.value".into(),
                use_context: output.clone(),
            },
            contract,
        )
        .unwrap();
    let workflow = WorkflowRequest { input, output };
    governance
        .add_workflow(
            &workflow,
            WorkflowPolicy {
                inputs: vec![InputRule {
                    object_type: None,
                    groups: vec!["default".into()],
                }],
                output_type: "example.report".into(),
                destination: "reporting".into(),
            },
        )
        .unwrap();
    let providers = Providers {
        identity,
        keys,
        governance: governance.clone(),
        catalog: None,
        registers: None,
    };
    let session = providers.session(actor.application(), &[workflow]).unwrap();
    let original = session
        .create(json!({"value":7}), providers.policy(&request).unwrap())
        .unwrap();
    let work = session.workflow("analysis", "report").unwrap();
    let mut data = work.receive(&original).unwrap();
    let other = session
        .create(json!({"value": 2}), providers.policy(&request).unwrap())
        .unwrap();
    data.include(&work.receive(&other).unwrap()).unwrap();
    data.set("default", Some("value"), json!(8)).unwrap();
    let additional = Governance::from_markdown(
        actor.did(),
        &POLICY.replace("Read the value.", "Retain the approved result."),
        "agents.md",
        "example.value",
    )
    .unwrap();
    assert!(work.attach(&mut data, additional.clone()).is_err());
    governance
        .approve_contract(&request, additional.clone())
        .unwrap();
    work.attach(&mut data, additional.clone()).unwrap();
    assert!(work.release(&mut data).is_err());
    governance
        .approve_contract(
            &PolicyRequest {
                object_type: "example.value".into(),
                use_context: UseContext::new(actor.application(), "report", "publish").unwrap(),
            },
            additional,
        )
        .unwrap();
    let publication = work.release(&mut data).unwrap();
    assert_eq!(data.policies().unwrap().len(), 2);
    assert_eq!(publication.writer(), actor.did());
    assert_eq!(
        work.receive(&publication)
            .unwrap()
            .get("default", Some("value"))
            .unwrap(),
        8
    );
}

#[test]
fn native_provider_constructors_reject_invalid_requests() {
    let use_context = UseContext::new("app", "analysis", "calculate").unwrap();
    assert!(PolicyRequest::new("", use_context.clone()).is_err());
    assert!(CatalogRequest::new("values", "", use_context.clone()).is_err());
    assert!(WorkflowRequest::new(
        use_context,
        UseContext::new("other", "report", "publish").unwrap()
    )
    .is_err());
    assert!(InputRule::new(vec![], None).is_err());
    assert!(InputRule::new(vec!["default".into(), "default".into()], None).is_err());
    assert!(InputRule::new(vec!["tn.agents".into()], None).is_err());
    assert!(WorkflowPolicy::new(vec![], "result", "reporting").is_err());
    let input = InputRule::new(vec!["default".into()], None).unwrap();
    assert!(WorkflowPolicy::new(vec![input.clone()], "result", "").is_err());
    assert!(WorkflowPolicy::new(vec![input.clone(), input], "result", "reporting").is_err());
}

#[test]
fn directory_validates_public_rust_structs_before_storage() {
    let directory = PolicyDirectory::new();
    let context = UseContext::new("app", "analysis", "calculate").unwrap();
    let request = WorkflowRequest {
        input: context.clone(),
        output: context,
    };
    let invalid = WorkflowPolicy {
        inputs: vec![],
        output_type: "result".into(),
        destination: "reporting".into(),
    };
    assert!(directory.add_workflow(&request, invalid).is_err());
    assert!(directory.workflow(&request).is_err());
    let valid = WorkflowPolicy::new(
        vec![InputRule::new(vec!["default".into()], None).unwrap()],
        "result",
        "reporting",
    )
    .unwrap();
    directory.add_workflow(&request, valid).unwrap();
    assert_eq!(directory.workflow(&request).unwrap().output_type, "result");
}
