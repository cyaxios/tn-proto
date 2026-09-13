use serde_json::json;
use std::sync::Arc;
use tn_core::governed::{Governance, UseContext};
use tn_core::providers::*;
const POLICY: &str = "## example.value\n### instruction\nRead the value.\n### use_for\nAnalysis.\n### do_not_use_for\nOther uses.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";
fn main() {
    let identity = Arc::new(LocalIdentity::generate("analysis-service").unwrap());
    let actor = identity.resolve("analysis-service").unwrap();
    let keys = Arc::new(LocalKeys::generate(&["default"]).unwrap());
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
        governance,
        catalog: None,
        registers: None,
    };
    let session = providers.session(actor.application(), &[workflow]).unwrap();
    let original = session
        .create(json!({"value":7}), providers.policy(&request).unwrap())
        .unwrap();
    let work = session.workflow("analysis", "report").unwrap();
    let mut data = work.receive(&original).unwrap();
    data.set("default", Some("value"), json!(8)).unwrap();
    let publication = work.release(&mut data).unwrap();
    println!("Released {}", publication.id());
    assert_eq!(
        work.receive(&publication)
            .unwrap()
            .get("default", Some("value"))
            .unwrap(),
        8
    );
}
