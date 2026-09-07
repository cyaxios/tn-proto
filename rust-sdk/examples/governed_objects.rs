//! Run with: cargo run -p tn-proto --example governed_objects
use std::sync::Arc;

use serde_json::json;
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::DeviceKey;
use tn_proto::{Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter};

const POLICY: &str = r"---
version: 1
schema: tn-agents-policy@v1
---
## research.sample
### instruction
Create an aggregate report from the supplied observations.
### use_for
Aggregate research.
### do_not_use_for
Individual disclosure.
### consequences
Contract review.
### on_violation_or_error
Refuse release.
";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = DeviceKey::generate();
    let policy = Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample")?;
    let expected_policy = policy.policy_ref().to_owned();
    let rules = example_group()?;
    let observations = example_group()?;
    let identities = example_group()?;
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])?
        .with_group("observations", observations.clone(), &[2; 32])?
        .with_group("identities", identities, &[3; 32])?;

    // Policy is an input to construction. The writer fills and encrypts
    // tn.agents, supplies matching AAD, hashes every group, and signs.
    let source = writer.seal(
        GovernedDraft::new("research.sample", policy)?
            .group("observations", json!({"counts": [12, 18]}))?
            .group("identities", json!({"participants": ["Alice", "Bob"]}))?,
    )?;

    // Send or retain these exact bytes. Parsing verifies the signature and
    // group binding before the receiving application opens the contract.
    let received = GovernedObject::parse(source.wire())?;
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)?
        .with_group("observations", observations)?;
    let view = reader.governance(&received)?;
    let accepted_writer = view.object().writer() == device.did();
    let admitted = view.authorize("aggregate", |contract, operation| {
        Ok(accepted_writer
            && contract.governed_by() == device.did()
            && contract.policy_ref() == expected_policy
            && contract.get("use_for") == Some(&json!("Aggregate research."))
            && operation == "aggregate")
    })?;
    let opened = reader.open(&admitted, ["observations"])?;
    let counts = opened.groups()["observations"]["counts"]
        .as_array()
        .ok_or("counts must be an array")?;
    let total = counts.iter().try_fold(0u64, |sum, count| {
        sum.checked_add(count.as_u64().ok_or("counts must be unsigned integers")?)
            .ok_or("aggregate overflow")
    })?;

    // The application computes a permitted result. Sealing a derivative
    // carries the contract and signs the source reference with the output.
    let result = writer.seal(
        opened
            .derive("research.aggregate")?
            .group("observations", json!({"total": total}))?,
    )?;
    assert_eq!(opened.hidden_groups(), ["identities"]);
    assert_eq!(opened.object().wire(), source.wire());
    assert_ne!(source.id(), result.id());
    GovernedObject::parse(result.wire())?;
    println!("Verified source: {}", source.id());
    println!("Aggregate: {total}; identities retained as ciphertext");
    println!("Signed derivative: {}", result.id());
    Ok(())
}

// Local material makes this example self-contained. Applications can use
// Tn::open_objects("tn.yaml") to load their existing identity and group keys.
fn example_group() -> tn_core::Result<Arc<dyn GroupCipher>> {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config::default())?;
    let kit = state.mint()?;
    Ok(Arc::new(
        BtnPublisherCipher::from_state(state).with_reader_kit(&kit.to_bytes())?,
    ))
}
