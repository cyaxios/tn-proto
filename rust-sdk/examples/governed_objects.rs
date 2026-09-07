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

    let rules = example_group()?;
    let observations = example_group()?;
    let identities = example_group()?;
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])?
        .with_group("observations", observations.clone(), &[2; 32])?
        .with_group("identities", identities, &[3; 32])?;

    // Policy is an input to construction. The writer fills and encrypts
    // tn.agents, supplies matching AAD, hashes every group, and signs.
    writer.require_groups(["observations", "identities"])?;
    let source = writer.seal(
        GovernedDraft::new("research.sample", policy.clone())?
            .group("observations", json!({"counts": [12, 18]}))?
            .group("identities", json!({"participants": ["Alice", "Bob"]}))?,
    )?;

    // Send or retain these exact bytes. Parsing verifies the signature and
    // group binding before the receiving application opens the contract.
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)?
        .with_group("observations", observations)?;
    let mut data = reader.receive(source.wire(), "aggregate", ["observations"], |ctx| {
        Ok(ctx.object().writer() == device.did()
            && ctx.object().object_type() == "research.sample"
            && ctx.governance().matches_contract(&policy)
            && ctx.policies()?.len() == 1
            && ctx.operation() == "aggregate")
    })?;
    let counts = data.group("observations").ok_or("observations missing")?["counts"]
        .as_array()
        .ok_or("counts must be an array")?;
    let total = counts.iter().try_fold(0u64, |sum, count| {
        sum.checked_add(count.as_u64().ok_or("counts must be unsigned integers")?)
            .ok_or("aggregate overflow")
    })?;

    // Mutate the working data. The object keeps its contract, source, and
    // unopened groups; release asks the application to admit this output.
    data.set_group("observations", json!({"total": total}))?;
    let result = writer.release(
        &mut data,
        "research.aggregate",
        "aggregate",
        "reports",
        |ctx| {
            Ok(ctx.purpose() == "aggregate"
                && ctx.destination() == "reports"
                && ctx
                    .data()
                    .policies()?
                    .iter()
                    .all(|p| p.matches_contract(&policy)))
        },
    )?;
    assert_eq!(data.hidden_groups(), ["identities"]);
    assert_eq!(data.history()[0].wire(), source.wire());
    assert_ne!(source.id(), result.id());
    GovernedObject::parse(result.wire())?;
    println!("Verified source: {}", source.id());
    println!("Aggregate: {total}; identities retained as ciphertext");
    println!("Signed release: {}", result.id());
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
