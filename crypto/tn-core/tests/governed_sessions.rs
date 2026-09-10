#![cfg(feature = "fs")]

use serde_json::json;
use tn_core::runtime::Objects;

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate an aggregate report.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

#[test]
fn independent_contexts_seal_without_shared_identity_or_reader_material() {
    let alice = Objects::ephemeral(POLICY, "alice.md", &["observations", "identities"]).unwrap();
    let bob = Objects::ephemeral(POLICY, "bob.md", &["observations"]).unwrap();
    assert_ne!(alice.did(), bob.did());
    let source = alice
        .seal(
            alice
                .draft("research.sample")
                .unwrap()
                .group("observations", json!({"count": 42}))
                .unwrap()
                .group("identities", json!({"person": "Alice"}))
                .unwrap(),
        )
        .unwrap();
    assert!(bob.reader().unwrap().governance(&source).is_err());
    let reader = alice.reader_for(["tn.agents", "observations"]).unwrap();
    let admitted = reader
        .governance(&source)
        .unwrap()
        .authorize("aggregate", |_, _| Ok(true))
        .unwrap();
    assert!(reader.open(&admitted, ["identities"]).is_err());
    let opened = reader.open(&admitted, ["observations"]).unwrap();
    let result = bob
        .seal(
            opened
                .derive("report.generated")
                .unwrap()
                .group("observations", json!({"total": 42}))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(result.writer(), bob.did());
    assert_eq!(
        bob.reader()
            .unwrap()
            .governance(&result)
            .unwrap()
            .governance()
            .governed_by(),
        alice.did()
    );
    drop(alice);
    assert!(reader.governance(&source).is_ok());
    assert!(bob.seal(bob.draft("research.sample").unwrap()).is_ok());
}

#[test]
fn context_creation_and_reader_scoping_validate_group_assignments() {
    assert!(Objects::ephemeral(POLICY, "agents.md", &["tn.agents"]).is_err());
    assert!(Objects::ephemeral(POLICY, "agents.md", &["default", "default"]).is_err());
    let objects = Objects::ephemeral(POLICY, "agents.md", &["default"]).unwrap();
    assert!(objects.reader_for(["missing"]).is_err());
    assert!(objects.reader_for(["default", "default"]).is_err());
}
