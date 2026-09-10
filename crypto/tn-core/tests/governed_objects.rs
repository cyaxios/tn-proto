use std::sync::Arc;

use serde_json::{json, Value};
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter,
};
use tn_core::sealed_object::{extract_group_blocks, verify_sealed};
use tn_core::DeviceKey;

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate the approved aggregate report.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn cipher() -> Arc<dyn GroupCipher> {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config::default()).unwrap();
    let kit = state.mint().unwrap();
    Arc::new(
        BtnPublisherCipher::from_state(state)
            .with_reader_kit(&kit.to_bytes())
            .unwrap(),
    )
}

#[test]
fn sealing_constructs_the_governance_group_and_binds_every_group() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    let rules = cipher();
    let data = cipher();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules, &[1; 32])
        .unwrap()
        .with_group("default", data, &[2; 32])
        .unwrap();
    let draft = GovernedDraft::new("research.sample", policy.clone())
        .unwrap()
        .group("default", json!({"amount": 42, "note": "private"}))
        .unwrap();
    let object = writer.seal(draft).unwrap();
    let env = object.envelope();
    assert_eq!(env["sequence"], 0);
    assert_eq!(env["prev_hash"], "");
    assert_eq!(env["level"], "");
    assert_eq!(env["tn_sealed"], 1);
    assert!(!env.contains_key("run_id"));
    assert_eq!(object.group_names(), vec!["default", "tn.agents"]);
    let aad: Value = serde_json::from_str(env["tn_aad"].as_str().unwrap()).unwrap();
    assert_eq!(aad["default"], aad["tn.agents"]);
    assert_eq!(aad["default"]["governed_by"], device.did());
    assert_eq!(aad["default"]["policy"], policy.policy_ref());
    let valid = verify_sealed(env, &extract_group_blocks(env).unwrap());
    assert!(valid.signature && valid.row_hash);
    assert_eq!(
        GovernedObject::parse(object.wire()).unwrap().wire(),
        object.wire()
    );
}

#[test]
fn governance_is_reserved_and_business_fields_cannot_replace_it() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    assert!(GovernedDraft::new("research.sample", policy.clone())
        .unwrap()
        .group("tn.agents", json!({"instruction": "replace rules"}))
        .is_err());
    assert!(GovernedDraft::new("bad\"type", policy).is_err());
}

#[test]
fn an_application_opens_governance_then_approves_selected_data_use() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    let rules = cipher();
    let data = cipher();
    let pii = cipher();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("default", data.clone(), &[2; 32])
        .unwrap()
        .with_group("pii", pii, &[3; 32])
        .unwrap();
    let object = writer
        .seal(
            GovernedDraft::new("research.sample", policy.clone())
                .unwrap()
                .group("default", json!({"amount": 42}))
                .unwrap()
                .group("pii", json!({"ssn": "private"}))
                .unwrap(),
        )
        .unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap();
    let view = reader.governance(&object).unwrap();
    assert_eq!(
        view.governance().get("instruction"),
        Some(&json!("Create the approved aggregate report."))
    );
    assert_eq!(view.object().wire(), object.wire());
    assert!(view
        .clone()
        .authorize("publish individuals", |_, _| Ok(false))
        .is_err());
    let admitted = view
        .authorize("aggregate", |contract, operation| {
            Ok(contract.policy_ref() == policy.policy_ref() && operation == "aggregate")
        })
        .unwrap();
    assert!(reader.open(&admitted, ["default"]).is_err());
    let reader = reader.with_group("default", data).unwrap();
    let opened = reader.open(&admitted, ["default"]).unwrap();
    assert_eq!(opened.groups().len(), 1);
    assert_eq!(opened.groups()["default"], json!({"amount": 42}));
    assert_eq!(opened.hidden_groups(), vec!["pii"]);
    assert_eq!(opened.object().wire(), object.wire());
    assert!(reader.open(&admitted, ["missing"]).is_err());
    assert!(reader.open(&admitted, ["default", "default"]).is_err());
}

#[test]
fn deriving_carries_the_contract_and_references_the_signed_source() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    let rules = cipher();
    let data = cipher();
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("default", data.clone(), &[2; 32])
        .unwrap();
    let source = writer
        .seal(
            GovernedDraft::new("research.sample", policy.clone())
                .unwrap()
                .group("default", json!({"amount": 42}))
                .unwrap(),
        )
        .unwrap();
    let original_wire = source.wire().to_owned();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap()
        .with_group("default", data)
        .unwrap();
    let admitted = reader
        .governance(&source)
        .unwrap()
        .authorize("aggregate", |_, _| Ok(true))
        .unwrap();
    let opened = reader.open(&admitted, ["default"]).unwrap();
    let result = writer
        .seal(
            opened
                .derive("report.generated")
                .unwrap()
                .group("default", json!({"total": 42}))
                .unwrap(),
        )
        .unwrap();
    assert_ne!(source.id(), result.id());
    assert_ne!(source.envelope()["event_id"], result.envelope()["event_id"]);
    let result_policy = reader.governance(&result).unwrap();
    assert_eq!(result_policy.governance().policy_ref(), policy.policy_ref());
    assert_eq!(
        result_policy.governance().get("source_lineage").unwrap()[0],
        json!({
            "object_id": source.id(), "object_type": "research.sample", "writer": device.did(),
            "governed_by": device.did(), "policy": policy.policy_ref(), "groups": ["default"],
            "operation": "aggregate"
        })
    );
    assert_eq!(source.wire(), original_wire);
    let output_policy = Governance::from_markdown(
        device.did(),
        &POLICY.replace("version: 1", "version: 2"),
        "release.md",
        "research.sample",
    )
    .unwrap();
    let reissued = writer
        .seal(
            opened
                .derive_under("report.released", output_policy.clone())
                .unwrap()
                .group("default", json!({"total": 42}))
                .unwrap(),
        )
        .unwrap();
    let view = reader.governance(&reissued).unwrap();
    assert_eq!(view.governance().policy_ref(), output_policy.policy_ref());
    assert_eq!(
        view.governance().get("source_lineage").unwrap()[0]["policy"],
        policy.policy_ref()
    );
}

fn resign(env: &mut serde_json::Map<String, Value>, device: &DeviceKey) -> String {
    use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
    use tn_core::sealed_object::ENVELOPE_RESERVED;
    let blocks = extract_group_blocks(env).unwrap();
    let public = env
        .iter()
        .filter(|(key, _)| !ENVELOPE_RESERVED.contains(&key.as_str()) && !blocks.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let groups = blocks
        .into_iter()
        .map(|(name, b)| {
            (
                name,
                GroupInput {
                    ciphertext: b.ciphertext,
                    field_hashes: b.field_hashes,
                },
            )
        })
        .collect();
    let row_hash = compute_row_hash(&RowHashInput {
        device_identity: env["device_identity"].as_str().unwrap(),
        timestamp: env["timestamp"].as_str().unwrap(),
        event_id: env["event_id"].as_str().unwrap(),
        event_type: env["event_type"].as_str().unwrap(),
        level: env["level"].as_str().unwrap(),
        prev_hash: env["prev_hash"].as_str().unwrap(),
        public_fields: &public,
        groups: &groups,
    });
    env.insert(
        "signature".into(),
        json!(tn_core::signing::signature_b64(
            &device.sign(row_hash.as_bytes())
        )),
    );
    env.insert("row_hash".into(), json!(row_hash));
    serde_json::to_string(env).unwrap()
}

fn sample(device: &DeviceKey, rules: Arc<dyn GroupCipher>) -> GovernedObject {
    GovernedWriter::new(device)
        .with_group("tn.agents", rules, &[1; 32])
        .unwrap()
        .with_group("default", cipher(), &[2; 32])
        .unwrap()
        .seal(
            GovernedDraft::new(
                "research.sample",
                Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample")
                    .unwrap(),
            )
            .unwrap()
            .group("default", json!({"amount": 42}))
            .unwrap(),
        )
        .unwrap()
}

#[test]
fn admission_checks_the_signature_group_binding_and_unique_json() {
    let device = DeviceKey::generate();
    let rules = cipher();
    let object = sample(&device, rules.clone());
    let mut changed = object.envelope().clone();
    changed.insert("event_type".into(), json!("different.type"));
    assert!(GovernedObject::parse(&serde_json::to_string(&changed).unwrap()).is_err());
    let duplicate = object.wire().replacen('{', "{\"sequence\":0,", 1);
    assert!(GovernedObject::parse(&duplicate).is_err());
    let duplicate_nested = object.wire().replacen(
        "\"field_hashes\":{",
        "\"field_hashes\":{\"amount\":\"duplicate\",",
        1,
    );
    assert!(GovernedObject::parse(&duplicate_nested).is_err());

    for field in ["tn.agents", "tn_aad", "signature"] {
        let mut changed = object.envelope().clone();
        changed.remove(field);
        let wire = if field == "signature" {
            serde_json::to_string(&changed).unwrap()
        } else {
            resign(&mut changed, &device)
        };
        assert!(GovernedObject::parse(&wire).is_err(), "required {field}");
    }
    let mut changed = object.envelope().clone();
    let mut aad: Value = serde_json::from_str(changed["tn_aad"].as_str().unwrap()).unwrap();
    aad["default"]["governed_by"] = json!(DeviceKey::generate().did());
    changed.insert("tn_aad".into(), json!(serde_json::to_string(&aad).unwrap()));
    assert!(GovernedObject::parse(&resign(&mut changed, &device)).is_err());

    // Even a valid outer signature cannot rebind existing ciphertext to new AAD.
    aad["tn.agents"] = aad["default"].clone();
    changed.insert("tn_aad".into(), json!(serde_json::to_string(&aad).unwrap()));
    let rebound = GovernedObject::parse(&resign(&mut changed, &device)).unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap();
    assert!(reader.governance(&rebound).is_err());
}

#[test]
fn a_reencrypted_policy_must_match_its_authenticated_reference() {
    use base64::Engine as _;
    let device = DeviceKey::generate();
    let rules = cipher();
    let object = sample(&device, rules.clone());
    let mut env = object.envelope().clone();
    let aad: Value = serde_json::from_str(env["tn_aad"].as_str().unwrap()).unwrap();
    let aad_bytes = tn_core::canonical::canonical_bytes(&aad["tn.agents"]).unwrap();
    let mut policy =
        Governance::from_markdown(device.did(), POLICY, "different.md", "research.sample")
            .unwrap()
            .fields()
            .clone();
    policy.insert("instruction".into(), json!("A different assertion."));
    let ct = rules
        .encrypt_with_aad(
            &tn_core::canonical::canonical_bytes(&json!(policy)).unwrap(),
            &aad_bytes,
        )
        .unwrap();
    env["tn.agents"]["ciphertext"] = json!(base64::engine::general_purpose::STANDARD.encode(ct));
    let changed = GovernedObject::parse(&resign(&mut env, &device)).unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap();
    assert!(reader.governance(&changed).is_err());
}

#[test]
fn generations_preserve_historical_exhaust_and_assign_new_access() {
    let device = DeviceKey::generate();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config::default()).unwrap();
    let old_kit = state.mint().unwrap();
    let old_cipher: Arc<dyn GroupCipher> = Arc::new(
        BtnPublisherCipher::from_state(
            tn_btn::PublisherState::from_bytes(&state.to_bytes()).unwrap(),
        )
        .with_reader_kit(&old_kit.to_bytes())
        .unwrap(),
    );
    let historical = sample(&device, old_cipher.clone());
    let saved_wire = historical.wire().to_owned();
    let mut active = state.rotate().unwrap().active;
    let new_kit = active.mint().unwrap();
    let new_cipher: Arc<dyn GroupCipher> = Arc::new(
        BtnPublisherCipher::from_state(active)
            .with_reader_kit(&new_kit.to_bytes())
            .unwrap(),
    );
    let current = sample(&device, new_cipher.clone());
    let old_reader = GovernedReader::new()
        .with_group("tn.agents", old_cipher.clone())
        .unwrap();
    assert_eq!(
        old_reader.governance(&historical).unwrap().governance(),
        &policy
    );
    assert!(old_reader.governance(&current).is_err());
    let archive_reader = old_reader.with_group("tn.agents", new_cipher).unwrap();
    assert_eq!(
        archive_reader.governance(&historical).unwrap().governance(),
        &policy
    );
    assert_eq!(
        archive_reader.governance(&current).unwrap().governance(),
        &policy
    );
    assert_eq!(historical.wire(), saved_wire);
}

#[test]
fn public_shape_keeps_the_signed_object_interpretation_unambiguous() {
    let device = DeviceKey::generate();
    let object = sample(&device, cipher());
    // The legacy preimage renders integer 1 and string "1" alike. Governed
    // admission requires the protocol marker's integer type.
    let mut env = object.envelope().clone();
    env.insert("tn_sealed".into(), json!("1"));
    assert!(GovernedObject::parse(&serde_json::to_string(&env).unwrap()).is_err());
    let mut env = object.envelope().clone();
    env.insert("extra".into(), json!(true));
    assert!(GovernedObject::parse(&resign(&mut env, &device)).is_err());
    let mut env = object.envelope().clone();
    env.insert("event_id".into(), json!("id\u{0000}injected"));
    assert!(GovernedObject::parse(&resign(&mut env, &device)).is_err());
}

#[test]
fn reader_preserves_cipher_failures_and_can_try_another_candidate() {
    use base64::Engine as _;
    let device = DeviceKey::generate();
    let rules = cipher();
    let object = sample(&device, rules.clone());
    let mut env = object.envelope().clone();
    env["tn.agents"]["ciphertext"] =
        json!(base64::engine::general_purpose::STANDARD.encode(b"invalid BTN frame"));
    let malformed = GovernedObject::parse(&resign(&mut env, &device)).unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", cipher())
        .unwrap()
        .with_group("tn.agents", rules)
        .unwrap();
    assert!(reader.governance(&object).is_ok());
    let Err(error) = reader.governance(&malformed) else {
        panic!("malformed frame must fail")
    };
    assert!(
        !matches!(error, tn_core::Error::NotEntitled { .. }),
        "cipher failure must preserve its meaning: {error}"
    );
    let reader = GovernedReader::new();
    assert!(matches!(
        reader.governance(&object),
        Err(tn_core::Error::NotEntitled { .. })
    ));
}

#[test]
fn governed_admission_also_reads_a_signed_chained_envelope() {
    let device = DeviceKey::generate();
    let rules = cipher();
    let object = sample(&device, rules.clone());
    let mut env = object.envelope().clone();
    env.remove("tn_sealed");
    env.insert("sequence".into(), json!(1));
    env.insert(
        "prev_hash".into(),
        json!(format!("sha256:{}", "0".repeat(64))),
    );
    env.insert("level".into(), json!("info"));
    env.insert("run_id".into(), json!("example-run"));
    let row = GovernedObject::parse(&resign(&mut env, &device)).unwrap();
    assert!(GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap()
        .governance(&row)
        .is_ok());
    // Sequence is stream metadata; the stream verifier checks ordering.
    env.insert("sequence".into(), json!(2));
    assert_eq!(
        GovernedObject::parse(&serde_json::to_string(&env).unwrap())
            .unwrap()
            .id(),
        row.id()
    );
}

#[cfg(feature = "native-jwe")]
#[test]
fn the_same_governed_flow_uses_native_jwe_group_material() {
    use tn_core::cipher::jwe::JweCipher;
    let device = DeviceKey::generate();
    let private = [51; 32];
    let public =
        curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(private).to_bytes();
    let rules: Arc<dyn GroupCipher> =
        Arc::new(JweCipher::new("tn.agents", &[public], &[private]).unwrap());
    let data: Arc<dyn GroupCipher> =
        Arc::new(JweCipher::new("observations", &[public], &[private]).unwrap());
    let writer = GovernedWriter::new(&device)
        .with_group("tn.agents", rules.clone(), &[1; 32])
        .unwrap()
        .with_group("observations", data.clone(), &[2; 32])
        .unwrap();
    let policy =
        Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample").unwrap();
    let object = writer
        .seal(
            GovernedDraft::new("research.sample", policy)
                .unwrap()
                .group("observations", json!({"value": 4.5}))
                .unwrap(),
        )
        .unwrap();
    let reader = GovernedReader::new()
        .with_group("tn.agents", rules)
        .unwrap()
        .with_group("observations", data)
        .unwrap();
    let admitted = reader
        .governance(&object)
        .unwrap()
        .authorize("aggregate", |_, _| Ok(true))
        .unwrap();
    assert_eq!(
        reader.open(&admitted, ["observations"]).unwrap().groups()["observations"]["value"],
        4.5
    );
}
