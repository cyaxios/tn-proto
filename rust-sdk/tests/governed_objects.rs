use serde_json::json;
use tn_proto::{GovernedObject, Tn, TnInitOptions, TnProfile, TnProjectOptions};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate the approved aggregate report.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

#[test]
fn configured_objects_sign_with_policy_and_leave_emission_files_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".tn/objects");
    std::fs::create_dir_all(root.join(".tn/config")).unwrap();
    std::fs::write(root.join(".tn/config/agents.md"), POLICY).unwrap();
    let tn = Tn::init_project_with_options(
        "objects",
        TnProjectOptions {
            project_dir: Some(dir.path().to_owned()),
            device_private_bytes: Some(vec![73; 32]),
            profile: TnProfile::Telemetry,
            init: TnInitOptions {
                skip_ceremony_init_emit: true,
                skip_policy_published_emit: true,
            },
        },
    )
    .unwrap();
    let log = tn.log_path().to_owned();
    let before = std::fs::read(&log).ok();
    let objects = tn.objects();
    assert!(objects.draft("no.such.policy").is_err());
    let source = objects
        .seal(
            objects
                .draft("research.sample")
                .unwrap()
                .group("default", json!({"amount": 42}))
                .unwrap(),
        )
        .unwrap();
    let reader = objects.reader().unwrap();
    let legacy = tn
        .unseal(source.wire(), tn_proto::UnsealOptions::default())
        .unwrap();
    assert!(legacy.valid.signature && legacy.valid.row_hash);
    assert_eq!(legacy.fields["amount"], 42);
    let admitted = reader
        .governance(&source)
        .unwrap()
        .authorize("aggregate", |contract, op| {
            Ok(op == "aggregate" && contract.get("use_for") == Some(&json!("Aggregate research.")))
        })
        .unwrap();
    let opened = reader.open(&admitted, ["default"]).unwrap();
    let derived = objects
        .seal(
            opened
                .derive("report.generated")
                .unwrap()
                .group("default", json!({"total": 42}))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(opened.groups()["default"]["amount"], 42);
    assert_ne!(source.id(), derived.id());
    GovernedObject::parse(derived.wire()).unwrap();
    assert_eq!(std::fs::read(&log).ok(), before);
    assert!(!root.join("admin/default.ndjson").exists());

    // A runtime adapter uses the material loaded through that runtime's
    // storage. Additional host files never silently broaden its reader.
    let mut foreign_state = tn_btn::PublisherState::setup(tn_btn::Config::default()).unwrap();
    let foreign_kit = foreign_state.mint().unwrap();
    let foreign_cipher = std::sync::Arc::new(tn_core::cipher::btn::BtnPublisherCipher::from_state(
        foreign_state,
    ));
    let foreign_device = tn_core::DeviceKey::generate();
    let foreign = tn_proto::GovernedWriter::new(&foreign_device)
        .with_group("tn.agents", foreign_cipher, &[4; 32])
        .unwrap()
        .seal(
            tn_proto::GovernedDraft::new(
                "research.sample",
                tn_proto::Governance::from_markdown(
                    foreign_device.did(),
                    POLICY,
                    "agents.md",
                    "research.sample",
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let kit_path = root.join("keys/tn.agents.btn.mykit");
    let saved_kit = std::fs::read(&kit_path).unwrap();
    std::fs::write(&kit_path, foreign_kit.to_bytes()).unwrap();
    assert!(objects.reader().unwrap().governance(&foreign).is_err());
    std::fs::write(&kit_path, saved_kit).unwrap();
    drop(objects);
    tn.close().unwrap();

    // A valid protocol configuration can point at an unusable log location:
    // object-only opening never opens, scans, rotates, or emits to that path.
    if log.exists() {
        std::fs::remove_file(&log).unwrap();
    }
    std::fs::create_dir(&log).unwrap();
    let objects = Tn::open_objects(root.join("tn.yaml")).unwrap();
    let object = objects
        .seal(
            objects
                .draft("research.sample")
                .unwrap()
                .group("default", json!({"amount": 7}))
                .unwrap(),
        )
        .unwrap();
    let reader = objects.reader().unwrap();
    let admitted = reader
        .governance(&object)
        .unwrap()
        .authorize("aggregate", |_, _| Ok(true))
        .unwrap();
    assert_eq!(
        reader.open(&admitted, ["default"]).unwrap().groups()["default"]["amount"],
        7
    );
    assert!(log.is_dir());
    assert!(!root.join("admin/default.ndjson").exists());
}
