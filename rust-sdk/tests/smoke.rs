mod common;

use serde_json::{json, Value};
use serde_yml::Value as YamlValue;
use tn_proto::{Identity, ReadOptions, Tn, TnProfile, TnProjectOptions};

#[test]
fn emits_and_reads_info_event() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let receipt = tn.info(
        "order.created",
        json!({
            "order_id": "A100",
            "amount": 4999,
        }),
    )?;
    assert!(receipt.emitted);
    assert_eq!(
        receipt
            .envelope
            .as_ref()
            .and_then(|v| v.get("event_type"))
            .and_then(Value::as_str),
        Some("order.created")
    );

    let entries = tn.read(ReadOptions::default())?;
    let entry = common::find_event(&entries, "order.created");
    assert_eq!(entry.get("level").and_then(Value::as_str), Some("info"));
    assert_eq!(entry.get("order_id").and_then(Value::as_str), Some("A100"));
    assert_eq!(entry.get("amount").and_then(Value::as_i64), Some(4999));

    tn.close()?;
    Ok(())
}

#[test]
fn rejects_non_object_fields() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let err = tn.info("bad.fields", "not an object").unwrap_err();
    assert!(err
        .to_string()
        .contains("fields must serialize to a JSON object"));
    Ok(())
}

#[test]
fn emit_with_aad_echoes_markers_and_reads_back() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let receipt = tn.emit_with_aad(
        "info",
        "order.flagged",
        json!({ "order_note": "escalate" }),
        json!({ "purpose": "audit" }),
    )?;
    assert!(receipt.emitted);
    let envelope = receipt.envelope.as_ref().expect("envelope");
    let echo = envelope
        .get("tn_aad")
        .and_then(Value::as_str)
        .expect("aad emit must echo a public tn_aad string");
    let echo: Value = serde_json::from_str(echo).expect("tn_aad echo is canonical JSON");
    assert_eq!(echo["default"]["purpose"], Value::String("audit".into()));

    // The sealed group still opens on read: the reader reconstructs the
    // bound AAD bytes from the public tn_aad echo.
    let entries = tn.read(ReadOptions::default())?;
    let entry = common::find_event(&entries, "order.flagged");
    assert_eq!(
        entry.get("order_note").and_then(Value::as_str),
        Some("escalate")
    );
    assert!(entry.get("tn_aad").is_some());

    tn.close()?;
    Ok(())
}

#[test]
fn emit_with_aad_empty_map_keeps_plain_wire_shape() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let receipt = tn.emit_with_aad(
        "info",
        "order.plain",
        json!({ "order_note": "quiet" }),
        json!({}),
    )?;
    assert!(receipt.emitted);
    let envelope = receipt.envelope.as_ref().expect("envelope");
    assert!(
        envelope.get("tn_aad").is_none(),
        "empty aad must not add a tn_aad field"
    );

    let err = tn
        .emit_with_aad("info", "order.bad", json!({ "ok": true }), json!(["nope"]))
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("aad must serialize to a JSON object"));

    tn.close()?;
    Ok(())
}

#[test]
fn config_view_exposes_runtime_basics() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let cfg = tn.config();

    assert!(cfg.device_identity.starts_with("did:key:"));
    assert!(cfg.yaml_path.ends_with("tn.yaml"));
    assert!(cfg.log_path.ends_with("tn.ndjson"));
    assert!(cfg.groups.iter().any(|name| name == "default"));

    Ok(())
}

#[test]
fn init_project_creates_persistent_ceremony_project() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let project_dir = temp.path().join(".tn").join("demo-project");

    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: None,
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )?;

    assert_eq!(tn.yaml_path(), project_dir.join("tn.yaml").as_path());
    assert!(project_dir.join("tn.yaml").is_file());
    assert!(project_dir.join("keys").join("local.private").is_file());
    assert!(project_dir.join("keys").join("local.public").is_file());
    assert!(project_dir.join("keys").join("index_master.key").is_file());
    assert!(project_dir.join("keys").join("default.btn.state").is_file());
    assert!(project_dir.join("keys").join("default.btn.mykit").is_file());
    assert!(project_dir
        .join("keys")
        .join("tn.agents.btn.state")
        .is_file());
    assert!(project_dir
        .join("keys")
        .join("tn.agents.btn.mykit")
        .is_file());
    assert!(project_dir.join("logs").is_dir());
    assert!(project_dir.join("admin").is_dir());
    assert!(project_dir.join("vault").is_dir());
    assert!(project_dir.join("streams").join("default.yaml").is_file());

    let did = tn.did().to_string();
    tn.info("project.created", json!({ "ok": true }))?;
    tn.close()?;

    let reopened = Tn::init(project_dir.join("tn.yaml"))?;
    assert_eq!(reopened.did(), did);
    let entries = reopened.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let entry = common::find_event(&entries, "project.created");
    assert_eq!(entry.get("ok").and_then(Value::as_bool), Some(true));

    Ok(())
}

#[test]
fn init_project_writes_project_yaml_contract() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: None,
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )?;
    let project_dir = temp.path().join(".tn").join("demo-project");
    let yaml_text = std::fs::read_to_string(project_dir.join("tn.yaml"))?;
    let yaml: YamlValue = serde_yml::from_str(&yaml_text)
        .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;

    assert_eq!(yaml_get_str(&yaml, &["ceremony", "mode"]), Some("local"));
    assert_eq!(yaml_get_str(&yaml, &["ceremony", "cipher"]), Some("btn"));
    assert_eq!(
        yaml_get_str(&yaml, &["ceremony", "admin_log_location"]),
        Some("./admin/default.ndjson")
    );
    assert_eq!(
        yaml_get_str(&yaml, &["ceremony", "project_name"]),
        Some("demo-project")
    );
    assert_eq!(
        yaml_get_str(&yaml, &["ceremony", "profile"]),
        Some("transaction")
    );
    assert_eq!(yaml_get_bool(&yaml, &["ceremony", "sign"]), Some(true));
    assert_eq!(yaml_get_bool(&yaml, &["ceremony", "chain"]), Some(true));
    assert_eq!(yaml_get_bool(&yaml, &["vault", "enabled"]), Some(false));
    assert_eq!(
        yaml_get_str(&yaml, &["logs", "path"]),
        Some("./logs/default.ndjson")
    );
    assert_eq!(yaml_get_str(&yaml, &["keystore", "path"]), Some("./keys"));
    assert_eq!(
        yaml_get_str(&yaml, &["device", "device_identity"]),
        Some(tn.did())
    );
    assert_eq!(
        std::fs::read_to_string(project_dir.join("keys").join("local.public"))?,
        tn.did()
    );
    assert!(yaml_get_str(&yaml, &["ceremony", "id"])
        .is_some_and(|id| id.starts_with("local_") && id.len() == "local_".len() + 8));
    assert_eq!(
        yaml_get_str(
            &yaml,
            &["groups", "default", "recipients", "0", "recipient_identity"]
        ),
        Some(tn.did())
    );
    assert_eq!(
        yaml_get_str(
            &yaml,
            &[
                "groups",
                "tn.agents",
                "recipients",
                "0",
                "recipient_identity"
            ]
        ),
        Some(tn.did())
    );
    assert_eq!(
        std::fs::read_to_string(project_dir.join("streams").join("default.yaml"))?,
        "extends: ../tn.yaml\n"
    );

    Ok(())
}

#[test]
fn init_project_stamps_selected_profile() -> tn_proto::Result<()> {
    let cases = [
        (TnProfile::Transaction, "transaction", true, true, true),
        (TnProfile::Audit, "audit", true, true, true),
        (TnProfile::SecureLog, "secure_log", true, false, true),
        (TnProfile::Telemetry, "telemetry", false, false, true),
        (TnProfile::Stdout, "stdout", false, false, false),
    ];

    for (profile, name, signs, chains, has_file_handler) in cases {
        let temp = tempfile::tempdir()?;
        let tn = Tn::init_project_with_options(
            "demo-project",
            TnProjectOptions {
                project_dir: Some(temp.path().to_path_buf()),
                device_private_bytes: None,
                profile,
                init: Default::default(),
            },
        )?;
        tn.close()?;

        let yaml_text = std::fs::read_to_string(temp.path().join(".tn/demo-project/tn.yaml"))?;
        let yaml: YamlValue = serde_yml::from_str(&yaml_text)
            .map_err(|err| tn_proto::Error::InvalidArgument(err.to_string()))?;
        assert_eq!(yaml_get_str(&yaml, &["ceremony", "profile"]), Some(name));
        assert_eq!(yaml_get_bool(&yaml, &["ceremony", "sign"]), Some(signs));
        assert_eq!(yaml_get_bool(&yaml, &["ceremony", "chain"]), Some(chains));

        let handlers = yaml
            .as_mapping()
            .and_then(|m| m.get(YamlValue::String("handlers".to_string())))
            .and_then(YamlValue::as_sequence)
            .expect("handlers must be a yaml sequence");
        assert!(handlers
            .iter()
            .any(|handler| { yaml_get_str(handler, &["kind"]) == Some("stdout") }));
        assert_eq!(
            handlers
                .iter()
                .any(|handler| { yaml_get_str(handler, &["kind"]) == Some("file.rotating") }),
            has_file_handler
        );
    }

    Ok(())
}

#[test]
fn profile_names_parse_from_catalog() -> tn_proto::Result<()> {
    assert_eq!(TnProfile::from_name("transaction")?, TnProfile::Transaction);
    assert_eq!(TnProfile::from_name("audit")?, TnProfile::Audit);
    assert_eq!(TnProfile::from_name("secure_log")?, TnProfile::SecureLog);
    assert_eq!(TnProfile::from_name("telemetry")?, TnProfile::Telemetry);
    assert_eq!(TnProfile::from_name("stdout")?, TnProfile::Stdout);

    let err = TnProfile::from_name("custom").unwrap_err();
    assert!(err.to_string().contains("unknown profile"));

    Ok(())
}

#[test]
fn init_project_reuses_existing_ceremony() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let options = TnProjectOptions {
        project_dir: Some(temp.path().to_path_buf()),
        device_private_bytes: None,
        profile: TnProfile::default(),
        init: Default::default(),
    };

    let tn = Tn::init_project_with_options("demo-project", options.clone())?;
    let did = tn.did().to_string();
    tn.close()?;

    let reopened = Tn::init_project_with_options("demo-project", options)?;
    assert_eq!(reopened.did(), did);

    Ok(())
}

#[test]
fn init_project_loads_or_mints_workspace_identity_by_default() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let options = TnProjectOptions {
        project_dir: Some(temp.path().to_path_buf()),
        device_private_bytes: None,
        profile: TnProfile::default(),
        init: Default::default(),
    };

    let first = Tn::init_project_with_options("alpha", options.clone())?;
    let identity_path = temp.path().join(".tn").join("identity.json");
    assert!(identity_path.is_file());
    let identity = Identity::load(&identity_path)?;
    assert_eq!(first.did(), identity.did);

    let second = Tn::init_project_with_options("beta", options)?;
    assert_eq!(second.did(), first.did());
    assert_eq!(
        std::fs::read(
            temp.path()
                .join(".tn")
                .join("beta")
                .join("keys")
                .join("local.private")
        )?,
        identity.device_private_bytes()?
    );

    Ok(())
}

#[test]
fn init_project_can_bind_existing_device_seed() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let seed = [7u8; 32];
    let expected_device = tn_core::DeviceKey::from_private_bytes(&seed)?;

    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: Some(seed.to_vec()),
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )?;
    let project_dir = temp.path().join(".tn").join("demo-project");

    assert_eq!(tn.did(), expected_device.did());
    assert!(!temp.path().join(".tn").join("identity.json").exists());
    assert_eq!(
        std::fs::read(project_dir.join("keys").join("local.private"))?,
        seed
    );
    assert_eq!(
        std::fs::read_to_string(project_dir.join("keys").join("local.public"))?,
        expected_device.did()
    );

    Ok(())
}

#[test]
fn init_project_rejects_invalid_device_seed_length() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;

    let err = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: Some(vec![1, 2, 3]),
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("device_private_bytes must be 32 bytes"));
    assert!(!temp
        .path()
        .join(".tn")
        .join("demo-project")
        .join("tn.yaml")
        .exists());

    Ok(())
}

#[test]
fn init_project_preserves_existing_default_stream_overlay() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let stream_path = temp
        .path()
        .join(".tn")
        .join("demo-project")
        .join("streams")
        .join("default.yaml");
    std::fs::create_dir_all(stream_path.parent().unwrap())?;
    std::fs::write(
        &stream_path,
        "extends: ../tn.yaml\nlogs:\n  path: ./logs/custom.ndjson\n",
    )?;

    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: None,
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )?;
    tn.close()?;

    assert_eq!(
        std::fs::read_to_string(stream_path)?,
        "extends: ../tn.yaml\nlogs:\n  path: ./logs/custom.ndjson\n"
    );

    Ok(())
}

#[test]
fn init_project_forwards_init_options() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: None,
            profile: TnProfile::default(),
            init: tn_proto::TnInitOptions {
                skip_ceremony_init_emit: true,
                skip_policy_published_emit: true,
            },
        },
    )?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    assert!(entries
        .iter()
        .all(|entry| entry.event_type() != Some("tn.ceremony.init")));

    Ok(())
}

#[test]
fn init_missing_yaml_remains_load_only() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("tn.yaml");

    let err = Tn::init(&missing).unwrap_err();
    assert!(!err.to_string().is_empty());
    assert!(!missing.exists());
}

#[test]
fn init_project_refuses_orphaned_keystore_without_yaml() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let private_path = temp
        .path()
        .join(".tn")
        .join("demo-project")
        .join("keys")
        .join("local.private");
    std::fs::create_dir_all(private_path.parent().unwrap())?;
    std::fs::write(&private_path, b"not a real key")?;

    let err = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            device_private_bytes: None,
            profile: TnProfile::default(),
            init: Default::default(),
        },
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("refusing to create fresh ceremony"));

    Ok(())
}

#[test]
fn init_project_rejects_invalid_project_names() -> tn_proto::Result<()> {
    for name in ["", "tn", "-bad", "bad/name", "bad name", "ümlaut"] {
        let err = Tn::init_project(name).unwrap_err();
        assert!(
            err.to_string().contains("invalid project name"),
            "unexpected error for {name:?}: {err}"
        );
    }

    Ok(())
}

fn yaml_get_str<'a>(value: &'a YamlValue, path: &[&str]) -> Option<&'a str> {
    yaml_get(value, path).and_then(YamlValue::as_str)
}

fn yaml_get_bool(value: &YamlValue, path: &[&str]) -> Option<bool> {
    yaml_get(value, path).and_then(YamlValue::as_bool)
}

fn yaml_get<'a>(value: &'a YamlValue, path: &[&str]) -> Option<&'a YamlValue> {
    let mut current = value;
    for segment in path {
        if let Ok(index) = segment.parse::<usize>() {
            current = current.as_sequence()?.get(index)?;
        } else {
            current = current
                .as_mapping()?
                .get(YamlValue::String((*segment).to_string()))?;
        }
    }
    Some(current)
}
