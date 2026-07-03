use std::path::Path;
#[cfg(feature = "http")]
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

use serde_yml::Value as YamlValue;
use tn_proto::{
    Error, ReadOptions, SetLinkStateOptions, Tn, TnProjectOptions, VaultClientConnectOptions,
    VaultConnectOptions, VaultLinkState, VaultProject, VaultProjectClient,
};

#[test]
fn vault_link_records_admin_state() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    let result = tn.vault().link("did:web:vault.example", "proj_123")?;
    assert_eq!(result.vault_identity, "did:web:vault.example");
    assert_eq!(result.project_id, "proj_123");

    let state = tn.admin().state(None)?;
    let link = state
        .vault_links
        .iter()
        .find(|row| row.vault_identity == "did:web:vault.example")
        .expect("vault link should appear in admin state");
    assert_eq!(link.project_id, "proj_123");
    assert!(link.unlinked_at.is_none());
    assert!(!link.linked_at.is_empty());

    Ok(())
}

#[test]
fn vault_link_is_idempotent_for_active_same_project() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    tn.vault().link("did:web:vault.example", "proj_123")?;
    tn.vault().link("did:web:vault.example", "proj_123")?;

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let linked_count = entries
        .iter()
        .filter(|entry| entry.event_type() == Some("tn.vault.linked"))
        .count();
    assert_eq!(linked_count, 1);

    Ok(())
}

#[test]
fn vault_unlink_records_reason_and_allows_relink() -> tn_proto::Result<()> {
    let mut tn = Tn::ephemeral()?;

    tn.vault().link("did:web:vault.example", "proj_123")?;
    let unlink = tn
        .vault()
        .unlink("did:web:vault.example", "proj_123", Some("rotated"))?;
    assert_eq!(unlink.reason.as_deref(), Some("rotated"));

    let state = tn.admin().state(None)?;
    let link = state
        .vault_links
        .iter()
        .find(|row| row.vault_identity == "did:web:vault.example")
        .expect("vault link should remain visible after unlink");
    assert!(link.unlinked_at.is_some());

    tn.vault().link("did:web:vault.example", "proj_123")?;
    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let linked_count = entries
        .iter()
        .filter(|entry| entry.event_type() == Some("tn.vault.linked"))
        .count();
    assert_eq!(linked_count, 2);

    Ok(())
}

#[test]
fn vault_unlink_without_reason_writes_null_reason() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let result = tn
        .vault()
        .unlink("did:web:vault.example", "proj_123", Option::<&str>::None)?;
    assert_eq!(result.reason, None);

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let unlink = entries
        .iter()
        .find(|entry| entry.event_type() == Some("tn.vault.unlinked"))
        .expect("unlink event should be readable");
    assert!(unlink.get("reason").is_some_and(serde_json::Value::is_null));

    Ok(())
}

#[test]
fn vault_body_encryption_roundtrips_supported_whole_body_model() -> tn_proto::Result<()> {
    let mut body = tn_proto::VaultBodyPlaintext::new();
    body.insert("body/tn.yaml".to_string(), b"ceremony: demo\n".to_vec());
    body.insert("body/keys/local.private".to_string(), vec![7_u8; 32]);
    let bek = tn_proto::VaultBek::new([3_u8; 32]);
    let nonce = [4_u8; 12];

    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &nonce)?;
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;

    assert_eq!(tn_proto::VAULT_BODY_CIPHER_SUITE, "aes-256-gcm");
    assert_eq!(tn_proto::VAULT_BODY_FRAME, "tn-encrypted-body-v2-zip");
    assert!(encrypted.starts_with(&nonce));
    assert_eq!(decrypted, body);

    let mut tampered = encrypted.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = tn_proto::decrypt_vault_body(&tampered, &bek).unwrap_err();
    assert!(err.to_string().contains("decrypt failed"));

    Ok(())
}

#[test]
fn vault_key_wrappers_validate_lengths_and_hide_debug_material() -> tn_proto::Result<()> {
    let bek = tn_proto::VaultBek::from_slice(&[9_u8; 32])?;
    let awk = tn_proto::VaultAwk::from_slice(&[8_u8; 32])?;

    assert_eq!(bek.as_bytes(), &[9_u8; 32]);
    assert_eq!(awk.as_bytes(), &[8_u8; 32]);
    assert_eq!(format!("{bek:?}"), "VaultBek(..)");
    assert_eq!(format!("{awk:?}"), "VaultAwk(..)");
    assert!(tn_proto::VaultBek::from_slice(&[1_u8; 31])
        .unwrap_err()
        .to_string()
        .contains("32 bytes"));
    assert!(tn_proto::VaultAwk::from_slice(&[1_u8; 33])
        .unwrap_err()
        .to_string()
        .contains("32 bytes"));

    Ok(())
}

#[test]
fn vault_wraps_and_unwraps_bek_under_awk() -> tn_proto::Result<()> {
    let awk = tn_proto::VaultAwk::new([2_u8; 32]);
    let bek = tn_proto::VaultBek::new([9_u8; 32]);
    let nonce = [7_u8; 12];

    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &nonce)?;
    let unwrapped = tn_proto::unwrap_bek_from_awk(&awk, &wrapped)?;

    assert_eq!(tn_proto::VAULT_BEK_WRAP_AAD, b"tn-vault-bek-wrap-v1");
    assert_eq!(tn_proto::VAULT_AWK_WRAP_AAD, b"tn-vault-awk-wrap-v1");
    assert_eq!(unwrapped.as_bytes(), bek.as_bytes());
    assert_eq!(
        wrapped.wrap_nonce_b64,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce)
    );
    assert_ne!(
        wrapped.wrapped_bek_b64,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bek.as_bytes())
    );
    assert_eq!(
        wrapped
            .clone()
            .into_json()
            .get("cipher_suite")
            .and_then(serde_json::Value::as_str),
        Some("aes-256-gcm")
    );

    Ok(())
}

#[test]
fn vault_derives_awk_and_bek_from_passphrase_material() -> tn_proto::Result<()> {
    let passphrase = "correct horse battery staple";
    let salt = [4_u8; 16];
    let awk = tn_proto::VaultAwk::new([5_u8; 32]);
    let bek = tn_proto::VaultBek::new([6_u8; 32]);
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[7_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let wrapped_bek = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[8_u8; 12])?;
    let credential = tn_proto::VaultCredentialWrap {
        kdf: "pbkdf2-sha256".to_string(),
        kdf_params: tn_proto::VaultCredentialKdfParams {
            salt_b64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                salt,
            )),
            iterations: Some(10_000),
            iter: None,
        },
        wrapped_account_key_b64: wrapped_awk.wrapped_b64,
        wrap_nonce_b64: wrapped_awk.nonce_b64,
    };

    let derived_awk = tn_proto::derive_awk_from_material(passphrase, &credential)?;
    let derived_bek = tn_proto::derive_bek_from_material(passphrase, &credential, &wrapped_bek)?;

    assert_eq!(derived_awk.as_bytes(), awk.as_bytes());
    assert_eq!(derived_bek.as_bytes(), bek.as_bytes());

    Ok(())
}

#[test]
fn vault_awk_derivation_rejects_weak_or_wrong_material() -> tn_proto::Result<()> {
    let credential = tn_proto::VaultCredentialWrap {
        kdf: "argon2id".to_string(),
        kdf_params: tn_proto::VaultCredentialKdfParams {
            salt_b64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [1_u8; 16],
            )),
            iterations: Some(10_000),
            iter: None,
        },
        wrapped_account_key_b64: "abc".to_string(),
        wrap_nonce_b64: "def".to_string(),
    };
    let err = tn_proto::derive_awk_from_material("pw", &credential).unwrap_err();
    assert!(err.to_string().contains("not supported"));

    let mut credential = credential;
    credential.kdf = "pbkdf2-sha256".to_string();
    credential.kdf_params.iterations = Some(9_999);
    let err = tn_proto::derive_awk_from_material("pw", &credential).unwrap_err();
    assert!(err.to_string().contains("refusing PBKDF2"));

    credential.kdf_params.iterations = Some(10_000);
    credential.kdf_params.salt_b64 = None;
    let err = tn_proto::derive_awk_from_material("pw", &credential).unwrap_err();
    assert!(err.to_string().contains("salt_b64"));

    let passphrase = "right";
    let wrong_passphrase = "wrong";
    let salt = [2_u8; 16];
    let key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped =
        wrap_raw_with_nonce(&key, &[3_u8; 32], &[4_u8; 12], tn_proto::VAULT_AWK_WRAP_AAD)?;
    credential.kdf_params.salt_b64 = Some(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        salt,
    ));
    credential.wrapped_account_key_b64 = wrapped.wrapped_b64;
    credential.wrap_nonce_b64 = wrapped.nonce_b64;

    let err = tn_proto::derive_awk_from_material(wrong_passphrase, &credential).unwrap_err();
    assert!(err.to_string().contains("unwrap AWK failed"));

    Ok(())
}

#[test]
fn vault_unwrap_bek_rejects_tampered_wire_fields() -> tn_proto::Result<()> {
    let awk = tn_proto::VaultAwk::new([2_u8; 32]);
    let wrong_awk = tn_proto::VaultAwk::new([3_u8; 32]);
    let bek = tn_proto::VaultBek::new([9_u8; 32]);
    let mut wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[7_u8; 12])?;

    let err = tn_proto::unwrap_bek_from_awk(&wrong_awk, &wrapped).unwrap_err();
    assert!(err.to_string().contains("unwrap BEK"));

    wrapped.wrap_nonce_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1_u8; 11]);
    let err = tn_proto::unwrap_bek_from_awk(&awk, &wrapped).unwrap_err();
    assert!(err.to_string().contains("expected 12"));

    wrapped.wrap_nonce_b64 = "not base64!".to_string();
    let err = tn_proto::unwrap_bek_from_awk(&awk, &wrapped).unwrap_err();
    assert!(err.to_string().contains("invalid wrap_nonce_b64"));

    Ok(())
}

struct WrappedRaw {
    wrapped_b64: String,
    nonce_b64: String,
}

#[cfg(feature = "http")]
fn credential_wrap_list_json(salt: &[u8], wrapped: &WrappedRaw) -> String {
    serde_json::json!([{
        "is_primary": true,
        "kdf": "pbkdf2-sha256",
        "kdf_params": {
            "salt_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                salt
            ),
            "iterations": 10000
        },
        "wrapped_account_key_b64": wrapped.wrapped_b64,
        "wrap_nonce_b64": wrapped.nonce_b64
    }])
    .to_string()
}

fn wrap_raw_with_nonce(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> tn_proto::Result<WrappedRaw> {
    use aes_gcm::aead::{Aead as _, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| tn_proto::Error::InvalidArgument(format!("invalid test key: {err}")))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| tn_proto::Error::InvalidArgument("test wrap failed".into()))?;
    Ok(WrappedRaw {
        wrapped_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        nonce_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
    })
}

#[test]
fn vault_collect_body_matches_wallet_push_layout() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "sync-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.info("payment.created", serde_json::json!({"amount": 42}))?;
    let body = tn.vault().collect_body()?;

    assert!(body.contains_key("body/tn.yaml"));
    assert!(body.contains_key("body/keys/local.private"));
    assert!(body.contains_key("body/keys/local.public"));
    assert!(body.contains_key("body/keys/index_master.key"));
    assert!(body.contains_key("body/keys/default.btn.state"));
    assert!(body.contains_key("body/keys/default.btn.mykit"));
    assert!(body.keys().all(|name| !name.starts_with("body/logs/")));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_init_upload_http_posts_pending_claim_and_persists_surfaces() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        201,
        r#"{"vault_id":"01TESTCLAIMID","expires_at":"2030-01-02T03:04:05Z"}"#,
    )])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "claim-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let result = tn
        .vault()
        .init_upload_http(&client, tn_proto::VaultInitUploadOptions::default())?;

    assert_eq!(result.vault_id, "01TESTCLAIMID");
    assert_eq!(result.expires_at, "2030-01-02T03:04:05Z");
    assert!(result
        .claim_url
        .starts_with(&format!("{}/claim/01TESTCLAIMID#k=", server.base_url())));
    assert_eq!(result.password_b64.len(), 43);
    assert!(result.claim_url.ends_with(&result.password_b64));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let request_lower = request.to_ascii_lowercase();
    assert!(request.starts_with("POST /api/v1/pending-claims "));
    assert!(request_lower.contains("content-type: application/octet-stream"));
    assert!(request_lower.contains("x-project-name: claim-demo"));
    assert!(request_lower.contains(&format!(
        "x-publisher-did: {}",
        tn.did().to_ascii_lowercase()
    )));
    assert!(
        request.contains("\r\n\r\nPK"),
        "pending-claim body should be a .tnpkg zip"
    );

    let sync_dir = tn.yaml_path().parent().unwrap().join(".tn").join("sync");
    let claim_file = sync_dir.join("claim_url.txt");
    assert_eq!(
        std::fs::read_to_string(&claim_file)?.trim(),
        result.claim_url
    );
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sync_dir.join("state.json"))?)?;
    assert_eq!(
        state["pending_claim"]["vault_id"].as_str(),
        Some("01TESTCLAIMID")
    );
    assert_eq!(
        state["pending_claim"]["password_b64"].as_str(),
        Some(result.password_b64.as_str())
    );

    let outbox = tn
        .yaml_path()
        .parent()
        .unwrap()
        .join(".tn")
        .join("tn")
        .join("admin")
        .join("outbox");
    let event_path = std::fs::read_dir(outbox)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("claim_url_issued_"))
        })
        .expect("claim-url admin event should be written");
    let event_text = std::fs::read_to_string(event_path)?;
    assert!(event_text.contains("tn.vault.claim_url_issued"));
    assert!(event_text.contains("#k=<redacted>"));
    assert!(!event_text.contains(&result.password_b64));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn init_project_with_vault_claim_creates_project_and_surfaces_claim() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        201,
        r#"{"vault_id":"01HELPERCLAIM","expires_at":"2030-05-06T07:08:09Z"}"#,
    )])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let temp = tempfile::tempdir()?;

    let result = Tn::init_project_with_vault_claim_options(
        "helper-demo",
        &client,
        tn_proto::TnProjectVaultClaimOptions {
            project: TnProjectOptions {
                project_dir: Some(temp.path().to_path_buf()),
                ..Default::default()
            },
            ..Default::default()
        },
    )?;

    assert!(result.tn.config().groups.contains(&"default".to_string()));
    assert_eq!(result.claim.vault_id, "01HELPERCLAIM");
    assert_eq!(result.claim.expires_at, "2030-05-06T07:08:09Z");
    assert!(result
        .claim
        .claim_url
        .starts_with(&format!("{}/claim/01HELPERCLAIM#k=", server.base_url())));
    assert!(result.claim.claim_url.ends_with(&result.claim.password_b64));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/pending-claims "));
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("x-project-name: helper-demo"));

    let claim_file = result
        .tn
        .yaml_path()
        .parent()
        .unwrap()
        .join(".tn")
        .join("sync")
        .join("claim_url.txt");
    assert_eq!(
        std::fs::read_to_string(claim_file)?.trim(),
        result.claim.claim_url
    );

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_init_upload_http_rejects_malformed_pending_claim_response() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(201, r#"{"vault_id":"missing-exp"}"#)])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "claim-bad-response",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let err = tn
        .vault()
        .init_upload_http(&client, tn_proto::VaultInitUploadOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("expires_at"));

    Ok(())
}

#[test]
fn vault_install_body_writes_project_layout_to_target_dir() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let source = Tn::init_project_with_options(
        "install-source",
        TnProjectOptions {
            project_dir: Some(temp.path().join("source")),
            ..Default::default()
        },
    )?;
    let body = source.vault().collect_body()?;
    let target = temp.path().join("restored");

    let result = source.vault().install_body(
        &body,
        tn_proto::VaultInstallBodyOptions::new(target.clone()),
    )?;

    assert_eq!(normalize_path(&result.target_dir), normalize_path(&target));
    assert_eq!(result.yaml_path, target.join("tn.yaml"));
    assert_eq!(result.keys_dir, target.join("keys"));
    assert!(result.written_paths.contains(&target.join("tn.yaml")));
    assert!(result
        .written_paths
        .contains(&target.join("keys").join("local.private")));
    assert!(result
        .written_paths
        .contains(&target.join("keys").join("local.public")));
    assert_eq!(std::fs::read(target.join("tn.yaml"))?, body["body/tn.yaml"]);
    assert_eq!(
        std::fs::read(target.join("keys").join("local.private"))?,
        body["body/keys/local.private"]
    );
    assert!(result.skipped_members.is_empty());

    Ok(())
}

#[test]
fn vault_install_body_dedupes_and_refuses_different_existing_files() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let source = Tn::init_project_with_options(
        "install-dedupe",
        TnProjectOptions {
            project_dir: Some(temp.path().join("source")),
            ..Default::default()
        },
    )?;
    let body = source.vault().collect_body()?;
    let target = temp.path().join("restored");

    tn_proto::install_vault_body(&body, tn_proto::VaultInstallBodyOptions::new(&target))?;
    let second =
        tn_proto::install_vault_body(&body, tn_proto::VaultInstallBodyOptions::new(&target))?;
    assert!(second.written_paths.is_empty());
    assert!(second.deduped_paths.contains(&target.join("tn.yaml")));

    std::fs::write(target.join("tn.yaml"), b"different")?;
    let err = tn_proto::install_vault_body(&body, tn_proto::VaultInstallBodyOptions::new(&target))
        .unwrap_err();
    assert!(err.to_string().contains("different contents"));

    let mut overwrite = tn_proto::VaultInstallBodyOptions::new(&target);
    overwrite.overwrite = true;
    let replaced = tn_proto::install_vault_body(&body, overwrite)?;
    assert!(replaced.written_paths.contains(&target.join("tn.yaml")));
    assert_eq!(std::fs::read(target.join("tn.yaml"))?, body["body/tn.yaml"]);

    Ok(())
}

#[test]
fn vault_install_body_rejects_missing_or_mismatched_identity_material() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let source = Tn::init_project_with_options(
        "install-invalid",
        TnProjectOptions {
            project_dir: Some(temp.path().join("source")),
            ..Default::default()
        },
    )?;
    let mut body = source.vault().collect_body()?;

    let mut missing = body.clone();
    missing.remove("body/keys/local.public");
    let err = tn_proto::install_vault_body(
        &missing,
        tn_proto::VaultInstallBodyOptions::new(temp.path()),
    )
    .unwrap_err();
    assert!(err.to_string().contains("local.public"));

    body.insert(
        "body/keys/local.public".to_string(),
        b"did:key:wrong".to_vec(),
    );
    let err = tn_proto::install_vault_body(
        &body,
        tn_proto::VaultInstallBodyOptions::new(temp.path().join("bad")),
    )
    .unwrap_err();
    assert!(err.to_string().contains("identity mismatch"));

    Ok(())
}

#[test]
fn vault_install_body_rejects_nested_or_traversal_key_members() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let source = Tn::init_project_with_options(
        "install-traversal",
        TnProjectOptions {
            project_dir: Some(temp.path().join("source")),
            ..Default::default()
        },
    )?;
    let mut body = source.vault().collect_body()?;
    body.insert("body/keys/nested/file".to_string(), b"nope".to_vec());

    let err = tn_proto::install_vault_body(
        &body,
        tn_proto::VaultInstallBodyOptions::new(temp.path().join("bad")),
    )
    .unwrap_err();

    assert!(err.to_string().contains("flat body/keys"));

    Ok(())
}

#[test]
fn vault_set_link_state_links_project_yaml() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let result = tn.vault().set_link_state(
        VaultLinkState::Linked,
        SetLinkStateOptions {
            linked_vault: Some("https://vault.example".to_string()),
            linked_project_id: Some("proj_123".to_string()),
        },
    )?;

    assert_eq!(result.state, VaultLinkState::Linked);
    assert_eq!(
        normalize_path(&result.yaml_path),
        normalize_path(tn.yaml_path())
    );
    assert_eq!(
        result.linked_vault.as_deref(),
        Some("https://vault.example")
    );
    assert_eq!(result.linked_project_id.as_deref(), Some("proj_123"));
    let state = tn.vault().link_state()?;
    assert_eq!(state.state, VaultLinkState::Linked);
    assert_eq!(state.linked_vault.as_deref(), Some("https://vault.example"));
    assert_eq!(state.linked_project_id.as_deref(), Some("proj_123"));
    assert!(state.vault_enabled);
    assert!(!state.autosync);
    assert_eq!(state.sync_interval_seconds, Some(600));

    let yaml = read_yaml(tn.yaml_path())?;
    assert_eq!(yaml_get_str(&yaml, &["ceremony", "mode"]), Some("linked"));
    assert_eq!(
        yaml_get_str(&yaml, &["ceremony", "linked_vault"]),
        Some("https://vault.example")
    );
    assert_eq!(
        yaml_get_str(&yaml, &["ceremony", "linked_project_id"]),
        Some("proj_123")
    );
    assert_eq!(yaml_get_bool(&yaml, &["vault", "enabled"]), Some(true));
    assert_eq!(
        yaml_get_str(&yaml, &["vault", "url"]),
        Some("https://vault.example")
    );
    assert_eq!(
        yaml_get_str(&yaml, &["vault", "linked_project_id"]),
        Some("proj_123")
    );
    assert_eq!(yaml_get_bool(&yaml, &["vault", "autosync"]), Some(false));
    assert_eq!(
        yaml_get_i64(&yaml, &["vault", "sync_interval_seconds"]),
        Some(600)
    );

    Ok(())
}

#[test]
fn vault_link_state_reads_default_local_project_yaml() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let state = tn.vault().link_state()?;

    assert_eq!(state.state, VaultLinkState::Local);
    assert_eq!(
        normalize_path(&state.yaml_path),
        normalize_path(tn.yaml_path())
    );
    assert_eq!(state.linked_vault, None);
    assert_eq!(state.linked_project_id, None);
    assert!(!state.vault_enabled);
    assert!(!state.autosync);
    assert_eq!(state.sync_interval_seconds, None);

    Ok(())
}

#[test]
fn vault_connect_links_yaml_and_reports_audit_attempt() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let mut options = VaultConnectOptions::new("https://vault.example", "proj_123");
    options.project_name = Some("demo-project".to_string());
    let result = tn.vault().connect(options)?;

    assert_eq!(result.vault, "https://vault.example");
    assert_eq!(result.project_id, "proj_123");
    assert_eq!(result.project_name.as_deref(), Some("demo-project"));
    assert!(result.newly_linked);
    assert!(result.audit_event_recorded);
    assert_eq!(result.state.state, VaultLinkState::Linked);
    assert_eq!(
        result.state.linked_vault.as_deref(),
        Some("https://vault.example")
    );
    assert_eq!(result.state.linked_project_id.as_deref(), Some("proj_123"));

    Ok(())
}

#[test]
fn vault_connect_is_idempotent_for_same_vault_project() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    tn.vault().connect(VaultConnectOptions::new(
        "https://vault.example",
        "proj_123",
    ))?;
    let result = tn.vault().connect(VaultConnectOptions::new(
        "https://vault.example",
        "proj_123",
    ))?;

    assert!(!result.newly_linked);
    assert!(!result.audit_event_recorded);
    assert_eq!(result.state.state, VaultLinkState::Linked);

    Ok(())
}

#[test]
fn vault_connect_can_skip_audit_event() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let mut options = VaultConnectOptions::new("https://vault.example", "proj_123");
    options.record_audit_event = false;
    let result = tn.vault().connect(options)?;

    assert!(result.newly_linked);
    assert!(!result.audit_event_recorded);
    assert_eq!(result.state.state, VaultLinkState::Linked);

    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    assert!(entries
        .iter()
        .all(|entry| entry.event_type() != Some("tn.vault.linked")));

    Ok(())
}

#[test]
fn vault_connect_rejects_different_active_project() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    tn.vault().connect(VaultConnectOptions::new(
        "https://vault.example",
        "proj_123",
    ))?;
    let err = tn
        .vault()
        .connect(VaultConnectOptions::new(
            "https://vault.example",
            "proj_456",
        ))
        .unwrap_err();

    assert!(err.to_string().contains("already linked"));
    let state = tn.vault().link_state()?;
    assert_eq!(state.linked_project_id.as_deref(), Some("proj_123"));

    Ok(())
}

#[test]
fn vault_connect_rejects_empty_values() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let err = tn
        .vault()
        .connect(VaultConnectOptions::new(" ", "proj_123"))
        .unwrap_err();
    assert!(err.to_string().contains("vault must not be empty"));

    let err = tn
        .vault()
        .connect(VaultConnectOptions::new("https://vault.example", " "))
        .unwrap_err();
    assert!(err.to_string().contains("project_id must not be empty"));

    Ok(())
}

#[test]
fn vault_connect_with_client_creates_project_and_connects() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut client = FakeVaultProjectClient::new("https://vault.example");

    let result = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;

    assert!(result.newly_linked);
    assert_eq!(result.vault, "https://vault.example");
    assert_eq!(result.project_id, "proj_1");
    assert_eq!(result.project_name.as_deref(), Some("demo-project"));
    assert_eq!(result.state.state, VaultLinkState::Linked);
    assert_eq!(client.calls.len(), 1);
    assert_eq!(client.calls[0].0, "demo-project");
    assert!(client.calls[0]
        .1
        .as_deref()
        .is_some_and(|id| id.starts_with("local_")));

    Ok(())
}

#[test]
fn vault_connect_with_client_uses_explicit_project_name() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut client = FakeVaultProjectClient::new("https://vault.example");

    let result = tn.vault().connect_with_client(
        &mut client,
        VaultClientConnectOptions {
            project_name: Some("operator-name".to_string()),
            ..Default::default()
        },
    )?;

    assert_eq!(result.project_name.as_deref(), Some("operator-name"));
    assert_eq!(client.calls[0].0, "operator-name");

    Ok(())
}

#[test]
fn vault_connect_with_client_is_idempotent_without_client_call() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut client = FakeVaultProjectClient::new("https://vault.example");
    tn.vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;
    client.calls.clear();

    let result = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;

    assert!(!result.newly_linked);
    assert_eq!(result.project_id, "proj_1");
    assert!(client.calls.is_empty());

    Ok(())
}

#[test]
fn vault_connect_with_client_propagates_project_client_error() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut client = FakeVaultProjectClient::new("https://vault.example");
    client.error = Some("project create failed".to_string());

    let err = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())
        .unwrap_err();

    assert!(err.to_string().contains("project create failed"));
    assert_eq!(tn.vault().link_state()?.state, VaultLinkState::Local);

    Ok(())
}

#[test]
fn vault_connect_with_client_rejects_empty_base_url() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut client = FakeVaultProjectClient::new(" ");

    let err = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())
        .unwrap_err();

    assert!(err.to_string().contains("vault base_url must not be empty"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_creates_project() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        201,
        r#"{"id":"proj_http","name":"demo-project","ceremony_id":"local_123"}"#,
    )])?;
    let mut client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;

    let project = client.ensure_project("demo-project", Some("local_123"))?;

    assert_eq!(project.id, "proj_http");
    assert_eq!(project.name, "demo-project");
    assert_eq!(project.ceremony_id.as_deref(), Some("local_123"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/v1/projects "));
    assert!(requests[0].contains("authorization: Bearer token-123"));
    assert!(requests[0].contains(r#""name":"demo-project""#));
    assert!(requests[0].contains(r#""ceremony_id":"local_123""#));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_project_crud_and_restore_manifest() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(
            201,
            r#"{"id":"proj 1/beta","name":"demo-project","ceremony_id":"local_123"}"#,
        ),
        json_response(
            200,
            r#"[{"id":"proj 1/beta","name":"demo-project","ceremony_id":"local_123"}]"#,
        ),
        json_response(
            200,
            r#"{"id":"proj 1/beta","name":"demo-project","ceremony_id":"local_123"}"#,
        ),
        json_response(
            200,
            r#"{"project_id":"proj 1/beta","files":[{"name":"admin-snapshot.tnpkg"}]}"#,
        ),
        json_response(204, ""),
    ])?;
    let client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;

    let created = client.create_project("demo-project", Some("local_123"))?;
    let projects = client.list_projects()?;
    let fetched = client.get_project("proj 1/beta")?;
    let manifest = client.restore_manifest("proj 1/beta")?;
    client.delete_project("proj 1/beta")?;

    assert_eq!(created.id, "proj 1/beta");
    assert_eq!(projects.len(), 1);
    assert_eq!(fetched.name, "demo-project");
    assert_eq!(
        manifest
            .get("project_id")
            .and_then(serde_json::Value::as_str),
        Some("proj 1/beta")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("POST /api/v1/projects "));
    assert!(requests[1].starts_with("GET /api/v1/projects "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj%201%2Fbeta "));
    assert!(requests[3].starts_with("POST /api/v1/projects/proj%201%2Fbeta/restore "));
    assert!(requests[4].starts_with("DELETE /api/v1/projects/proj%201%2Fbeta "));
    assert!(requests
        .iter()
        .all(|request| request.contains("authorization: Bearer token-123")));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_on_malformed_restore_manifest() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(200, r#"[]"#)])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client.restore_manifest("proj_123").unwrap_err();

    assert!(err.to_string().contains("restore manifest"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_file_routes_roundtrip_raw_sealed_bytes() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"[{"name":"snap 1/package.tnpkg","size":4,"sha256":"abcd","uploaded_at":"2026-06-24T00:00:00Z"}]"#,
        ),
        json_response(
            201,
            r#"{"name":"snap 1/package.tnpkg","size":4,"sha256":"abcd","uploaded_at":"2026-06-24T00:00:00Z"}"#,
        ),
        binary_response(200, b"\x01\x02\x03\x04"),
        json_response(204, ""),
    ])?;
    let client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;

    let files = client.list_files("proj 1/beta")?;
    let uploaded = client.upload_sealed("proj 1/beta", "snap 1/package.tnpkg", [1, 2, 3, 4])?;
    let downloaded = client.download_sealed("proj 1/beta", "snap 1/package.tnpkg")?;
    client.delete_file("proj 1/beta", "snap 1/package.tnpkg")?;

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "snap 1/package.tnpkg");
    assert_eq!(files[0].size, Some(4));
    assert_eq!(files[0].sha256.as_deref(), Some("abcd"));
    assert_eq!(
        files[0].uploaded_at.as_deref(),
        Some("2026-06-24T00:00:00Z")
    );
    assert_eq!(uploaded.name, "snap 1/package.tnpkg");
    assert_eq!(downloaded, vec![1, 2, 3, 4]);
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj%201%2Fbeta/files "));
    assert!(requests[1]
        .starts_with("PUT /api/v1/projects/proj%201%2Fbeta/files/snap%201%2Fpackage.tnpkg "));
    assert!(requests[1].contains("content-type: application/octet-stream"));
    assert!(requests[2]
        .starts_with("GET /api/v1/projects/proj%201%2Fbeta/files/snap%201%2Fpackage.tnpkg "));
    assert!(requests[3]
        .starts_with("DELETE /api/v1/projects/proj%201%2Fbeta/files/snap%201%2Fpackage.tnpkg "));
    assert!(requests
        .iter()
        .all(|request| request.contains("authorization: Bearer token-123")));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_posts_inbox_snapshot() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        201,
        r#"{"stored_path":"/api/v1/inbox/did:key:zPub/snapshots/ceremony-1/20260626T210000000000Z.tnpkg","byte_size":7,"manifest_signature_b64":"sig-123","head_row_hash":"hash-123"}"#,
    )])?;
    let client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;

    let result = client.post_inbox_snapshot(
        "did:key:zPub",
        "ceremony-1",
        "20260626T210000000000Z",
        b"package",
    )?;

    assert_eq!(
        result.stored_path,
        "/api/v1/inbox/did:key:zPub/snapshots/ceremony-1/20260626T210000000000Z.tnpkg"
    );
    assert_eq!(result.byte_size, 7);
    assert_eq!(result.manifest_signature_b64, "sig-123");
    assert_eq!(result.head_row_hash.as_deref(), Some("hash-123"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "POST /api/v1/inbox/did%3Akey%3AzPub/snapshots/ceremony-1/20260626T210000000000Z.tnpkg "
    ));
    assert!(requests[0].contains("authorization: Bearer token-123"));
    assert!(requests[0].contains("content-type: application/octet-stream"));
    assert!(requests[0].ends_with("package"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_on_malformed_file_metadata() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(200, r#"[{"size":4}]"#)])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client.list_files("proj_123").unwrap_err();

    assert!(err.to_string().contains("missing name"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_fetches_primary_credential_wrap() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        200,
        r#"[
            {
              "id":"secondary",
              "is_primary":false,
              "kdf":"pbkdf2-sha256",
              "kdf_params":{"salt_b64":"AQID","iterations":10000},
              "wrapped_account_key_b64":"abc",
              "wrap_nonce_b64":"def"
            },
            {
              "id":"primary",
              "is_primary":true,
              "kdf":"pbkdf2-sha256",
              "kdf_params":{"salt_b64":"BAUG","iterations":300000},
              "wrapped_account_key_b64":"primary-wrap",
              "wrap_nonce_b64":"primary-nonce"
            }
        ]"#,
    )])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    client.set_bearer_token("jwt-credential");

    let credential = client.get_credential_wrap(None)?;

    assert_eq!(credential.kdf, "pbkdf2-sha256");
    assert_eq!(credential.kdf_params.iterations, Some(300_000));
    assert_eq!(credential.wrapped_account_key_b64, "primary-wrap");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[0].contains("authorization: Bearer jwt-credential"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_fetches_explicit_credential_wrap() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        200,
        r#"{
          "kdf":"pbkdf2-sha256",
          "kdf_params":{"salt_b64":"AQID","iter":10000},
          "wrapped_account_key_b64":"explicit-wrap",
          "wrap_nonce_b64":"explicit-nonce"
        }"#,
    )])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    client.set_bearer_token("jwt-explicit");

    let credential = client.get_credential_wrap(Some("cred id/one"))?;

    assert_eq!(credential.kdf_params.iter, Some(10_000));
    assert_eq!(credential.wrapped_account_key_b64, "explicit-wrap");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials/cred%20id%2Fone/wrap "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_derives_awk_from_passphrase() -> tn_proto::Result<()> {
    let passphrase = "vault account passphrase";
    let salt = [21_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let awk = tn_proto::VaultAwk::new([22_u8; 32]);
    let wrapped = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[23_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let body = serde_json::json!([{
        "is_primary": true,
        "kdf": "pbkdf2-sha256",
        "kdf_params": {
            "salt_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                salt
            ),
            "iterations": 10000
        },
        "wrapped_account_key_b64": wrapped.wrapped_b64,
        "wrap_nonce_b64": wrapped.nonce_b64
    }])
    .to_string();
    let server = LocalHttpServer::start(vec![json_response(200, &body)])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    client.set_bearer_token("jwt-derive");

    let derived = client.derive_awk_from_passphrase(passphrase, None)?;

    assert_eq!(derived.as_bytes(), awk.as_bytes());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_derives_and_caches_account_awk() -> tn_proto::Result<()> {
    let passphrase = "vault account passphrase";
    let salt = [24_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let awk = tn_proto::VaultAwk::new([25_u8; 32]);
    let wrapped = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[26_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let body = serde_json::json!([{
        "is_primary": true,
        "kdf": "pbkdf2-sha256",
        "kdf_params": {
            "salt_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                salt
            ),
            "iterations": 10000
        },
        "wrapped_account_key_b64": wrapped.wrapped_b64,
        "wrap_nonce_b64": wrapped.nonce_b64
    }])
    .to_string();
    let server = LocalHttpServer::start(vec![json_response(200, &body)])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    client.set_bearer_token("jwt-cache");
    let temp = tempfile::tempdir()?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));

    let cached =
        tn_proto::cache_account_awk_with_client(&store, &client, "acct_cache", passphrase, None)?;

    assert_eq!(cached.as_bytes(), awk.as_bytes());
    assert_eq!(
        tn_proto::load_cached_account_awk(&store, "acct_cache")
            .expect("cached account AWK")
            .as_bytes(),
        awk.as_bytes()
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_rejects_ambiguous_or_malformed_credentials() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"[
                {"is_primary":true,"kdf":"pbkdf2-sha256","kdf_params":{"salt_b64":"AQID"},"wrapped_account_key_b64":"a","wrap_nonce_b64":"b"},
                {"is_primary":true,"kdf":"pbkdf2-sha256","kdf_params":{"salt_b64":"BAUG"},"wrapped_account_key_b64":"c","wrap_nonce_b64":"d"}
            ]"#,
        ),
        json_response(200, r#"[]"#),
        json_response(200, r#"{"not":"array"}"#),
        json_response(200, r#"{"kdf":"pbkdf2-sha256"}"#),
    ])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    client.set_bearer_token("jwt-bad");

    let err = client.get_credential_wrap(None).unwrap_err();
    assert!(err.to_string().contains("2 primary credentials"));

    let err = client.get_credential_wrap(None).unwrap_err();
    assert!(err.to_string().contains("no credentials"));

    let err = client.get_credential_wrap(None).unwrap_err();
    assert!(err.to_string().contains("expected array"));

    let err = client
        .get_credential_wrap(Some("missing-fields"))
        .unwrap_err();
    assert!(err.to_string().contains("invalid vault credential wrap"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_whole_body_awk_bek_routes() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"wrapped_bek_b64":"bek","wrap_nonce_b64":"nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        json_response(
            200,
            r#"{"wrapped_bek_b64":"bek","wrap_nonce_b64":"nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        json_response(200, r#"{"ciphertext_b64":"AAECAw","generation":2}"#),
        json_response(200, r#"{"ciphertext_b64":"BAUGBw","generation":3}"#),
    ])?;
    let client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;

    let wrapped = client.get_wrapped_key("proj 1/beta")?;
    let stored = client.put_wrapped_key(
        "proj 1/beta",
        serde_json::json!({
            "wrapped_bek_b64": "bek",
            "wrap_nonce_b64": "nonce"
        }),
    )?;
    let blob = client.get_encrypted_blob("proj 1/beta")?;
    let updated = client.put_encrypted_blob_account(
        "proj 1/beta",
        serde_json::json!({
            "ciphertext_b64": "BAUGBw",
            "generation": 3
        }),
        "*",
    )?;

    assert_eq!(
        wrapped
            .get("wrapped_bek_b64")
            .and_then(serde_json::Value::as_str),
        Some("bek")
    );
    assert_eq!(
        stored
            .get("cipher_suite")
            .and_then(serde_json::Value::as_str),
        Some("aes-256-gcm")
    );
    assert_eq!(
        blob.get("ciphertext_b64")
            .and_then(serde_json::Value::as_str),
        Some("AAECAw")
    );
    assert_eq!(
        updated
            .get("generation")
            .and_then(serde_json::Value::as_i64),
        Some(3)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj%201%2Fbeta/wrapped-key "));
    assert!(requests[1].starts_with("PUT /api/v1/projects/proj%201%2Fbeta/wrapped-key "));
    assert!(requests[1].contains(r#""cipher_suite":"aes-256-gcm""#));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj%201%2Fbeta/encrypted-blob "));
    assert!(requests[3].starts_with("PUT /api/v1/projects/proj%201%2Fbeta/encrypted-blob-account "));
    assert!(requests[3].contains("if-match: *"));
    assert!(requests
        .iter()
        .all(|request| request.contains("authorization: Bearer token-123")));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_http_client_uploads_collected_encrypted_body() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "push-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_123".to_string(),
        project_name: Some("push-demo".to_string()),
        record_audit_event: false,
    })?;
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"wrapped_bek_b64":"wrapped","wrap_nonce_b64":"nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        json_response(200, r#"{"generation":7,"etag":"etag-7"}"#),
    ])?;
    let client =
        tn_proto::VaultHttpProjectClient::with_options(tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: Some("token-123".to_string()),
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        })?;
    let bek = tn_proto::VaultBek::new([5_u8; 32]);
    let awk = tn_proto::VaultAwk::new([6_u8; 32]);
    let mut options = tn_proto::VaultPushBodyOptions::wrap_with_awk(bek.clone(), &awk)?;
    options.if_match = "*".to_string();

    let result = tn.vault().push_body_with_http_client(&client, options)?;

    assert_eq!(result.project_id, "proj_123");
    assert!(result.body_member_count >= 6);
    assert!(result.encrypted_len > 28);
    assert_eq!(
        result
            .wrapped_key_response
            .get("cipher_suite")
            .and_then(serde_json::Value::as_str),
        Some("aes-256-gcm")
    );
    assert_eq!(
        result
            .encrypted_blob_response
            .get("generation")
            .and_then(serde_json::Value::as_i64),
        Some(7)
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("PUT /api/v1/projects/proj_123/wrapped-key "));
    assert!(requests[0].contains(r#""cipher_suite":"aes-256-gcm""#));
    assert!(requests[1].starts_with("PUT /api/v1/projects/proj_123/encrypted-blob-account "));
    assert!(requests[1].contains("if-match: *"));
    assert!(requests
        .iter()
        .all(|request| request.contains("authorization: Bearer token-123")));

    let ciphertext_b64 = extract_json_string(&requests[1], "ciphertext_b64")
        .expect("encrypted body request should contain ciphertext_b64");
    let encrypted =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext_b64)
            .expect("ciphertext_b64 should decode");
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;
    assert!(decrypted.contains_key("body/tn.yaml"));
    assert!(decrypted.contains_key("body/keys/local.private"));
    assert!(decrypted.contains_key("body/keys/default.btn.state"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_awk_mints_bek_when_wrapped_key_missing() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "mint-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_mint".to_string(),
        project_name: Some("mint-demo".to_string()),
        record_audit_event: false,
    })?;
    let server = LocalHttpServer::start(vec![
        json_response(404, r#"{"error":"missing wrapped key"}"#),
        json_response(404, r#"{"error":"missing blob"}"#),
        json_response(
            200,
            r#"{"wrapped_bek_b64":"stored","wrap_nonce_b64":"stored_nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        json_response(200, r#"{"generation":1}"#),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let awk = tn_proto::VaultAwk::new([6_u8; 32]);

    let result = tn.vault().push_body_with_awk_http_client(
        &client,
        tn_proto::VaultPushWithAwkOptions::new(awk.clone()),
    )?;

    assert!(result.wrapped_key_created);
    assert_eq!(result.if_match, "*");
    assert_eq!(result.push.project_id, "proj_mint");
    assert_eq!(
        result
            .push
            .encrypted_blob_response
            .get("generation")
            .and_then(serde_json::Value::as_i64),
        Some(1)
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_mint/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_mint/encrypted-blob "));
    assert!(requests[2].starts_with("PUT /api/v1/projects/proj_mint/wrapped-key "));
    assert!(requests[3].starts_with("PUT /api/v1/projects/proj_mint/encrypted-blob-account "));
    assert!(requests[3].contains("if-match: *"));

    let wrapped_body = extract_json_value(&requests[2]).expect("wrapped-key request JSON");
    let wrapped = tn_proto::VaultWrappedBek::from_json(&wrapped_body)?;
    let bek = tn_proto::unwrap_bek_from_awk(&awk, &wrapped)?;
    let encrypted = decode_request_b64_field(&requests[3], "ciphertext_b64");
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;
    assert!(decrypted.contains_key("body/tn.yaml"));
    assert!(decrypted.contains_key("body/keys/local.private"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_awk_reuses_existing_wrapped_key() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "reuse-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_reuse".to_string(),
        project_name: Some("reuse-demo".to_string()),
        record_audit_event: false,
    })?;
    let awk = tn_proto::VaultAwk::new([7_u8; 32]);
    let bek = tn_proto::VaultBek::new([8_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[9_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":12}"#),
        json_response(200, r#"{"generation":13}"#),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let result = tn
        .vault()
        .push_body_with_awk_http_client(&client, tn_proto::VaultPushWithAwkOptions::new(awk))?;

    assert!(!result.wrapped_key_created);
    assert_eq!(result.if_match, "12");
    assert_eq!(result.push.project_id, "proj_reuse");
    assert_eq!(
        result
            .push
            .encrypted_blob_response
            .get("generation")
            .and_then(serde_json::Value::as_i64),
        Some(13)
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_reuse/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_reuse/encrypted-blob "));
    assert!(requests[2].starts_with("PUT /api/v1/projects/proj_reuse/encrypted-blob-account "));
    assert!(requests[2].contains("if-match: 12"));

    let encrypted = decode_request_b64_field(&requests[2], "ciphertext_b64");
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;
    assert!(decrypted.contains_key("body/tn.yaml"));
    assert!(decrypted.contains_key("body/keys/local.private"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_passphrase_derives_awk_and_uploads_body() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "passphrase-push-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_pass_push".to_string(),
        project_name: Some("passphrase-push-demo".to_string()),
        record_audit_event: false,
    })?;
    let passphrase = "push-passphrase";
    let awk = tn_proto::VaultAwk::new([30_u8; 32]);
    let salt = [31_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[32_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let credential_json = credential_wrap_list_json(&salt, &wrapped_awk);
    let server = LocalHttpServer::start(vec![
        json_response(200, &credential_json),
        json_response(404, r#"{"error":"missing wrapped key"}"#),
        json_response(404, r#"{"error":"missing blob"}"#),
        json_response(
            200,
            r#"{"wrapped_bek_b64":"stored","wrap_nonce_b64":"stored_nonce","cipher_suite":"aes-256-gcm"}"#,
        ),
        json_response(200, r#"{"generation":2}"#),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let result = tn.vault().push_body_with_passphrase_http_client(
        &client,
        passphrase,
        tn_proto::VaultPushWithPassphraseOptions::new(),
    )?;

    assert!(result.wrapped_key_created);
    assert_eq!(result.if_match, "*");
    assert_eq!(result.push.project_id, "proj_pass_push");
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_pass_push/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_pass_push/encrypted-blob "));
    assert!(requests[3].starts_with("PUT /api/v1/projects/proj_pass_push/wrapped-key "));
    assert!(requests[4].starts_with("PUT /api/v1/projects/proj_pass_push/encrypted-blob-account "));

    let wrapped_body = extract_json_value(&requests[3]).expect("wrapped-key request JSON");
    let wrapped = tn_proto::VaultWrappedBek::from_json(&wrapped_body)?;
    let bek = tn_proto::unwrap_bek_from_awk(&awk, &wrapped)?;
    let encrypted = decode_request_b64_field(&requests[4], "ciphertext_b64");
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;
    assert!(decrypted.contains_key("body/tn.yaml"));
    assert!(decrypted.contains_key("body/keys/local.private"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_cached_awk_uses_store_without_credential_fetch() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cached-push-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_cached_push".to_string(),
        project_name: Some("cached-push-demo".to_string()),
        record_audit_event: false,
    })?;
    let awk = tn_proto::VaultAwk::new([40_u8; 32]);
    let bek = tn_proto::VaultBek::new([41_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[42_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":20}"#),
        json_response(200, r#"{"generation":21}"#),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    store.set_account_awk("acct_cached", &awk)?;

    let result = tn.vault().push_body_with_cached_awk_http_client(
        &client,
        &store,
        tn_proto::VaultPushWithCachedAwkOptions::new("acct_cached"),
    )?;

    assert!(!result.wrapped_key_created);
    assert_eq!(result.if_match, "20");
    assert_eq!(result.push.project_id, "proj_cached_push");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_cached_push/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_cached_push/encrypted-blob "));
    assert!(
        requests[2].starts_with("PUT /api/v1/projects/proj_cached_push/encrypted-blob-account ")
    );
    assert!(!requests
        .iter()
        .any(|request| request.contains("/api/v1/account/credentials")));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_push_body_with_cached_awk_errors_without_cache_or_passphrase() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cached-push-error-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let client = tn_proto::VaultHttpProjectClient::new("http://127.0.0.1:9")?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));

    let err = tn
        .vault()
        .push_body_with_cached_awk_http_client(
            &client,
            &store,
            tn_proto::VaultPushWithCachedAwkOptions::new("acct_missing"),
        )
        .unwrap_err();

    assert!(err.to_string().contains("cached AWK not found"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_restore_body_with_awk_downloads_and_decrypts_body() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "restore-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_restore".to_string(),
        project_name: Some("restore-demo".to_string()),
        record_audit_event: false,
    })?;
    let awk = tn_proto::VaultAwk::new([10_u8; 32]);
    let bek = tn_proto::VaultBek::new([11_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[12_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.clone().into_json()).expect("wrapped json");
    let mut body = tn_proto::VaultBodyPlaintext::new();
    body.insert(
        "body/tn.yaml".to_string(),
        b"ceremony:\n  id: demo\n".to_vec(),
    );
    body.insert("body/keys/local.private".to_string(), vec![4_u8; 32]);
    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &[13_u8; 12])?;
    let encrypted_json = serde_json::json!({
        "ciphertext_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        ),
        "generation": 9
    })
    .to_string();
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, &encrypted_json),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let result = tn.vault().restore_body_with_awk_http_client(
        &client,
        tn_proto::VaultRestoreWithAwkOptions::new(awk),
    )?;

    assert_eq!(result.project_id, "proj_restore");
    assert_eq!(result.wrapped_key, wrapped);
    assert_eq!(result.body, body);
    assert_eq!(
        result
            .encrypted_blob_response
            .get("generation")
            .and_then(serde_json::Value::as_i64),
        Some(9)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_restore/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_restore/encrypted-blob "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_restore_body_with_cached_awk_derives_and_caches_on_miss() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "cached-restore-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_cached_restore".to_string(),
        project_name: Some("cached-restore-demo".to_string()),
        record_audit_event: false,
    })?;
    let passphrase = "restore-cache-passphrase";
    let awk = tn_proto::VaultAwk::new([43_u8; 32]);
    let bek = tn_proto::VaultBek::new([44_u8; 32]);
    let salt = [45_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[46_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let credential_json = credential_wrap_list_json(&salt, &wrapped_awk);
    let wrapped_bek = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[47_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped_bek.into_json()).expect("wrapped json");
    let mut body = tn_proto::VaultBodyPlaintext::new();
    body.insert(
        "body/tn.yaml".to_string(),
        b"ceremony:\n  id: cached\n".to_vec(),
    );
    body.insert("body/keys/local.private".to_string(), vec![4_u8; 32]);
    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &[48_u8; 12])?;
    let encrypted_json = serde_json::json!({
        "ciphertext_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        )
    })
    .to_string();
    let server = LocalHttpServer::start(vec![
        json_response(200, &credential_json),
        json_response(200, &wrapped_json),
        json_response(200, &encrypted_json),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    let mut options = tn_proto::VaultRestoreWithCachedAwkOptions::new("acct_restore");
    options.passphrase = Some(passphrase.to_string());

    let result = tn
        .vault()
        .restore_body_with_cached_awk_http_client(&client, &store, options)?;

    assert_eq!(result.project_id, "proj_cached_restore");
    assert_eq!(result.body, body);
    assert_eq!(
        store
            .get_account_awk("acct_restore")?
            .expect("derived AWK should be cached")
            .as_bytes(),
        awk.as_bytes()
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_cached_restore/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_cached_restore/encrypted-blob "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_restore_and_install_body_with_passphrase_downloads_and_writes_target(
) -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "passphrase-restore-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("restore-runtime")),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_pass_restore".to_string(),
        project_name: Some("passphrase-restore-demo".to_string()),
        record_audit_event: false,
    })?;
    let source = Tn::init_project_with_options(
        "passphrase-body-source",
        TnProjectOptions {
            project_dir: Some(temp.path().join("body-source")),
            ..Default::default()
        },
    )?;
    let body = source.vault().collect_body()?;
    let passphrase = "restore-passphrase";
    let awk = tn_proto::VaultAwk::new([33_u8; 32]);
    let bek = tn_proto::VaultBek::new([34_u8; 32]);
    let salt = [35_u8; 16];
    let credential_key = tn_proto::derive_credential_key_pbkdf2(passphrase, &salt, 10_000)?;
    let wrapped_awk = wrap_raw_with_nonce(
        &credential_key,
        awk.as_bytes(),
        &[36_u8; 12],
        tn_proto::VAULT_AWK_WRAP_AAD,
    )?;
    let credential_json = credential_wrap_list_json(&salt, &wrapped_awk);
    let wrapped_bek = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[37_u8; 12])?;
    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &[38_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped_bek.into_json()).expect("wrapped json");
    let encrypted_json = serde_json::json!({
        "ciphertext_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        )
    })
    .to_string();
    let server = LocalHttpServer::start(vec![
        json_response(200, &credential_json),
        json_response(200, &wrapped_json),
        json_response(200, &encrypted_json),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let target = temp.path().join("installed-passphrase");

    let result = tn
        .vault()
        .restore_and_install_body_with_passphrase_http_client(
            &client,
            passphrase,
            tn_proto::VaultRestoreWithPassphraseOptions::new(),
            tn_proto::VaultInstallBodyOptions::new(target.clone()),
        )?;

    assert_eq!(result.restore.project_id, "proj_pass_restore");
    assert_eq!(result.restore.body, body);
    assert_eq!(result.install.yaml_path, target.join("tn.yaml"));
    assert_eq!(std::fs::read(target.join("tn.yaml"))?, body["body/tn.yaml"]);
    assert_eq!(
        std::fs::read(target.join("keys").join("local.private"))?,
        body["body/keys/local.private"]
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/account/credentials?include=wrap "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_pass_restore/wrapped-key "));
    assert!(requests[2].starts_with("GET /api/v1/projects/proj_pass_restore/encrypted-blob "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_restore_and_install_body_with_awk_downloads_and_writes_target() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "restore-install-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("source")),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_restore_install".to_string(),
        project_name: Some("restore-install-demo".to_string()),
        record_audit_event: false,
    })?;
    let source = Tn::init_project_with_options(
        "body-source",
        TnProjectOptions {
            project_dir: Some(temp.path().join("body-source")),
            ..Default::default()
        },
    )?;
    let body = source.vault().collect_body()?;
    let awk = tn_proto::VaultAwk::new([14_u8; 32]);
    let bek = tn_proto::VaultBek::new([15_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[16_u8; 12])?;
    let encrypted = tn_proto::encrypt_vault_body_with_nonce(&body, &bek, &[17_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let encrypted_json = serde_json::json!({
        "ciphertext_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        )
    })
    .to_string();
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, &encrypted_json),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;
    let target = temp.path().join("installed");

    let result = tn.vault().restore_and_install_body_with_awk_http_client(
        &client,
        tn_proto::VaultRestoreWithAwkOptions::new(awk),
        tn_proto::VaultInstallBodyOptions::new(target.clone()),
    )?;

    assert_eq!(result.restore.project_id, "proj_restore_install");
    assert_eq!(result.restore.body, body);
    assert_eq!(result.install.yaml_path, target.join("tn.yaml"));
    assert_eq!(std::fs::read(target.join("tn.yaml"))?, body["body/tn.yaml"]);
    assert_eq!(
        std::fs::read(target.join("keys").join("local.private"))?,
        body["body/keys/local.private"]
    );
    assert!(result
        .install
        .written_paths
        .contains(&target.join("keys").join("local.public")));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_restore_install/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_restore_install/encrypted-blob "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_restore_body_with_awk_rejects_malformed_encrypted_blob() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "restore-bad-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().connect(VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_restore_bad".to_string(),
        project_name: Some("restore-bad-demo".to_string()),
        record_audit_event: false,
    })?;
    let awk = tn_proto::VaultAwk::new([10_u8; 32]);
    let bek = tn_proto::VaultBek::new([11_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[12_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":9}"#),
    ])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = tn
        .vault()
        .restore_body_with_awk_http_client(&client, tn_proto::VaultRestoreWithAwkOptions::new(awk))
        .unwrap_err();

    assert!(err.to_string().contains("missing ciphertext"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_on_malformed_whole_body_response() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(200, r#"[]"#)])?;
    let client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client.get_wrapped_key("proj_123").unwrap_err();

    assert!(err.to_string().contains("wrapped-key response"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_reuses_project_after_conflict() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(409, r#"{"error":"exists"}"#),
        json_response(
            200,
            r#"[{"id":"other","name":"other"},{"_id":"proj_existing","name":"demo-project"}]"#,
        ),
    ])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let project = client.ensure_project("demo-project", Some("local_123"))?;

    assert_eq!(project.id, "proj_existing");
    assert_eq!(project.name, "demo-project");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /api/v1/projects "));
    assert!(requests[1].starts_with("GET /api/v1/projects "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_when_conflict_has_no_match() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(409, r#"{"error":"exists"}"#),
        json_response(200, r#"[{"id":"other","name":"other"}]"#),
    ])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client
        .ensure_project("demo-project", Some("local_123"))
        .unwrap_err();

    assert!(err.to_string().contains("returned 409"));
    assert!(err.to_string().contains("no match"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_on_malformed_project_json() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(201, r#"{"name":"demo-project"}"#)])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client
        .ensure_project("demo-project", Some("local_123"))
        .unwrap_err();

    assert!(err.to_string().contains("missing id"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_authenticates_identity() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(200, r#"{"nonce":"nonce-123"}"#),
        json_response(200, r#"{"token":"jwt-123"}"#),
    ])?;
    let seed = [7_u8; 32];
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&seed)?;
    let device = tn_core::DeviceKey::from_private_bytes(&seed)?;
    let expected_signature = tn_core::signing::signature_b64(&device.sign(b"nonce-123"));
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let token = client.authenticate(&identity)?;

    assert_eq!(token, "jwt-123");
    assert_eq!(client.bearer_token(), Some("jwt-123"));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /api/v1/auth/challenge "));
    assert!(!requests[0].contains("authorization: Bearer"));
    assert!(requests[0].contains(&format!(r#""did":"{}""#, device.did())));
    assert!(requests[1].starts_with("POST /api/v1/auth/verify "));
    assert!(!requests[1].contains("authorization: Bearer"));
    assert!(requests[1].contains(&format!(r#""did":"{}""#, device.did())));
    assert!(requests[1].contains(r#""nonce":"nonce-123""#));
    assert!(requests[1].contains(&format!(r#""signature":"{expected_signature}""#)));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_for_identity_skips_auth_with_token() -> tn_proto::Result<()> {
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&[8_u8; 32])?;

    let client = tn_proto::VaultHttpProjectClient::for_identity(
        &identity,
        tn_proto::VaultHttpProjectClientOptions {
            base_url: "http://127.0.0.1:1".to_string(),
            bearer_token: Some("existing-token".to_string()),
            timeout: std::time::Duration::from_millis(50),
            user_agent: None,
        },
    )?;

    assert_eq!(client.bearer_token(), Some("existing-token"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_uses_authenticated_token_for_projects() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(200, r#"{"nonce":"nonce-123"}"#),
        json_response(200, r#"{"token":"jwt-123"}"#),
        json_response(
            201,
            r#"{"id":"proj_http","name":"demo-project","ceremony_id":"local_123"}"#,
        ),
    ])?;
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&[9_u8; 32])?;
    let mut client = tn_proto::VaultHttpProjectClient::for_identity(
        &identity,
        tn_proto::VaultHttpProjectClientOptions {
            base_url: server.base_url(),
            bearer_token: None,
            timeout: std::time::Duration::from_secs(5),
            user_agent: Some("tn-proto-test".to_string()),
        },
    )?;

    let project = client.ensure_project("demo-project", Some("local_123"))?;

    assert_eq!(project.id, "proj_http");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].starts_with("POST /api/v1/projects "));
    assert!(requests[2].contains("authorization: Bearer jwt-123"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_connect_http_authenticates_creates_project_and_connects() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![
        json_response(200, r#"{"nonce":"nonce-123"}"#),
        json_response(200, r#"{"token":"jwt-123"}"#),
        json_response(
            201,
            r#"{"id":"proj_http","name":"demo-project","ceremony_id":"local_123"}"#,
        ),
    ])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&[11_u8; 32])?;
    let base_url = server.base_url();

    let result = tn
        .vault()
        .connect_http(&identity, tn_proto::VaultHttpConnectOptions::new(&base_url))?;

    assert!(result.newly_linked);
    assert!(result.audit_event_recorded);
    assert_eq!(result.vault, base_url);
    assert_eq!(result.project_id, "proj_http");
    assert_eq!(result.project_name.as_deref(), Some("demo-project"));
    assert_eq!(result.state.state, VaultLinkState::Linked);
    assert_eq!(
        result.state.linked_vault.as_deref(),
        Some(result.vault.as_str())
    );
    assert_eq!(result.state.linked_project_id.as_deref(), Some("proj_http"));
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST /api/v1/auth/challenge "));
    assert!(requests[1].starts_with("POST /api/v1/auth/verify "));
    assert!(requests[2].starts_with("POST /api/v1/projects "));
    assert!(requests[2].contains("authorization: Bearer jwt-123"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_connect_http_is_idempotent_without_network_call() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(Vec::new())?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let base_url = server.base_url();
    tn.vault()
        .connect(VaultConnectOptions::new(&base_url, "proj_existing"))?;
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&[12_u8; 32])?;

    let result = tn.vault().connect_http(
        &identity,
        tn_proto::VaultHttpConnectOptions {
            project_name: Some("explicit-name".to_string()),
            ..tn_proto::VaultHttpConnectOptions::new(&base_url)
        },
    )?;

    assert!(!result.newly_linked);
    assert!(!result.audit_event_recorded);
    assert_eq!(result.project_id, "proj_existing");
    assert_eq!(result.project_name.as_deref(), Some("explicit-name"));
    assert!(server.requests().is_empty());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn vault_http_project_client_errors_on_malformed_challenge_json() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(200, r#"{"not_nonce":"nope"}"#)])?;
    let identity = tn_proto::VaultDeviceIdentity::from_private_bytes(&[10_u8; 32])?;
    let mut client = tn_proto::VaultHttpProjectClient::new(server.base_url())?;

    let err = client.authenticate(&identity).unwrap_err();

    assert!(err.to_string().contains("missing nonce"));
    assert_eq!(client.bearer_token(), None);

    Ok(())
}

#[test]
fn vault_set_link_state_unlinks_project_yaml() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    tn.vault().set_link_state(
        VaultLinkState::Linked,
        SetLinkStateOptions {
            linked_vault: Some("https://vault.example".to_string()),
            linked_project_id: Some("proj_123".to_string()),
        },
    )?;
    let result = tn
        .vault()
        .set_link_state(VaultLinkState::Local, SetLinkStateOptions::default())?;

    assert_eq!(result.state, VaultLinkState::Local);
    assert_eq!(result.linked_vault, None);
    assert_eq!(result.linked_project_id, None);
    let state = tn.vault().link_state()?;
    assert_eq!(state.state, VaultLinkState::Local);
    assert_eq!(state.linked_vault, None);
    assert_eq!(state.linked_project_id, None);
    assert!(!state.vault_enabled);
    assert!(!state.autosync);

    let yaml = read_yaml(tn.yaml_path())?;
    assert_eq!(yaml_get_str(&yaml, &["ceremony", "mode"]), Some("local"));
    assert!(yaml_get(&yaml, &["ceremony", "linked_vault"]).is_none());
    assert!(yaml_get(&yaml, &["ceremony", "linked_project_id"]).is_none());
    assert_eq!(yaml_get_bool(&yaml, &["vault", "enabled"]), Some(false));
    assert_eq!(yaml_get_str(&yaml, &["vault", "url"]), Some(""));
    assert_eq!(
        yaml_get_str(&yaml, &["vault", "linked_project_id"]),
        Some("")
    );
    assert_eq!(yaml_get_bool(&yaml, &["vault", "autosync"]), Some(false));
    assert_eq!(
        yaml_get_i64(&yaml, &["vault", "sync_interval_seconds"]),
        Some(600)
    );

    Ok(())
}

#[test]
fn vault_set_link_state_requires_vault_when_linking() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let err = tn
        .vault()
        .set_link_state(VaultLinkState::Linked, SetLinkStateOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("linked mode requires"));

    let yaml = read_yaml(tn.yaml_path())?;
    assert_eq!(yaml_get_str(&yaml, &["ceremony", "mode"]), Some("local"));
    assert_eq!(yaml_get_bool(&yaml, &["vault", "enabled"]), Some(false));

    Ok(())
}

#[test]
fn vault_set_link_state_rejects_different_active_vault() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    tn.vault().set_link_state(
        VaultLinkState::Linked,
        SetLinkStateOptions {
            linked_vault: Some("https://vault-a.example".to_string()),
            linked_project_id: Some("proj_a".to_string()),
        },
    )?;
    let err = tn
        .vault()
        .set_link_state(
            VaultLinkState::Linked,
            SetLinkStateOptions {
                linked_vault: Some("https://vault-b.example".to_string()),
                linked_project_id: Some("proj_b".to_string()),
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("already linked"));

    let yaml = read_yaml(tn.yaml_path())?;
    assert_eq!(
        yaml_get_str(&yaml, &["vault", "url"]),
        Some("https://vault-a.example")
    );
    assert_eq!(
        yaml_get_str(&yaml, &["vault", "linked_project_id"]),
        Some("proj_a")
    );

    Ok(())
}

#[test]
fn vault_set_link_state_updates_extends_parent_yaml() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let project = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let project_yaml_path = project.yaml_path().to_path_buf();
    let stream_path = temp
        .path()
        .join(".tn")
        .join("demo-project")
        .join("streams")
        .join("vault-stream.yaml");
    std::fs::write(&stream_path, "extends: ../tn.yaml\n")?;
    project.close()?;

    let stream = Tn::init(&stream_path)?;
    let result = stream.vault().set_link_state(
        VaultLinkState::Linked,
        SetLinkStateOptions {
            linked_vault: Some("https://vault.example".to_string()),
            linked_project_id: Some("proj_123".to_string()),
        },
    )?;

    assert_eq!(
        normalize_path(&result.yaml_path),
        normalize_path(&project_yaml_path)
    );
    let project_yaml = read_yaml(&project_yaml_path)?;
    let stream_yaml = read_yaml(&stream_path)?;
    assert_eq!(
        yaml_get_str(&project_yaml, &["vault", "url"]),
        Some("https://vault.example")
    );
    assert!(yaml_get(&stream_yaml, &["vault"]).is_none());

    let state = stream.vault().link_state()?;
    assert_eq!(
        normalize_path(&state.yaml_path),
        normalize_path(&project_yaml_path)
    );
    assert_eq!(state.state, VaultLinkState::Linked);
    assert_eq!(state.linked_vault.as_deref(), Some("https://vault.example"));
    assert_eq!(state.linked_project_id.as_deref(), Some("proj_123"));

    Ok(())
}

#[test]
fn vault_link_state_rejects_unknown_yaml_mode() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "demo-project",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let mut yaml = read_yaml(tn.yaml_path())?;
    yaml.as_mapping_mut()
        .unwrap()
        .get_mut(YamlValue::String("ceremony".to_string()))
        .unwrap()
        .as_mapping_mut()
        .unwrap()
        .insert(
            YamlValue::String("mode".to_string()),
            YamlValue::String("somewhere-else".to_string()),
        );
    std::fs::write(tn.yaml_path(), serde_yml::to_string(&yaml)?)?;

    let err = tn.vault().link_state().unwrap_err();
    assert!(err.to_string().contains("ceremony.mode must be"));

    Ok(())
}

fn read_yaml(path: &Path) -> tn_proto::Result<YamlValue> {
    let yaml_text = std::fs::read_to_string(path)?;
    Ok(serde_yml::from_str(&yaml_text)?)
}

#[derive(Debug)]
struct FakeVaultProjectClient {
    base_url: String,
    calls: Vec<(String, Option<String>)>,
    error: Option<String>,
}

impl FakeVaultProjectClient {
    fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            calls: Vec::new(),
            error: None,
        }
    }
}

impl VaultProjectClient for FakeVaultProjectClient {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn ensure_project(
        &mut self,
        name: &str,
        ceremony_id: Option<&str>,
    ) -> tn_proto::Result<VaultProject> {
        self.calls
            .push((name.to_string(), ceremony_id.map(ToOwned::to_owned)));
        if let Some(error) = &self.error {
            return Err(Error::InvalidArgument(error.clone()));
        }
        Ok(VaultProject {
            id: format!("proj_{}", self.calls.len()),
            name: name.to_string(),
            ceremony_id: ceremony_id.map(ToOwned::to_owned),
        })
    }
}

#[cfg(feature = "http")]
struct LocalHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

#[cfg(feature = "http")]
impl LocalHttpServer {
    fn start(responses: Vec<String>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let request = read_http_request(&mut stream);
                thread_requests.lock().unwrap().push(request);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Ok(Self {
            base_url,
            requests,
            handle: Some(handle),
        })
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn requests(&self) -> Vec<String> {
        std::thread::sleep(std::time::Duration::from_millis(25));
        self.requests.lock().unwrap().clone()
    }
}

#[cfg(feature = "http")]
impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(feature = "http")]
fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];

    loop {
        let n = stream.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
        if http_request_complete(&data) {
            break;
        }
    }

    String::from_utf8_lossy(&data).to_string()
}

#[cfg(feature = "http")]
fn http_request_complete(data: &[u8]) -> bool {
    let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&data[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    data.len() >= header_end + 4 + content_length
}

#[cfg(feature = "http")]
fn json_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        409 => "Conflict",
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(feature = "http")]
fn binary_response(status: u16, body: &[u8]) -> String {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        _ => "Status",
    };
    let body = String::from_utf8_lossy(body);
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(feature = "http")]
fn extract_json_string(request: &str, key: &str) -> Option<String> {
    let value = extract_json_value(request)?;
    value.get(key)?.as_str().map(ToOwned::to_owned)
}

#[cfg(feature = "http")]
fn extract_json_value(request: &str) -> Option<serde_json::Value> {
    let (_, body) = request.split_once("\r\n\r\n")?;
    serde_json::from_str::<serde_json::Value>(body).ok()
}

#[cfg(feature = "http")]
fn decode_request_b64_field(request: &str, key: &str) -> Vec<u8> {
    let value = extract_json_string(request, key).expect("request JSON string field");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .expect("request base64 field should decode")
}

fn normalize_path(path: &Path) -> std::path::PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn yaml_get_str<'a>(value: &'a YamlValue, path: &[&str]) -> Option<&'a str> {
    yaml_get(value, path).and_then(YamlValue::as_str)
}

fn yaml_get_bool(value: &YamlValue, path: &[&str]) -> Option<bool> {
    yaml_get(value, path).and_then(YamlValue::as_bool)
}

fn yaml_get_i64(value: &YamlValue, path: &[&str]) -> Option<i64> {
    yaml_get(value, path).and_then(YamlValue::as_i64)
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
