use tn_proto::{Tn, TnProjectOptions};

#[cfg(feature = "http")]
use std::io::{Read, Write};
#[cfg(feature = "http")]
use std::net::TcpListener;
#[cfg(feature = "http")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "http")]
use std::thread;
#[cfg(feature = "http")]
use tn_proto::{
    VaultHttpProjectClient, VaultHttpProjectClientOptions, WalletPublishGroupKeysOptions,
    WalletStageInboxOptions, WalletSyncOptions,
};

#[test]
fn wallet_paths_match_python_typescript_stem_convention() {
    let yaml = std::path::Path::new("/workspace/.tn/payments/tn.yaml");

    let paths = tn_proto::wallet_paths(yaml);

    assert_eq!(
        paths.stem_dir,
        std::path::Path::new("/workspace/.tn/payments/.tn/tn")
    );
    assert_eq!(
        paths.inbox_dir,
        std::path::Path::new("/workspace/.tn/payments/.tn/tn/inbox")
    );
    assert_eq!(
        paths.sync_state_path,
        std::path::Path::new("/workspace/.tn/payments/.tn/tn/sync/state.json")
    );
    assert_eq!(tn_proto::inbox_dir(yaml), paths.inbox_dir);
    assert_eq!(
        tn_proto::wallet_sync_state_path(yaml),
        paths.sync_state_path
    );
}

#[test]
fn safe_path_segment_sanitizes_dids_and_rejects_traversal() {
    assert_eq!(
        tn_proto::safe_path_segment("did:key:zabc"),
        Some("did_key_zabc".to_string())
    );
    assert_eq!(
        tn_proto::safe_path_segment("did:web:example.com:team/project"),
        Some("did_web_example.com_team_project".to_string())
    );
    assert_eq!(tn_proto::safe_path_segment(""), None);
    assert_eq!(tn_proto::safe_path_segment("."), None);
    assert_eq!(tn_proto::safe_path_segment(".."), None);
    assert_eq!(tn_proto::safe_path_segment("../escape"), None);
    assert_eq!(tn_proto::safe_path_segment("..\u{0}escape"), None);
}

#[test]
fn wallet_account_bound_state_is_best_effort() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let yaml = temp.path().join("tn.yaml");

    assert!(!tn_proto::wallet_is_account_bound(&yaml));

    let state_path = tn_proto::wallet_sync_state_path(&yaml);
    std::fs::create_dir_all(state_path.parent().unwrap())?;
    std::fs::write(&state_path, "not json")?;
    assert!(!tn_proto::wallet_is_account_bound(&yaml));

    std::fs::write(&state_path, r#"{"account_bound":false}"#)?;
    assert!(!tn_proto::wallet_is_account_bound(&yaml));

    std::fs::write(&state_path, r#"{"account_bound":true,"other":"kept"}"#)?;
    assert!(tn_proto::wallet_is_account_bound(&yaml));

    Ok(())
}

#[test]
fn wallet_namespace_exposes_paths_for_active_tn() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let paths = tn.wallet().paths();

    assert_eq!(paths, tn_proto::wallet_paths(tn.yaml_path()));
    assert_eq!(tn.wallet().inbox_dir(), paths.inbox_dir);
    assert!(!tn.wallet().is_account_bound());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_stage_account_inbox_stages_valid_packages_into_sanitized_paths() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"team/payments","ts":"2026-06-26T12:00:00Z","consumed_at":null}]}"#,
        ),
        binary_response(200, b"package-one"),
    ])?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;

    assert_eq!(result.skipped, 0);
    assert!(!result.not_bound);
    assert!(!result.unauthorized);
    assert_eq!(result.staged_paths.len(), 1);
    let staged_path = &result.staged_paths[0];
    assert_eq!(std::fs::read(staged_path)?, b"package-one");
    assert!(staged_path.ends_with(
        std::path::Path::new("did_key_zPublisher")
            .join("team_payments")
            .join("2026-06-26T12_00_00Z.tnpkg")
    ));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/account/inbox "));
    assert!(requests[1].starts_with(
        "GET /api/v1/account/inbox/did%3Akey%3AzPublisher/team%2Fpayments/2026-06-26T12%3A00%3A00Z.tnpkg "
    ));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_stage_account_inbox_skips_existing_consumed_and_stale_items() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;

    let existing = tn
        .wallet()
        .inbox_dir()
        .join("did_key_zPublisher")
        .join("existing")
        .join("2026-06-26T12_00_00Z.tnpkg");
    std::fs::create_dir_all(existing.parent().unwrap())?;
    std::fs::write(&existing, b"already-here")?;

    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"items":[
                {"publisher_identity":"did:key:zPublisher","ceremony_id":"existing","ts":"2026-06-26T12:00:00Z"},
                {"publisher_identity":"did:key:zPublisher","ceremony_id":"consumed","ts":"2026-06-26T12:01:00Z","consumed_at":"2026-06-26T12:02:00Z"},
                {"publisher_identity":"did:key:zPublisher","ceremony_id":"gone","ts":"2026-06-26T12:03:00Z"},
                {"publisher_identity":"did:key:zPublisher","ceremony_id":"missing","ts":"2026-06-26T12:04:00Z"},
                {"publisher_identity":"did:key:zPublisher","ceremony_id":"fresh","ts":"2026-06-26T12:05:00Z"}
            ]}"#,
        ),
        json_response(410, r#"{"error":"gone"}"#),
        json_response(404, r#"{"error":"missing"}"#),
        binary_response(200, b"fresh-package"),
    ])?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;

    assert_eq!(result.skipped, 4);
    assert_eq!(result.staged_paths.len(), 1);
    assert_eq!(std::fs::read(&existing)?, b"already-here");
    assert_eq!(std::fs::read(&result.staged_paths[0])?, b"fresh-package");
    assert_eq!(server.requests().len(), 4);

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_stage_account_inbox_rejects_malicious_path_segments() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let server = LocalHttpServer::start(vec![json_response(
        200,
        r#"{"items":[{"publisher_identity":"../escape","ceremony_id":"ceremony","ts":"2026-06-26T12:00:00Z"}]}"#,
    )])?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;

    assert_eq!(result.skipped, 1);
    assert!(result.staged_paths.is_empty());
    assert_eq!(server.requests().len(), 1);
    assert!(!temp.path().join("escape").exists());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_stage_account_inbox_returns_not_bound_without_network() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let server = LocalHttpServer::start(Vec::new())?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;

    assert!(result.not_bound);
    assert!(result.staged_paths.is_empty());
    assert_eq!(result.skipped, 0);
    assert!(server.requests().is_empty());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_stage_account_inbox_returns_unauthorized_nonfatally() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let server = LocalHttpServer::start(vec![json_response(403, r#"{"error":"forbidden"}"#)])?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;

    assert!(result.unauthorized);
    assert!(result.staged_paths.is_empty());
    assert_eq!(result.skipped, 0);
    assert_eq!(server.requests().len(), 1);

    Ok(())
}

#[test]
fn wallet_absorb_staged_packages_counts_valid_duplicate_and_malformed() -> tn_proto::Result<()> {
    let mut producer = Tn::ephemeral()?;
    producer.admin().ensure_group("payments", ["order_id"])?;
    producer.info(
        "payment.created",
        serde_json::json!({ "order_id": "WALLET-1" }),
    )?;
    let producer_dir = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent");
    let exported = producer_dir.join("admin-snapshot.tnpkg");
    producer.pkg().export_admin_snapshot(&exported)?;

    let consumer = Tn::ephemeral()?;
    let inbox = consumer
        .wallet()
        .inbox_dir()
        .join("did_key_zPublisher")
        .join("payments");
    std::fs::create_dir_all(&inbox)?;
    let staged = inbox.join("2026-06-26T12_00_00Z.tnpkg");
    std::fs::copy(&exported, &staged)?;
    let malformed = inbox.join("2026-06-26T12_01_00Z.tnpkg");
    std::fs::write(&malformed, b"not a tnpkg archive")?;

    let first = consumer.wallet().absorb_staged_packages()?;
    assert_eq!(first.absorbed, 1);
    assert_eq!(first.no_op, 0);
    assert_eq!(first.rejected, 1);
    assert_eq!(first.stashed, 0);
    assert_eq!(first.warnings.len(), 1);
    assert!(staged.exists());
    assert!(malformed.exists());

    let second = consumer.wallet().absorb_staged_packages()?;
    assert_eq!(second.absorbed, 0);
    assert_eq!(second.no_op, 1);
    assert_eq!(second.rejected, 1);
    assert_eq!(second.stashed, 0);

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_pull_and_absorb_composes_staging_with_absorb_counts() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "payments",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"payments","ts":"2026-06-26T12:00:00Z"}]}"#,
        ),
        binary_response(200, b"not a tnpkg archive"),
    ])?;
    let client = vault_client(server.base_url())?;

    let result = tn
        .wallet()
        .pull_and_absorb(&client, WalletStageInboxOptions::default())?;

    assert_eq!(result.staged.staged_paths.len(), 1);
    assert_eq!(result.absorbed, 0);
    assert_eq!(result.no_op, 0);
    assert_eq!(result.stashed, 0);
    assert_eq!(result.rejected, 1);
    assert_eq!(result.warnings.len(), 1);
    assert!(result.staged.staged_paths[0].exists());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_push_body_with_cached_awk_uses_cached_key_without_credential_fetch(
) -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-push-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    tn.info(
        "wallet.push.ready",
        serde_json::json!({ "order_id": "PUSH-1" }),
    )?;
    tn.vault().connect(tn_proto::VaultConnectOptions {
        vault: "http://vault.test".to_string(),
        project_id: "proj_wallet_push".to_string(),
        project_name: Some("wallet-push-demo".to_string()),
        record_audit_event: false,
    })?;
    let awk = tn_proto::VaultAwk::new([70_u8; 32]);
    let bek = tn_proto::VaultBek::new([71_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[72_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":8}"#),
        json_response(200, r#"{"generation":9}"#),
    ])?;
    let client = vault_client(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    store.set_account_awk("acct_wallet", &awk)?;

    let result = tn.wallet().push_body_with_cached_awk(
        &client,
        &store,
        tn_proto::VaultPushWithCachedAwkOptions::new("acct_wallet"),
    )?;

    assert!(!result.wrapped_key_created);
    assert_eq!(result.if_match, "8");
    assert_eq!(result.push.project_id, "proj_wallet_push");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_wallet_push/wrapped-key "));
    assert!(requests[1].starts_with("GET /api/v1/projects/proj_wallet_push/encrypted-blob "));
    assert!(
        requests[2].starts_with("PUT /api/v1/projects/proj_wallet_push/encrypted-blob-account ")
    );
    assert!(!requests
        .iter()
        .any(|request| request.contains("/api/v1/account/credentials")));

    let encrypted = decode_request_b64_field(&requests[2], "ciphertext_b64");
    let decrypted = tn_proto::decrypt_vault_body(&encrypted, &bek)?;
    assert!(decrypted.contains_key("body/tn.yaml"));
    assert!(decrypted.contains_key("body/keys/local.private"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_push_body_with_cached_awk_errors_without_cache_or_passphrase() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-push-error-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let client = vault_client("http://127.0.0.1:9".to_string())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));

    let err = tn
        .wallet()
        .push_body_with_cached_awk(
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
fn wallet_publish_group_keys_posts_self_addressed_snapshot() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut tn = Tn::init_project_with_options(
        "wallet-group-keys",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    tn.admin().ensure_group("payments", ["order_id"])?;
    let response = serde_json::json!({
        "stored_path": "/stored/group-keys.tnpkg",
        "byte_size": 123,
        "manifest_signature_b64": "sig-group-keys",
        "head_row_hash": null,
    });
    let server = LocalHttpServer::start(vec![json_response(201, &response.to_string())])?;
    let client = vault_client(server.base_url())?;

    let result = tn.wallet().publish_group_keys(
        &client,
        WalletPublishGroupKeysOptions {
            groups: Some(vec!["payments".to_string()]),
            ts: Some("20260626T213000000000Z".to_string()),
        },
    )?;

    assert_eq!(result.published_groups, vec!["payments".to_string()]);
    assert_eq!(
        result
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.manifest_signature_b64.as_str()),
        Some("sig-group-keys")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let expected_prefix = format!(
        "POST /api/v1/inbox/{}/snapshots/local_",
        percent_encode_path_segment(tn.did())
    );
    assert!(requests[0].starts_with(&expected_prefix), "{}", requests[0]);
    assert!(
        requests[0].contains("/20260626T213000000000Z.tnpkg "),
        "{}",
        requests[0]
    );
    assert!(requests[0].contains("content-type: application/octet-stream"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_publish_group_keys_returns_empty_when_no_requested_groups_match() -> tn_proto::Result<()>
{
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-group-keys-empty",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let server = LocalHttpServer::start(Vec::new())?;
    let client = vault_client(server.base_url())?;

    let result = tn.wallet().publish_group_keys(
        &client,
        WalletPublishGroupKeysOptions {
            groups: Some(vec!["missing".to_string()]),
            ts: Some("20260626T213000000000Z".to_string()),
        },
    )?;

    assert!(result.published_groups.is_empty());
    assert!(result.snapshot.is_none());
    assert!(server.requests().is_empty());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_sync_pull_only_stages_without_absorbing_or_pushing() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-sync-pull-only",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"sync","ts":"2026-06-26T12:00:00Z"}]}"#,
        ),
        binary_response(200, b"not a tnpkg archive"),
    ])?;
    let client = vault_client(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));

    let result = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            pull_only: true,
            ..Default::default()
        },
    )?;

    assert_eq!(result.staged, 1);
    assert_eq!(result.absorbed, 0);
    assert_eq!(result.rejected, 0);
    assert!(!result.pushed);
    assert!(result.account_bound);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/account/inbox "));
    assert!(requests[1].starts_with("GET /api/v1/account/inbox/"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_sync_pull_only_preserves_unknown_sync_state_and_records_summary() -> tn_proto::Result<()>
{
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-sync-state",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let state_path = tn_proto::wallet_sync_state_path(tn.yaml_path());
    std::fs::create_dir_all(state_path.parent().unwrap())?;
    std::fs::write(
        &state_path,
        serde_json::json!({
            "account_bound": true,
            "account_id": "acct_sync_state",
            "inbox_cursor": "cursor-kept",
            "pending_claims_cursor": "pending-kept",
            "custom_future_field": { "kept": true }
        })
        .to_string(),
    )?;
    let server = LocalHttpServer::start(vec![json_response(200, r#"{"items":[]}"#)])?;
    let client = vault_client(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));

    let result = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            pull_only: true,
            ..Default::default()
        },
    )?;

    assert_eq!(result.staged, 0);
    assert_eq!(result.skipped, 0);
    assert!(!result.pushed);
    assert!(result.account_bound);
    assert_eq!(result.account_id.as_deref(), Some("acct_sync_state"));

    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path)?)?;
    assert_eq!(state["account_bound"], true);
    assert_eq!(state["account_id"], "acct_sync_state");
    assert_eq!(state["inbox_cursor"], "cursor-kept");
    assert_eq!(state["pending_claims_cursor"], "pending-kept");
    assert_eq!(state["custom_future_field"]["kept"], true);
    assert_eq!(state["last_wallet_sync"]["staged"], 0);
    assert_eq!(state["last_wallet_sync"]["pushed"], false);
    assert_eq!(state["last_wallet_sync"]["account_bound"], true);
    assert_eq!(state["last_wallet_sync"]["account_id"], "acct_sync_state");
    assert!(state["last_wallet_sync_at"].as_str().is_some());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_sync_options_debug_redacts_passphrase() {
    let options = WalletSyncOptions {
        passphrase: Some("correct horse battery staple".to_string()),
        credential_id: Some("cred_123".to_string()),
        ..Default::default()
    };

    let debug = format!("{options:?}");

    assert!(!debug.contains("correct horse battery staple"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("cred_123"));
}

#[cfg(feature = "http")]
#[test]
fn wallet_sync_push_only_skips_pull_and_absorb() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-sync-push-only",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let awk = tn_proto::VaultAwk::new([80_u8; 32]);
    let bek = tn_proto::VaultBek::new([81_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[82_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":11}"#),
        json_response(200, r#"{"generation":12}"#),
    ])?;
    let client = vault_client(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    store.set_account_awk("acct_sync_push", &awk)?;

    let result = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            push_only: true,
            account_id: Some("acct_sync_push".to_string()),
            project_id: Some("proj_sync_push".to_string()),
            ..Default::default()
        },
    )?;

    assert_eq!(result.staged, 0);
    assert_eq!(result.absorbed, 0);
    assert!(result.pushed);
    assert!(!result.account_bound);
    assert_eq!(result.account_id, None);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(!requests
        .iter()
        .any(|request| request.contains("/api/v1/account/inbox")));
    assert!(requests[0].starts_with("GET /api/v1/projects/proj_sync_push/wrapped-key "));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn wallet_sync_default_pulls_absorbs_then_pushes() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "wallet-sync-default",
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    write_account_bound_state(tn.yaml_path())?;
    let awk = tn_proto::VaultAwk::new([90_u8; 32]);
    let bek = tn_proto::VaultBek::new([91_u8; 32]);
    let wrapped = tn_proto::wrap_bek_under_awk_with_nonce(&awk, &bek, &[92_u8; 12])?;
    let wrapped_json = serde_json::to_string(&wrapped.into_json()).expect("wrapped json");
    let server = LocalHttpServer::start(vec![
        json_response(
            200,
            r#"{"items":[{"publisher_identity":"did:key:zPublisher","ceremony_id":"sync","ts":"2026-06-26T12:00:00Z"}]}"#,
        ),
        binary_response(200, b"not a tnpkg archive"),
        json_response(
            201,
            r#"{"stored_path":"/stored/group-keys.tnpkg","byte_size":123,"manifest_signature_b64":"sig-group-keys","head_row_hash":null}"#,
        ),
        json_response(200, &wrapped_json),
        json_response(200, r#"{"generation":21}"#),
        json_response(200, r#"{"generation":22}"#),
    ])?;
    let client = vault_client(server.base_url())?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    store.set_account_awk("acct_sync_default", &awk)?;

    let result = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            account_id: Some("acct_sync_default".to_string()),
            project_id: Some("proj_sync_default".to_string()),
            ..Default::default()
        },
    )?;

    assert_eq!(result.staged, 1);
    assert_eq!(result.absorbed, 0);
    assert_eq!(result.rejected, 1);
    assert_eq!(result.published_groups, vec!["default".to_string()]);
    assert!(result.pushed);
    assert!(result.account_bound);
    assert_eq!(result.warnings.len(), 1);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert!(requests[0].starts_with("GET /api/v1/account/inbox "));
    assert!(requests[1].starts_with("GET /api/v1/account/inbox/"));
    assert!(requests[2].starts_with("POST /api/v1/inbox/"));
    assert!(requests[2].contains("/snapshots/local_"));
    assert!(requests[3].starts_with("GET /api/v1/projects/proj_sync_default/wrapped-key "));
    assert!(requests[4].starts_with("GET /api/v1/projects/proj_sync_default/encrypted-blob "));
    assert!(
        requests[5].starts_with("PUT /api/v1/projects/proj_sync_default/encrypted-blob-account ")
    );

    Ok(())
}

#[cfg(feature = "http")]
fn write_account_bound_state(yaml_path: &std::path::Path) -> tn_proto::Result<()> {
    let state_path = tn_proto::wallet_sync_state_path(yaml_path);
    std::fs::create_dir_all(state_path.parent().unwrap())?;
    std::fs::write(state_path, r#"{"account_bound":true}"#)?;
    Ok(())
}

#[cfg(feature = "http")]
fn vault_client(base_url: String) -> tn_proto::Result<VaultHttpProjectClient> {
    let mut options = VaultHttpProjectClientOptions::new(base_url);
    options.bearer_token = Some("test-token".to_string());
    VaultHttpProjectClient::with_options(options)
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
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
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
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
}

#[cfg(feature = "http")]
fn extract_json_value(request: &str) -> Option<serde_json::Value> {
    let (_, body) = request.split_once("\r\n\r\n")?;
    serde_json::from_str::<serde_json::Value>(body).ok()
}

#[cfg(feature = "http")]
fn extract_json_string(request: &str, key: &str) -> Option<String> {
    extract_json_value(request)?
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

#[cfg(feature = "http")]
fn decode_request_b64_field(request: &str, key: &str) -> Vec<u8> {
    let value = extract_json_string(request, key).expect("request JSON string field");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .expect("request base64 field should decode")
}

#[cfg(feature = "http")]
fn percent_encode_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                write!(&mut out, "%{byte:02X}").expect("writing to String cannot fail");
            }
        }
    }
    out
}
