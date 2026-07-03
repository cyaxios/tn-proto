#![cfg(feature = "http")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value as JsonValue;
use tempfile::TempDir;
use tn_proto::{
    FileCredentialStore, Tn, TnProjectOptions, VaultClientConnectOptions, VaultHttpProjectClient,
    VaultInstallBodyOptions, VaultRestoreWithPassphraseOptions, WalletStageInboxOptions,
    WalletSyncOptions,
};

#[test]
fn dev_vault_passphrase_push_restore_and_wrong_passphrase() -> tn_proto::Result<()> {
    let Some(dev) = dev_login("rust-live")? else {
        eprintln!(
            "skipping Rust dev-vault live test: {} is not reachable or dev auth bypass is disabled",
            vault_base()
        );
        return Ok(());
    };

    let temp = TempDir::new()?;
    let project_name = format!("rust-live-{}", unique_suffix());
    let tn = Tn::init_project_with_options(
        &project_name,
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    let mut client = VaultHttpProjectClient::new(vault_base())?;
    client.set_bearer_token(dev.token);

    let connection = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;

    let mut push_options = tn_proto::VaultPushWithPassphraseOptions::new();
    push_options.project_id = Some(connection.project_id.clone());
    let push =
        tn.vault()
            .push_body_with_passphrase_http_client(&client, &dev.passphrase, push_options)?;
    assert_eq!(push.push.project_id, connection.project_id);
    assert!(push.push.body_member_count > 0);

    let restore_dir = temp.path().join("restored");
    let mut restore_options = VaultRestoreWithPassphraseOptions::new();
    restore_options.project_id = Some(connection.project_id.clone());
    let restore = tn
        .vault()
        .restore_and_install_body_with_passphrase_http_client(
            &client,
            &dev.passphrase,
            restore_options,
            VaultInstallBodyOptions::new(&restore_dir),
        )?;
    assert_eq!(restore.restore.project_id, connection.project_id);
    assert!(restore.install.yaml_path.exists());
    assert!(restore_dir.join("keys").join("local.private").exists());

    let wrong_restore_dir = temp.path().join("wrong-passphrase-restore");
    let mut wrong_options = VaultRestoreWithPassphraseOptions::new();
    wrong_options.project_id = Some(connection.project_id);
    let err = tn
        .vault()
        .restore_and_install_body_with_passphrase_http_client(
            &client,
            "definitely not the account passphrase",
            wrong_options,
            VaultInstallBodyOptions::new(&wrong_restore_dir),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("unwrap")
            || err.to_string().contains("decrypt")
            || err.to_string().contains("AEAD"),
        "unexpected wrong-passphrase error: {err}"
    );
    assert!(
        !wrong_restore_dir.join("tn.yaml").exists(),
        "wrong passphrase must not install partial restore output"
    );

    Ok(())
}

#[test]
fn dev_vault_wallet_sync_uses_passphrase_then_cached_awk() -> tn_proto::Result<()> {
    let Some(dev) = dev_login("rust-wallet-sync")? else {
        eprintln!(
            "skipping Rust dev-vault wallet sync test: {} is not reachable or dev auth bypass is disabled",
            vault_base()
        );
        return Ok(());
    };

    let temp = TempDir::new()?;
    let project_name = format!("rust-wallet-sync-{}", unique_suffix());
    let tn = Tn::init_project_with_options(
        &project_name,
        TnProjectOptions {
            project_dir: Some(temp.path().join("runtime")),
            ..Default::default()
        },
    )?;
    tn.info(
        "wallet.sync.live",
        serde_json::json!({ "project_name": project_name }),
    )?;

    let mut client = VaultHttpProjectClient::new(vault_base())?;
    client.set_bearer_token(dev.token);
    let connection = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;
    write_wallet_account_bound_state(tn.yaml_path(), &dev.account_id)?;

    let inbox = tn
        .wallet()
        .stage_account_inbox(&client, WalletStageInboxOptions::default())?;
    assert_eq!(inbox.staged_paths.len(), 0);
    assert_eq!(inbox.skipped, 0);
    assert!(!inbox.not_bound);
    assert!(!inbox.unauthorized);

    let store = FileCredentialStore::new(temp.path().join("credentials.json"));
    let first = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            account_id: Some(dev.account_id.clone()),
            project_id: Some(connection.project_id.clone()),
            passphrase: Some(dev.passphrase.clone()),
            ..Default::default()
        },
    )?;
    assert!(first.pushed);
    assert!(first.account_bound);
    assert_eq!(first.account_id.as_deref(), Some(dev.account_id.as_str()));
    assert_eq!(first.published_groups, vec!["default".to_string()]);
    assert!(store.get_account_awk(&dev.account_id)?.is_some());

    let second = tn.wallet().sync_with_cached_awk(
        &client,
        &store,
        WalletSyncOptions {
            push_only: true,
            account_id: Some(dev.account_id.clone()),
            project_id: Some(connection.project_id),
            ..Default::default()
        },
    )?;
    assert!(second.pushed);
    assert_eq!(second.staged, 0);
    assert_eq!(second.absorbed, 0);
    assert!(second.warnings.is_empty());

    let state: JsonValue = serde_json::from_slice(&std::fs::read(
        tn_proto::wallet_sync_state_path(tn.yaml_path()),
    )?)?;
    assert_eq!(state["account_bound"], true);
    assert_eq!(state["account_id"], dev.account_id);
    assert_eq!(state["last_wallet_sync"]["pushed"], true);
    assert!(state["last_wallet_sync_at"].as_str().is_some());

    Ok(())
}

struct DevLogin {
    account_id: String,
    token: String,
    passphrase: String,
}

fn dev_login(stem: &str) -> tn_proto::Result<Option<DevLogin>> {
    let base = vault_base();
    let handle = format!("{stem}-{}", unique_suffix());
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = match http
        .post(format!("{base}/api/v1/dev/login"))
        .json(&serde_json::json!({ "handle": handle }))
        .send()
    {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let raw: JsonValue = response.json()?;
    let token = raw
        .get("token")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| tn_proto::Error::VaultHttp("dev/login response missing token".into()))?;
    let account_id = raw
        .get("account_id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            tn_proto::Error::VaultHttp("dev/login response missing account_id".into())
        })?;
    let passphrase = raw
        .get("passphrase")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("tn-dev-{handle}"));
    Ok(Some(DevLogin {
        account_id,
        token,
        passphrase,
    }))
}

fn vault_base() -> String {
    std::env::var("PLUMB_VAULT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:34987".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}

fn write_wallet_account_bound_state(
    yaml_path: &std::path::Path,
    account_id: &str,
) -> tn_proto::Result<()> {
    let state_path = tn_proto::wallet_sync_state_path(yaml_path);
    std::fs::create_dir_all(state_path.parent().unwrap())?;
    std::fs::write(
        state_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "account_id": account_id,
            "account_bound": true,
        }))?,
    )?;
    Ok(())
}
