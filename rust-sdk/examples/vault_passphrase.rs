// Demonstrates the passphrase-backed vault flow: initialize a local project,
// authenticate to a vault with the local device identity, push the encrypted
// project body, then restore that body into an explicit target directory.
//
// Required environment variables:
//   TN_VAULT_URL
//   TN_VAULT_PASSPHRASE
//
// Optional:
//   TN_PROJECT_NAME
//   TN_RESTORE_DIR
//   TN_VAULT_CREDENTIAL_ID
//   TN_VAULT_SESSION_TOKEN or TN_VAULT_JWT

use std::env;
use std::path::PathBuf;

use tn_proto::{
    Tn, VaultClientConnectOptions, VaultDeviceIdentity, VaultHttpProjectClient,
    VaultHttpProjectClientOptions, VaultInstallBodyOptions, VaultPushWithPassphraseOptions,
    VaultRestoreWithPassphraseOptions,
};

fn main() -> tn_proto::Result<()> {
    let Some(vault_url) = env_value("TN_VAULT_URL") else {
        print_usage();
        return Ok(());
    };
    let Some(passphrase) = env_value("TN_VAULT_PASSPHRASE") else {
        print_usage();
        return Ok(());
    };

    let project_name = env_value("TN_PROJECT_NAME").unwrap_or_else(|| "payments".to_string());
    let restore_dir = env_value("TN_RESTORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("restored-payments"));
    let credential_id = env_value("TN_VAULT_CREDENTIAL_ID");

    let tn = Tn::init_project(&project_name)?;
    let device_seed = std::fs::read(tn.yaml_path().parent().unwrap().join("keys/local.private"))?;
    let identity = VaultDeviceIdentity::from_private_bytes(&device_seed)?;
    let mut client = VaultHttpProjectClient::for_identity(
        &identity,
        VaultHttpProjectClientOptions::new(&vault_url),
    )?;

    let connection = tn
        .vault()
        .connect_with_client(&mut client, VaultClientConnectOptions::default())?;
    println!("linked vault project {}", connection.project_id);

    let mut push_options = VaultPushWithPassphraseOptions::new();
    push_options.credential_id = credential_id.clone();
    let push =
        tn.vault()
            .push_body_with_passphrase_http_client(&client, &passphrase, push_options)?;
    println!(
        "pushed {} body members to {}",
        push.push.body_member_count, push.push.project_id
    );

    let mut restore_options = VaultRestoreWithPassphraseOptions::new();
    restore_options.project_id = Some(connection.project_id);
    restore_options.credential_id = credential_id;
    let restore = tn
        .vault()
        .restore_and_install_body_with_passphrase_http_client(
            &client,
            &passphrase,
            restore_options,
            VaultInstallBodyOptions::new(&restore_dir),
        )?;
    println!("restored {}", restore.install.yaml_path.display());

    Ok(())
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn print_usage() {
    eprintln!(
        "Set TN_VAULT_URL and TN_VAULT_PASSPHRASE, then run:\n\
         cargo run -p tn-proto --features http --example vault_passphrase\n\n\
         Optional: TN_PROJECT_NAME, TN_RESTORE_DIR, TN_VAULT_CREDENTIAL_ID,\n\
         TN_VAULT_SESSION_TOKEN or TN_VAULT_JWT"
    );
}
