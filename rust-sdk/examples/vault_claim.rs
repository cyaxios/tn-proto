// Creates or opens a local TN project, uploads an encrypted pending claim to a
// vault, and prints the browser claim URL.
//
// By default this targets the hosted TN vault:
//   https://vault.tn-proto.org
//
// Optional environment variables:
//   TN_VAULT_URL     Override the vault base URL.
//   TN_PROJECT_NAME  Override the local project name.
//
// Run from the repository root:
//   cargo run -p tn-proto --features http --example vault_claim

use std::env;

use tn_proto::{Tn, VaultHttpProjectClient};

const HOSTED_VAULT_URL: &str = "https://vault.tn-proto.org";

fn main() -> tn_proto::Result<()> {
    let vault_url = env::var("TN_VAULT_URL").unwrap_or_else(|_| HOSTED_VAULT_URL.to_string());
    let project = env::var("TN_PROJECT_NAME").unwrap_or_else(|_| "rust-vault-claim".to_string());

    let client = VaultHttpProjectClient::new(&vault_url)?;
    let onboarding = Tn::init_project_with_vault_claim(&project, &client)?;

    println!("project: {project}");
    println!("yaml: {}", onboarding.tn.yaml_path().display());
    println!("expires: {}", onboarding.claim.expires_at);
    println!("claim URL: {}", onboarding.claim.claim_url);

    Ok(())
}
