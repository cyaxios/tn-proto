//! Small command-line wrapper around the Rust SDK.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use tn_proto::{
    default_credential_store, list_local_invites, AbsorbReceiptExt, AccountConnectOptions,
    BundleForRecipientOptions, CompileEnrolmentOptions, MintInvitationOptions, OfferOptions,
    ReadOptions, Tn, TnProjectOptions, TnProjectVaultClaimOptions, VaultHttpProjectClient,
    VaultInitUploadOptions, VaultInstallBodyOptions, VaultLinkState,
    VaultRestoreWithCachedAwkOptions, WalletSyncOptions,
};

const HOSTED_VAULT_URL: &str = "https://vault.tn-proto.org";

#[derive(Debug, Parser)]
#[command(name = "tn-proto")]
#[command(about = "Rust CLI wrapper for tn-proto", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create or open a local TN project.
    Init(ProjectInitArgs),
    /// Create/open a project, upload an encrypted pending claim, and print the claim URL.
    ClaimLink(ClaimLinkArgs),
    /// Read decrypted entries from an existing ceremony.
    Read(ReadArgs),
    /// Verify entries in an existing ceremony and fail on invalid rows.
    Verify(VerifyArgs),
    /// Show local project, account, vault, wallet, and group status.
    Show(ShowArgs),
    /// Watch an existing ceremony for newly visible entries.
    Watch(WatchArgs),
    /// Work with local tn-invite-*.zip recipient invitations.
    Inbox {
        #[command(subcommand)]
        command: InboxCommand,
    },
    /// Inspect and absorb .tnpkg packages.
    Pkg {
        #[command(subcommand)]
        command: PkgCommand,
    },
    /// Manage groups in an existing ceremony.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Bind a local project identity to a vault account.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Sync an account-bound project with a vault.
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    /// Manage local vault link-state.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
}

#[derive(Debug, Parser)]
struct ProjectInitArgs {
    /// Project name under .tn/<project>.
    project: String,
    /// Workspace directory that owns .tn/<project>.
    #[arg(long)]
    project_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ClaimLinkArgs {
    /// Project name under .tn/<project>.
    project: String,
    /// Vault base URL.
    #[arg(long, env = "TN_VAULT_URL", default_value = HOSTED_VAULT_URL)]
    vault: String,
    /// Workspace directory that owns .tn/<project>.
    #[arg(long)]
    project_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ReadArgs {
    /// Ceremony tn.yaml to read from.
    #[arg(long)]
    yaml: PathBuf,
    /// Include entries from every run instead of only this process run.
    #[arg(long)]
    all_runs: bool,
    /// Include per-entry verification flags in a _valid block.
    #[arg(long)]
    verify: bool,
    /// Pretty-print JSON entries instead of newline-delimited compact JSON.
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, Parser)]
struct VerifyArgs {
    /// Ceremony tn.yaml to verify.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct ShowArgs {
    /// Ceremony tn.yaml to inspect.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct WatchArgs {
    /// Ceremony tn.yaml to watch.
    #[arg(long)]
    yaml: PathBuf,
    /// Start by replaying the current read view instead of waiting for new entries.
    #[arg(long)]
    from_beginning: bool,
    /// Use native file notifications. Requires building the CLI with `--features cli,watch`.
    #[arg(long)]
    native: bool,
    /// Include per-entry verification flags in a _valid block.
    #[arg(long)]
    verify: bool,
    /// Pretty-print JSON entries instead of newline-delimited compact JSON.
    #[arg(long)]
    pretty: bool,
    /// Optional exact event type to print.
    #[arg(long)]
    event_type: Option<String>,
    /// Optional event type prefix to print.
    #[arg(long)]
    event_type_prefix: Option<String>,
    /// Maximum number of entries to print before exiting.
    #[arg(long, default_value_t = 1)]
    limit: usize,
    /// Maximum time to wait, in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,
    /// Poll interval for the polling watcher, in milliseconds.
    #[arg(long, default_value_t = 300)]
    poll_interval_ms: u64,
}

#[derive(Debug, Subcommand)]
enum InboxCommand {
    /// List local tn-invite-*.zip files.
    List(InboxListArgs),
    /// Inspect a tn-invite-*.zip without accepting it.
    Inspect(InboxInspectArgs),
    /// Accept a tn-invite-*.zip into an existing ceremony.
    Accept(InboxAcceptArgs),
    /// Mint a tn-invite-*.zip for a recipient.
    Mint(InboxMintArgs),
}

#[derive(Debug, Parser)]
struct InboxListArgs {
    /// Directory to scan.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
}

#[derive(Debug, Parser)]
struct InboxInspectArgs {
    /// Path to the tn-invite-*.zip file.
    zip: PathBuf,
}

#[derive(Debug, Parser)]
struct InboxAcceptArgs {
    /// Path to the tn-invite-*.zip file.
    zip: PathBuf,
    /// Ceremony tn.yaml to accept the invite into.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct InboxMintArgs {
    /// Recipient device DID or friendly label.
    recipient: String,
    /// Destination invite zip path.
    out: PathBuf,
    /// Publisher ceremony tn.yaml.
    #[arg(long)]
    yaml: PathBuf,
    /// Group to mint the reader kit for.
    #[arg(long, default_value = "default")]
    group: String,
    /// Sender label/email recorded in the invitation manifest.
    #[arg(long)]
    from_email: Option<String>,
    /// Friendly project name recorded in the invitation manifest.
    #[arg(long)]
    project_name: Option<String>,
    /// Free-form note recorded in the invitation manifest.
    #[arg(long)]
    note: Option<String>,
    /// Optional caller-supplied opaque invitation id.
    #[arg(long)]
    invitation_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum PkgCommand {
    /// Inspect a .tnpkg without absorbing it.
    Inspect(PkgInspectArgs),
    /// Absorb a .tnpkg into an existing ceremony.
    Absorb(PkgAbsorbArgs),
    /// Compile a recipient handoff package for one group.
    CompileEnrolment(PkgCompileEnrolmentArgs),
    /// Compile a recipient handoff package and attest an offer event.
    Offer(PkgOfferArgs),
    /// Export a .tnpkg from an existing ceremony.
    Export {
        #[command(subcommand)]
        command: PkgExportCommand,
    },
}

#[derive(Debug, Parser)]
struct PkgInspectArgs {
    /// Package path to inspect.
    package: PathBuf,
    /// Print all package body entry names.
    #[arg(long)]
    entries: bool,
}

#[derive(Debug, Parser)]
struct PkgAbsorbArgs {
    /// Package path to absorb.
    package: PathBuf,
    /// Ceremony tn.yaml to absorb into.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct PkgCompileEnrolmentArgs {
    /// Ceremony tn.yaml to compile from.
    #[arg(long)]
    yaml: PathBuf,
    /// Recipient DID to mint reader kits for.
    #[arg(long)]
    recipient: String,
    /// Group to include in the handoff package.
    #[arg(long, default_value = "default")]
    group: String,
    /// Destination .tnpkg path.
    #[arg(long)]
    out: PathBuf,
    /// Encrypt the bundle body and wrap the body key for the recipient DID.
    #[arg(long)]
    seal_for_recipient: bool,
}

#[derive(Debug, Parser)]
struct PkgOfferArgs {
    /// Ceremony tn.yaml to compile from.
    #[arg(long)]
    yaml: PathBuf,
    /// Peer DID to offer access to.
    #[arg(long)]
    peer: String,
    /// Group to include in the offer package.
    #[arg(long, default_value = "default")]
    group: String,
    /// Destination .tnpkg path.
    #[arg(long)]
    out: PathBuf,
    /// Encrypt the bundle body and wrap the body key for the peer DID.
    #[arg(long)]
    seal_for_recipient: bool,
}

#[derive(Debug, Subcommand)]
enum PkgExportCommand {
    /// Export a governance/admin snapshot package.
    AdminSnapshot(PkgExportAdminSnapshotArgs),
    /// Mint recipient-specific reader kits and export them as a kit bundle.
    BundleForRecipient(PkgExportBundleForRecipientArgs),
    /// Export the admin snapshot plus reader bundle files for a recipient.
    RecipientHandoff(PkgExportRecipientHandoffArgs),
}

#[derive(Debug, Parser)]
struct PkgExportAdminSnapshotArgs {
    /// Ceremony tn.yaml to export from.
    #[arg(long)]
    yaml: PathBuf,
    /// Destination .tnpkg path.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Parser)]
struct PkgExportBundleForRecipientArgs {
    /// Ceremony tn.yaml to export from.
    #[arg(long)]
    yaml: PathBuf,
    /// Recipient DID to mint reader kits for.
    #[arg(long)]
    recipient: String,
    /// Destination .tnpkg path.
    #[arg(long)]
    out: PathBuf,
    /// Comma-separated group subset. Repeatable.
    #[arg(long, value_delimiter = ',')]
    group: Vec<String>,
    /// Encrypt the bundle body and wrap the body key for the recipient DID.
    #[arg(long)]
    seal_for_recipient: bool,
}

#[derive(Debug, Parser)]
struct PkgExportRecipientHandoffArgs {
    /// Ceremony tn.yaml to export from.
    #[arg(long)]
    yaml: PathBuf,
    /// Recipient DID to mint reader kits for.
    #[arg(long)]
    recipient: String,
    /// Destination directory for handoff packages.
    #[arg(long)]
    out_dir: PathBuf,
    /// Comma-separated group subset. Repeatable.
    #[arg(long, value_delimiter = ',')]
    group: Vec<String>,
    /// Encrypt the reader bundle body and wrap the body key for the recipient DID.
    #[arg(long)]
    seal_for_recipient: bool,
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
    /// List groups declared by an existing ceremony.
    List(GroupListArgs),
    /// List recipient leaves for a group.
    Recipients(GroupRecipientsArgs),
    /// Add or update a group and field routing.
    Add(GroupAddArgs),
    /// Mint a reader kit for a recipient in an existing group.
    AddRecipient(GroupAddRecipientArgs),
    /// Revoke a reader by leaf index in an existing group.
    RevokeRecipient(GroupRevokeRecipientArgs),
}

#[derive(Debug, Parser)]
struct GroupListArgs {
    /// Ceremony tn.yaml to inspect.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct GroupRecipientsArgs {
    /// Existing group to inspect.
    group: String,
    /// Ceremony tn.yaml to inspect.
    #[arg(long)]
    yaml: PathBuf,
    /// Include revoked recipient leaves.
    #[arg(long)]
    include_revoked: bool,
}

#[derive(Debug, Parser)]
struct GroupAddArgs {
    /// Group name to add or update.
    name: String,
    /// Ceremony tn.yaml to update.
    #[arg(long)]
    yaml: PathBuf,
    /// Comma-separated field names to route into this group.
    #[arg(long, value_delimiter = ',')]
    fields: Vec<String>,
}

#[derive(Debug, Parser)]
struct GroupAddRecipientArgs {
    /// Existing group to mint the reader kit for.
    group: String,
    /// Recipient device DID to record in the admin event.
    recipient: String,
    /// Ceremony tn.yaml to update.
    #[arg(long)]
    yaml: PathBuf,
    /// Destination .btn.mykit path.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Parser)]
struct GroupRevokeRecipientArgs {
    /// Existing group to revoke the reader from.
    group: String,
    /// Reader leaf index to revoke.
    leaf_index: u64,
    /// Ceremony tn.yaml to update.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Redeem a vault connect code for an existing ceremony.
    ConnectCode(AuthConnectCodeArgs),
    /// Clear local account binding and cached account key.
    Logout(AuthLogoutArgs),
    /// Show local account binding status for an existing ceremony.
    Status(AuthStatusArgs),
    /// Alias for `auth status`.
    Whoami(AuthStatusArgs),
}

#[derive(Debug, Parser)]
struct AuthConnectCodeArgs {
    /// Connect code from the vault account UI.
    code: String,
    /// Ceremony tn.yaml to bind.
    #[arg(long)]
    yaml: PathBuf,
    /// Vault base URL.
    #[arg(long, env = "TN_VAULT_URL", default_value = HOSTED_VAULT_URL)]
    vault: String,
    /// Explicit identity.json path to use for signing.
    #[arg(long)]
    identity_path: Option<PathBuf>,
    /// Machine identity.json path override.
    #[arg(long)]
    machine_identity_path: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct AuthStatusArgs {
    /// Ceremony tn.yaml to inspect.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct AuthLogoutArgs {
    /// Ceremony tn.yaml whose local account binding should be cleared.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Link an existing ceremony to a known vault project.
    Connect(VaultConnectArgs),
    /// Clear local vault link-state and optionally emit an unlink audit event.
    Unlink(VaultUnlinkArgs),
}

#[derive(Debug, Parser)]
struct VaultConnectArgs {
    /// Ceremony tn.yaml to update.
    #[arg(long)]
    yaml: PathBuf,
    /// Vault base URL or identity.
    #[arg(long, env = "TN_VAULT_URL", default_value = HOSTED_VAULT_URL)]
    vault: String,
    /// Vault-side project id.
    #[arg(long)]
    project_id: String,
    /// Optional friendly project name.
    #[arg(long)]
    project_name: Option<String>,
    /// Do not emit a local tn.vault.linked audit event.
    #[arg(long)]
    no_audit_event: bool,
}

#[derive(Debug, Parser)]
struct VaultUnlinkArgs {
    /// Ceremony tn.yaml to update.
    #[arg(long)]
    yaml: PathBuf,
    /// Vault base URL or identity. Defaults to the current YAML link-state.
    #[arg(long)]
    vault: Option<String>,
    /// Vault-side project id. Defaults to the current YAML link-state.
    #[arg(long)]
    project_id: Option<String>,
    /// Optional reason to include in the local tn.vault.unlinked audit event.
    #[arg(long)]
    reason: Option<String>,
    /// Do not emit a local tn.vault.unlinked audit event.
    #[arg(long)]
    no_audit_event: bool,
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    /// Show local wallet/account/vault diagnostic state.
    Status(WalletStatusArgs),
    /// Pull account inbox packages, absorb them, publish group keys, and push the encrypted body.
    Sync(WalletSyncArgs),
    /// Restore an encrypted project body from the vault into a target directory.
    Restore(WalletRestoreArgs),
    /// Clear local vault link-state for this wallet/project.
    Unlink(VaultUnlinkArgs),
}

#[derive(Debug, Parser)]
struct WalletStatusArgs {
    /// Ceremony tn.yaml to inspect.
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(Debug, Parser)]
struct WalletSyncArgs {
    /// Ceremony tn.yaml to sync.
    #[arg(long)]
    yaml: PathBuf,
    /// Vault base URL.
    #[arg(long, env = "TN_VAULT_URL", default_value = HOSTED_VAULT_URL)]
    vault: String,
    /// Stage inbox packages without absorbing or pushing.
    #[arg(long)]
    pull_only: bool,
    /// Skip pull/absorb and only push the encrypted project body.
    #[arg(long)]
    push_only: bool,
    /// Retry the push side without pulling first.
    #[arg(long)]
    drain_queue: bool,
    /// Explicit identity.json path for vault auth.
    #[arg(long)]
    identity_path: Option<PathBuf>,
    /// Vault account id override. Defaults to local sync state.
    #[arg(long)]
    account_id: Option<String>,
    /// Vault project id override. Defaults to local vault link-state when present.
    #[arg(long)]
    project_id: Option<String>,
    /// Account passphrase fallback when no cached account key exists.
    #[arg(long, env = "TN_VAULT_PASSPHRASE")]
    passphrase: Option<String>,
    /// Credential id used with the passphrase fallback.
    #[arg(long, env = "TN_VAULT_CREDENTIAL_ID")]
    credential_id: Option<String>,
    /// Comma-separated group subset for group-key publishing.
    #[arg(long, value_delimiter = ',')]
    group: Vec<String>,
}

#[derive(Debug, Parser)]
struct WalletRestoreArgs {
    /// Ceremony tn.yaml used for local account/link-state context.
    #[arg(long)]
    yaml: PathBuf,
    /// Directory that will receive restored tn.yaml and keys/.
    #[arg(long)]
    target_dir: PathBuf,
    /// Vault base URL.
    #[arg(long, env = "TN_VAULT_URL", default_value = HOSTED_VAULT_URL)]
    vault: String,
    /// Vault account id override. Defaults to local account state.
    #[arg(long)]
    account_id: Option<String>,
    /// Vault project id override. Defaults to local vault link-state when present.
    #[arg(long)]
    project_id: Option<String>,
    /// Account passphrase fallback when no cached account key exists.
    #[arg(long, env = "TN_VAULT_PASSPHRASE")]
    passphrase: Option<String>,
    /// Credential id used with the passphrase fallback.
    #[arg(long, env = "TN_VAULT_CREDENTIAL_ID")]
    credential_id: Option<String>,
    /// Allow restore to overwrite different existing files in target-dir.
    #[arg(long)]
    overwrite: bool,
}

fn main() -> tn_proto::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => init_project(args),
        Command::ClaimLink(args) => claim_link(args),
        Command::Read(args) => read_entries(args),
        Command::Verify(args) => verify_entries(args),
        Command::Show(args) => show_project(args),
        Command::Watch(args) => watch_entries(args),
        Command::Inbox { command } => inbox(command),
        Command::Pkg { command } => pkg(command),
        Command::Group { command } => group(command),
        Command::Auth { command } => auth(command),
        Command::Wallet { command } => wallet(command),
        Command::Vault { command } => vault(command),
    }
}

fn init_project(args: ProjectInitArgs) -> tn_proto::Result<()> {
    let tn = Tn::init_project_with_options(
        &args.project,
        TnProjectOptions {
            project_dir: args.project_dir,
            ..Default::default()
        },
    )?;

    println!("project: {}", args.project);
    println!("yaml: {}", tn.yaml_path().display());
    println!("did: {}", tn.did());
    Ok(())
}

fn claim_link(args: ClaimLinkArgs) -> tn_proto::Result<()> {
    let client = VaultHttpProjectClient::new(&args.vault)?;
    let onboarding = Tn::init_project_with_vault_claim_options(
        &args.project,
        &client,
        TnProjectVaultClaimOptions {
            project: TnProjectOptions {
                project_dir: args.project_dir,
                ..Default::default()
            },
            upload: VaultInitUploadOptions::default(),
        },
    )?;

    println!("project: {}", args.project);
    println!("yaml: {}", onboarding.tn.yaml_path().display());
    println!("expires: {}", onboarding.claim.expires_at);
    println!("claim URL: {}", onboarding.claim.claim_url);
    eprintln!("Treat the full claim URL as a secret until it expires.");
    Ok(())
}

fn read_entries(args: ReadArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let entries = tn.read(ReadOptions {
        all_runs: args.all_runs,
        verify: args.verify,
    })?;

    for entry in entries {
        let value = serde_json::Value::Object(entry.into_map());
        if args.pretty {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!("{}", serde_json::to_string(&value)?);
        }
    }
    Ok(())
}

fn verify_entries(args: VerifyArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: true,
    })?;
    let mut invalid = 0usize;

    for entry in &entries {
        match entry.validity() {
            Some(validity) if validity.signature && validity.row_hash && validity.chain => {}
            Some(validity) => {
                invalid += 1;
                println!(
                    "invalid: event_type={} sequence={} signature={} row_hash={} chain={}",
                    entry.event_type().unwrap_or("(unknown)"),
                    entry
                        .sequence()
                        .map(|sequence| sequence.to_string())
                        .unwrap_or_else(|| "(unknown)".to_string()),
                    validity.signature,
                    validity.row_hash,
                    validity.chain
                );
            }
            None => {
                invalid += 1;
                println!(
                    "invalid: event_type={} sequence={} missing verification flags",
                    entry.event_type().unwrap_or("(unknown)"),
                    entry
                        .sequence()
                        .map(|sequence| sequence.to_string())
                        .unwrap_or_else(|| "(unknown)".to_string())
                );
            }
        }
    }

    println!("yaml: {}", tn.yaml_path().display());
    println!("entries: {}", entries.len());
    println!("invalid: {invalid}");
    println!("valid: {}", invalid == 0);

    if invalid > 0 {
        return Err(tn_proto::Error::InvalidArgument(format!(
            "verification failed: {invalid} invalid entries"
        )));
    }
    Ok(())
}

fn show_project(args: ShowArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let config = tn.config();
    let account = tn.account().status();
    let vault = tn.vault().link_state()?;
    let wallet_paths = tn.wallet().paths();
    let entries = tn.read(ReadOptions {
        all_runs: true,
        verify: false,
    })?;
    let groups = config.groups;

    println!("yaml: {}", config.yaml_path.display());
    println!("log: {}", config.log_path.display());
    println!("did: {}", config.device_identity);
    println!("entries: {}", entries.len());
    println!(
        "groups: {}",
        if groups.is_empty() {
            "(none)".to_string()
        } else {
            groups.join(",")
        }
    );
    println!(
        "account: {}",
        account.account_id.as_deref().unwrap_or("(not bound)")
    );
    println!("account bound: {}", account.account_bound);
    println!("key cached: {}", account.key_cached);
    println!("account verdict: {:?}", account.verdict);
    println!("vault state: {:?}", vault.state);
    println!("vault enabled: {}", vault.vault_enabled);
    println!("vault autosync: {}", vault.autosync);
    if let Some(interval) = vault.sync_interval_seconds {
        println!("vault sync interval seconds: {interval}");
    }
    println!(
        "vault: {}",
        vault.linked_vault.as_deref().unwrap_or("(not linked)")
    );
    println!(
        "project id: {}",
        vault.linked_project_id.as_deref().unwrap_or("(not linked)")
    );
    println!("wallet root: {}", wallet_paths.stem_dir.display());
    println!("wallet inbox: {}", wallet_paths.inbox_dir.display());
    println!("wallet state: {}", wallet_paths.sync_state_path.display());
    println!("wallet account bound: {}", tn.wallet().is_account_bound());
    Ok(())
}

fn watch_entries(args: WatchArgs) -> tn_proto::Result<()> {
    if args.limit == 0 {
        return Err(tn_proto::Error::InvalidArgument(
            "watch --limit must be greater than zero".into(),
        ));
    }

    if args.native {
        return watch_entries_native(args);
    }
    watch_entries_polling(args)
}

fn watch_options(args: &WatchArgs) -> tn_proto::WatchOptions {
    tn_proto::WatchOptions {
        start: if args.from_beginning {
            tn_proto::WatchStart::Beginning
        } else {
            tn_proto::WatchStart::Latest
        },
        read: ReadOptions {
            all_runs: true,
            verify: args.verify,
        },
        poll_interval: Duration::from_millis(args.poll_interval_ms),
        event_type: args.event_type.clone(),
        event_type_prefix: args.event_type_prefix.clone(),
    }
}

fn print_watch_entries(
    entries: Vec<tn_proto::Entry>,
    printed: &mut usize,
    args: &WatchArgs,
) -> tn_proto::Result<()> {
    for entry in entries {
        if *printed >= args.limit {
            break;
        }
        let value = serde_json::Value::Object(entry.into_map());
        if args.pretty {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!("{}", serde_json::to_string(&value)?);
        }
        *printed += 1;
    }
    Ok(())
}

fn watch_entries_polling(args: WatchArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let mut watch = tn.polling_watch(watch_options(&args))?;
    let timeout = Duration::from_millis(args.timeout_ms);
    let started = Instant::now();
    let mut printed = 0usize;

    while printed < args.limit {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let entries = watch.wait_for_entries(remaining)?;
        if entries.is_empty() {
            break;
        }
        print_watch_entries(entries, &mut printed, &args)?;
    }
    Ok(())
}

#[cfg(feature = "watch")]
fn watch_entries_native(args: WatchArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let mut watch = tn.native_watch(tn_proto::NativeWatchOptions {
        polling: watch_options(&args),
    })?;
    let timeout = Duration::from_millis(args.timeout_ms);
    let started = Instant::now();
    let mut printed = 0usize;

    while printed < args.limit {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let entries = watch.wait_for_entries(remaining)?;
        if entries.is_empty() {
            break;
        }
        print_watch_entries(entries, &mut printed, &args)?;
    }
    Ok(())
}

#[cfg(not(feature = "watch"))]
fn watch_entries_native(_args: WatchArgs) -> tn_proto::Result<()> {
    Err(tn_proto::Error::InvalidArgument(
        "watch --native requires building tn-proto with `--features cli,watch`".into(),
    ))
}

fn inbox(command: InboxCommand) -> tn_proto::Result<()> {
    match command {
        InboxCommand::List(args) => inbox_list(args),
        InboxCommand::Inspect(args) => inbox_inspect(args),
        InboxCommand::Accept(args) => inbox_accept(args),
        InboxCommand::Mint(args) => inbox_mint(args),
    }
}

fn inbox_list(args: InboxListArgs) -> tn_proto::Result<()> {
    let invites = list_local_invites(&args.dir)?;
    if invites.is_empty() {
        println!("No tn-invite-*.zip files found in {}", args.dir.display());
    } else {
        for path in invites {
            println!("{}", path.display());
        }
    }
    Ok(())
}

fn inbox_inspect(args: InboxInspectArgs) -> tn_proto::Result<()> {
    let info = tn_proto::inspect_invitation_path(&args.zip)?;
    let manifest = &info.manifest;

    println!("invite: {}", args.zip.display());
    println!("group: {}", info.group_name());
    println!(
        "sender: {}",
        manifest.from_email.as_deref().unwrap_or("(none)")
    );
    println!(
        "from did: {}",
        manifest.from_account_did.as_deref().unwrap_or("(none)")
    );
    println!(
        "project id: {}",
        manifest.project_id.as_deref().unwrap_or("(none)")
    );
    println!(
        "project name: {}",
        manifest.project_name.as_deref().unwrap_or("(none)")
    );
    if let Some(leaf_index) = manifest.leaf_index.as_ref() {
        println!("leaf: {leaf_index}");
    } else {
        println!("leaf: (none)");
    }
    println!("kit entry: {}", info.kit_entry_name);
    println!("kit bytes: {}", info.kit_len);
    println!("kit sha256: {}", info.kit_sha256_actual);
    println!("kit hash verified: {}", info.kit_hash_verified());
    println!(
        "created at: {}",
        manifest.created_at.as_deref().unwrap_or("(none)")
    );
    println!(
        "provenance: {}",
        manifest.provenance.as_deref().unwrap_or("(none)")
    );
    println!("note: {}", manifest.note.as_deref().unwrap_or("(none)"));
    Ok(())
}

fn inbox_accept(args: InboxAcceptArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let accepted = tn.inbox().accept_path(&args.zip)?;

    println!("accepted invite: {}", args.zip.display());
    println!("group: {}", accepted.group_name());
    println!("from: {}", accepted.from_email());
    if let Some(leaf_index) = accepted.leaf_index() {
        println!("leaf: {leaf_index}");
    }
    println!("kit: {}", accepted.kit_path.display());
    if let Some(backup_path) = accepted.backup_path {
        println!("backup: {}", backup_path.display());
    }
    println!("absorbed_at: {}", accepted.absorbed_at);
    Ok(())
}

fn inbox_mint(args: InboxMintArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let link_state = tn.vault().link_state()?;
    let minted = tn.inbox().mint_invite_path(
        &args.recipient,
        &args.out,
        MintInvitationOptions {
            group: Some(args.group),
            from_email: args.from_email,
            project_id: link_state.linked_project_id,
            project_name: args.project_name,
            note: args.note,
            invitation_id: args.invitation_id,
            ..MintInvitationOptions::default()
        },
    )?;

    println!("invite: {}", minted.path.display());
    println!("recipient: {}", minted.recipient_did);
    println!("group: {}", minted.manifest.group_name());
    if let Some(from_email) = minted.manifest.from_email.as_deref() {
        println!("from: {from_email}");
    }
    if let Some(leaf_index) = minted.manifest.leaf_index.as_ref() {
        println!("leaf: {leaf_index}");
    }
    if let Some(kit_sha256) = minted.manifest.kit_sha256.as_deref() {
        println!("kit_sha256: {kit_sha256}");
    }
    println!("inner kit: {}", minted.kit_entry_name);
    println!("bytes: {}", minted.zip_len);
    Ok(())
}

fn pkg(command: PkgCommand) -> tn_proto::Result<()> {
    match command {
        PkgCommand::Inspect(args) => pkg_inspect(args),
        PkgCommand::Absorb(args) => pkg_absorb(args),
        PkgCommand::CompileEnrolment(args) => pkg_compile_enrolment(args),
        PkgCommand::Offer(args) => pkg_offer(args),
        PkgCommand::Export { command } => pkg_export(command),
    }
}

fn pkg_inspect(args: PkgInspectArgs) -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;
    let info = tn.pkg().inspect_path(&args.package)?;

    println!("package: {}", args.package.display());
    println!("kind: {}", info.kind().as_str());
    println!("category: {:?}", info.category());
    println!("verified: {}", info.verified());
    println!("signature: {:?}", info.signature);
    println!("publisher: {}", info.publisher_did());
    println!("recipient: {}", info.recipient_did().unwrap_or("(none)"));
    println!("ceremony: {}", info.ceremony_id());
    println!("body entries: {}", info.body_entry_count);
    println!("contains reader keys: {}", info.contains_reader_keys());
    println!("contains secrets: {}", info.contains_secret_material());
    if args.entries {
        for entry in &info.body_entry_names {
            println!("entry: {entry}");
        }
    }
    Ok(())
}

fn pkg_absorb(args: PkgAbsorbArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let receipt = tn.pkg().absorb_path(&args.package)?;

    println!("package: {}", args.package.display());
    println!("yaml: {}", tn.yaml_path().display());
    println!("kind: {}", receipt.kind);
    println!("status: {:?}", receipt.status());
    println!("legacy status: {}", receipt.legacy_status);
    if !receipt.legacy_reason.is_empty() {
        println!("reason: {}", receipt.legacy_reason);
    }
    println!("accepted: {}", receipt.accepted_count);
    println!("deduped: {}", receipt.deduped_count);
    println!("noop: {}", receipt.noop);
    println!("conflicts: {}", receipt.conflicts.len());
    for path in &receipt.replaced_kit_paths {
        println!("replaced kit: {}", path.display());
    }
    Ok(())
}

fn pkg_compile_enrolment(args: PkgCompileEnrolmentArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let compiled = tn.pkg().compile_enrolment(CompileEnrolmentOptions {
        group: args.group,
        recipient_did: args.recipient,
        out_path: args.out,
        seal_for_recipient: args.seal_for_recipient,
    })?;
    let info = tn.pkg().inspect_path(&compiled.path)?;

    println!("package: {}", compiled.path.display());
    println!("yaml: {}", tn.yaml_path().display());
    println!("recipient: {}", compiled.recipient_did);
    println!("groups: {}", compiled.groups.join(","));
    println!("kind: {}", info.kind().as_str());
    println!("verified: {}", info.verified());
    println!("sealed: {}", args.seal_for_recipient);
    println!("manifest sha256: {}", compiled.manifest_sha256);
    println!("package sha256: {}", compiled.package_sha256);
    println!("contains reader keys: {}", info.contains_reader_keys());
    println!("contains secrets: {}", info.contains_secret_material());
    Ok(())
}

fn pkg_offer(args: PkgOfferArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let receipt = tn.pkg().offer(OfferOptions {
        group: args.group,
        peer_did: args.peer,
        out_path: args.out,
        seal_for_recipient: args.seal_for_recipient,
    })?;
    let info = tn.pkg().inspect_path(&receipt.path)?;

    println!("package: {}", receipt.path.display());
    println!("yaml: {}", tn.yaml_path().display());
    println!("peer: {}", receipt.peer_did);
    println!("group: {}", receipt.group);
    println!("status: {}", receipt.status);
    println!("kind: {}", info.kind().as_str());
    println!("verified: {}", info.verified());
    println!("sealed: {}", args.seal_for_recipient);
    println!("package sha256: {}", receipt.package_sha256);
    println!("contains reader keys: {}", info.contains_reader_keys());
    println!("contains secrets: {}", info.contains_secret_material());
    Ok(())
}

fn pkg_export(command: PkgExportCommand) -> tn_proto::Result<()> {
    match command {
        PkgExportCommand::AdminSnapshot(args) => pkg_export_admin_snapshot(args),
        PkgExportCommand::BundleForRecipient(args) => pkg_export_bundle_for_recipient(args),
        PkgExportCommand::RecipientHandoff(args) => pkg_export_recipient_handoff(args),
    }
}

fn pkg_export_admin_snapshot(args: PkgExportAdminSnapshotArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let written = tn.pkg().export_admin_snapshot(&args.out)?;
    let info = tn.pkg().inspect_path(&written)?;

    println!("package: {}", written.display());
    println!("yaml: {}", tn.yaml_path().display());
    println!("kind: {}", info.kind().as_str());
    println!("verified: {}", info.verified());
    println!("body entries: {}", info.body_entry_count);
    println!("contains secrets: {}", info.contains_secret_material());
    Ok(())
}

fn pkg_export_bundle_for_recipient(args: PkgExportBundleForRecipientArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let groups = if args.group.is_empty() {
        None
    } else {
        Some(args.group)
    };
    let result = tn.pkg().bundle_for_recipient(
        args.recipient,
        &args.out,
        BundleForRecipientOptions {
            groups,
            seal_for_recipient: args.seal_for_recipient,
        },
    )?;
    let info = tn.pkg().inspect_path(&result.path)?;

    println!("package: {}", result.path.display());
    println!("yaml: {}", tn.yaml_path().display());
    println!("recipient: {}", result.recipient_did);
    println!("groups: {}", result.groups.join(","));
    println!("kind: {}", info.kind().as_str());
    println!("verified: {}", info.verified());
    println!("body entries: {}", info.body_entry_count);
    println!("sealed: {}", args.seal_for_recipient);
    println!("contains reader keys: {}", info.contains_reader_keys());
    println!("contains secrets: {}", info.contains_secret_material());
    Ok(())
}

fn pkg_export_recipient_handoff(args: PkgExportRecipientHandoffArgs) -> tn_proto::Result<()> {
    std::fs::create_dir_all(&args.out_dir)?;
    let tn = Tn::init(&args.yaml)?;
    let admin_path = args.out_dir.join("admin-snapshot.tnpkg");
    let bundle_path = args.out_dir.join("reader-bundle.tnpkg");
    let groups = if args.group.is_empty() {
        None
    } else {
        Some(args.group)
    };

    let admin_written = tn.pkg().export_admin_snapshot(&admin_path)?;
    let admin_info = tn.pkg().inspect_path(&admin_written)?;
    let bundle = tn.pkg().bundle_for_recipient(
        args.recipient,
        &bundle_path,
        BundleForRecipientOptions {
            groups,
            seal_for_recipient: args.seal_for_recipient,
        },
    )?;
    let bundle_info = tn.pkg().inspect_path(&bundle.path)?;

    println!("yaml: {}", tn.yaml_path().display());
    println!("recipient: {}", bundle.recipient_did);
    println!("groups: {}", bundle.groups.join(","));
    println!("admin package: {}", admin_written.display());
    println!("admin verified: {}", admin_info.verified());
    println!(
        "admin contains secrets: {}",
        admin_info.contains_secret_material()
    );
    println!("bundle package: {}", bundle.path.display());
    println!("bundle verified: {}", bundle_info.verified());
    println!("bundle sealed: {}", args.seal_for_recipient);
    println!(
        "bundle contains reader keys: {}",
        bundle_info.contains_reader_keys()
    );
    println!(
        "bundle contains secrets: {}",
        bundle_info.contains_secret_material()
    );
    println!("send: admin-snapshot.tnpkg, reader-bundle.tnpkg");
    Ok(())
}

fn group(command: GroupCommand) -> tn_proto::Result<()> {
    match command {
        GroupCommand::List(args) => group_list(args),
        GroupCommand::Recipients(args) => group_recipients(args),
        GroupCommand::Add(args) => group_add(args),
        GroupCommand::AddRecipient(args) => group_add_recipient(args),
        GroupCommand::RevokeRecipient(args) => group_revoke_recipient(args),
    }
}

fn group_list(args: GroupListArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let groups = tn.group_names();

    println!("yaml: {}", tn.yaml_path().display());
    println!("groups: {}", groups.len());
    for group in groups {
        println!("group: {group}");
    }
    Ok(())
}

fn group_recipients(args: GroupRecipientsArgs) -> tn_proto::Result<()> {
    let mut tn = Tn::init(&args.yaml)?;
    let recipients = tn.admin().recipients(&args.group, args.include_revoked)?;

    println!("yaml: {}", tn.yaml_path().display());
    println!("group: {}", args.group);
    println!("recipients: {}", recipients.len());
    for recipient in recipients {
        println!(
            "leaf: {} recipient: {} revoked: {}",
            recipient.leaf_index,
            recipient.recipient_identity.as_deref().unwrap_or("(none)"),
            recipient.revoked
        );
    }
    Ok(())
}

fn group_add(args: GroupAddArgs) -> tn_proto::Result<()> {
    let mut tn = Tn::init(&args.yaml)?;
    let result = tn.admin().ensure_group(&args.name, args.fields)?;

    println!("group: {}", result.group);
    println!("yaml: {}", tn.yaml_path().display());
    println!("created: {}", result.created);
    println!("changed: {}", result.changed);
    if result.fields.is_empty() {
        println!("fields: (none)");
    } else {
        println!("fields: {}", result.fields.join(","));
    }
    println!("cipher: btn");
    tn.close()?;
    Ok(())
}

fn group_add_recipient(args: GroupAddRecipientArgs) -> tn_proto::Result<()> {
    let mut tn = Tn::init(&args.yaml)?;
    let result = tn
        .admin()
        .add_recipient(&args.group, Some(args.recipient), &args.out)?;

    println!("group: {}", result.group);
    println!(
        "recipient: {}",
        result.recipient_did.as_deref().unwrap_or("")
    );
    println!("leaf index: {}", result.leaf_index);
    println!("kit: {}", result.kit_path.display());
    println!("yaml: {}", tn.yaml_path().display());
    tn.close()?;
    Ok(())
}

fn group_revoke_recipient(args: GroupRevokeRecipientArgs) -> tn_proto::Result<()> {
    let mut tn = Tn::init(&args.yaml)?;
    let result = tn.admin().revoke_recipient(&args.group, args.leaf_index)?;

    println!("group: {}", result.group);
    println!("leaf index: {}", result.leaf_index);
    println!("yaml: {}", tn.yaml_path().display());
    println!("revoked: true");
    tn.close()?;
    Ok(())
}

fn auth(command: AuthCommand) -> tn_proto::Result<()> {
    match command {
        AuthCommand::ConnectCode(args) => auth_connect_code(args),
        AuthCommand::Logout(args) => auth_logout(args),
        AuthCommand::Status(args) | AuthCommand::Whoami(args) => auth_status(args),
    }
}

fn auth_connect_code(args: AuthConnectCodeArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let mut options = AccountConnectOptions::new(args.vault);
    options.supplied_identity_path = args.identity_path;
    options.machine_identity_path = args.machine_identity_path;
    let connected = tn.account().connect_code_http(args.code, options)?;

    println!("account: {}", connected.account_id);
    println!("did: {}", connected.did);
    println!("signing tier: {:?}", connected.signing_tier);
    println!(
        "signing source: {}",
        connected.signing_source_path.display()
    );
    if let Some(project_id) = connected.project_id {
        println!("project id: {project_id}");
    }
    if let Some(project_name) = connected.project_name {
        println!("project name: {project_name}");
    }
    Ok(())
}

fn auth_status(args: AuthStatusArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let status = tn.account().status();

    println!("did: {}", status.device_did);
    println!(
        "account: {}",
        status.account_id.as_deref().unwrap_or("(not bound)")
    );
    println!("account bound: {}", status.account_bound);
    println!("key cached: {}", status.key_cached);
    println!("verdict: {:?}", status.verdict);
    println!("message: {}", status.verdict.message());
    println!("vault state: {:?}", status.vault.state);
    if let Some(linked_vault) = status.vault.linked_vault {
        println!("vault: {linked_vault}");
    }
    if let Some(project_id) = status.vault.linked_project_id {
        println!("project id: {project_id}");
    }
    Ok(())
}

fn auth_logout(args: AuthLogoutArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let result = tn.account().logout()?;

    println!(
        "previous account: {}",
        result.previous_account_id.as_deref().unwrap_or("(none)")
    );
    println!("deleted cached key: {}", result.deleted_cached_key);
    println!("account bound: {}", result.status.account_bound);
    println!("verdict: {:?}", result.status.verdict);
    println!("message: {}", result.status.verdict.message());
    Ok(())
}

fn vault(command: VaultCommand) -> tn_proto::Result<()> {
    match command {
        VaultCommand::Connect(args) => vault_connect(args),
        VaultCommand::Unlink(args) => vault_unlink(args),
    }
}

fn vault_connect(args: VaultConnectArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let result = tn.vault().connect(tn_proto::VaultConnectOptions {
        vault: args.vault,
        project_id: args.project_id,
        project_name: args.project_name,
        record_audit_event: !args.no_audit_event,
    })?;

    println!("vault: {}", result.vault);
    println!("project id: {}", result.project_id);
    if let Some(project_name) = result.project_name {
        println!("project name: {project_name}");
    }
    println!("newly linked: {}", result.newly_linked);
    println!("audit event recorded: {}", result.audit_event_recorded);
    println!("state: {:?}", result.state.state);
    println!("yaml: {}", result.state.yaml_path.display());
    Ok(())
}

fn vault_unlink(args: VaultUnlinkArgs) -> tn_proto::Result<()> {
    unlink_vault_state(args, "vault unlink")
}

fn unlink_vault_state(args: VaultUnlinkArgs, command_name: &str) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let before = tn.vault().link_state()?;
    let vault = args.vault.or(before.linked_vault).ok_or_else(|| {
        tn_proto::Error::InvalidArgument(format!("{command_name} requires --vault"))
    })?;
    let project_id = args
        .project_id
        .or(before.linked_project_id)
        .ok_or_else(|| {
            tn_proto::Error::InvalidArgument(format!("{command_name} requires --project-id"))
        })?;

    let event_recorded = if args.no_audit_event {
        false
    } else {
        tn.vault()
            .unlink(&vault, &project_id, args.reason.as_deref())?;
        true
    };
    let state = tn.vault().set_link_state(
        VaultLinkState::Local,
        tn_proto::SetLinkStateOptions::default(),
    )?;

    println!("vault: {vault}");
    println!("project id: {project_id}");
    if let Some(reason) = args.reason {
        println!("reason: {reason}");
    }
    println!("audit event recorded: {event_recorded}");
    println!("state: {:?}", state.state);
    println!("yaml: {}", state.yaml_path.display());
    Ok(())
}

fn wallet(command: WalletCommand) -> tn_proto::Result<()> {
    match command {
        WalletCommand::Status(args) => wallet_status(args),
        WalletCommand::Sync(args) => wallet_sync(args),
        WalletCommand::Restore(args) => wallet_restore(args),
        WalletCommand::Unlink(args) => unlink_vault_state(args, "wallet unlink"),
    }
}

fn wallet_status(args: WalletStatusArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let account = tn.account().status();
    let paths = tn.wallet().paths();
    let vault = tn.vault().link_state()?;

    println!("yaml: {}", tn.yaml_path().display());
    println!("wallet root: {}", paths.stem_dir.display());
    println!("wallet inbox: {}", paths.inbox_dir.display());
    println!("wallet state: {}", paths.sync_state_path.display());
    println!(
        "account: {}",
        account.account_id.as_deref().unwrap_or("(not bound)")
    );
    println!("account bound: {}", account.account_bound);
    println!("key cached: {}", account.key_cached);
    println!("verdict: {:?}", account.verdict);
    println!("wallet account bound: {}", tn.wallet().is_account_bound());
    println!("vault state: {:?}", vault.state);
    println!("vault enabled: {}", vault.vault_enabled);
    println!("vault autosync: {}", vault.autosync);
    if let Some(interval) = vault.sync_interval_seconds {
        println!("vault sync interval seconds: {interval}");
    }
    if let Some(linked_vault) = vault.linked_vault {
        println!("vault: {linked_vault}");
    }
    if let Some(project_id) = vault.linked_project_id {
        println!("project id: {project_id}");
    }
    Ok(())
}

fn wallet_sync(args: WalletSyncArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let client = VaultHttpProjectClient::new(&args.vault)?;
    let account_id = args.account_id.or_else(|| tn.account().account_id());
    let project_id = match args.project_id {
        Some(project_id) => Some(project_id),
        None => tn.vault().link_state()?.linked_project_id,
    };
    let options = WalletSyncOptions {
        pull_only: args.pull_only,
        push_only: args.push_only,
        drain_queue: args.drain_queue,
        vault: Some(args.vault),
        identity_path: args.identity_path,
        account_id,
        passphrase: args.passphrase,
        credential_id: args.credential_id,
        project_id,
        group_key_groups: non_empty_vec(args.group),
    };
    let result = tn
        .wallet()
        .sync_with_cached_awk(&client, &default_credential_store(), options)?;

    println!("staged: {}", result.staged);
    println!("skipped: {}", result.skipped);
    println!("absorbed: {}", result.absorbed);
    println!("no-op: {}", result.no_op);
    println!("stashed: {}", result.stashed);
    println!("rejected: {}", result.rejected);
    println!("pushed: {}", result.pushed);
    println!(
        "account: {}",
        result.account_id.as_deref().unwrap_or("(not bound)")
    );
    println!("account bound: {}", result.account_bound);
    if result.published_groups.is_empty() {
        println!("published groups: (none)");
    } else {
        println!("published groups: {}", result.published_groups.join(", "));
    }
    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn non_empty_vec(values: Vec<String>) -> Option<Vec<String>> {
    let values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(values)
}

fn wallet_restore(args: WalletRestoreArgs) -> tn_proto::Result<()> {
    let tn = Tn::init(&args.yaml)?;
    let client = VaultHttpProjectClient::new(&args.vault)?;
    let account_id = args
        .account_id
        .or_else(|| tn.account().account_id())
        .ok_or_else(|| {
            tn_proto::Error::InvalidArgument("wallet restore requires account_id".into())
        })?;
    let project_id = match args.project_id {
        Some(project_id) => Some(project_id),
        None => tn.vault().link_state()?.linked_project_id,
    };
    let mut restore_options = VaultRestoreWithCachedAwkOptions::new(account_id);
    restore_options.project_id = project_id;
    restore_options.passphrase = args.passphrase;
    restore_options.credential_id = args.credential_id;
    let mut install_options = VaultInstallBodyOptions::new(args.target_dir);
    install_options.overwrite = args.overwrite;
    let result = tn
        .vault()
        .restore_and_install_body_with_cached_awk_http_client(
            &client,
            &default_credential_store(),
            restore_options,
            install_options,
        )?;

    println!("project id: {}", result.restore.project_id);
    println!("target dir: {}", result.install.target_dir.display());
    println!("yaml: {}", result.install.yaml_path.display());
    println!("keys dir: {}", result.install.keys_dir.display());
    println!("written: {}", result.install.written_paths.len());
    println!("deduped: {}", result.install.deduped_paths.len());
    println!("skipped members: {}", result.install.skipped_members.len());
    Ok(())
}
